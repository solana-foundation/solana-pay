//! The durable, append-only `pay push` journal and its resume reducer.
//!
//! Two independent halves live here:
//!
//! - [`Journal`]: an append-only JSONL writer. Every write is flushed and
//!   `sync_data`'d before the call returns. [`Journal::append_chunk_signed`]
//!   is the *only* way to obtain a [`ChunkBroadcastPermit`], and
//!   [`Journal::append_chunk_broadcast`] requires one — so a durable
//!   `chunk_signed` record is structurally required before any broadcast
//!   step can run, not just a convention callers are trusted to follow.
//! - [`reduce_chunk_resume_action`]: pure resume logic. It takes an
//!   [`ResumeRpc`] trait object rather than a live RPC client, so the exact
//!   decision matrix in the plan's "Journal and resume" section is
//!   unit-testable without a network.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use solana_hash::Hash;
use solana_signature::Signature;

use super::planner::FeePayerMode;
use crate::{Error, Result};

/// `~/.config/pay/push/<UTC timestamp>-<manifest-prefix>.jsonl`.
pub fn default_journal_path(manifest_hash_prefix: &str) -> PathBuf {
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ");
    PathBuf::from(
        shellexpand::tilde(&format!(
            "~/.config/pay/push/{timestamp}-{manifest_hash_prefix}.jsonl"
        ))
        .into_owned(),
    )
}

// ── Event log ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JournalEventKind {
    RunCreated {
        manifest_hash_hex: String,
        network: String,
        currency: String,
        mint: String,
        token_program: String,
        decimals: u8,
        row_count: usize,
        total_amount_raw: u64,
        requested_fee_mode: String,
    },
    PreflightCompleted {
        fee_payer_mode: String,
        estimated_fee_lamports: u64,
        missing_ata_rent_lamports: u64,
        reserve_lamports: u64,
        chunk_count: usize,
        max_token_raw: u64,
    },
    AuthorizationGranted {
        account_pubkey: String,
        max_token_raw: u64,
        max_transactions: usize,
        expires_at: DateTime<Utc>,
    },
    ChunkPrepared {
        chunk_index: u32,
        row_numbers: Vec<u64>,
        memo: String,
    },
    ChunkSigned {
        chunk_index: u32,
        row_numbers: Vec<u64>,
        signature: String,
        signed_transaction_base64: String,
        blockhash: String,
        last_valid_block_height: u64,
    },
    ChunkBroadcast {
        chunk_index: u32,
        signature: String,
    },
    ChunkConfirmed {
        chunk_index: u32,
        signature: String,
    },
    ChunkFailed {
        chunk_index: u32,
        reason: String,
        retryable: bool,
    },
    RunInterrupted {
        reason: String,
        confirmed: usize,
        failed: usize,
        remaining: usize,
    },
    RunCompleted {
        confirmed: usize,
        failed: usize,
        unknown: usize,
    },
}

impl JournalEventKind {
    fn chunk_index(&self) -> Option<u32> {
        match self {
            Self::ChunkPrepared { chunk_index, .. }
            | Self::ChunkSigned { chunk_index, .. }
            | Self::ChunkBroadcast { chunk_index, .. }
            | Self::ChunkConfirmed { chunk_index, .. }
            | Self::ChunkFailed { chunk_index, .. } => Some(*chunk_index),
            _ => None,
        }
    }
}

/// One durable line: a monotonic sequence number, an RFC 3339 UTC
/// timestamp, and the event payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JournalEvent {
    pub sequence: u64,
    pub timestamp: DateTime<Utc>,
    #[serde(flatten)]
    pub kind: JournalEventKind,
}

/// Proof that a `chunk_signed` event has been durably appended — written,
/// flushed, and `sync_data`'d — to the journal. The only way to construct
/// one is [`Journal::append_chunk_signed`], and
/// [`Journal::append_chunk_broadcast`] requires one: there is no code path
/// that reaches "broadcast" without first passing through a completed
/// fsync of the signed transaction.
#[derive(Debug, Clone, Copy)]
// `#[non_exhaustive]` only blocks *other crates* from constructing this
// struct literal — within `pay-core` it would have no effect, and any
// other module could then forge a permit without ever calling
// `append_chunk_signed`. The private field is deliberate: it is the actual
// enforcement mechanism (construction is only possible from this module),
// not just an API-evolution nicety.
#[allow(clippy::manual_non_exhaustive)]
pub struct ChunkBroadcastPermit {
    pub chunk_index: u32,
    _private: (),
}

/// An append-only JSONL writer for one `pay push` run. A single writer
/// should own the file for the run's lifetime; the plan's "single writer
/// task serializes events" requirement is the caller's responsibility (this
/// type is not internally synchronized across threads).
pub struct Journal {
    file: File,
    path: PathBuf,
    next_sequence: u64,
}

impl Journal {
    /// Create a brand-new journal file at `path`, mode `0600`, failing if it
    /// already exists (a fresh run must never silently continue someone
    /// else's journal).
    pub fn create_new(path: PathBuf) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("failed to create journal directory: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let mut options = OpenOptions::new();
        options.create_new(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&path).map_err(|e| {
            Error::Config(format!("failed to create journal {}: {e}", path.display()))
        })?;

        Ok(Self {
            file,
            path,
            next_sequence: 1,
        })
    }

    /// Re-open an existing journal for a resumed run. `next_sequence` picks
    /// up after the highest sequence number [`load_events`] can recover
    /// (tolerating one truncated final line).
    pub fn open_existing(path: PathBuf) -> Result<(Self, Vec<JournalEvent>)> {
        let events = load_events(&path)?;
        let next_sequence = events.last().map(|e| e.sequence + 1).unwrap_or(1);
        let file = OpenOptions::new().append(true).open(&path).map_err(|e| {
            Error::Config(format!("failed to open journal {}: {e}", path.display()))
        })?;
        Ok((
            Self {
                file,
                path,
                next_sequence,
            },
            events,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append_event(&mut self, kind: JournalEventKind) -> Result<JournalEvent> {
        let event = JournalEvent {
            sequence: self.next_sequence,
            timestamp: Utc::now(),
            kind,
        };
        let mut line = serde_json::to_string(&event)
            .map_err(|e| Error::Config(format!("failed to serialize journal event: {e}")))?;
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| Error::Config(format!("failed to write journal event: {e}")))?;
        self.file
            .flush()
            .map_err(|e| Error::Config(format!("failed to flush journal event: {e}")))?;
        self.file
            .sync_data()
            .map_err(|e| Error::Config(format!("failed to fsync journal event: {e}")))?;
        self.next_sequence += 1;
        Ok(event)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_run_created(
        &mut self,
        manifest_hash_hex: String,
        network: String,
        currency: String,
        mint: String,
        token_program: String,
        decimals: u8,
        row_count: usize,
        total_amount_raw: u64,
        requested_fee_mode: String,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::RunCreated {
            manifest_hash_hex,
            network,
            currency,
            mint,
            token_program,
            decimals,
            row_count,
            total_amount_raw,
            requested_fee_mode,
        })
    }

    pub fn append_preflight_completed(
        &mut self,
        fee_payer_mode: FeePayerMode,
        estimated_fee_lamports: u64,
        missing_ata_rent_lamports: u64,
        reserve_lamports: u64,
        chunk_count: usize,
        max_token_raw: u64,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::PreflightCompleted {
            fee_payer_mode: fee_payer_mode_label(fee_payer_mode).to_string(),
            estimated_fee_lamports,
            missing_ata_rent_lamports,
            reserve_lamports,
            chunk_count,
            max_token_raw,
        })
    }

    pub fn append_authorization_granted(
        &mut self,
        account_pubkey: String,
        max_token_raw: u64,
        max_transactions: usize,
        expires_at: DateTime<Utc>,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::AuthorizationGranted {
            account_pubkey,
            max_token_raw,
            max_transactions,
            expires_at,
        })
    }

    pub fn append_chunk_prepared(
        &mut self,
        chunk_index: u32,
        row_numbers: Vec<u64>,
        memo: String,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::ChunkPrepared {
            chunk_index,
            row_numbers,
            memo,
        })
    }

    /// Durably record a signature before any broadcast can occur. Returns
    /// both the event and a [`ChunkBroadcastPermit`] — the only credential
    /// [`Self::append_chunk_broadcast`] accepts.
    #[allow(clippy::too_many_arguments)]
    pub fn append_chunk_signed(
        &mut self,
        chunk_index: u32,
        row_numbers: Vec<u64>,
        signature: &Signature,
        signed_transaction_base64: String,
        blockhash: &Hash,
        last_valid_block_height: u64,
    ) -> Result<(JournalEvent, ChunkBroadcastPermit)> {
        let event = self.append_event(JournalEventKind::ChunkSigned {
            chunk_index,
            row_numbers,
            signature: signature.to_string(),
            signed_transaction_base64,
            blockhash: blockhash.to_string(),
            last_valid_block_height,
        })?;
        Ok((
            event,
            ChunkBroadcastPermit {
                chunk_index,
                _private: (),
            },
        ))
    }

    /// Record that a signed chunk was submitted to the network. Requires the
    /// [`ChunkBroadcastPermit`] produced by the matching
    /// [`Self::append_chunk_signed`] call for the same chunk.
    pub fn append_chunk_broadcast(
        &mut self,
        permit: ChunkBroadcastPermit,
        signature: &Signature,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::ChunkBroadcast {
            chunk_index: permit.chunk_index,
            signature: signature.to_string(),
        })
    }

    pub fn append_chunk_confirmed(
        &mut self,
        chunk_index: u32,
        signature: &Signature,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::ChunkConfirmed {
            chunk_index,
            signature: signature.to_string(),
        })
    }

    pub fn append_chunk_failed(
        &mut self,
        chunk_index: u32,
        reason: String,
        retryable: bool,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::ChunkFailed {
            chunk_index,
            reason,
            retryable,
        })
    }

    pub fn append_run_interrupted(
        &mut self,
        reason: String,
        confirmed: usize,
        failed: usize,
        remaining: usize,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::RunInterrupted {
            reason,
            confirmed,
            failed,
            remaining,
        })
    }

    pub fn append_run_completed(
        &mut self,
        confirmed: usize,
        failed: usize,
        unknown: usize,
    ) -> Result<JournalEvent> {
        self.append_event(JournalEventKind::RunCompleted {
            confirmed,
            failed,
            unknown,
        })
    }
}

fn fee_payer_mode_label(mode: FeePayerMode) -> &'static str {
    match mode {
        FeePayerMode::SelfFunded => "self_funded",
        FeePayerMode::Gasless => "gasless",
    }
}

/// Load every event from a journal file, tolerating exactly one truncated
/// final line (the crash-mid-write case) but rejecting any parse failure
/// that is not the last line, and rejecting non-monotonic sequence numbers
/// anywhere in the file.
pub fn load_events(path: &Path) -> Result<Vec<JournalEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::Config(format!("failed to read journal {}: {e}", path.display())))?;
    let lines: Vec<&str> = raw.split_inclusive('\n').collect();

    let mut events = Vec::with_capacity(lines.len());
    let last_index = lines.len().saturating_sub(1);
    let mut offset = 0usize;
    for (index, raw_line) in lines.iter().enumerate() {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            offset += raw_line.len();
            continue;
        }
        match serde_json::from_str::<JournalEvent>(line) {
            Ok(event) => events.push(event),
            Err(e) => {
                if index == last_index {
                    // Tolerate a crash mid-write: the last line may be a
                    // partial JSON record that never finished fsync'ing.
                    // Remove it before the append-mode writer reopens the
                    // file so its next event cannot merge into invalid JSON.
                    OpenOptions::new()
                        .write(true)
                        .open(path)
                        .and_then(|file| file.set_len(offset as u64))
                        .map_err(|error| {
                            Error::Config(format!(
                                "failed to truncate partial journal line in {}: {error}",
                                path.display()
                            ))
                        })?;
                    break;
                }
                return Err(Error::Config(format!(
                    "journal {} is corrupted at line {}: {e}",
                    path.display(),
                    index + 1
                )));
            }
        }
        offset += raw_line.len();
    }

    for pair in events.windows(2) {
        if pair[1].sequence <= pair[0].sequence {
            return Err(Error::Config(format!(
                "journal {} has non-monotonic sequence numbers ({} then {})",
                path.display(),
                pair[0].sequence,
                pair[1].sequence
            )));
        }
    }

    Ok(events)
}

// ── Resume reduction ─────────────────────────────────────────────────────

/// What the exact on-chain/off-chain status of a signature is, as observed
/// by a live RPC/pay-api lookup. Injected via [`ResumeRpc`] so
/// [`reduce_chunk_resume_action`] is unit-testable without a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcSignatureStatus {
    Confirmed,
    Failed,
    NotFound,
    /// RPC could not determine the answer (timeout, ambiguous response,
    /// etc.). This must never be treated as "safe to rebuild."
    Unknown,
}

/// The one RPC capability resume needs: signature status, and the current
/// confirmed block height (to decide blockhash expiry). A later slice wires
/// this to a live RPC client; tests wire it to a fixed fixture.
pub trait ResumeRpc {
    fn signature_status(&self, signature: &str) -> RpcSignatureStatus;
    fn current_block_height(&self) -> u64;
}

/// What the executor should do next for one chunk, derived purely from the
/// event log plus one RPC lookup. See the plan's "Journal and resume"
/// section for the exact rule this implements per branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkResumeAction {
    /// Already confirmed in the log — nothing to do.
    Skip,
    /// Direct mode: the signed bytes are still within their blockhash's
    /// validity window and RPC does not see the signature yet. Rebroadcast
    /// the exact same bytes; never rebuild while they remain valid.
    RebroadcastIdenticalBytes { signed_transaction_base64: String },
    /// Gasless mode: re-present the exact saved credential so pay-api's
    /// durable idempotency record returns the same final signature,
    /// regardless of how much time has passed.
    RepresentGaslessCredential { signed_transaction_base64: String },
    /// RPC now reports the previously unconfirmed signature as confirmed —
    /// record it and treat the chunk as done.
    RecordConfirmedThenSkip { signature: String },
    /// An on-chain or journal-recorded failure — a fresh attempt is allowed
    /// under policy (a later slice's retry budget), not indefinitely.
    RetryAfterFailure,
    /// The signed transaction's blockhash has proven expired and RPC does
    /// not see the signature: safe to rebuild the same logical chunk fresh.
    RebuildWithFreshBlockhash,
    /// No `chunk_signed` event exists yet for this chunk: it was never
    /// attempted, so it is safe to plan and sign it under the new permit.
    NeedsSigning,
    /// RPC could not determine the signature's status. Stop; never sign a
    /// replacement while the answer is unknown.
    StopUnknown { signature: String },
}

/// Reduce the event log into the single next action for `chunk_index`, per
/// the plan's resume rules.
pub fn reduce_chunk_resume_action(
    chunk_index: u32,
    events: &[JournalEvent],
    fee_payer_mode: FeePayerMode,
    rpc: &dyn ResumeRpc,
) -> ChunkResumeAction {
    let mut last_signed: Option<(String, String, u64)> = None;
    let mut confirmed = false;

    for event in events {
        if event.kind.chunk_index() != Some(chunk_index) {
            continue;
        }
        match &event.kind {
            JournalEventKind::ChunkSigned {
                signature,
                signed_transaction_base64,
                last_valid_block_height,
                ..
            } => {
                // A fresh `chunk_signed` (e.g. after a resign) supersedes
                // any earlier terminal state recorded for this chunk.
                last_signed = Some((
                    signature.clone(),
                    signed_transaction_base64.clone(),
                    *last_valid_block_height,
                ));
                confirmed = false;
            }
            JournalEventKind::ChunkConfirmed { .. } => confirmed = true,
            // A recorded failure never short-circuits straight to a fresh
            // attempt: the chunk's deterministic signature was journaled
            // before the broadcast that produced this failure (see the
            // module docs' fsync-before-broadcast invariant), so the
            // failure may describe a lost response to a submission that
            // still landed. The mode-specific reconciliation below always
            // re-checks that signature's real status before permitting a
            // replacement transfer — a `ChunkFailed` event by itself proves
            // nothing about whether the network ever saw the transaction.
            JournalEventKind::ChunkFailed { .. } => {}
            JournalEventKind::ChunkBroadcast { .. } => {}
            _ => {}
        }
    }

    if confirmed {
        return ChunkResumeAction::Skip;
    }

    let Some((signature, signed_transaction_base64, last_valid_block_height)) = last_signed else {
        return ChunkResumeAction::NeedsSigning;
    };

    match fee_payer_mode {
        // pay-api owns the authoritative status for a gasless chunk; there
        // is no client-signature-based RPC lookup that means anything here
        // (the client is not the fee payer, so its signature is not the
        // transaction id). Always re-present the saved credential.
        FeePayerMode::Gasless => ChunkResumeAction::RepresentGaslessCredential {
            signed_transaction_base64,
        },
        FeePayerMode::SelfFunded => match rpc.signature_status(&signature) {
            RpcSignatureStatus::Confirmed => {
                ChunkResumeAction::RecordConfirmedThenSkip { signature }
            }
            RpcSignatureStatus::Failed => ChunkResumeAction::RetryAfterFailure,
            RpcSignatureStatus::Unknown => ChunkResumeAction::StopUnknown { signature },
            RpcSignatureStatus::NotFound => {
                if rpc.current_block_height() <= last_valid_block_height {
                    ChunkResumeAction::RebroadcastIdenticalBytes {
                        signed_transaction_base64,
                    }
                } else {
                    ChunkResumeAction::RebuildWithFreshBlockhash
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedRpc {
        status: RpcSignatureStatus,
        current_block_height: u64,
    }

    impl ResumeRpc for FixedRpc {
        fn signature_status(&self, _signature: &str) -> RpcSignatureStatus {
            self.status
        }
        fn current_block_height(&self) -> u64 {
            self.current_block_height
        }
    }

    fn signed_event(chunk_index: u32, sequence: u64, last_valid_block_height: u64) -> JournalEvent {
        JournalEvent {
            sequence,
            timestamp: Utc::now(),
            kind: JournalEventKind::ChunkSigned {
                chunk_index,
                row_numbers: vec![2, 3],
                signature: "sig-1".to_string(),
                signed_transaction_base64: "YmFzZTY0".to_string(),
                blockhash: "hash-1".to_string(),
                last_valid_block_height,
            },
        }
    }

    // ── Journal writer / fsync-before-broadcast ──

    #[test]
    fn create_new_writes_mode_0600_and_appends_monotonic_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let mut journal = Journal::create_new(path.clone()).unwrap();

        let e1 = journal
            .append_run_created(
                "abc".into(),
                "mainnet".into(),
                "USDG".into(),
                "mint".into(),
                "token".into(),
                6,
                10,
                1_000,
                "auto".into(),
            )
            .unwrap();
        let e2 = journal
            .append_chunk_prepared(0, vec![2, 3], "memo".into())
            .unwrap();
        assert_eq!(e1.sequence, 1);
        assert_eq!(e2.sequence, 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let events = load_events(&path).unwrap();
        assert_eq!(events.len(), 2);
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        assert_eq!(contents.lines().count(), 2);

        let (mut reopened, _) = Journal::open_existing(path.clone()).unwrap();
        reopened
            .append_chunk_prepared(2, vec![4], "memo".into())
            .unwrap();
        assert_eq!(load_events(&path).unwrap().len(), 3);
    }

    #[test]
    fn append_chunk_broadcast_requires_a_signed_permit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let mut journal = Journal::create_new(path.clone()).unwrap();

        let signature = Signature::default();
        let blockhash = Hash::default();
        let (_signed_event, permit) = journal
            .append_chunk_signed(0, vec![2], &signature, "YmFzZTY0".into(), &blockhash, 1_000)
            .unwrap();

        // The only way to reach this call is with the permit `sign_chunk`
        // produced above, and that permit is only returned *after* the
        // fsync in `append_chunk_signed` has already completed — by the
        // time this line runs, the chunk_signed event is already durable.
        let broadcast_event = journal.append_chunk_broadcast(permit, &signature).unwrap();
        assert!(matches!(
            broadcast_event.kind,
            JournalEventKind::ChunkBroadcast { .. }
        ));

        let events = load_events(&path).unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0].kind,
            JournalEventKind::ChunkSigned { .. }
        ));
        assert!(matches!(
            events[1].kind,
            JournalEventKind::ChunkBroadcast { .. }
        ));
    }

    #[test]
    fn load_events_tolerates_one_truncated_final_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let mut journal = Journal::create_new(path.clone()).unwrap();
        journal
            .append_chunk_prepared(0, vec![2], "memo".into())
            .unwrap();
        journal
            .append_chunk_prepared(1, vec![3], "memo".into())
            .unwrap();
        drop(journal);

        // Simulate a crash mid-write: append a syntactically broken partial line.
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"sequence\":3,\"timestamp\":\"2026-01")
            .unwrap();

        let events = load_events(&path).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn load_events_rejects_corruption_before_the_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let mut journal = Journal::create_new(path.clone()).unwrap();
        journal
            .append_chunk_prepared(0, vec![2], "memo".into())
            .unwrap();
        drop(journal);

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"not json at all\n").unwrap();
        file.write_all(b"{\"sequence\":3,\"timestamp\":\"2026-01-01T00:00:00Z\",\"kind\":\"chunk_prepared\",\"chunk_index\":1,\"row_numbers\":[3],\"memo\":\"m\"}\n").unwrap();

        let err = load_events(&path).unwrap_err();
        assert!(err.to_string().contains("corrupted at line 2"), "{err}");
    }

    #[test]
    fn load_events_rejects_non_monotonic_sequences() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        std::fs::write(
            &path,
            "{\"sequence\":2,\"timestamp\":\"2026-01-01T00:00:00Z\",\"kind\":\"chunk_prepared\",\"chunk_index\":0,\"row_numbers\":[2],\"memo\":\"m\"}\n\
             {\"sequence\":1,\"timestamp\":\"2026-01-01T00:00:01Z\",\"kind\":\"chunk_prepared\",\"chunk_index\":1,\"row_numbers\":[3],\"memo\":\"m\"}\n",
        )
        .unwrap();

        let err = load_events(&path).unwrap_err();
        assert!(err.to_string().contains("non-monotonic"), "{err}");
    }

    #[test]
    fn open_existing_resumes_sequence_after_truncated_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("run.jsonl");
        let mut journal = Journal::create_new(path.clone()).unwrap();
        journal
            .append_chunk_prepared(0, vec![2], "memo".into())
            .unwrap();
        drop(journal);

        let (mut resumed, events) = Journal::open_existing(path.clone()).unwrap();
        assert_eq!(events.len(), 1);
        let next = resumed
            .append_chunk_prepared(1, vec![3], "memo".into())
            .unwrap();
        assert_eq!(next.sequence, 2);
    }

    // ── Resume reduction ──

    #[test]
    fn confirmed_chunk_is_skipped() {
        let events = vec![
            signed_event(0, 1, 1_000),
            JournalEvent {
                sequence: 2,
                timestamp: Utc::now(),
                kind: JournalEventKind::ChunkConfirmed {
                    chunk_index: 0,
                    signature: "sig-1".into(),
                },
            },
        ];
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Unknown,
            current_block_height: 0,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::Skip
        );
    }

    #[test]
    fn never_signed_chunk_needs_signing() {
        let events = vec![signed_event(1, 1, 1_000)]; // different chunk
        let rpc = FixedRpc {
            status: RpcSignatureStatus::NotFound,
            current_block_height: 0,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::NeedsSigning
        );
    }

    #[test]
    fn self_funded_within_blockheight_and_not_found_rebroadcasts_identical_bytes() {
        let events = vec![signed_event(0, 1, 1_000)];
        let rpc = FixedRpc {
            status: RpcSignatureStatus::NotFound,
            current_block_height: 500,
        };
        let action = reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc);
        assert_eq!(
            action,
            ChunkResumeAction::RebroadcastIdenticalBytes {
                signed_transaction_base64: "YmFzZTY0".to_string()
            }
        );
    }

    #[test]
    fn self_funded_past_blockheight_and_not_found_rebuilds_fresh() {
        let events = vec![signed_event(0, 1, 1_000)];
        let rpc = FixedRpc {
            status: RpcSignatureStatus::NotFound,
            current_block_height: 1_001,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::RebuildWithFreshBlockhash
        );
    }

    #[test]
    fn never_rebuilds_a_replacement_for_an_unknown_still_valid_signature() {
        let events = vec![signed_event(0, 1, 1_000)];
        // Blockhash is still valid (current height < last valid height) AND
        // RPC can't determine status: must stop, never rebuild.
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Unknown,
            current_block_height: 1,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::StopUnknown {
                signature: "sig-1".to_string()
            }
        );

        // Also true once the blockhash *has* expired: Unknown still wins.
        let rpc_expired = FixedRpc {
            status: RpcSignatureStatus::Unknown,
            current_block_height: 5_000,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc_expired),
            ChunkResumeAction::StopUnknown {
                signature: "sig-1".to_string()
            }
        );
    }

    #[test]
    fn self_funded_confirmed_by_rpc_after_lost_response() {
        let events = vec![signed_event(0, 1, 1_000)];
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Confirmed,
            current_block_height: 999,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::RecordConfirmedThenSkip {
                signature: "sig-1".to_string()
            }
        );
    }

    #[test]
    fn explicit_failure_still_reconciles_against_rpc_before_retrying() {
        // A `ChunkFailed` event (e.g. a lost `sendTransaction` response)
        // does not by itself prove the network never saw the transaction.
        // An `Unknown` RPC answer must still block a fresh attempt, exactly
        // as it would with no failure recorded at all.
        let mut events = vec![signed_event(0, 1, 1_000)];
        events.push(JournalEvent {
            sequence: 2,
            timestamp: Utc::now(),
            kind: JournalEventKind::ChunkFailed {
                chunk_index: 0,
                reason: "lost sendTransaction response".into(),
                retryable: true,
            },
        });
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Unknown,
            current_block_height: 0,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::StopUnknown {
                signature: "sig-1".to_string()
            }
        );
    }

    #[test]
    fn explicit_failure_is_confirmed_instead_of_retried_if_rpc_later_sees_it_landed() {
        // The exact double-submission risk Greptile flagged: a failed
        // broadcast attempt must not permit a fresh signature while RPC
        // shows the original signed transaction already confirmed.
        let mut events = vec![signed_event(0, 1, 1_000)];
        events.push(JournalEvent {
            sequence: 2,
            timestamp: Utc::now(),
            kind: JournalEventKind::ChunkFailed {
                chunk_index: 0,
                reason: "lost sendTransaction response".into(),
                retryable: true,
            },
        });
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Confirmed,
            current_block_height: 999,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::RecordConfirmedThenSkip {
                signature: "sig-1".to_string()
            }
        );
    }

    #[test]
    fn explicit_failure_confirmed_on_chain_still_retries() {
        let mut events = vec![signed_event(0, 1, 1_000)];
        events.push(JournalEvent {
            sequence: 2,
            timestamp: Utc::now(),
            kind: JournalEventKind::ChunkFailed {
                chunk_index: 0,
                reason: "insufficient funds".into(),
                retryable: false,
            },
        });
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Failed,
            current_block_height: 0,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::RetryAfterFailure
        );
    }

    #[test]
    fn gasless_always_represents_the_saved_credential_until_terminal() {
        let events = vec![signed_event(0, 1, 1_000)];
        // Even with a very stale blockhash, gasless resume never touches
        // direct-RPC signature lookups — pay-api's idempotency store is
        // authoritative.
        let rpc = FixedRpc {
            status: RpcSignatureStatus::Unknown,
            current_block_height: 999_999,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::Gasless, &rpc),
            ChunkResumeAction::RepresentGaslessCredential {
                signed_transaction_base64: "YmFzZTY0".to_string()
            }
        );
    }

    #[test]
    fn a_resign_event_supersedes_the_prior_terminal_state() {
        // First attempt failed, then a resign (fresh chunk_signed) happened
        // — the failure must not still gate the newer signature.
        let events = vec![
            signed_event(0, 1, 1_000),
            JournalEvent {
                sequence: 2,
                timestamp: Utc::now(),
                kind: JournalEventKind::ChunkFailed {
                    chunk_index: 0,
                    reason: "blockhash not found".into(),
                    retryable: true,
                },
            },
            signed_event(0, 3, 2_000),
        ];
        let rpc = FixedRpc {
            status: RpcSignatureStatus::NotFound,
            current_block_height: 1_500,
        };
        assert_eq!(
            reduce_chunk_resume_action(0, &events, FeePayerMode::SelfFunded, &rpc),
            ChunkResumeAction::RebroadcastIdenticalBytes {
                signed_transaction_base64: "YmFzZTY0".to_string()
            }
        );
    }
}
