//! Business logic behind `POST /api/v1/transfer-batches` — gasless CSV
//! batch payouts. The handler in `pay-api` only parses the HTTP request,
//! calls into this module, and maps the result to a response; every rule
//! below is what actually decides whether a chunk gets broadcast.
//!
//! ## Why this doesn't depend on `pay-core::client::push`
//!
//! `pay-core`'s `client::push` module (`manifest`/`planner`/`permit`/
//! `journal`) is the CLI's shared core, but `pay-api-core` cannot pull it
//! in: `permit::BatchSigningPermit` is built around a *local, one-time
//! Touch ID / Polkit authorization prompt* over a keystore-backed signer
//! (`pay-core::keystore`, `pay-core::signer`) — concepts that only make
//! sense for a desktop CLI holding the end user's own key. A stateless HTTP
//! handler has no keystore and no user to prompt; it signs with whatever
//! `pay-api/src/signer.rs` resolves at boot (a GCP-KMS key in production,
//! an in-memory key for local dev — see [`TransferBatchSponsor`]). So the
//! slice of *instruction-shape validation* this endpoint needs (compute
//! budget + idempotent-ATA-create + `transfer_checked` + memo, matching
//! `pay_core::client::push::planner`'s chunk shape byte-for-byte) is
//! re-derived here directly against PayKit, the same way the CLI's planner
//! and permit do — not imported from them. [`validate_prepared_transaction`]
//! is deliberately structured like `permit::BatchSigningPermit`'s
//! same-named validator for exactly this reason: the two are independent
//! implementations of one shared on-chain contract, so they *should* look
//! alike and are expected to be kept in sync by hand.
//!
//! ## Two-step, header-gated flow (mirrors `send.rs`)
//!
//! 1. **Quote** — POST with no `Authorization` header. [`validate_request`]
//!    checks the chunk's shape, then [`quote`] resolves live on-chain state
//!    (which destination ATAs are missing, a fresh blockhash) and returns
//!    HTTP 402 with a `TransferBatchChallengeBody`: the sponsor's fee-payer
//!    pubkey, the exact blockhash to build against, and its expiry.
//! 2. **Submit** — POST the *same* body again with
//!    `Authorization: Bearer <base64 bincode Transaction>`. The caller
//!    signed that exact chunk transaction locally as `sender` (`pay push`'s
//!    CLI does this with `permit::BatchSigningPermit::sign_chunk`, which
//!    leaves the fee-payer slot unsigned for a gasless chunk — see
//!    `journal::ChunkResumeAction::RepresentGaslessCredential`, whose doc
//!    comment already describes re-presenting this exact credential to
//!    pay-api on resume). [`submit`] decodes it, re-validates every
//!    instruction against the request's own fields (never trusting
//!    anything in the transaction that can be independently derived),
//!    verifies `sender`'s signature, appends the sponsor's fee-payer
//!    signature, broadcasts, waits for confirmation, and returns
//!    [`TransferBatchResponse`].
//!
//! A chunk is one atomic transaction — Solana has no notion of a
//! transaction landing "3 of 4 instructions succeeded" — so partial-chunk
//! failure is not a real state the chain can produce.
//! [`pay_api_types::transfer_batch::TransferBatchResponse`] deliberately
//! carries one signature and one status for the whole chunk rather than a
//! per-transfer outcome list; a failed chunk is reported as one HTTP error
//! (via [`TransferBatchError`]), not a 200 with partial results.
//!
//! ## Known simplifications (flagged, not silently worked around)
//!
//! - **Fee-reimbursement pricing is a static, operator-configured
//!   SOL/USD rate** ([`TransferBatchSettings::usd_per_sol`]), not a live
//!   oracle lookup like `/v1/send`'s Helius DAS / CoinGecko fallback. The
//!   quoted `feeReimbursementRaw` is informational only: unlike
//!   `/v1/send`'s `fee_within`, nothing in the on-chain chunk transaction
//!   actually collects it (see the next point) — a real settlement/billing
//!   path for it is follow-up work.
//! - **The chunk transaction never contains a reimbursement transfer.**
//!   `pay_core::client::push::permit::BatchSigningPermit::sign_chunk` (already
//!   shipped and tested) signs a gasless chunk as *exactly* compute-budget +
//!   `{ata-create?, transfer_checked}` per row + memo — no extra transfer to
//!   the fee payer. Since that CLI behavior is load-bearing and already
//!   tested, [`validate_prepared_transaction`] matches it exactly rather
//!   than inventing an on-chain reimbursement leg the real client never
//!   produces.
//! - **No stored challenge state.** This module is stateless: a quote's
//!   "expiry" is enforced implicitly by the blockhash's own
//!   `lastValidBlockHeight` (an expired chunk simply fails to land on-chain
//!   and `submit` surfaces that as an RPC error), not by a
//!   server-side session the endpoint would need a database for.
//! - **ATA rent is a configured flat lamport figure**
//!   ([`TransferBatchSettings::ata_rent_lamports`]), not a live
//!   `getMinimumBalanceForRentExemption` lookup, and does not distinguish
//!   Token vs Token-2022 account length. Both are the same kind of
//!   deliberate v1 simplification `pay_core::client::push::planner` already
//!   documents for its own rent/fee estimates.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::Duration as ChronoDuration;
use pay_api_types::transfer_batch::{
    BATCH_ID_HEX_LEN, MAX_TRANSFER_BATCH_TRANSFERS, MIN_TRANSFER_BATCH_TRANSFERS,
    TransferBatchChallengeBody, TransferBatchErrorBody, TransferBatchErrorDetail,
    TransferBatchRequest, TransferBatchResponse, TransferBatchStatus, TransferNetwork,
};
use pay_kit::mpp::protocol::solana::programs;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::ata::associated_token_address;
use crate::rpc::RpcClient;
use crate::stablecoin::Stablecoin;

/// Leading hex characters of `batchId` used in the on-chain memo. Mirrors
/// `pay_core::client::push::MANIFEST_HASH_PREFIX_LEN` — duplicated as a
/// plain constant (not imported) for the same reason every other small
/// constant in this module is duplicated rather than pulled in from
/// `pay-core`: see the module docs.
const MANIFEST_HASH_PREFIX_LEN: usize = 8;

/// Mirrors PayKit's private compute-budget/ATA-create/transfer-checked
/// instruction discriminators. Byte-for-byte identical to the constants of
/// the same name in `pay_core::client::push::planner`, which documents the
/// same duplication rationale: this validator must decode instructions
/// built by PayKit without depending on PayKit's private builder internals.
const ATA_CREATE_IDEMPOTENT_DISCRIMINATOR: u8 = 1;
const COMPUTE_UNIT_LIMIT_DISCRIMINATOR: u8 = 2;
const COMPUTE_UNIT_PRICE_DISCRIMINATOR: u8 = 3;
const TRANSFER_CHECKED_DISCRIMINATOR: u8 = 12;

/// The Solana account index a fee payer's signature always occupies:
/// `account_keys[0]` is always the fee payer, by protocol convention.
const FEE_PAYER_SIGNATURE_INDEX: usize = 0;

// ── Errors ───────────────────────────────────────────────────────────────

/// Every way a `/api/v1/transfer-batches` request or credential can be
/// rejected. Each variant carries enough detail for
/// [`TransferBatchError::to_body`] to produce an actionable
/// [`TransferBatchErrorBody`] (which field, why, whether retrying makes
/// sense) rather than a generic "bad request".
#[derive(Debug, thiserror::Error)]
pub enum TransferBatchError {
    #[error(
        "batchId must be exactly {BATCH_ID_HEX_LEN} lowercase hex characters (a BLAKE3 digest)"
    )]
    InvalidBatchId,
    #[error("sender is not a valid base58 Solana address")]
    InvalidSender,
    #[error("unsupported currency `{0}`")]
    UnsupportedCurrency(String),
    #[error(
        "transfers must contain between {MIN_TRANSFER_BATCH_TRANSFERS} and {MAX_TRANSFER_BATCH_TRANSFERS} entries, got {actual}"
    )]
    TransferCountOutOfBounds { actual: usize },
    #[error("transfers[{index}].recipient is not a valid base58 Solana address")]
    InvalidRecipient { index: usize },
    #[error(
        "transfers[{index}].amount `{amount}` is not a valid positive decimal amount at {decimals} decimals"
    )]
    InvalidAmount {
        index: usize,
        amount: String,
        decimals: u8,
    },
    #[error("transfers[{index}].rowId {row_id} duplicates transfers[{first_index}].rowId")]
    DuplicateRowId {
        index: usize,
        first_index: usize,
        row_id: u64,
    },
    #[error("push is not configured for network `{0}`")]
    NetworkNotConfigured(String),
    #[error("Authorization header is not a valid base64-encoded prepared transaction: {0}")]
    MalformedCredential(String),
    #[error("prepared transaction does not match the authorized chunk: {0}")]
    TransactionMismatch(String),
    #[error("sender's signature over the prepared transaction is missing or invalid")]
    InvalidSenderSignature,
    #[error("the fee-payer signature slot must be unsigned in the submitted transaction")]
    FeePayerSlotAlreadySigned,
    #[error("push sponsor is not configured: {0}")]
    SponsorNotConfigured(String),
    #[error("failed to co-sign the prepared transaction: {0}")]
    SigningFailed(String),
    #[error(transparent)]
    Rpc(#[from] crate::error::Error),
}

impl TransferBatchError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Rpc(err) => err.http_status(),
            Self::SponsorNotConfigured(_) => 503,
            Self::SigningFailed(_) => 502,
            _ => 400,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidBatchId => "invalid_batch_id",
            Self::InvalidSender => "invalid_sender",
            Self::UnsupportedCurrency(_) => "unsupported_currency",
            Self::TransferCountOutOfBounds { .. } => "invalid_transfer_count",
            Self::InvalidRecipient { .. } => "invalid_recipient",
            Self::InvalidAmount { .. } => "invalid_amount",
            Self::DuplicateRowId { .. } => "duplicate_row_id",
            Self::NetworkNotConfigured(_) => "network_not_configured",
            Self::MalformedCredential(_) => "malformed_credential",
            Self::TransactionMismatch(_) => "transaction_mismatch",
            Self::InvalidSenderSignature => "invalid_sender_signature",
            Self::FeePayerSlotAlreadySigned => "fee_payer_slot_already_signed",
            Self::SponsorNotConfigured(_) => "sponsor_not_configured",
            Self::SigningFailed(_) => "signing_failed",
            Self::Rpc(_) => "rpc_error",
        }
    }

    pub fn field(&self) -> Option<String> {
        match self {
            Self::InvalidBatchId => Some("batchId".to_string()),
            Self::InvalidSender => Some("sender".to_string()),
            Self::UnsupportedCurrency(_) => Some("currency".to_string()),
            Self::TransferCountOutOfBounds { .. } => Some("transfers".to_string()),
            Self::InvalidRecipient { index } => Some(format!("transfers[{index}].recipient")),
            Self::InvalidAmount { index, .. } => Some(format!("transfers[{index}].amount")),
            Self::DuplicateRowId { index, .. } => Some(format!("transfers[{index}].rowId")),
            Self::NetworkNotConfigured(_) => Some("network".to_string()),
            _ => None,
        }
    }

    /// Whether an identical retry (of the whole request, credential
    /// included) might succeed with no changes.
    pub fn retryable(&self) -> bool {
        match self {
            Self::SponsorNotConfigured(_) | Self::SigningFailed(_) => true,
            Self::Rpc(err) => matches!(
                err,
                crate::error::Error::RpcTimeout { .. }
                    | crate::error::Error::RpcRateLimited
                    | crate::error::Error::RpcTransport(_)
            ),
            _ => false,
        }
    }

    pub fn to_body(&self) -> TransferBatchErrorBody {
        TransferBatchErrorBody {
            error: TransferBatchErrorDetail {
                code: self.code().to_string(),
                message: self.to_string(),
                field: self.field(),
                retryable: self.retryable(),
            },
        }
    }
}

// ── Validation ───────────────────────────────────────────────────────────

/// One transfer after parsing: recipient and amount are structurally valid
/// and amount is already in the stablecoin's raw base units.
#[derive(Debug, Clone)]
pub struct ValidatedTransfer {
    pub row_id: u64,
    pub recipient: Pubkey,
    pub amount_raw: u64,
}

/// A `TransferBatchRequest` after every pure (no-I/O) check has passed.
#[derive(Debug, Clone)]
pub struct ValidatedChunk {
    /// Lowercased 64-hex-character batch id, as received.
    pub batch_id: String,
    pub chunk_index: u32,
    pub sender: Pubkey,
    pub network: TransferNetwork,
    pub coin: Stablecoin,
    pub transfers: Vec<ValidatedTransfer>,
    /// `pay-push:v1:<8-hex-char batchId prefix>:<chunkIndex>` — must match
    /// `pay_core::client::push::planner`'s memo format exactly, since the
    /// CLI stamps this same string into the transaction it signs.
    pub memo: String,
}

impl ValidatedChunk {
    /// Sum of every transfer's raw amount. `None` on overflow (impossible
    /// in practice at 8 transfers of `u64::MAX` each not summing past
    /// `u64::MAX`... except it *is* possible with adversarial input, so this
    /// is checked, not assumed).
    pub fn recipient_amount_raw(&self) -> Option<u64> {
        self.transfers
            .iter()
            .try_fold(0u64, |acc, t| acc.checked_add(t.amount_raw))
    }
}

/// Validate a `TransferBatchRequest`'s shape: no RPC, no config beyond the
/// stablecoin registry every other endpoint already resolves at boot.
pub fn validate_request(
    request: &TransferBatchRequest,
    stablecoins: &[Stablecoin],
) -> Result<ValidatedChunk, TransferBatchError> {
    if request.batch_id.len() != BATCH_ID_HEX_LEN
        || request.batch_id.bytes().any(|b| b.is_ascii_uppercase())
        || blake3::Hash::from_hex(&request.batch_id).is_err()
    {
        return Err(TransferBatchError::InvalidBatchId);
    }

    let sender =
        Pubkey::from_str(request.sender.trim()).map_err(|_| TransferBatchError::InvalidSender)?;

    let currency = request.currency.trim();
    let coin = stablecoins
        .iter()
        .find(|c| c.symbol.eq_ignore_ascii_case(currency) || c.mint.to_string() == currency)
        .cloned()
        .ok_or_else(|| TransferBatchError::UnsupportedCurrency(request.currency.clone()))?;

    if request.transfers.len() < MIN_TRANSFER_BATCH_TRANSFERS
        || request.transfers.len() > MAX_TRANSFER_BATCH_TRANSFERS
    {
        return Err(TransferBatchError::TransferCountOutOfBounds {
            actual: request.transfers.len(),
        });
    }

    let mut transfers = Vec::with_capacity(request.transfers.len());
    let mut seen_row_ids: Vec<u64> = Vec::with_capacity(request.transfers.len());
    for (index, entry) in request.transfers.iter().enumerate() {
        if let Some(first_index) = seen_row_ids.iter().position(|&r| r == entry.row_id) {
            return Err(TransferBatchError::DuplicateRowId {
                index,
                first_index,
                row_id: entry.row_id,
            });
        }
        seen_row_ids.push(entry.row_id);

        let recipient = Pubkey::from_str(entry.recipient.trim())
            .map_err(|_| TransferBatchError::InvalidRecipient { index })?;
        let amount_raw =
            parse_positive_base_units(&entry.amount, coin.decimals).ok_or_else(|| {
                TransferBatchError::InvalidAmount {
                    index,
                    amount: entry.amount.clone(),
                    decimals: coin.decimals,
                }
            })?;
        transfers.push(ValidatedTransfer {
            row_id: entry.row_id,
            recipient,
            amount_raw,
        });
    }

    let batch_id = request.batch_id.to_ascii_lowercase();
    let prefix = &batch_id[..MANIFEST_HASH_PREFIX_LEN];
    let memo = format!("pay-push:v1:{prefix}:{}", request.chunk_index);

    Ok(ValidatedChunk {
        batch_id,
        chunk_index: request.chunk_index,
        sender,
        network: request.network,
        coin,
        transfers,
        memo,
    })
}

fn parse_positive_base_units(amount: &str, decimals: u8) -> Option<u64> {
    let raw = pay_kit::mpp::parse_units(amount.trim(), decimals).ok()?;
    let parsed = raw.parse::<u64>().ok()?;
    if parsed == 0 { None } else { Some(parsed) }
}

// ── Runtime ──────────────────────────────────────────────────────────────

/// The pay-api-controlled signer that co-signs every gasless chunk as fee
/// payer. Resolved once at boot by `pay-api/src/signer.rs` (GCP KMS in
/// production, an in-memory key for local dev) — this module never touches
/// key material directly, only the [`SolanaSigner`] trait object.
pub struct TransferBatchSponsor {
    pub fee_payer_pubkey: Pubkey,
    pub signer: Arc<dyn SolanaSigner>,
}

/// Operator-configured pricing and transaction-shape ceilings. See the
/// module docs' "Known simplifications" for why these are static config
/// rather than live lookups.
#[derive(Debug, Clone)]
pub struct TransferBatchSettings {
    pub compute_unit_price_micro_lamports: u64,
    pub compute_unit_limit: u32,
    pub estimated_fee_lamports: u64,
    pub ata_rent_lamports: u64,
    pub usd_per_sol: f64,
    pub challenge_ttl: ChronoDuration,
    pub confirm_timeout: Duration,
}

/// Everything [`quote`] and [`submit`] need for one request, borrowed from
/// `pay-api`'s `AppState` for the duration of the call.
pub struct TransferBatchRuntime<'a> {
    pub rpc: &'a RpcClient,
    pub rpc_url: &'a str,
    pub sponsor: &'a TransferBatchSponsor,
    pub settings: &'a TransferBatchSettings,
}

impl<'a> TransferBatchRuntime<'a> {
    /// Resolve the RPC endpoint for `chunk.network` and bundle it with the
    /// sponsor/settings pay-api already resolved at boot.
    pub fn resolve(
        chunk: &ValidatedChunk,
        rpc: &'a RpcClient,
        networks: &'a std::collections::HashMap<TransferNetwork, String>,
        sponsor: &'a TransferBatchSponsor,
        settings: &'a TransferBatchSettings,
    ) -> Result<Self, TransferBatchError> {
        let rpc_url = networks
            .get(&chunk.network)
            .map(String::as_str)
            .ok_or_else(|| {
                TransferBatchError::NetworkNotConfigured(chunk.network.as_str().to_string())
            })?;
        Ok(Self {
            rpc,
            rpc_url,
            sponsor,
            settings,
        })
    }
}

// ── Quote (402) ──────────────────────────────────────────────────────────

/// Resolve live on-chain state for `chunk` and price it. This is the only
/// I/O `quote` performs: two RPC calls (`getMultipleAccounts` for
/// destination ATAs, `getLatestBlockhash`).
pub async fn quote(
    runtime: &TransferBatchRuntime<'_>,
    chunk: &ValidatedChunk,
) -> Result<TransferBatchChallengeBody, TransferBatchError> {
    let dest_atas: Vec<String> = chunk
        .transfers
        .iter()
        .map(|t| {
            associated_token_address(&t.recipient, &chunk.coin.mint, &chunk.coin.token_program)
                .to_string()
        })
        .collect();
    let accounts = runtime
        .rpc
        .get_multiple_accounts(runtime.rpc_url, &dest_atas)
        .await
        .map_err(TransferBatchError::Rpc)?;
    let missing_ata_count = accounts.iter().filter(|a| a.is_none()).count();

    let (recent_blockhash, challenge_last_valid_block_height) = runtime
        .rpc
        .get_latest_blockhash_with_last_valid_height(runtime.rpc_url)
        .await
        .map_err(TransferBatchError::Rpc)?;

    let recipient_amount_raw = chunk.recipient_amount_raw().ok_or_else(|| {
        TransferBatchError::TransactionMismatch("recipient amount total overflowed u64".to_string())
    })?;

    let estimated_fee_lamports = runtime.settings.estimated_fee_lamports.saturating_add(
        (missing_ata_count as u64).saturating_mul(runtime.settings.ata_rent_lamports),
    );

    let fee_reimbursement_raw = fee_reimbursement_base_units(
        estimated_fee_lamports,
        runtime.settings.usd_per_sol,
        chunk.coin.decimals,
    )?;

    let total_amount_raw = recipient_amount_raw
        .checked_add(fee_reimbursement_raw)
        .ok_or_else(|| {
            TransferBatchError::TransactionMismatch("total amount overflowed u64".to_string())
        })?;

    Ok(TransferBatchChallengeBody {
        batch_id: chunk.batch_id.clone(),
        chunk_index: chunk.chunk_index,
        transfer_count: chunk.transfers.len(),
        recipient_amount_raw: recipient_amount_raw.to_string(),
        fee_reimbursement_raw: fee_reimbursement_raw.to_string(),
        total_amount_raw: total_amount_raw.to_string(),
        estimated_fee_lamports,
        missing_ata_count,
        fee_payer: runtime.sponsor.fee_payer_pubkey.to_string(),
        recent_blockhash,
        challenge_expires_at: (chrono::Utc::now() + runtime.settings.challenge_ttl).to_rfc3339(),
        challenge_last_valid_block_height,
    })
}

fn fee_reimbursement_base_units(
    estimated_fee_lamports: u64,
    usd_per_sol: f64,
    decimals: u8,
) -> Result<u64, TransferBatchError> {
    if !usd_per_sol.is_finite() || usd_per_sol <= 0.0 {
        return Err(TransferBatchError::SponsorNotConfigured(
            "push.usdPerSol must be a positive finite number".to_string(),
        ));
    }
    let scale = 10f64.powi(decimals as i32);
    let raw = ((estimated_fee_lamports as f64 / 1_000_000_000f64) * usd_per_sol * scale).ceil();
    if !raw.is_finite() || raw < 0.0 || raw > u64::MAX as f64 {
        return Err(TransferBatchError::SponsorNotConfigured(
            "computed fee reimbursement is out of range".to_string(),
        ));
    }
    Ok(raw as u64)
}

// ── Submit (200) ─────────────────────────────────────────────────────────

/// Decode, validate, co-sign, and broadcast a caller-signed chunk
/// transaction. `prepared_transaction_base64` is the exact bearer
/// credential produced by `permit::BatchSigningPermit::sign_chunk` for a
/// gasless chunk (base64 `bincode` of a `Transaction` with `sender`'s
/// signature present and the fee-payer slot still default/unsigned).
pub async fn submit(
    runtime: &TransferBatchRuntime<'_>,
    chunk: &ValidatedChunk,
    prepared_transaction_base64: &str,
) -> Result<TransferBatchResponse, TransferBatchError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(prepared_transaction_base64.trim())
        .map_err(|e| TransferBatchError::MalformedCredential(e.to_string()))?;
    let mut tx: Transaction = bincode::deserialize(&bytes)
        .map_err(|e| TransferBatchError::MalformedCredential(e.to_string()))?;

    validate_prepared_transaction(chunk, runtime, &tx)?;
    verify_sender_signature(&tx, &chunk.sender)?;

    if tx
        .signatures
        .get(FEE_PAYER_SIGNATURE_INDEX)
        .copied()
        .unwrap_or_default()
        != Signature::default()
    {
        return Err(TransferBatchError::FeePayerSlotAlreadySigned);
    }

    runtime
        .sponsor
        .signer
        .sign_transaction(&mut tx)
        .await
        .map_err(|e| TransferBatchError::SigningFailed(e.to_string()))?;

    let signed_bytes =
        bincode::serialize(&tx).map_err(|e| TransferBatchError::SigningFailed(e.to_string()))?;
    let signed_b64 = base64::engine::general_purpose::STANDARD.encode(signed_bytes);

    let signature = runtime
        .rpc
        .send_raw_transaction(runtime.rpc_url, &signed_b64)
        .await
        .map_err(TransferBatchError::Rpc)?;
    runtime
        .rpc
        .confirm_signature(
            runtime.rpc_url,
            &signature,
            runtime.settings.confirm_timeout,
        )
        .await
        .map_err(TransferBatchError::Rpc)?;

    Ok(TransferBatchResponse {
        batch_id: chunk.batch_id.clone(),
        chunk_index: chunk.chunk_index,
        row_ids: chunk.transfers.iter().map(|t| t.row_id).collect(),
        signature,
        status: TransferBatchStatus::Confirmed,
    })
}

fn verify_sender_signature(tx: &Transaction, sender: &Pubkey) -> Result<(), TransferBatchError> {
    let index = tx
        .message
        .account_keys
        .iter()
        .position(|k| k == sender)
        .ok_or(TransferBatchError::InvalidSenderSignature)?;
    let signature = tx
        .signatures
        .get(index)
        .ok_or(TransferBatchError::InvalidSenderSignature)?;
    if *signature == Signature::default() {
        return Err(TransferBatchError::InvalidSenderSignature);
    }
    if !signature.verify(sender.as_ref(), &tx.message_data()) {
        return Err(TransferBatchError::InvalidSenderSignature);
    }
    Ok(())
}

/// Re-validate every field the chunk requires before a fee-payer signature
/// is ever produced. Structured like (and kept in sync by hand with)
/// `pay_core::client::push::permit::BatchSigningPermit::validate_prepared_transaction` —
/// see the module docs for why the two can't share code.
fn validate_prepared_transaction(
    chunk: &ValidatedChunk,
    runtime: &TransferBatchRuntime<'_>,
    tx: &Transaction,
) -> Result<(), TransferBatchError> {
    let message = &tx.message;

    let actual_fee_payer = *message
        .account_keys
        .first()
        .ok_or_else(|| mismatch("prepared transaction has no accounts"))?;
    if actual_fee_payer != runtime.sponsor.fee_payer_pubkey {
        return Err(mismatch(&format!(
            "fee payer {actual_fee_payer} does not match the configured sponsor {}",
            runtime.sponsor.fee_payer_pubkey
        )));
    }

    let allowed_programs = [
        program_id(programs::COMPUTE_BUDGET_PROGRAM),
        program_id(programs::ASSOCIATED_TOKEN_PROGRAM),
        program_id(programs::TOKEN_PROGRAM),
        program_id(programs::TOKEN_2022_PROGRAM),
        program_id(programs::MEMO_PROGRAM),
    ];
    for ix in &message.instructions {
        let pid = account_at(message, ix.program_id_index)?;
        if !allowed_programs.contains(&pid) {
            return Err(mismatch(&format!(
                "instruction uses disallowed program {pid}"
            )));
        }
    }

    let mut cursor = 0usize;

    let price_ix = instruction_at(message, cursor)?;
    let price = decode_compute_unit_price(message, price_ix)?;
    if price > runtime.settings.compute_unit_price_micro_lamports {
        return Err(mismatch(&format!(
            "compute-unit price {price} exceeds the sponsor's ceiling of {}",
            runtime.settings.compute_unit_price_micro_lamports
        )));
    }
    cursor += 1;

    let limit_ix = instruction_at(message, cursor)?;
    let limit = decode_compute_unit_limit(message, limit_ix)?;
    if limit > runtime.settings.compute_unit_limit {
        return Err(mismatch(&format!(
            "compute-unit limit {limit} exceeds the sponsor's ceiling of {}",
            runtime.settings.compute_unit_limit
        )));
    }
    cursor += 1;

    let source_ata =
        associated_token_address(&chunk.sender, &chunk.coin.mint, &chunk.coin.token_program);

    for entry in &chunk.transfers {
        let expected_dest_ata = associated_token_address(
            &entry.recipient,
            &chunk.coin.mint,
            &chunk.coin.token_program,
        );

        // An idempotent ATA-create instruction is optional: whether the
        // destination already exists is a live on-chain fact the caller
        // observed independently at sign time, and idempotent creation is
        // harmless either way. If present, it must be well-formed and
        // target exactly this recipient — never trust its presence alone.
        if let Some(ix) = message.instructions.get(cursor) {
            let pid = account_at(message, ix.program_id_index)?;
            if pid == program_id(programs::ASSOCIATED_TOKEN_PROGRAM) {
                validate_ata_create(
                    message,
                    ix,
                    &runtime.sponsor.fee_payer_pubkey,
                    &entry.recipient,
                    &expected_dest_ata,
                    &chunk.coin.mint,
                    &chunk.coin.token_program,
                )?;
                cursor += 1;
            }
        }

        let transfer_ix = instruction_at(message, cursor)?;
        validate_transfer_checked(
            message,
            transfer_ix,
            &source_ata,
            &chunk.coin.mint,
            &expected_dest_ata,
            &chunk.sender,
            entry.amount_raw,
            chunk.coin.decimals,
        )?;
        cursor += 1;
    }

    let memo_ix = instruction_at(message, cursor)?;
    validate_memo(message, memo_ix, &chunk.memo)?;
    cursor += 1;

    if cursor != message.instructions.len() {
        return Err(mismatch(&format!(
            "prepared transaction has {} unexpected trailing instruction(s)",
            message.instructions.len() - cursor
        )));
    }

    Ok(())
}

fn mismatch(detail: &str) -> TransferBatchError {
    TransferBatchError::TransactionMismatch(detail.to_string())
}

fn program_id(value: &str) -> Pubkey {
    Pubkey::from_str(value).expect("PayKit program id constants are always valid base58")
}

fn instruction_at(
    message: &Message,
    index: usize,
) -> Result<&solana_message::compiled_instruction::CompiledInstruction, TransferBatchError> {
    message
        .instructions
        .get(index)
        .ok_or_else(|| mismatch("prepared transaction is missing an expected instruction"))
}

fn account_at(message: &Message, index: u8) -> Result<Pubkey, TransferBatchError> {
    message
        .account_keys
        .get(index as usize)
        .copied()
        .ok_or_else(|| mismatch("instruction account index out of range"))
}

fn decode_compute_unit_price(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
) -> Result<u64, TransferBatchError> {
    let program = account_at(message, ix.program_id_index)?;
    if program != program_id(programs::COMPUTE_BUDGET_PROGRAM) {
        return Err(mismatch("expected a compute-unit-price instruction"));
    }
    if ix.data.first().copied() != Some(COMPUTE_UNIT_PRICE_DISCRIMINATOR) || ix.data.len() != 9 {
        return Err(mismatch("malformed compute-unit-price instruction"));
    }
    Ok(u64::from_le_bytes(ix.data[1..9].try_into().unwrap()))
}

fn decode_compute_unit_limit(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
) -> Result<u32, TransferBatchError> {
    let program = account_at(message, ix.program_id_index)?;
    if program != program_id(programs::COMPUTE_BUDGET_PROGRAM) {
        return Err(mismatch("expected a compute-unit-limit instruction"));
    }
    if ix.data.first().copied() != Some(COMPUTE_UNIT_LIMIT_DISCRIMINATOR) || ix.data.len() != 5 {
        return Err(mismatch("malformed compute-unit-limit instruction"));
    }
    Ok(u32::from_le_bytes(ix.data[1..5].try_into().unwrap()))
}

#[allow(clippy::too_many_arguments)]
fn validate_ata_create(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    fee_payer: &Pubkey,
    owner: &Pubkey,
    expected_ata: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Result<(), TransferBatchError> {
    if ix.data != [ATA_CREATE_IDEMPOTENT_DISCRIMINATOR] {
        return Err(mismatch(
            "ATA-create instruction is not the idempotent variant",
        ));
    }
    if ix.accounts.len() != 6 {
        return Err(mismatch("malformed ATA-create instruction"));
    }
    let payer = account_at(message, ix.accounts[0])?;
    let ata = account_at(message, ix.accounts[1])?;
    let owner_account = account_at(message, ix.accounts[2])?;
    let mint_account = account_at(message, ix.accounts[3])?;
    let system_program = account_at(message, ix.accounts[4])?;
    let token_program_account = account_at(message, ix.accounts[5])?;

    if payer != *fee_payer {
        return Err(mismatch(
            "ATA-create is not paid by the sponsor's fee payer",
        ));
    }
    if ata != *expected_ata {
        return Err(mismatch("ATA-create targets an unexpected address"));
    }
    if owner_account != *owner {
        return Err(mismatch(
            "ATA-create targets an owner outside the authorized chunk",
        ));
    }
    if mint_account != *mint {
        return Err(mismatch("ATA-create references the wrong mint"));
    }
    if system_program != program_id(programs::SYSTEM_PROGRAM) {
        return Err(mismatch("ATA-create references the wrong system program"));
    }
    if token_program_account != *token_program {
        return Err(mismatch("ATA-create references the wrong token program"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_transfer_checked(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    source_ata: &Pubkey,
    mint: &Pubkey,
    expected_destination: &Pubkey,
    authority: &Pubkey,
    amount_raw: u64,
    decimals: u8,
) -> Result<(), TransferBatchError> {
    let program = account_at(message, ix.program_id_index)?;
    let is_token = program == program_id(programs::TOKEN_PROGRAM);
    let is_token_2022 = program == program_id(programs::TOKEN_2022_PROGRAM);
    if !is_token && !is_token_2022 {
        return Err(mismatch("expected a Token/Token-2022 transfer instruction"));
    }
    if ix.accounts.len() != 4 {
        return Err(mismatch("malformed transfer_checked instruction"));
    }
    if ix.data.len() != 10 || ix.data[0] != TRANSFER_CHECKED_DISCRIMINATOR {
        return Err(mismatch("expected a transfer_checked instruction"));
    }
    let amount = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
    let ix_decimals = ix.data[9];

    let source = account_at(message, ix.accounts[0])?;
    let mint_account = account_at(message, ix.accounts[1])?;
    let destination = account_at(message, ix.accounts[2])?;
    let authority_account = account_at(message, ix.accounts[3])?;

    if source != *source_ata {
        return Err(mismatch(
            "transfer source ATA does not match the authorized sender",
        ));
    }
    if mint_account != *mint {
        return Err(mismatch("transfer references the wrong mint"));
    }
    if destination != *expected_destination {
        return Err(mismatch(
            "transfer destination does not match the authorized chunk",
        ));
    }
    if authority_account != *authority {
        return Err(mismatch(
            "transfer authority does not match the authorized sender",
        ));
    }
    if amount != amount_raw {
        return Err(mismatch(&format!(
            "transfer amount {amount} does not match the authorized amount {amount_raw}"
        )));
    }
    if ix_decimals != decimals {
        return Err(mismatch("transfer decimals do not match the mint"));
    }
    Ok(())
}

fn validate_memo(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    expected_memo: &str,
) -> Result<(), TransferBatchError> {
    let program = account_at(message, ix.program_id_index)?;
    if program != program_id(programs::MEMO_PROGRAM) {
        return Err(mismatch("expected a memo instruction"));
    }
    match std::str::from_utf8(&ix.data) {
        Ok(memo) if memo == expected_memo => Ok(()),
        Ok(memo) => Err(mismatch(&format!(
            "memo `{memo}` does not match the authorized memo `{expected_memo}`"
        ))),
        Err(_) => Err(mismatch("memo is not valid UTF-8")),
    }
}

// Only used to build well-formed test fixtures below; kept internal.
#[cfg(test)]
fn compute_unit_price_instruction(micro_lamports: u64) -> solana_instruction::Instruction {
    let mut data = vec![COMPUTE_UNIT_PRICE_DISCRIMINATOR];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    solana_instruction::Instruction {
        program_id: program_id(programs::COMPUTE_BUDGET_PROGRAM),
        accounts: vec![],
        data,
    }
}

#[cfg(test)]
fn compute_unit_limit_instruction(units: u32) -> solana_instruction::Instruction {
    let mut data = vec![COMPUTE_UNIT_LIMIT_DISCRIMINATOR];
    data.extend_from_slice(&units.to_le_bytes());
    solana_instruction::Instruction {
        program_id: program_id(programs::COMPUTE_BUDGET_PROGRAM),
        accounts: vec![],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stablecoin::TokenProgram;
    use pay_api_types::transfer_batch::TransferBatchEntry;
    use pay_kit::mpp::client::{TransferEntry, build_spl_transfer_batch_instructions};
    use solana_hash::Hash;

    fn coin() -> Stablecoin {
        Stablecoin {
            symbol: "USDG".to_string(),
            mint: Pubkey::new_unique(),
            token_program: TokenProgram::SplToken.program_id(),
            decimals: 6,
        }
    }

    fn valid_request(sender: &Pubkey, transfers: usize) -> TransferBatchRequest {
        TransferBatchRequest {
            batch_id: "a".repeat(BATCH_ID_HEX_LEN),
            chunk_index: 0,
            sender: sender.to_string(),
            currency: "USDG".to_string(),
            network: TransferNetwork::Localnet,
            transfers: (0..transfers)
                .map(|i| TransferBatchEntry {
                    row_id: i as u64,
                    recipient: Pubkey::new_unique().to_string(),
                    amount: "1.5".to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn validate_request_accepts_a_well_formed_chunk() {
        let sender = Pubkey::new_unique();
        let request = valid_request(&sender, 3);
        let chunk = validate_request(&request, &[coin()]).unwrap();
        assert_eq!(chunk.transfers.len(), 3);
        assert_eq!(chunk.sender, sender);
        assert_eq!(chunk.memo, "pay-push:v1:aaaaaaaa:0");
        assert_eq!(chunk.recipient_amount_raw().unwrap(), 1_500_000 * 3);
    }

    #[test]
    fn validate_request_rejects_bad_batch_id_shape() {
        let sender = Pubkey::new_unique();
        let mut request = valid_request(&sender, 1);
        request.batch_id = "not-hex".to_string();
        let err = validate_request(&request, &[coin()]).unwrap_err();
        assert!(matches!(err, TransferBatchError::InvalidBatchId));
        assert_eq!(err.field(), Some("batchId".to_string()));
    }

    #[test]
    fn validate_request_rejects_uppercase_batch_id() {
        let sender = Pubkey::new_unique();
        let mut request = valid_request(&sender, 1);
        request.batch_id = "A".repeat(BATCH_ID_HEX_LEN);
        assert!(matches!(
            validate_request(&request, &[coin()]).unwrap_err(),
            TransferBatchError::InvalidBatchId
        ));
    }

    #[test]
    fn validate_request_rejects_too_many_transfers() {
        let sender = Pubkey::new_unique();
        let request = valid_request(&sender, MAX_TRANSFER_BATCH_TRANSFERS + 1);
        let err = validate_request(&request, &[coin()]).unwrap_err();
        assert!(matches!(
            err,
            TransferBatchError::TransferCountOutOfBounds { actual } if actual == MAX_TRANSFER_BATCH_TRANSFERS + 1
        ));
    }

    #[test]
    fn validate_request_rejects_empty_transfers() {
        let sender = Pubkey::new_unique();
        let request = valid_request(&sender, 0);
        assert!(matches!(
            validate_request(&request, &[coin()]).unwrap_err(),
            TransferBatchError::TransferCountOutOfBounds { actual: 0 }
        ));
    }

    #[test]
    fn validate_request_rejects_unsupported_currency() {
        let sender = Pubkey::new_unique();
        let mut request = valid_request(&sender, 1);
        request.currency = "NOPE".to_string();
        let err = validate_request(&request, &[coin()]).unwrap_err();
        assert!(matches!(err, TransferBatchError::UnsupportedCurrency(c) if c == "NOPE"));
    }

    #[test]
    fn validate_request_rejects_invalid_recipient() {
        let sender = Pubkey::new_unique();
        let mut request = valid_request(&sender, 1);
        request.transfers[0].recipient = "not-a-pubkey".to_string();
        let err = validate_request(&request, &[coin()]).unwrap_err();
        assert!(matches!(
            err,
            TransferBatchError::InvalidRecipient { index: 0 }
        ));
        assert_eq!(err.field(), Some("transfers[0].recipient".to_string()));
    }

    #[test]
    fn validate_request_rejects_zero_amount() {
        let sender = Pubkey::new_unique();
        let mut request = valid_request(&sender, 1);
        request.transfers[0].amount = "0".to_string();
        assert!(matches!(
            validate_request(&request, &[coin()]).unwrap_err(),
            TransferBatchError::InvalidAmount { index: 0, .. }
        ));
    }

    #[test]
    fn validate_request_rejects_duplicate_row_ids() {
        let sender = Pubkey::new_unique();
        let mut request = valid_request(&sender, 2);
        request.transfers[1].row_id = request.transfers[0].row_id;
        let err = validate_request(&request, &[coin()]).unwrap_err();
        assert!(matches!(
            err,
            TransferBatchError::DuplicateRowId {
                index: 1,
                first_index: 0,
                ..
            }
        ));
    }

    /// A throwaway in-memory keypair wrapped as a `pay_kit` signer, the same
    /// way both the sponsor and (in real gasless pushes) the CLI's
    /// `permit::BatchSigningPermit` wrap theirs. The pubkey is sliced
    /// directly out of the 64-byte Solana keypair layout
    /// (`secret[0..32] || public[32..64]`) rather than going through the
    /// `solana_signer::Signer` trait, so tests don't need a direct
    /// dependency on the `solana-signer` crate just for one accessor.
    fn fresh_signer() -> (pay_kit::mpp::solana_keychain::Signer, Pubkey) {
        let keypair = solana_keypair::Keypair::new();
        let bytes = keypair.to_bytes();
        let pubkey = Pubkey::new_from_array(bytes[32..64].try_into().unwrap());
        let json = serde_json::to_string(&bytes.to_vec()).unwrap();
        let signer = pay_kit::mpp::solana_keychain::Signer::from_memory(&json).unwrap();
        assert_eq!(signer.pubkey(), pubkey);
        (signer, pubkey)
    }

    fn sponsor() -> (TransferBatchSponsor, Pubkey) {
        let (signer, pubkey) = fresh_signer();
        (
            TransferBatchSponsor {
                fee_payer_pubkey: pubkey,
                signer: Arc::new(signer),
            },
            pubkey,
        )
    }

    fn settings() -> TransferBatchSettings {
        TransferBatchSettings {
            compute_unit_price_micro_lamports: 10_000,
            compute_unit_limit: 400_000,
            estimated_fee_lamports: 10_000,
            ata_rent_lamports: 2_039_280,
            usd_per_sol: 150.0,
            challenge_ttl: ChronoDuration::minutes(2),
            confirm_timeout: Duration::from_secs(30),
        }
    }

    fn unsigned_chunk_transaction(
        chunk: &ValidatedChunk,
        fee_payer: &Pubkey,
        settings: &TransferBatchSettings,
    ) -> Transaction {
        let last = chunk.transfers.len() - 1;
        let entries: Vec<TransferEntry> = chunk
            .transfers
            .iter()
            .enumerate()
            .map(|(i, t)| TransferEntry {
                recipient: t.recipient,
                amount: t.amount_raw,
                ata_creation_required: false,
                memo: if i == last {
                    Some(chunk.memo.clone())
                } else {
                    None
                },
            })
            .collect();

        let mut instructions = vec![
            compute_unit_price_instruction(settings.compute_unit_price_micro_lamports),
            compute_unit_limit_instruction(settings.compute_unit_limit),
        ];
        instructions.extend(
            build_spl_transfer_batch_instructions(
                &chunk.sender,
                &chunk.coin.mint,
                &chunk.coin.token_program,
                chunk.coin.decimals,
                fee_payer,
                &entries,
            )
            .unwrap(),
        );

        let message =
            Message::new_with_blockhash(&instructions, Some(fee_payer), &Hash::new_unique());
        Transaction::new_unsigned(message)
    }

    /// Build the exact chunk transaction `sender_signer` would produce via
    /// `permit::BatchSigningPermit::sign_chunk` for a gasless chunk: signed
    /// as the sending authority, fee-payer slot left default/unsigned.
    async fn build_signed_chunk_transaction(
        chunk: &ValidatedChunk,
        fee_payer: &Pubkey,
        sender_signer: &pay_kit::mpp::solana_keychain::Signer,
        settings: &TransferBatchSettings,
    ) -> Transaction {
        let mut tx = unsigned_chunk_transaction(chunk, fee_payer, settings);
        sender_signer.sign_transaction(&mut tx).await.unwrap();
        tx
    }

    #[tokio::test]
    async fn submit_rejects_a_transaction_with_no_sender_signature() {
        let (_sender_signer, sender) = fresh_signer();
        let request = valid_request(&sender, 1);
        let coin = coin();
        let chunk = validate_request(&request, &[coin]).unwrap();

        let (sponsor, fee_payer) = sponsor();
        let settings = settings();
        let tx = unsigned_chunk_transaction(&chunk, &fee_payer, &settings);
        let bytes = bincode::serialize(&tx).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);

        let rpc = RpcClient::new(Duration::from_secs(1)).unwrap();
        let networks = std::collections::HashMap::from([(
            TransferNetwork::Localnet,
            "http://localhost:1".to_string(),
        )]);
        let runtime =
            TransferBatchRuntime::resolve(&chunk, &rpc, &networks, &sponsor, &settings).unwrap();

        let err = submit(&runtime, &chunk, &b64).await.unwrap_err();
        assert!(matches!(err, TransferBatchError::InvalidSenderSignature));
    }

    #[tokio::test]
    async fn validate_prepared_transaction_accepts_a_faithful_transaction() {
        let (sender_signer, sender) = fresh_signer();
        let request = valid_request(&sender, 2);
        let coin = coin();
        let chunk = validate_request(&request, &[coin]).unwrap();
        let (sponsor, fee_payer) = sponsor();
        let settings = settings();

        let tx =
            build_signed_chunk_transaction(&chunk, &fee_payer, &sender_signer, &settings).await;
        let networks = std::collections::HashMap::from([(
            TransferNetwork::Localnet,
            "http://localhost:1".to_string(),
        )]);
        let rpc = RpcClient::new(Duration::from_secs(1)).unwrap();
        let runtime =
            TransferBatchRuntime::resolve(&chunk, &rpc, &networks, &sponsor, &settings).unwrap();

        assert!(validate_prepared_transaction(&chunk, &runtime, &tx).is_ok());
        assert!(verify_sender_signature(&tx, &chunk.sender).is_ok());
    }

    #[tokio::test]
    async fn validate_prepared_transaction_rejects_wrong_fee_payer() {
        let (sender_signer, sender) = fresh_signer();
        let request = valid_request(&sender, 1);
        let coin = coin();
        let chunk = validate_request(&request, &[coin]).unwrap();
        let (sponsor, _fee_payer) = sponsor();
        let settings = settings();

        let other_fee_payer = Pubkey::new_unique();
        let tx =
            build_signed_chunk_transaction(&chunk, &other_fee_payer, &sender_signer, &settings)
                .await;
        let networks = std::collections::HashMap::from([(
            TransferNetwork::Localnet,
            "http://localhost:1".to_string(),
        )]);
        let rpc = RpcClient::new(Duration::from_secs(1)).unwrap();
        let runtime =
            TransferBatchRuntime::resolve(&chunk, &rpc, &networks, &sponsor, &settings).unwrap();

        let err = validate_prepared_transaction(&chunk, &runtime, &tx).unwrap_err();
        assert!(err.to_string().contains("fee payer"), "{err}");
    }

    #[tokio::test]
    async fn validate_prepared_transaction_rejects_tampered_amount() {
        let (sender_signer, sender) = fresh_signer();
        let request = valid_request(&sender, 1);
        let coin = coin();
        let chunk = validate_request(&request, std::slice::from_ref(&coin)).unwrap();
        let (sponsor, fee_payer) = sponsor();
        let settings = settings();

        // Build against a *different* (higher) amount than what was
        // validated, simulating a caller trying to smuggle a bigger
        // transfer past the quoted chunk.
        let mut tampered = chunk.clone();
        tampered.transfers[0].amount_raw += 1;
        let tx =
            build_signed_chunk_transaction(&tampered, &fee_payer, &sender_signer, &settings).await;

        let networks = std::collections::HashMap::from([(
            TransferNetwork::Localnet,
            "http://localhost:1".to_string(),
        )]);
        let rpc = RpcClient::new(Duration::from_secs(1)).unwrap();
        let runtime =
            TransferBatchRuntime::resolve(&chunk, &rpc, &networks, &sponsor, &settings).unwrap();

        let err = validate_prepared_transaction(&chunk, &runtime, &tx).unwrap_err();
        assert!(err.to_string().contains("amount"), "{err}");
    }

    #[test]
    fn fee_reimbursement_base_units_rejects_non_positive_price() {
        assert!(fee_reimbursement_base_units(10_000, 0.0, 6).is_err());
        assert!(fee_reimbursement_base_units(10_000, f64::NAN, 6).is_err());
    }

    #[test]
    fn fee_reimbursement_base_units_scales_by_decimals() {
        // 10_000 lamports = 0.00001 SOL, at $150/SOL = $0.0015, at 6
        // decimals that's 1_500 raw units (rounded up).
        let raw = fee_reimbursement_base_units(10_000, 150.0, 6).unwrap();
        assert_eq!(raw, 1_500);
    }
}
