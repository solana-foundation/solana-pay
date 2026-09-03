//! The one-approval batch signing permit.
//!
//! `pay push` shows one Touch ID / platform-auth prompt per process
//! invocation ([`AuthIntent::AuthorizeBatch`]), then loads the signer exactly
//! once into a [`BatchSigningPermit`]. Everything downstream
//! ([`super::executor::PushExecutor`]) hands the permit a *prepared*
//! transaction per chunk and gets back a signature or a rejection — it never
//! touches the raw signer. `sign_chunk` re-validates every field the plan
//! requires before producing a signature, so a compromised or buggy caller
//! cannot get the permit to sign anything outside the exact authorized plan.

use std::collections::HashMap;

use base64::Engine;
use chrono::{DateTime, Utc};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_hash::Hash;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::accounts::AccountsStore;
use crate::client::push::manifest::TransferManifest;
use crate::client::push::planner::{
    FeePayerMode, PlannedChunk, TransactionPlan, associated_token_program_id,
    ata_create_idempotent_discriminator, compute_budget_program_id,
    compute_unit_limit_discriminator, compute_unit_price_discriminator,
    derive_associated_token_address, memo_program_id, system_program_id, token_2022_program_id,
    token_program_id, transfer_checked_discriminator,
};
use crate::client::send::format_token_amount;
use crate::keystore::AuthIntent;
use crate::signer::{
    AuthOverride, ResolvedSigner, load_signer_for_network_with_intent_and_override,
};
use crate::{Error, Result};

/// A chunk may be re-signed with a fresh blockhash a bounded number of times
/// (e.g. after a proven blockhash expiry). This bounds retries without
/// granting an unlimited number of chances to sign new content.
pub const MAX_RESIGN_ATTEMPTS_PER_CHUNK: u32 = 5;

/// Everything shown on the one authorization prompt, plus what
/// [`AuthIntent::authorize_batch`] needs to pick a Linux Polkit action
/// bucket.
#[derive(Debug, Clone, Copy)]
pub struct BatchAuthorizationSummary<'a> {
    pub account: &'a str,
    pub currency: &'a str,
    pub currency_decimals: u8,
    pub network: &'a str,
    /// The exact recipient total from the plan (sum of every planned
    /// transfer). Always `<= max_total_raw`.
    pub recipient_total_raw: u64,
    /// The worst-case ceiling the permit may sign for, including the
    /// gasless reimbursement estimate when applicable. Equals
    /// `recipient_total_raw` for a self-funded plan.
    pub max_total_raw: u64,
}

/// Build the `AuthIntent::AuthorizeBatch` prompt for a plan. Stablecoins are
/// USD-pegged 1:1, so the raw ceiling doubles as its own dollar estimate for
/// the Linux Polkit payment-limit bucket.
fn authorization_intent(
    summary: &BatchAuthorizationSummary<'_>,
    recipient_count: usize,
    manifest_hash_prefix: &str,
) -> AuthIntent {
    let recipient_total_display =
        format_token_amount(summary.recipient_total_raw, summary.currency_decimals);
    let max_total_display = format_token_amount(summary.max_total_raw, summary.currency_decimals);
    let max_total_usd = format!("${max_total_display}");
    AuthIntent::authorize_batch(
        summary.account,
        recipient_count,
        &recipient_total_display,
        &max_total_display,
        &max_total_usd,
        summary.currency,
        summary.network,
        manifest_hash_prefix,
    )
}

/// Prove that every row `plan` intends to sign is exactly the row the
/// authorization prompt showed the user — same recipient, same amount, no
/// row added or dropped — before the permit accepts the plan at all.
///
/// `plan` and `manifest` are supplied separately by the caller, so nothing
/// upstream of this call structurally guarantees they describe the same
/// batch. Without this check a caller could show `manifest`'s recipients on
/// the approval prompt and then hand the permit a `plan` built from a
/// different recipient set; every downstream signature would be produced
/// against the unreviewed plan.
fn validate_plan_matches_manifest(
    manifest: &TransferManifest,
    plan: &TransactionPlan,
) -> Result<()> {
    let mut expected: HashMap<u64, (Pubkey, u64)> = manifest
        .rows
        .iter()
        .map(|row| (row.row_number, (row.recipient, row.amount_raw)))
        .collect();

    for chunk in &plan.chunks {
        for entry in &chunk.entries {
            match expected.remove(&entry.row_number) {
                Some((recipient, amount_raw))
                    if recipient == entry.recipient && amount_raw == entry.amount_raw => {}
                Some(_) => {
                    return Err(Error::Config(format!(
                        "plan row {} does not match the authorized manifest's recipient/amount",
                        entry.row_number
                    )));
                }
                None => {
                    return Err(Error::Config(format!(
                        "plan row {} is not present in the authorized manifest",
                        entry.row_number
                    )));
                }
            }
        }
    }

    if !expected.is_empty() {
        return Err(Error::Config(format!(
            "plan is missing {} manifest row(s) that were shown for approval",
            expected.len()
        )));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SignedChunkRecord {
    blockhash: Hash,
    last_valid_block_height: u64,
    attempts: u32,
}

/// Proof, supplied by the executor after querying RPC, that a chunk's
/// previously signed blockhash has expired and it is safe to re-sign the
/// same logical chunk with a fresh one. Permit-level pure validation
/// (`resign_chunk`) still refuses the re-sign unless `confirmed_current_block_height`
/// is strictly past `previous_last_valid_block_height` — this is what makes
/// "unexpired re-sign" a rejection rather than a trust-the-caller no-op.
#[derive(Debug, Clone, Copy)]
pub struct BlockhashExpiryProof {
    pub previous_blockhash: Hash,
    pub previous_last_valid_block_height: u64,
    pub confirmed_current_block_height: u64,
}

/// The result of successfully signing one chunk.
#[derive(Debug, Clone)]
pub struct SignedChunk {
    pub chunk_index: u32,
    pub row_numbers: Vec<u64>,
    /// The permit-held signer's signature. In self-funded mode this is also
    /// the transaction's final on-chain id; in gasless mode pay-api's
    /// fee-payer co-signature becomes the final id once broadcast.
    pub signature: Signature,
    pub signed_transaction_base64: String,
    pub blockhash: Hash,
    pub last_valid_block_height: u64,
}

/// The live, in-memory, one-approval batch signing authority.
///
/// Holds the loaded [`ResolvedSigner`] — a local keypair or a remote
/// backend, whichever the account resolves to — and nothing outside this
/// module ever gets a reference to it. Dies with the process; there is no
/// persistence and no serialization path for the signer itself.
pub struct BatchSigningPermit {
    manifest_hash: [u8; 32],
    account_pubkey: Pubkey,
    #[allow(dead_code)]
    // recorded for parity with the plan's field list; validated by callers that route by network.
    network_genesis_hash: [u8; 32],
    mint: Pubkey,
    token_program: Pubkey,
    decimals: u8,
    source_ata: Pubkey,
    fee_payer_mode: FeePayerMode,
    fee_payer: Pubkey,
    chunks: Vec<PlannedChunk>,
    max_token_raw: u64,
    max_transactions: usize,
    expires_at: DateTime<Utc>,

    signer: ResolvedSigner,
    runtime: tokio::runtime::Runtime,

    signed_amount_raw: u64,
    signed_tx_count: usize,
    signed_chunks: HashMap<u32, SignedChunkRecord>,
}

impl std::fmt::Debug for BatchSigningPermit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchSigningPermit")
            .field("account_pubkey", &self.account_pubkey)
            .field("fee_payer_mode", &self.fee_payer_mode)
            .field("chunks", &self.chunks.len())
            .field("max_token_raw", &self.max_token_raw)
            .field("expires_at", &self.expires_at)
            .field("signed_tx_count", &self.signed_tx_count)
            .finish_non_exhaustive()
    }
}

#[allow(clippy::too_many_arguments)]
impl BatchSigningPermit {
    /// Show the one `AuthorizeBatch` prompt, load the signer exactly once on
    /// success, and construct the permit for `plan`. `ttl` bounds how long
    /// the in-memory permit remains usable after authorization (it always
    /// also dies with the process).
    pub fn authorize(
        network: &str,
        store: &dyn AccountsStore,
        account_override: Option<&str>,
        network_genesis_hash: [u8; 32],
        manifest: &TransferManifest,
        plan: TransactionPlan,
        summary: BatchAuthorizationSummary<'_>,
        ttl: chrono::Duration,
        auth_override: AuthOverride,
    ) -> Result<Self> {
        validate_plan_matches_manifest(manifest, &plan)?;

        let manifest_hash_prefix = super::manifest_hash_prefix(&manifest.hash_hex()).to_string();
        let recipient_count = manifest.rows.len();
        let intent = authorization_intent(&summary, recipient_count, &manifest_hash_prefix);

        let (signer, _ephemeral) = load_signer_for_network_with_intent_and_override(
            network,
            store,
            account_override,
            &intent,
            auth_override,
        )?;
        let account_pubkey = signer.pubkey();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Config(format!("Failed to create signing runtime: {e}")))?;

        let source_ata = derive_associated_token_address(
            &account_pubkey,
            &manifest.context.mint,
            &manifest.context.token_program,
        );

        let max_transactions = plan.chunks.len();
        Ok(Self {
            manifest_hash: manifest.hash,
            account_pubkey,
            network_genesis_hash,
            mint: manifest.context.mint,
            token_program: manifest.context.token_program,
            decimals: manifest.context.decimals,
            source_ata,
            fee_payer_mode: plan.fee_payer_mode,
            fee_payer: plan.fee_payer,
            chunks: plan.chunks,
            max_token_raw: summary.max_total_raw,
            max_transactions,
            expires_at: Utc::now() + ttl,
            signer,
            runtime,
            signed_amount_raw: 0,
            signed_tx_count: 0,
            signed_chunks: HashMap::new(),
        })
    }

    pub fn account_pubkey(&self) -> Pubkey {
        self.account_pubkey
    }

    pub fn fee_payer(&self) -> Pubkey {
        self.fee_payer
    }

    pub fn fee_payer_mode(&self) -> FeePayerMode {
        self.fee_payer_mode
    }

    pub fn manifest_hash(&self) -> [u8; 32] {
        self.manifest_hash
    }

    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }

    pub fn signed_amount_raw(&self) -> u64 {
        self.signed_amount_raw
    }

    pub fn signed_transaction_count(&self) -> usize {
        self.signed_tx_count
    }

    fn plan_for(&self, chunk_index: u32) -> Result<&PlannedChunk> {
        self.chunks
            .get(chunk_index as usize)
            .ok_or_else(|| Error::Config(format!("permit has no chunk index {chunk_index}")))
    }

    fn ensure_not_expired(&self) -> Result<()> {
        if Utc::now() > self.expires_at {
            return Err(Error::Config(
                "batch signing permit has expired; re-run `pay push --resume` to authorize again"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Sign chunk `chunk_index` for the first time. Rejects a chunk that has
    /// already been signed once — see [`Self::resign_chunk`] for the bounded,
    /// proof-gated re-sign path.
    pub fn sign_chunk(
        &mut self,
        chunk_index: u32,
        prepared_transaction: &Transaction,
        last_valid_block_height: u64,
    ) -> Result<SignedChunk> {
        self.ensure_not_expired()?;
        if self.signed_chunks.contains_key(&chunk_index) {
            return Err(Error::Config(format!(
                "chunk {chunk_index} was already signed; use resign_chunk with a blockhash expiry proof"
            )));
        }

        let plan = self.plan_for(chunk_index)?.clone();
        self.validate_prepared_transaction(&plan, prepared_transaction)?;

        let chunk_total = plan.token_total_raw()?;
        let projected_amount = self
            .signed_amount_raw
            .checked_add(chunk_total)
            .ok_or_else(|| Error::Config("signed amount overflowed u64".to_string()))?;
        if projected_amount > self.max_token_raw {
            return Err(Error::Config(format!(
                "chunk {chunk_index} would sign {chunk_total} raw units, exceeding the authorized \
                 ceiling of {} (already signed {})",
                self.max_token_raw, self.signed_amount_raw
            )));
        }
        if self.signed_tx_count + 1 > self.max_transactions {
            return Err(Error::Config(format!(
                "chunk {chunk_index} would exceed the authorized transaction count ceiling of {}",
                self.max_transactions
            )));
        }

        // Reserve before producing a signature: the reservation stands even
        // if a network error happens after this call returns.
        self.signed_amount_raw = projected_amount;
        self.signed_tx_count += 1;

        let (signature, blockhash, encoded) = self.sign_transaction_bytes(prepared_transaction)?;
        self.signed_chunks.insert(
            chunk_index,
            SignedChunkRecord {
                blockhash,
                last_valid_block_height,
                attempts: 1,
            },
        );

        Ok(SignedChunk {
            chunk_index,
            row_numbers: plan.row_numbers(),
            signature,
            signed_transaction_base64: encoded,
            blockhash,
            last_valid_block_height,
        })
    }

    /// Re-sign the same logical chunk with a fresh blockhash after the
    /// journal/executor has proven the previous blockhash expired.
    ///
    /// Consumes a bounded per-chunk attempt counter, not another unit of the
    /// permit's token/transaction ceiling — this is the *same* recipient
    /// allowance, just re-signed with a new blockhash.
    pub fn resign_chunk(
        &mut self,
        chunk_index: u32,
        prepared_transaction: &Transaction,
        last_valid_block_height: u64,
        expiry: &BlockhashExpiryProof,
    ) -> Result<SignedChunk> {
        self.ensure_not_expired()?;
        let record = self
            .signed_chunks
            .get(&chunk_index)
            .copied()
            .ok_or_else(|| {
                Error::Config(format!(
                    "chunk {chunk_index} has no prior signature to re-sign; call sign_chunk first"
                ))
            })?;

        if expiry.previous_blockhash != record.blockhash
            || expiry.previous_last_valid_block_height != record.last_valid_block_height
        {
            return Err(Error::Config(format!(
                "chunk {chunk_index}: expiry proof does not match the permit's recorded prior signature"
            )));
        }
        if expiry.confirmed_current_block_height <= expiry.previous_last_valid_block_height {
            return Err(Error::Config(format!(
                "chunk {chunk_index}: prior blockhash has not proven expired yet \
                 (confirmed height {} <= last valid height {})",
                expiry.confirmed_current_block_height, expiry.previous_last_valid_block_height
            )));
        }
        if record.attempts >= MAX_RESIGN_ATTEMPTS_PER_CHUNK {
            return Err(Error::Config(format!(
                "chunk {chunk_index} exceeded the bounded re-sign attempt limit ({MAX_RESIGN_ATTEMPTS_PER_CHUNK})"
            )));
        }
        if prepared_transaction.message.recent_blockhash == record.blockhash {
            return Err(Error::Config(format!(
                "chunk {chunk_index}: re-sign must use a fresh blockhash, not the expired one"
            )));
        }

        let plan = self.plan_for(chunk_index)?.clone();
        self.validate_prepared_transaction(&plan, prepared_transaction)?;

        let (signature, blockhash, encoded) = self.sign_transaction_bytes(prepared_transaction)?;
        let attempts = record.attempts + 1;
        self.signed_chunks.insert(
            chunk_index,
            SignedChunkRecord {
                blockhash,
                last_valid_block_height,
                attempts,
            },
        );

        Ok(SignedChunk {
            chunk_index,
            row_numbers: plan.row_numbers(),
            signature,
            signed_transaction_base64: encoded,
            blockhash,
            last_valid_block_height,
        })
    }

    fn sign_transaction_bytes(
        &self,
        prepared_transaction: &Transaction,
    ) -> Result<(Signature, Hash, String)> {
        let mut tx = prepared_transaction.clone();
        let result = self
            .runtime
            .block_on(self.signer.sign_transaction(&mut tx))
            .map_err(|e| Error::Config(format!("failed to sign prepared transaction: {e}")))?;
        let (_, signature) = result.into_signed_transaction();
        let blockhash = tx.message.recent_blockhash;
        let bytes = bincode::serialize(&tx)
            .map_err(|e| Error::Config(format!("failed to serialize signed transaction: {e}")))?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        Ok((signature, blockhash, encoded))
    }

    /// Re-validate every field the plan requires before a signature is ever
    /// produced. See the module docs and the plan's "One-approval batch
    /// permit" section for the exact checklist.
    fn validate_prepared_transaction(&self, plan: &PlannedChunk, tx: &Transaction) -> Result<()> {
        let message = &tx.message;
        let chunk_index = plan.chunk_index;

        let actual_fee_payer = *message
            .account_keys
            .first()
            .ok_or_else(|| config_error(chunk_index, "prepared transaction has no accounts"))?;
        if actual_fee_payer != self.fee_payer {
            return Err(config_error(
                chunk_index,
                &format!(
                    "fee payer {actual_fee_payer} does not match the authorized fee payer {}",
                    self.fee_payer
                ),
            ));
        }

        let allowed_programs = [
            compute_budget_program_id(),
            associated_token_program_id(),
            token_program_id(),
            token_2022_program_id(),
            memo_program_id(),
        ];
        for ix in &message.instructions {
            let program_id = *message
                .account_keys
                .get(ix.program_id_index as usize)
                .ok_or_else(|| {
                    config_error(chunk_index, "instruction program id index out of range")
                })?;
            if !allowed_programs.contains(&program_id) {
                return Err(config_error(
                    chunk_index,
                    &format!("instruction uses disallowed program {program_id}"),
                ));
            }
        }

        let mut cursor = 0usize;

        let price_ix = instruction_at(message, cursor, chunk_index)?;
        let price = decode_compute_unit_price(message, price_ix, chunk_index)?;
        if price > plan.compute_unit_price_micro_lamports {
            return Err(config_error(
                chunk_index,
                &format!(
                    "compute-unit price {price} exceeds the approved ceiling of {}",
                    plan.compute_unit_price_micro_lamports
                ),
            ));
        }
        cursor += 1;

        let limit_ix = instruction_at(message, cursor, chunk_index)?;
        let limit = decode_compute_unit_limit(message, limit_ix, chunk_index)?;
        if limit > plan.compute_unit_limit {
            return Err(config_error(
                chunk_index,
                &format!(
                    "compute-unit limit {limit} exceeds the approved ceiling of {}",
                    plan.compute_unit_limit
                ),
            ));
        }
        cursor += 1;

        for entry in &plan.entries {
            let expected_dest_ata =
                derive_associated_token_address(&entry.recipient, &self.mint, &self.token_program);

            if entry.ata_creation_required {
                let ix = instruction_at(message, cursor, chunk_index)?;
                validate_ata_create(
                    message,
                    ix,
                    &self.fee_payer,
                    &entry.recipient,
                    &expected_dest_ata,
                    &self.mint,
                    &self.token_program,
                    chunk_index,
                )?;
                cursor += 1;
            }

            let ix = instruction_at(message, cursor, chunk_index)?;
            validate_transfer_checked(
                message,
                ix,
                &self.source_ata,
                &self.mint,
                &expected_dest_ata,
                &self.account_pubkey,
                entry.amount_raw,
                self.decimals,
                chunk_index,
            )?;
            cursor += 1;
        }

        let memo_ix = instruction_at(message, cursor, chunk_index)?;
        validate_memo(message, memo_ix, &plan.memo, chunk_index)?;
        cursor += 1;

        if cursor != message.instructions.len() {
            return Err(config_error(
                chunk_index,
                &format!(
                    "prepared transaction has {} unexpected trailing instruction(s)",
                    message.instructions.len() - cursor
                ),
            ));
        }

        Ok(())
    }
}

fn config_error(chunk_index: u32, detail: &str) -> Error {
    Error::Config(format!("chunk {chunk_index}: {detail}"))
}

fn instruction_at(
    message: &Message,
    index: usize,
    chunk_index: u32,
) -> Result<&solana_message::compiled_instruction::CompiledInstruction> {
    message.instructions.get(index).ok_or_else(|| {
        config_error(
            chunk_index,
            "prepared transaction is missing an expected instruction",
        )
    })
}

fn account_at(message: &Message, index: u8, chunk_index: u32) -> Result<Pubkey> {
    message
        .account_keys
        .get(index as usize)
        .copied()
        .ok_or_else(|| config_error(chunk_index, "instruction account index out of range"))
}

fn decode_compute_unit_price(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    chunk_index: u32,
) -> Result<u64> {
    let program_id = account_at(message, ix.program_id_index, chunk_index)?;
    if program_id != compute_budget_program_id() {
        return Err(config_error(
            chunk_index,
            "expected a compute-unit-price instruction",
        ));
    }
    if ix.data.first().copied() != Some(compute_unit_price_discriminator()) || ix.data.len() != 9 {
        return Err(config_error(
            chunk_index,
            "malformed compute-unit-price instruction",
        ));
    }
    Ok(u64::from_le_bytes(ix.data[1..9].try_into().unwrap()))
}

fn decode_compute_unit_limit(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    chunk_index: u32,
) -> Result<u32> {
    let program_id = account_at(message, ix.program_id_index, chunk_index)?;
    if program_id != compute_budget_program_id() {
        return Err(config_error(
            chunk_index,
            "expected a compute-unit-limit instruction",
        ));
    }
    if ix.data.first().copied() != Some(compute_unit_limit_discriminator()) || ix.data.len() != 5 {
        return Err(config_error(
            chunk_index,
            "malformed compute-unit-limit instruction",
        ));
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
    chunk_index: u32,
) -> Result<()> {
    let program_id = account_at(message, ix.program_id_index, chunk_index)?;
    if program_id != associated_token_program_id() {
        return Err(config_error(
            chunk_index,
            "expected an ATA-create instruction",
        ));
    }
    if ix.data != vec![ata_create_idempotent_discriminator()] {
        return Err(config_error(
            chunk_index,
            "ATA-create instruction is not the idempotent variant",
        ));
    }
    if ix.accounts.len() != 6 {
        return Err(config_error(
            chunk_index,
            "malformed ATA-create instruction",
        ));
    }
    let payer = account_at(message, ix.accounts[0], chunk_index)?;
    let ata = account_at(message, ix.accounts[1], chunk_index)?;
    let owner_account = account_at(message, ix.accounts[2], chunk_index)?;
    let mint_account = account_at(message, ix.accounts[3], chunk_index)?;
    let system_program = account_at(message, ix.accounts[4], chunk_index)?;
    let token_program_account = account_at(message, ix.accounts[5], chunk_index)?;

    if payer != *fee_payer {
        return Err(config_error(
            chunk_index,
            "ATA-create is not paid by the authorized fee payer",
        ));
    }
    if ata != *expected_ata {
        return Err(config_error(
            chunk_index,
            "ATA-create targets an unexpected address",
        ));
    }
    if owner_account != *owner {
        return Err(config_error(
            chunk_index,
            "ATA-create targets an owner outside the planned recipient set",
        ));
    }
    if mint_account != *mint {
        return Err(config_error(
            chunk_index,
            "ATA-create references the wrong mint",
        ));
    }
    if system_program != system_program_id() {
        return Err(config_error(
            chunk_index,
            "ATA-create references the wrong system program",
        ));
    }
    if token_program_account != *token_program {
        return Err(config_error(
            chunk_index,
            "ATA-create references the wrong token program",
        ));
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
    chunk_index: u32,
) -> Result<()> {
    let program_id = account_at(message, ix.program_id_index, chunk_index)?;
    let is_token = program_id == token_program_id();
    let is_token_2022 = program_id == token_2022_program_id();
    if !is_token && !is_token_2022 {
        return Err(config_error(
            chunk_index,
            "expected a Token/Token-2022 transfer instruction",
        ));
    }
    if ix.accounts.len() != 4 {
        return Err(config_error(
            chunk_index,
            "malformed transfer_checked instruction",
        ));
    }
    if ix.data.len() != 10 || ix.data[0] != transfer_checked_discriminator() {
        return Err(config_error(
            chunk_index,
            "expected a transfer_checked instruction",
        ));
    }
    let amount = u64::from_le_bytes(ix.data[1..9].try_into().unwrap());
    let ix_decimals = ix.data[9];

    let source = account_at(message, ix.accounts[0], chunk_index)?;
    let mint_account = account_at(message, ix.accounts[1], chunk_index)?;
    let destination = account_at(message, ix.accounts[2], chunk_index)?;
    let authority_account = account_at(message, ix.accounts[3], chunk_index)?;

    if source != *source_ata {
        return Err(config_error(
            chunk_index,
            "transfer source ATA does not match the permit",
        ));
    }
    if mint_account != *mint {
        return Err(config_error(
            chunk_index,
            "transfer references the wrong mint",
        ));
    }
    if destination != *expected_destination {
        return Err(config_error(
            chunk_index,
            "transfer destination does not match the planned recipient",
        ));
    }
    if authority_account != *authority {
        return Err(config_error(
            chunk_index,
            "transfer authority does not match the permit's account",
        ));
    }
    if amount != amount_raw {
        return Err(config_error(
            chunk_index,
            &format!("transfer amount {amount} does not match the planned amount {amount_raw}"),
        ));
    }
    if ix_decimals != decimals {
        return Err(config_error(
            chunk_index,
            "transfer decimals do not match the mint",
        ));
    }

    Ok(())
}

fn validate_memo(
    message: &Message,
    ix: &solana_message::compiled_instruction::CompiledInstruction,
    expected_memo: &str,
    chunk_index: u32,
) -> Result<()> {
    let program_id = account_at(message, ix.program_id_index, chunk_index)?;
    if program_id != memo_program_id() {
        return Err(config_error(chunk_index, "expected a memo instruction"));
    }
    match std::str::from_utf8(&ix.data) {
        Ok(memo) if memo == expected_memo => Ok(()),
        Ok(memo) => Err(config_error(
            chunk_index,
            &format!("memo `{memo}` does not match the planned memo `{expected_memo}`"),
        )),
        Err(_) => Err(config_error(chunk_index, "memo is not valid UTF-8")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Account, AccountsFile, Keystore, MemoryAccountsStore};
    use crate::client::push::manifest::{ManifestContext, parse_manifest_csv};
    use crate::client::push::planner::{AtaSnapshot, DestinationAtaStatus, pack_chunks};
    use solana_message::Message as LegacyMessage;

    fn fresh_account_and_store() -> (MemoryAccountsStore, Pubkey) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let mut full = Vec::with_capacity(64);
        full.extend_from_slice(&signing_key.to_bytes());
        full.extend_from_slice(&verifying_key.to_bytes());

        let account = Account {
            keystore: Keystore::Ephemeral,
            provider: None,
            active: false,
            auth_required: Some(false),
            pubkey: Some(bs58::encode(verifying_key.to_bytes()).into_string()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some(bs58::encode(&full).into_string()),
            created_at: Some("2026-08-12T00:00:00Z".to_string()),
            subscriptions: std::collections::BTreeMap::new(),
        };

        let mut file = AccountsFile::default();
        file.upsert("localnet", "default", account);
        let store = MemoryAccountsStore::with_file(file);
        let pubkey = Pubkey::new_from_array(verifying_key.to_bytes());
        (store, pubkey)
    }

    fn manifest_and_plan(
        sender: &Pubkey,
        rows: usize,
        fee_payer_mode: FeePayerMode,
        fee_payer: &Pubkey,
    ) -> (TransferManifest, TransactionPlan) {
        let mut csv = String::from("recipient,amount\n");
        for i in 0..rows {
            let recipient = Pubkey::new_from_array([(i + 10) as u8; 32]);
            csv.push_str(&format!("{recipient},1\n"));
        }
        let context = ManifestContext {
            network_genesis_hash: [3; 32],
            mint: Pubkey::new_from_array([77; 32]),
            token_program: token_program_id(),
            decimals: 6,
        };
        let manifest = parse_manifest_csv(csv.as_bytes(), context).unwrap();
        let ata = AtaSnapshot {
            sender_ata: derive_associated_token_address(
                sender,
                &manifest.context.mint,
                &manifest.context.token_program,
            ),
            sender_ata_exists: true,
            destinations: manifest
                .rows
                .iter()
                .map(|row| DestinationAtaStatus {
                    recipient: row.recipient,
                    ata: derive_associated_token_address(
                        &row.recipient,
                        &manifest.context.mint,
                        &manifest.context.token_program,
                    ),
                    exists: false,
                })
                .collect(),
        };
        let plan = pack_chunks(&manifest, &ata, fee_payer_mode, sender, fee_payer, 1).unwrap();
        (manifest, plan)
    }

    fn build_permit(
        rows: usize,
        fee_payer_mode: FeePayerMode,
    ) -> (BatchSigningPermit, TransferManifest, Pubkey) {
        let (store, sender) = fresh_account_and_store();
        let fee_payer = if matches!(fee_payer_mode, FeePayerMode::Gasless) {
            Pubkey::new_unique()
        } else {
            sender
        };
        let (manifest, plan) = manifest_and_plan(&sender, rows, fee_payer_mode, &fee_payer);
        let max_total_raw = plan.total_token_raw().unwrap();
        let summary = BatchAuthorizationSummary {
            account: "default",
            currency: "USDG",
            currency_decimals: 6,
            network: "localnet",
            recipient_total_raw: max_total_raw,
            max_total_raw,
        };
        let permit = BatchSigningPermit::authorize(
            "localnet",
            &store,
            Some("default"),
            manifest.context.network_genesis_hash,
            &manifest,
            plan,
            summary,
            chrono::Duration::hours(1),
            None,
        )
        .unwrap();
        (permit, manifest, sender)
    }

    fn build_unsigned_transaction(plan: &PlannedChunk, permit: &BatchSigningPermit) -> Transaction {
        build_unsigned_transaction_with(plan, permit, permit.fee_payer, permit.account_pubkey)
    }

    fn build_unsigned_transaction_with(
        plan: &PlannedChunk,
        permit: &BatchSigningPermit,
        fee_payer: Pubkey,
        authority: Pubkey,
    ) -> Transaction {
        use crate::client::push::planner::{
            compute_unit_limit_instruction, compute_unit_price_instruction,
        };
        use pay_kit::mpp::client::{TransferEntry, build_spl_transfer_batch_instructions};

        let last = plan.entries.len() - 1;
        let entries: Vec<TransferEntry> = plan
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| TransferEntry {
                recipient: e.recipient,
                amount: e.amount_raw,
                ata_creation_required: e.ata_creation_required,
                memo: if i == last {
                    Some(plan.memo.clone())
                } else {
                    None
                },
            })
            .collect();

        let mut instructions = vec![
            compute_unit_price_instruction(plan.compute_unit_price_micro_lamports),
            compute_unit_limit_instruction(plan.compute_unit_limit),
        ];
        instructions.extend(
            build_spl_transfer_batch_instructions(
                &authority,
                &permit.mint,
                &permit.token_program,
                permit.decimals,
                &fee_payer,
                &entries,
            )
            .unwrap(),
        );

        let message =
            LegacyMessage::new_with_blockhash(&instructions, Some(&fee_payer), &Hash::new_unique());
        Transaction::new_unsigned(message)
    }

    #[test]
    fn sign_chunk_accepts_a_faithful_prepared_transaction() {
        let (mut permit, _manifest, _sender) = build_permit(3, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction(&plan, &permit);

        let signed = permit.sign_chunk(0, &tx, 1_000).unwrap();
        assert_eq!(signed.chunk_index, 0);
        assert_eq!(signed.row_numbers, plan.row_numbers());
        assert_eq!(permit.signed_transaction_count(), 1);
        assert_eq!(permit.signed_amount_raw(), plan.token_total_raw().unwrap());
    }

    #[test]
    fn sign_chunk_rejects_wrong_recipient() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let mut plan = permit.chunks[0].clone();
        plan.entries[0].recipient = Pubkey::new_unique();
        let tx = build_unsigned_transaction(&plan, &permit);

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        // The row's ATA-create instruction (built for the wrong owner) is
        // validated before its transfer_checked instruction, so this is
        // rejected as an unexpected ATA-create target rather than a
        // mismatched transfer destination — both are the same underlying
        // "recipient does not match the plan" defect.
        let message = err.to_string();
        assert!(
            message.contains("destination") || message.contains("unexpected address"),
            "{message}"
        );
    }

    #[test]
    fn sign_chunk_rejects_wrong_amount() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let mut plan = permit.chunks[0].clone();
        plan.entries[0].amount_raw += 1;
        let tx = build_unsigned_transaction(&plan, &permit);

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("amount"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_wrong_mint() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let mut tx = build_unsigned_transaction(&plan, &permit);
        // Corrupt the mint account referenced by the first transfer_checked
        // instruction (index 3 in the compiled instruction list: price,
        // limit, transfer#0's mint account key).
        let bad_mint = Pubkey::new_unique();
        let idx = tx
            .message
            .account_keys
            .iter()
            .position(|k| *k == permit.mint)
            .unwrap();
        tx.message.account_keys[idx] = bad_mint;

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("mint"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_wrong_source_ata() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let mut tx = build_unsigned_transaction(&plan, &permit);
        let idx = tx
            .message
            .account_keys
            .iter()
            .position(|k| *k == permit.source_ata)
            .unwrap();
        tx.message.account_keys[idx] = Pubkey::new_unique();

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("source ATA"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_wrong_fee_payer() {
        let (mut permit, _manifest, sender) = build_permit(2, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let other_fee_payer = Pubkey::new_unique();
        let tx = build_unsigned_transaction_with(&plan, &permit, other_fee_payer, sender);

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("fee payer"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_wrong_memo() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let mut plan = permit.chunks[0].clone();
        plan.memo = "pay-push:v1:deadbeef:0".to_string();
        let tx = build_unsigned_transaction(&plan, &permit);

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("memo"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_disallowed_program() {
        let (mut permit, _manifest, _sender) = build_permit(1, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let mut tx = build_unsigned_transaction(&plan, &permit);
        // Swap the memo program for an arbitrary, disallowed program id.
        let disallowed = Pubkey::new_unique();
        let idx = tx
            .message
            .account_keys
            .iter()
            .position(|k| *k == memo_program_id())
            .unwrap();
        tx.message.account_keys[idx] = disallowed;

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("disallowed program"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_compute_budget_over_ceiling() {
        let (permit, _manifest, _sender) = build_permit(1, FeePayerMode::SelfFunded);
        let mut plan = permit.chunks[0].clone();
        // Build the transaction with the plan's real (authorized) price,
        // then lower the plan's own ceiling so that same price now exceeds
        // what `validate_prepared_transaction` will accept.
        let tx = build_unsigned_transaction(&plan, &permit);
        plan.compute_unit_price_micro_lamports = 0;

        let err = permit
            .validate_prepared_transaction(&plan, &tx)
            .unwrap_err();
        assert!(err.to_string().contains("compute-unit price"), "{err}");
    }

    #[test]
    fn sign_chunk_rejects_over_budget_amount() {
        let (mut permit, _manifest, sender) = build_permit(2, FeePayerMode::SelfFunded);
        permit.max_token_raw = 1; // lower than any real chunk total
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction_with(&plan, &permit, permit.fee_payer, sender);

        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(
            err.to_string().contains("exceeding the authorized ceiling"),
            "{err}"
        );
    }

    #[test]
    fn sign_chunk_twice_is_rejected_without_resign_proof() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction(&plan, &permit);
        permit.sign_chunk(0, &tx, 1_000).unwrap();

        let tx2 = build_unsigned_transaction(&plan, &permit);
        let err = permit.sign_chunk(0, &tx2, 1_000).unwrap_err();
        assert!(err.to_string().contains("already signed"), "{err}");
    }

    #[test]
    fn resign_chunk_rejects_unexpired_blockhash() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction(&plan, &permit);
        let signed = permit.sign_chunk(0, &tx, 1_000).unwrap();

        let tx2 = build_unsigned_transaction(&plan, &permit); // fresh random blockhash
        let proof = BlockhashExpiryProof {
            previous_blockhash: signed.blockhash,
            previous_last_valid_block_height: signed.last_valid_block_height,
            confirmed_current_block_height: 500, // still before last_valid_block_height (1000)
        };
        let err = permit.resign_chunk(0, &tx2, 1_500, &proof).unwrap_err();
        assert!(err.to_string().contains("has not proven expired"), "{err}");
    }

    #[test]
    fn resign_chunk_succeeds_after_proven_expiry_without_double_counting() {
        let (mut permit, _manifest, _sender) = build_permit(2, FeePayerMode::SelfFunded);
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction(&plan, &permit);
        let signed = permit.sign_chunk(0, &tx, 1_000).unwrap();
        let amount_after_first_sign = permit.signed_amount_raw();
        let count_after_first_sign = permit.signed_transaction_count();

        let tx2 = build_unsigned_transaction(&plan, &permit);
        let proof = BlockhashExpiryProof {
            previous_blockhash: signed.blockhash,
            previous_last_valid_block_height: signed.last_valid_block_height,
            confirmed_current_block_height: 2_000,
        };
        permit.resign_chunk(0, &tx2, 2_500, &proof).unwrap();

        assert_eq!(permit.signed_amount_raw(), amount_after_first_sign);
        assert_eq!(permit.signed_transaction_count(), count_after_first_sign);
    }

    #[test]
    fn permit_expiry_rejects_further_signing() {
        let (store, sender) = fresh_account_and_store();
        let (manifest, plan) = manifest_and_plan(&sender, 1, FeePayerMode::SelfFunded, &sender);
        let max_total_raw = plan.total_token_raw().unwrap();
        let summary = BatchAuthorizationSummary {
            account: "default",
            currency: "USDG",
            currency_decimals: 6,
            network: "localnet",
            recipient_total_raw: max_total_raw,
            max_total_raw,
        };
        let mut permit = BatchSigningPermit::authorize(
            "localnet",
            &store,
            Some("default"),
            manifest.context.network_genesis_hash,
            &manifest,
            plan,
            summary,
            chrono::Duration::seconds(-1), // already expired
            None,
        )
        .unwrap();
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction(&plan, &permit);
        let err = permit.sign_chunk(0, &tx, 1_000).unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn authorize_rejects_a_plan_whose_recipient_does_not_match_the_approved_manifest() {
        // The exact authorization-binding gap Greptile flagged: the prompt
        // is built from `manifest`, but a caller could hand `authorize` an
        // unrelated `plan` — here, one signing a different recipient than
        // the one the manifest (and therefore the approval prompt) showed.
        let (store, sender) = fresh_account_and_store();
        let (manifest, approved_plan) =
            manifest_and_plan(&sender, 1, FeePayerMode::SelfFunded, &sender);
        let mut mismatched_plan = approved_plan;
        let approved_recipient = manifest.rows[0].recipient;
        let swapped_recipient = Pubkey::new_unique();
        assert_ne!(approved_recipient, swapped_recipient);
        mismatched_plan.chunks[0].entries[0].recipient = swapped_recipient;

        let max_total_raw = mismatched_plan.total_token_raw().unwrap();
        let summary = BatchAuthorizationSummary {
            account: "default",
            currency: "USDG",
            currency_decimals: 6,
            network: "localnet",
            recipient_total_raw: max_total_raw,
            max_total_raw,
        };
        let err = BatchSigningPermit::authorize(
            "localnet",
            &store,
            Some("default"),
            manifest.context.network_genesis_hash,
            &manifest,
            mismatched_plan,
            summary,
            chrono::Duration::hours(1),
            None,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the authorized manifest's recipient/amount"),
            "{err}"
        );
    }

    #[test]
    fn gasless_permit_signs_as_authority_leaving_fee_payer_slot_unsigned() {
        let (mut permit, _manifest, sender) = build_permit(2, FeePayerMode::Gasless);
        let plan = permit.chunks[0].clone();
        let tx = build_unsigned_transaction_with(&plan, &permit, permit.fee_payer, sender);
        let signed = permit.sign_chunk(0, &tx, 1_000).unwrap();
        assert_ne!(permit.fee_payer, sender);
        assert_eq!(signed.chunk_index, 0);
    }
}
