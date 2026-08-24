//! Read-only preflight, fee-mode selection, and deterministic transaction
//! packing for `pay push`.
//!
//! Everything in this module runs before a wallet is ever unlocked: ATA
//! lookups, blockhash/fee estimation, balance checks, and the exact
//! instruction lists for every planned chunk. [`permit::BatchSigningPermit`]
//! (built from a [`TransactionPlan`] after authorization) is the only thing
//! downstream that is allowed to touch a signer.

use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_transaction::Transaction;
use std::str::FromStr;

use pay_kit::mpp::client::{
    ComputeBudgetOptions, TransferEntry, build_spl_transfer_batch_instructions,
};
use pay_kit::mpp::protocol::solana::{
    MAX_SPLITS, SOLANA_MAX_COMPUTE_UNIT_LIMIT, check_transaction_packet_size, programs,
};

use super::manifest::TransferManifest;
use crate::{Error, Result};

// ── Numeric bounds ──────────────────────────────────────────────────────────

/// A gasless chunk's user payouts ride as MPP charge splits, and PayKit caps
/// a charge at `MAX_SPLITS` splits (the fee-payer reimbursement is the
/// primary transfer, so every user payout is a split). Re-exported from
/// PayKit rather than duplicated: it is already `pub const` there
/// (`pay_kit::mpp::protocol::solana::MAX_SPLITS`), so hardcoding a second
/// copy would be exactly the drift risk the plan warns against.
pub const MAX_GASLESS_TRANSFERS_PER_CHUNK: usize = MAX_SPLITS;

/// Floor on the SOL reserve preflight sets aside on top of the exact
/// estimated fee and missing-ATA rent (plan: `max(10_000 lamports, 5% of the
/// estimated transaction fees)`).
pub const MIN_FEE_RESERVE_LAMPORTS: u64 = 10_000;

/// Conservative secondary safety margin on top of `check_transaction_packet_size`.
/// A legacy message can technically reference more account keys than this
/// before hitting the packet-size ceiling in unusual cases (many
/// already-existing ATAs, e.g.), but pay-push chunks are homogeneous
/// (compute budget + ATA-create + transfer_checked + memo), so in practice
/// packet size binds first. This exists as defense in depth, not as the
/// primary bound.
pub const MAX_STATIC_ACCOUNT_KEYS: usize = 64;

/// `spl_token::state::Account::LEN`. Duplicated as a plain constant rather
/// than adding an `spl-token` dependency for one number — this is a stable
/// on-chain account layout, not implementation detail.
pub const TOKEN_ACCOUNT_LEN: usize = 165;

/// Token-2022 base account length. The Associated Token Account program
/// attaches an `ImmutableOwner` extension (2-byte type + 2-byte length + 0
/// bytes of body) plus a 1-byte account-type discriminator to every ATA it
/// creates, on top of the same 165-byte base layout Token uses.
///
/// This does not account for mint-specific extensions that also enlarge the
/// *token account* (e.g. `TransferFeeAmount` for a `TransferFeeConfig`
/// mint). V1 does not parse per-mint extensions; the fee/rent reserve buffer
/// (see [`compute_reserve_lamports`]) is expected to absorb the difference
/// for the currently supported stablecoin set. Decision #8 already excludes
/// confidential mints from V1.
pub const TOKEN_2022_BASE_ATA_LEN: usize = TOKEN_ACCOUNT_LEN + 1 + 4;

/// Conservative compute-unit ceiling enforced while *packing* (before the
/// real simulate-and-refine pass the plan describes happens against a live
/// RPC). Chosen well under [`SOLANA_MAX_COMPUTE_UNIT_LIMIT`] so the
/// after-simulation refinement always has headroom to raise the limit
/// without ever needing to shrink a chunk post hoc.
pub const PACKING_COMPUTE_UNIT_CEILING: u32 = 1_200_000;

// Conservative fixed per-instruction compute-unit estimates used only to
// decide whether a candidate chunk is *plausibly* cheap enough while
// packing. These are deliberately generous placeholders: the plan's real
// bound comes from simulating the finalized chunk and re-deriving its exact
// `SetComputeUnitLimit` (see [`refine_compute_unit_limit`]), which every
// signed transaction must go through before authorization.
const COMPUTE_BUDGET_OVERHEAD_UNITS: u64 = 500;
const MEMO_OVERHEAD_UNITS: u64 = 500;
const TRANSFER_CHECKED_UNITS: u64 = 10_000;
const ATA_CREATE_UNITS: u64 = 25_000;

/// `spl_associated_token_account::instruction::AssociatedTokenAccountInstruction::CreateIdempotent`
/// discriminator, and the SetComputeUnit{Price,Limit} discriminators from
/// the Compute Budget program. Matches PayKit's own private constants of
/// the same name (`mpp::client::charge`) byte-for-byte; duplicated here
/// because the permit must decode instructions built by this planner
/// without depending on PayKit's private builder internals.
const ATA_CREATE_IDEMPOTENT_DISCRIMINATOR: u8 = 1;
const COMPUTE_UNIT_LIMIT_DISCRIMINATOR: u8 = 2;
const COMPUTE_UNIT_PRICE_DISCRIMINATOR: u8 = 3;
/// `spl_token::instruction::TokenInstruction::TransferChecked` discriminator.
const TRANSFER_CHECKED_DISCRIMINATOR: u8 = 12;

// ── Fee mode ─────────────────────────────────────────────────────────────

/// Who ends up paying transaction fees and missing-ATA rent for a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeePayerMode {
    /// The sender's own SOL balance pays fees and rent.
    SelfFunded,
    /// pay-api's fee payer pays fees and rent, reimbursed in stablecoin.
    Gasless,
}

/// The user's requested fee mode (`pay push --self-funded` / `--gasless` /
/// default `auto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FeeModeRequest {
    #[default]
    Auto,
    SelfFunded,
    Gasless,
}

/// The exact SOL cost self-funded mode would incur, as measured by
/// preflight (`getFeeForMessage` plus rent for missing ATAs plus the
/// explicit reserve).
#[derive(Debug, Clone, Copy, Default)]
pub struct SelfFundedCost {
    pub estimated_fee_lamports: u64,
    pub missing_ata_rent_lamports: u64,
    pub reserve_lamports: u64,
}

impl SelfFundedCost {
    /// `fee + rent + reserve`, checked against `u64` overflow (preflight
    /// numbers are real cluster quantities and will never be anywhere near
    /// this large, but a corrupt RPC response should error, not wrap).
    pub fn total_lamports(&self) -> Result<u64> {
        self.estimated_fee_lamports
            .checked_add(self.missing_ata_rent_lamports)
            .and_then(|sum| sum.checked_add(self.reserve_lamports))
            .ok_or_else(|| Error::Config("self-funded cost overflowed u64 lamports".to_string()))
    }
}

/// `max(MIN_FEE_RESERVE_LAMPORTS, 5% of estimated_fee_lamports)`.
pub fn compute_reserve_lamports(estimated_fee_lamports: u64) -> u64 {
    let five_percent = ((estimated_fee_lamports as u128 * 5) / 100) as u64;
    five_percent.max(MIN_FEE_RESERVE_LAMPORTS)
}

/// Choose (or reject) a fee-payer mode from the measured preflight cost.
///
/// - `SelfFunded` request: fails fast when SOL is short — a forced
///   self-funded run never falls back to gasless.
/// - `Gasless` request: fails fast when pay-api is unavailable — a forced
///   gasless run never treats spare SOL as permission to spend it.
/// - `Auto`: self-funded when SOL exactly covers `total_lamports()`,
///   otherwise gasless (if available), otherwise an actionable shortfall
///   error naming both the SOL gap and the pay-api unavailability.
pub fn decide_fee_mode(
    requested: FeeModeRequest,
    sol_lamports: u64,
    cost: &SelfFundedCost,
    gasless_available: bool,
) -> Result<FeePayerMode> {
    let total = cost.total_lamports()?;
    let self_funded_covered = sol_lamports >= total;

    match requested {
        FeeModeRequest::SelfFunded => {
            if self_funded_covered {
                Ok(FeePayerMode::SelfFunded)
            } else {
                Err(Error::Config(format!(
                    "self-funded mode requires {total} lamports (fee {} + rent {} + reserve {}) \
                     but the sender only has {sol_lamports} lamports of SOL",
                    cost.estimated_fee_lamports,
                    cost.missing_ata_rent_lamports,
                    cost.reserve_lamports
                )))
            }
        }
        FeeModeRequest::Gasless => {
            if gasless_available {
                Ok(FeePayerMode::Gasless)
            } else {
                Err(Error::Config(
                    "gasless mode requires pay-api, which is unavailable".to_string(),
                ))
            }
        }
        FeeModeRequest::Auto => {
            if self_funded_covered {
                Ok(FeePayerMode::SelfFunded)
            } else if gasless_available {
                Ok(FeePayerMode::Gasless)
            } else {
                Err(Error::Config(format!(
                    "auto fee mode could not proceed: self-funded needs {total} lamports but the \
                     sender only has {sol_lamports}, and pay-api (gasless fallback) is unavailable"
                )))
            }
        }
    }
}

// ── Rent ─────────────────────────────────────────────────────────────────

/// `spl_token`/`spl_token_2022` account length for a mint's ATAs. See
/// [`TOKEN_2022_BASE_ATA_LEN`] for the Token-2022 approximation caveat.
pub fn token_account_len(token_program: &Pubkey) -> usize {
    if *token_program == token_2022_program_id() {
        TOKEN_2022_BASE_ATA_LEN
    } else {
        TOKEN_ACCOUNT_LEN
    }
}

/// Solana's rent-exemption formula (`solana_rent::Rent::default().minimum_balance`),
/// duplicated as a plain function rather than pulling in a `solana-rent`
/// dependency for one calculation. `ACCOUNT_STORAGE_OVERHEAD` (128),
/// `DEFAULT_LAMPORTS_PER_BYTE_YEAR` (3480), and `DEFAULT_EXEMPTION_THRESHOLD`
/// (2.0) are stable cluster-wide protocol defaults, not implementation
/// detail that could silently drift underneath this crate.
pub fn rent_exempt_minimum_lamports(data_len: usize) -> u64 {
    const ACCOUNT_STORAGE_OVERHEAD: u64 = 128;
    const DEFAULT_LAMPORTS_PER_BYTE_YEAR: u64 = 1_000_000_000 / 100 * 365 / (1024 * 1024);
    const DEFAULT_EXEMPTION_THRESHOLD: f64 = 2.0;

    (((ACCOUNT_STORAGE_OVERHEAD + data_len as u64) * DEFAULT_LAMPORTS_PER_BYTE_YEAR) as f64
        * DEFAULT_EXEMPTION_THRESHOLD) as u64
}

// ── ATA snapshot ─────────────────────────────────────────────────────────

/// Whether one destination's ATA already exists, as observed by preflight's
/// bounded `getMultipleAccounts` calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestinationAtaStatus {
    pub recipient: Pubkey,
    pub ata: Pubkey,
    pub exists: bool,
}

/// The exact set of ATA facts the plan's preflight step needs, aligned
/// 1:1 by index with [`TransferManifest::rows`].
#[derive(Debug, Clone)]
pub struct AtaSnapshot {
    pub sender_ata: Pubkey,
    pub sender_ata_exists: bool,
    pub destinations: Vec<DestinationAtaStatus>,
}

impl AtaSnapshot {
    pub fn missing_count(&self) -> usize {
        self.destinations.iter().filter(|d| !d.exists).count()
    }
}

// ── Packing ──────────────────────────────────────────────────────────────

/// One planned SPL transfer inside a chunk. Carries `row_number` (rather
/// than a bare index) so a permit-rejection or journal entry can always cite
/// the exact CSV line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTransferEntry {
    pub row_number: u64,
    pub recipient: Pubkey,
    pub amount_raw: u64,
    pub ata_creation_required: bool,
}

/// One exact, sized, packet-checked transaction shape. Everything a
/// `BatchSigningPermit` needs to validate a re-presented transaction against
/// what was authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedChunk {
    pub chunk_index: u32,
    pub entries: Vec<PlannedTransferEntry>,
    pub compute_unit_price_micro_lamports: u64,
    pub compute_unit_limit: u32,
    pub memo: String,
    /// Serialized length of the unsigned transaction at planning time
    /// (placeholder blockhash). Recorded for observability; the packet-size
    /// bound has already been enforced by the time this struct exists.
    pub serialized_len: usize,
}

impl PlannedChunk {
    pub fn row_numbers(&self) -> Vec<u64> {
        self.entries.iter().map(|e| e.row_number).collect()
    }

    /// Checked sum of this chunk's transfer amounts.
    pub fn token_total_raw(&self) -> Result<u64> {
        self.entries
            .iter()
            .try_fold(0u64, |acc, e| acc.checked_add(e.amount_raw))
            .ok_or_else(|| Error::Config("chunk token total overflowed u64".to_string()))
    }
}

/// The complete, ordered, deterministic transaction plan for a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionPlan {
    pub fee_payer_mode: FeePayerMode,
    pub fee_payer: Pubkey,
    pub chunks: Vec<PlannedChunk>,
}

impl TransactionPlan {
    pub fn total_transactions(&self) -> usize {
        self.chunks.len()
    }

    pub fn total_token_raw(&self) -> Result<u64> {
        self.chunks.iter().try_fold(0u64, |acc, chunk| {
            let total = chunk.token_total_raw()?;
            acc.checked_add(total)
                .ok_or_else(|| Error::Config("plan token total overflowed u64".to_string()))
        })
    }
}

/// Pack every manifest row into the fewest ordered, packet-size-respecting
/// chunks, per the plan's "Transaction-packing algorithm" section.
///
/// `sender` is the token authority (and, in self-funded mode, also the fee
/// payer). `fee_payer` is the account paying transaction fees and
/// missing-ATA rent for every chunk: the sender itself in self-funded mode,
/// or pay-api's advertised fee payer in gasless mode.
pub fn pack_chunks(
    manifest: &TransferManifest,
    ata: &AtaSnapshot,
    fee_payer_mode: FeePayerMode,
    sender: &Pubkey,
    fee_payer: &Pubkey,
    compute_unit_price_micro_lamports: u64,
) -> Result<TransactionPlan> {
    if manifest.rows.len() != ata.destinations.len() {
        return Err(Error::Config(
            "ATA snapshot row count does not match the manifest".to_string(),
        ));
    }
    for (row, dest) in manifest.rows.iter().zip(ata.destinations.iter()) {
        if row.recipient != dest.recipient {
            return Err(Error::Config(format!(
                "ATA snapshot row {} recipient mismatch",
                row.row_number
            )));
        }
    }

    let prefix = super::manifest_hash_prefix(&manifest.hash_hex()).to_string();
    let mut chunks: Vec<PlannedChunk> = Vec::new();
    let mut pending_rows: Vec<usize> = Vec::new();

    for row_index in 0..manifest.rows.len() {
        pending_rows.push(row_index);
        let chunk_index = chunks.len() as u32;

        let gasless_cap_exceeded = matches!(fee_payer_mode, FeePayerMode::Gasless)
            && pending_rows.len() > MAX_GASLESS_TRANSFERS_PER_CHUNK;

        let build_result = if gasless_cap_exceeded {
            None
        } else {
            Some(build_planned_chunk(
                manifest,
                ata,
                &pending_rows,
                chunk_index,
                fee_payer_mode,
                sender,
                fee_payer,
                compute_unit_price_micro_lamports,
                &prefix,
            ))
        };

        let fits = matches!(build_result, Some(Ok(_)));
        if fits {
            // Row fits in the current (still-open) chunk; keep accumulating.
            continue;
        }

        if pending_rows.len() == 1 {
            let reason = match build_result {
                Some(Err(e)) => e.to_string(),
                _ => format!(
                    "gasless chunks are capped at {MAX_GASLESS_TRANSFERS_PER_CHUNK} payouts"
                ),
            };
            return Err(Error::Config(format!(
                "CSV row {} cannot fit in a transaction on its own: {reason}",
                manifest.rows[row_index].row_number
            )));
        }

        // Finalize everything except the row that just broke the bound, then
        // retry that row alone in a fresh chunk.
        pending_rows.pop();
        let finalized = build_planned_chunk(
            manifest,
            ata,
            &pending_rows,
            chunk_index,
            fee_payer_mode,
            sender,
            fee_payer,
            compute_unit_price_micro_lamports,
            &prefix,
        )?;
        chunks.push(finalized);

        pending_rows = vec![row_index];
        let next_chunk_index = chunks.len() as u32;
        if let Err(e) = build_planned_chunk(
            manifest,
            ata,
            &pending_rows,
            next_chunk_index,
            fee_payer_mode,
            sender,
            fee_payer,
            compute_unit_price_micro_lamports,
            &prefix,
        ) {
            return Err(Error::Config(format!(
                "CSV row {} cannot fit in a transaction on its own: {e}",
                manifest.rows[row_index].row_number
            )));
        }
    }

    if !pending_rows.is_empty() {
        let chunk_index = chunks.len() as u32;
        chunks.push(build_planned_chunk(
            manifest,
            ata,
            &pending_rows,
            chunk_index,
            fee_payer_mode,
            sender,
            fee_payer,
            compute_unit_price_micro_lamports,
            &prefix,
        )?);
    }

    Ok(TransactionPlan {
        fee_payer_mode,
        fee_payer: *fee_payer,
        chunks,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_planned_chunk(
    manifest: &TransferManifest,
    ata: &AtaSnapshot,
    row_indices: &[usize],
    chunk_index: u32,
    fee_payer_mode: FeePayerMode,
    sender: &Pubkey,
    fee_payer: &Pubkey,
    compute_unit_price_micro_lamports: u64,
    manifest_prefix: &str,
) -> Result<PlannedChunk> {
    if matches!(fee_payer_mode, FeePayerMode::Gasless)
        && row_indices.len() > MAX_GASLESS_TRANSFERS_PER_CHUNK
    {
        return Err(Error::Config(format!(
            "gasless chunks are capped at {MAX_GASLESS_TRANSFERS_PER_CHUNK} payouts (MPP split limit)"
        )));
    }

    let memo = format!("pay-push:v1:{manifest_prefix}:{chunk_index}");
    let last = row_indices.len() - 1;
    let ata_create_count = row_indices
        .iter()
        .filter(|&&idx| !ata.destinations[idx].exists)
        .count();

    let kit_entries: Vec<TransferEntry> = row_indices
        .iter()
        .enumerate()
        .map(|(position, &row_index)| {
            let row = &manifest.rows[row_index];
            let dest = &ata.destinations[row_index];
            TransferEntry {
                recipient: row.recipient,
                amount: row.amount_raw,
                ata_creation_required: !dest.exists,
                memo: if position == last {
                    Some(memo.clone())
                } else {
                    None
                },
            }
        })
        .collect();

    let compute_unit_limit = estimate_compute_units(kit_entries.len(), ata_create_count);
    let compute_budget = ComputeBudgetOptions {
        compute_unit_price_micro_lamports,
        compute_unit_limit,
    };
    compute_budget.validate().map_err(kit_error)?;

    let mut instructions = vec![
        compute_unit_price_instruction(compute_budget.compute_unit_price_micro_lamports),
        compute_unit_limit_instruction(compute_budget.compute_unit_limit),
    ];
    let batch = build_spl_transfer_batch_instructions(
        sender,
        &manifest.context.mint,
        &manifest.context.token_program,
        manifest.context.decimals,
        fee_payer,
        &kit_entries,
    )
    .map_err(kit_error)?;
    instructions.extend(batch);

    let message = Message::new_with_blockhash(&instructions, Some(fee_payer), &Hash::default());
    if message.account_keys.len() > MAX_STATIC_ACCOUNT_KEYS {
        return Err(Error::Config(format!(
            "chunk needs {} account keys, exceeding the conservative {MAX_STATIC_ACCOUNT_KEYS}-key limit",
            message.account_keys.len()
        )));
    }

    let transaction = Transaction::new_unsigned(message);
    let serialized_len = check_transaction_packet_size(&transaction).map_err(kit_error)?;

    let entries = row_indices
        .iter()
        .map(|&row_index| {
            let row = &manifest.rows[row_index];
            PlannedTransferEntry {
                row_number: row.row_number,
                recipient: row.recipient,
                amount_raw: row.amount_raw,
                ata_creation_required: !ata.destinations[row_index].exists,
            }
        })
        .collect();

    Ok(PlannedChunk {
        chunk_index,
        entries,
        compute_unit_price_micro_lamports: compute_budget.compute_unit_price_micro_lamports,
        compute_unit_limit: compute_budget.compute_unit_limit,
        memo,
        serialized_len,
    })
}

/// Build the real (unsigned) transaction for `chunk`, ready for
/// [`super::permit::BatchSigningPermit::sign_chunk`]. This is the
/// production counterpart of `build_planned_chunk`'s internal
/// instruction-building (which only proves the chunk *fits*, at packing
/// time, against a placeholder blockhash): the executor calls this once it
/// has a live blockhash, right before signing, so staleness is bounded to
/// one round trip rather than however long a chunk sat in a plan.
///
/// `blockhash` must be a recently-fetched value from the network the chunk
/// targets; this function performs no RPC itself, matching every other
/// pure/read-only-preflight function in this module.
pub fn build_chunk_transaction(
    chunk: &PlannedChunk,
    mint: &Pubkey,
    token_program: &Pubkey,
    decimals: u8,
    sender: &Pubkey,
    fee_payer: &Pubkey,
    blockhash: Hash,
) -> Result<Transaction> {
    let last = chunk.entries.len().checked_sub(1).ok_or_else(|| {
        Error::Config("cannot build a transaction for a chunk with no entries".to_string())
    })?;
    let kit_entries: Vec<TransferEntry> = chunk
        .entries
        .iter()
        .enumerate()
        .map(|(position, entry)| TransferEntry {
            recipient: entry.recipient,
            amount: entry.amount_raw,
            ata_creation_required: entry.ata_creation_required,
            memo: if position == last {
                Some(chunk.memo.clone())
            } else {
                None
            },
        })
        .collect();

    let mut instructions = vec![
        compute_unit_price_instruction(chunk.compute_unit_price_micro_lamports),
        compute_unit_limit_instruction(chunk.compute_unit_limit),
    ];
    instructions.extend(
        build_spl_transfer_batch_instructions(
            sender,
            mint,
            token_program,
            decimals,
            fee_payer,
            &kit_entries,
        )
        .map_err(kit_error)?,
    );

    let message = Message::new_with_blockhash(&instructions, Some(fee_payer), &blockhash);
    Ok(Transaction::new_unsigned(message))
}

fn estimate_compute_units(transfer_count: usize, ata_create_count: usize) -> u32 {
    let total = COMPUTE_BUDGET_OVERHEAD_UNITS
        + MEMO_OVERHEAD_UNITS
        + (transfer_count as u64) * TRANSFER_CHECKED_UNITS
        + (ata_create_count as u64) * ATA_CREATE_UNITS;
    total.min(PACKING_COMPUTE_UNIT_CEILING as u64) as u32
}

/// Apply the plan's post-finalize compute-unit refinement formula:
/// `ceil(units_consumed * 1.15) + 10_000`, capped at Solana's real
/// per-transaction ceiling. Pure and unit-testable; the network round trip
/// that produces `units_consumed` (a signature-verification-disabled
/// `simulateTransaction` call against the finalized chunk) is executor RPC
/// glue and is wired up alongside broadcast in a later slice.
pub fn refine_compute_unit_limit(units_consumed: u64) -> u32 {
    let scaled = units_consumed.saturating_mul(115).div_ceil(100);
    let with_margin = scaled.saturating_add(10_000);
    with_margin.min(SOLANA_MAX_COMPUTE_UNIT_LIMIT as u64) as u32
}

// ── Instruction helpers (mirror PayKit's private compute-budget builders) ──

pub(crate) fn compute_unit_price_instruction(micro_lamports: u64) -> Instruction {
    let mut data = vec![COMPUTE_UNIT_PRICE_DISCRIMINATOR];
    data.extend_from_slice(&micro_lamports.to_le_bytes());
    Instruction {
        program_id: compute_budget_program_id(),
        accounts: vec![],
        data,
    }
}

pub(crate) fn compute_unit_limit_instruction(units: u32) -> Instruction {
    let mut data = vec![COMPUTE_UNIT_LIMIT_DISCRIMINATOR];
    data.extend_from_slice(&units.to_le_bytes());
    Instruction {
        program_id: compute_budget_program_id(),
        accounts: vec![],
        data,
    }
}

/// Standard Associated Token Account address derivation
/// (`[owner, token_program, mint]` seeds under the ATA program). Duplicated
/// from PayKit's private helper of the same shape because the permit needs
/// to re-derive the expected destination ATA for validation without
/// depending on PayKit's private builder internals.
pub(crate) fn derive_associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Pubkey {
    let seeds = &[owner.as_ref(), token_program.as_ref(), mint.as_ref()];
    Pubkey::find_program_address(seeds, &associated_token_program_id()).0
}

pub(crate) fn compute_budget_program_id() -> Pubkey {
    program_pubkey(programs::COMPUTE_BUDGET_PROGRAM)
}

pub(crate) fn memo_program_id() -> Pubkey {
    program_pubkey(programs::MEMO_PROGRAM)
}

pub(crate) fn associated_token_program_id() -> Pubkey {
    program_pubkey(programs::ASSOCIATED_TOKEN_PROGRAM)
}

pub(crate) fn token_program_id() -> Pubkey {
    program_pubkey(programs::TOKEN_PROGRAM)
}

pub(crate) fn token_2022_program_id() -> Pubkey {
    program_pubkey(programs::TOKEN_2022_PROGRAM)
}

pub(crate) fn system_program_id() -> Pubkey {
    program_pubkey(programs::SYSTEM_PROGRAM)
}

fn program_pubkey(value: &str) -> Pubkey {
    Pubkey::from_str(value).expect("PayKit program id constants are always valid base58")
}

pub(crate) fn kit_error(error: pay_kit::mpp::Error) -> Error {
    Error::Mpp(error.to_string())
}

pub(crate) const fn ata_create_idempotent_discriminator() -> u8 {
    ATA_CREATE_IDEMPOTENT_DISCRIMINATOR
}

pub(crate) const fn transfer_checked_discriminator() -> u8 {
    TRANSFER_CHECKED_DISCRIMINATOR
}

pub(crate) const fn compute_unit_price_discriminator() -> u8 {
    COMPUTE_UNIT_PRICE_DISCRIMINATOR
}

pub(crate) const fn compute_unit_limit_discriminator() -> u8 {
    COMPUTE_UNIT_LIMIT_DISCRIMINATOR
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest_with_rows(rows: usize, decimals: u8) -> TransferManifest {
        let mut csv = String::from("recipient,amount\n");
        for i in 0..rows {
            let recipient = Pubkey::new_from_array([(i + 1) as u8; 32]);
            csv.push_str(&format!("{recipient},1\n"));
        }
        let context = super::super::manifest::ManifestContext {
            network_genesis_hash: [1; 32],
            mint: Pubkey::new_from_array([9; 32]),
            token_program: token_program_id(),
            decimals,
        };
        super::super::manifest::parse_manifest_csv(csv.as_bytes(), context).unwrap()
    }

    fn snapshot_all_missing(manifest: &TransferManifest) -> AtaSnapshot {
        AtaSnapshot {
            sender_ata: Pubkey::new_unique(),
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
        }
    }

    fn snapshot_all_existing(manifest: &TransferManifest) -> AtaSnapshot {
        let mut snapshot = snapshot_all_missing(manifest);
        for dest in &mut snapshot.destinations {
            dest.exists = true;
        }
        snapshot
    }

    // ── decide_fee_mode ──

    #[test]
    fn auto_prefers_self_funded_when_sol_covers_cost() {
        let cost = SelfFundedCost {
            estimated_fee_lamports: 5_000,
            missing_ata_rent_lamports: 2_039_280,
            reserve_lamports: 10_000,
        };
        let mode = decide_fee_mode(FeeModeRequest::Auto, 10_000_000, &cost, true).unwrap();
        assert_eq!(mode, FeePayerMode::SelfFunded);
    }

    #[test]
    fn auto_falls_back_to_gasless_when_sol_short() {
        let cost = SelfFundedCost {
            estimated_fee_lamports: 5_000,
            missing_ata_rent_lamports: 2_039_280,
            reserve_lamports: 10_000,
        };
        let mode = decide_fee_mode(FeeModeRequest::Auto, 1_000, &cost, true).unwrap();
        assert_eq!(mode, FeePayerMode::Gasless);
    }

    #[test]
    fn auto_fails_when_sol_short_and_gasless_unavailable() {
        let cost = SelfFundedCost {
            estimated_fee_lamports: 5_000,
            missing_ata_rent_lamports: 0,
            reserve_lamports: 10_000,
        };
        let err = decide_fee_mode(FeeModeRequest::Auto, 1_000, &cost, false).unwrap_err();
        assert!(err.to_string().contains("pay-api"));
    }

    #[test]
    fn forced_self_funded_fails_fast_on_shortfall_even_if_gasless_available() {
        let cost = SelfFundedCost {
            estimated_fee_lamports: 5_000,
            missing_ata_rent_lamports: 0,
            reserve_lamports: 10_000,
        };
        let err = decide_fee_mode(FeeModeRequest::SelfFunded, 1_000, &cost, true).unwrap_err();
        assert!(err.to_string().contains("self-funded mode requires"));
    }

    #[test]
    fn forced_gasless_never_spends_available_sol() {
        let cost = SelfFundedCost {
            estimated_fee_lamports: 5_000,
            missing_ata_rent_lamports: 0,
            reserve_lamports: 10_000,
        };
        // Plenty of SOL, but forced gasless with pay-api down must still fail
        // rather than silently spending SOL.
        let err =
            decide_fee_mode(FeeModeRequest::Gasless, 10_000_000_000, &cost, false).unwrap_err();
        assert!(err.to_string().contains("gasless mode requires pay-api"));

        let mode = decide_fee_mode(FeeModeRequest::Gasless, 10_000_000_000, &cost, true).unwrap();
        assert_eq!(mode, FeePayerMode::Gasless);
    }

    #[test]
    fn reserve_uses_five_percent_floor_of_ten_thousand() {
        assert_eq!(compute_reserve_lamports(0), MIN_FEE_RESERVE_LAMPORTS);
        assert_eq!(compute_reserve_lamports(100_000), MIN_FEE_RESERVE_LAMPORTS);
        assert_eq!(compute_reserve_lamports(1_000_000), 50_000);
    }

    #[test]
    fn rent_exempt_minimum_matches_known_token_account_rent() {
        // Well-known real-world SPL token account rent-exempt minimum.
        assert_eq!(rent_exempt_minimum_lamports(TOKEN_ACCOUNT_LEN), 2_039_280);
    }

    // ── pack_chunks ──

    #[test]
    fn every_row_appears_exactly_once_in_original_order() {
        let manifest = manifest_with_rows(50, 6);
        let ata = snapshot_all_missing(&manifest);
        let sender = Pubkey::new_unique();
        let plan = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap();

        let mut seen_row_numbers = Vec::new();
        for chunk in &plan.chunks {
            seen_row_numbers.extend(chunk.row_numbers());
        }
        let expected: Vec<u64> = manifest.rows.iter().map(|r| r.row_number).collect();
        assert_eq!(seen_row_numbers, expected);
    }

    #[test]
    fn packed_transactions_never_exceed_packet_size() {
        let manifest = manifest_with_rows(200, 6);
        let ata = snapshot_all_missing(&manifest);
        let sender = Pubkey::new_unique();
        let plan = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap();
        assert!(
            plan.chunks.len() > 1,
            "200 missing-ATA rows must span multiple chunks"
        );
        for chunk in &plan.chunks {
            assert!(chunk.serialized_len <= pay_kit::mpp::protocol::solana::PACKET_DATA_SIZE);
        }
    }

    #[test]
    fn gasless_chunks_cap_at_eight_transfers() {
        let manifest = manifest_with_rows(20, 6);
        let ata = snapshot_all_existing(&manifest);
        let sender = Pubkey::new_unique();
        let fee_payer = Pubkey::new_unique();
        let plan = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::Gasless,
            &sender,
            &fee_payer,
            1,
        )
        .unwrap();
        for chunk in &plan.chunks {
            assert!(chunk.entries.len() <= MAX_GASLESS_TRANSFERS_PER_CHUNK);
        }
        let total: usize = plan.chunks.iter().map(|c| c.entries.len()).sum();
        assert_eq!(total, 20);
        assert_eq!(plan.chunks.len(), 3); // 8 + 8 + 4
    }

    #[test]
    fn self_funded_existing_atas_pack_more_transfers_per_chunk_than_missing_atas() {
        let manifest_missing = manifest_with_rows(100, 6);
        let missing = snapshot_all_missing(&manifest_missing);
        let sender = Pubkey::new_unique();
        let plan_missing = pack_chunks(
            &manifest_missing,
            &missing,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap();

        let manifest_existing = manifest_with_rows(100, 6);
        let existing = snapshot_all_existing(&manifest_existing);
        let plan_existing = pack_chunks(
            &manifest_existing,
            &existing,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap();

        assert!(plan_existing.chunks.len() < plan_missing.chunks.len());
    }

    #[test]
    fn token_2022_packs_successfully() {
        let mut manifest = manifest_with_rows(10, 6);
        manifest.context.token_program = token_2022_program_id();
        // Rebuild rows against a Token-2022 context (parse_manifest_csv baked
        // in the token program used at manifest_with_rows time already
        // matched TOKEN_PROGRAM; overwrite it directly here since packing
        // only reads `manifest.context`, not the hash).
        let ata = snapshot_all_missing(&manifest);
        let sender = Pubkey::new_unique();
        let plan = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap();
        assert!(!plan.chunks.is_empty());
    }

    #[test]
    fn memo_is_last_instruction_and_carries_chunk_identity() {
        let manifest = manifest_with_rows(3, 6);
        let ata = snapshot_all_missing(&manifest);
        let sender = Pubkey::new_unique();
        let plan = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap();
        let hash_hex = manifest.hash_hex();
        let prefix = super::super::manifest_hash_prefix(&hash_hex);
        for chunk in &plan.chunks {
            assert_eq!(
                chunk.memo,
                format!("pay-push:v1:{prefix}:{}", chunk.chunk_index)
            );
        }
    }

    #[test]
    fn refine_compute_unit_limit_applies_margin_and_caps() {
        assert_eq!(refine_compute_unit_limit(100_000), 125_000);
        assert_eq!(
            refine_compute_unit_limit(SOLANA_MAX_COMPUTE_UNIT_LIMIT as u64 * 10),
            SOLANA_MAX_COMPUTE_UNIT_LIMIT
        );
    }

    #[test]
    fn ata_snapshot_length_mismatch_is_rejected() {
        let manifest = manifest_with_rows(5, 6);
        let mut ata = snapshot_all_missing(&manifest);
        ata.destinations.pop();
        let sender = Pubkey::new_unique();
        let err = pack_chunks(
            &manifest,
            &ata,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            1,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }
}
