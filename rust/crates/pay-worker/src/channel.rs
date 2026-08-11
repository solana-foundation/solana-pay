//! Channel decoding, distribution-preimage recovery, and instruction building
//! for the payment-channels program.
//!
//! Reuses pay-kit's Codama-generated [`Channel`] account (borsh-decoded via
//! `Channel::from_bytes`) and its instruction builders, plus pay-api-core's
//! ATA derivation and RPC client.

use std::str::FromStr;

use pay_api_core::ata::{SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, associated_token_address};
use pay_api_core::rpc::RpcClient;
use pay_kit::core::payment_channels::{default_program_id, find_event_authority_pda, to_address};
use pay_kit::generated::payment_channels::generated::accounts::Channel;
use pay_kit::generated::payment_channels::generated::instructions::{
    DistributeBuilder, OPEN_DISCRIMINATOR, ReclaimBuilder, RequestCloseBuilder, SealBuilder,
    SettleAndSealBuilder, WithdrawPayerBuilder,
};
use pay_kit::generated::payment_channels::generated::types::{
    DistributeArgs, DistributionEntry, SettleAndSealArgs,
};
use sha2::{Digest, Sha256};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;

use crate::error::JobError;

/// `Sysvar1nstructions1111111111111111111111111` — needed by
/// `settle_and_seal`.
pub const INSTRUCTIONS_SYSVAR: Pubkey =
    solana_pubkey::pubkey!("Sysvar1nstructions1111111111111111111111111");

/// Channel status byte values.
pub const STATUS_OPEN: u8 = 0;
pub const STATUS_SEALED: u8 = 1;
pub const STATUS_CLOSING: u8 = 2;
pub const STATUS_DISTRIBUTED: u8 = 3;

/// Fixed serialized size of the current epoch-addressed Channel account.
pub const CHANNEL_ACCOUNT_SIZE: usize = 256;

/// Byte length of the on-chain `open` instruction header that precedes the
/// distribution `recipients` vector: `disc(1) + salt(8) + deposit(8) +
/// grace_period(4) + open_slot(8)`.
const OPEN_HEADER_LEN: usize = 29;

/// A distribution must fit in a Solana transaction together with the fixed
/// channel accounts. Keep malformed preimages from requesting an unbounded
/// allocation and reject plans that cannot be represented safely.
const MAX_DISTRIBUTION_RECIPIENTS: usize = 64;

/// Resolve the token program that owns `mint` (SPL Token vs Token-2022) by
/// reading the mint account's owner. Falls back to SPL Token if unknown.
pub async fn resolve_token_program(
    rpc: &RpcClient,
    rpc_url: &str,
    mint: &Pubkey,
) -> Result<Pubkey, JobError> {
    let accounts = rpc
        .get_multiple_accounts_with_owner(rpc_url, &[mint.to_string()])
        .await?;
    let owner = accounts
        .into_iter()
        .next()
        .flatten()
        .map(|a| a.owner)
        .unwrap_or_default();
    Ok(match owner.as_str() {
        s if s == TOKEN_2022_PROGRAM_ID.to_string() => TOKEN_2022_PROGRAM_ID,
        _ => SPL_TOKEN_PROGRAM_ID,
    })
}

/// A decoded live channel plus its account address.
#[derive(Debug, Clone)]
pub struct DecodedChannel {
    pub address: Pubkey,
    pub channel: Channel,
}

impl DecodedChannel {
    pub fn payer(&self) -> Pubkey {
        Pubkey::from(self.channel.payer.to_bytes())
    }
    pub fn payee(&self) -> Pubkey {
        Pubkey::from(self.channel.payee.to_bytes())
    }
    pub fn rent_payer(&self) -> Pubkey {
        Pubkey::from(self.channel.rent_payer.to_bytes())
    }
    pub fn mint(&self) -> Pubkey {
        Pubkey::from(self.channel.mint.to_bytes())
    }
    pub fn open_slot(&self) -> u64 {
        self.channel.open_slot
    }
    /// UNIX deadline after which a CLOSING channel can be permissionlessly
    /// sealed: `closure_started_at + grace_period`.
    pub fn close_deadline(&self) -> i64 {
        self.channel
            .closure_started_at
            .saturating_add(i64::from(self.channel.grace_period))
    }
}

/// Discover every `Distributed` channel directly from chain state. This is the
/// durable reclaim queue: a proxy restart cannot lose an in-process timer.
pub async fn discover_distributed_channels(
    rpc: &RpcClient,
    rpc_url: &str,
) -> Result<Vec<Pubkey>, JobError> {
    let program_id = default_program_id();
    let accounts = rpc
        .get_program_accounts_filtered(
            rpc_url,
            &program_id.to_string(),
            CHANNEL_ACCOUNT_SIZE,
            3,
            &[STATUS_DISTRIBUTED],
        )
        .await?;
    accounts
        .into_iter()
        .map(|account| {
            Pubkey::from_str(&account.pubkey).map_err(|_| JobError::InvalidAddress(account.pubkey))
        })
        .collect()
}

/// Fetch and borsh-decode a channel account. Returns `Ok(None)` when the
/// account doesn't exist, isn't owned by the payment-channels program, or
/// isn't a decodable `Channel` (e.g. a 1-byte tombstone / `ClosedChannel`).
pub async fn fetch_channel(
    rpc: &RpcClient,
    rpc_url: &str,
    address: &Pubkey,
) -> Result<Option<DecodedChannel>, JobError> {
    let program_id = default_program_id();
    let accounts = rpc
        .get_multiple_accounts_with_owner(rpc_url, &[address.to_string()])
        .await?;
    let Some(account) = accounts.into_iter().next().flatten() else {
        return Ok(None);
    };
    if account.owner != program_id.to_string() {
        return Ok(None);
    }
    // Tombstoned / closed channels are a different (short) account shape; the
    // borsh decode fails cleanly and we treat them as "not a live channel".
    match Channel::from_bytes(&account.data) {
        Ok(channel) => Ok(Some(DecodedChannel {
            address: *address,
            channel,
        })),
        Err(_) => Ok(None),
    }
}

/// The recovered distribution preimage: the raw `count || entries` bytes that
/// `distribute` expects, plus the decoded recipients (for building the
/// recipient-ATA remaining-accounts tail).
pub struct DistributionPreimage {
    /// `count(u32 LE) || entries(count × 34)` — borsh of `Vec<DistributionEntry>`.
    pub preimage_bytes: Vec<u8>,
    pub recipients: Vec<DistributionEntry>,
}

/// Recover the distribution preimage for `channel` from its `open` (creation)
/// transaction.
///
/// The on-chain `distribution_hash` is `sha256(count || entries)`; only the
/// hash is stored, so we walk `getSignaturesForAddress` back to the OLDEST
/// signature (the open), decode the `open` instruction data, and slice off the
/// 21-byte header to recover `count || entries`. We verify
/// `sha256(preimage) == channel.distribution_hash` before returning.
///
/// This works for every channel, including the empty-plan case (count = 0,
/// preimage = `00 00 00 00`).
pub async fn recover_distribution_preimage(
    rpc: &RpcClient,
    rpc_url: &str,
    channel: &DecodedChannel,
) -> Result<DistributionPreimage, JobError> {
    let open_sig = find_open_signature(rpc, rpc_url, &channel.address).await?;
    let tx_b64 = rpc
        .get_transaction_base64(rpc_url, &open_sig)
        .await?
        .ok_or(JobError::OpenTxNotFound)?;
    let ix_data = extract_open_ix_data(&tx_b64)?;

    if ix_data.len() < OPEN_HEADER_LEN {
        return Err(JobError::OpenIxDecode(format!(
            "open instruction data too short: {} bytes",
            ix_data.len()
        )));
    }
    let preimage_bytes = ix_data[OPEN_HEADER_LEN..].to_vec();

    // Verify against the on-chain hash before trusting the preimage.
    let computed = Sha256::digest(&preimage_bytes);
    if computed.as_slice() != channel.channel.distribution_hash {
        return Err(JobError::DistributionHashMismatch);
    }

    let recipients = decode_recipients(&preimage_bytes)?;
    Ok(DistributionPreimage {
        preimage_bytes,
        recipients,
    })
}

/// Walk `getSignaturesForAddress` (newest-first, paginated) to the oldest
/// signature that touched the channel — that's the `open`.
async fn find_open_signature(
    rpc: &RpcClient,
    rpc_url: &str,
    channel: &Pubkey,
) -> Result<String, JobError> {
    const PAGE: u32 = 1000;
    let addr = channel.to_string();
    let mut before: Option<String> = None;
    let mut oldest: Option<String> = None;
    loop {
        let page = rpc
            .get_signatures_for_address(rpc_url, &addr, before.as_deref(), PAGE)
            .await?;
        if page.is_empty() {
            break;
        }
        // Signatures come back newest-first; the last of each page is its
        // oldest. Keep paginating with `before = last` until a short page.
        let last = page.last().cloned();
        oldest = last.clone();
        if (page.len() as u32) < PAGE {
            break;
        }
        before = last;
    }
    oldest.ok_or(JobError::OpenTxNotFound)
}

/// Decode a base64 bincode transaction and return the data bytes of the
/// instruction whose program id is the payment-channels program and whose
/// discriminator (`data[0]`) is `OPEN_DISCRIMINATOR` (1).
///
/// Decodes as a `VersionedTransaction` so it handles both legacy and v0
/// (versioned) transactions — the relayer opens channels via v0 txs, which a
/// legacy `Transaction` decode rejects. An invoked program id is always a
/// static account key (never address-lookup-loaded), so the compiled
/// `program_id_index` resolves against the message's static account keys for
/// both message versions.
fn extract_open_ix_data(tx_b64: &str) -> Result<Vec<u8>, JobError> {
    use base64::Engine;
    use solana_message::VersionedMessage;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tx_b64.trim())
        .map_err(|e| JobError::OpenIxDecode(format!("base64 decode: {e}")))?;
    let tx: solana_transaction::versioned::VersionedTransaction = bincode::deserialize(&raw)
        .map_err(|e| JobError::OpenIxDecode(format!("bincode deserialize: {e}")))?;
    let program_id = default_program_id();
    let (keys, instructions) = match &tx.message {
        VersionedMessage::Legacy(m) => (&m.account_keys, &m.instructions),
        VersionedMessage::V0(m) => (&m.account_keys, &m.instructions),
    };
    for ix in instructions {
        let Some(program) = keys.get(ix.program_id_index as usize) else {
            continue;
        };
        if *program == program_id && ix.data.first().copied() == Some(OPEN_DISCRIMINATOR) {
            return Ok(ix.data.clone());
        }
    }
    Err(JobError::OpenIxDecode(
        "no open instruction found in the channel's creation transaction".into(),
    ))
}

/// Decode `count(u32 LE) || entries(count × 34)` into `DistributionEntry`s.
fn decode_recipients(preimage: &[u8]) -> Result<Vec<DistributionEntry>, JobError> {
    if preimage.len() < 4 {
        return Err(JobError::OpenIxDecode("preimage shorter than count".into()));
    }
    let count = u32::from_le_bytes([preimage[0], preimage[1], preimage[2], preimage[3]]) as usize;
    if count > MAX_DISTRIBUTION_RECIPIENTS {
        return Err(JobError::OpenIxDecode(format!(
            "distribution has {count} recipients; maximum is {MAX_DISTRIBUTION_RECIPIENTS}"
        )));
    }
    let payload_len = preimage.len() - 4;
    let expected_payload_len = count
        .checked_mul(34)
        .ok_or_else(|| JobError::OpenIxDecode("recipient payload length overflow".into()))?;
    if payload_len < expected_payload_len {
        return Err(JobError::OpenIxDecode(
            "preimage truncated mid-entry".into(),
        ));
    }
    if payload_len > expected_payload_len {
        return Err(JobError::OpenIxDecode(
            "preimage has trailing recipient data".into(),
        ));
    }
    let mut out = Vec::with_capacity(count);
    let mut off = 4;
    for _ in 0..count {
        let end = off + 34;
        let slice = preimage
            .get(off..end)
            .ok_or_else(|| JobError::OpenIxDecode("preimage truncated mid-entry".into()))?;
        let mut recipient = [0u8; 32];
        recipient.copy_from_slice(&slice[..32]);
        let bps = u16::from_le_bytes([slice[32], slice[33]]);
        out.push(DistributionEntry {
            recipient: solana_address::Address::from(recipient),
            bps,
        });
        off = end;
    }
    Ok(out)
}

// ── Instruction builders ────────────────────────────────────────────────────

/// `event_authority` PDA for the payment-channels program.
pub fn event_authority() -> Pubkey {
    find_event_authority_pda(&default_program_id()).0
}

/// `settle_and_seal` with `has_voucher = 0` (no voucher). Signer =
/// `merchant` (must be the channel's payee).
pub fn build_settle_and_seal_ix(channel: &Pubkey, payee: &Pubkey) -> Instruction {
    SettleAndSealBuilder::new()
        .payee(to_address(payee))
        .channel(to_address(channel))
        .instructions_sysvar(to_address(&INSTRUCTIONS_SYSVAR))
        .settle_and_seal_args(SettleAndSealArgs { has_voucher: 0 })
        .instruction()
}

/// `request_close` — starts the grace window. Signer = `payer`.
pub fn build_request_close_ix(channel: &Pubkey, payer: &Pubkey) -> Instruction {
    RequestCloseBuilder::new()
        .payer(to_address(payer))
        .channel(to_address(channel))
        .instruction()
}

/// `seal` — permissionless once the grace deadline has elapsed.
pub fn build_seal_ix(channel: &Pubkey) -> Instruction {
    SealBuilder::new()
        .channel(to_address(channel))
        .instruction()
}

/// Permissionless rent reclaim for a fully distributed channel. The program
/// enforces `clock.slot > open_slot + OPEN_SLOT_WINDOW` and returns the PDA's
/// lamports to the channel-bound rent payer.
pub fn build_reclaim_ix(channel: &Pubkey, rent_payer: &Pubkey) -> Instruction {
    ReclaimBuilder::new()
        .channel(to_address(channel))
        .rent_payer(to_address(rent_payer))
        .instruction()
}

/// `withdraw_payer` — payer refund; no preimage requirement. Signer = `payer`.
#[allow(clippy::too_many_arguments)]
pub fn build_withdraw_payer_ix(
    channel: &Pubkey,
    payer: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let channel_ata = associated_token_address(channel, mint, token_program);
    let payer_ata = associated_token_address(payer, mint, token_program);
    WithdrawPayerBuilder::new()
        .payer(to_address(payer))
        .channel(to_address(channel))
        .channel_token_account(to_address(&channel_ata))
        .payer_token_account(to_address(&payer_ata))
        .mint(to_address(mint))
        .token_program(to_address(token_program))
        .instruction()
}

/// Accounts derived for a `distribute` instruction, surfaced for logging.
pub struct DistributeAccounts {
    pub channel_ata: Pubkey,
    pub payer_ata: Pubkey,
    pub payee_ata: Pubkey,
    pub treasury_ata: Pubkey,
    pub recipient_atas: Vec<Pubkey>,
}

/// `distribute` — permissionless; refunds payer + pays recipients + tombstones.
///
/// Requires the recovered distribution preimage. The recipient-ATA tail is one
/// `ATA(recipient, mint, token_program)` per entry, in order, passed as
/// remaining accounts (writable, non-signer).
pub fn build_distribute_ix(
    channel: &DecodedChannel,
    treasury_owner: &Pubkey,
    token_program: &Pubkey,
    preimage: &DistributionPreimage,
) -> (Instruction, DistributeAccounts) {
    let channel_addr = channel.address;
    let payer = channel.payer();
    let rent_payer = channel.rent_payer();
    let payee = channel.payee();
    let mint = channel.mint();

    let channel_ata = associated_token_address(&channel_addr, &mint, token_program);
    let payer_ata = associated_token_address(&payer, &mint, token_program);
    let payee_ata = associated_token_address(&payee, &mint, token_program);
    let treasury_ata = associated_token_address(treasury_owner, &mint, token_program);

    let recipient_atas: Vec<Pubkey> = preimage
        .recipients
        .iter()
        .map(|e| {
            let recipient = Pubkey::from(e.recipient.to_bytes());
            associated_token_address(&recipient, &mint, token_program)
        })
        .collect();

    let remaining: Vec<solana_instruction::AccountMeta> = recipient_atas
        .iter()
        .map(|ata| solana_instruction::AccountMeta::new(to_address(ata), false))
        .collect();

    let ix = DistributeBuilder::new()
        .channel(to_address(&channel_addr))
        .payer(to_address(&payer))
        .rent_payer(to_address(&rent_payer))
        .channel_token_account(to_address(&channel_ata))
        .payer_token_account(to_address(&payer_ata))
        .payee_token_account(to_address(&payee_ata))
        .treasury_token_account(to_address(&treasury_ata))
        .mint(to_address(&mint))
        .token_program(to_address(token_program))
        .event_authority(to_address(&event_authority()))
        .self_program(to_address(&default_program_id()))
        .distribute_args(DistributeArgs {
            recipients: preimage.recipients.clone(),
        })
        .add_remaining_accounts(&remaining)
        .instruction();

    (
        ix,
        DistributeAccounts {
            channel_ata,
            payer_ata,
            payee_ata,
            treasury_ata,
            recipient_atas,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plan_preimage_hashes_to_zero_count() {
        // count = 0 → preimage = the 4 bytes 00 00 00 00.
        let preimage = 0u32.to_le_bytes();
        let hash = Sha256::digest(preimage);
        let recipients = decode_recipients(&preimage).unwrap();
        assert!(recipients.is_empty());
        // Sanity: the hash is deterministic and 32 bytes.
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn decode_recipients_parses_entries() {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&2u32.to_le_bytes());
        // entry 0
        preimage.extend_from_slice(&[1u8; 32]);
        preimage.extend_from_slice(&4000u16.to_le_bytes());
        // entry 1
        preimage.extend_from_slice(&[2u8; 32]);
        preimage.extend_from_slice(&6000u16.to_le_bytes());
        let recipients = decode_recipients(&preimage).unwrap();
        assert_eq!(recipients.len(), 2);
        assert_eq!(recipients[0].bps, 4000);
        assert_eq!(recipients[1].bps, 6000);
        assert_eq!(recipients[0].recipient.to_bytes(), [1u8; 32]);
    }

    #[test]
    fn decode_recipients_rejects_truncated() {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&1u32.to_le_bytes());
        preimage.extend_from_slice(&[1u8; 10]); // too short for a 34-byte entry
        assert!(decode_recipients(&preimage).is_err());
    }

    #[test]
    fn decode_recipients_rejects_unbounded_count_before_allocating() {
        assert!(decode_recipients(&u32::MAX.to_le_bytes()).is_err());
    }

    #[test]
    fn extract_open_ix_data_rejects_garbage() {
        assert!(extract_open_ix_data("not base64!!!").is_err());
    }
}
