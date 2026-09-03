//! Fetch and decode an MPP payment-channel account.
//!
//! The Channel struct (auto-generated from the on-chain IDL) is laid out as:
//!
//! ```text
//! offset  size  field
//!      0     1  discriminator
//!      1     1  version
//!      2     1  bump
//!      3     1  status              (0 Open, 1 Sealed, 2 Closing)
//!      4     8  salt (u64 LE)
//!     12     8  deposit (u64 LE)
//!     20     8  settled (u64 LE)
//!     28     8  paid_out (u64 LE)
//!     36     8  closure_started_at (i64 LE)
//!     44     8  payer_withdrawn_at (i64 LE)
//!     52     4  grace_period (u32 LE)
//!     56    32  distribution_hash
//!     88    32  payer                (Address)
//!    120    32  payee
//!    152    32  authorized_signer
//!    184    32  mint
//! ```
//!
//! Total: 216 bytes.

use std::str::FromStr;

use solana_pubkey::Pubkey;

use crate::error::{Error, Result};
use crate::receipt::PAYMENT_CHANNELS_PROGRAM;
use crate::rpc::RpcClient;

const CHANNEL_LAYOUT_LEN: usize = 216;
const STATUS_OFFSET: usize = 3;
const DEPOSIT_OFFSET: usize = 12;
const SETTLED_OFFSET: usize = 20;
const PAID_OUT_OFFSET: usize = 28;
const PAYER_OFFSET: usize = 88;
const PAYEE_OFFSET: usize = 120;
const MINT_OFFSET: usize = 184;

#[derive(Debug, Clone)]
pub struct ChannelState {
    pub address: String,
    pub status: ChannelStatus,
    pub deposit: u64,
    pub settled: u64,
    pub paid_out: u64,
    pub payer: Pubkey,
    pub payee: Pubkey,
    pub mint: Pubkey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    Open,
    Sealed,
    Closing,
    Unknown,
}

impl ChannelStatus {
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Open,
            1 => Self::Sealed,
            2 => Self::Closing,
            _ => Self::Unknown,
        }
    }

    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Closing => "closing",
            Self::Unknown => "unknown",
        }
    }
}

/// Resolve the channel account among a set of candidate addresses by querying
/// the cluster for whichever one is owned by the payment-channels program.
///
/// `candidates` is typically the `accounts` list of the program instruction —
/// we don't know which slot holds the channel PDA without the IDL, so we let
/// the RPC tell us.
pub async fn fetch_channel(
    rpc: &RpcClient,
    rpc_url: &str,
    candidates: &[String],
) -> Result<Option<ChannelState>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let accounts = rpc
        .get_multiple_accounts_with_owner(rpc_url, candidates)
        .await?;
    for (address, account) in candidates.iter().zip(accounts) {
        let Some(account) = account else { continue };
        if account.owner != PAYMENT_CHANNELS_PROGRAM {
            continue;
        }
        if account.data.len() < CHANNEL_LAYOUT_LEN {
            continue;
        }
        return Ok(Some(decode_channel(address, &account.data)?));
    }
    Ok(None)
}

fn decode_channel(address: &str, data: &[u8]) -> Result<ChannelState> {
    let status = ChannelStatus::from_byte(data[STATUS_OFFSET]);
    let deposit = u64::from_le_bytes(slice_8(data, DEPOSIT_OFFSET)?);
    let settled = u64::from_le_bytes(slice_8(data, SETTLED_OFFSET)?);
    let paid_out = u64::from_le_bytes(slice_8(data, PAID_OUT_OFFSET)?);
    let payer = pubkey_at(data, PAYER_OFFSET)?;
    let payee = pubkey_at(data, PAYEE_OFFSET)?;
    let mint = pubkey_at(data, MINT_OFFSET)?;
    Ok(ChannelState {
        address: address.to_string(),
        status,
        deposit,
        settled,
        paid_out,
        payer,
        payee,
        mint,
    })
}

fn slice_8(data: &[u8], offset: usize) -> Result<[u8; 8]> {
    data.get(offset..offset + 8)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::RpcMalformed)
}

fn pubkey_at(data: &[u8], offset: usize) -> Result<Pubkey> {
    let slice = data.get(offset..offset + 32).ok_or(Error::RpcMalformed)?;
    let array: [u8; 32] = slice.try_into().map_err(|_| Error::RpcMalformed)?;
    Ok(Pubkey::new_from_array(array))
}

/// Resolve the mint's token program by checking which of SPL Token vs
/// Token-2022 owns it. Both can host stablecoins; we don't want to assume.
pub async fn fetch_mint_program(
    rpc: &RpcClient,
    rpc_url: &str,
    mint: &Pubkey,
) -> Result<Option<Pubkey>> {
    let mint_str = mint.to_string();
    let accounts = rpc
        .get_multiple_accounts_with_owner(rpc_url, &[mint_str])
        .await?;
    let account = match accounts.into_iter().next().flatten() {
        Some(a) => a,
        None => return Ok(None),
    };
    Pubkey::from_str(&account.owner)
        .map(Some)
        .map_err(|_| Error::RpcMalformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_channel_bytes(status: u8, payer: [u8; 32], payee: [u8; 32], mint: [u8; 32]) -> Vec<u8> {
        let mut data = vec![0u8; CHANNEL_LAYOUT_LEN];
        data[STATUS_OFFSET] = status;
        // deposit u64 LE = 5_000_000
        data[DEPOSIT_OFFSET..DEPOSIT_OFFSET + 8].copy_from_slice(&5_000_000u64.to_le_bytes());
        data[SETTLED_OFFSET..SETTLED_OFFSET + 8].copy_from_slice(&1_000_000u64.to_le_bytes());
        data[PAID_OUT_OFFSET..PAID_OUT_OFFSET + 8].copy_from_slice(&4_000_000u64.to_le_bytes());
        data[PAYER_OFFSET..PAYER_OFFSET + 32].copy_from_slice(&payer);
        data[PAYEE_OFFSET..PAYEE_OFFSET + 32].copy_from_slice(&payee);
        data[MINT_OFFSET..MINT_OFFSET + 32].copy_from_slice(&mint);
        data
    }

    #[test]
    fn channel_status_byte_round_trip() {
        assert_eq!(ChannelStatus::from_byte(0), ChannelStatus::Open);
        assert_eq!(ChannelStatus::from_byte(1), ChannelStatus::Sealed);
        assert_eq!(ChannelStatus::from_byte(2), ChannelStatus::Closing);
        assert_eq!(ChannelStatus::from_byte(99), ChannelStatus::Unknown);
        assert_eq!(ChannelStatus::Open.as_wire_str(), "open");
        assert_eq!(ChannelStatus::Sealed.as_wire_str(), "sealed");
        assert_eq!(ChannelStatus::Closing.as_wire_str(), "closing");
        assert_eq!(ChannelStatus::Unknown.as_wire_str(), "unknown");
    }

    #[test]
    fn decode_channel_extracts_payer_payee_mint_and_amounts() {
        let payer = [1u8; 32];
        let payee = [2u8; 32];
        let mint = [3u8; 32];
        let data = make_channel_bytes(1, payer, payee, mint);
        let decoded = decode_channel("ChannelAddr", &data).unwrap();
        assert_eq!(decoded.status, ChannelStatus::Sealed);
        assert_eq!(decoded.deposit, 5_000_000);
        assert_eq!(decoded.settled, 1_000_000);
        assert_eq!(decoded.paid_out, 4_000_000);
        assert_eq!(decoded.payer.to_bytes(), payer);
        assert_eq!(decoded.payee.to_bytes(), payee);
        assert_eq!(decoded.mint.to_bytes(), mint);
        assert_eq!(decoded.address, "ChannelAddr");
    }

    #[test]
    fn decode_channel_rejects_short_buffer() {
        // Only 50 bytes — not enough for any of the fields past status.
        let data = vec![0u8; 50];
        assert!(decode_channel("X", &data).is_err());
    }
}
