//! Decode an on-chain `RecurringDelegation` account (the spec's
//! "SubscriptionDelegation") published by the canonical subscriptions
//! program.
//!
//! The layout is the codama-generated borsh struct from pay-kit
//! (`subscriptions-client`). We deserialize the bytes through that
//! generated type rather than hand-rolling offsets, so when pay-kit
//! regenerates from the IDL we pick up changes automatically.

use borsh::BorshDeserialize;
use pay_kit::generated::subscriptions::accounts::RecurringDelegation;
use solana_pubkey::Pubkey;
use tracing::debug;

use crate::error::{Error, Result};
use crate::receipt::SUBSCRIPTIONS_PROGRAM;
use crate::rpc::RpcClient;

#[derive(Debug, Clone)]
pub struct RecurringDelegationState {
    pub address: String,
    /// Header `delegator` — the subscriber wallet.
    pub subscriber: Pubkey,
    /// Header `delegatee` — the wallet authorized to pull renewals (the
    /// operator).
    pub puller: Pubkey,
    pub mint: Pubkey,
    pub current_period_start_ts: i64,
    pub period_length_s: u64,
    pub expiry_ts: i64,
    pub amount_per_period: u64,
}

/// Resolve the recurring-delegation account among a set of candidate
/// addresses by querying the cluster for whichever one is owned by the
/// subscriptions program AND parses as a RecurringDelegation layout.
pub async fn fetch_recurring_delegation(
    rpc: &RpcClient,
    rpc_url: &str,
    candidates: &[String],
) -> Result<Option<RecurringDelegationState>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let accounts = rpc
        .get_multiple_accounts_with_owner(rpc_url, candidates)
        .await?;
    for (address, account) in candidates.iter().zip(accounts) {
        let Some(account) = account else { continue };
        if account.owner != SUBSCRIPTIONS_PROGRAM {
            continue;
        }
        match decode_recurring(address, &account.data) {
            Ok(state) => return Ok(Some(state)),
            Err(_) => {
                debug!(
                    address = %address,
                    bytes = account.data.len(),
                    "subscriptions-owned account did not decode as RecurringDelegation"
                );
            }
        }
    }
    Ok(None)
}

fn decode_recurring(address: &str, data: &[u8]) -> Result<RecurringDelegationState> {
    let decoded =
        RecurringDelegation::deserialize(&mut &data[..]).map_err(|_| Error::RpcMalformed)?;
    Ok(RecurringDelegationState {
        address: address.to_string(),
        subscriber: Pubkey::new_from_array(decoded.header.delegator.to_bytes()),
        puller: Pubkey::new_from_array(decoded.header.delegatee.to_bytes()),
        mint: Pubkey::new_from_array(decoded.mint.to_bytes()),
        current_period_start_ts: decoded.current_period_start_ts,
        period_length_s: decoded.period_length_s,
        expiry_ts: decoded.expiry_ts,
        amount_per_period: decoded.amount_per_period,
    })
}

/// Format a `period_hours` value as a friendly label.
pub fn period_label(period_hours: u64) -> String {
    if period_hours.is_multiple_of(24 * 7) {
        let weeks = period_hours / (24 * 7);
        return match weeks {
            1 => "Every week".to_string(),
            n => format!("Every {n} weeks"),
        };
    }
    if period_hours.is_multiple_of(24) {
        let days = period_hours / 24;
        return match days {
            1 => "Every day".to_string(),
            n => format!("Every {n} days"),
        };
    }
    format!("Every {period_hours} h")
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshSerialize;
    use pay_kit::generated::subscriptions::types::Header;

    fn make_recurring_account(
        subscriber: [u8; 32],
        puller: [u8; 32],
        mint: [u8; 32],
        amount: u64,
        period_s: u64,
        start: i64,
        expiry: i64,
    ) -> Vec<u8> {
        let account = RecurringDelegation {
            header: Header {
                discriminator: 0,
                version: 0,
                bump: 0,
                delegator: solana_address::Address::new_from_array(subscriber),
                delegatee: solana_address::Address::new_from_array(puller),
                payer: solana_address::Address::new_from_array([0u8; 32]),
                init_id: 0,
            },
            subscription_authority: solana_address::Address::new_from_array([0u8; 32]),
            mint: solana_address::Address::new_from_array(mint),
            current_period_start_ts: start,
            period_length_s: period_s,
            expiry_ts: expiry,
            amount_per_period: amount,
            amount_pulled_in_period: 0,
        };
        let mut bytes = Vec::new();
        account.serialize(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn decode_recurring_extracts_subscriber_period_and_amount() {
        let subscriber = [1u8; 32];
        let puller = [2u8; 32];
        let mint = [3u8; 32];
        let data = make_recurring_account(
            subscriber,
            puller,
            mint,
            10_000_000,
            30 * 24 * 3600,
            1_700_000_000,
            1_800_000_000,
        );
        let decoded = decode_recurring("Addr", &data).unwrap();
        assert_eq!(decoded.subscriber.to_bytes(), subscriber);
        assert_eq!(decoded.puller.to_bytes(), puller);
        assert_eq!(decoded.mint.to_bytes(), mint);
        assert_eq!(decoded.period_length_s, 30 * 24 * 3600);
        assert_eq!(decoded.amount_per_period, 10_000_000);
        assert_eq!(decoded.current_period_start_ts, 1_700_000_000);
        assert_eq!(decoded.expiry_ts, 1_800_000_000);
    }

    #[test]
    fn decode_recurring_rejects_short_buffer() {
        let data = vec![0u8; 50];
        assert!(decode_recurring("X", &data).is_err());
    }

    #[test]
    fn period_label_handles_days_weeks_and_hours() {
        assert_eq!(period_label(24), "Every day");
        assert_eq!(period_label(24 * 30), "Every 30 days");
        assert_eq!(period_label(168), "Every week");
        assert_eq!(period_label(168 * 4), "Every 4 weeks");
        assert_eq!(period_label(6), "Every 6 h");
    }
}
