//! API-contract types shared between `core` (producer) and `api` (serialiser).
//!
//! Anything in here is part of the public wire format — change with care.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Networks the service can route to.
///
/// Aliases (`mainnet-beta`, `surfpool`, `localnet`) parse to the same variant
/// for caller convenience but always serialise to the canonical lowercase form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Sandbox,
}

#[derive(Debug, thiserror::Error)]
#[error("unknown network: {0}")]
pub struct UnknownNetwork(pub String);

impl FromStr for Network {
    type Err = UnknownNetwork;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" | "mainnet-beta" => Ok(Self::Mainnet),
            "sandbox" | "surfpool" | "localnet" => Ok(Self::Sandbox),
            other => Err(UnknownNetwork(other.to_string())),
        }
    }
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Sandbox => "sandbox",
        }
    }
}

/// One stablecoin's balance for a given owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StablecoinBalance {
    pub symbol: String,
    pub mint: String,
    pub decimals: u8,
    /// Raw on-chain amount as a string — preserves u64 precision in JSON.
    pub raw_amount: String,
    /// Human-readable amount (`raw_amount / 10^decimals`).
    pub ui_amount: f64,
}

/// Wire response of `/v1/balance/stablecoins`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StablecoinBalances {
    pub address: String,
    pub network: Network,
    pub balances: Vec<StablecoinBalance>,
}

/// Wire response of `/v1/receipt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub signature: String,
    pub network: Network,
    pub status: ReceiptStatus,
    /// Slot containing the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    /// Block time (unix seconds, UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_time: Option<i64>,
    /// Fee payer (base58).
    pub fee_payer: String,
    /// Fee in lamports as a string to preserve u64 precision.
    pub fee_lamports: String,
    /// Confirmation status reported by the cluster.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_status: Option<String>,
    /// Detected pay-protocol intent.
    pub intent: ReceiptIntent,
    /// Value transfers (token + SOL) attributed to this transaction.
    pub transfers: Vec<ReceiptTransfer>,
    /// When the intent is `mpp/charge` with multiple recipients, this is the
    /// split breakdown (sum of `transfers` grouped by recipient). Always
    /// present (empty when not applicable) so callers can safely iterate.
    #[serde(default)]
    pub splits: Vec<ReceiptSplit>,
    /// Aggregate net amount for the primary asset, if all transfers share a
    /// single mint/asset (otherwise omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<ReceiptAmount>,
    /// Session-specific breakdown (deposit, consumed, refunded). Present when
    /// `intent.name == "session"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<ReceiptSession>,
    /// Subscription-specific breakdown (plan, period, amount-per-period).
    /// Present when `intent.name == "subscription"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription: Option<ReceiptSubscription>,
    /// Programs invoked at the top level. Useful for callers that want to
    /// surface "via payment-channels" / "memo" badges without re-parsing.
    pub programs: Vec<String>,
    /// New SPL token accounts that were created in this transaction. Each
    /// entry costs the sender ~0.00204 SOL of rent so the UI can surface it.
    #[serde(default)]
    pub account_creations: Vec<ReceiptAccountCreation>,
    /// Best-effort SOL price quote at the time of the receipt request. Used
    /// by the UI to show a "≈ $X" gloss next to SOL-denominated rows (network
    /// fee, account rent). `None` when the price source is unreachable —
    /// callers must treat the value as informational and not load-bearing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sol_usd_price: Option<f64>,
}

/// One SPL token account that was created (and rent-paid) inside this tx.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptAccountCreation {
    /// Address of the newly-created token account (the ATA).
    pub account: String,
    /// Wallet that the ATA is for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet: Option<String>,
    /// Mint the ATA holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mint: Option<String>,
    /// Symbol of the mint, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Token logo URI, if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// Rent paid in lamports.
    pub rent_lamports: String,
    /// Payer of the rent (typically the fee_payer / sender).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paid_by: Option<String>,
}

/// Pay-protocol intent detected for a confirmed transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptIntent {
    /// Backwards-compatible shorthand kept for older callers.
    pub kind: ReceiptIntentKind,
    /// Protocol family: `mpp`, `x402`, or `null` for plain transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// Intent name within the protocol: `charge`, `session`, `exact`, or
    /// `transfer`.
    pub name: String,
    /// Display label suitable for badges, e.g. "MPP · session · open".
    pub label: String,
    /// Optional `mpp/session` sub-action: `open`, `topUp`, `settle`,
    /// `settleAndSeal`, `requestClose`, `seal`, `distribute`,
    /// `withdrawPayer`, or pull-mode delegation actions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The on-chain program backing the intent when one applies
    /// (payment-channels, multi-delegator).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptIntentKind {
    #[serde(rename = "x402/exact")]
    X402Exact,
    #[serde(rename = "mpp/charge")]
    MppCharge,
    #[serde(rename = "mpp/session")]
    MppSession,
    /// Recurring fixed-amount payment authorized by an on-chain
    /// SubscriptionDelegation. Lifecycle actions: `subscribe`, `renew`,
    /// `cancel`, `createPlan`, `updatePlan`, `deletePlan`,
    /// `initSubscriptionAuthority`, `closeSubscriptionAuthority`.
    #[serde(rename = "mpp/subscription")]
    MppSubscription,
    Transfer,
}

/// Lifecycle state of the underlying payment-channel account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelStatus {
    Open,
    Closing,
    #[serde(alias = "finalized")]
    Sealed,
    Unknown,
}

/// Structured view of an `mpp/session` lifecycle event.
///
/// Each session-related transaction (open, settle, seal, …) maps the raw
/// SPL token movements onto roles so the UI can show "payer deposited X",
/// "operator consumed Y", "X refunded to payer".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSession {
    /// The session action that this transaction performed.
    pub action: String,
    /// Channel / delegation account (base58) when extractable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// Lifecycle state of the channel as of this transaction. Resolved from
    /// the Channel account when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_status: Option<ChannelStatus>,
    /// Wallet that locked the deposit / approved the delegation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Primary recipient of session proceeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payee: Option<String>,
    /// Wallet that paid the on-chain fee for this action (operator on
    /// settle/seal, payer on open).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opener: Option<String>,
    /// Amount locked when the channel was opened (push mode) or approved
    /// (pull mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deposit: Option<ReceiptAmount>,
    /// Amount paid out from the channel during this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumed: Option<ReceiptAmount>,
    /// Amount returned to the payer when closing or sealing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refunded: Option<ReceiptAmount>,
    /// Per-recipient distribution at settle/distribute time. Always present
    /// (empty for non-distribute actions).
    #[serde(default)]
    pub distributed: Vec<ReceiptSplit>,
    /// Granular per-transfer classification. Always present.
    #[serde(default)]
    pub events: Vec<ReceiptSessionEvent>,
}

/// Structured view of an `mpp/subscription` lifecycle event (activate /
/// renew / cancel / admin).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSubscription {
    /// The subscription action that this transaction performed.
    /// One of `subscribe`, `renew`, `cancel`, `createPlan`, `updatePlan`,
    /// `deletePlan`, `initSubscriptionAuthority`, `closeSubscriptionAuthority`.
    pub action: String,
    /// Lifecycle state inferred from the action.
    pub status: SubscriptionStatus,
    /// Wallet that holds the recurring authorization (the subscriber).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriber: Option<String>,
    /// Wallet that the per-period charge is paid to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    /// Plan PDA address (base58) when extractable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
    /// SubscriptionDelegation / RecurringDelegation PDA address (base58),
    /// the spec's `subscriptionId`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,
    /// Per-period amount charged this transaction (when applicable —
    /// `subscribe` / `renew` carry a real token transfer; `cancel` does not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_amount: Option<ReceiptAmount>,
    /// On-chain `period_hours` from the RecurringDelegation account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_hours: Option<u64>,
    /// User-facing period label (e.g. "Every 30 days", "Every 2 weeks").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_label: Option<String>,
    /// Current period start (unix seconds, UTC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_start_ts: Option<i64>,
    /// Current period end (unix seconds, UTC; exclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_end_ts: Option<i64>,
    /// Effective subscription expiry (unix seconds, UTC), when the plan
    /// or delegation imposes one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_ts: Option<i64>,
    /// Per-transfer classification, same shape as the session block uses.
    #[serde(default)]
    pub events: Vec<ReceiptSessionEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionStatus {
    /// Subscription just activated; recurring authorization is live.
    Active,
    /// Renewal charge ran successfully.
    Renewed,
    /// Subscription cancelled on-chain.
    Cancelled,
    /// Plan-administration action (createPlan / updatePlan / deletePlan,
    /// initSubscriptionAuthority / closeSubscriptionAuthority).
    Admin,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSessionEvent {
    /// `deposit`, `consume`, `refund`, `distribute`.
    pub kind: String,
    pub sender: String,
    pub receiver: String,
    pub asset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub decimals: u8,
    pub raw_amount: String,
    pub ui_amount: f64,
}

/// Confirmed status of the transaction itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    Success,
    Failed,
}

/// A single value movement attributed to a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptTransfer {
    /// Source address (base58). For token transfers this is the token-account
    /// owner when available, otherwise the token account.
    pub sender: String,
    /// Destination address (base58). For token transfers this is the
    /// destination token-account owner when available, otherwise the token
    /// account.
    pub receiver: String,
    /// Asset identifier. `"SOL"` for the native asset, otherwise the SPL mint.
    pub asset: String,
    /// Token symbol if known (from the registry, hard-coded curated table, or
    /// upstream metadata lookup).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Long-form token name when available (e.g. "USD Coin").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Token icon URL when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    /// Decimals used to format `raw_amount`.
    pub decimals: u8,
    /// Raw on-chain amount as a string — preserves u64 precision.
    pub raw_amount: String,
    /// Human-readable amount (`raw_amount / 10^decimals`).
    pub ui_amount: f64,
    /// Optional memo paired with this transfer (decoded from the closest
    /// SPL memo instruction in the same transaction).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// Aggregated payment split (used by `mpp/charge` with multiple recipients).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptSplit {
    pub recipient: String,
    pub raw_amount: String,
    pub ui_amount: f64,
    /// Share of the total in basis points (1/100 of a percent).
    pub bps: u16,
}

/// Aggregate amount carried by [`Receipt::total`] and session blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptAmount {
    pub asset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    pub decimals: u8,
    pub raw_amount: String,
    pub ui_amount: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_aliases_parse() {
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("mainnet-beta".parse::<Network>().unwrap(), Network::Mainnet);
        assert_eq!("sandbox".parse::<Network>().unwrap(), Network::Sandbox);
        assert_eq!("surfpool".parse::<Network>().unwrap(), Network::Sandbox);
        assert_eq!("localnet".parse::<Network>().unwrap(), Network::Sandbox);
        assert!("devnet".parse::<Network>().is_err());
    }

    #[test]
    fn network_serialises_canonical() {
        assert_eq!(
            serde_json::to_string(&Network::Mainnet).unwrap(),
            "\"mainnet\""
        );
        assert_eq!(
            serde_json::to_string(&Network::Sandbox).unwrap(),
            "\"sandbox\""
        );
    }

    #[test]
    fn channel_status_serializes_sealed_and_accepts_legacy_finalized() {
        assert_eq!(
            serde_json::to_string(&ChannelStatus::Sealed).unwrap(),
            "\"sealed\""
        );
        assert_eq!(
            serde_json::from_str::<ChannelStatus>("\"finalized\"").unwrap(),
            ChannelStatus::Sealed
        );
    }
}
