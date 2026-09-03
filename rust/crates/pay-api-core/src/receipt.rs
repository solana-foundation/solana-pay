//! Build a [`Receipt`] from a Solana `getTransaction` (jsonParsed) result.
//!
//! The classifier is intentionally heuristic — it inspects program IDs and the
//! parsed instruction shape exposed by the RPC and maps them onto pay-protocol
//! intents (`x402/exact`, `mpp/charge`, `mpp/session`, or plain `transfer`).
//! Fully decoding instruction data is left to the on-chain SDKs.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::Engine;
use bs58;
use pay_api_types::{
    ChannelStatus as WireChannelStatus, Network, Receipt, ReceiptAccountCreation, ReceiptAmount,
    ReceiptIntent, ReceiptIntentKind, ReceiptSession, ReceiptSessionEvent, ReceiptSplit,
    ReceiptStatus, ReceiptSubscription, ReceiptTransfer, SubscriptionStatus,
};
use serde_json::Value;

use crate::channel_state::{ChannelState, ChannelStatus, fetch_channel};
use crate::error::{Error, Result};
use crate::rpc::RpcClient;
use crate::stablecoin::Stablecoin;
use crate::subscription_state::{fetch_recurring_delegation, period_label};
use crate::token_metadata::{TokenMetadata, resolve_mints};

/// Canonical SPL memo program v2.
pub const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// Original SPL memo program v1 (still observed on-chain).
pub const MEMO_PROGRAM_V1: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
/// MPP payment-channels program. Re-exported from pay-kit so the receipt
/// classifier always matches the deployed program id instead of drifting from a
/// hand-copied constant.
pub use pay_kit::core::payment_channels::PAYMENT_CHANNELS_PROGRAM_ID as PAYMENT_CHANNELS_PROGRAM;
/// MPP multi-delegator program (pull-mode sessions).
pub const MULTI_DELEGATOR_PROGRAM: &str = "EPEUTog1kptYkthDJF6MuB1aM4aDAwHYwoF32Rzv5rqg";
/// Canonical MPP subscriptions program (shares discriminator space with the
/// multi-delegator but is the spec'd program for the `subscription` intent).
pub const SUBSCRIPTIONS_PROGRAM: &str = "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44";
/// Associated Token Account program (handles `create` / `createIdempotent`).
pub const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// Discriminators that — on either the multi-delegator OR the subscriptions
/// program — denote the subscription intent rather than the pull-mode session
/// intent. Used by the classifier to decide which intent kind to emit.
const SUBSCRIPTION_DISCRIMINATORS: &[u8] = &[
    0,  // initializeSubscriptionAuthority
    6,  // closeSubscriptionAuthority
    7,  // createPlan
    8,  // updatePlan
    9,  // deletePlan
    10, // transferSubscription (renew)
    11, // subscribe
    12, // cancelSubscription
];

const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";

/// Build a fully-resolved [`Receipt`], including token metadata and (when
/// applicable) an MPP session breakdown.
pub async fn build_receipt(
    rpc: &RpcClient,
    rpc_url: &str,
    signature: &str,
    network: Network,
    rpc_value: &Value,
    stablecoins: &[Stablecoin],
) -> Result<Receipt> {
    let mut receipt = build_receipt_skeleton(signature, network, rpc_value, stablecoins)?;
    let mints = collect_mints(&receipt);
    let mut metadata = resolve_mints(rpc, rpc_url, network, stablecoins, &mints).await;
    apply_metadata(&mut receipt, &metadata);

    if let Some(ref mut session) = receipt.session {
        apply_metadata_to_session(session, &metadata);
    }

    // For mpp/session, reconcile transfer legs with the wallet owners exposed
    // in `meta.postTokenBalances`. This works for both open and closed
    // channels (a settled channel's account shrinks to a 1-byte marker, so
    // fetching its PDA tells us nothing) and uses information already inside
    // the same getTransaction response.
    if matches!(receipt.intent.kind, ReceiptIntentKind::MppSession) {
        let ata_owners = collect_ata_owners(rpc_value);
        reconcile_session_via_balances(&mut receipt, &ata_owners);

        // Best-effort: if the channel is still open, decode its state to
        // attach the on-chain `payer`, `payee`, and `status`.
        let candidates = session_account_candidates(rpc_value);
        if !candidates.is_empty()
            && let Ok(Some(channel)) = fetch_channel(rpc, rpc_url, &candidates).await
        {
            attach_channel_state(&mut receipt, &channel);
        }
    }

    if matches!(receipt.intent.kind, ReceiptIntentKind::MppSubscription) {
        // Try to find the RecurringDelegation PDA in the instruction's
        // accounts list and decode period_hours / amount / start / expiry.
        let candidates = session_account_candidates(rpc_value);
        if !candidates.is_empty()
            && let Ok(Some(state)) = fetch_recurring_delegation(rpc, rpc_url, &candidates).await
        {
            let mint = state.mint.to_string();
            if !metadata.contains_key(&mint) {
                metadata.extend(resolve_mints(rpc, rpc_url, network, stablecoins, &[mint]).await);
            }
            attach_recurring_delegation_state(&mut receipt, &state);
        }
        if let Some(ref mut subscription) = receipt.subscription {
            attach_subscription_metadata(subscription, &metadata);
        }
    }
    Ok(receipt)
}

/// Build an `ata_address → owner_wallet` map from the transaction's pre/post
/// token balances. Both pre and post are scanned so we cover token accounts
/// that only exist on one side.
fn collect_ata_owners(rpc_value: &Value) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let meta = rpc_value.get("meta").cloned().unwrap_or(Value::Null);
    let account_keys = collect_account_keys(
        &rpc_value
            .pointer("/transaction/message")
            .cloned()
            .unwrap_or(Value::Null),
    );
    for field in ["postTokenBalances", "preTokenBalances"] {
        let Some(arr) = meta.get(field).and_then(Value::as_array) else {
            continue;
        };
        for entry in arr {
            let Some(account_index) = entry.get("accountIndex").and_then(Value::as_u64) else {
                continue;
            };
            let owner = entry
                .get("owner")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if owner.is_empty() {
                continue;
            }
            if let Some(addr) = account_keys.get(account_index as usize) {
                map.entry(addr.clone()).or_insert(owner);
            }
        }
    }
    map
}

/// Reclassify session events using `ata_owners` so we can tell apart:
///
/// - operator's payee (fee_payer's wallet receives)
/// - original payer refund (any non-operator wallet receiving from the channel)
/// - platform splits / treasury (other recipients)
fn reconcile_session_via_balances(receipt: &mut Receipt, ata_owners: &BTreeMap<String, String>) {
    let Some(session) = receipt.session.as_mut() else {
        return;
    };
    let operator = receipt.fee_payer.clone();

    // First pass: classify based on operator/non-operator and accumulate
    // totals per wallet to identify the largest non-operator refund.
    let mut wallet_total: BTreeMap<String, u128> = BTreeMap::new();
    for ev in &session.events {
        let raw: u128 = ev.raw_amount.parse().unwrap_or(0);
        let owner = ata_owners
            .get(&ev.receiver)
            .cloned()
            .unwrap_or_else(|| ev.receiver.clone());
        *wallet_total.entry(owner).or_default() += raw;
    }

    let payer_wallet = wallet_total
        .iter()
        .filter(|(w, _)| *w != &operator)
        .max_by_key(|(_, raw)| **raw)
        .map(|(w, _)| w.clone());

    let mut consumed_total: u128 = 0;
    let mut refunded_total: u128 = 0;
    let mut sample_decimals: u8 = 0;
    let mut sample_asset = String::new();
    let mut sample_symbol: Option<String> = None;
    let mut sample_name: Option<String> = None;
    let mut sample_logo: Option<String> = None;

    for ev in session.events.iter_mut() {
        let raw: u128 = ev.raw_amount.parse().unwrap_or(0);
        sample_decimals = ev.decimals;
        sample_asset = ev.asset.clone();
        if sample_symbol.is_none() {
            sample_symbol = ev.symbol.clone();
        }
        // Resolve the owner exactly as the first pass does: when the receiver
        // isn't an ATA tracked in `ata_owners` it is already a wallet address,
        // so fall back to it. Without this fallback, wallet-keyed receivers
        // resolve to `None`, the refund/consume checks both miss, and every leg
        // falls through to `consumed` — making a settleAndSeal report the
        // whole channel balance as consumed instead of just the payee's share.
        let owner = ata_owners
            .get(&ev.receiver)
            .cloned()
            .unwrap_or_else(|| ev.receiver.clone());
        let is_refund = matches!(&payer_wallet, Some(p) if p == &owner);
        let is_consume = owner == operator;
        if is_refund {
            ev.kind = "refund".to_string();
            refunded_total += raw;
        } else if is_consume {
            ev.kind = "consume".to_string();
            consumed_total += raw;
        } else {
            ev.kind = "distribute".to_string();
            consumed_total += raw;
        }
    }

    // Pick up name/logo from the matching transfer for the totals.
    for t in &receipt.transfers {
        if t.asset == sample_asset {
            if sample_name.is_none() {
                sample_name = t.name.clone();
            }
            if sample_logo.is_none() {
                sample_logo = t.logo_uri.clone();
            }
        }
    }

    session.payer = payer_wallet.clone();
    // For settle / seal / distribute, the wallet receiving the operator's
    // leg is the fee_payer — they signed the transaction. For open / topUp
    // the original `build_session` value already represents the channel-ATA
    // owner, which is the channel PDA; leave it untouched in that case.
    let action_acts_as_operator = matches!(
        session.action.as_str(),
        "settle" | "settleAndSeal" | "distribute" | "seal" | "requestClose"
    );
    if action_acts_as_operator {
        session.payee = Some(operator.clone());
    }
    session.consumed = amount_from_raw(
        consumed_total,
        sample_decimals,
        &sample_asset,
        &sample_symbol,
        &sample_name,
        &sample_logo,
    );
    session.refunded = amount_from_raw(
        refunded_total,
        sample_decimals,
        &sample_asset,
        &sample_symbol,
        &sample_name,
        &sample_logo,
    );

    // Re-derive distributed[] from the consume + distribute events so the
    // refund leg is excluded from the operator-side breakdown.
    let mut by_recipient: BTreeMap<String, u128> = BTreeMap::new();
    for ev in &session.events {
        if ev.kind == "consume" || ev.kind == "distribute" {
            let raw: u128 = ev.raw_amount.parse().unwrap_or(0);
            *by_recipient.entry(ev.receiver.clone()).or_default() += raw;
        }
    }
    let grand = consumed_total.max(1);
    session.distributed = by_recipient
        .into_iter()
        .map(|(recipient, raw)| {
            let bps = ((raw * 10_000) / grand) as u16;
            ReceiptSplit {
                recipient,
                raw_amount: raw.to_string(),
                ui_amount: ui_amount_from_raw(raw, sample_decimals),
                bps,
            }
        })
        .collect();

    // Infer channel lifecycle from the action when the on-chain state isn't
    // available (e.g. account already closed).
    session.channel_status = Some(match session.action.as_str() {
        "open" | "topUp" => WireChannelStatus::Open,
        "requestClose" => WireChannelStatus::Closing,
        "seal" | "settleAndSeal" | "withdrawPayer" => WireChannelStatus::Sealed,
        "settle" | "distribute" => WireChannelStatus::Open,
        _ => WireChannelStatus::Unknown,
    });
}

fn attach_channel_state(receipt: &mut Receipt, channel: &ChannelState) {
    let Some(session) = receipt.session.as_mut() else {
        return;
    };
    session.channel = Some(channel.address.clone());
    session.channel_status = Some(match channel.status {
        ChannelStatus::Open => WireChannelStatus::Open,
        ChannelStatus::Closing => WireChannelStatus::Closing,
        ChannelStatus::Sealed => WireChannelStatus::Sealed,
        ChannelStatus::Unknown => WireChannelStatus::Unknown,
    });
    // The on-chain Channel struct is authoritative for payer / payee when the
    // account is still open.
    session.payer = Some(channel.payer.to_string());
    session.payee = Some(channel.payee.to_string());
}

/// Fill in subscription fields that can only be read from the on-chain
/// RecurringDelegation account: subscriber, per-period amount, period length
/// and expiry. Mirrors the channel-state pattern so the skeleton stays
/// usable without the RPC round-trip.
fn attach_recurring_delegation_state(
    receipt: &mut Receipt,
    state: &crate::subscription_state::RecurringDelegationState,
) {
    let Some(subscription) = receipt.subscription.as_mut() else {
        return;
    };
    subscription.subscription_id = Some(state.address.clone());
    if subscription.subscriber.is_none() {
        subscription.subscriber = Some(state.subscriber.to_string());
    }

    let period_hours = state.period_length_s / 3600;
    if period_hours > 0 {
        subscription.period_hours = Some(period_hours);
        subscription.period_label = Some(period_label(period_hours));
    }
    if state.current_period_start_ts > 0 {
        subscription.period_start_ts = Some(state.current_period_start_ts);
        subscription.period_end_ts = Some(
            state
                .current_period_start_ts
                .saturating_add(state.period_length_s as i64),
        );
    }
    if state.expiry_ts > 0 {
        subscription.expires_at_ts = Some(state.expiry_ts);
    }
    if subscription.period_amount.is_none() && state.amount_per_period > 0 {
        subscription.period_amount = Some(ReceiptAmount {
            asset: state.mint.to_string(),
            symbol: None,
            name: None,
            logo_uri: None,
            decimals: 0,
            raw_amount: state.amount_per_period.to_string(),
            ui_amount: state.amount_per_period as f64,
        });
    }
}

fn attach_subscription_metadata(
    subscription: &mut ReceiptSubscription,
    metadata: &HashMap<String, TokenMetadata>,
) {
    if let Some(ref mut amount) = subscription.period_amount
        && let Some(meta) = metadata.get(&amount.asset)
    {
        apply_meta_to_amount(amount, meta);
        if amount.decimals == 0
            && let Some(d) = meta.decimals
        {
            amount.decimals = d;
            let raw: u128 = amount.raw_amount.parse().unwrap_or(0);
            amount.ui_amount = ui_amount_from_raw(raw, d);
        }
    }
    for ev in &mut subscription.events {
        if ev.symbol.is_none()
            && let Some(meta) = metadata.get(&ev.asset)
        {
            ev.symbol = meta.symbol.clone();
        }
    }
}

fn session_account_candidates(rpc_value: &Value) -> Vec<String> {
    let message = rpc_value
        .pointer("/transaction/message")
        .cloned()
        .unwrap_or(Value::Null);
    let top = message
        .get("instructions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut set = std::collections::BTreeSet::new();
    for ix in &top {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        if program != PAYMENT_CHANNELS_PROGRAM
            && program != MULTI_DELEGATOR_PROGRAM
            && program != SUBSCRIPTIONS_PROGRAM
        {
            continue;
        }
        if let Some(accs) = ix.get("accounts").and_then(Value::as_array) {
            for a in accs {
                if let Some(s) = a.as_str() {
                    set.insert(s.to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

fn amount_from_raw(
    raw: u128,
    decimals: u8,
    asset: &str,
    symbol: &Option<String>,
    name: &Option<String>,
    logo_uri: &Option<String>,
) -> Option<ReceiptAmount> {
    if raw == 0 {
        return None;
    }
    Some(ReceiptAmount {
        asset: asset.to_string(),
        symbol: symbol.clone(),
        name: name.clone(),
        logo_uri: logo_uri.clone(),
        decimals,
        raw_amount: raw.to_string(),
        ui_amount: ui_amount_from_raw(raw, decimals),
    })
}

/// Pure synchronous build path used by unit tests and offline callers.
pub fn build_receipt_skeleton(
    signature: &str,
    network: Network,
    rpc_value: &Value,
    stablecoins: &[Stablecoin],
) -> Result<Receipt> {
    let slot = rpc_value.get("slot").and_then(Value::as_u64);
    let block_time = rpc_value.get("blockTime").and_then(Value::as_i64);
    let meta = rpc_value.get("meta").cloned().unwrap_or(Value::Null);
    let transaction = rpc_value.get("transaction").cloned().unwrap_or(Value::Null);
    let message = transaction.get("message").cloned().unwrap_or(Value::Null);

    let status = match meta.pointer("/err") {
        Some(err) if !err.is_null() => ReceiptStatus::Failed,
        _ => ReceiptStatus::Success,
    };

    let fee_lamports = meta
        .get("fee")
        .and_then(Value::as_u64)
        .map(|fee| fee.to_string())
        .unwrap_or_else(|| "0".to_string());

    let account_keys = collect_account_keys(&message);
    let fee_payer = account_keys.first().cloned().ok_or(Error::RpcMalformed)?;

    let top_instructions = message
        .get("instructions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let inner_instructions = flatten_inner_instructions(&meta);

    let mut programs: Vec<String> = top_instructions
        .iter()
        .filter_map(program_id_for_instruction)
        .collect();
    programs.sort();
    programs.dedup();

    let mut transfers =
        extract_token_transfers(&top_instructions, &inner_instructions, stablecoins);
    let mut balance_fallback_count = 0;
    if transfers.is_empty() {
        // Some RPCs (e.g. Surfpool) return inner SPL transfers *unparsed*, so the
        // instruction walk finds nothing. Fall back to the net token-balance
        // deltas the RPC always reports, so CPI-driven transfers — payment-channel
        // settle/distribute in particular — still surface instead of an empty receipt.
        transfers = extract_transfers_from_balances(rpc_value, stablecoins);
        balance_fallback_count = transfers.len();
    }
    transfers.extend(extract_sol_transfers(
        &top_instructions,
        &inner_instructions,
    ));
    attach_memos_to_transfers(
        &top_instructions,
        &inner_instructions,
        &mut transfers,
        balance_fallback_count,
    );

    let intent = classify_intent(&programs, &top_instructions, &transfers);

    let splits = if matches!(intent.kind, ReceiptIntentKind::MppCharge) {
        build_splits(&transfers)
    } else {
        Vec::new()
    };

    let total = aggregate_total(&transfers);

    let session = match intent.kind {
        ReceiptIntentKind::MppSession => Some(build_session(
            intent
                .action
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            intent.program_id.clone(),
            &transfers,
            &fee_payer,
            &top_instructions,
            &account_keys,
        )),
        _ => None,
    };

    // When a transaction touches the subscriptions program we synthesize a
    // subscription block from the instructions + parsed token transfers; the
    // async path further enriches it with on-chain RecurringDelegation
    // state. The /v1/subscriptions/* handlers can build their own receipt
    // directly when they already know the plan/period — anyone hitting the
    // generic /v1/receipt endpoint for a subscription signature still gets
    // the full block.
    let subscription = match intent.kind {
        ReceiptIntentKind::MppSubscription => Some(build_subscription(
            intent
                .action
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            &transfers,
            &fee_payer,
        )),
        _ => None,
    };

    let inner_groups = rpc_value
        .pointer("/meta/innerInstructions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let account_creations = detect_account_creations(&top_instructions, &inner_groups);

    Ok(Receipt {
        signature: signature.to_string(),
        network,
        status,
        slot,
        block_time,
        fee_payer,
        fee_lamports,
        confirmation_status: None,
        intent,
        transfers,
        splits,
        total,
        session,
        subscription,
        programs,
        account_creations,
        sol_usd_price: None,
    })
}

/// Detect SPL Associated Token Account creations (both `create` and
/// `createIdempotent` variants). An idempotent call only allocates when the
/// ATA didn't already exist, so we confirm by looking for a `system.createAccount`
/// in the instruction's inner-instructions group.
fn detect_account_creations(top: &[Value], inner_groups: &[Value]) -> Vec<ReceiptAccountCreation> {
    let mut out = Vec::new();
    for (idx, ix) in top.iter().enumerate() {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        let program_name = ix.get("program").and_then(Value::as_str).unwrap_or("");
        if program != ATA_PROGRAM && program_name != "spl-associated-token-account" {
            continue;
        }
        let parsed = match ix.get("parsed") {
            Some(p) => p,
            None => continue,
        };
        let kind = parsed.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(kind, "create" | "createIdempotent") {
            continue;
        }

        let info = match parsed.get("info") {
            Some(i) => i,
            None => continue,
        };
        let account = info
            .get("account")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        let wallet = info
            .get("wallet")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mint = info.get("mint").and_then(Value::as_str).map(str::to_string);
        let paid_by = info
            .get("source")
            .and_then(Value::as_str)
            .map(str::to_string);

        // Look up inner instructions for this top-level index. A real
        // allocation has a `system.createAccount` in there; idempotent calls
        // on existing ATAs have no inner createAccount and should be skipped.
        let mut rent_lamports: u64 = 0;
        for grp in inner_groups {
            let group_idx = grp.get("index").and_then(Value::as_u64).unwrap_or(u64::MAX);
            if group_idx != idx as u64 {
                continue;
            }
            let Some(ixs) = grp.get("instructions").and_then(Value::as_array) else {
                continue;
            };
            for inner in ixs {
                let inner_type = inner
                    .pointer("/parsed/type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if inner_type == "createAccount"
                    && let Some(l) = inner
                        .pointer("/parsed/info/lamports")
                        .and_then(Value::as_u64)
                {
                    rent_lamports = rent_lamports.saturating_add(l);
                }
            }
        }

        if rent_lamports == 0 {
            // No allocation actually happened (idempotent path, ATA already
            // existed). Don't surface it as a cost.
            continue;
        }

        out.push(ReceiptAccountCreation {
            account,
            wallet,
            mint,
            symbol: None,
            logo_uri: None,
            rent_lamports: rent_lamports.to_string(),
            paid_by,
        });
    }
    out
}

/// Apply the optional confirmation status from `getSignatureStatuses`.
pub fn apply_confirmation_status(receipt: &mut Receipt, status_value: Option<&Value>) {
    if let Some(value) = status_value
        && let Some(s) = value.get("confirmationStatus").and_then(Value::as_str)
    {
        receipt.confirmation_status = Some(s.to_string());
    }
}

fn collect_mints(receipt: &Receipt) -> Vec<String> {
    let mut set = BTreeSet::new();
    for t in &receipt.transfers {
        set.insert(t.asset.clone());
    }
    if let Some(total) = &receipt.total {
        set.insert(total.asset.clone());
    }
    for ac in &receipt.account_creations {
        if let Some(mint) = &ac.mint {
            set.insert(mint.clone());
        }
    }
    set.into_iter().collect()
}

fn apply_metadata(receipt: &mut Receipt, metadata: &HashMap<String, TokenMetadata>) {
    for t in &mut receipt.transfers {
        if let Some(meta) = metadata.get(&t.asset) {
            apply_meta_to_transfer(t, meta);
        }
    }
    if let Some(ref mut total) = receipt.total
        && let Some(meta) = metadata.get(&total.asset)
    {
        apply_meta_to_amount(total, meta);
    }
    for split in &mut receipt.splits {
        // splits already inherit decimals from the underlying transfers; no
        // metadata to apply here.
        let _ = split;
    }
    for ac in &mut receipt.account_creations {
        if let Some(mint) = &ac.mint
            && let Some(meta) = metadata.get(mint)
        {
            if ac.symbol.is_none() {
                ac.symbol = meta.symbol.clone();
            }
            if ac.logo_uri.is_none() {
                ac.logo_uri = meta.logo_uri.clone();
            }
        }
    }
}

fn apply_metadata_to_session(
    session: &mut ReceiptSession,
    metadata: &HashMap<String, TokenMetadata>,
) {
    if let Some(ref mut deposit) = session.deposit
        && let Some(meta) = metadata.get(&deposit.asset)
    {
        apply_meta_to_amount(deposit, meta);
    }
    if let Some(ref mut consumed) = session.consumed
        && let Some(meta) = metadata.get(&consumed.asset)
    {
        apply_meta_to_amount(consumed, meta);
    }
    if let Some(ref mut refunded) = session.refunded
        && let Some(meta) = metadata.get(&refunded.asset)
    {
        apply_meta_to_amount(refunded, meta);
    }
    for ev in &mut session.events {
        if let Some(meta) = metadata.get(&ev.asset)
            && ev.symbol.is_none()
        {
            ev.symbol = meta.symbol.clone();
        }
    }
}

fn apply_meta_to_transfer(t: &mut ReceiptTransfer, meta: &TokenMetadata) {
    if t.symbol.is_none() {
        t.symbol = meta.symbol.clone();
    }
    if t.name.is_none() {
        t.name = meta.name.clone();
    }
    if t.logo_uri.is_none() {
        t.logo_uri = meta.logo_uri.clone();
    }
}

fn apply_meta_to_amount(a: &mut ReceiptAmount, meta: &TokenMetadata) {
    if a.symbol.is_none() {
        a.symbol = meta.symbol.clone();
    }
    if a.name.is_none() {
        a.name = meta.name.clone();
    }
    if a.logo_uri.is_none() {
        a.logo_uri = meta.logo_uri.clone();
    }
}

fn flatten_inner_instructions(meta: &Value) -> Vec<Value> {
    meta.get("innerInstructions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .flat_map(|entry| {
            entry
                .get("instructions")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect()
}

fn collect_account_keys(message: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(arr) = message.get("accountKeys").and_then(Value::as_array) {
        for entry in arr {
            if let Some(s) = entry.as_str() {
                out.push(s.to_string());
            } else if let Some(s) = entry.get("pubkey").and_then(Value::as_str) {
                out.push(s.to_string());
            }
        }
    }
    out
}

fn program_id_for_instruction(instruction: &Value) -> Option<String> {
    instruction
        .get("programId")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Decode a single instruction as an SPL memo. Returns `None` for any
/// non-memo instruction or when the decoded payload sanitises to an
/// empty string.
fn decode_memo_ix(ix: &Value) -> Option<String> {
    let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
    let program_name = ix.get("program").and_then(Value::as_str).unwrap_or("");
    let is_memo =
        program == MEMO_PROGRAM || program == MEMO_PROGRAM_V1 || program_name == "spl-memo";
    if !is_memo {
        return None;
    }
    if let Some(text) = ix.get("parsed").and_then(Value::as_str) {
        return sanitize_memo(text);
    }
    if let Some(text) = ix.pointer("/parsed/info/memo").and_then(Value::as_str) {
        return sanitize_memo(text);
    }
    if let Some(data) = ix.get("data").and_then(Value::as_str) {
        if let Ok(bytes) = bs58::decode(data).into_vec()
            && let Ok(text) = std::str::from_utf8(&bytes)
            && let Some(clean) = sanitize_memo(text)
        {
            return Some(clean);
        }
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data)
            && let Ok(text) = std::str::from_utf8(&bytes)
        {
            return sanitize_memo(text);
        }
    }
    None
}

/// Memo payloads originate from arbitrary on-chain bytes — they may
/// carry control characters, Unicode bidi-override characters that can
/// spoof rendered text, or be excessively long. This applies the same
/// hygiene rules the UI uses so consumers of the API receive memo
/// strings safe to render directly.
///
/// Specifically: drop ASCII / Unicode C0/C1 control characters (keeping
/// tab and newline), strip the bidirectional override / isolate range
/// (`U+202A..U+202E`, `U+2066..U+2069`), trim leading/trailing
/// whitespace, and truncate to `MAX_DISPLAY_LEN` graphemes with an
/// ellipsis. Returns `None` when nothing meaningful is left.
const MAX_DISPLAY_LEN: usize = 200;

fn sanitize_memo(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .filter(|c| {
            // Keep \t and \n; drop everything else in the C0/C1 ranges.
            if *c == '\t' || *c == '\n' {
                return true;
            }
            if c.is_control() {
                return false;
            }
            // Drop bidirectional formatting overrides + isolates.
            !matches!(*c,
                '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{200E}' | '\u{200F}'
            )
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return None;
    }
    let char_count = trimmed.chars().count();
    if char_count <= MAX_DISPLAY_LEN {
        return Some(trimmed.to_string());
    }
    let mut out: String = trimmed.chars().take(MAX_DISPLAY_LEN).collect();
    out.push('…');
    Some(out)
}

/// Return `true` if the instruction is a token or SOL transfer that we
/// emit as a `ReceiptTransfer`. Must stay in sync with the filters in
/// `extract_token_transfers` and `extract_sol_transfers` so the memo
/// pairing pass can align positions one-to-one with the transfer list.
fn is_transfer_ix(ix: &Value) -> bool {
    let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
    let kind = ix
        .pointer("/parsed/type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if program == SPL_TOKEN_PROGRAM || program == TOKEN_2022_PROGRAM {
        return matches!(
            kind,
            "transfer" | "transferChecked" | "mintTo" | "mintToChecked"
        );
    }
    if program == SYSTEM_PROGRAM {
        return matches!(kind, "transfer" | "transferChecked");
    }
    false
}

/// Pair each memo instruction with its nearest transfer (by position in
/// the linearised top-then-inner instruction stream). Memos are claimed
/// at most once; transfers without a nearby memo are left as-is.
///
/// Conventions this handles:
/// - `transfer; memo` (typical x402/exact ordering — memo carries the nonce)
/// - `memo; transfer` (MPP charge with credential proof before the move)
/// - multiple `(memo, transfer)` pairs in a multi-recipient charge
/// - lone memos with no transfers (silently dropped)
fn attach_memos_to_transfers(
    top: &[Value],
    inner: &[Value],
    transfers: &mut [ReceiptTransfer],
    balance_fallback_count: usize,
) {
    let all: Vec<&Value> = top.iter().chain(inner.iter()).collect();
    let mut memo_positions: Vec<(usize, String)> = Vec::new();
    let mut transfer_positions: Vec<usize> = Vec::new();
    for (pos, ix) in all.iter().enumerate() {
        if let Some(text) = decode_memo_ix(ix) {
            memo_positions.push((pos, text));
            continue;
        }
        if is_transfer_ix(ix) {
            transfer_positions.push(pos);
        }
    }
    // `transfer_positions` should align 1:1 with `transfers` because both
    // walks visit the same instructions in the same order. Balance-derived
    // fallback transfers are the one expected exception: they have no parsed
    // instruction positions, so pair memos by receipt order for that prefix.
    if transfer_positions.len() != transfers.len() {
        attach_memos_to_balance_fallback(&memo_positions, transfers, balance_fallback_count);
        return;
    }
    // Assign memos to transfers by *global* minimal proximity rather than
    // letting each transfer greedily claim its nearest memo in list order.
    // Iterating transfers first lets an earlier transfer steal a memo that
    // actually sits closer to a later transfer: e.g. `transfer; transfer;
    // memo` (a multi-recipient charge with one trailing memo) would attach
    // the memo to the *first* recipient when it belongs to the second. Build
    // every (distance, memo, transfer) candidate, assign in ascending-distance
    // order, and skip any memo/transfer already claimed — so each memo lands on
    // its nearest still-available transfer.
    let mut candidates: Vec<(usize, usize, usize)> = Vec::new();
    for (m_idx, (memo_pos, _)) in memo_positions.iter().enumerate() {
        for (t_idx, transfer_pos) in transfer_positions.iter().enumerate() {
            candidates.push((transfer_pos.abs_diff(*memo_pos), m_idx, t_idx));
        }
    }
    // Sort by distance, then by memo/transfer position for deterministic ties.
    candidates.sort_by_key(|&(dist, m_idx, t_idx)| {
        (dist, memo_positions[m_idx].0, transfer_positions[t_idx])
    });
    let mut memo_claimed = vec![false; memo_positions.len()];
    let mut transfer_claimed = vec![false; transfers.len()];
    for (_, m_idx, t_idx) in candidates {
        if memo_claimed[m_idx] || transfer_claimed[t_idx] {
            continue;
        }
        transfers[t_idx].memo = Some(memo_positions[m_idx].1.clone());
        memo_claimed[m_idx] = true;
        transfer_claimed[t_idx] = true;
    }
}

fn attach_memos_to_balance_fallback(
    memo_positions: &[(usize, String)],
    transfers: &mut [ReceiptTransfer],
    balance_fallback_count: usize,
) {
    let fallback_count = balance_fallback_count.min(transfers.len());
    if fallback_count == 0 || memo_positions.is_empty() {
        return;
    }

    for ((_, memo), transfer) in memo_positions
        .iter()
        .zip(transfers.iter_mut().take(fallback_count))
    {
        if transfer.memo.is_none() {
            transfer.memo = Some(memo.clone());
        }
    }
}

fn extract_token_transfers(
    top: &[Value],
    inner: &[Value],
    stablecoins: &[Stablecoin],
) -> Vec<ReceiptTransfer> {
    let mut out = Vec::new();
    for ix in top.iter().chain(inner.iter()) {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        if program != SPL_TOKEN_PROGRAM && program != TOKEN_2022_PROGRAM {
            continue;
        }
        let parsed = match ix.get("parsed") {
            Some(value) => value,
            None => continue,
        };
        let kind = parsed.get("type").and_then(Value::as_str).unwrap_or("");
        if !matches!(
            kind,
            "transfer" | "transferChecked" | "mintTo" | "mintToChecked"
        ) {
            continue;
        }
        let info = match parsed.get("info") {
            Some(value) => value,
            None => continue,
        };

        let (raw_amount, decimals) = if let Some(token_amount) = info.get("tokenAmount") {
            let amount_str = token_amount
                .get("amount")
                .and_then(Value::as_str)
                .unwrap_or("0")
                .to_string();
            let decimals = token_amount
                .get("decimals")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u8;
            (amount_str, decimals)
        } else {
            let amount_str = info
                .get("amount")
                .and_then(Value::as_str)
                .unwrap_or("0")
                .to_string();
            (amount_str, 0)
        };

        let mint = info.get("mint").and_then(Value::as_str).map(str::to_string);

        let sender = info
            .get("authority")
            .or_else(|| info.get("source"))
            .or_else(|| info.get("multisigAuthority"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let receiver = info
            .get("destination")
            .or_else(|| info.get("account"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let (symbol, decimals) = match &mint {
            Some(mint_str) => match stablecoins.iter().find(|c| c.mint.to_string() == *mint_str) {
                Some(coin) => (Some(coin.symbol.clone()), coin.decimals),
                None => (None, decimals),
            },
            None => (None, decimals),
        };

        let raw_u128: u128 = raw_amount.parse().unwrap_or(0);
        let ui_amount = ui_amount_from_raw(raw_u128, decimals);

        out.push(ReceiptTransfer {
            sender,
            receiver,
            asset: mint.unwrap_or_else(|| "UNKNOWN".to_string()),
            symbol,
            name: None,
            logo_uri: None,
            decimals,
            raw_amount,
            ui_amount,
            memo: None,
        });
    }
    out
}

/// Derive token transfers from `meta.{pre,post}TokenBalances` deltas.
///
/// Used as a fallback when instruction-based extraction finds nothing — e.g.
/// when the RPC returns inner SPL transfers unparsed (Surfpool does this for
/// payment-channel settle/distribute CPIs). Balance deltas are always reported,
/// so credits are paired against debits of the same mint instead of attributing
/// every credit to one transaction-wide sender.
fn extract_transfers_from_balances(
    rpc_value: &Value,
    stablecoins: &[Stablecoin],
) -> Vec<ReceiptTransfer> {
    #[derive(Clone)]
    struct BalanceEntry {
        owner: String,
        mint: String,
        decimals: u8,
        amount: u128,
    }

    #[derive(Clone)]
    struct BalanceDelta {
        account_index: u64,
        owner: String,
        mint: String,
        decimals: u8,
        raw: u128,
    }

    fn index_balances(arr: &[Value], account_keys: &[String]) -> BTreeMap<u64, BalanceEntry> {
        let mut map = BTreeMap::new();
        for entry in arr {
            let Some(idx) = entry.get("accountIndex").and_then(Value::as_u64) else {
                continue;
            };
            let owner = entry
                .get("owner")
                .and_then(Value::as_str)
                .filter(|owner| !owner.is_empty())
                .or_else(|| account_keys.get(idx as usize).map(String::as_str))
                .unwrap_or_default()
                .to_string();
            if owner.is_empty() {
                continue;
            }
            let mint = entry
                .get("mint")
                .and_then(Value::as_str)
                .filter(|mint| !mint.is_empty())
                .unwrap_or_default()
                .to_string();
            if mint.is_empty() {
                continue;
            }
            let token_amount = entry.get("uiTokenAmount");
            let amount = token_amount
                .and_then(|t| t.get("amount"))
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(0);
            let decimals = token_amount
                .and_then(|t| t.get("decimals"))
                .and_then(Value::as_u64)
                .unwrap_or(0) as u8;
            map.insert(
                idx,
                BalanceEntry {
                    owner,
                    mint,
                    decimals,
                    amount,
                },
            );
        }
        map
    }

    fn build_transfer(
        sender: String,
        receiver: String,
        mint: String,
        decimals: u8,
        raw: u128,
        stablecoins: &[Stablecoin],
    ) -> ReceiptTransfer {
        let (symbol, decimals) = match stablecoins.iter().find(|c| c.mint.to_string() == mint) {
            Some(coin) => (Some(coin.symbol.clone()), coin.decimals),
            None => (None, decimals),
        };
        ReceiptTransfer {
            sender,
            receiver,
            asset: mint,
            symbol,
            name: None,
            logo_uri: None,
            decimals,
            raw_amount: raw.to_string(),
            ui_amount: ui_amount_from_raw(raw, decimals),
            memo: None,
        }
    }

    fn choose_debit(debits: &[BalanceDelta], amount: u128) -> Option<usize> {
        debits
            .iter()
            .position(|debit| debit.raw == amount)
            .or_else(|| debits.iter().position(|debit| debit.raw > 0))
    }

    let pre = rpc_value
        .pointer("/meta/preTokenBalances")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let post = rpc_value
        .pointer("/meta/postTokenBalances")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let account_keys = collect_account_keys(
        &rpc_value
            .pointer("/transaction/message")
            .cloned()
            .unwrap_or(Value::Null),
    );
    let pre_map = index_balances(&pre, &account_keys);
    let post_map = index_balances(&post, &account_keys);

    let mut indices: Vec<u64> = pre_map.keys().chain(post_map.keys()).copied().collect();
    indices.sort_unstable();
    indices.dedup();

    let mut credits = Vec::new();
    let mut debits = Vec::new();

    for idx in indices {
        let pre_entry = pre_map.get(&idx);
        let post_entry = post_map.get(&idx);
        if pre_entry
            .zip(post_entry)
            .is_some_and(|(pre, post)| pre.mint != post.mint)
        {
            continue;
        }
        let pre_amt = pre_entry.map(|entry| entry.amount).unwrap_or(0);
        let post_amt = post_entry.map(|entry| entry.amount).unwrap_or(0); // closed account → 0
        if post_amt > pre_amt {
            let Some(entry) = post_entry.or(pre_entry) else {
                continue;
            };
            credits.push(BalanceDelta {
                account_index: idx,
                owner: entry.owner.clone(),
                mint: entry.mint.clone(),
                decimals: entry.decimals,
                raw: post_amt - pre_amt,
            });
        } else if pre_amt > post_amt {
            let Some(entry) = pre_entry.or(post_entry) else {
                continue;
            };
            debits.push(BalanceDelta {
                account_index: idx,
                owner: entry.owner.clone(),
                mint: entry.mint.clone(),
                decimals: entry.decimals,
                raw: pre_amt - post_amt,
            });
        }
    }

    let mut debits_by_mint: BTreeMap<String, Vec<BalanceDelta>> = BTreeMap::new();
    for debit in debits {
        debits_by_mint
            .entry(debit.mint.clone())
            .or_default()
            .push(debit);
    }
    for mint_debits in debits_by_mint.values_mut() {
        mint_debits.sort_by_key(|debit| debit.account_index);
    }
    credits.sort_by_key(|credit| credit.account_index);

    let mut out = Vec::new();
    for credit in credits {
        let Some(mint_debits) = debits_by_mint.get_mut(&credit.mint) else {
            continue;
        };
        let mut remaining = credit.raw;
        while remaining > 0 {
            let Some(debit_idx) = choose_debit(mint_debits, remaining) else {
                break;
            };
            let matched = remaining.min(mint_debits[debit_idx].raw);
            if matched == 0 {
                break;
            }
            out.push(build_transfer(
                mint_debits[debit_idx].owner.clone(),
                credit.owner.clone(),
                credit.mint.clone(),
                credit.decimals,
                matched,
                stablecoins,
            ));
            mint_debits[debit_idx].raw -= matched;
            remaining -= matched;
        }
    }
    out
}

fn extract_sol_transfers(top: &[Value], inner: &[Value]) -> Vec<ReceiptTransfer> {
    let mut out = Vec::new();
    for ix in top.iter().chain(inner.iter()) {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        if program != SYSTEM_PROGRAM {
            continue;
        }
        let parsed = match ix.get("parsed") {
            Some(value) => value,
            None => continue,
        };
        let kind = parsed.get("type").and_then(Value::as_str).unwrap_or("");
        if kind != "transfer" && kind != "transferChecked" {
            continue;
        }
        let info = match parsed.get("info") {
            Some(value) => value,
            None => continue,
        };
        let lamports = info.get("lamports").and_then(Value::as_u64).unwrap_or(0);
        let sender = info
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let receiver = info
            .get("destination")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        out.push(ReceiptTransfer {
            sender,
            receiver,
            asset: "SOL".to_string(),
            symbol: Some("SOL".to_string()),
            name: Some("Solana".to_string()),
            logo_uri: None,
            decimals: 9,
            raw_amount: lamports.to_string(),
            ui_amount: ui_amount_from_raw(lamports as u128, 9),
            memo: None,
        });
    }
    out
}

fn classify_intent(
    programs: &[String],
    top: &[Value],
    transfers: &[ReceiptTransfer],
) -> ReceiptIntent {
    let has_payment_channels = programs.iter().any(|p| p == PAYMENT_CHANNELS_PROGRAM);
    let has_subscriptions = programs.iter().any(|p| p == SUBSCRIPTIONS_PROGRAM);
    let has_multi_delegator = programs.iter().any(|p| p == MULTI_DELEGATOR_PROGRAM);

    if has_payment_channels {
        let action = action_for_payment_channels(top);
        return session_intent(action, PAYMENT_CHANNELS_PROGRAM);
    }

    // Both `subscriptions` and `multi-delegator` use the same discriminator
    // layout; the discriminator is what tells `mpp/subscription` apart from
    // `mpp/session` (pull-mode SPL delegation). When the dedicated
    // subscriptions program is present we always emit `subscription`. When
    // only multi-delegator is present we look at the discriminator to
    // disambiguate (e.g. legacy deployments still using multi-delegator for
    // subscriptions).
    if has_subscriptions {
        let (action, kind) = action_for_multi_delegator_like(top, SUBSCRIPTIONS_PROGRAM);
        return match kind {
            DelegationKind::Subscription => subscription_intent(action, SUBSCRIPTIONS_PROGRAM),
            DelegationKind::Session => session_intent(action, SUBSCRIPTIONS_PROGRAM),
        };
    }
    if has_multi_delegator {
        let (action, kind) = action_for_multi_delegator_like(top, MULTI_DELEGATOR_PROGRAM);
        return match kind {
            DelegationKind::Subscription => subscription_intent(action, MULTI_DELEGATOR_PROGRAM),
            DelegationKind::Session => session_intent(action, MULTI_DELEGATOR_PROGRAM),
        };
    }

    let has_memo = programs
        .iter()
        .any(|p| p == MEMO_PROGRAM || p == MEMO_PROGRAM_V1);
    let distinct_receivers = transfers
        .iter()
        .filter(|t| !t.receiver.is_empty())
        .map(|t| t.receiver.as_str())
        .collect::<BTreeSet<_>>();
    let distinct_assets = transfers
        .iter()
        .map(|t| t.asset.as_str())
        .collect::<BTreeSet<_>>();
    let token_transfer_count = transfers.iter().filter(|t| t.asset != "SOL").count();

    if token_transfer_count >= 2 && distinct_receivers.len() >= 2 && distinct_assets.len() == 1 {
        return ReceiptIntent {
            kind: ReceiptIntentKind::MppCharge,
            protocol: Some("mpp".to_string()),
            name: "charge".to_string(),
            label: "MPP · charge".to_string(),
            action: None,
            program_id: None,
        };
    }
    if has_memo && token_transfer_count == 1 {
        return ReceiptIntent {
            kind: ReceiptIntentKind::X402Exact,
            protocol: Some("x402".to_string()),
            name: "exact".to_string(),
            label: "x402 · exact".to_string(),
            action: None,
            program_id: None,
        };
    }
    ReceiptIntent {
        kind: ReceiptIntentKind::Transfer,
        protocol: None,
        name: "transfer".to_string(),
        label: "Transfer".to_string(),
        action: None,
        program_id: None,
    }
}

/// Build the subscription block from instructions + token transfers. Maps
/// the on-chain action to the user-facing lifecycle status and pre-fills the
/// per-period amount when this transaction carries a real token transfer
/// (subscribe / renew). On-chain account fields (period_hours, period start,
/// expiry, subscriber, plan) are filled in later by
/// [`attach_recurring_delegation_state`] when the async builder fetches them.
#[allow(dead_code)]
fn build_subscription(
    action: String,
    transfers: &[ReceiptTransfer],
    fee_payer: &str,
) -> ReceiptSubscription {
    let status = match action.as_str() {
        "subscribe" => SubscriptionStatus::Active,
        "renew" => SubscriptionStatus::Renewed,
        "cancel" => SubscriptionStatus::Cancelled,
        "createPlan"
        | "updatePlan"
        | "deletePlan"
        | "initSubscriptionAuthority"
        | "closeSubscriptionAuthority" => SubscriptionStatus::Admin,
        _ => SubscriptionStatus::Unknown,
    };

    let token_transfer = transfers.iter().find(|t| t.asset != "SOL");
    let period_amount = token_transfer.map(|t| ReceiptAmount {
        asset: t.asset.clone(),
        symbol: t.symbol.clone(),
        name: t.name.clone(),
        logo_uri: t.logo_uri.clone(),
        decimals: t.decimals,
        raw_amount: t.raw_amount.clone(),
        ui_amount: t.ui_amount,
    });

    // For activate/renew the subscriber is the wallet that signed (fee_payer
    // when client-broadcast) OR the SPL transfer's authority. We default to
    // the token transfer authority because, for renewals, the operator pays
    // fees but the subscriber's delegation is what authorizes the move.
    let subscriber = token_transfer
        .map(|t| t.sender.clone())
        .filter(|s| !s.is_empty());
    let recipient = token_transfer
        .map(|t| t.receiver.clone())
        .filter(|s| !s.is_empty());

    let events: Vec<ReceiptSessionEvent> = transfers
        .iter()
        .filter(|t| t.asset != "SOL")
        .map(|t| ReceiptSessionEvent {
            kind: match action.as_str() {
                "subscribe" => "activate".to_string(),
                "renew" => "renew".to_string(),
                _ => "charge".to_string(),
            },
            sender: t.sender.clone(),
            receiver: t.receiver.clone(),
            asset: t.asset.clone(),
            symbol: t.symbol.clone(),
            decimals: t.decimals,
            raw_amount: t.raw_amount.clone(),
            ui_amount: t.ui_amount,
        })
        .collect();

    let _ = fee_payer; // reserved for future heuristics
    ReceiptSubscription {
        action,
        status,
        subscriber,
        recipient,
        plan: None,
        subscription_id: None,
        period_amount,
        period_hours: None,
        period_label: None,
        period_start_ts: None,
        period_end_ts: None,
        expires_at_ts: None,
        events,
    }
}

fn session_intent(action: Option<String>, program_id: &str) -> ReceiptIntent {
    let label = match &action {
        Some(action) => format!("MPP · session · {action}"),
        None => "MPP · session".to_string(),
    };
    ReceiptIntent {
        kind: ReceiptIntentKind::MppSession,
        protocol: Some("mpp".to_string()),
        name: "session".to_string(),
        label,
        action,
        program_id: Some(program_id.to_string()),
    }
}

fn subscription_intent(action: Option<String>, program_id: &str) -> ReceiptIntent {
    let label = match &action {
        Some(action) => format!("MPP · subscription · {action}"),
        None => "MPP · subscription".to_string(),
    };
    ReceiptIntent {
        kind: ReceiptIntentKind::MppSubscription,
        protocol: Some("mpp".to_string()),
        name: "subscription".to_string(),
        label,
        action,
        program_id: Some(program_id.to_string()),
    }
}

#[derive(Debug, Clone, Copy)]
enum DelegationKind {
    Session,
    Subscription,
}

/// Decode the first byte of the first multi-delegator-like instruction
/// (multi-delegator OR subscriptions program) AND classify whether that
/// discriminator belongs to the subscription intent or to the pull-mode
/// session intent. Returns the resolved action label too.
fn action_for_multi_delegator_like(
    top: &[Value],
    program_id: &str,
) -> (Option<String>, DelegationKind) {
    for ix in top {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        if program != program_id {
            continue;
        }
        let Some(data) = ix.get("data").and_then(Value::as_str) else {
            continue;
        };
        let Some(byte) = first_data_byte(data) else {
            continue;
        };
        let kind = if SUBSCRIPTION_DISCRIMINATORS.contains(&byte) {
            DelegationKind::Subscription
        } else {
            DelegationKind::Session
        };
        let label = subscription_or_session_label(byte);
        return (Some(label), kind);
    }
    (None, DelegationKind::Session)
}

fn subscription_or_session_label(byte: u8) -> String {
    match byte {
        0 => "initSubscriptionAuthority".to_string(),
        1 => "createFixedDelegation".to_string(),
        2 => "createRecurringDelegation".to_string(),
        3 => "revokeDelegation".to_string(),
        4 => "transferFixed".to_string(),
        5 => "transferRecurring".to_string(),
        6 => "closeSubscriptionAuthority".to_string(),
        7 => "createPlan".to_string(),
        8 => "updatePlan".to_string(),
        9 => "deletePlan".to_string(),
        10 => "renew".to_string(),
        11 => "subscribe".to_string(),
        12 => "cancel".to_string(),
        228 => "emitEvent".to_string(),
        other => format!("ix-{other}"),
    }
}

fn action_for_payment_channels(top: &[Value]) -> Option<String> {
    for ix in top {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        if program != PAYMENT_CHANNELS_PROGRAM {
            continue;
        }
        if let Some(data) = ix.get("data").and_then(Value::as_str)
            && let Some(byte) = first_data_byte(data)
        {
            return Some(match byte {
                1 => "open".to_string(),
                2 => "settle".to_string(),
                3 => "topUp".to_string(),
                4 => "settleAndSeal".to_string(),
                5 => "requestClose".to_string(),
                6 => "seal".to_string(),
                7 => "distribute".to_string(),
                8 => "withdrawPayer".to_string(),
                228 => "emitEvent".to_string(),
                other => format!("ix-{other}"),
            });
        }
    }
    None
}

fn first_data_byte(data: &str) -> Option<u8> {
    if let Ok(bytes) = bs58::decode(data).into_vec()
        && let Some(first) = bytes.first()
    {
        return Some(*first);
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data)
        && let Some(first) = bytes.first()
    {
        return Some(*first);
    }
    None
}

fn build_splits(transfers: &[ReceiptTransfer]) -> Vec<ReceiptSplit> {
    let mut totals: BTreeMap<String, u128> = BTreeMap::new();
    let mut grand_total: u128 = 0;
    for t in transfers {
        if t.asset == "SOL" {
            continue;
        }
        let raw: u128 = t.raw_amount.parse().unwrap_or(0);
        *totals.entry(t.receiver.clone()).or_default() += raw;
        grand_total += raw;
    }
    if grand_total == 0 {
        return Vec::new();
    }
    let decimals = transfers
        .iter()
        .find(|t| t.asset != "SOL")
        .map(|t| t.decimals)
        .unwrap_or(0);

    totals
        .into_iter()
        .map(|(recipient, raw)| {
            let bps = ((raw * 10_000) / grand_total) as u16;
            ReceiptSplit {
                recipient,
                raw_amount: raw.to_string(),
                ui_amount: ui_amount_from_raw(raw, decimals),
                bps,
            }
        })
        .collect()
}

fn aggregate_total(transfers: &[ReceiptTransfer]) -> Option<ReceiptAmount> {
    let mut iter = transfers.iter();
    let first = iter.next()?;
    let mut total: u128 = first.raw_amount.parse().unwrap_or(0);
    for t in iter {
        if t.asset != first.asset || t.decimals != first.decimals {
            return None;
        }
        let raw: u128 = t.raw_amount.parse().unwrap_or(0);
        total += raw;
    }
    Some(ReceiptAmount {
        asset: first.asset.clone(),
        symbol: first.symbol.clone(),
        name: first.name.clone(),
        logo_uri: first.logo_uri.clone(),
        decimals: first.decimals,
        raw_amount: total.to_string(),
        ui_amount: ui_amount_from_raw(total, first.decimals),
    })
}

/// Classify each transfer in an mpp/session transaction by role: deposit (payer
/// → channel), refund (channel → payer), or consume/distribute (channel →
/// recipient).
fn build_session(
    action: String,
    program_id: Option<String>,
    transfers: &[ReceiptTransfer],
    fee_payer: &str,
    top_instructions: &[Value],
    account_keys: &[String],
) -> ReceiptSession {
    let channel = extract_session_channel(top_instructions, account_keys, program_id.as_deref());

    // For `open`: the sender of the deposit is the original payer.
    // For `settle`/`distribute`/`seal`: the channel sends to recipients
    // (one of which may be the original payer if a refund is included).
    let token_transfers: Vec<&ReceiptTransfer> =
        transfers.iter().filter(|t| t.asset != "SOL").collect();

    // Heuristics for who the channel was opened for.
    //
    // - `open`/`topUp`: the only token transfer goes payer → channel, so the
    //   instruction's `authority` (sender) is the payer and the destination is
    //   the channel-token-account (close enough to "payee" for display).
    // - settle / settleAndSeal / distribute / seal / requestClose: the
    //   channel pays out to N recipients. The largest leg is the operator's
    //   primary recipient (the merchant's payee). The smallest leg, if it
    //   matches an address that previously paid into the channel, is the
    //   refund to the original payer — but we can't see that on a single
    //   transaction without account lookups, so we surface "payee" only.
    // - `initMultiDelegate`/`createFixedDelegation`: pull-mode setup — the
    //   fee-payer is the wallet authorizing delegation.
    let (payer, payee) = match action.as_str() {
        "open" | "topUp" => (
            token_transfers
                .first()
                .map(|t| t.sender.clone())
                .filter(|s| !s.is_empty()),
            token_transfers.first().map(|t| t.receiver.clone()),
        ),
        "initMultiDelegate" | "createFixedDelegation" => (Some(fee_payer.to_string()), None),
        "settle" | "settleAndSeal" | "distribute" => (None, primary_recipient(&token_transfers)),
        "seal" | "requestClose" | "withdrawPayer" => (
            // On close, the channel sends the remainder back to the payer.
            // We can't know which leg is the refund without account-info
            // lookups; leave `payer` empty and surface the breakdown via
            // events[].
            None,
            primary_recipient(&token_transfers),
        ),
        _ => (None, None),
    };

    let mut events: Vec<ReceiptSessionEvent> = Vec::new();
    let mut deposit_total: u128 = 0;
    let mut consumed_total: u128 = 0;
    let mut refunded_total: u128 = 0;
    let mut sample: Option<&ReceiptTransfer> = None;
    let mut distributed: Vec<ReceiptSplit> = Vec::new();

    for t in &token_transfers {
        sample = Some(t);
        let raw: u128 = t.raw_amount.parse().unwrap_or(0);
        let role = classify_session_event(&action, t, fee_payer);
        match role.as_str() {
            "deposit" => deposit_total += raw,
            "refund" => refunded_total += raw,
            "consume" | "distribute" => consumed_total += raw,
            _ => {}
        }
        events.push(ReceiptSessionEvent {
            kind: role,
            sender: t.sender.clone(),
            receiver: t.receiver.clone(),
            asset: t.asset.clone(),
            symbol: t.symbol.clone(),
            decimals: t.decimals,
            raw_amount: t.raw_amount.clone(),
            ui_amount: t.ui_amount,
        });
    }

    // Build a distributed[] list for distribute / settle actions, grouping
    // consumes by recipient and reporting basis-point shares.
    if matches!(action.as_str(), "distribute" | "settle" | "settleAndSeal") && consumed_total > 0 {
        let mut by_recipient: BTreeMap<String, u128> = BTreeMap::new();
        for ev in &events {
            if ev.kind == "consume" || ev.kind == "distribute" {
                let raw: u128 = ev.raw_amount.parse().unwrap_or(0);
                *by_recipient.entry(ev.receiver.clone()).or_default() += raw;
            }
        }
        let decimals = sample.map(|t| t.decimals).unwrap_or(0);
        distributed = by_recipient
            .into_iter()
            .map(|(recipient, raw)| {
                let bps = ((raw * 10_000) / consumed_total) as u16;
                ReceiptSplit {
                    recipient,
                    raw_amount: raw.to_string(),
                    ui_amount: ui_amount_from_raw(raw, decimals),
                    bps,
                }
            })
            .collect();
    }

    let deposit = amount_from(deposit_total, sample);
    let consumed = amount_from(consumed_total, sample);
    let refunded = amount_from(refunded_total, sample);

    ReceiptSession {
        action,
        channel,
        channel_status: None,
        payer,
        payee,
        opener: Some(fee_payer.to_string()),
        deposit,
        consumed,
        refunded,
        distributed,
        events,
    }
}

/// Return the largest receiver across all token transfers, used as a
/// reasonable approximation of the "primary payee" for settle / seal
/// actions where the channel pays out to multiple recipients.
fn primary_recipient(transfers: &[&ReceiptTransfer]) -> Option<String> {
    let mut totals: BTreeMap<String, u128> = BTreeMap::new();
    for t in transfers {
        if t.receiver.is_empty() {
            continue;
        }
        let raw: u128 = t.raw_amount.parse().unwrap_or(0);
        *totals.entry(t.receiver.clone()).or_default() += raw;
    }
    totals
        .into_iter()
        .max_by_key(|&(_, raw)| raw)
        .map(|(k, _)| k)
}

fn classify_session_event(action: &str, t: &ReceiptTransfer, fee_payer: &str) -> String {
    match action {
        "open" | "topUp" => "deposit".to_string(),
        "seal" | "requestClose" | "withdrawPayer" => {
            // Refund vs consume: if the destination matches the fee payer
            // (operator triggering seal) we can't reliably tell which
            // recipient is the original payer without account-info lookups —
            // so default to refund for the largest receiver-equal-to-sender-
            // payer pattern, else mark as refund whichever happens to be the
            // smaller leg.
            if t.receiver == fee_payer || t.sender == fee_payer {
                "refund".to_string()
            } else {
                "consume".to_string()
            }
        }
        "settle" | "settleAndSeal" | "distribute" => "distribute".to_string(),
        _ => "consume".to_string(),
    }
}

fn amount_from(raw: u128, sample: Option<&ReceiptTransfer>) -> Option<ReceiptAmount> {
    if raw == 0 {
        return None;
    }
    let sample = sample?;
    Some(ReceiptAmount {
        asset: sample.asset.clone(),
        symbol: sample.symbol.clone(),
        name: sample.name.clone(),
        logo_uri: sample.logo_uri.clone(),
        decimals: sample.decimals,
        raw_amount: raw.to_string(),
        ui_amount: ui_amount_from_raw(raw, sample.decimals),
    })
}

/// Heuristic channel discovery: scan the payment-channels instruction for an
/// account that is not the fee-payer or a well-known program / sysvar.
fn extract_session_channel(
    top: &[Value],
    account_keys: &[String],
    program_id: Option<&str>,
) -> Option<String> {
    let program_id = program_id?;
    for ix in top {
        let program = ix.get("programId").and_then(Value::as_str).unwrap_or("");
        if program != program_id {
            continue;
        }
        let accounts = ix
            .get("accounts")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        for entry in accounts {
            if account_keys.first().map(String::as_str) == Some(entry) {
                continue;
            }
            if entry == SPL_TOKEN_PROGRAM
                || entry == TOKEN_2022_PROGRAM
                || entry == SYSTEM_PROGRAM
                || entry == "Sysvar1nstructions1111111111111111111111111"
                || entry == "SysvarRent111111111111111111111111111111111"
                || entry == "Ed25519SigVerify111111111111111111111111111"
                || entry == "ComputeBudget111111111111111111111111111111"
            {
                continue;
            }
            return Some(entry.to_string());
        }
    }
    None
}

fn ui_amount_from_raw(raw: u128, decimals: u8) -> f64 {
    if decimals == 0 {
        return raw as f64;
    }
    let divisor = 10f64.powi(decimals as i32);
    (raw as f64) / divisor
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use solana_pubkey::Pubkey;

    fn parse(value: Value) -> Receipt {
        build_receipt_skeleton(
            "5DummySignature11111111111111111111111111111111111111111111111111111111111111111111111111",
            Network::Mainnet,
            &value,
            &[],
        )
        .expect("receipt builds")
    }

    #[test]
    fn recurring_state_amount_uses_mint_decimals() {
        let mint = Pubkey::new_unique();
        let mut subscription = ReceiptSubscription {
            action: "cancel".to_string(),
            status: SubscriptionStatus::Cancelled,
            subscriber: None,
            recipient: None,
            plan: None,
            subscription_id: None,
            period_amount: None,
            period_hours: None,
            period_label: None,
            period_start_ts: None,
            period_end_ts: None,
            expires_at_ts: None,
            events: Vec::new(),
        };
        let state = crate::subscription_state::RecurringDelegationState {
            address: Pubkey::new_unique().to_string(),
            subscriber: Pubkey::new_unique(),
            puller: Pubkey::new_unique(),
            mint,
            current_period_start_ts: 0,
            period_length_s: 0,
            expiry_ts: 0,
            amount_per_period: 5_000_000,
        };
        let mut receipt = parse(json!({
            "slot": 1,
            "meta": {"err": null, "fee": 0, "innerInstructions": []},
            "transaction": {"message": {"accountKeys": ["payer"], "instructions": []}}
        }));
        receipt.subscription = Some(subscription.clone());
        attach_recurring_delegation_state(&mut receipt, &state);
        subscription = receipt.subscription.take().unwrap();

        let metadata = HashMap::from([(
            mint.to_string(),
            TokenMetadata {
                symbol: Some("USDC".to_string()),
                decimals: Some(6),
                ..TokenMetadata::default()
            },
        )]);
        attach_subscription_metadata(&mut subscription, &metadata);

        let amount = subscription.period_amount.unwrap();
        assert_eq!(amount.decimals, 6);
        assert_eq!(amount.ui_amount, 5.0);
    }

    #[test]
    fn classifies_x402_exact_when_memo_and_single_transfer() {
        let rpc = json!({
            "slot": 100,
            "blockTime": 1_700_000_000_i64,
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": "Payer11111111111111111111111111111111111111", "signer": true, "writable": true}
                    ],
                    "instructions": [
                        {
                            "programId": SPL_TOKEN_PROGRAM,
                            "program": "spl-token",
                            "parsed": {
                                "type": "transferChecked",
                                "info": {
                                    "authority": "AuthorityXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                                    "destination": "DestinationXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                                    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                                    "tokenAmount": {"amount": "1000000", "decimals": 6}
                                }
                            }
                        },
                        {
                            "programId": MEMO_PROGRAM,
                            "program": "spl-memo",
                            "parsed": "abc123nonce"
                        }
                    ]
                }
            }
        });
        let receipt = parse(rpc);
        assert!(matches!(receipt.intent.kind, ReceiptIntentKind::X402Exact));
        assert_eq!(receipt.intent.protocol.as_deref(), Some("x402"));
        assert_eq!(receipt.intent.name, "exact");
        assert_eq!(receipt.transfers.len(), 1);
        assert_eq!(receipt.transfers[0].memo.as_deref(), Some("abc123nonce"));
        assert!(receipt.splits.is_empty());
        assert!(receipt.session.is_none());
    }

    #[test]
    fn classifies_mpp_charge_with_multiple_recipients() {
        let rpc = json!({
            "slot": 100,
            "blockTime": 1_700_000_000_i64,
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Payer11111111111111111111111111111111111111"}],
                    "instructions": [
                        token_transfer("Auth", "DestA", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "700000", 6),
                        token_transfer("Auth", "DestB", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "300000", 6)
                    ]
                }
            }
        });
        let receipt = parse(rpc);
        assert!(matches!(receipt.intent.kind, ReceiptIntentKind::MppCharge));
        assert_eq!(receipt.intent.protocol.as_deref(), Some("mpp"));
        assert_eq!(receipt.intent.name, "charge");
        assert_eq!(receipt.splits.len(), 2);
        assert_eq!(receipt.splits.iter().map(|s| s.bps).sum::<u16>(), 10_000);
    }

    #[test]
    fn mpp_session_open_populates_deposit_and_payer() {
        let rpc = json!({
            "slot": 100,
            "blockTime": 1_700_000_000_i64,
            "meta": {
                "err": null,
                "fee": 5000_u64,
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [
                        token_transfer(
                            "Payer11111111111111111111111111111111111111",
                            "ChannelATAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                            "5000000",
                            6
                        )
                    ]
                }]
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": "Payer11111111111111111111111111111111111111"},
                        {"pubkey": "ChannelPDAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}
                    ],
                    "instructions": [{
                        "programId": PAYMENT_CHANNELS_PROGRAM,
                        "accounts": ["Payer11111111111111111111111111111111111111", "ChannelPDAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
                        "data": bs58::encode([1u8, 0, 0, 0]).into_string()
                    }]
                }
            }
        });
        let receipt = parse(rpc);
        assert!(matches!(receipt.intent.kind, ReceiptIntentKind::MppSession));
        assert_eq!(receipt.intent.action.as_deref(), Some("open"));
        let session = receipt.session.expect("session attached");
        assert_eq!(session.action, "open");
        assert_eq!(
            session.channel.as_deref(),
            Some("ChannelPDAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        );
        assert_eq!(
            session.payer.as_deref(),
            Some("Payer11111111111111111111111111111111111111")
        );
        let deposit = session.deposit.expect("deposit");
        assert_eq!(deposit.raw_amount, "5000000");
        assert!(session.consumed.is_none());
        assert!(session.refunded.is_none());
    }

    #[test]
    fn mpp_session_settle_groups_distributions() {
        let rpc = json!({
            "slot": 100,
            "blockTime": 1_700_000_000_i64,
            "meta": {
                "err": null,
                "fee": 5000_u64,
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [
                        token_transfer("ChannelOwner", "DestA", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "700000", 6),
                        token_transfer("ChannelOwner", "DestB", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "300000", 6)
                    ]
                }]
            },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Operator11111111111111111111111111111111111"}],
                    "instructions": [{
                        "programId": PAYMENT_CHANNELS_PROGRAM,
                        "accounts": ["Operator11111111111111111111111111111111111", "ChannelPDA22"],
                        "data": bs58::encode([4u8, 0, 0, 0]).into_string()
                    }]
                }
            }
        });
        let receipt = parse(rpc);
        let session = receipt.session.expect("session");
        assert_eq!(session.action, "settleAndSeal");
        assert_eq!(session.distributed.len(), 2);
        assert_eq!(
            session.distributed.iter().map(|s| s.bps).sum::<u16>(),
            10_000
        );
    }

    fn token_transfer(
        authority: &str,
        destination: &str,
        mint: &str,
        amount: &str,
        decimals: u8,
    ) -> Value {
        json!({
            "programId": SPL_TOKEN_PROGRAM,
            "program": "spl-token",
            "parsed": {
                "type": "transferChecked",
                "info": {
                    "authority": authority,
                    "destination": destination,
                    "mint": mint,
                    "tokenAmount": {"amount": amount, "decimals": decimals}
                }
            }
        })
    }

    // ── Plain transfer / SOL / Token-2022 ─────────────────────────────────

    #[test]
    fn classifies_plain_transfer_when_no_memo_or_protocol() {
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Payer11111111111111111111111111111111111111"}],
                    "instructions": [
                        token_transfer("Auth", "Dest", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "1000", 6)
                    ]
                }
            }
        });
        let r = parse(rpc);
        assert!(matches!(r.intent.kind, ReceiptIntentKind::Transfer));
        assert_eq!(r.intent.name, "transfer");
        assert!(r.intent.protocol.is_none());
        assert!(r.session.is_none());
        assert!(r.splits.is_empty());
    }

    #[test]
    fn extracts_sol_transfer_from_system_program() {
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Payer11111111111111111111111111111111111111"}],
                    "instructions": [{
                        "programId": SYSTEM_PROGRAM,
                        "program": "system",
                        "parsed": {
                            "type": "transfer",
                            "info": {
                                "source": "Source11111111111111111111111111111111111111",
                                "destination": "Dest1111111111111111111111111111111111111111",
                                "lamports": 2_500_000u64
                            }
                        }
                    }]
                }
            }
        });
        let r = parse(rpc);
        assert_eq!(r.transfers.len(), 1);
        let t = &r.transfers[0];
        assert_eq!(t.asset, "SOL");
        assert_eq!(t.symbol.as_deref(), Some("SOL"));
        assert_eq!(t.decimals, 9);
        assert_eq!(t.raw_amount, "2500000");
        assert!((t.ui_amount - 0.0025).abs() < 1e-9);
    }

    #[test]
    fn extracts_token_2022_transfer() {
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Payer11111111111111111111111111111111111111"}],
                    "instructions": [{
                        "programId": TOKEN_2022_PROGRAM,
                        "program": "spl-token-2022",
                        "parsed": {
                            "type": "transferChecked",
                            "info": {
                                "authority": "AuthorityXXX",
                                "destination": "Dest22",
                                "mint": "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
                                "tokenAmount": {"amount": "500000", "decimals": 6}
                            }
                        }
                    }]
                }
            }
        });
        let r = parse(rpc);
        assert_eq!(r.transfers.len(), 1);
        assert_eq!(
            r.transfers[0].asset,
            "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
        );
    }

    #[test]
    fn extracts_token_transfer_without_token_amount_falls_back_to_amount_field() {
        // Plain SPL `transfer` (legacy) only exposes `amount`, no `tokenAmount`.
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Payer11111111111111111111111111111111111111"}],
                    "instructions": [{
                        "programId": SPL_TOKEN_PROGRAM,
                        "program": "spl-token",
                        "parsed": {
                            "type": "transfer",
                            "info": {
                                "authority": "Auth",
                                "destination": "Dest",
                                "source": "Source",
                                "amount": "12345"
                            }
                        }
                    }]
                }
            }
        });
        let r = parse(rpc);
        assert_eq!(r.transfers.len(), 1);
        assert_eq!(r.transfers[0].raw_amount, "12345");
    }

    // ── Stablecoin registry ────────────────────────────────────────────────

    #[test]
    fn applies_stablecoin_symbol_and_decimals_from_registry() {
        use solana_pubkey::Pubkey;
        use std::str::FromStr;
        let coin = Stablecoin {
            symbol: "USDC".to_string(),
            mint: Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap(),
            token_program: crate::ata::SPL_TOKEN_PROGRAM_ID,
            decimals: 6,
        };
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": {
                "message": {
                    "accountKeys": [{"pubkey": "Payer11111111111111111111111111111111111111"}],
                    "instructions": [
                        token_transfer("Auth", "Dest", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "1500000", 0)
                    ]
                }
            }
        });
        let r = build_receipt_skeleton("sig", Network::Mainnet, &rpc, &[coin]).unwrap();
        assert_eq!(r.transfers[0].symbol.as_deref(), Some("USDC"));
        // Registry decimals (6) override the per-instruction value.
        assert_eq!(r.transfers[0].decimals, 6);
        assert!((r.transfers[0].ui_amount - 1.5).abs() < 1e-9);
    }

    // ── Memo extraction (per-transfer) ────────────────────────────────────
    //
    // Memos no longer live at the top level; the closest one to each
    // transfer in instruction order is attached as `transfer.memo`. Each
    // case below pairs a memo with exactly one token transfer so the
    // decoder under test sees a valid attribution path.

    fn parse_memo_paired_with_transfer(memo_ix: Value) -> Receipt {
        parse(json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "P"}],
                "instructions": [
                    token_transfer("A", "B", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "1", 6),
                    memo_ix,
                ]
            }}
        }))
    }

    #[test]
    fn extracts_memo_from_parsed_string() {
        let r = parse_memo_paired_with_transfer(json!({
            "programId": MEMO_PROGRAM,
            "program": "spl-memo",
            "parsed": "hello world"
        }));
        assert_eq!(r.transfers.len(), 1);
        assert_eq!(r.transfers[0].memo.as_deref(), Some("hello world"));
    }

    #[test]
    fn extracts_memo_from_parsed_info_memo_object() {
        let r = parse_memo_paired_with_transfer(json!({
            "programId": MEMO_PROGRAM,
            "parsed": { "info": { "memo": "structured-memo" } }
        }));
        assert_eq!(r.transfers[0].memo.as_deref(), Some("structured-memo"));
    }

    #[test]
    fn extracts_memo_from_base58_data() {
        let data = bs58::encode("nonce-abc".as_bytes()).into_string();
        let r = parse_memo_paired_with_transfer(json!({
            "programId": MEMO_PROGRAM,
            "data": data,
        }));
        assert_eq!(r.transfers[0].memo.as_deref(), Some("nonce-abc"));
    }

    #[test]
    fn extracts_legacy_memo_v1_when_paired_with_transfer() {
        let r = parse_memo_paired_with_transfer(json!({
            "programId": MEMO_PROGRAM_V1,
            "program": "spl-memo",
            "parsed": "legacy-memo"
        }));
        assert_eq!(r.transfers[0].memo.as_deref(), Some("legacy-memo"));
    }

    #[test]
    fn memo_with_no_transfer_is_dropped() {
        // With the per-transfer model, a memo that has no transfer to
        // attribute to is silently dropped — the public contract no
        // longer surfaces it anywhere.
        let r = parse(json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "P"}],
                "instructions": [{
                    "programId": MEMO_PROGRAM,
                    "program": "spl-memo",
                    "parsed": "orphan"
                }]
            }}
        }));
        assert!(r.transfers.is_empty());
    }

    #[test]
    fn sanitize_memo_strips_control_chars_and_bidi_overrides() {
        // U+202E is the right-to-left override — classic spoofing char.
        let dirty = "Hello\u{0007}\u{202E}gnirts\u{202C} world";
        let clean = sanitize_memo(dirty).unwrap();
        assert!(!clean.chars().any(|c| c == '\u{202E}' || c == '\u{0007}'));
        assert!(clean.contains("Hello"));
    }

    #[test]
    fn sanitize_memo_preserves_tabs_newlines_and_unicode() {
        let memo = "line1\nline2\t indented · café";
        let clean = sanitize_memo(memo).unwrap();
        assert_eq!(clean, memo);
    }

    #[test]
    fn sanitize_memo_returns_none_for_empty_after_strip() {
        assert!(sanitize_memo("\u{202E}\u{202C}").is_none());
        assert!(sanitize_memo("   ").is_none());
        assert!(sanitize_memo("").is_none());
    }

    #[test]
    fn sanitize_memo_caps_long_payloads_with_ellipsis() {
        let huge: String = "a".repeat(500);
        let clean = sanitize_memo(&huge).unwrap();
        assert_eq!(clean.chars().count(), MAX_DISPLAY_LEN + 1); // +1 for the ellipsis
        assert!(clean.ends_with('…'));
    }

    #[test]
    fn pairs_per_transfer_memos_by_proximity() {
        // memo-A, transfer-1, memo-B, transfer-2 ⇒ T1=A, T2=B.
        let r = parse(json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "P"}],
                "instructions": [
                    {"programId": MEMO_PROGRAM, "program": "spl-memo", "parsed": "alpha"},
                    token_transfer("A", "B", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "1", 6),
                    {"programId": MEMO_PROGRAM, "program": "spl-memo", "parsed": "beta"},
                    token_transfer("A", "C", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "2", 6),
                ]
            }}
        }));
        assert_eq!(r.transfers.len(), 2);
        assert_eq!(r.transfers[0].memo.as_deref(), Some("alpha"));
        assert_eq!(r.transfers[1].memo.as_deref(), Some("beta"));
    }

    #[test]
    fn trailing_memo_attaches_to_nearest_transfer_not_first() {
        // transfer-1; transfer-2; memo ⇒ the single memo belongs to the
        // *nearest* (second) transfer, not the first. Regression for a
        // revenue-split charge where the trailing "Partner revenue share"
        // memo was mis-attributed to the primary recipient.
        let r = parse(json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "P"}],
                "instructions": [
                    token_transfer("A", "B", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "80000", 6),
                    token_transfer("A", "C", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "20000", 6),
                    {"programId": MEMO_PROGRAM, "program": "spl-memo", "parsed": "Partner revenue share"},
                ]
            }}
        }));
        assert_eq!(r.transfers.len(), 2);
        assert_eq!(r.transfers[0].memo, None);
        assert_eq!(
            r.transfers[1].memo.as_deref(),
            Some("Partner revenue share")
        );
    }

    #[test]
    fn balance_derived_transfer_keeps_memo_without_parsed_transfer_position() {
        let rpc = json!({
            "meta": {
                "err": null,
                "fee": 5000_u64,
                "innerInstructions": [],
                "preTokenBalances": [
                    {"accountIndex": 1, "owner": "SenderWallet", "mint": "M", "uiTokenAmount": {"amount": "100", "decimals": 6}},
                    {"accountIndex": 2, "owner": "ReceiverWallet", "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}}
                ],
                "postTokenBalances": [
                    {"accountIndex": 1, "owner": "SenderWallet", "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 2, "owner": "ReceiverWallet", "mint": "M", "uiTokenAmount": {"amount": "100", "decimals": 6}}
                ]
            },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "Payer"}, {"pubkey": "SenderATA"}, {"pubkey": "ReceiverATA"}],
                "instructions": [{
                    "programId": MEMO_PROGRAM,
                    "program": "spl-memo",
                    "parsed": "balance-memo"
                }]
            }}
        });

        let r = parse(rpc);
        assert_eq!(r.transfers.len(), 1);
        assert_eq!(r.transfers[0].sender, "SenderWallet");
        assert_eq!(r.transfers[0].receiver, "ReceiverWallet");
        assert_eq!(r.transfers[0].memo.as_deref(), Some("balance-memo"));
    }

    #[test]
    fn balance_fallback_uses_account_key_when_owner_is_missing() {
        let rpc = json!({
            "meta": {
                "preTokenBalances": [
                    {"accountIndex": 1, "mint": "M", "uiTokenAmount": {"amount": "50", "decimals": 6}},
                    {"accountIndex": 2, "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}}
                ],
                "postTokenBalances": [
                    {"accountIndex": 1, "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 2, "mint": "M", "uiTokenAmount": {"amount": "50", "decimals": 6}}
                ]
            },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "Payer"}, {"pubkey": "SourceTokenAccount"}, {"pubkey": "DestTokenAccount"}],
                "instructions": []
            }}
        });

        let transfers = extract_transfers_from_balances(&rpc, &[]);
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].sender, "SourceTokenAccount");
        assert_eq!(transfers[0].receiver, "DestTokenAccount");
        assert!(!transfers[0].sender.is_empty());
        assert!(!transfers[0].receiver.is_empty());
    }

    #[test]
    fn balance_fallback_pairs_credits_with_matching_debit_sources() {
        let rpc = json!({
            "meta": {
                "preTokenBalances": [
                    {"accountIndex": 1, "owner": "SenderA", "mint": "M", "uiTokenAmount": {"amount": "100", "decimals": 6}},
                    {"accountIndex": 2, "owner": "SenderB", "mint": "M", "uiTokenAmount": {"amount": "50", "decimals": 6}},
                    {"accountIndex": 3, "owner": "ReceiverA", "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 4, "owner": "ReceiverB", "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}}
                ],
                "postTokenBalances": [
                    {"accountIndex": 1, "owner": "SenderA", "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 2, "owner": "SenderB", "mint": "M", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 3, "owner": "ReceiverA", "mint": "M", "uiTokenAmount": {"amount": "50", "decimals": 6}},
                    {"accountIndex": 4, "owner": "ReceiverB", "mint": "M", "uiTokenAmount": {"amount": "100", "decimals": 6}}
                ]
            },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "Payer"}, {"pubkey": "A"}, {"pubkey": "B"}, {"pubkey": "C"}, {"pubkey": "D"}],
                "instructions": []
            }}
        });

        let transfers = extract_transfers_from_balances(&rpc, &[]);
        assert_eq!(transfers.len(), 2);
        assert_eq!(transfers[0].sender, "SenderB");
        assert_eq!(transfers[0].receiver, "ReceiverA");
        assert_eq!(transfers[0].raw_amount, "50");
        assert_eq!(transfers[1].sender, "SenderA");
        assert_eq!(transfers[1].receiver, "ReceiverB");
        assert_eq!(transfers[1].raw_amount, "100");
    }

    // ── MPP session action decoding ───────────────────────────────────────

    #[test]
    fn payment_channels_actions_decode_per_discriminator() {
        let cases: &[(u8, &str)] = &[
            (1, "open"),
            (2, "settle"),
            (3, "topUp"),
            (4, "settleAndSeal"),
            (5, "requestClose"),
            (6, "seal"),
            (7, "distribute"),
            (8, "withdrawPayer"),
        ];
        for (disc, label) in cases {
            let rpc = json!({
                "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
                "transaction": { "message": {
                    "accountKeys": [{"pubkey": "Op"}, {"pubkey": "C"}],
                    "instructions": [{
                        "programId": PAYMENT_CHANNELS_PROGRAM,
                        "accounts": ["Op", "C"],
                        "data": bs58::encode([*disc]).into_string()
                    }]
                }}
            });
            let r = parse(rpc);
            assert!(matches!(r.intent.kind, ReceiptIntentKind::MppSession));
            assert_eq!(r.intent.action.as_deref(), Some(*label), "disc {disc}");
            assert!(r.intent.label.contains("MPP"));
        }
    }

    #[test]
    fn multi_delegator_session_actions_route_to_mpp_session() {
        // Delegation lifecycle instructions (createFixedDelegation,
        // createRecurringDelegation, transferFixed, transferRecurring,
        // revokeDelegation) all belong to the pull-mode session intent.
        let cases: &[(u8, &str)] = &[
            (1, "createFixedDelegation"),
            (2, "createRecurringDelegation"),
            (3, "revokeDelegation"),
            (4, "transferFixed"),
            (5, "transferRecurring"),
        ];
        for (disc, label) in cases {
            let rpc = subscription_program_tx(MULTI_DELEGATOR_PROGRAM, *disc);
            let r = parse(rpc);
            assert!(
                matches!(r.intent.kind, ReceiptIntentKind::MppSession),
                "disc {disc} should be mpp/session"
            );
            assert_eq!(r.intent.action.as_deref(), Some(*label), "disc {disc}");
            assert_eq!(
                r.intent.program_id.as_deref(),
                Some(MULTI_DELEGATOR_PROGRAM)
            );
        }
    }

    #[test]
    fn subscription_discriminators_route_to_mpp_subscription() {
        // Subscription-flow instructions (subscribe, transferSubscription
        // a.k.a. renew, cancelSubscription, createPlan, updatePlan,
        // deletePlan, initSubscriptionAuthority, closeSubscriptionAuthority)
        // route to the new mpp/subscription intent regardless of whether
        // they're emitted by the legacy multi-delegator program or the
        // canonical subscriptions program.
        let cases: &[(u8, &str)] = &[
            (0, "initSubscriptionAuthority"),
            (6, "closeSubscriptionAuthority"),
            (7, "createPlan"),
            (8, "updatePlan"),
            (9, "deletePlan"),
            (10, "renew"),
            (11, "subscribe"),
            (12, "cancel"),
        ];
        for program in [MULTI_DELEGATOR_PROGRAM, SUBSCRIPTIONS_PROGRAM] {
            for (disc, label) in cases {
                let rpc = subscription_program_tx(program, *disc);
                let r = parse(rpc);
                assert!(
                    matches!(r.intent.kind, ReceiptIntentKind::MppSubscription),
                    "program {program} disc {disc} should be mpp/subscription"
                );
                assert_eq!(r.intent.action.as_deref(), Some(*label), "disc {disc}");
                assert_eq!(r.intent.program_id.as_deref(), Some(program));
                assert!(r.subscription.is_some());
            }
        }
    }

    fn subscription_program_tx(program: &'static str, disc: u8) -> Value {
        json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "Op"}, {"pubkey": "D"}],
                "instructions": [{
                    "programId": program,
                    "accounts": ["Op", "D"],
                    "data": bs58::encode([disc]).into_string()
                }]
            }}
        })
    }

    #[test]
    fn subscription_status_maps_from_action() {
        let rpc_subscribe = subscription_program_tx(SUBSCRIPTIONS_PROGRAM, 11);
        let r = parse(rpc_subscribe);
        let s = r.subscription.expect("subscribe builds a block");
        assert_eq!(s.action, "subscribe");
        assert_eq!(s.status, pay_api_types::SubscriptionStatus::Active);

        let rpc_renew = subscription_program_tx(SUBSCRIPTIONS_PROGRAM, 10);
        let r = parse(rpc_renew);
        let s = r.subscription.expect("renew builds a block");
        assert_eq!(s.action, "renew");
        assert_eq!(s.status, pay_api_types::SubscriptionStatus::Renewed);

        let rpc_cancel = subscription_program_tx(SUBSCRIPTIONS_PROGRAM, 12);
        let r = parse(rpc_cancel);
        let s = r.subscription.expect("cancel builds a block");
        assert_eq!(s.action, "cancel");
        assert_eq!(s.status, pay_api_types::SubscriptionStatus::Cancelled);

        for disc in [0u8, 6, 7, 8, 9] {
            let r = parse(subscription_program_tx(SUBSCRIPTIONS_PROGRAM, disc));
            let s = r.subscription.expect("admin builds a block");
            assert_eq!(s.status, pay_api_types::SubscriptionStatus::Admin);
        }
    }

    #[test]
    fn subscription_extracts_per_period_amount_from_token_transfer() {
        // A real subscribe tx contains the SPL token transfer for the first
        // billing period. The builder lifts that into `period_amount`.
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [{
                "index": 0,
                "instructions": [
                    token_transfer(
                        "Subscriber11111111111111111111111111111111",
                        "RecipientATA",
                        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                        "10000000",
                        6
                    )
                ]
            }] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "Subscriber11111111111111111111111111111111"}],
                "instructions": [{
                    "programId": SUBSCRIPTIONS_PROGRAM,
                    "accounts": ["Subscriber11111111111111111111111111111111"],
                    "data": bs58::encode([11u8]).into_string()
                }]
            }}
        });
        let r = parse(rpc);
        let s = r.subscription.unwrap();
        let amount = s.period_amount.expect("per-period amount populated");
        assert_eq!(amount.raw_amount, "10000000");
        assert_eq!(
            s.subscriber.as_deref(),
            Some("Subscriber11111111111111111111111111111111")
        );
        assert_eq!(s.recipient.as_deref(), Some("RecipientATA"));
    }

    // ── Session reconciliation via postTokenBalances ──────────────────────

    #[test]
    fn settle_seal_reconciles_refund_using_post_token_balances() {
        // Settle/seal transaction with two destinations:
        //   - dest_payer_ata receives the largest share → payer refund
        //   - dest_operator_ata receives the small share → consumed
        let rpc = json!({
            "slot": 100,
            "blockTime": 1_700_000_000_i64,
            "meta": {
                "err": null,
                "fee": 5000_u64,
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [
                        token_transfer("ChannelPDA", "OperatorATA", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "100", 6),
                        token_transfer("ChannelPDA", "PayerATA",    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "9900", 6)
                    ]
                }],
                "preTokenBalances": [
                    {"accountIndex": 1, "owner": "OperatorWallet", "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
                    {"accountIndex": 2, "owner": "PayerWallet",    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}
                ],
                "postTokenBalances": [
                    {"accountIndex": 1, "owner": "OperatorWallet", "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
                    {"accountIndex": 2, "owner": "PayerWallet",    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"}
                ]
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": "OperatorWallet", "signer": true},
                        {"pubkey": "OperatorATA"},
                        {"pubkey": "PayerATA"}
                    ],
                    "instructions": [{
                        "programId": PAYMENT_CHANNELS_PROGRAM,
                        "accounts": ["OperatorWallet", "ChannelPDA"],
                        "data": bs58::encode([4u8]).into_string()
                    }]
                }
            }
        });

        // Build the skeleton, then manually invoke the reconciler with the
        // ata→owner map (the async path does this internally).
        let mut receipt = build_receipt_skeleton("sig", Network::Sandbox, &rpc, &[]).unwrap();
        let owners = collect_ata_owners(&rpc);
        reconcile_session_via_balances(&mut receipt, &owners);

        let s = receipt.session.expect("session present");
        assert_eq!(s.payer.as_deref(), Some("PayerWallet"));
        assert_eq!(s.payee.as_deref(), Some("OperatorWallet"));
        assert_eq!(s.refunded.as_ref().unwrap().raw_amount, "9900");
        assert_eq!(s.consumed.as_ref().unwrap().raw_amount, "100");
        // refund leg is excluded from distributed[]
        assert_eq!(s.distributed.len(), 1);
        assert_eq!(s.distributed[0].recipient, "OperatorATA");
    }

    #[test]
    fn settle_seal_reconciles_refund_with_wallet_keyed_receivers() {
        // Regression: on Surfpool/sandbox the settle/seal CPIs come back
        // unparsed, so transfers are derived from balance deltas and their
        // `receiver` is the OWNER WALLET (not an ATA in `ata_owners`). The
        // refund leg must still be detected; otherwise the whole channel
        // balance is reported as consumed. No inner token transfers here, which
        // forces the balance-delta extraction path.
        let rpc = json!({
            "slot": 100,
            "blockTime": 1_700_000_000_i64,
            "meta": {
                "err": null,
                "fee": 5000_u64,
                "preTokenBalances": [
                    {"accountIndex": 1, "owner": "OperatorWallet", "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 2, "owner": "PayerWallet",    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "uiTokenAmount": {"amount": "0", "decimals": 6}},
                    {"accountIndex": 3, "owner": "ChannelPDA",     "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "uiTokenAmount": {"amount": "10000", "decimals": 6}}
                ],
                "postTokenBalances": [
                    {"accountIndex": 1, "owner": "OperatorWallet", "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "uiTokenAmount": {"amount": "100",  "decimals": 6}},
                    {"accountIndex": 2, "owner": "PayerWallet",    "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "uiTokenAmount": {"amount": "9900", "decimals": 6}},
                    {"accountIndex": 3, "owner": "ChannelPDA",     "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "uiTokenAmount": {"amount": "0",    "decimals": 6}}
                ]
            },
            "transaction": {
                "message": {
                    "accountKeys": [
                        {"pubkey": "OperatorWallet", "signer": true},
                        {"pubkey": "OperatorATA"},
                        {"pubkey": "PayerATA"},
                        {"pubkey": "ChannelATA"}
                    ],
                    "instructions": [{
                        "programId": PAYMENT_CHANNELS_PROGRAM,
                        "accounts": ["OperatorWallet", "ChannelPDA"],
                        "data": bs58::encode([4u8]).into_string()
                    }]
                }
            }
        });

        let mut receipt = build_receipt_skeleton("sig", Network::Sandbox, &rpc, &[]).unwrap();
        // Sanity: the balance-delta path produced wallet-keyed receivers.
        let session = receipt.session.as_ref().expect("session present");
        assert!(
            session.events.iter().any(|e| e.receiver == "PayerWallet"),
            "expected wallet-keyed receiver from balance extraction"
        );

        let owners = collect_ata_owners(&rpc);
        reconcile_session_via_balances(&mut receipt, &owners);

        let s = receipt.session.expect("session present");
        assert_eq!(s.payer.as_deref(), Some("PayerWallet"));
        assert_eq!(s.payee.as_deref(), Some("OperatorWallet"));
        assert_eq!(s.refunded.as_ref().unwrap().raw_amount, "9900");
        assert_eq!(s.consumed.as_ref().unwrap().raw_amount, "100");
        assert_eq!(s.distributed.len(), 1);
        assert_eq!(s.distributed[0].recipient, "OperatorWallet");
    }

    #[test]
    fn reconcile_classifies_third_party_recipient_as_distribute() {
        let rpc = json!({
            "meta": {
                "err": null,
                "fee": 5000_u64,
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [
                        token_transfer("PDA", "OperatorATA", "M", "100", 6),
                        token_transfer("PDA", "TreasuryATA", "M", "50", 6),
                        token_transfer("PDA", "PayerATA",    "M", "9850", 6)
                    ]
                }],
                "postTokenBalances": [
                    {"accountIndex": 1, "owner": "OperatorWallet", "mint": "M"},
                    {"accountIndex": 2, "owner": "TreasuryWallet", "mint": "M"},
                    {"accountIndex": 3, "owner": "PayerWallet",    "mint": "M"}
                ]
            },
            "transaction": { "message": {
                "accountKeys": [
                    {"pubkey": "OperatorWallet"},
                    {"pubkey": "OperatorATA"},
                    {"pubkey": "TreasuryATA"},
                    {"pubkey": "PayerATA"}
                ],
                "instructions": [{
                    "programId": PAYMENT_CHANNELS_PROGRAM,
                    "accounts": ["OperatorWallet"],
                    "data": bs58::encode([4u8]).into_string()
                }]
            }}
        });
        let mut r = build_receipt_skeleton("sig", Network::Sandbox, &rpc, &[]).unwrap();
        reconcile_session_via_balances(&mut r, &collect_ata_owners(&rpc));
        let s = r.session.unwrap();
        let kinds: Vec<&str> = s.events.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"refund"));
        assert!(kinds.contains(&"consume"));
        assert!(kinds.contains(&"distribute"));
        // 100 (consume) + 50 (distribute) = 150
        assert_eq!(s.consumed.unwrap().raw_amount, "150");
        assert_eq!(s.refunded.unwrap().raw_amount, "9850");
    }

    #[test]
    fn reconcile_with_no_post_token_balances_falls_back_to_ata_addresses() {
        // When the RPC doesn't return preTokenBalances/postTokenBalances we
        // can't identify owners — the reconciler degrades gracefully and uses
        // the destination ATA address itself as a stand-in. The contract is:
        // the receipt still has a session block, the reconciler doesn't crash,
        // and the operator's tx-signer is detected as the payee.
        let rpc = json!({
            "meta": {
                "err": null, "fee": 5000_u64,
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [
                        token_transfer("PDA", "A", "M", "100", 6)
                    ]
                }]
            },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "Op"}, {"pubkey": "A"}],
                "instructions": [{
                    "programId": PAYMENT_CHANNELS_PROGRAM,
                    "accounts": ["Op"],
                    "data": bs58::encode([4u8]).into_string()
                }]
            }}
        });
        let mut r = build_receipt_skeleton("sig", Network::Sandbox, &rpc, &[]).unwrap();
        let owners = collect_ata_owners(&rpc);
        assert!(
            owners.is_empty(),
            "no postTokenBalances should give empty map"
        );
        reconcile_session_via_balances(&mut r, &owners);
        let s = r.session.expect("session still present");
        assert_eq!(s.payee.as_deref(), Some("Op"));
        // Without owner data the only "non-operator wallet" the reconciler can
        // see is the destination ATA itself, so it surfaces as the payer.
        assert!(s.payer.is_some());
    }

    // ── Account creation detection (ATAs) ─────────────────────────────────

    #[test]
    fn detects_create_idempotent_when_inner_create_account_present() {
        let inner = vec![
            json!({"program": "spl-token", "parsed": {"type": "getAccountDataSize"}}),
            json!({
                "program": "system",
                "parsed": {"type": "createAccount", "info": {"lamports": 2_039_280u64}}
            }),
            json!({"program": "spl-token", "parsed": {"type": "initializeAccount3"}}),
        ];
        let creations = detect_account_creations(
            &[json!({
                "programId": ATA_PROGRAM,
                "program": "spl-associated-token-account",
                "parsed": {
                    "type": "createIdempotent",
                    "info": {
                        "account": "NewATA",
                        "wallet": "Wallet",
                        "mint": "Mint",
                        "source": "Payer"
                    }
                }
            })],
            &[json!({ "index": 0, "instructions": inner })],
        );
        assert_eq!(creations.len(), 1);
        let c = &creations[0];
        assert_eq!(c.account, "NewATA");
        assert_eq!(c.wallet.as_deref(), Some("Wallet"));
        assert_eq!(c.mint.as_deref(), Some("Mint"));
        assert_eq!(c.paid_by.as_deref(), Some("Payer"));
        assert_eq!(c.rent_lamports, "2039280");
    }

    #[test]
    fn skips_create_idempotent_when_no_allocation_happened() {
        // No inner system.createAccount → idempotent call on an existing ATA.
        let creations = detect_account_creations(
            &[json!({
                "programId": ATA_PROGRAM,
                "program": "spl-associated-token-account",
                "parsed": { "type": "createIdempotent", "info": {"account": "X", "wallet": "W", "mint": "M"} }
            })],
            &[json!({ "index": 0, "instructions": [] })],
        );
        assert!(creations.is_empty());
    }

    #[test]
    fn detects_eager_create_ata() {
        let inner = vec![json!({
            "program": "system",
            "parsed": {"type": "createAccount", "info": {"lamports": 2_039_280u64}}
        })];
        let creations = detect_account_creations(
            &[json!({
                "programId": ATA_PROGRAM,
                "program": "spl-associated-token-account",
                "parsed": {"type": "create", "info": {"account": "A", "wallet": "W", "mint": "M"}}
            })],
            &[json!({"index": 0, "instructions": inner})],
        );
        assert_eq!(creations.len(), 1);
    }

    #[test]
    fn ignores_non_ata_program_instructions() {
        let creations = detect_account_creations(
            &[json!({
                "programId": SYSTEM_PROGRAM,
                "program": "system",
                "parsed": {"type": "transfer"}
            })],
            &[],
        );
        assert!(creations.is_empty());
    }

    // ── Splits aggregation ────────────────────────────────────────────────

    #[test]
    fn build_splits_groups_by_recipient_and_sums_to_10000_bps() {
        let transfers = vec![
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "A".into(),
                asset: "M".into(),
                symbol: None,
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "300".into(),
                ui_amount: 0.0003,
                memo: None,
            },
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "A".into(),
                asset: "M".into(),
                symbol: None,
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "200".into(),
                ui_amount: 0.0002,
                memo: None,
            },
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "B".into(),
                asset: "M".into(),
                symbol: None,
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "500".into(),
                ui_amount: 0.0005,
                memo: None,
            },
        ];
        let splits = build_splits(&transfers);
        assert_eq!(splits.len(), 2);
        let a = splits.iter().find(|s| s.recipient == "A").unwrap();
        let b = splits.iter().find(|s| s.recipient == "B").unwrap();
        assert_eq!(a.raw_amount, "500");
        assert_eq!(a.bps, 5_000);
        assert_eq!(b.raw_amount, "500");
        assert_eq!(b.bps, 5_000);
    }

    #[test]
    fn build_splits_skips_sol_transfers_and_handles_zero_total() {
        let transfers = vec![ReceiptTransfer {
            sender: "S".into(),
            receiver: "A".into(),
            asset: "SOL".into(),
            symbol: Some("SOL".into()),
            name: None,
            logo_uri: None,
            decimals: 9,
            raw_amount: "100".into(),
            ui_amount: 1e-7,
            memo: None,
        }];
        let splits = build_splits(&transfers);
        assert!(splits.is_empty());
    }

    // ── Total aggregation ─────────────────────────────────────────────────

    #[test]
    fn aggregate_total_sums_when_assets_match() {
        let transfers = vec![
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "A".into(),
                asset: "M".into(),
                symbol: Some("USDC".into()),
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "100".into(),
                ui_amount: 0.0001,
                memo: None,
            },
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "B".into(),
                asset: "M".into(),
                symbol: Some("USDC".into()),
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "900".into(),
                ui_amount: 0.0009,
                memo: None,
            },
        ];
        let total = aggregate_total(&transfers).unwrap();
        assert_eq!(total.raw_amount, "1000");
        assert_eq!(total.symbol.as_deref(), Some("USDC"));
    }

    #[test]
    fn aggregate_total_returns_none_when_assets_differ() {
        let transfers = vec![
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "A".into(),
                asset: "M1".into(),
                symbol: None,
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "100".into(),
                ui_amount: 0.0001,
                memo: None,
            },
            ReceiptTransfer {
                sender: "S".into(),
                receiver: "B".into(),
                asset: "M2".into(),
                symbol: None,
                name: None,
                logo_uri: None,
                decimals: 6,
                raw_amount: "900".into(),
                ui_amount: 0.0009,
                memo: None,
            },
        ];
        assert!(aggregate_total(&transfers).is_none());
    }

    // ── Status ────────────────────────────────────────────────────────────

    #[test]
    fn failed_transaction_yields_failed_status() {
        let rpc = json!({
            "meta": { "err": "InstructionError", "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "P"}],
                "instructions": [
                    token_transfer("A", "B", "M", "1", 6)
                ]
            }}
        });
        let r = parse(rpc);
        assert!(matches!(r.status, ReceiptStatus::Failed));
    }

    #[test]
    fn session_status_inferred_from_action_when_channel_state_missing() {
        // settleAndSeal on a closed channel — channel account would
        // already be the 1-byte marker, so the inferred status carries the
        // visual.
        let rpc = json!({
            "meta": {
                "err": null, "fee": 5000_u64,
                "innerInstructions": [{
                    "index": 0,
                    "instructions": [token_transfer("PDA", "A", "M", "100", 6)]
                }],
                "postTokenBalances": [
                    {"accountIndex": 1, "owner": "OperatorWallet", "mint": "M"}
                ]
            },
            "transaction": { "message": {
                "accountKeys": [{"pubkey": "OperatorWallet"}, {"pubkey": "A"}],
                "instructions": [{
                    "programId": PAYMENT_CHANNELS_PROGRAM,
                    "accounts": ["OperatorWallet"],
                    "data": bs58::encode([4u8]).into_string()
                }]
            }}
        });
        let mut r = build_receipt_skeleton("sig", Network::Sandbox, &rpc, &[]).unwrap();
        reconcile_session_via_balances(&mut r, &collect_ata_owners(&rpc));
        let s = r.session.unwrap();
        assert_eq!(s.channel_status, Some(WireChannelStatus::Sealed));
    }

    #[test]
    fn rejects_malformed_response_missing_account_keys() {
        let rpc = json!({
            "meta": { "err": null, "fee": 5000_u64, "innerInstructions": [] },
            "transaction": { "message": { "instructions": [] } }
        });
        let err = build_receipt_skeleton("sig", Network::Mainnet, &rpc, &[]);
        assert!(err.is_err());
    }
}
