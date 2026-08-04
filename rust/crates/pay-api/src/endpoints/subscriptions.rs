//! `POST /v1/subscriptions/cancel` — pay-api proxy for the subscriptions
//! program's `cancel_subscription` instruction.
//!
//! Asymmetric value-add: MPP defines an activation intent
//! (`intent="subscription"`) but **no** intent for cancellation — the spec
//! treats cancellation as a pure on-chain operation. This endpoint fills
//! that gap by charging a small **`intent="charge"`** USDC service fee in
//! exchange for SOL gas sponsorship: the agent partially signs a
//! `cancel_subscription` transaction (subscriber signature in place,
//! fee-payer slot left empty); the gateway co-signs as fee-payer and
//! broadcasts.
//!
//! Wire shape (mirrors [`super::send`]):
//!
//! 1. `POST /v1/subscriptions/cancel { tx, network }` with **no**
//!    `Authorization` header → `402 Payment Required` with a charge
//!    challenge for the cost-based USDC service fee (SOL gas converted
//!    via the SOL/USD oracle).
//! 2. `POST` again with `Authorization: Payment <credential>` and the
//!    same body → gateway verifies the charge, co-signs the
//!    `cancel_subscription` tx as fee-payer, broadcasts, waits for
//!    `confirmed` commitment, and returns `200 OK` with the cancel-tx
//!    signature + the charge receipt.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use pay_api_core::{Error, Stablecoin};
use pay_api_types::Network;
use pay_kit::mpp::ReceiptKind;
use pay_kit::mpp::program::subscriptions::{
    INSTRUCTION_CANCEL_SUBSCRIPTION, SUBSCRIPTIONS_PROGRAM_ID,
};
use pay_kit::mpp::protocol::solana::MethodDetails;
use pay_kit::mpp::server::{Config as MppConfig, Mpp};
use pay_kit::mpp::solana_keychain::{Signer, SolanaSigner};
use pay_kit::mpp::{ChargeRequest as MppChargeRequest, PaymentCredential};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use tracing::{info, warn};

use crate::state::AppState;

const PAYMENT_RECEIPT_HEADER: HeaderName = HeaderName::from_static("payment-receipt");
const COMPUTE_BUDGET_PROGRAM_ID: &str = "ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Debug, Deserialize)]
pub struct CancelRequest {
    /// Standard-base64 of the partially-signed `cancel_subscription`
    /// transaction. The agent signs as subscriber; the fee-payer slot
    /// (account_keys[0]) is left empty for the gateway.
    ///
    /// Optional on the **first** (unauthenticated) POST so a fresh
    /// client can discover the gateway's fee-payer pubkey + service
    /// fee via the 402 response before building the tx. Required on
    /// the second POST (with `Authorization`); the gateway co-signs
    /// and broadcasts it.
    #[serde(default)]
    pub tx: Option<String>,
    /// Base58 of the `SubscriptionDelegation` PDA being cancelled.
    /// Required on the discovery POST when `tx` is omitted — without
    /// it the gateway can't bind the charge challenge to a specific
    /// subscription. When `tx` is present this field is ignored;
    /// the gateway extracts the PDA from the tx's account_metas.
    #[serde(default, rename = "subscriptionPda")]
    pub subscription_pda: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    /// Stablecoin the agent wants to pay the service fee in.
    /// Defaults to `"USDC"` if not provided.
    #[serde(default)]
    pub currency: Option<String>,
}

#[derive(Debug, Serialize)]
struct CancelChallengeResponse {
    challenge: pay_kit::mpp::PaymentChallenge,
    #[serde(rename = "wwwAuthenticate")]
    www_authenticate: String,
    network: Network,
    currency: String,
    /// Service fee in USDC base units (decimal string).
    #[serde(rename = "feeRaw")]
    fee_raw: String,
    /// Service fee in SOL lamports the gateway expects to pay on-chain.
    #[serde(rename = "estimatedFeeLamports")]
    estimated_fee_lamports: u64,
    #[serde(rename = "solUsdPrice")]
    sol_usd_price: f64,
    #[serde(rename = "feePayer")]
    fee_payer: String,
    #[serde(rename = "subscriptionPda")]
    subscription_pda: String,
    /// Base58 subscriber pubkey extracted from the submitted transaction.
    /// `None` on the discovery POST (no tx was supplied) — the client
    /// already knows its own pubkey so the echoed value is purely
    /// informational and we omit it cleanly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriber: Option<String>,
}

#[derive(Debug, Serialize)]
struct CancelReceiptResponse {
    /// Cancel transaction signature (base58).
    pub signature: String,
    /// Payment-Receipt header echoed in the response body for clients
    /// that prefer JSON over header parsing.
    pub receipt: pay_kit::mpp::Receipt,
    /// Base58 of the on-chain `SubscriptionDelegation` PDA that was
    /// cancelled.
    #[serde(rename = "subscriptionPda")]
    pub subscription_pda: String,
}

struct ParsedCancelTx {
    /// The full (partially-signed) transaction the agent submitted.
    tx: Transaction,
    /// Subscriber pubkey extracted from the cancel_subscription
    /// instruction's first account meta.
    subscriber: Pubkey,
    /// Plan PDA — the second account meta of cancel_subscription.
    /// Surfaced for downstream telemetry / structured logs; not yet
    /// consumed by the handler itself.
    #[allow(dead_code)]
    plan_pda: Pubkey,
    /// SubscriptionDelegation PDA — the third account meta. We surface
    /// this as the canonical id of what's being cancelled.
    subscription_pda: Pubkey,
    /// Index of the cancel_subscription instruction in
    /// `tx.message.instructions`. Used for trace logging.
    #[allow(dead_code)]
    cancel_ix_index: usize,
}

struct ResolvedCancel {
    network: Network,
    cluster: &'static str,
    rpc_url: String,
    coin: Stablecoin,
    /// Parsed cancel tx — present when the client included `tx` in
    /// the body (second-phase POST), absent on the discovery POST.
    /// The 402 challenge can be built from `subscription_pda` alone;
    /// only the broadcast path requires the full parsed tx.
    parsed: Option<ParsedCancelTx>,
    /// Subscription PDA the request is for. Sourced either from the
    /// parsed tx's account_metas (when `tx` was supplied) or from the
    /// explicit `subscriptionPda` field on the discovery POST.
    subscription_pda: Pubkey,
    fee_payer_pubkey: String,
}

struct PreparedChallenge {
    resolved: ResolvedCancel,
    sol_usd_price: f64,
    fee_raw: u64,
    charge_request: MppChargeRequest,
}

pub async fn cancel_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CancelRequest>,
) -> Result<Response, ApiError> {
    let resolved = resolve_cancel_request(&state, &request).map_err(ApiError)?;

    if let Some(header) = headers.get(AUTHORIZATION) {
        return verify_and_broadcast(state, resolved, header).await;
    }

    let prepared = prepare_challenge(&state, resolved)
        .await
        .map_err(ApiError)?;
    let mpp = new_mpp(&state, &prepared.resolved, None)
        .await
        .map_err(ApiError)?;
    let challenge = mpp
        .charge_challenge(&prepared.charge_request)
        .map_err(|_| ApiError(Error::PaymentChallenge))?;
    let www_authenticate = pay_kit::mpp::format_www_authenticate(&challenge)
        .map_err(|_| ApiError(Error::PaymentChallenge))?;

    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        Json(CancelChallengeResponse {
            challenge,
            www_authenticate: www_authenticate.clone(),
            network: prepared.resolved.network,
            currency: prepared.resolved.coin.symbol.clone(),
            fee_raw: prepared.fee_raw.to_string(),
            estimated_fee_lamports: state.subscriptions.estimated_fee_lamports,
            sol_usd_price: prepared.sol_usd_price,
            fee_payer: prepared.resolved.fee_payer_pubkey.clone(),
            subscription_pda: prepared.resolved.subscription_pda.to_string(),
            subscriber: prepared
                .resolved
                .parsed
                .as_ref()
                .map(|p| p.subscriber.to_string()),
        }),
    )
        .into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&www_authenticate).map_err(|_| ApiError(Error::PaymentChallenge))?,
    );
    Ok(response)
}

async fn verify_and_broadcast(
    state: Arc<AppState>,
    resolved: ResolvedCancel,
    header: &HeaderValue,
) -> Result<Response, ApiError> {
    // The second-phase POST MUST carry the tx so we can co-sign + broadcast.
    // Reject cleanly if the client forgot it — without this check we'd
    // pass the credential verification and then crash later in
    // `co_sign_and_broadcast`.
    if resolved.parsed.is_none() {
        return Err(ApiError(Error::InvalidPaymentCredential));
    }

    let header = header
        .to_str()
        .map_err(|_| ApiError(Error::InvalidPaymentCredential))?;
    let credential = PaymentCredential::from_header(header)
        .map_err(|_| ApiError(Error::InvalidPaymentCredential))?;
    let charge_request: MppChargeRequest = credential
        .challenge
        .request
        .decode()
        .map_err(|_| ApiError(Error::InvalidPaymentCredential))?;

    validate_paid_cancel_request(&charge_request, &resolved).map_err(ApiError)?;

    let signer = fee_payer_signer(&state)
        .await
        .map_err(|_| ApiError(Error::FeePayerSigner))?;
    let mpp = new_mpp(&state, &resolved, Some(Arc::clone(&signer)))
        .await
        .map_err(ApiError)?;

    // ── Verify the USDC charge credential ───────────────────────────────
    let charge_receipt = match mpp.verify(&credential, &charge_request).await {
        Ok(receipt) => receipt,
        Err(error) => {
            warn!(
                error = %error,
                code = error.code.unwrap_or("unknown"),
                retryable = error.retryable,
                title = %error.title,
                "subscription cancel: charge verification failed"
            );
            return Err(ApiError(Error::InvalidPaymentCredential));
        }
    };

    // ── Co-sign the cancel_subscription tx as fee-payer ─────────────────
    let signature = co_sign_and_broadcast(&state, &resolved, signer)
        .await
        .map_err(ApiError)?;

    // ── Wait for confirmation ───────────────────────────────────────────
    state
        .rpc
        .confirm_signature(
            &resolved.rpc_url,
            &signature.to_string(),
            Duration::from_secs(state.subscriptions.confirm_timeout_seconds),
        )
        .await
        .map_err(ApiError)?;

    info!(
        signature = %signature,
        subscription = %resolved.subscription_pda,
        "subscription cancel confirmed"
    );

    // Wrap the charge receipt in `ReceiptKind::Charge` for the on-the-wire
    // `Payment-Receipt` header; the JSON response body still surfaces the
    // base receipt for clients that don't parse headers.
    let kind = ReceiptKind::Charge(charge_receipt);
    let receipt_header =
        pay_kit::mpp::format_receipt(&kind).map_err(|_| ApiError(Error::PaymentChallenge))?;
    let receipt = match kind {
        ReceiptKind::Charge(r) => r,
        ReceiptKind::Subscription { base, .. } => base,
    };

    let mut response = (
        StatusCode::OK,
        Json(CancelReceiptResponse {
            signature: signature.to_string(),
            receipt,
            subscription_pda: resolved.subscription_pda.to_string(),
        }),
    )
        .into_response();
    response.headers_mut().insert(
        PAYMENT_RECEIPT_HEADER,
        HeaderValue::from_str(&receipt_header).map_err(|_| ApiError(Error::PaymentChallenge))?,
    );
    Ok(response)
}

fn resolve_cancel_request(
    state: &AppState,
    request: &CancelRequest,
) -> Result<ResolvedCancel, Error> {
    if !state.subscriptions.enabled {
        return Err(Error::SendNotConfigured(
            "set PAY_API_SUBSCRIPTIONS__ENABLED=true and configure a fee payer".into(),
        ));
    }

    let network = match request.network.as_deref().map(str::trim) {
        Some("") | None => Network::Mainnet,
        Some(value) => value.parse::<Network>().map_err(Error::from)?,
    };
    let cluster = mpp_cluster(network);
    let rpc_url = state.rpc_url_for(network)?.to_string();

    let currency = request
        .currency
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("USDC");
    let coin = resolve_stablecoin(&state.stablecoins, currency)
        .ok_or_else(|| Error::UnsupportedCurrency(currency.to_string()))?
        .clone();

    let fee_payer_pubkey = configured_fee_payer_pubkey(state)?;

    // Two entry shapes:
    //   - Discovery POST (no `tx`): client supplies `subscriptionPda` so
    //     the 402 challenge can be bound to that subscription, the
    //     gateway's fee-payer pubkey can be advertised, and the
    //     subscriber can build the tx after learning the price.
    //   - Authenticated POST (with `tx`): we parse the tx, validate
    //     scope, and extract the PDA from its account_metas.
    let (parsed, subscription_pda) = match request.tx.as_deref() {
        Some(tx_b64) if !tx_b64.trim().is_empty() => {
            let parsed = parse_cancel_tx(tx_b64, &fee_payer_pubkey)?;
            let pda = parsed.subscription_pda;
            (Some(parsed), pda)
        }
        _ => {
            let pda_str = request
                .subscription_pda
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or(Error::InvalidPaymentCredential)?;
            let pda = Pubkey::from_str(pda_str).map_err(|_| Error::InvalidAddress)?;
            (None, pda)
        }
    };

    Ok(ResolvedCancel {
        network,
        cluster,
        rpc_url,
        coin,
        parsed,
        subscription_pda,
        fee_payer_pubkey,
    })
}

/// Decode the base64-encoded transaction, validate its instruction scope,
/// and pull out the subscriber + plan + subscription PDAs the agent is
/// asking us to cancel.
///
/// Per the spec § "Activation Scope Verification" (adapted for the
/// cancel case): the submitted transaction may contain only
/// `cancel_subscription` on the canonical subscriptions program, plus
/// optional compute-budget and memo instructions. Everything else is
/// rejected.
fn parse_cancel_tx(tx_b64: &str, expected_fee_payer: &str) -> Result<ParsedCancelTx, Error> {
    use base64::Engine;
    use solana_sanitize::Sanitize;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(tx_b64.trim())
        .map_err(|_| Error::InvalidPaymentCredential)?;
    let tx: Transaction =
        bincode::deserialize(&raw).map_err(|_| Error::InvalidPaymentCredential)?;
    tx.sanitize().map_err(|_| Error::InvalidPaymentCredential)?;

    let keys = &tx.message.account_keys;
    let required_signatures = tx.message.header.num_required_signatures as usize;
    if keys.is_empty() || required_signatures == 0 || tx.signatures.len() != required_signatures {
        return Err(Error::InvalidPaymentCredential);
    }

    // Fee-payer slot must be set to *our* operator pubkey so that signing
    // it later doesn't disturb the account-keys ordering or invalidate
    // the subscriber's signature.
    let expected_fp = Pubkey::from_str(expected_fee_payer).map_err(|_| Error::InvalidAddress)?;
    if keys[0] != expected_fp {
        return Err(Error::InvalidPaymentCredential);
    }

    let program_id = Pubkey::from_str(SUBSCRIPTIONS_PROGRAM_ID).expect("valid program id");
    let compute_budget =
        Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).expect("valid compute budget program id");
    let memo = Pubkey::from_str(MEMO_PROGRAM_ID).expect("valid memo program id");

    let mut cancel_ix_index: Option<usize> = None;
    for (i, ix) in tx.message.instructions.iter().enumerate() {
        let prog_idx = ix.program_id_index as usize;
        if prog_idx >= keys.len() {
            return Err(Error::InvalidPaymentCredential);
        }
        let program = keys[prog_idx];
        if program == program_id {
            if ix.data.first().copied() != Some(INSTRUCTION_CANCEL_SUBSCRIPTION) {
                return Err(Error::InvalidPaymentCredential);
            }
            if cancel_ix_index.is_some() {
                return Err(Error::InvalidPaymentCredential);
            }
            cancel_ix_index = Some(i);
        } else if program != compute_budget && program != memo {
            return Err(Error::InvalidPaymentCredential);
        }
    }

    let cancel_ix_index = cancel_ix_index.ok_or(Error::InvalidPaymentCredential)?;
    let cancel_ix = &tx.message.instructions[cancel_ix_index];

    // Subscriber = accounts[0], plan_pda = accounts[1], subscription_pda =
    // accounts[2] per the program's `CancelSubscriptionAccounts` layout.
    let resolve = |index: usize| -> Result<Pubkey, Error> {
        let key_idx = *cancel_ix
            .accounts
            .get(index)
            .ok_or(Error::InvalidPaymentCredential)? as usize;
        keys.get(key_idx)
            .copied()
            .ok_or(Error::InvalidPaymentCredential)
    };
    let subscriber = resolve(0)?;
    let plan_pda = resolve(1)?;
    let subscription_pda = resolve(2)?;

    Ok(ParsedCancelTx {
        tx,
        subscriber,
        plan_pda,
        subscription_pda,
        cancel_ix_index,
    })
}

async fn prepare_challenge(
    state: &AppState,
    resolved: ResolvedCancel,
) -> Result<PreparedChallenge, Error> {
    let price_rpc_url = state.rpc_url_for(Network::Mainnet)?;
    let sol_usd_price = state
        .rpc
        .get_asset_price_per_token(price_rpc_url, &state.subscriptions.sol_price_asset)
        .await?;
    let fee_raw = fee_base_units(
        state.subscriptions.estimated_fee_lamports,
        sol_usd_price,
        resolved.coin.decimals,
    )?;
    // Fetch a recent blockhash on the cancel network and embed it in
    // the charge challenge's `methodDetails` (mirrors MPP charge:
    // clients build the tx without their own Solana RPC connection).
    let recent_blockhash = state.rpc.get_latest_blockhash(&resolved.rpc_url).await.ok();
    let charge_request = build_charge_request(&resolved, fee_raw, recent_blockhash)?;

    Ok(PreparedChallenge {
        resolved,
        sol_usd_price,
        fee_raw,
        charge_request,
    })
}

fn build_charge_request(
    resolved: &ResolvedCancel,
    fee_raw: u64,
    recent_blockhash: Option<String>,
) -> Result<MppChargeRequest, Error> {
    let method_details = MethodDetails {
        network: Some(resolved.cluster.to_string()),
        decimals: Some(resolved.coin.decimals),
        token_program: Some(resolved.coin.token_program.to_string()),
        fee_payer: Some(true),
        fee_payer_key: Some(resolved.fee_payer_pubkey.clone()),
        splits: None,
        recent_blockhash,
        confidential: None,
        auditor_elgamal_pubkey: None,
        recipient_elgamal_pubkey: None,
    };
    Ok(MppChargeRequest {
        amount: fee_raw.to_string(),
        currency: resolved.coin.mint.to_string(),
        recipient: Some(resolved.fee_payer_pubkey.clone()),
        description: Some(format!(
            "Cancel subscription {} (gateway fee {} {})",
            short_address(&resolved.subscription_pda.to_string()),
            format_base_units(fee_raw, resolved.coin.decimals),
            resolved.coin.symbol
        )),
        external_id: Some(resolved.subscription_pda.to_string()),
        method_details: Some(
            serde_json::to_value(method_details).map_err(|_| Error::PaymentChallenge)?,
        ),
        ..Default::default()
    })
}

fn validate_paid_cancel_request(
    charge_request: &MppChargeRequest,
    resolved: &ResolvedCancel,
) -> Result<(), Error> {
    if charge_request.currency != resolved.coin.mint.to_string() {
        return Err(Error::InvalidPaymentCredential);
    }
    if charge_request.recipient.as_deref() != Some(resolved.fee_payer_pubkey.as_str()) {
        return Err(Error::InvalidPaymentCredential);
    }
    // Pin external_id to the subscription PDA so the on-the-wire USDC tx
    // carries an audit trail of which subscription it paid to cancel.
    if charge_request.external_id.as_deref() != Some(resolved.subscription_pda.to_string().as_str())
    {
        return Err(Error::InvalidPaymentCredential);
    }
    Ok(())
}

async fn co_sign_and_broadcast(
    state: &AppState,
    resolved: &ResolvedCancel,
    signer: Arc<dyn SolanaSigner>,
) -> Result<Signature, Error> {
    // Broadcast path requires the full parsed tx — `verify_and_broadcast`
    // only invokes us after confirming `parsed.is_some()`.
    let parsed = resolved
        .parsed
        .as_ref()
        .ok_or(Error::InvalidPaymentCredential)?;
    let mut tx = parsed.tx.clone();
    let fee_payer = signer.pubkey();
    let fee_payer_index = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == fee_payer)
        .ok_or(Error::FeePayerSigner)?;

    let msg_bytes = tx.message_data();
    let sig_bytes = signer
        .sign_message(&msg_bytes)
        .await
        .map_err(|_| Error::FeePayerSigner)?;
    let signature = Signature::from(<[u8; 64]>::from(sig_bytes));
    if tx.signatures.len() <= fee_payer_index {
        return Err(Error::FeePayerSigner);
    }
    tx.signatures[fee_payer_index] = signature;

    let serialised = bincode::serialize(&tx).map_err(|_| Error::PaymentChallenge)?;
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &serialised);

    let sig_str = state
        .rpc
        .send_raw_transaction(&resolved.rpc_url, &tx_b64)
        .await?;
    Signature::from_str(&sig_str).map_err(|_| Error::RpcMalformed)
}

async fn new_mpp(
    state: &AppState,
    resolved: &ResolvedCancel,
    fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
) -> Result<Mpp, Error> {
    let has_fee_payer_signer = fee_payer_signer.is_some();
    Mpp::new(MppConfig {
        recipient: resolved.fee_payer_pubkey.clone(),
        currency: resolved.coin.mint.to_string(),
        decimals: resolved.coin.decimals,
        network: resolved.cluster.to_string(),
        rpc_url: Some(resolved.rpc_url.clone()),
        challenge_binding_secret: state.subscriptions_challenge_binding_secret.clone(),
        realm: Some(state.subscriptions.realm.clone()),
        fee_payer: has_fee_payer_signer,
        fee_payer_signer,
        html: false,
        ..Default::default()
    })
    .map_err(|_| Error::PaymentChallenge)
}

async fn fee_payer_signer(state: &AppState) -> Result<Arc<dyn SolanaSigner>, Error> {
    let key_name = state
        .subscriptions_fee_payer
        .key_name
        .as_deref()
        .ok_or_else(|| {
            Error::SendNotConfigured(
                "subscriptions.fee_payer.key_name (or send.fee_payer.key_name) is missing".into(),
            )
        })?;
    let pubkey = state
        .subscriptions_fee_payer
        .pubkey
        .as_deref()
        .ok_or_else(|| {
            Error::SendNotConfigured(
                "subscriptions.fee_payer.pubkey (or send.fee_payer.pubkey) is missing".into(),
            )
        })?;
    let signer = Signer::from_gcp_kms(key_name.to_string(), pubkey.to_string())
        .await
        .map_err(|_| Error::FeePayerSigner)?;
    Ok(Arc::new(signer))
}

fn configured_fee_payer_pubkey(state: &AppState) -> Result<String, Error> {
    let pubkey = state
        .subscriptions_fee_payer
        .pubkey
        .as_deref()
        .ok_or_else(|| {
            Error::SendNotConfigured(
                "subscriptions.fee_payer.pubkey (or send.fee_payer.pubkey) is missing".into(),
            )
        })?
        .trim();
    Pubkey::from_str(pubkey).map_err(|_| {
        Error::SendNotConfigured(
            "invalid subscriptions.fee_payer.pubkey (or send.fee_payer.pubkey)".into(),
        )
    })?;
    Ok(pubkey.to_string())
}

fn resolve_stablecoin<'a>(coins: &'a [Stablecoin], currency: &str) -> Option<&'a Stablecoin> {
    let currency = currency.trim();
    coins.iter().find(|coin| {
        coin.symbol.eq_ignore_ascii_case(currency) || coin.mint.to_string() == currency
    })
}

fn fee_base_units(
    estimated_fee_lamports: u64,
    sol_usd_price: f64,
    decimals: u8,
) -> Result<u64, Error> {
    if !sol_usd_price.is_finite() || sol_usd_price <= 0.0 {
        return Err(Error::PriceUnavailable);
    }
    let scale = 10f64.powi(decimals as i32);
    let raw = ((estimated_fee_lamports as f64 / 1_000_000_000f64) * sol_usd_price * scale).ceil();
    if !raw.is_finite() || raw <= 0.0 || raw > u64::MAX as f64 {
        return Err(Error::PriceUnavailable);
    }
    Ok(raw as u64)
}

fn mpp_cluster(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Sandbox => "localnet",
    }
}

fn short_address(address: &str) -> String {
    let mut chars = address.chars();
    let prefix = chars.by_ref().take(4).collect::<String>();
    let suffix = address
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    if address.chars().count() <= 8 {
        address.to_string()
    } else {
        format!("{prefix}...{suffix}")
    }
}

fn format_base_units(raw: u64, decimals: u8) -> String {
    if decimals == 0 {
        return raw.to_string();
    }
    let Some(scale) = 10_u128.checked_pow(decimals as u32) else {
        return raw.to_string();
    };
    let raw = raw as u128;
    let whole = raw / scale;
    let fraction = raw % scale;
    if fraction == 0 {
        return whole.to_string();
    }
    let mut fraction = format!("{fraction:0width$}", width = decimals as usize);
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{whole}.{fraction}")
}

pub struct ApiError(Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            warn!(error = %self.0, "subscription cancel request failed");
        }
        let body = Json(json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::Message;
    use solana_transaction::Transaction;

    fn build_cancel_tx(
        fee_payer: Pubkey,
        subscriber: Pubkey,
        plan_pda: Pubkey,
        subscription_pda: Pubkey,
    ) -> Transaction {
        let program_id = Pubkey::from_str(SUBSCRIPTIONS_PROGRAM_ID).unwrap();
        let event_authority = Pubkey::new_unique();
        // Order in CancelSubscriptionAccounts: subscriber, plan_pda,
        // subscription_pda, event_authority, self_program.
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(subscriber, true),
                AccountMeta::new_readonly(plan_pda, false),
                AccountMeta::new(subscription_pda, false),
                AccountMeta::new_readonly(event_authority, false),
                AccountMeta::new_readonly(program_id, false),
            ],
            data: vec![INSTRUCTION_CANCEL_SUBSCRIPTION],
        };
        let message = Message::new(&[ix], Some(&fee_payer));
        Transaction::new_unsigned(message)
    }

    fn encode_tx(tx: &Transaction) -> String {
        let bytes = bincode::serialize(tx).unwrap();
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &bytes)
    }

    #[test]
    fn parse_cancel_tx_extracts_subscriber_plan_and_subscription() {
        let fee_payer = Pubkey::new_unique();
        let subscriber = Pubkey::new_unique();
        let plan = Pubkey::new_unique();
        let sub = Pubkey::new_unique();
        let tx = build_cancel_tx(fee_payer, subscriber, plan, sub);
        let parsed = parse_cancel_tx(&encode_tx(&tx), &fee_payer.to_string()).unwrap();
        assert_eq!(parsed.subscriber, subscriber);
        assert_eq!(parsed.plan_pda, plan);
        assert_eq!(parsed.subscription_pda, sub);
    }

    #[test]
    fn parse_cancel_tx_rejects_wrong_fee_payer() {
        let real_fee_payer = Pubkey::new_unique();
        let imposter = Pubkey::new_unique();
        let tx = build_cancel_tx(
            real_fee_payer,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        // Submitting an imposter pubkey as the expected fee payer must fail.
        assert!(parse_cancel_tx(&encode_tx(&tx), &imposter.to_string()).is_err());
    }

    #[test]
    fn parse_cancel_tx_rejects_missing_signature_slots() {
        let fee_payer = Pubkey::new_unique();
        let mut tx = build_cancel_tx(
            fee_payer,
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            Pubkey::new_unique(),
        );
        tx.signatures.clear();

        assert!(parse_cancel_tx(&encode_tx(&tx), &fee_payer.to_string()).is_err());
    }

    #[test]
    fn parse_cancel_tx_rejects_extra_program() {
        let fee_payer = Pubkey::new_unique();
        let sub = Pubkey::new_unique();
        let program_id = Pubkey::from_str(SUBSCRIPTIONS_PROGRAM_ID).unwrap();
        let event_authority = Pubkey::new_unique();
        let unauthorised_program = Pubkey::new_unique();
        let cancel_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(Pubkey::new_unique(), true),
                AccountMeta::new_readonly(Pubkey::new_unique(), false),
                AccountMeta::new(sub, false),
                AccountMeta::new_readonly(event_authority, false),
                AccountMeta::new_readonly(program_id, false),
            ],
            data: vec![INSTRUCTION_CANCEL_SUBSCRIPTION],
        };
        let rogue_ix = Instruction {
            program_id: unauthorised_program,
            accounts: vec![],
            data: vec![0xAA],
        };
        let message = Message::new(&[cancel_ix, rogue_ix], Some(&fee_payer));
        let tx = Transaction::new_unsigned(message);
        assert!(parse_cancel_tx(&encode_tx(&tx), &fee_payer.to_string()).is_err());
    }

    #[test]
    fn parse_cancel_tx_rejects_missing_cancel_instruction() {
        // A compute-budget-only transaction has no cancel ix to authorise.
        let fee_payer = Pubkey::new_unique();
        let compute = Pubkey::from_str(COMPUTE_BUDGET_PROGRAM_ID).unwrap();
        let ix = Instruction {
            program_id: compute,
            accounts: vec![],
            data: vec![2, 0, 0, 0, 0],
        };
        let message = Message::new(&[ix], Some(&fee_payer));
        let tx = Transaction::new_unsigned(message);
        assert!(parse_cancel_tx(&encode_tx(&tx), &fee_payer.to_string()).is_err());
    }

    #[test]
    fn parse_cancel_tx_rejects_two_cancel_instructions() {
        let fee_payer = Pubkey::new_unique();
        let program_id = Pubkey::from_str(SUBSCRIPTIONS_PROGRAM_ID).unwrap();
        let dummy = Pubkey::new_unique();
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(dummy, true),
                AccountMeta::new_readonly(dummy, false),
                AccountMeta::new(dummy, false),
                AccountMeta::new_readonly(dummy, false),
                AccountMeta::new_readonly(program_id, false),
            ],
            data: vec![INSTRUCTION_CANCEL_SUBSCRIPTION],
        };
        let message = Message::new(&[ix.clone(), ix], Some(&fee_payer));
        let tx = Transaction::new_unsigned(message);
        assert!(parse_cancel_tx(&encode_tx(&tx), &fee_payer.to_string()).is_err());
    }

    #[test]
    fn fee_base_units_converts_lamports_to_stablecoin_base_units() {
        // 10_000 lamports at SOL = $150 = 0.000_001_5 SOL × 1e6 USDC scale = 1500.
        assert_eq!(fee_base_units(10_000, 150.0, 6).unwrap(), 1500);
        // Always rounds up so the gateway is never under-paid.
        assert_eq!(fee_base_units(1, 0.01, 6).unwrap(), 1);
    }

    #[test]
    fn fee_base_units_rejects_unfunded_price_oracle() {
        assert!(fee_base_units(10_000, 0.0, 6).is_err());
        assert!(fee_base_units(10_000, f64::NAN, 6).is_err());
    }

    #[test]
    fn format_base_units_strips_trailing_zeros() {
        assert_eq!(format_base_units(1_500, 6), "0.0015");
        assert_eq!(format_base_units(1_000_000, 6), "1");
        assert_eq!(format_base_units(0, 6), "0");
    }

    #[test]
    fn short_address_keeps_edges() {
        assert_eq!(
            short_address("96WoyH3JmANSMsQLGC3MKyiGiXCymZyM9SLaWjcRrKuD"),
            "96Wo...rKuD"
        );
    }

    #[test]
    fn mpp_cluster_uses_canonical_wire_slugs() {
        assert_eq!(mpp_cluster(Network::Mainnet), "mainnet");
        assert_eq!(mpp_cluster(Network::Sandbox), "localnet");
    }
}
