use std::str::FromStr;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use pay_api_core::ata::{SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID, associated_token_address};
use pay_api_core::{Error, Stablecoin};
use pay_api_types::Network;
use pay_kit::mpp::protocol::solana::{MethodDetails, Split};
use pay_kit::mpp::server::{Config as MppConfig, Mpp};
use pay_kit::mpp::{ChargeRequest as MppChargeRequest, PaymentCredential, Receipt};
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_pubkey::Pubkey;
use spl_token_2022_interface::extension::{
    BaseStateWithExtensions, ExtensionType, StateWithExtensions,
};
use spl_token_2022_interface::state::{Account as Token2022Account, Mint as Token2022Mint};
use tracing::warn;

use crate::config::FeeRefundSplitConfig;
use crate::state::AppState;

const PAYMENT_RECEIPT_HEADER: HeaderName = HeaderName::from_static("payment-receipt");
const SPL_TOKEN_ACCOUNT_LEN: usize = 165;

/// Canonical on-chain memos the send endpoint stamps onto each transfer.
/// These show up on the receipt page paired with their transfer (see
/// `attach_memos_to_transfers` in pay-api-core). The main-transfer memo
/// is overridden by `SendRequest.memo` when the caller supplies one.
const MAIN_TRANSFER_MEMO: &str = "Transfer";
const NETWORK_FEE_MEMO: &str = "Network fee";
const NETWORK_FEE_WITH_ATA_MEMO: &str = "Network fee (include account creation)";

/// Pick the canonical fee-payer-refund memo: the standard "Network fee"
/// label, with an "(include account creation)" suffix when the same
/// payment had to spin up a new recipient ATA.
fn fee_refund_memo(ata_creation_required: bool) -> &'static str {
    if ata_creation_required {
        NETWORK_FEE_WITH_ATA_MEMO
    } else {
        NETWORK_FEE_MEMO
    }
}

/// Resolve the on-chain memo for the user-facing transfer. The
/// canonical default is `MAIN_TRANSFER_MEMO`; a non-empty caller-supplied
/// memo overrides it so invoice IDs / order numbers can ride along.
fn main_transfer_memo(user_memo: Option<&str>) -> String {
    user_memo
        .map(str::trim)
        .filter(|memo| !memo.is_empty())
        .unwrap_or(MAIN_TRANSFER_MEMO)
        .to_string()
}

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub recipient: String,
    pub amount: String,
    pub currency: String,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub memo: Option<String>,
    #[serde(default, rename = "feeWithin", alias = "fee_within")]
    pub fee_within: bool,
    /// Request a Token-2022 confidential transfer (amount hidden on-chain).
    /// Only valid for a Token-2022 mint with the Confidential Transfer
    /// extension; the challenge is issued with `methodDetails.confidential`.
    #[serde(default)]
    pub confidential: bool,
}

#[derive(Debug, Serialize)]
struct SendChallengeResponse {
    challenge: pay_kit::mpp::PaymentChallenge,
    #[serde(rename = "wwwAuthenticate")]
    www_authenticate: String,
    recipient: String,
    currency: String,
    network: Network,
    #[serde(rename = "recipientAmountRaw")]
    recipient_amount_raw: String,
    #[serde(rename = "requestedAmountRaw")]
    requested_amount_raw: String,
    #[serde(rename = "feeRefundRaw")]
    fee_refund_raw: String,
    #[serde(rename = "totalAmountRaw")]
    total_amount_raw: String,
    #[serde(rename = "feeWithin")]
    fee_within: bool,
    #[serde(rename = "recipientAtaCreationRequired")]
    recipient_ata_creation_required: bool,
    #[serde(rename = "feePayer")]
    fee_payer: String,
    #[serde(rename = "solUsdPrice")]
    sol_usd_price: f64,
    #[serde(rename = "estimatedFeeLamports")]
    estimated_fee_lamports: u64,
}

#[derive(Debug, Serialize)]
struct SendReceiptResponse {
    receipt: Receipt,
}

struct ResolvedSend {
    network: Network,
    cluster: &'static str,
    rpc_url: String,
    recipient: String,
    coin: Stablecoin,
    requested_amount_raw: u64,
    memo: Option<String>,
    fee_within: bool,
    fee_payer_pubkey: String,
    confidential: bool,
}

struct PreparedChallenge {
    resolved: ResolvedSend,
    sol_usd_price: f64,
    estimated_fee_lamports: u64,
    recipient_amount_raw: u64,
    fee_refund_raw: u64,
    total_amount_raw: u64,
    recipient_ata_creation_required: bool,
    charge_request: MppChargeRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendChallengeLayout {
    ExistingRecipientAta,
    CreateRecipientAta,
}

pub async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<SendRequest>,
) -> Result<Response, ApiError> {
    let resolved = resolve_send_request(&state, &request).map_err(ApiError)?;
    ensure_confidential_transfer_supported(&state, &resolved)
        .await
        .map_err(ApiError)?;

    if let Some(header) = headers.get(AUTHORIZATION) {
        return verify_paid_send(state, resolved, header).await;
    }

    let prepared = prepare_challenge(&state, resolved)
        .await
        .map_err(ApiError)?;
    let mpp = new_mpp(&state, &prepared.resolved, None, None)
        .await
        .map_err(ApiError)?;
    let challenge = mpp
        .charge_challenge(&prepared.charge_request)
        .map_err(|e| {
            tracing::error!(error = ?e, "charge_challenge failed");
            ApiError(Error::PaymentChallenge)
        })?;
    let www_authenticate = pay_kit::mpp::format_www_authenticate(&challenge)
        .map_err(|_| ApiError(Error::PaymentChallenge))?;

    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        Json(SendChallengeResponse {
            challenge,
            www_authenticate: www_authenticate.clone(),
            recipient: prepared.resolved.recipient,
            currency: prepared.resolved.coin.symbol,
            network: prepared.resolved.network,
            recipient_amount_raw: prepared.recipient_amount_raw.to_string(),
            requested_amount_raw: prepared.resolved.requested_amount_raw.to_string(),
            fee_refund_raw: prepared.fee_refund_raw.to_string(),
            total_amount_raw: prepared.total_amount_raw.to_string(),
            fee_within: prepared.resolved.fee_within,
            recipient_ata_creation_required: prepared.recipient_ata_creation_required,
            fee_payer: prepared.resolved.fee_payer_pubkey,
            sol_usd_price: prepared.sol_usd_price,
            estimated_fee_lamports: prepared.estimated_fee_lamports,
        }),
    )
        .into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_str(&www_authenticate).map_err(|_| ApiError(Error::PaymentChallenge))?,
    );
    Ok(response)
}

async fn verify_paid_send(
    state: Arc<AppState>,
    resolved: ResolvedSend,
    header: &HeaderValue,
) -> Result<Response, ApiError> {
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

    validate_paid_send_request(&charge_request, &resolved).map_err(ApiError)?;

    // Confidential settlement runs on the worker for the resolved request
    // network (shared store for that network's orphan guard + replay
    // protection); normal settlement stays on the direct per-request path.
    let receipt = if resolved.confidential {
        let handle = state
            .confidential
            .get(&resolved.network)
            .ok_or(ApiError(Error::FeePayerSigner))?;
        match handle
            .settle(
                credential,
                charge_request,
                resolved.coin.mint.to_string(),
                resolved.coin.decimals,
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                warn!(error = %error, "confidential send verification failed");
                return Err(ApiError(Error::InvalidPaymentCredential));
            }
        }
    } else {
        let signer = fee_payer_signer(&state)
            .await
            .map_err(|_| ApiError(Error::FeePayerSigner))?;
        // Thread the credential's recipient through so pay-kit's verify
        // pin holds for the `CreateRecipientAta` layout (where the
        // primary recipient is the fee-payer, not the user). The actual
        // user-target validation already ran in
        // `validate_paid_send_request` and understands both layouts.
        let mpp = new_mpp(
            &state,
            &resolved,
            Some(signer),
            charge_request.recipient.as_deref(),
        )
        .await
        .map_err(ApiError)?;
        match mpp.verify(&credential, &charge_request).await {
            Ok(receipt) => receipt,
            Err(error) => {
                warn!(
                    error = %error,
                    code = error.code.unwrap_or("unknown"),
                    retryable = error.retryable,
                    title = %error.title,
                    "send payment verification failed"
                );
                return Err(ApiError(Error::InvalidPaymentCredential));
            }
        }
    };
    // Wrap the charge receipt in ReceiptKind::Charge for the new
    // intent-tagged Payment-Receipt header shape introduced by pay-kit.
    let kind = pay_kit::mpp::ReceiptKind::Charge(receipt);
    let receipt_header =
        pay_kit::mpp::format_receipt(&kind).map_err(|_| ApiError(Error::PaymentChallenge))?;
    let receipt = match kind {
        pay_kit::mpp::ReceiptKind::Charge(r) => r,
        pay_kit::mpp::ReceiptKind::Subscription { base, .. } => base,
    };

    let mut response = (StatusCode::OK, Json(SendReceiptResponse { receipt })).into_response();
    response.headers_mut().insert(
        PAYMENT_RECEIPT_HEADER,
        HeaderValue::from_str(&receipt_header).map_err(|_| ApiError(Error::PaymentChallenge))?,
    );
    Ok(response)
}

fn resolve_send_request(state: &AppState, request: &SendRequest) -> Result<ResolvedSend, Error> {
    if !state.send.enabled {
        return Err(Error::SendNotConfigured(
            "set PAY_API_SEND__ENABLED=true and configure a fee payer".into(),
        ));
    }

    let network = match request.network.as_deref().map(str::trim) {
        Some("") | None => Network::Mainnet,
        Some(value) => value.parse::<Network>().map_err(Error::from)?,
    };
    let cluster = mpp_cluster(network);
    let rpc_url = state.rpc_url_for(network)?.to_string();

    Pubkey::from_str(request.recipient.trim()).map_err(|_| Error::InvalidAddress)?;
    let recipient = request.recipient.trim().to_string();
    let coin = resolve_stablecoin(&state.stablecoins, &request.currency)
        .ok_or_else(|| Error::UnsupportedCurrency(request.currency.clone()))?
        .clone();
    let requested_amount_raw = parse_positive_base_units(&request.amount, coin.decimals)?;
    let memo = request
        .memo
        .as_deref()
        .map(str::trim)
        .filter(|memo| !memo.is_empty())
        .map(ToOwned::to_owned);
    let fee_payer_pubkey = configured_fee_payer_pubkey(state)?;

    Ok(ResolvedSend {
        network,
        cluster,
        rpc_url,
        recipient,
        coin,
        requested_amount_raw,
        memo,
        fee_within: request.fee_within,
        fee_payer_pubkey,
        confidential: request.confidential,
    })
}

async fn ensure_confidential_transfer_supported(
    state: &AppState,
    resolved: &ResolvedSend,
) -> Result<(), Error> {
    if !resolved.confidential {
        return Ok(());
    }
    if resolved.coin.token_program != TOKEN_2022_PROGRAM_ID {
        return Err(Error::UnsupportedCurrency(format!(
            "{} is not a Token-2022 confidential-transfer mint",
            resolved.coin.symbol
        )));
    }

    let accounts = state
        .rpc
        .get_multiple_accounts(&resolved.rpc_url, &[resolved.coin.mint.to_string()])
        .await?;
    let mint_data = accounts
        .into_iter()
        .next()
        .flatten()
        .ok_or(Error::RpcMalformed)?;
    if !token_2022_mint_supports_confidential_transfer(&mint_data)? {
        return Err(Error::UnsupportedCurrency(format!(
            "{} does not support confidential transfers",
            resolved.coin.symbol
        )));
    }
    Ok(())
}

async fn prepare_challenge(
    state: &AppState,
    resolved: ResolvedSend,
) -> Result<PreparedChallenge, Error> {
    let recipient_ata_creation_required = recipient_ata_creation_required(state, &resolved).await?;
    let estimated_fee_lamports =
        estimate_send_fee_lamports(state, &resolved, recipient_ata_creation_required).await?;
    // Confidential charges are gateway-paid and ABSORB the SOL fee: it is not
    // recovered as a token refund, so there is no fee split and the recipient
    // receives exactly the requested amount. The recipient must already hold a
    // CT-configured account, so the gateway-creates-ATA layout does not apply.
    //
    // The SOL/USD price oracle is only needed for the non-confidential fee
    // refund, so fetch it lazily inside that branch — confidential sends would
    // otherwise make a (discarded) mainnet DAS `getAsset` call, which requires a
    // DAS-capable RPC.
    let (fee_refund_raw, sol_usd_price) = if resolved.confidential {
        (0, 0.0)
    } else {
        let price_rpc_url = state.rpc_url_for(Network::Mainnet)?;
        let sol_usd_price = state
            .rpc
            .get_asset_price_per_token(price_rpc_url, &state.send.sol_price_asset)
            .await?;
        let refund = fee_refund_base_units(
            estimated_fee_lamports,
            sol_usd_price,
            resolved.coin.decimals,
        )?;
        (refund, sol_usd_price)
    };
    let amounts = compute_send_amounts(
        resolved.requested_amount_raw,
        fee_refund_raw,
        resolved.fee_within,
    )?;
    let layout = if recipient_ata_creation_required && !resolved.confidential {
        SendChallengeLayout::CreateRecipientAta
    } else {
        SendChallengeLayout::ExistingRecipientAta
    };
    // Build with the same RPC pay-api will later use to co-sign and broadcast;
    // otherwise the verifier can reject a freshly signed client transaction
    // with "Blockhash not found" when the client used a different RPC backend.
    let recent_blockhash = state.rpc.get_latest_blockhash(&resolved.rpc_url).await.ok();
    let charge_request = build_charge_request(
        &resolved,
        &amounts,
        fee_refund_raw,
        layout,
        &state.send.fee_refund_split,
        recent_blockhash,
    )?;

    Ok(PreparedChallenge {
        resolved,
        sol_usd_price,
        estimated_fee_lamports,
        recipient_amount_raw: amounts.recipient_amount_raw,
        fee_refund_raw,
        total_amount_raw: amounts.total_amount_raw,
        recipient_ata_creation_required,
        charge_request,
    })
}

fn build_charge_request(
    resolved: &ResolvedSend,
    amounts: &SendAmounts,
    fee_refund_raw: u64,
    layout: SendChallengeLayout,
    fee_refund_config: &FeeRefundSplitConfig,
    recent_blockhash: Option<String>,
) -> Result<MppChargeRequest, Error> {
    // Memo placement per layout:
    //   ExistingRecipientAta: primary = user transfer  ⇒ external_id = "Transfer"
    //                         split   = fee refund     ⇒ split.memo  = "Network fee"
    //   CreateRecipientAta:   primary = fee payer + ATA rent ⇒ external_id = "Network fee (include account creation)"
    //                         split   = user transfer  ⇒ split.memo  = "Transfer"
    // The "Transfer" slot is overridden by `resolved.memo` when the
    // caller supplied one.
    let (primary_recipient, primary_memo, splits) = if resolved.confidential {
        // Confidential charges are gateway-paid and ABSORB the SOL fee: no
        // refund split (the client's validate rejects confidential+splits, and
        // the bundle is single-recipient). The recipient must already hold a
        // CT-configured account, so there is no gateway-creates-ATA layout. The
        // memo is logical only — confidential charges reconcile by signature,
        // not an on-chain marker.
        (
            resolved.recipient.clone(),
            main_transfer_memo(resolved.memo.as_deref()),
            Vec::new(),
        )
    } else {
        match layout {
            SendChallengeLayout::ExistingRecipientAta => (
                resolved.recipient.clone(),
                main_transfer_memo(resolved.memo.as_deref()),
                vec![compute_fee_refund_split(
                    fee_refund_config,
                    &resolved.fee_payer_pubkey,
                    fee_refund_raw,
                    /* ata_creation_required = */ false,
                )],
            ),
            SendChallengeLayout::CreateRecipientAta => (
                resolved.fee_payer_pubkey.clone(),
                fee_refund_memo(true).to_string(),
                vec![compute_recipient_split(
                    resolved,
                    amounts.recipient_amount_raw,
                    true,
                )],
            ),
        }
    };

    let method_details = MethodDetails {
        network: Some(resolved.cluster.to_string()),
        decimals: Some(resolved.coin.decimals),
        token_program: Some(resolved.coin.token_program.to_string()),
        fee_payer: Some(true),
        fee_payer_key: Some(resolved.fee_payer_pubkey.clone()),
        splits: Some(splits),
        recent_blockhash,
        // Confidential transfers: the client settles via a bundle. The auditor
        // is the mint issuer's compliance facility (not the gateway), and the
        // client fetches the recipient ElGamal pubkey from chain, so neither
        // optional hint is set here.
        confidential: resolved.confidential.then_some(true),
        auditor_elgamal_pubkey: None,
        recipient_elgamal_pubkey: None,
    };

    Ok(MppChargeRequest {
        amount: amounts.total_amount_raw.to_string(),
        currency: resolved.coin.mint.to_string(),
        recipient: Some(primary_recipient),
        description: Some(challenge_description(resolved, amounts, fee_refund_raw)),
        external_id: Some(primary_memo),
        method_details: Some(
            serde_json::to_value(method_details).map_err(|_| Error::PaymentChallenge)?,
        ),
        ..Default::default()
    })
}

fn challenge_description(
    resolved: &ResolvedSend,
    amounts: &SendAmounts,
    fee_refund_raw: u64,
) -> String {
    format!(
        "Send {} {} to address {} (fee: {} {})",
        format_base_units(amounts.recipient_amount_raw, resolved.coin.decimals),
        resolved.coin.symbol,
        short_address(&resolved.recipient),
        format_base_units(fee_refund_raw, resolved.coin.decimals),
        resolved.coin.symbol
    )
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

pub(super) fn format_base_units(raw: u64, decimals: u8) -> String {
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

struct SendAmounts {
    recipient_amount_raw: u64,
    total_amount_raw: u64,
}

fn compute_send_amounts(
    requested_amount_raw: u64,
    fee_refund_raw: u64,
    fee_within: bool,
) -> Result<SendAmounts, Error> {
    if fee_within {
        let recipient_amount_raw = requested_amount_raw
            .checked_sub(fee_refund_raw)
            .ok_or_else(|| {
                Error::InvalidAmount(
                    "amount must exceed the estimated fee when feeWithin is true".into(),
                )
            })?;
        if recipient_amount_raw == 0 {
            return Err(Error::InvalidAmount(
                "amount must exceed the estimated fee when feeWithin is true".into(),
            ));
        }
        return Ok(SendAmounts {
            recipient_amount_raw,
            total_amount_raw: requested_amount_raw,
        });
    }

    let total_amount_raw = requested_amount_raw
        .checked_add(fee_refund_raw)
        .ok_or_else(|| Error::InvalidAmount("recipient amount plus fee is too large".into()))?;
    Ok(SendAmounts {
        recipient_amount_raw: requested_amount_raw,
        total_amount_raw,
    })
}

async fn recipient_ata_creation_required(
    state: &AppState,
    resolved: &ResolvedSend,
) -> Result<bool, Error> {
    let recipient = Pubkey::from_str(&resolved.recipient).map_err(|_| Error::InvalidAddress)?;
    let ata = associated_token_address(
        &recipient,
        &resolved.coin.mint,
        &resolved.coin.token_program,
    );
    let accounts = state
        .rpc
        .get_multiple_accounts(&resolved.rpc_url, &[ata.to_string()])
        .await?;
    Ok(accounts.first().is_none_or(Option::is_none))
}

async fn estimate_send_fee_lamports(
    state: &AppState,
    resolved: &ResolvedSend,
    recipient_ata_creation_required: bool,
) -> Result<u64, Error> {
    let mut estimated_fee_lamports = state.send.estimated_fee_lamports;
    if recipient_ata_creation_required {
        let account_len = recipient_token_account_len(state, resolved).await?;
        let ata_rent_lamports = state
            .rpc
            .get_minimum_balance_for_rent_exemption(&resolved.rpc_url, account_len)
            .await?;
        estimated_fee_lamports =
            add_ata_rent_to_estimated_fee(estimated_fee_lamports, ata_rent_lamports)?;
    }
    Ok(estimated_fee_lamports)
}

fn add_ata_rent_to_estimated_fee(
    estimated_fee_lamports: u64,
    ata_rent_lamports: u64,
) -> Result<u64, Error> {
    estimated_fee_lamports
        .checked_add(ata_rent_lamports)
        .ok_or_else(|| Error::InvalidAmount("estimated fee plus ATA rent is too large".into()))
}

async fn recipient_token_account_len(
    state: &AppState,
    resolved: &ResolvedSend,
) -> Result<usize, Error> {
    if resolved.coin.token_program == SPL_TOKEN_PROGRAM_ID {
        return Ok(SPL_TOKEN_ACCOUNT_LEN);
    }

    if resolved.coin.token_program == TOKEN_2022_PROGRAM_ID {
        let accounts = state
            .rpc
            .get_multiple_accounts(&resolved.rpc_url, &[resolved.coin.mint.to_string()])
            .await?;
        let mint_data = accounts
            .into_iter()
            .next()
            .flatten()
            .ok_or(Error::RpcMalformed)?;
        return token_2022_account_len(&mint_data);
    }

    Err(Error::UnsupportedCurrency(resolved.coin.symbol.clone()))
}

fn token_2022_account_len(mint_data: &[u8]) -> Result<usize, Error> {
    let mint =
        StateWithExtensions::<Token2022Mint>::unpack(mint_data).map_err(|_| Error::RpcMalformed)?;
    let mut required_extensions = ExtensionType::get_required_init_account_extensions(
        &mint
            .get_extension_types()
            .map_err(|_| Error::RpcMalformed)?,
    );
    if !required_extensions.contains(&ExtensionType::ImmutableOwner) {
        required_extensions.push(ExtensionType::ImmutableOwner);
    }
    ExtensionType::try_calculate_account_len::<Token2022Account>(&required_extensions)
        .map_err(|_| Error::RpcMalformed)
}

fn token_2022_mint_supports_confidential_transfer(mint_data: &[u8]) -> Result<bool, Error> {
    let mint =
        StateWithExtensions::<Token2022Mint>::unpack(mint_data).map_err(|_| Error::RpcMalformed)?;
    Ok(mint
        .get_extension_types()
        .map_err(|_| Error::RpcMalformed)?
        .contains(&ExtensionType::ConfidentialTransferMint))
}

fn compute_fee_refund_split(
    config: &FeeRefundSplitConfig,
    fee_payer_pubkey: &str,
    fee_refund_raw: u64,
    ata_creation_required: bool,
) -> Split {
    // `label` stays config-driven (it's UI metadata, not on-chain), but
    // `memo` is always the canonical "Network fee" string so the receipt
    // page can render a consistent label across providers.
    Split {
        recipient: fee_payer_pubkey.to_string(),
        amount: fee_refund_raw.to_string(),
        ata_creation_required: None,
        label: non_empty(config.label.trim()),
        memo: Some(fee_refund_memo(ata_creation_required).to_string()),
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

fn compute_recipient_split(
    resolved: &ResolvedSend,
    recipient_amount_raw: u64,
    ata_creation_required: bool,
) -> Split {
    Split {
        recipient: resolved.recipient.clone(),
        amount: recipient_amount_raw.to_string(),
        ata_creation_required: ata_creation_required.then_some(true),
        label: None,
        memo: Some(main_transfer_memo(resolved.memo.as_deref())),
    }
}

fn validate_paid_send_request(
    charge_request: &MppChargeRequest,
    resolved: &ResolvedSend,
) -> Result<(), Error> {
    if charge_request.currency != resolved.coin.mint.to_string() {
        return Err(Error::InvalidPaymentCredential);
    }

    let method_details: MethodDetails = charge_request
        .method_details
        .as_ref()
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        .map_err(|_| Error::InvalidPaymentCredential)?
        .ok_or(Error::InvalidPaymentCredential)?;

    if method_details.network.as_deref() != Some(resolved.cluster)
        || method_details.decimals != Some(resolved.coin.decimals)
        || method_details.token_program.as_deref() != Some(&resolved.coin.token_program.to_string())
        || method_details.fee_payer != Some(true)
        || method_details.fee_payer_key.as_deref() != Some(resolved.fee_payer_pubkey.as_str())
    {
        return Err(Error::InvalidPaymentCredential);
    }

    if (method_details.confidential == Some(true)) != resolved.confidential {
        return Err(Error::InvalidPaymentCredential);
    }

    // Confidential charges are gateway-paid, absorb the SOL fee, and carry no
    // splits: the recipient is the primary and receives exactly the requested
    // amount. Reconciliation is by signature, so the memo is logical only.
    if method_details.confidential == Some(true) {
        if method_details
            .splits
            .as_deref()
            .is_some_and(|s| !s.is_empty())
        {
            return Err(Error::InvalidPaymentCredential);
        }
        if charge_request.recipient.as_deref() != Some(resolved.recipient.as_str()) {
            return Err(Error::InvalidPaymentCredential);
        }
        let expected_main = main_transfer_memo(resolved.memo.as_deref());
        if charge_request.external_id.as_deref() != Some(expected_main.as_str()) {
            return Err(Error::InvalidPaymentCredential);
        }
        let total_amount_raw = charge_request
            .amount
            .parse::<u64>()
            .map_err(|_| Error::InvalidPaymentCredential)?;
        if total_amount_raw != resolved.requested_amount_raw {
            return Err(Error::InvalidPaymentCredential);
        }
        return Ok(());
    }

    let splits = method_details
        .splits
        .as_deref()
        .ok_or(Error::InvalidPaymentCredential)?;
    if splits.len() != 1 {
        return Err(Error::InvalidPaymentCredential);
    }
    let split = &splits[0];
    let total_amount_raw = charge_request
        .amount
        .parse::<u64>()
        .map_err(|_| Error::InvalidPaymentCredential)?;

    match charge_request.recipient.as_deref() {
        Some(primary) if primary == resolved.recipient => {
            // Layout 1 — existing recipient ATA. Primary = user transfer,
            // split = fee-payer refund. Expected memos:
            //   external_id = main_transfer_memo (user-supplied OR "Transfer")
            //   split.memo  = "Network fee"
            let expected_main = main_transfer_memo(resolved.memo.as_deref());
            if charge_request.external_id.as_deref() != Some(expected_main.as_str()) {
                return Err(Error::InvalidPaymentCredential);
            }
            if split.recipient != resolved.fee_payer_pubkey
                || split.memo.as_deref() != Some(fee_refund_memo(false))
            {
                return Err(Error::InvalidPaymentCredential);
            }
            let fee_refund_raw = split
                .amount
                .parse::<u64>()
                .map_err(|_| Error::InvalidPaymentCredential)?;
            if fee_refund_raw == 0 {
                return Err(Error::InvalidPaymentCredential);
            }
            let recipient_amount_raw = total_amount_raw
                .checked_sub(fee_refund_raw)
                .ok_or(Error::InvalidPaymentCredential)?;
            validate_send_amounts(total_amount_raw, recipient_amount_raw, resolved)?;
        }
        Some(primary) if primary == resolved.fee_payer_pubkey => {
            // Layout 2 — fee-payer creates recipient ATA. Primary =
            // fee-payer transfer (refund + ATA rent), split = user
            // transfer. Expected memos:
            //   external_id = "Network fee (include account creation)"
            //   split.memo  = main_transfer_memo (user-supplied OR "Transfer")
            if charge_request.external_id.as_deref() != Some(fee_refund_memo(true)) {
                return Err(Error::InvalidPaymentCredential);
            }
            let expected_main = main_transfer_memo(resolved.memo.as_deref());
            if split.recipient != resolved.recipient
                || split.memo.as_deref() != Some(expected_main.as_str())
            {
                return Err(Error::InvalidPaymentCredential);
            }
            let recipient_amount_raw = split
                .amount
                .parse::<u64>()
                .map_err(|_| Error::InvalidPaymentCredential)?;
            if recipient_amount_raw == 0 {
                return Err(Error::InvalidPaymentCredential);
            }
            validate_send_amounts(total_amount_raw, recipient_amount_raw, resolved)?;
        }
        _ => {
            return Err(Error::InvalidPaymentCredential);
        }
    }

    Ok(())
}

fn validate_send_amounts(
    total_amount_raw: u64,
    recipient_amount_raw: u64,
    resolved: &ResolvedSend,
) -> Result<(), Error> {
    let fee_refund_raw = total_amount_raw
        .checked_sub(recipient_amount_raw)
        .ok_or(Error::InvalidPaymentCredential)?;
    if fee_refund_raw == 0 {
        return Err(Error::InvalidPaymentCredential);
    }

    if resolved.fee_within {
        if total_amount_raw != resolved.requested_amount_raw
            || recipient_amount_raw >= resolved.requested_amount_raw
        {
            return Err(Error::InvalidPaymentCredential);
        }
    } else if recipient_amount_raw != resolved.requested_amount_raw
        || total_amount_raw <= resolved.requested_amount_raw
    {
        return Err(Error::InvalidPaymentCredential);
    }
    Ok(())
}

async fn new_mpp(
    state: &AppState,
    resolved: &ResolvedSend,
    fee_payer_signer: Option<Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>>,
    recipient_override: Option<&str>,
) -> Result<Mpp, Error> {
    // `MppConfig.recipient` is what pay-kit's verify pins
    // `credential.request.recipient` against. The two valid send
    // layouts emit different primary recipients:
    //   - `ExistingRecipientAta` → primary = the user's target wallet
    //   - `CreateRecipientAta`   → primary = the gateway fee-payer
    //     (who pays ATA rent, then splits the remainder to the user)
    // The verify path passes the decoded credential's recipient
    // through so pay-kit's pin trivially holds for both layouts; the
    // emission path passes None and gets `resolved.recipient`, which
    // pay-kit ignores at emission time (it just hashes the encoded
    // request blob).
    let has_fee_payer_signer = fee_payer_signer.is_some();
    Mpp::new(MppConfig {
        recipient: recipient_override
            .map(str::to_string)
            .unwrap_or_else(|| resolved.recipient.clone()),
        currency: resolved.coin.mint.to_string(),
        decimals: resolved.coin.decimals,
        network: resolved.cluster.to_string(),
        rpc_url: Some(resolved.rpc_url.clone()),
        challenge_binding_secret: state.send.mpp_challenge_binding_secret.clone(),
        realm: Some(state.send.realm.clone()),
        fee_payer: has_fee_payer_signer,
        fee_payer_signer,
        html: false,
        ..Default::default()
    })
    .map_err(|e| {
        tracing::error!(error = ?e, "Mpp::new failed");
        Error::PaymentChallenge
    })
}

async fn fee_payer_signer(
    state: &AppState,
) -> Result<Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>, Error> {
    crate::signer::build_fee_payer_signer(
        &state.send.fee_payer,
        "send.fee_payer.key_name is missing",
        "send.fee_payer.pubkey is missing",
    )
    .await
}

fn configured_fee_payer_pubkey(state: &AppState) -> Result<String, Error> {
    let pubkey = state
        .send
        .fee_payer
        .pubkey
        .as_deref()
        .ok_or_else(|| Error::SendNotConfigured("send.fee_payer.pubkey is missing".into()))?
        .trim();
    Pubkey::from_str(pubkey)
        .map_err(|_| Error::SendNotConfigured("invalid fee payer pubkey".into()))?;
    Ok(pubkey.to_string())
}

fn resolve_stablecoin<'a>(coins: &'a [Stablecoin], currency: &str) -> Option<&'a Stablecoin> {
    let currency = currency.trim();
    coins.iter().find(|coin| {
        coin.symbol.eq_ignore_ascii_case(currency) || coin.mint.to_string() == currency
    })
}

fn parse_positive_base_units(amount: &str, decimals: u8) -> Result<u64, Error> {
    let raw = pay_kit::mpp::parse_units(amount.trim(), decimals)
        .map_err(|_| Error::InvalidAmount(amount.to_string()))?;
    let parsed = raw
        .parse::<u64>()
        .map_err(|_| Error::InvalidAmount(amount.to_string()))?;
    if parsed == 0 {
        return Err(Error::InvalidAmount(amount.to_string()));
    }
    Ok(parsed)
}

fn fee_refund_base_units(
    estimated_fee_lamports: u64,
    sol_usd_price: f64,
    stablecoin_decimals: u8,
) -> Result<u64, Error> {
    if !sol_usd_price.is_finite() || sol_usd_price <= 0.0 {
        return Err(Error::PriceUnavailable);
    }
    let scale = 10f64.powi(stablecoin_decimals as i32);
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

pub struct ApiError(Error);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        if status.is_server_error() {
            warn!(error = %self.0, "send request failed");
        }
        let body = Json(json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spl_token_2022_interface::extension::{
        BaseStateWithExtensionsMut, StateWithExtensionsMut,
        confidential_transfer::ConfidentialTransferMint,
    };

    fn test_coin() -> Stablecoin {
        Stablecoin {
            symbol: "USDC".to_string(),
            mint: Pubkey::from_str("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap(),
            token_program: Pubkey::from_str("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA").unwrap(),
            decimals: 6,
        }
    }

    fn resolved_send() -> ResolvedSend {
        ResolvedSend {
            network: Network::Mainnet,
            cluster: "mainnet",
            rpc_url: "https://mainnet.helius-rpc.com/?api-key=test".to_string(),
            recipient: Pubkey::new_unique().to_string(),
            coin: test_coin(),
            requested_amount_raw: 1_000_000,
            memo: None,
            fee_within: false,
            fee_payer_pubkey: Pubkey::new_unique().to_string(),
            confidential: false,
        }
    }

    #[test]
    fn fee_refund_base_units_ceil_converts_sol_fee_to_stablecoin_units() {
        assert_eq!(fee_refund_base_units(10_000, 150.0, 6).unwrap(), 1500);
        assert_eq!(fee_refund_base_units(1, 0.01, 6).unwrap(), 1);
    }

    #[test]
    fn parse_positive_base_units_requires_positive_human_amount() {
        assert_eq!(parse_positive_base_units("1.25", 6).unwrap(), 1_250_000);
        assert!(parse_positive_base_units("0", 6).is_err());
        assert!(parse_positive_base_units("-1", 6).is_err());
        assert!(parse_positive_base_units("1.0000001", 6).is_err());
    }

    #[test]
    fn compute_send_amounts_puts_fee_on_top_by_default() {
        let amounts = compute_send_amounts(1_000_000, 1_500, false).unwrap();
        assert_eq!(amounts.recipient_amount_raw, 1_000_000);
        assert_eq!(amounts.total_amount_raw, 1_001_500);
    }

    #[test]
    fn compute_send_amounts_can_take_fee_within_amount() {
        let amounts = compute_send_amounts(1_000_000, 1_500, true).unwrap();
        assert_eq!(amounts.recipient_amount_raw, 998_500);
        assert_eq!(amounts.total_amount_raw, 1_000_000);
    }

    #[test]
    fn compute_send_amounts_rejects_fee_within_when_fee_consumes_amount() {
        assert!(compute_send_amounts(1_500, 1_500, true).is_err());
        assert!(compute_send_amounts(1_000, 1_500, true).is_err());
    }

    #[test]
    fn add_ata_rent_to_estimated_fee_includes_fee_payer_outflow() {
        assert_eq!(
            add_ata_rent_to_estimated_fee(10_000, 2_039_280).unwrap(),
            2_049_280
        );
        assert!(add_ata_rent_to_estimated_fee(u64::MAX, 1).is_err());
    }

    #[test]
    fn challenge_description_includes_send_amount_recipient_and_fee() {
        let resolved = resolved_send();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, true).unwrap();

        assert_eq!(
            challenge_description(&resolved, &amounts, 1_500),
            format!(
                "Send 0.9985 USDC to address {} (fee: 0.0015 USDC)",
                short_address(&resolved.recipient)
            )
        );
    }

    #[test]
    fn short_address_keeps_edges() {
        assert_eq!(
            short_address("96WoyH3JmANSMsQLGC3MKyiGiXCymZyM9SLaWjcRrKuD"),
            "96Wo...rKuD"
        );
        assert_eq!(short_address("12345678"), "12345678");
    }

    #[test]
    fn mpp_cluster_uses_canonical_wire_slugs() {
        assert_eq!(mpp_cluster(Network::Mainnet), "mainnet");
        assert_eq!(mpp_cluster(Network::Sandbox), "localnet");
    }

    #[test]
    fn build_charge_request_keeps_existing_recipient_ata_format() {
        let resolved = resolved_send();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            Some("BlockhashXyz".to_string()),
        )
        .unwrap();
        assert_eq!(request.amount, "1001500");
        assert_eq!(request.currency, resolved.coin.mint.to_string());
        assert_eq!(
            request.recipient.as_deref(),
            Some(resolved.recipient.as_str())
        );
        let expected_description = format!(
            "Send 1 USDC to address {} (fee: 0.0015 USDC)",
            short_address(&resolved.recipient)
        );
        assert_eq!(
            request.description.as_deref(),
            Some(expected_description.as_str())
        );
        // With no user-supplied memo, the main transfer carries the
        // canonical "Transfer" memo; the fee-payer refund carries "Network
        // fee" (no ATA creation in this layout).
        assert_eq!(request.external_id.as_deref(), Some(MAIN_TRANSFER_MEMO));

        let details: MethodDetails =
            serde_json::from_value(request.method_details.clone().unwrap()).unwrap();
        let splits = details.splits.unwrap();
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].recipient, resolved.fee_payer_pubkey);
        assert_eq!(splits[0].amount, "1500");
        assert_eq!(splits[0].label.as_deref(), Some("Fee payer refund"));
        assert_eq!(splits[0].memo.as_deref(), Some(NETWORK_FEE_MEMO));
        assert_eq!(details.fee_payer, Some(true));
        assert_eq!(details.fee_payer_key, Some(resolved.fee_payer_pubkey));
        assert_eq!(details.recent_blockhash.as_deref(), Some("BlockhashXyz"));
    }

    #[test]
    fn build_charge_request_uses_external_id_for_existing_recipient_ata_memo() {
        let mut resolved = resolved_send();
        resolved.memo = Some("invoice-123".to_string());
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        assert_eq!(
            request.recipient.as_deref(),
            Some(resolved.recipient.as_str())
        );
        // User-supplied memo overrides the canonical "Transfer" on the
        // main transfer slot.
        assert_eq!(request.external_id.as_deref(), Some("invoice-123"));

        let details: MethodDetails =
            serde_json::from_value(request.method_details.clone().unwrap()).unwrap();
        let splits = details.splits.unwrap();
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].recipient, resolved.fee_payer_pubkey);
        assert_eq!(splits[0].memo.as_deref(), Some(NETWORK_FEE_MEMO));
    }

    #[test]
    fn build_charge_request_uses_recipient_split_when_ata_creation_is_required() {
        let mut resolved = resolved_send();
        resolved.memo = Some("invoice-123".to_string());
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::CreateRecipientAta,
            &FeeRefundSplitConfig::default(),
            Some("BlockhashXyz".to_string()),
        )
        .unwrap();
        assert_eq!(request.amount, "1001500");
        assert_eq!(
            request.recipient.as_deref(),
            Some(resolved.fee_payer_pubkey.as_str())
        );

        let details: MethodDetails =
            serde_json::from_value(request.method_details.clone().unwrap()).unwrap();
        let splits = details.splits.unwrap();
        assert_eq!(splits.len(), 1);
        assert_eq!(splits[0].recipient, resolved.recipient);
        assert_eq!(splits[0].amount, "1000000");
        assert_eq!(splits[0].ata_creation_required, Some(true));
        // User-supplied memo overrides "Transfer" on the user's split.
        assert_eq!(splits[0].memo.as_deref(), Some("invoice-123"));
        // Primary recipient (fee payer) carries the ATA-variant fee memo.
        assert_eq!(
            request.external_id.as_deref(),
            Some(NETWORK_FEE_WITH_ATA_MEMO)
        );
        assert_eq!(details.recent_blockhash.as_deref(), Some("BlockhashXyz"));
    }

    #[test]
    fn validate_paid_send_request_accepts_existing_ata_fee_on_top_request() {
        let resolved = resolved_send();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        validate_paid_send_request(&request, &resolved).unwrap();
    }

    #[test]
    fn validate_paid_send_request_requires_external_id_for_existing_ata_memo() {
        let mut resolved = resolved_send();
        resolved.memo = Some("invoice-123".to_string());
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let mut request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        validate_paid_send_request(&request, &resolved).unwrap();

        request.external_id = None;
        assert!(validate_paid_send_request(&request, &resolved).is_err());
    }

    #[test]
    fn validate_paid_send_request_accepts_new_ata_fee_on_top_request() {
        let resolved = resolved_send();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::CreateRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        validate_paid_send_request(&request, &resolved).unwrap();
    }

    #[test]
    fn validate_paid_send_request_accepts_fee_within_request() {
        let mut resolved = resolved_send();
        resolved.fee_within = true;
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, true).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        validate_paid_send_request(&request, &resolved).unwrap();
    }

    #[test]
    fn validate_paid_send_request_rejects_missing_split() {
        let resolved = resolved_send();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 1_500, false).unwrap();
        let mut request = build_charge_request(
            &resolved,
            &amounts,
            1_500,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();
        request.method_details = Some(
            serde_json::to_value(MethodDetails {
                network: Some("mainnet".to_string()),
                decimals: Some(6),
                token_program: Some(resolved.coin.token_program.to_string()),
                fee_payer: Some(true),
                fee_payer_key: Some(resolved.fee_payer_pubkey.clone()),
                splits: None,
                recent_blockhash: None,
                confidential: None,
                auditor_elgamal_pubkey: None,
                recipient_elgamal_pubkey: None,
            })
            .unwrap(),
        );

        assert!(validate_paid_send_request(&request, &resolved).is_err());
    }

    #[test]
    fn compute_fee_refund_split_uses_computed_amount() {
        let fee_payer = Pubkey::new_unique().to_string();
        let split =
            compute_fee_refund_split(&FeeRefundSplitConfig::default(), &fee_payer, 1_234, false);

        assert_eq!(split.recipient, fee_payer);
        assert_eq!(split.amount, "1234");
        assert_eq!(split.ata_creation_required, None);
        assert_eq!(split.memo.as_deref(), Some(NETWORK_FEE_MEMO));
    }

    #[test]
    fn compute_fee_refund_split_stamps_ata_variant_memo_when_ata_required() {
        let fee_payer = Pubkey::new_unique().to_string();
        let split =
            compute_fee_refund_split(&FeeRefundSplitConfig::default(), &fee_payer, 1_234, true);

        assert_eq!(split.memo.as_deref(), Some(NETWORK_FEE_WITH_ATA_MEMO));
    }

    #[test]
    fn main_transfer_memo_uses_user_override_when_supplied() {
        assert_eq!(main_transfer_memo(None), MAIN_TRANSFER_MEMO);
        assert_eq!(main_transfer_memo(Some("")), MAIN_TRANSFER_MEMO);
        assert_eq!(main_transfer_memo(Some("   ")), MAIN_TRANSFER_MEMO);
        assert_eq!(main_transfer_memo(Some("invoice-42")), "invoice-42");
    }

    // ── Confidential charges: gateway-paid, absorb the fee, no splits ──

    fn confidential_resolved() -> ResolvedSend {
        let mut r = resolved_send();
        r.confidential = true;
        r.coin.token_program = TOKEN_2022_PROGRAM_ID;
        r
    }

    fn token_2022_mint_data(extension_types: &[ExtensionType]) -> Vec<u8> {
        let mint_len =
            ExtensionType::try_calculate_account_len::<Token2022Mint>(extension_types).unwrap();
        let mut data = vec![0u8; mint_len];
        let mut mint = StateWithExtensionsMut::<Token2022Mint>::unpack_uninitialized(&mut data)
            .expect("mint data unpacks");
        for extension_type in extension_types {
            if *extension_type == ExtensionType::ConfidentialTransferMint {
                mint.init_extension::<ConfidentialTransferMint>(true)
                    .expect("confidential extension initializes");
            }
        }
        mint.base = Token2022Mint {
            is_initialized: true,
            decimals: 6,
            ..Token2022Mint::default()
        };
        mint.pack_base();
        mint.init_account_type().expect("account type initializes");
        data
    }

    #[test]
    fn token_2022_mint_supports_confidential_transfer_extension() {
        let data = token_2022_mint_data(&[ExtensionType::ConfidentialTransferMint]);
        assert!(token_2022_mint_supports_confidential_transfer(&data).unwrap());
    }

    #[test]
    fn token_2022_mint_without_confidential_extension_is_rejected() {
        let data = token_2022_mint_data(&[]);
        assert!(!token_2022_mint_supports_confidential_transfer(&data).unwrap());
    }

    #[test]
    fn build_charge_request_confidential_has_no_splits_and_real_recipient() {
        let resolved = confidential_resolved();
        // Absorb model: fee_refund_raw = 0 ⇒ total == requested.
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 0, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            0,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        assert_eq!(request.amount, resolved.requested_amount_raw.to_string());
        assert_eq!(
            request.recipient.as_deref(),
            Some(resolved.recipient.as_str())
        );
        let md: MethodDetails =
            serde_json::from_value(request.method_details.clone().unwrap()).unwrap();
        assert_eq!(md.confidential, Some(true));
        assert_eq!(md.fee_payer, Some(true));
        assert_eq!(
            md.fee_payer_key.as_deref(),
            Some(resolved.fee_payer_pubkey.as_str())
        );
        assert!(
            md.splits.as_deref().is_none_or(|s| s.is_empty()),
            "confidential charge must carry no splits"
        );
    }

    #[test]
    fn validate_paid_send_request_accepts_confidential() {
        let resolved = confidential_resolved();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 0, false).unwrap();
        let request = build_charge_request(
            &resolved,
            &amounts,
            0,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();
        validate_paid_send_request(&request, &resolved).expect("confidential charge validates");
    }

    #[test]
    fn validate_paid_send_request_rejects_confidential_mode_mismatch() {
        let confidential = confidential_resolved();
        let amounts = compute_send_amounts(confidential.requested_amount_raw, 0, false).unwrap();
        let request = build_charge_request(
            &confidential,
            &amounts,
            0,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();

        let mut plain = confidential;
        plain.confidential = false;
        assert!(validate_paid_send_request(&request, &plain).is_err());
    }

    #[test]
    fn validate_paid_send_request_rejects_confidential_with_splits() {
        let resolved = confidential_resolved();
        let amounts = compute_send_amounts(resolved.requested_amount_raw, 0, false).unwrap();
        let mut request = build_charge_request(
            &resolved,
            &amounts,
            0,
            SendChallengeLayout::ExistingRecipientAta,
            &FeeRefundSplitConfig::default(),
            None,
        )
        .unwrap();
        // Tamper: smuggle a split into the confidential challenge — must reject.
        let mut md: MethodDetails =
            serde_json::from_value(request.method_details.clone().unwrap()).unwrap();
        md.splits = Some(vec![Split {
            recipient: resolved.fee_payer_pubkey.clone(),
            amount: "1".to_string(),
            ata_creation_required: None,
            label: None,
            memo: None,
        }]);
        request.method_details = Some(serde_json::to_value(&md).unwrap());
        assert!(validate_paid_send_request(&request, &resolved).is_err());
    }
}
