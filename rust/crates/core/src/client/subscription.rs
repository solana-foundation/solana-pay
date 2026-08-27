//! Client-side support for the MPP `subscription` intent.
//!
//! Mirrors [`crate::client::mpp`] but specialised to `intent="subscription"`:
//! parses the 402 challenge, builds the activation transaction via
//! `pay_kit::mpp::client::build_subscription_activation_transaction`, formats
//! the `Authorization: Payment` header, and persists the resulting
//! `Subscription` into `~/.config/pay/accounts.yml` when activation settles.
//!
//! Renewals are server-driven on-chain transactions and do not pass through
//! this module — only activation produces an HTTP credential.
//!
//! See `docs/subscriptions.md` and
//! `mpp-specs/specs/methods/solana/draft-solana-subscription-00.md` for the
//! authoritative wire shapes.

use pay_kit::mpp::client::{
    BuildSubscriptionActivationOptions, SubscriptionMethodDetails,
    build_subscription_activation_transaction_with_options,
};
use pay_kit::mpp::format_authorization;
use pay_kit::mpp::protocol::core::PaymentCredential;
use pay_kit::mpp::protocol::intents::{
    SubscriptionPeriodUnit, SubscriptionReceiptExtensions, SubscriptionRequest,
};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
use tracing::{info, warn};

use crate::accounts::{
    AccountChoice, AccountsStore, ResolvedEphemeral, Subscription, SubscriptionStatus,
    resolve_account_for_network,
};
use crate::client::mpp::Challenge;
use crate::keystore::SubscriptionAuthorization;
use crate::{Error, Result};

/// Parsed subscription challenge, useful for both the dispatcher (deciding
/// whether to surface the prompt) and the actual sign-and-retry path.
#[derive(Debug, Clone)]
pub struct DecodedSubscriptionChallenge {
    pub request: SubscriptionRequest,
    pub method_details: SubscriptionMethodDetails,
    pub network: String,
    pub period_unit: SubscriptionPeriodUnit,
    pub period_count: u64,
    /// Amount in mint base units, mirroring the spec wire form.
    pub amount_base_units: String,
    /// Decimal precision of the mint as advertised by the server.
    pub decimals: u8,
    /// Symbolic currency (e.g. "USDC") when resolvable from the mint;
    /// otherwise the raw mint b58.
    pub currency_label: String,
}

/// Outcome returned from [`build_credential`] — the formatted `Authorization`
/// header plus the context needed to persist a [`Subscription`] once the
/// activation settles.
pub struct BuiltCredential {
    /// `Authorization: Payment <base64url(credential)>` ready to set on the
    /// retry request.
    pub authorization: String,
    /// Decoded challenge state. Caller threads this back into
    /// [`persist_from_receipt`] after observing a `Payment-Receipt`.
    pub decoded: DecodedSubscriptionChallenge,
    /// Subscriber pubkey (b58) bound into the activation transaction.
    pub subscriber: String,
    /// Account name within the resolved network the activation signed under.
    pub account_name: String,
    /// Network slug used for both signing and persistence.
    pub network: String,
    /// Notice for the caller when a fresh ephemeral wallet was generated.
    pub ephemeral_notice: Option<ResolvedEphemeral>,
    /// Resource URL the activation was issued against, mirrored into the
    /// stored subscription so `pay subscriptions list` can surface it.
    pub resource_url: Option<String>,
    /// Human-readable description echoed from the challenge.
    pub description: Option<String>,
    /// `Authorization: Payment …` header signed against the bundled
    /// `authenticate` challenge (when present in the 402). Populated by
    /// [`build_credential`] when called with an authenticate challenge so
    /// the post-activation persistence step caches it for re-use.
    pub authenticate_token: Option<String>,
    /// Server-set RFC 3339 expiration of [`Self::authenticate_token`].
    pub authenticate_expires_at: Option<String>,
}

/// Try to extract a `subscription`-intent challenge from a `WWW-Authenticate`
/// header value. Returns `None` for non-subscription challenges so callers
/// can fall through to `mpp::parse` for charge.
pub fn parse(header_value: &str) -> Option<Challenge> {
    let challenge = crate::client::mpp::parse(header_value)?;
    if is_subscription_challenge(&challenge) {
        Some(challenge)
    } else {
        None
    }
}

/// Extract every subscription challenge from a lowercase header list. Mirrors
/// [`crate::client::mpp::parse_headers`] so the dispatch loop can ask each
/// intent module in turn.
pub fn parse_headers(headers: &[(String, String)]) -> Vec<Challenge> {
    crate::client::mpp::parse_headers(headers)
        .into_iter()
        .filter(is_subscription_challenge)
        .collect()
}

/// Returns true when a `PaymentChallenge` carries `intent="subscription"` and
/// `method="solana"`. Both are required by the spec, and the local CLI only
/// implements the Solana method profile.
pub fn is_subscription_challenge(challenge: &Challenge) -> bool {
    challenge.intent.as_str() == "subscription" && challenge.method.as_str() == "solana"
}

/// Decode a subscription challenge into a strongly-typed `DecodedSubscriptionChallenge`.
///
/// Performs all the validation that doesn't need a signer or RPC (the
/// challenge JSON, `methodDetails`, mapped period bounds) so the caller can
/// surface clear errors before prompting Touch ID.
pub fn decode(challenge: &Challenge) -> Result<DecodedSubscriptionChallenge> {
    ensure_challenge_active(challenge)?;

    let request: SubscriptionRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Mpp(format!("Failed to decode subscription request: {e}")))?;

    let method_details_value = request
        .method_details
        .clone()
        .ok_or_else(|| Error::Mpp("Subscription challenge is missing methodDetails".into()))?;
    let method_details = SubscriptionMethodDetails::from_json(&method_details_value)
        .map_err(|e| Error::Mpp(format!("Invalid subscription methodDetails: {e}")))?;
    method_details
        .validate()
        .map_err(|e| Error::Mpp(format!("Invalid subscription methodDetails: {e}")))?;

    let period_count = request
        .parse_period_count()
        .map_err(|e| Error::Mpp(e.to_string()))?;
    let period_hours = request
        .period_hours()
        .map_err(|e| Error::Mpp(e.to_string()))?;
    validate_authorized_terms(&request, &method_details, period_hours)?;

    let network = method_details_value
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("mainnet")
        .to_string();

    let decimals = method_details.decimals.unwrap_or(6);

    // The challenge stores the mint b58 in `currency`. For display we prefer
    // a known stablecoin symbol; otherwise fall back to a short prefix of the
    // mint so list/status rows stay readable.
    let currency_label = pay_types::Stablecoin::from_mint(&request.currency)
        .map(|c| c.symbol().to_string())
        .unwrap_or_else(|| {
            if request.currency.len() > 8 {
                format!("{}…", &request.currency[..8])
            } else {
                request.currency.clone()
            }
        });

    Ok(DecodedSubscriptionChallenge {
        amount_base_units: request.amount.clone(),
        period_unit: request.period_unit,
        period_count,
        request,
        method_details,
        network: normalize_network(&network).to_string(),
        decimals,
        currency_label,
    })
}

/// Ensure the terms shown to the user are the same terms the PayKit builder
/// will place in the activation transaction. PayKit consumes several values
/// from `methodDetails`, while the prompt historically consumed the parent
/// request; accepting a mismatch would authorize one action and sign another.
fn validate_authorized_terms(
    request: &SubscriptionRequest,
    details: &SubscriptionMethodDetails,
    period_hours: u64,
) -> Result<()> {
    if request.currency != details.mint {
        return Err(Error::Mpp(
            "Subscription request currency does not match methodDetails.mint".into(),
        ));
    }

    match details.amount.as_deref() {
        Some(amount) if amount == request.amount => {}
        Some(_) => {
            return Err(Error::Mpp(
                "Subscription request amount does not match methodDetails.amount".into(),
            ));
        }
        None => {
            return Err(Error::Mpp(
                "Subscription challenge missing methodDetails.amount".into(),
            ));
        }
    }

    // `decimals` never reaches the chain — it only scales the amount rendered
    // in the Touch ID / polkit prompt, in the payment-limit tier, and in the
    // remote gate's approval description. A server that overstates it makes a
    // 10 USDC/period pull read as "$0.01", so pin it to the mint whenever the
    // mint is one we know the true precision for.
    if let Some(expected) = pay_types::Stablecoin::decimals_for_mint(&details.mint)
        && details.decimals.unwrap_or(expected) != expected
    {
        return Err(Error::Mpp(
            "Subscription methodDetails.decimals does not match the mint's precision".into(),
        ));
    }

    let transaction_recipient = details.recipient.as_deref().unwrap_or(&details.puller);
    if request.recipient != transaction_recipient {
        return Err(Error::Mpp(
            "Subscription request recipient does not match methodDetails recipient".into(),
        ));
    }

    match details.expected_period_hours {
        Some(hours) if hours == period_hours => {}
        Some(_) => {
            return Err(Error::Mpp(
                "Subscription request cadence does not match methodDetails.expectedPeriodHours"
                    .into(),
            ));
        }
        None => {
            return Err(Error::Mpp(
                "Subscription challenge missing methodDetails.expectedPeriodHours".into(),
            ));
        }
    }

    if details.plan_id_numeric.is_none() {
        return Err(Error::Mpp(
            "Subscription challenge missing methodDetails.planIdNumeric".into(),
        ));
    }
    if details.plan_bump.is_none() {
        return Err(Error::Mpp(
            "Subscription challenge missing methodDetails.planBump".into(),
        ));
    }
    if details.expected_created_at.is_none() {
        return Err(Error::Mpp(
            "Subscription challenge missing methodDetails.expectedCreatedAt".into(),
        ));
    }

    Ok(())
}

fn subscription_authorization(
    challenge: &Challenge,
    decoded: &DecodedSubscriptionChallenge,
) -> SubscriptionAuthorization {
    let details = &decoded.method_details;
    SubscriptionAuthorization {
        version: 1,
        challenge_id: challenge.id.clone(),
        challenge_realm: challenge.realm.clone(),
        challenge_expires: challenge.expires.clone(),
        challenge_digest: challenge.digest.clone(),
        network: decoded.network.clone(),
        plan_id: details.plan_id.clone(),
        plan_id_numeric: details.plan_id_numeric,
        plan_bump: details.plan_bump,
        plan_created_at: details.expected_created_at,
        recipient: details
            .recipient
            .clone()
            .unwrap_or_else(|| details.puller.clone()),
        puller: details.puller.clone(),
        merchant: details.merchant.clone(),
        mint: details.mint.clone(),
        token_program: details.token_program.clone(),
        program_id: details.program_id.clone(),
        amount_base_units: decoded.amount_base_units.clone(),
        decimals: decoded.decimals,
        period_unit: period_unit_name(decoded.period_unit).to_string(),
        period_count: decoded.period_count,
        expected_period_hours: details.expected_period_hours,
        subscription_expires: decoded.request.subscription_expires.clone(),
        external_id: decoded.request.external_id.clone(),
        fee_payer: details.fee_payer,
        fee_payer_key: details.fee_payer_key.clone(),
        account: None,
        subscriber: None,
    }
}

/// Build a signed activation credential and return the `Authorization`
/// header value plus the context needed for post-activation persistence.
///
/// Network resolution mirrors [`crate::client::mpp::build_credential`]:
/// `network_override` wins, otherwise `methodDetails.network`, otherwise
/// `mainnet`.
pub fn build_credential(
    challenge: &Challenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
) -> Result<BuiltCredential> {
    build_credential_with_authenticate(
        challenge,
        None,
        store,
        network_override,
        account_override,
        resource_url,
    )
}

/// Variant of [`build_credential`] that ALSO signs an `authenticate`
/// challenge bundled in the same 402 response. The activation transaction
/// and the SIWMPP credential are produced from the SAME signer Arc — the
/// keystore is unlocked once and the cached secret signs both. The
/// authenticate token is returned on the [`BuiltCredential`] for the
/// caller to thread into the persistence step.
pub fn build_credential_with_authenticate(
    challenge: &Challenge,
    authenticate_challenge: Option<&Challenge>,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
) -> Result<BuiltCredential> {
    build_credential_with_authenticate_and_override(
        challenge,
        authenticate_challenge,
        store,
        network_override,
        account_override,
        resource_url,
        None,
    )
}

/// Variant of [`build_credential_with_authenticate`] that accepts an
/// optional auth-gate override threaded down to the signer. Used by
/// `pay-mcp` to route the keystore prompt through MCP elicitation when
/// the connected client supports it.
pub fn build_credential_with_authenticate_and_override(
    challenge: &Challenge,
    authenticate_challenge: Option<&Challenge>,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
    auth_override: crate::signer::AuthOverride,
) -> Result<BuiltCredential> {
    let decoded = decode(challenge)?;

    let amount_label = format_amount(&decoded.amount_base_units, decoded.decimals);
    let period_label = format!(
        "{count} {unit}{plural}",
        count = decoded.period_count,
        unit = period_unit_name(decoded.period_unit),
        plural = if decoded.period_count == 1 { "" } else { "s" }
    );
    let reason = decoded
        .request
        .description
        .clone()
        .or_else(|| challenge.description.clone())
        .unwrap_or_else(|| {
            format!(
                "Subscribe ({amount_label} {currency} every {period_label})",
                currency = decoded.currency_label
            )
        });
    let prompt_context =
        crate::client::prompt::payment_prompt_context(Some(&reason), &[resource_url]);
    let intent_reason = format!(
        "Recurring subscription — {amount_label} {currency} every {period_label}",
        currency = decoded.currency_label
    );
    let auth_intent = crate::keystore::AuthIntent::authorize_subscription(
        &amount_label,
        &intent_reason,
        &prompt_context.operator,
        subscription_authorization(challenge, &decoded),
    );

    // Same intent-vs-network check as charge — refuse to sign if the user
    // forced a network slug that contradicts the server.
    let embedded_blockhash = decoded.method_details.recent_blockhash.as_deref();
    crate::client::mpp::check_client_network_intent(
        network_override,
        &decoded.network,
        embedded_blockhash,
    )?;

    let network = network_override
        .map(str::to_string)
        .unwrap_or_else(|| decoded.network.clone());

    let (signer, ephemeral_notice) =
        crate::signer::load_signer_for_network_subscription_with_intent_and_override(
            &network,
            store,
            account_override,
            &amount_label,
            &auth_intent,
            auth_override,
        )?;
    let subscriber = signer.pubkey().to_string();

    // Human approval can outlive the server's challenge. Re-check after the
    // gate returns so an expired challenge never reaches transaction signing,
    // even though we refresh the Solana blockhash below.
    ensure_challenge_active(challenge)?;

    let rpc_url = resolve_rpc_url(&network, embedded_blockhash);
    // `confirmed` (not the default `finalized`) — the interactive 402
    // flow blocks on this round-trip and finalisation costs ~13 extra
    // seconds for no UX gain. The SubscriptionAuthority init we send
    // through this client is also recovered automatically on the next
    // request if the cluster forks past it, which is vanishingly rare.
    let rpc = RpcClient::new_with_commitment(
        rpc_url.clone(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );

    info!(
        amount = %decoded.amount_base_units,
        currency = %decoded.currency_label,
        plan = %decoded.method_details.plan_id,
        network = %network,
        %rpc_url,
        signer = %subscriber,
        "Building subscription activation credential"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;

    // Surfpool sandbox: same auto-fund cheatcode as the charge path so the
    // first-period transfer's source ATA exists on-chain.
    if crate::client::mpp::should_auto_fund_surfpool(network_override, embedded_blockhash) {
        let fund_url = rpc_url.clone();
        let pubkey = subscriber.clone();
        if let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(
            &fund_url, &pubkey,
        )) {
            warn!(error = %e, "Could not auto-fund subscriber via Surfpool — broadcast may fail");
        }
    }

    // A remote approval can exceed Solana's ~60-90 second blockhash window.
    // Keep using the challenge's blockhash to resolve the intended RPC, but
    // refresh the liveness value after approval and immediately before the
    // transaction is built and signed. Durable subscription terms remain
    // unchanged and are what the AuthIntent binds.
    let fresh_blockhash = rpc
        .get_latest_blockhash()
        .map_err(|e| Error::Mpp(format!("Failed to refresh activation blockhash: {e}")))?;
    let activation_details =
        with_recent_blockhash(&decoded.method_details, fresh_blockhash.to_string());

    let payload = rt
        .block_on(build_subscription_activation_transaction_with_options(
            &signer,
            &rpc,
            &activation_details,
            BuildSubscriptionActivationOptions {
                external_id: decoded.request.external_id.clone(),
                ..Default::default()
            },
        ))
        .map_err(|e| Error::Mpp(format!("Failed to build activation transaction: {e}")))?;

    let credential = PaymentCredential::new(challenge.to_echo(), payload);
    let authorization = format_authorization(&credential)
        .map_err(|e| Error::Mpp(format!("Failed to format subscription credential: {e}")))?;

    // Account name resolution: the override wins, else we re-read the
    // resolver the signer used. We need this for persistence so the
    // subscription row lands under the right `(network, account)` tuple.
    let account_name = resolve_account_name(store, &network, account_override)?;

    // Sign the SIWMPP authenticate challenge with the SAME unlocked
    // signer when present. We do this immediately so the user doesn't
    // re-prompt later, and so the persistence step can cache the token
    // in the same row as the freshly-activated subscription.
    let (authenticate_token, authenticate_expires_at) = match authenticate_challenge {
        Some(auth) => match sign_authenticate(&rt, &signer, auth, &decoded.method_details) {
            Ok((header, expiry)) => (Some(header), Some(expiry)),
            Err(e) => {
                warn!(
                    error = %e,
                    "Subscription activation signed, but SIWMPP authenticate signing failed — \
                     server will re-issue a 402 with a fresh authenticate challenge on next call"
                );
                (None, None)
            }
        },
        None => (None, None),
    };

    Ok(BuiltCredential {
        authorization,
        decoded,
        subscriber,
        account_name,
        network,
        ephemeral_notice,
        resource_url: resource_url.map(str::to_string),
        description: extract_description(challenge),
        authenticate_token,
        authenticate_expires_at,
    })
}

fn with_recent_blockhash(
    details: &SubscriptionMethodDetails,
    recent_blockhash: String,
) -> SubscriptionMethodDetails {
    let mut details = details.clone();
    details.recent_blockhash = Some(recent_blockhash);
    details
}

fn ensure_challenge_active(challenge: &Challenge) -> Result<()> {
    if challenge.is_expired() {
        return Err(Error::Mpp(
            "Subscription challenge is expired or has an invalid expiration timestamp".into(),
        ));
    }
    Ok(())
}

/// Sign a SIWMPP `authenticate` challenge with the same signer the
/// activation tx used. Returns (Authorization header, expires_at).
fn sign_authenticate(
    rt: &tokio::runtime::Runtime,
    signer: &dyn SolanaSigner,
    challenge: &Challenge,
    method_details: &SubscriptionMethodDetails,
) -> Result<(String, String)> {
    use pay_kit::mpp::program::subscriptions::{
        default_program_id, find_subscription_pda, parse_pubkey,
    };

    let plan_pubkey = parse_pubkey(&method_details.plan_id, "planId")
        .map_err(|e| Error::Mpp(format!("Invalid planId for authenticate: {e}")))?;
    let program_pubkey = match method_details.program_id.as_deref() {
        Some(p) => parse_pubkey(p, "programId")
            .map_err(|e| Error::Mpp(format!("Invalid programId for authenticate: {e}")))?,
        None => default_program_id(),
    };
    let (subscription_pda, _) =
        find_subscription_pda(&plan_pubkey, &signer.pubkey(), &program_pubkey);

    let header = rt
        .block_on(pay_kit::mpp::client::build_authenticate_credential_header(
            signer,
            challenge,
            &subscription_pda.to_string(),
        ))
        .map_err(|e| Error::Mpp(format!("Failed to build authenticate credential: {e}")))?;

    let request: pay_kit::mpp::AuthenticateRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Mpp(format!("Decoding authenticate request: {e}")))?;
    Ok((header, request.expiration_time))
}

/// Parse a `Payment-Receipt` header into a [`Subscription`] and persist it
/// under the account that signed the activation.
///
/// `built` is the value returned by [`build_credential`]; this function is
/// intended to be called immediately after the retry sees a 2xx response so
/// we record the freshly-activated subscription before any further work.
///
/// The standard pay-kit `Receipt` struct does not yet model subscription
/// extension fields (`subscriptionId`, `periodIndex`, `periodStartTs`,
/// `periodEndTs`, `expiresAt`). We therefore parse the base64url-encoded
/// receipt JSON directly here, extracting both the standard fields and the
/// subscription-extension fields the spec adds. A follow-up should widen
/// `pay_kit::mpp::Receipt` to include a `metadata` map and drop this local
/// parsing.
pub fn persist_from_receipt(
    built: &BuiltCredential,
    receipt_header: &str,
    store: &dyn AccountsStore,
) -> Result<Subscription> {
    let extensions = parse_subscription_receipt(receipt_header)?;
    let subscription = subscription_from_built_and_extensions(built, &extensions);

    let mut file = store.load()?;
    file.upsert_subscription(&built.network, &built.account_name, subscription.clone())?;
    store.save(&file)?;
    info!(
        subscription_id = %subscription.subscription_id,
        plan_id = %subscription.plan_id,
        network = %built.network,
        account = %built.account_name,
        "Persisted subscription after activation"
    );
    Ok(subscription)
}

/// Subscription-flavoured receipt fields parsed from a `Payment-Receipt`
/// header. Holds both the standard fields and the extensions defined by
/// the Solana subscription profile.
#[derive(Debug, Clone)]
pub struct ParsedSubscriptionReceipt {
    pub reference: String,
    pub timestamp: Option<String>,
    pub extensions: SubscriptionReceiptExtensions,
}

/// Decode a `Payment-Receipt` header value into the subscription-shaped
/// fields. Delegates to the SDK's new `ReceiptKind`-aware parser so the
/// wire shape stays in lock-step with whatever pay-kit emits.
pub fn parse_subscription_receipt(header: &str) -> Result<ParsedSubscriptionReceipt> {
    let kind = pay_kit::mpp::parse_receipt(header.trim())
        .map_err(|e| Error::Mpp(format!("Could not parse Payment-Receipt: {e}")))?;
    match kind {
        pay_kit::mpp::ReceiptKind::Subscription { base, extensions } => {
            Ok(ParsedSubscriptionReceipt {
                reference: base.reference,
                timestamp: Some(base.timestamp),
                extensions,
            })
        }
        pay_kit::mpp::ReceiptKind::Charge(_) => Err(Error::Mpp(
            "Receipt is a charge receipt, not subscription".into(),
        )),
        pay_kit::mpp::ReceiptKind::Session { .. } => Err(Error::Mpp(
            "Receipt is a session receipt, not subscription".into(),
        )),
    }
}

fn subscription_from_built_and_extensions(
    built: &BuiltCredential,
    parsed: &ParsedSubscriptionReceipt,
) -> Subscription {
    Subscription {
        subscription_id: parsed.extensions.subscription_id.clone(),
        plan_id: parsed.extensions.plan_id.clone(),
        program_id: if built.decoded.method_details.program_id.as_deref()
            == Some(pay_kit::mpp::program::subscriptions::SUBSCRIPTIONS_PROGRAM_ID)
            || built.decoded.method_details.program_id.is_none()
        {
            None
        } else {
            built.decoded.method_details.program_id.clone()
        },
        mint: built.decoded.method_details.mint.clone(),
        currency: Some(built.decoded.currency_label.clone()),
        amount_per_period: built.decoded.amount_base_units.clone(),
        period_unit: period_unit_name(built.decoded.period_unit).to_string(),
        period_count: u32::try_from(built.decoded.period_count).unwrap_or(u32::MAX),
        recipient: built.decoded.request.recipient.clone(),
        puller: built.decoded.method_details.puller.clone(),
        network: built.network.clone(),
        status: SubscriptionStatus::Active,
        activated_at: parsed
            .timestamp
            .clone()
            .unwrap_or_else(|| parsed.extensions.period_start_ts.clone()),
        activation_signature: parsed
            .extensions
            .activation_signature
            .clone()
            .unwrap_or_default(),
        last_charged_period: parsed.extensions.period_index.parse::<u64>().ok(),
        expires_at: parsed.extensions.expires_at.clone(),
        resource_url: built.resource_url.clone(),
        description: built.description.clone(),
        authenticate_token: built.authenticate_token.clone(),
        authenticate_expires_at: built.authenticate_expires_at.clone(),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn extract_description(challenge: &Challenge) -> Option<String> {
    if let Some(d) = challenge.description.as_deref()
        && !d.is_empty()
    {
        return Some(d.to_string());
    }
    let request: SubscriptionRequest = challenge.request.decode().ok()?;
    request.description
}

fn period_unit_name(unit: SubscriptionPeriodUnit) -> &'static str {
    match unit {
        SubscriptionPeriodUnit::Day => "day",
        SubscriptionPeriodUnit::Week => "week",
    }
}

/// Derive the deterministic `subscription_id` (the `SubscriptionDelegation`
/// PDA) from a [`BuiltCredential`] and persist a fresh `Subscription` entry
/// into `accounts.yml`. Used by every activation path that doesn't see the
/// `Payment-Receipt` header (curl/wget/httpie wrappers, the MCP curl tool)
/// — the receipt would otherwise be the authoritative source of the
/// `subscription_id`. A best-effort `getSignaturesForAddress` against the
/// freshly-created PDA backfills the activation signature; if that fails
/// (RPC blip, indexer lag) it stays empty and `pay subscriptions refresh`
/// can reconcile later.
pub fn persist_local_subscription_after_activation(
    built: &BuiltCredential,
    store: &dyn crate::accounts::AccountsStore,
) -> Result<()> {
    use pay_kit::mpp::program::subscriptions::{
        SUBSCRIPTIONS_PROGRAM_ID, default_program_id, find_subscription_pda, parse_pubkey,
    };

    let program_id = match built.decoded.method_details.program_id.as_deref() {
        Some(p) => parse_pubkey(p, "programId")
            .map_err(|e| Error::Mpp(format!("Invalid programId: {e}")))?,
        None => default_program_id(),
    };
    let plan_pda = parse_pubkey(&built.decoded.method_details.plan_id, "planId")
        .map_err(|e| Error::Mpp(format!("Invalid planId: {e}")))?;
    let subscriber = parse_pubkey(&built.subscriber, "subscriber")
        .map_err(|e| Error::Mpp(format!("Invalid subscriber: {e}")))?;
    let (subscription_pda, _) = find_subscription_pda(&plan_pda, &subscriber, &program_id);

    let activation_signature =
        lookup_activation_signature(&built.network, &subscription_pda.to_string(), None)
            .unwrap_or_default();

    let subscription = crate::accounts::Subscription {
        subscription_id: subscription_pda.to_string(),
        plan_id: built.decoded.method_details.plan_id.clone(),
        program_id: if built.decoded.method_details.program_id.as_deref()
            == Some(SUBSCRIPTIONS_PROGRAM_ID)
            || built.decoded.method_details.program_id.is_none()
        {
            None
        } else {
            built.decoded.method_details.program_id.clone()
        },
        mint: built.decoded.method_details.mint.clone(),
        currency: Some(built.decoded.currency_label.clone()),
        amount_per_period: built.decoded.amount_base_units.clone(),
        period_unit: match built.decoded.period_unit {
            pay_kit::mpp::SubscriptionPeriodUnit::Day => "day".to_string(),
            pay_kit::mpp::SubscriptionPeriodUnit::Week => "week".to_string(),
        },
        period_count: u32::try_from(built.decoded.period_count).unwrap_or(u32::MAX),
        recipient: built.decoded.request.recipient.clone(),
        puller: built.decoded.method_details.puller.clone(),
        network: built.network.clone(),
        status: crate::accounts::SubscriptionStatus::Active,
        activated_at: chrono::Utc::now().to_rfc3339(),
        activation_signature,
        last_charged_period: Some(0),
        expires_at: built.decoded.request.subscription_expires.clone(),
        resource_url: built.resource_url.clone(),
        description: built.description.clone(),
        authenticate_token: built.authenticate_token.clone(),
        authenticate_expires_at: built.authenticate_expires_at.clone(),
    };

    let mut file = store.load()?;
    file.upsert_subscription(&built.network, &built.account_name, subscription)?;
    store.save(&file)
}

/// Best-effort lookup of the activation `Subscribe` transaction signature
/// for an on-chain `SubscriptionDelegation` PDA, walking
/// `getSignaturesForAddress` and returning the oldest entry.
///
/// `rpc_url`, when `Some`, overrides the network-derived default — useful
/// for `pay subscriptions refresh --rpc-url <…>`. Returns `None` when the
/// PDA pubkey is malformed, RPC errors out, or the signature history is
/// empty (e.g. indexer lag right after a fresh activation). Callers
/// persist an empty `activation_signature` and rely on
/// `pay subscriptions refresh` to reconcile later.
pub fn lookup_activation_signature(
    network: &str,
    subscription_id: &str,
    rpc_url: Option<&str>,
) -> Option<String> {
    let pda: solana_pubkey::Pubkey = subscription_id.parse().ok()?;
    let rpc_url = rpc_url
        .map(str::to_string)
        .unwrap_or_else(|| default_rpc_url_for_network(network));
    let rpc = RpcClient::new(rpc_url);
    let sigs = rpc.get_signatures_for_address(&pda).ok()?;
    sigs.into_iter().last().map(|s| s.signature)
}

/// Map a pay-side network slug to the RPC URL pay uses for that network.
///
/// `localnet` and `surfnet` both route to the same sandbox cluster pay
/// server proxies to, so a local subscription resolves against the same
/// chain state the server saw at activation time.
pub fn default_rpc_url_for_network(network: &str) -> String {
    match network {
        "localnet" | "surfnet" => crate::config::SANDBOX_RPC_URL.to_string(),
        other => pay_kit::mpp::protocol::solana::default_rpc_url(other).to_string(),
    }
}

fn resolve_rpc_url(network: &str, embedded_blockhash: Option<&str>) -> String {
    std::env::var("PAY_RPC_URL").unwrap_or_else(|_| {
        if network == "localnet"
            && embedded_blockhash
                .is_some_and(|h| h.starts_with(crate::client::mpp::SURFPOOL_BLOCKHASH_PREFIX))
        {
            crate::config::SANDBOX_RPC_URL.to_string()
        } else {
            pay_kit::mpp::protocol::solana::default_rpc_url(network).to_string()
        }
    })
}

fn normalize_network(network: &str) -> &str {
    match network {
        "mainnet-beta" => "mainnet",
        other => other,
    }
}

/// Lookup the account name that the signer loader would resolve to. This
/// keeps persistence aligned with whichever wallet actually signed.
fn resolve_account_name(
    store: &dyn AccountsStore,
    network: &str,
    account_override: Option<&str>,
) -> Result<String> {
    if let Some(name) = account_override {
        return Ok(name.to_string());
    }
    let file = store.load()?;
    match resolve_account_for_network(network, &file) {
        AccountChoice::Resolved { name, .. } => Ok(name),
        AccountChoice::Missing => Ok(crate::accounts::DEFAULT_ACCOUNT_NAME.to_string()),
    }
}

fn format_amount(base_units: &str, decimals: u8) -> String {
    let raw: u128 = base_units.parse().unwrap_or(0);
    if decimals == 0 {
        return format!("${raw}");
    }
    let divisor = 10u128.pow(decimals as u32);
    let value = raw as f64 / divisor as f64;
    if (value * 100.0).round() / 100.0 == value {
        format!("${value:.2}")
    } else {
        format!("${value:.6}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    const PLAN: &str = "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT";
    const MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const PULLER: &str = "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h";
    const RECIPIENT: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";
    const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

    fn subscription_request(network: &str) -> serde_json::Value {
        serde_json::json!({
            "amount": "10000000",
            "currency": MINT,
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": RECIPIENT,
            "externalId": PLAN,
            "description": "Pro feed",
            "methodDetails": {
                "planId": PLAN,
                "mint": MINT,
                "tokenProgram": TOKEN_PROGRAM,
                "puller": PULLER,
                "recipient": RECIPIENT,
                "amount": "10000000",
                "decimals": 6,
                "network": network,
                "planIdNumeric": 42,
                "planBump": 254,
                "expectedPeriodHours": 720,
                "expectedCreatedAt": 1770000000,
            },
        })
    }

    fn challenge_from_request(request: serde_json::Value) -> Challenge {
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        let header = format!(
            "Payment id=\"sub-1\", realm=\"test\", method=\"solana\", \
             intent=\"subscription\", request=\"{b64}\""
        );
        crate::client::mpp::parse(&header).unwrap()
    }

    fn subscription_challenge(network: &str) -> Challenge {
        challenge_from_request(subscription_request(network))
    }

    #[test]
    fn is_subscription_challenge_detects_intent_and_method() {
        let challenge = subscription_challenge("mainnet");
        assert!(is_subscription_challenge(&challenge));

        // Same request but wrapped as a charge intent — must be rejected.
        let request = serde_json::json!({
            "amount": "10000000",
            "currency": MINT,
            "recipient": RECIPIENT,
            "methodDetails": {"network": "mainnet"},
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        let header = format!(
            "Payment id=\"c\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
        );
        let charge = crate::client::mpp::parse(&header).unwrap();
        assert!(!is_subscription_challenge(&charge));
    }

    #[test]
    fn parse_returns_none_for_non_subscription() {
        // Build a charge header and confirm parse() rejects it.
        let request = serde_json::json!({
            "amount": "1",
            "currency": "USDC",
            "recipient": RECIPIENT,
            "methodDetails": {"network": "mainnet"},
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        let header = format!(
            "Payment id=\"x\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
        );
        assert!(parse(&header).is_none());
    }

    #[test]
    fn decode_extracts_period_and_plan_and_currency_symbol() {
        let challenge = subscription_challenge("mainnet");
        let decoded = decode(&challenge).expect("decode");
        assert_eq!(decoded.amount_base_units, "10000000");
        assert_eq!(decoded.period_unit, SubscriptionPeriodUnit::Day);
        assert_eq!(decoded.period_count, 30);
        assert_eq!(decoded.method_details.plan_id, PLAN);
        assert_eq!(decoded.network, "mainnet");
        // USDC mainnet mint resolves to the symbol.
        assert_eq!(decoded.currency_label, "USDC");
        assert_eq!(decoded.decimals, 6);
    }

    #[test]
    fn decode_rejects_expired_or_invalid_challenge_before_authorization() {
        let mut expired = subscription_challenge("mainnet");
        expired.expires = Some("1970-01-01T00:00:00Z".to_string());
        assert!(
            decode(&expired)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );

        let mut invalid = subscription_challenge("mainnet");
        invalid.expires = Some("not-a-timestamp".to_string());
        assert!(
            decode(&invalid)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
    }

    #[test]
    fn authorization_context_binds_durable_subscription_terms() {
        let challenge = subscription_challenge("mainnet");
        let decoded = decode(&challenge).expect("decode");
        let authorization = subscription_authorization(&challenge, &decoded);

        assert_eq!(authorization.version, 1);
        assert_eq!(authorization.challenge_id, "sub-1");
        assert_eq!(authorization.challenge_realm, "test");
        assert_eq!(authorization.network, "mainnet");
        assert_eq!(authorization.plan_id, PLAN);
        assert_eq!(authorization.plan_id_numeric, Some(42));
        assert_eq!(authorization.plan_bump, Some(254));
        assert_eq!(authorization.recipient, RECIPIENT);
        assert_eq!(authorization.puller, PULLER);
        assert_eq!(authorization.mint, MINT);
        assert_eq!(authorization.amount_base_units, "10000000");
        assert_eq!(authorization.period_unit, "day");
        assert_eq!(authorization.period_count, 30);
        assert_eq!(authorization.expected_period_hours, Some(720));
        assert_eq!(authorization.account, None);
        assert_eq!(authorization.subscriber, None);
    }

    #[test]
    fn decode_rejects_amount_mismatch_before_authorization() {
        let mut request = subscription_request("mainnet");
        request["methodDetails"]["amount"] = serde_json::json!("99999999");
        let err = decode(&challenge_from_request(request)).unwrap_err();
        assert!(err.to_string().contains("amount does not match"));
    }

    #[test]
    fn decode_rejects_recipient_mismatch_before_authorization() {
        let mut request = subscription_request("mainnet");
        request["methodDetails"]["recipient"] = serde_json::json!(PULLER);
        let err = decode(&challenge_from_request(request)).unwrap_err();
        assert!(err.to_string().contains("recipient does not match"));
    }

    #[test]
    fn decode_rejects_decimals_that_disagree_with_the_mint() {
        let mut request = subscription_request("mainnet");
        // 10 USDC/period rendered as "$0.01" if the client trusts `decimals`.
        request["methodDetails"]["decimals"] = serde_json::json!(9);
        let err = decode(&challenge_from_request(request)).unwrap_err();
        assert!(err.to_string().contains("decimals does not match"));
    }

    #[test]
    fn decode_accepts_a_challenge_that_omits_decimals_for_a_known_mint() {
        let mut request = subscription_request("mainnet");
        request["methodDetails"]
            .as_object_mut()
            .unwrap()
            .remove("decimals");
        let decoded = decode(&challenge_from_request(request)).expect("decode");
        assert_eq!(decoded.decimals, 6);
    }

    #[test]
    fn decode_rejects_cadence_mismatch_before_authorization() {
        let mut request = subscription_request("mainnet");
        request["methodDetails"]["expectedPeriodHours"] = serde_json::json!(24);
        let err = decode(&challenge_from_request(request)).unwrap_err();
        assert!(err.to_string().contains("cadence does not match"));
    }

    #[test]
    fn activation_replaces_stale_blockhash_without_mutating_bound_terms() {
        let decoded = decode(&subscription_challenge("mainnet")).expect("decode");
        let mut stale = decoded.method_details.clone();
        stale.recent_blockhash = Some("stale".to_string());

        let fresh = with_recent_blockhash(&stale, "fresh".to_string());

        assert_eq!(stale.recent_blockhash.as_deref(), Some("stale"));
        assert_eq!(fresh.recent_blockhash.as_deref(), Some("fresh"));
        assert_eq!(fresh.plan_id, stale.plan_id);
        assert_eq!(fresh.amount, stale.amount);
        assert_eq!(fresh.recipient, stale.recipient);
    }

    #[test]
    fn decode_rejects_challenge_without_method_details() {
        let request = serde_json::json!({
            "amount": "10000000",
            "currency": MINT,
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": RECIPIENT,
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        let header = format!(
            "Payment id=\"s\", realm=\"r\", method=\"solana\", \
             intent=\"subscription\", request=\"{b64}\""
        );
        let challenge = crate::client::mpp::parse(&header).unwrap();
        let err = decode(&challenge).unwrap_err();
        assert!(format!("{err}").to_lowercase().contains("methoddetails"));
    }

    #[test]
    fn decode_rejects_month_period() {
        // periodUnit=month is rejected at the deserialize layer per the spec.
        let request = serde_json::json!({
            "amount": "1",
            "currency": MINT,
            "periodUnit": "month",
            "periodCount": "1",
            "recipient": RECIPIENT,
            "methodDetails": {"planId": PLAN, "mint": MINT, "tokenProgram": TOKEN_PROGRAM, "puller": PULLER},
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        let header = format!(
            "Payment id=\"s\", realm=\"r\", method=\"solana\", \
             intent=\"subscription\", request=\"{b64}\""
        );
        let challenge = crate::client::mpp::parse(&header).unwrap();
        let err = decode(&challenge).unwrap_err();
        let msg = format!("{err}").to_lowercase();
        assert!(msg.contains("month") || msg.contains("period") || msg.contains("unknown"));
    }

    #[test]
    fn decode_falls_back_to_truncated_mint_when_currency_unknown() {
        let request = serde_json::json!({
            "amount": "1",
            "currency": "Bonk1111111111111111111111111111111111111111",
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": RECIPIENT,
            "methodDetails": {
                "planId": PLAN,
                "mint": "Bonk1111111111111111111111111111111111111111",
                "tokenProgram": TOKEN_PROGRAM,
                "puller": PULLER,
                "recipient": RECIPIENT,
                "amount": "1",
                "decimals": 5,
                "network": "mainnet",
                "planIdNumeric": 42,
                "planBump": 254,
                "expectedPeriodHours": 720,
                "expectedCreatedAt": 1770000000,
            },
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        let header = format!(
            "Payment id=\"s\", realm=\"r\", method=\"solana\", \
             intent=\"subscription\", request=\"{b64}\""
        );
        let challenge = crate::client::mpp::parse(&header).unwrap();
        let decoded = decode(&challenge).unwrap();
        assert!(decoded.currency_label.contains("…"));
        assert_eq!(decoded.decimals, 5);
    }

    #[test]
    fn format_amount_renders_two_decimal_when_exact() {
        assert_eq!(format_amount("10000000", 6), "$10.00");
        assert_eq!(format_amount("99900000", 6), "$99.90");
        assert_eq!(format_amount("0", 6), "$0.00");
    }

    #[test]
    fn format_amount_handles_zero_decimals_and_large_values() {
        assert_eq!(format_amount("42", 0), "$42");
        assert_eq!(format_amount("123456789", 6), "$123.456789");
    }

    #[test]
    fn normalize_network_collapses_mainnet_beta() {
        assert_eq!(normalize_network("mainnet-beta"), "mainnet");
        assert_eq!(normalize_network("devnet"), "devnet");
    }

    #[test]
    fn parse_subscription_receipt_round_trip() {
        let payload = serde_json::json!({
            "method": "solana",
            "status": "success",
            "timestamp": "2026-01-15T12:03:10Z",
            "reference": "5J8signature",
            "subscriptionId": "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE",
            "planId": PLAN,
            "periodIndex": "0",
            "periodStartTs": "2026-01-15T12:03:10Z",
            "periodEndTs": "2026-02-14T12:03:10Z",
            "expiresAt": "2026-07-14T12:00:00Z",
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let parsed = parse_subscription_receipt(&header).expect("parse");
        assert_eq!(parsed.reference, "5J8signature");
        assert_eq!(parsed.timestamp.as_deref(), Some("2026-01-15T12:03:10Z"));
        assert_eq!(
            parsed.extensions.subscription_id,
            "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE"
        );
        assert_eq!(parsed.extensions.plan_id, PLAN);
        assert_eq!(parsed.extensions.period_index, "0");
        assert_eq!(
            parsed.extensions.expires_at.as_deref(),
            Some("2026-07-14T12:00:00Z")
        );
    }

    #[test]
    fn parse_subscription_receipt_errors_on_invalid_base64() {
        let err = parse_subscription_receipt("not!valid!base64!!!").unwrap_err();
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("base64url") || msg.contains("decode") || msg.contains("invalid"),
            "{err}"
        );
    }

    #[test]
    fn parse_subscription_receipt_errors_when_subscription_fields_missing() {
        // Standard receipt fields only — no subscriptionId etc.
        let payload = serde_json::json!({
            "method": "solana",
            "status": "success",
            "timestamp": "2026-01-15T12:03:10Z",
            "reference": "5J8signature",
            "challengeId": "c-1",
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        assert!(parse_subscription_receipt(&header).is_err());
    }

    #[test]
    fn parse_subscription_receipt_rejects_session_receipt() {
        let payload = serde_json::json!({
            "method": "solana",
            "status": "success",
            "timestamp": "2026-01-15T12:03:10Z",
            "reference": "5J8signature",
            "intent": "session",
            "acceptedCumulative": "25",
            "spent": "25",
            "idleTimeoutSeconds": 60,
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let err = parse_subscription_receipt(&header).unwrap_err();
        assert!(format!("{err}").contains("session receipt"));
    }

    #[test]
    fn parse_headers_filters_to_subscription_only() {
        let sub =
            pay_kit::mpp::format_www_authenticate(&subscription_challenge("mainnet")).unwrap();
        let charge_request = serde_json::json!({
            "amount": "1",
            "currency": "USDC",
            "recipient": RECIPIENT,
            "methodDetails": {"network": "mainnet"},
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&charge_request).unwrap());
        let charge_header = format!(
            "Payment id=\"c\", realm=\"r\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
        );

        let headers = vec![
            ("www-authenticate".to_string(), sub),
            ("www-authenticate".to_string(), charge_header),
        ];
        let subs = parse_headers(&headers);
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].intent.as_str(), "subscription");
    }
}
