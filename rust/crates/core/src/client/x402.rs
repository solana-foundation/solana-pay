//! x402 protocol support.
//!
//! Thin wrapper around `pay_kit::x402::client::exact` for challenge detection
//! and payment building.

use pay_kit::x402::solana_keychain::SolanaSigner;
use pay_kit::x402::solana_rpc_client::rpc_client::RpcClient;
use pay_kit::x402::{
    PAYMENT_REQUIRED_HEADER, X402_V1_PAYMENT_REQUIRED_HEADER, X402_VERSION_FIELD, X402_VERSION_V1,
    X402_VERSION_V2,
    client::exact::{
        build_payment_header as build_payment_header_v2, build_payment_header_v1,
        parse_x402_challenge_for_network,
    },
    exact::{
        PaymentExtensions, PaymentRequiredEnvelope, PaymentRequirements, SOLANA_DEVNET,
        SOLANA_MAINNET, SOLANA_TESTNET, default_rpc_url, generate_payment_identifier_id,
    },
    siwx::{
        SiwxChainSelectionOptions, SiwxExtension, create_siwx_header,
        siwx_extension_from_payment_required,
    },
};
use tracing::{debug, warn};

use crate::accounts::{AccountsStore, ResolvedEphemeral};
use crate::{Error, Result};

pub use pay_kit::x402::{SIGN_IN_WITH_X_HEADER, X402_V1_PAYMENT_HEADER, X402_V2_PAYMENT_HEADER};

#[derive(Debug, Clone)]
pub struct Challenge {
    pub x402_version: u64,
    pub requirements: PaymentRequirements,
    pub siwx: Option<SiwxExtension>,
    /// Raw `extensions` blob from the server's PAYMENT-REQUIRED envelope.
    /// Stored verbatim so `build_payment` can echo it back per x402 v2
    /// §5.1.2 ("client must include at least the info received").
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct SiwxAuthChallenge {
    pub extension: SiwxExtension,
}

/// An x402 `upto` (usage-metered) challenge: authorize a ceiling now, the
/// receiver authorizer settles the actual amount after serving.
#[derive(Debug, Clone)]
pub struct UptoChallenge {
    pub requirements: pay_kit::x402::upto::UptoRequirements,
}

#[derive(Debug)]
pub struct BuiltPayment {
    pub headers: Vec<(&'static str, String)>,
    pub ephemeral_notice: Option<ResolvedEphemeral>,
}

/// Try to parse an x402 challenge from headers and/or body.
/// Defaults to preferring Solana mainnet when multiple chains are offered.
pub fn parse(headers: &[(String, String)], body: Option<&str>) -> Option<Challenge> {
    let requirements = parse_x402_challenge_for_network(headers, body, Some(SOLANA_MAINNET))?;
    let siwx = parse_siwx_extension(headers, body).ok().flatten();
    let extensions =
        parse_payment_required_envelope(headers, body).and_then(|envelope| envelope.extensions);
    Some(Challenge {
        x402_version: detect_x402_version(headers, body),
        requirements,
        siwx,
        extensions,
    })
}

/// Try to parse an x402 `sign-in-with-x` challenge.
///
/// Unlike a pure auth gate, this is returned even when the same 402 also
/// advertises payment options in `accepts` — a wallet that already holds
/// credits (or has previously paid) should be able to sign in and spend
/// those instead of paying again. The caller decides preference + fallback
/// (see `classify_402`).
pub fn parse_siwx_auth(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<SiwxAuthChallenge> {
    let envelope = parse_payment_required_envelope(headers, body)?;
    let extension = siwx_extension_from_payment_required(&envelope)
        .ok()
        .flatten()?;
    Some(SiwxAuthChallenge { extension })
}

/// Build signed x402 retry headers.
///
/// The `ephemeral_notice` field is `Some` only when this call generated a fresh
/// ephemeral wallet — the caller renders the "Generated <network> wallet"
/// CLI notice with it.
///
/// Network resolution mirrors `mpp::build_credential`:
/// 1. `network_override` (CLI flag) wins.
/// 2. `requirements.cluster` or `requirements.network`.
/// 3. `mainnet`.
pub fn build_payment(
    challenge: &Challenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
) -> Result<BuiltPayment> {
    build_payment_with_override(
        challenge,
        store,
        network_override,
        account_override,
        resource_url,
        None,
    )
}

/// Variant of [`build_payment`] that accepts an optional auth-gate override
/// threaded down to the signer.
pub fn build_payment_with_override(
    challenge: &Challenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
    auth_override: crate::signer::AuthOverride,
) -> Result<BuiltPayment> {
    let requirements = &challenge.requirements;
    let amount = format_amount(&requirements.amount, &requirements.currency);
    let prompt_context = crate::client::prompt::payment_prompt_context(
        requirements.description.as_deref(),
        &[Some(requirements.resource.as_str()), resource_url],
    );
    let intent = crate::keystore::AuthIntent::authorize_payment_details(
        &amount,
        &prompt_context.reason,
        &prompt_context.operator,
    );

    let cluster_raw = normalize_network(
        requirements
            .cluster
            .as_deref()
            .unwrap_or(requirements.network.as_str()),
    );

    // Surfpool embeds a base58 sentinel prefix in every blockhash it
    // issues (`SURFNETxSAFEHASH…`). When the server's challenge carries
    // such a blockhash, the server is on a Surfpool / surfnet fork even
    // if the wire CAIP-2 says devnet — the x402 spec has no localnet
    // sentinel of its own, so the blockhash itself self-identifies the
    // ledger. Mirrors the MPP client's auto-sandbox detection in
    // `mpp.rs::resolve_rpc_url` / `should_auto_fund_surfpool`.
    let embedded_blockhash = requirements.recent_blockhash.as_deref();
    let surfpool_detected = embedded_blockhash
        .is_some_and(|h| h.starts_with(crate::client::mpp::SURFPOOL_BLOCKHASH_PREFIX));
    let cluster = if surfpool_detected {
        "localnet".to_string()
    } else {
        cluster_raw
    };

    crate::client::mpp::check_client_network_intent(
        network_override,
        &cluster,
        embedded_blockhash,
    )?;

    let should_auto_fund_surfpool =
        should_auto_fund_surfpool_for_x402(network_override, embedded_blockhash);
    let network = network_override.map(str::to_string).unwrap_or(cluster);

    let (signer, ephemeral_notice) =
        crate::signer::load_signer_for_network_payment_with_intent_and_override(
            &network,
            store,
            account_override,
            &amount,
            &intent,
            auth_override,
        )?;

    let rpc_url = std::env::var("PAY_RPC_URL").unwrap_or_else(|_| {
        if surfpool_detected {
            // `default_rpc_url("localnet")` is `http://localhost:8899`
            // (the in-process test-validator default). For an
            // auto-detected Surfpool server, route to the hosted
            // sandbox at `https://402.surfnet.dev:8899` instead so
            // signing + funding land on the same ledger the server
            // settles against.
            crate::config::SANDBOX_RPC_URL.to_string()
        } else {
            default_rpc_url(&network).to_string()
        }
    });
    let rpc = RpcClient::new(rpc_url.clone());

    debug!(
        amount = %requirements.amount,
        currency = %requirements.currency,
        cluster = %network,
        recipient = %requirements.recipient,
        signer = %signer.pubkey(),
        "Building x402 payment"
    );
    tracing::debug!(?requirements, "Full x402 requirements");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;

    if should_auto_fund_surfpool {
        let pubkey = signer.pubkey().to_string();
        let fund_url = rpc_url.clone();
        if let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(
            &fund_url, &pubkey,
        )) {
            warn!(error = %e, "Could not auto-fund ephemeral via Surfpool — broadcast may fail if wallet is empty");
        }
    }

    let (payment_header_name, payment_header_value) = match challenge.x402_version {
        X402_VERSION_V1 => {
            let header = rt
                .block_on(build_payment_header_v1(&signer, &rpc, requirements))
                .map_err(|e| Error::Mpp(format!("Failed to build x402 payment: {e}")))?;
            (X402_V1_PAYMENT_HEADER, header)
        }
        _ => {
            let extensions = build_outbound_extensions(challenge.extensions.as_ref())?;
            let header = rt
                .block_on(build_payment_header_v2(
                    &signer,
                    &rpc,
                    requirements,
                    extensions,
                ))
                .map_err(|e| Error::Mpp(format!("Failed to build x402 payment: {e}")))?;
            (X402_V2_PAYMENT_HEADER, header)
        }
    };

    let mut headers = vec![(payment_header_name, payment_header_value)];
    if let Some((header_name, header_value)) = build_siwx_header(challenge, &signer, &network, &rt)?
    {
        headers.push((header_name, header_value));
    }

    Ok(BuiltPayment {
        headers,
        ephemeral_notice,
    })
}

/// Try to parse an x402 `upto` challenge from headers and/or body — the first
/// advertised `upto` currency, used to build the channel open.
pub fn parse_upto(headers: &[(String, String)], body: Option<&str>) -> Option<UptoChallenge> {
    pay_kit::x402::client::upto::parse_upto_challenge(headers, body)
        .map(|requirements| UptoChallenge { requirements })
}

/// Every advertised x402 `upto` requirement, so the balance- and cost-aware
/// selector can choose among the offered currencies (not just the first).
pub fn parse_upto_accepts(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Vec<pay_kit::x402::upto::UptoRequirements> {
    pay_kit::x402::client::upto::parse_upto_accepts(headers, body)
}

/// Build a signed x402 `upto` payment: a payment-channel `open` authorization
/// whose deposit is the authorized ceiling. The client signs only the open;
/// the fee payer co-signs and broadcasts it, and the receiver authorizer signs
/// settlement for the actual metered amount. Mirrors [`build_payment`] — same
/// signer resolution, surfpool detection, network check and auto-fund — but
/// uses the server-provided `extra.recentBlockhash` + `extra.recentSlot`, so no
/// RPC round-trip is needed.
pub fn build_upto_payment(
    challenge: &UptoChallenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
) -> Result<BuiltPayment> {
    build_upto_payment_with_override(
        challenge,
        store,
        network_override,
        account_override,
        resource_url,
        None,
    )
}

/// Variant of [`build_upto_payment`] that accepts an optional auth-gate
/// override threaded down to the signer.
pub fn build_upto_payment_with_override(
    challenge: &UptoChallenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
    auth_override: crate::signer::AuthOverride,
) -> Result<BuiltPayment> {
    let requirements = &challenge.requirements;
    let amount = format_amount(&requirements.amount, &requirements.asset);
    let prompt_context = crate::client::prompt::payment_prompt_context(None, &[resource_url]);
    let intent = crate::keystore::AuthIntent::authorize_payment_details(
        &amount,
        &prompt_context.reason,
        &prompt_context.operator,
    );

    // `UptoRequirements` carries only the CAIP-2 `network` (no `cluster`), so map
    // it to a cluster; a Surfpool blockhash overrides to `localnet` (see the
    // exact path for the rationale).
    // Normalize the mapped cluster to a pay slug ("mainnet-beta" -> "mainnet"):
    // `cluster_for_caip2_network` returns the SDK cluster name, and the bare
    // `to_string` arm used to win, so `check_client_network_intent` rejected
    // `--mainnet` and `account_for_network` missed wallets keyed under "mainnet".
    let cluster_raw = pay_kit::x402::exact::cluster_for_caip2_network(&requirements.network)
        .map(normalize_network)
        .unwrap_or_else(|| normalize_network(&requirements.network));
    let embedded_blockhash = requirements.extra.recent_blockhash.as_deref();
    let surfpool_detected = embedded_blockhash
        .is_some_and(|h| h.starts_with(crate::client::mpp::SURFPOOL_BLOCKHASH_PREFIX));
    let cluster = if surfpool_detected {
        "localnet".to_string()
    } else {
        cluster_raw
    };
    crate::client::mpp::check_client_network_intent(
        network_override,
        &cluster,
        embedded_blockhash,
    )?;

    let should_auto_fund_surfpool =
        should_auto_fund_surfpool_for_x402(network_override, embedded_blockhash);
    let network = network_override.map(str::to_string).unwrap_or(cluster);

    let (signer, ephemeral_notice) =
        crate::signer::load_signer_for_network_payment_with_intent_and_override(
            &network,
            store,
            account_override,
            &amount,
            &intent,
            auth_override,
        )?;

    let rpc_url = std::env::var("PAY_RPC_URL").unwrap_or_else(|_| {
        if surfpool_detected {
            crate::config::SANDBOX_RPC_URL.to_string()
        } else {
            default_rpc_url(&network).to_string()
        }
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;

    if should_auto_fund_surfpool {
        let pubkey = signer.pubkey().to_string();
        let fund_url = rpc_url.clone();
        if let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(
            &fund_url, &pubkey,
        )) {
            warn!(error = %e, "Could not auto-fund ephemeral via Surfpool — channel open may fail if wallet is empty");
        }
    }

    // Authorization window + a unique nonce.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let expires_at = now + requirements.max_timeout_seconds as i64;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().to_string())
        .unwrap_or_else(|_| "0".to_string());

    let header = rt
        .block_on(pay_kit::x402::client::upto::build_upto_header(
            &signer,
            requirements,
            expires_at,
            nonce,
        ))
        .map_err(|e| Error::Mpp(format!("Failed to build x402 upto payment: {e}")))?;

    Ok(BuiltPayment {
        headers: vec![(X402_V2_PAYMENT_HEADER, header)],
        ephemeral_notice,
    })
}

/// Build a signed x402 SIWX-only retry header.
pub fn build_siwx_auth_header(
    challenge: &SiwxAuthChallenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
) -> Result<BuiltPayment> {
    build_siwx_auth_header_with_override(
        challenge,
        store,
        network_override,
        account_override,
        resource_url,
        None,
    )
}

/// Variant of [`build_siwx_auth_header`] that accepts an optional auth-gate
/// override threaded down to the signer.
pub fn build_siwx_auth_header_with_override(
    challenge: &SiwxAuthChallenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
    auth_override: crate::signer::AuthOverride,
) -> Result<BuiltPayment> {
    let preferred_chain_id = network_override.and_then(siwx_chain_id_for_network);
    let chain = pay_kit::x402::siwx::select_siwx_chain(
        &challenge.extension,
        &SiwxChainSelectionOptions {
            preferred_chain_id,
            supported_chain_ids: vec![],
        },
    )
    .map_err(|e| Error::Mpp(format!("Failed to select x402 sign-in challenge: {e}")))?;
    let network = network_override
        .map(str::to_string)
        .unwrap_or_else(|| normalize_network(&chain.chain_id));
    let desc = crate::client::prompt::payment_description(None, &[resource_url]);
    let reason = format!("authorize sign-in for {desc}");
    let intent = crate::keystore::AuthIntent::from_reason(&reason);
    let (signer, ephemeral_notice) =
        crate::signer::load_signer_for_network_with_intent_and_override(
            &network,
            store,
            account_override,
            &intent,
            auth_override,
        )?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;
    let header = rt
        .block_on(create_siwx_header(&challenge.extension, &chain, &signer))
        .map_err(|e| Error::Mpp(format!("Failed to sign x402 sign-in challenge: {e}")))?;

    Ok(BuiltPayment {
        headers: vec![(SIGN_IN_WITH_X_HEADER, header)],
        ephemeral_notice,
    })
}

fn build_siwx_header(
    challenge: &Challenge,
    signer: &dyn SolanaSigner,
    network: &str,
    rt: &tokio::runtime::Runtime,
) -> Result<Option<(&'static str, String)>> {
    let Some(extension) = &challenge.siwx else {
        return Ok(None);
    };
    let preferred_chain_id = siwx_chain_id_for_network(network);
    let chain = pay_kit::x402::siwx::select_siwx_chain(
        extension,
        &SiwxChainSelectionOptions {
            preferred_chain_id,
            supported_chain_ids: vec![],
        },
    )
    .map_err(|e| Error::Mpp(format!("Failed to select x402 sign-in challenge: {e}")))?;
    let header = rt
        .block_on(create_siwx_header(extension, &chain, signer))
        .map_err(|e| Error::Mpp(format!("Failed to sign x402 sign-in challenge: {e}")))?;

    Ok(Some((SIGN_IN_WITH_X_HEADER, header)))
}

/// Normalize CAIP-2 network identifiers to the slugs pay uses internally.
///
/// x402 challenges use CAIP-2 chain IDs like `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`
/// (Solana mainnet). The pay account system uses `mainnet`, `devnet`, `localnet`.
fn normalize_network(raw: &str) -> String {
    match raw {
        // Solana CAIP-2 genesis hashes
        SOLANA_MAINNET | "solana" | "mainnet-beta" => "mainnet".to_string(),
        SOLANA_DEVNET | "solana-devnet" => "devnet".to_string(),
        SOLANA_TESTNET | "solana-testnet" => "testnet".to_string(),
        // Already a slug
        s if !s.contains(':') => s.to_string(),
        // Unknown CAIP-2 — pass through, will error downstream with a clear message
        other => other.to_string(),
    }
}

fn siwx_chain_id_for_network(network: &str) -> Option<String> {
    match network {
        "mainnet" | "mainnet-beta" | "solana" => Some(SOLANA_MAINNET.to_string()),
        "devnet" | "localnet" | "solana-devnet" => Some(SOLANA_DEVNET.to_string()),
        "testnet" | "solana-testnet" => Some(SOLANA_TESTNET.to_string()),
        value if value.starts_with("solana:") => Some(value.to_string()),
        _ => None,
    }
}

fn parse_siwx_extension(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<Option<SiwxExtension>> {
    let Some(envelope) = parse_payment_required_envelope(headers, body) else {
        return Ok(None);
    };
    siwx_extension_from_payment_required(&envelope)
        .map_err(|e| Error::Mpp(format!("Failed to parse x402 sign-in challenge: {e}")))
}

/// Build the `extensions` blob to include on the outbound
/// `PAYMENT-SIGNATURE` from the server's inbound `PAYMENT-REQUIRED`
/// extensions. Echoes the server payload verbatim per x402 v2 §5.1.2,
/// and appends a fresh `payment-identifier.info.id` when the server
/// flagged that extension `info.required = true`.
///
/// TODO: cache the generated id keyed on `(resource_url, body_hash)`
/// so HTTP-level retries of the same logical request reuse the same
/// idempotency key and benefit from server-side cached 200s.
fn build_outbound_extensions(
    inbound: Option<&serde_json::Value>,
) -> Result<Option<PaymentExtensions>> {
    let Some(mut ext) = PaymentExtensions::echoing(inbound)
        .map_err(|e| Error::Mpp(format!("malformed PAYMENT-REQUIRED extensions: {e}")))?
    else {
        return Ok(None);
    };
    if ext.requires_payment_identifier() {
        ext = ext.with_payment_identifier_id(generate_payment_identifier_id());
    }
    Ok(Some(ext))
}

fn parse_payment_required_envelope(
    headers: &[(String, String)],
    body: Option<&str>,
) -> Option<PaymentRequiredEnvelope> {
    if let Some(value) = header_value(headers, PAYMENT_REQUIRED_HEADER)
        && let Some(envelope) = parse_payment_required_envelope_header(value)
    {
        return Some(envelope);
    }

    if let Some(value) = header_value(headers, X402_V1_PAYMENT_REQUIRED_HEADER)
        && let Some(envelope) = parse_payment_required_envelope_header(value)
    {
        return Some(envelope);
    }

    body.and_then(|body| serde_json::from_str::<PaymentRequiredEnvelope>(body).ok())
}

fn parse_payment_required_envelope_header(value: &str) -> Option<PaymentRequiredEnvelope> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .ok()?;
    serde_json::from_slice::<PaymentRequiredEnvelope>(&decoded).ok()
}

fn format_amount(amount: &str, currency: &str) -> String {
    let base: u64 = amount.parse().unwrap_or(0);
    let value = if currency.to_uppercase() == "SOL" {
        base as f64 / 1_000_000_000.0
    } else {
        base as f64 / 1_000_000.0
    };
    format!("${}", format_value(value))
}

fn format_value(v: f64) -> String {
    if v == 0.0 {
        "0".to_string()
    } else if v >= 0.01 && is_cent_exact(v) {
        format!("{v:.2}")
    } else if v >= 0.01 {
        format_precise_value(v, 6)
    } else if v >= 0.001 {
        format!("{v:.3}")
    } else if v >= 0.0001 {
        format!("{v:.4}")
    } else {
        format!("{v:.6}")
    }
}

fn is_cent_exact(v: f64) -> bool {
    let rounded_to_cent = (v * 100.0).round() / 100.0;
    (v - rounded_to_cent).abs() < 0.0000005
}

fn format_precise_value(v: f64, decimals: usize) -> String {
    let mut value = format!("{v:.decimals$}");
    while value.contains('.') && value.ends_with('0') {
        value.pop();
    }
    value
}

fn detect_x402_version(headers: &[(String, String)], body: Option<&str>) -> u64 {
    // Mirror `parse_x402_challenge_for_network`'s selection order so the
    // version we report is the one whose payload the parser actually consumed.
    // If the parser took the v1 header but we reported V2 from the body, the
    // build path would emit a v2 envelope from v1-parsed requirements — same
    // struct shape today but a latent mismatch the moment the wire formats
    // diverge.
    if header_value(headers, PAYMENT_REQUIRED_HEADER).is_some() {
        return X402_VERSION_V2;
    }

    if let Some(value) = header_value(headers, X402_V1_PAYMENT_REQUIRED_HEADER) {
        return x402_version_from_json(value).unwrap_or(X402_VERSION_V1);
    }

    if let Some(version) = body.and_then(x402_version_from_json) {
        return version;
    }

    X402_VERSION_V2
}

fn should_auto_fund_surfpool_for_x402(
    network_override: Option<&str>,
    embedded_blockhash: Option<&str>,
) -> bool {
    crate::client::mpp::should_auto_fund_surfpool(network_override, embedded_blockhash)
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn x402_version_from_json(body: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get(X402_VERSION_FIELD)
        .and_then(|v| v.as_u64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Account, AccountsFile, Keystore, MemoryAccountsStore};
    use pay_kit::x402::exact::EXACT_SCHEME;

    fn sample_requirements() -> PaymentRequirements {
        PaymentRequirements {
            network: "solana".to_string(),
            cluster: Some("mainnet".to_string()),
            recipient: "11111111111111111111111111111111".to_string(),
            amount: "1000000".to_string(),
            currency: "USDC".to_string(),
            decimals: Some(6),
            token_program: None,
            resource: "https://api.example.com/v1/test".to_string(),
            description: Some("API access".to_string()),
            max_age: Some(60),
            recent_blockhash: None,
            fee_payer: None,
            fee_payer_key: None,
            extra: None,
            accepted: None,
            resource_info: None,
        }
    }

    fn surfpool_hash() -> &'static str {
        "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx18b8dc98"
    }

    #[test]
    fn x402_auto_fund_skips_mainnet_override() {
        assert!(!should_auto_fund_surfpool_for_x402(Some("mainnet"), None));
        assert!(!should_auto_fund_surfpool_for_x402(
            Some("mainnet"),
            Some("9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F")
        ));
    }

    #[test]
    fn x402_auto_fund_runs_for_sandbox_override_or_surfpool_blockhash() {
        assert!(should_auto_fund_surfpool_for_x402(Some("localnet"), None));
        assert!(should_auto_fund_surfpool_for_x402(Some("sandbox"), None));
        assert!(should_auto_fund_surfpool_for_x402(
            None,
            Some(surfpool_hash())
        ));
    }

    #[test]
    fn x402_auto_fund_skips_plain_localnet_without_override_or_surfpool_hash() {
        assert!(!should_auto_fund_surfpool_for_x402(
            None,
            Some("9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F")
        ));
    }

    #[test]
    fn format_value_zero() {
        assert_eq!(format_value(0.0), "0");
    }

    #[test]
    fn format_value_large() {
        assert_eq!(format_value(1.5), "1.50");
    }

    #[test]
    fn format_value_preserves_fractional_cent_fees() {
        assert_eq!(format_value(1.0015), "1.0015");
    }

    #[test]
    fn format_value_cents() {
        assert_eq!(format_value(0.01), "0.01");
    }

    #[test]
    fn format_value_milli() {
        assert_eq!(format_value(0.005), "0.005");
    }

    #[test]
    fn format_value_micro() {
        assert_eq!(format_value(0.0005), "0.0005");
    }

    #[test]
    fn format_value_tiny() {
        assert_eq!(format_value(0.00005), "0.000050");
    }

    #[test]
    fn format_amount_usdc() {
        assert_eq!(format_amount("1000000", "USDC"), "$1.00");
    }

    #[test]
    fn format_amount_usdc_with_fee_fraction() {
        assert_eq!(format_amount("1001500", "USDC"), "$1.0015");
    }

    #[test]
    fn format_amount_sol() {
        assert_eq!(format_amount("1000000000", "SOL"), "$1.00");
    }

    #[test]
    fn format_amount_zero() {
        assert_eq!(format_amount("0", "USDC"), "$0");
    }

    #[test]
    fn format_amount_invalid_number() {
        assert_eq!(format_amount("abc", "USDC"), "$0");
    }

    #[test]
    fn parse_empty_headers_and_body() {
        assert!(parse(&[], None).is_none());
    }

    #[test]
    fn parse_no_x402_headers() {
        let headers = vec![("content-type".to_string(), "text/html".to_string())];
        assert!(parse(&headers, None).is_none());
    }

    #[test]
    fn parse_v1_body_sets_v1_version() {
        let body = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V1,
            "accepts": [{
                "network": "solana-devnet",
                "maxAmountRequired": "5000",
                "payTo": "abc123",
                "asset": "SOL",
                "resource": "/test"
            }]
        })
        .to_string();

        let challenge = parse(&[], Some(&body)).unwrap();
        assert_eq!(challenge.x402_version, X402_VERSION_V1);
        assert_eq!(challenge.requirements.amount, "5000");
    }

    #[test]
    fn parse_v1_header_with_v2_body_keeps_v1_version() {
        // Mixed-config server: only the v1 header is present, but the body
        // declares x402Version=2. The upstream parser consumes the v1 header,
        // so we must report V1 to keep the build path aligned with what was
        // parsed — otherwise we'd emit a v2 proof for a v1-only server.
        let v1_requirements = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana-devnet",
            "maxAmountRequired": "5000",
            "payTo": "abc123",
            "asset": "SOL",
            "resource": "/test"
        });
        let body = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": []
        })
        .to_string();
        let headers = vec![(
            X402_V1_PAYMENT_REQUIRED_HEADER.to_string(),
            v1_requirements.to_string(),
        )];

        let challenge = parse(&headers, Some(&body)).unwrap();
        assert_eq!(challenge.x402_version, X402_VERSION_V1);
    }

    #[test]
    fn parse_v2_payment_required_header_sets_v2_version() {
        let selected = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "10000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "6cvgmdrsVxyiuPzqMCSBnS7fAmA5Mk2VG4BcfVhC8jdC",
            "maxTimeoutSeconds": 300,
            "extra": {
                "feePayer": "AepWpq3GQwL8CeKMtZyKtKPa7W91Coygh3ropAJapVdU",
                "decimals": 6
            }
        });
        let payment_required = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "resource": {
                "url": "https://api.example.com/v1/test",
                "description": "API access"
            },
            "accepts": [selected.clone()]
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payment_required.to_string().as_bytes(),
        );
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let challenge = parse(&headers, None).unwrap();
        assert_eq!(challenge.x402_version, X402_VERSION_V2);
        assert_eq!(challenge.requirements.amount, "10000");
        assert_eq!(challenge.requirements.accepted.as_ref(), Some(&selected));
        assert_eq!(
            challenge
                .requirements
                .resource_info
                .as_ref()
                .map(|resource| resource.url.as_str()),
            Some("https://api.example.com/v1/test")
        );
    }

    #[test]
    fn parse_v2_payment_required_header_captures_siwx_extension() {
        let selected = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "10000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "6cvgmdrsVxyiuPzqMCSBnS7fAmA5Mk2VG4BcfVhC8jdC",
            "maxTimeoutSeconds": 300,
            "extra": {
                "feePayer": "AepWpq3GQwL8CeKMtZyKtKPa7W91Coygh3ropAJapVdU",
                "decimals": 6
            }
        });
        let payment_required = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "resource": {
                "url": "https://api.example.com/v1/test",
                "description": "API access"
            },
            "accepts": [selected],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "api.example.com",
                        "uri": "https://api.example.com",
                        "version": "1",
                        "nonce": "nonce-123",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": [{
                        "chainId": SOLANA_MAINNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payment_required.to_string().as_bytes(),
        );
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let challenge = parse(&headers, None).unwrap();

        assert_eq!(
            challenge
                .siwx
                .as_ref()
                .map(|extension| extension.nonce.as_str()),
            Some("nonce-123")
        );
    }

    #[test]
    fn parse_captures_payment_identifier_extension_for_echo() {
        // Birdeye-style challenge — payment-identifier marked
        // info.required:true. The parser must surface this so
        // build_outbound_extensions can append a client-side id.
        let selected = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "3000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "6cvgmdrsVxyiuPzqMCSBnS7fAmA5Mk2VG4BcfVhC8jdC",
            "maxTimeoutSeconds": 60,
            "extra": { "feePayer": "AepWpq3GQwL8CeKMtZyKtKPa7W91Coygh3ropAJapVdU" }
        });
        let payment_required = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": [selected],
            "extensions": {
                "payment-identifier": {
                    "info": { "required": true },
                    "schema": { "type": "object", "required": ["id"] }
                }
            }
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payment_required.to_string().as_bytes(),
        );
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let challenge = parse(&headers, None).unwrap();
        let raw = challenge.extensions.as_ref().expect("extensions captured");
        assert_eq!(
            raw["payment-identifier"]["info"]["required"],
            serde_json::json!(true)
        );

        let outbound = build_outbound_extensions(challenge.extensions.as_ref())
            .unwrap()
            .expect("outbound extensions produced");
        let pid = outbound
            .payment_identifier
            .as_ref()
            .expect("payment-identifier echoed");
        // Echoed server fields preserved.
        assert_eq!(pid.info.required, Some(true));
        assert!(pid.schema.is_some());
        // Client-side id appended, matching the spec pattern.
        let id = pid.info.id.as_deref().expect("id appended");
        assert!(id.starts_with("pay_"));
        assert!(id.len() >= 16 && id.len() <= 128);
    }

    #[test]
    fn build_outbound_extensions_returns_none_when_inbound_absent() {
        assert!(build_outbound_extensions(None).unwrap().is_none());
    }

    #[test]
    fn build_outbound_extensions_echoes_without_appending_when_not_required() {
        // payment-identifier with info.required=false should be echoed
        // but the client should NOT generate an id (avoids polluting
        // idempotency state when the server doesn't need it).
        let inbound = serde_json::json!({
            "payment-identifier": { "info": { "required": false } }
        });
        let outbound = build_outbound_extensions(Some(&inbound))
            .unwrap()
            .expect("echoed");
        assert!(!outbound.requires_payment_identifier());
        assert!(
            outbound
                .payment_identifier
                .as_ref()
                .and_then(|p| p.info.id.as_deref())
                .is_none()
        );
    }

    #[test]
    fn parse_siwx_auth_reads_auth_only_challenge() {
        let payment_required = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "resource": {
                "url": "https://api.example.com/v1/test",
                "description": "API access"
            },
            "accepts": [],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "api.example.com",
                        "uri": "https://api.example.com",
                        "version": "1",
                        "nonce": "nonce-123",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": [{
                        "chainId": SOLANA_MAINNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payment_required.to_string().as_bytes(),
        );
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let challenge = parse_siwx_auth(&headers, None).unwrap();

        assert_eq!(challenge.extension.nonce, "nonce-123");
        assert!(parse(&headers, None).is_none());
    }

    #[test]
    fn parse_siwx_auth_reads_auth_only_body() {
        let body = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": [],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "api.example.com",
                        "uri": "https://api.example.com",
                        "version": "1",
                        "nonce": "nonce-from-body",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": [{
                        "chainId": SOLANA_DEVNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        })
        .to_string();

        let challenge = parse_siwx_auth(&[], Some(&body)).unwrap();

        assert_eq!(challenge.extension.nonce, "nonce-from-body");
    }

    #[test]
    fn parse_siwx_auth_reads_siwx_even_with_payment() {
        let selected = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "10000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "6cvgmdrsVxyiuPzqMCSBnS7fAmA5Mk2VG4BcfVhC8jdC",
            "maxTimeoutSeconds": 300
        });
        let payment_required = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": [selected],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "api.example.com",
                        "uri": "https://api.example.com",
                        "version": "1",
                        "nonce": "nonce-123",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": [{
                        "chainId": SOLANA_MAINNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payment_required.to_string().as_bytes(),
        );
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        // sign-in-with-x is surfaced even when payment options coexist, so a
        // funded wallet can prefer spending credits over paying.
        let siwx = parse_siwx_auth(&headers, None).expect("siwx challenge present");
        assert_eq!(siwx.extension.nonce, "nonce-123");
        assert!(parse(&headers, None).unwrap().siwx.is_some());
    }

    #[test]
    fn parse_payment_challenge_survives_malformed_siwx_extension() {
        let selected = serde_json::json!({
            "scheme": EXACT_SCHEME,
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "10000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "6cvgmdrsVxyiuPzqMCSBnS7fAmA5Mk2VG4BcfVhC8jdC",
            "maxTimeoutSeconds": 300
        });
        let payment_required = serde_json::json!({
            X402_VERSION_FIELD: X402_VERSION_V2,
            "accepts": [selected],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "api.example.com",
                        "uri": "https://api.example.com",
                        "version": "1",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": []
                }
            }
        });
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payment_required.to_string().as_bytes(),
        );
        let headers = vec![(PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let challenge = parse(&headers, None).unwrap();

        assert_eq!(challenge.requirements.amount, "10000");
        assert!(challenge.siwx.is_none());
    }

    #[test]
    fn normalize_network_maps_sdk_identifiers_to_pay_slugs() {
        assert_eq!(normalize_network(SOLANA_MAINNET), "mainnet");
        assert_eq!(normalize_network("mainnet-beta"), "mainnet");
        assert_eq!(normalize_network(SOLANA_DEVNET), "devnet");
        assert_eq!(normalize_network("solana-devnet"), "devnet");
        assert_eq!(normalize_network(SOLANA_TESTNET), "testnet");
        assert_eq!(normalize_network("localnet"), "localnet");
    }

    #[test]
    fn siwx_chain_id_for_network_maps_pay_networks() {
        assert_eq!(
            siwx_chain_id_for_network("mainnet").as_deref(),
            Some(SOLANA_MAINNET)
        );
        assert_eq!(
            siwx_chain_id_for_network("devnet").as_deref(),
            Some(SOLANA_DEVNET)
        );
        assert_eq!(
            siwx_chain_id_for_network("localnet").as_deref(),
            Some(SOLANA_DEVNET)
        );
        assert_eq!(
            siwx_chain_id_for_network("testnet").as_deref(),
            Some(SOLANA_TESTNET)
        );
    }

    #[test]
    fn build_siwx_header_signs_selected_chain() {
        const TEST_KEYPAIR_BYTES: [u8; 64] = [
            41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254, 227, 176, 196,
            204, 122, 47, 166, 133, 155, 252, 217, 0, 253, 17, 49, 143, 47, 94, 121, 167, 195, 136,
            72, 22, 157, 48, 77, 88, 63, 96, 57, 122, 181, 243, 236, 188, 241, 134, 174, 224, 100,
            246, 17, 170, 104, 17, 151, 48,
        ];
        let signer =
            pay_kit::x402::solana_keychain::memory::MemorySigner::from_bytes(&TEST_KEYPAIR_BYTES)
                .unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let extension = pay_kit::x402::siwx::SiwxExtension::new(
            pay_kit::x402::siwx::SiwxExtensionInfo {
                domain: "api.example.com".to_string(),
                uri: "https://api.example.com".to_string(),
                statement: Some("Sign in to pay.".to_string()),
                version: "1".to_string(),
                nonce: "nonce-123".to_string(),
                issued_at: "2026-04-27T00:00:00Z".to_string(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: None,
            },
            pay_kit::x402::siwx::default_solana_siwx_chains(),
        );
        let challenge = Challenge {
            x402_version: X402_VERSION_V2,
            requirements: sample_requirements(),
            siwx: Some(extension),
            extensions: None,
        };

        let (header_name, header_value) = build_siwx_header(&challenge, &signer, "devnet", &rt)
            .unwrap()
            .unwrap();
        let payload = pay_kit::x402::siwx::parse_siwx_header(&header_value).unwrap();

        assert_eq!(header_name, SIGN_IN_WITH_X_HEADER);
        assert_eq!(payload.chain_id, SOLANA_DEVNET);
        assert!(pay_kit::x402::siwx::verify_siwx_payload(&payload).unwrap());
    }

    #[test]
    fn build_siwx_auth_header_signs_without_payment() {
        const TEST_KEYPAIR_BYTES: [u8; 64] = [
            41, 99, 180, 88, 51, 57, 48, 80, 61, 63, 219, 75, 176, 49, 116, 254, 227, 176, 196,
            204, 122, 47, 166, 133, 155, 252, 217, 0, 253, 17, 49, 143, 47, 94, 121, 167, 195, 136,
            72, 22, 157, 48, 77, 88, 63, 96, 57, 122, 181, 243, 236, 188, 241, 134, 174, 224, 100,
            246, 17, 170, 104, 17, 151, 48,
        ];
        let pubkey = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";
        let account = Account {
            keystore: Keystore::Ephemeral,
            active: true,
            auth_required: Some(false),
            pubkey: Some(pubkey.to_string()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some(bs58::encode(TEST_KEYPAIR_BYTES).into_string()),
            created_at: Some("2026-04-27T00:00:00Z".to_string()),
            subscriptions: std::collections::BTreeMap::new(),
        };
        let mut file = AccountsFile::default();
        file.upsert("devnet", "default", account);
        let store = MemoryAccountsStore::with_file(file);
        let challenge = SiwxAuthChallenge {
            extension: pay_kit::x402::siwx::SiwxExtension::new(
                pay_kit::x402::siwx::SiwxExtensionInfo {
                    domain: "api.example.com".to_string(),
                    uri: "https://api.example.com".to_string(),
                    statement: Some("Sign in.".to_string()),
                    version: "1".to_string(),
                    nonce: "nonce-123".to_string(),
                    issued_at: "2026-04-27T00:00:00Z".to_string(),
                    expiration_time: None,
                    not_before: None,
                    request_id: None,
                    resources: None,
                },
                pay_kit::x402::siwx::default_solana_siwx_chains(),
            ),
        };

        let built = build_siwx_auth_header(&challenge, &store, Some("devnet"), None, None).unwrap();
        let payload = pay_kit::x402::siwx::parse_siwx_header(&built.headers[0].1).unwrap();

        assert_eq!(built.headers.len(), 1);
        assert_eq!(built.headers[0].0, SIGN_IN_WITH_X_HEADER);
        assert_eq!(payload.address, pubkey);
        assert_eq!(payload.chain_id, SOLANA_DEVNET);
        assert!(pay_kit::x402::siwx::verify_siwx_payload(&payload).unwrap());
    }

    #[test]
    fn build_siwx_auth_header_rejects_unsupported_preferred_chain() {
        let extension = pay_kit::x402::siwx::SiwxExtension::new(
            pay_kit::x402::siwx::SiwxExtensionInfo {
                domain: "api.example.com".to_string(),
                uri: "https://api.example.com".to_string(),
                statement: Some("Sign in.".to_string()),
                version: "1".to_string(),
                nonce: "nonce-123".to_string(),
                issued_at: "2026-04-27T00:00:00Z".to_string(),
                expiration_time: None,
                not_before: None,
                request_id: None,
                resources: None,
            },
            vec![pay_kit::x402::siwx::SupportedChain::solana(SOLANA_MAINNET)],
        );
        let challenge = SiwxAuthChallenge { extension };
        let store = MemoryAccountsStore::new();

        let err =
            build_siwx_auth_header(&challenge, &store, Some("devnet"), None, None).unwrap_err();

        assert!(
            err.to_string()
                .contains("siwx_preferred_chain_not_supported")
        );
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn v1_header_name_is_x_payment() {
        assert_eq!(X402_V1_PAYMENT_HEADER, "X-PAYMENT");
    }

    #[test]
    fn v2_header_name_is_payment_signature() {
        assert_eq!(X402_V2_PAYMENT_HEADER, "PAYMENT-SIGNATURE");
    }

    #[test]
    fn build_payment_rejects_network_intent_mismatch_before_signer_lookup() {
        let store = MemoryAccountsStore::new();
        let challenge = Challenge {
            x402_version: X402_VERSION_V2,
            requirements: sample_requirements(),
            siwx: None,
            extensions: None,
        };

        let err = build_payment(&challenge, &store, Some("localnet"), None, None).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("you forced network `localnet`"));
        assert!(msg.contains("server expects `mainnet`"));
        assert_eq!(
            store.save_count(),
            0,
            "mismatch must fail before any wallet mutation"
        );
    }

    #[test]
    fn build_payment_requires_mainnet_wallet_when_no_override_is_set() {
        let store = MemoryAccountsStore::new();
        let challenge = Challenge {
            x402_version: X402_VERSION_V2,
            requirements: sample_requirements(),
            siwx: None,
            extensions: None,
        };

        let err = build_payment(&challenge, &store, None, None, None).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("No account configured for network `mainnet`"));
        assert!(msg.contains("pay setup"));
    }

    #[test]
    fn build_payment_reports_named_account_miss_for_network() {
        let store = MemoryAccountsStore::new();
        let requirements = sample_requirements();

        let challenge = Challenge {
            x402_version: X402_VERSION_V2,
            requirements,
            siwx: None,
            extensions: None,
        };
        let err = build_payment(&challenge, &store, None, Some("alice"), None).unwrap_err();
        let msg = err.to_string();

        assert!(msg.contains("No account named `alice` configured for network `mainnet`"));
        assert_eq!(
            store.save_count(),
            0,
            "named-account miss must not lazily create"
        );
    }

    #[test]
    fn surfpool_blockhash_promotes_cluster_to_localnet() {
        // Server advertises devnet CAIP-2 (no localnet sentinel exists
        // in the x402 spec) but the recentBlockhash carries the
        // Surfpool prefix. The client should treat this as
        // localnet/sandbox — same auto-detection the MPP client does.
        let mut requirements = sample_requirements();
        requirements.network = pay_kit::x402::exact::SOLANA_DEVNET.to_string();
        requirements.cluster = Some("devnet".to_string());
        requirements.recent_blockhash = Some(format!(
            "{}xxxxxxxxxxxxxxxxxxx1892bcad",
            crate::client::mpp::SURFPOOL_BLOCKHASH_PREFIX
        ));

        let challenge = Challenge {
            x402_version: X402_VERSION_V2,
            requirements,
            siwx: None,
            extensions: None,
        };

        // We can't exercise the full build path here (it needs a live
        // RPC for funding + signing) — but the network-intent check
        // fires before any I/O. Without the surfpool promotion the
        // check would compare a hypothetical `--mainnet` override
        // against `devnet`; with the promotion in place it compares
        // against `localnet` instead.
        let store = MemoryAccountsStore::new();
        let err = build_payment(&challenge, &store, Some("mainnet"), None, None).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("localnet"),
            "expected promoted cluster `localnet` in error, got: {msg}"
        );
        assert!(
            !msg.contains("devnet"),
            "cluster should be promoted away from devnet, got: {msg}"
        );
    }
}
