//! MPP (Machine Payments Protocol) support.
//!
//! Thin wrapper around `pay_kit::mpp` for challenge detection and credential building.

use pay_kit::mpp::client::build_credential_header;
use pay_kit::mpp::protocol::solana::default_rpc_url;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
use pay_kit::mpp::{ChargeRequest, parse_www_authenticate_all};
use pay_types::Stablecoin;
use tracing::{info, warn};

use crate::accounts::{
    AccountChoice, AccountsStore, ResolvedEphemeral, resolve_account_for_network,
};
use crate::{Error, Result};

// Re-export the challenge type for the runner/CLI.
pub use pay_kit::mpp::PaymentChallenge as Challenge;

/// Try to extract an MPP challenge from the `www-authenticate` header value.
pub fn parse(header_value: &str) -> Option<Challenge> {
    parse_all([header_value]).into_iter().next()
}

/// Extract every MPP challenge from repeated or combined `WWW-Authenticate`
/// header values.
pub fn parse_all<'a>(header_values: impl IntoIterator<Item = &'a str>) -> Vec<Challenge> {
    parse_www_authenticate_all(header_values)
        .into_iter()
        .filter_map(|result| result.ok())
        .collect()
}

/// Extract every MPP challenge from a lowercase header list.
pub fn parse_headers(headers: &[(String, String)]) -> Vec<Challenge> {
    parse_all(
        headers
            .iter()
            .filter(|(name, _)| name == "www-authenticate")
            .map(|(_, value)| value.as_str()),
    )
}

/// Build a signed credential and return the `Authorization` header value
/// alongside an optional `ResolvedEphemeral` notice that the caller should
/// render if `Some` (signals "we just generated a fresh ephemeral wallet
/// for this network — let the user know what its pubkey is").
///
/// Network resolution:
///
/// 1. `network_override` (if `Some`) — set by `--mainnet` / `--sandbox`
///    CLI flags. Forces a specific network slug regardless of what the
///    challenge advertises.
/// 2. Otherwise, `challenge.method_details.network`.
/// 3. Otherwise, `mainnet`.
pub fn build_credential(
    challenge: &Challenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
) -> Result<(String, Option<ResolvedEphemeral>)> {
    build_credential_with_override(
        challenge,
        store,
        network_override,
        account_override,
        resource_url,
        None,
    )
}

/// Variant of [`build_credential`] that accepts an optional auth-gate
/// override threaded down to the signer.
pub fn build_credential_with_override(
    challenge: &Challenge,
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: Option<&str>,
    auth_override: crate::signer::AuthOverride,
) -> Result<(String, Option<ResolvedEphemeral>)> {
    let request: ChargeRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Mpp(format!("Failed to decode challenge request: {e}")))?;

    let amount = format_amount(&request.amount, &request.currency);
    let prompt_context = crate::client::prompt::payment_prompt_context(
        charge_prompt_reason(
            request.description.as_deref(),
            challenge.description.as_deref(),
        ),
        &[resource_url],
    );
    let intent = crate::keystore::AuthIntent::authorize_payment_details(
        &amount,
        &prompt_context.reason,
        &prompt_context.operator,
    );

    let challenge_network = request
        .method_details
        .as_ref()
        .and_then(|v| v.get("network"))
        .and_then(|v| v.as_str())
        .unwrap_or("mainnet")
        .to_string();
    let challenge_network = normalize_network(&challenge_network).to_string();
    let embedded_blockhash = request
        .method_details
        .as_ref()
        .and_then(|v| v.get("recentBlockhash"))
        .and_then(|v| v.as_str());

    // Client-side network intent check: refuse to sign if the user
    // explicitly forced a network slug via `--sandbox`/`--mainnet` and
    // the server's challenge advertises a different one. Better to
    // abort here with a clear error than to sign a credential that
    // either gets rejected by the verifier or — worse — somehow
    // succeeds against the wrong cluster.
    check_client_network_intent(network_override, &challenge_network, embedded_blockhash)?;

    // Auto-funding via Surfpool runs when the user explicitly opted into
    // sandbox (`--sandbox`/`--local`) OR when the challenge embeds a
    // Surfpool blockhash — meaning we hit a sandbox gateway without a flag.
    // The `surfnet_setTokenAccount` cheatcode is required to properly
    // initialize token accounts in surfpool's local state; JIT-fetched
    // accounts from mainnet are read-only and fail simulation.
    let user_opted_into_sandbox = should_auto_fund_surfpool(network_override, embedded_blockhash);
    let network = network_override
        .map(str::to_string)
        .unwrap_or(challenge_network);

    let (signer, ephemeral_notice) =
        crate::signer::load_signer_for_network_payment_with_intent_and_override(
            &network,
            store,
            account_override,
            &amount,
            &intent,
            auth_override,
        )?;

    let rpc_url = resolve_rpc_url(&network, embedded_blockhash);
    let rpc = RpcClient::new(rpc_url.clone());

    info!(
        amount = %request.amount,
        currency = %request.currency,
        network = %network,
        %rpc_url,
        signer = %signer.pubkey(),
        "Building MPP credential"
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;

    // Auto-fund when in sandbox mode. We fund on every call (idempotent)
    // because Surfpool requires `surfnet_setTokenAccount` to properly
    // initialize token accounts — JIT-fetched accounts from mainnet
    // fail simulation without it.
    if user_opted_into_sandbox {
        let pubkey = signer.pubkey().to_string();
        let fund_url = rpc_url.clone();
        if let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(
            &fund_url, &pubkey,
        )) {
            warn!(error = %e, "Could not auto-fund ephemeral via Surfpool — broadcast may fail if wallet is empty");
        }
    }

    let header = rt
        .block_on(build_credential_header(&signer, &rpc, challenge))
        .map_err(|e| Error::Mpp(format!("Failed to build credential: {e}")))?;

    Ok((header, ephemeral_notice))
}

/// Select a stablecoin charge challenge the configured wallet can actually pay.
///
/// If balances cannot be fetched, the first stablecoin Solana charge challenge is
/// returned so older payment paths continue to work. If balances are known and
/// none of the advertised currencies is funded enough, payment is rejected
/// before the client signs anything.
pub fn select_challenge_by_balance<'a>(
    challenges: &'a [Challenge],
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> Result<Option<&'a Challenge>> {
    let candidates = decoded_charge_candidates(challenges, network_override)?;
    let Some(first) = candidates.first() else {
        return Ok(None);
    };

    let network = normalize_network(&first.network);
    let pubkey = match account_pubkey_for_network(store, network, account_override)? {
        Some(pubkey) => pubkey,
        None => return Ok(Some(&challenges[first.index])),
    };

    let rpc_url = resolve_rpc_url(&first.network, first.embedded_blockhash.as_deref());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;

    if first.user_opted_into_sandbox
        && let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(&rpc_url, &pubkey))
    {
        warn!(error = %e, "Could not auto-fund wallet via Surfpool before challenge selection");
    }

    let balances = match rt.block_on(crate::client::balance::get_stablecoin_balances(
        &rpc_url, &pubkey,
    )) {
        Ok(balances) => balances,
        Err(e) => {
            warn!(error = %e, %rpc_url, %pubkey, "Could not fetch balances for MPP challenge selection");
            return Ok(Some(&challenges[first.index]));
        }
    };

    if let Some(index) = select_candidate_index_for_balances(&candidates, &balances) {
        let selected = &candidates[index];
        info!(
            currency = %selected.currency,
            amount = selected.amount,
            network = %selected.network,
            pubkey = %pubkey,
            "Selected MPP challenge based on wallet balance"
        );
        return Ok(Some(&challenges[selected.index]));
    }

    Err(Error::PaymentRejected(format!(
        "wallet `{pubkey}` does not have enough balance on `{network}` for any advertised MPP challenge"
    )))
}

/// A payment option chosen across both protocols by [`choose_payment`].
pub enum ChosenPayment {
    /// Settle via an MPP charge challenge.
    Mpp(Box<Challenge>),
    /// Settle via the x402 `exact` alternative advertised on the same 402.
    X402(Box<crate::client::x402::Challenge>),
    /// Settle via the x402 `upto` alternative advertised on the same 402.
    X402Upto(Box<crate::client::x402::UptoChallenge>),
}

/// Choose how to pay a 402, across *both* MPP charge challenges and an x402
/// alternative, by what the wallet can actually fund.
///
/// This is the balance-aware, cross-protocol replacement for
/// [`select_challenge_by_balance`]: it builds the funded-token set from the
/// wallet's on-chain stablecoin balances and delegates ranking to
/// [`pay_kit::select_payment_parsed`] (default strategy:
/// [`HighestBalance`](pay_kit::OrderingStrategy::HighestBalance)). This
/// is what lets a wallet holding only USDC settle a USDC x402 offer even when
/// the server's MPP challenge is denominated in a coin the wallet doesn't hold.
///
/// Falls back to the first MPP challenge (legacy behavior) when balances can't
/// be fetched or no wallet exists for the network, so older paths keep working.
pub fn choose_payment(
    mpp_challenges: &[Challenge],
    x402_alternative: Option<&crate::client::x402::Challenge>,
    x402_upto_accepts: &[pay_kit::x402::upto::UptoRequirements],
    store: &dyn AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> Result<ChosenPayment> {
    let candidates = decoded_charge_candidates(mpp_challenges, network_override)?;

    // Network/RPC come from the first decodable MPP charge. With no decodable
    // MPP candidate, honor an x402 alternative (exact preferred, else the first
    // advertised upto — balance-aware ranking needs an MPP network to fetch
    // against, so this degenerate path settles the first offered upto).
    let Some(first) = candidates.first() else {
        if let Some(c) = x402_alternative.cloned() {
            return Ok(ChosenPayment::X402(Box::new(c)));
        }
        if let Some(requirements) = x402_upto_accepts.first() {
            return Ok(ChosenPayment::X402Upto(Box::new(
                crate::client::x402::UptoChallenge {
                    requirements: requirements.clone(),
                },
            )));
        }
        return Err(Error::Mpp("No usable payment challenge".to_string()));
    };

    let legacy_first_mpp =
        || ChosenPayment::Mpp(Box::new(mpp_challenges[candidates[0].index].clone()));

    let network = normalize_network(&first.network);
    let pubkey = match account_pubkey_for_network(store, network, account_override)? {
        Some(pubkey) => pubkey,
        None => return Ok(legacy_first_mpp()),
    };

    let rpc_url = resolve_rpc_url(&first.network, first.embedded_blockhash.as_deref());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create runtime: {e}")))?;

    if first.user_opted_into_sandbox
        && let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(&rpc_url, &pubkey))
    {
        warn!(error = %e, "Could not auto-fund wallet via Surfpool before payment selection");
    }

    let balances = match rt.block_on(crate::client::balance::get_stablecoin_balances(
        &rpc_url, &pubkey,
    )) {
        Ok(balances) => balances,
        Err(e) => {
            warn!(error = %e, %rpc_url, %pubkey, "Could not fetch balances for payment selection");
            return Ok(legacy_first_mpp());
        }
    };

    // The wallet's spendable stablecoins become the (mint, network, available)
    // preference set. pay-kit normalizes advertised currencies to mints with
    // the same registry, so both sides speak mint addresses.
    let funded: Vec<pay_kit::AcceptableToken> = balances
        .tokens
        .iter()
        .map(|t| pay_kit::AcceptableToken {
            mint: t.mint.clone(),
            network: network.to_string(),
            available: t.raw_amount,
        })
        .collect();

    let x402_accepts: Vec<pay_kit::x402::exact::PaymentRequirements> = x402_alternative
        .map(|c| c.requirements.clone())
        .into_iter()
        .collect();
    // Cost-first across all three schemes; `CheapestPayable` ties break to MPP
    // (native one-shot), then upto, then exact — see `select`'s `Source::rank`.
    match pay_kit::select_payment_parsed_all(
        mpp_challenges,
        &x402_accepts,
        x402_upto_accepts,
        &funded,
        &pay_kit::OrderingStrategy::CheapestPayable,
    ) {
        Ok(pay_kit::SelectedPayment::MppCharge { challenge, .. }) => {
            Ok(ChosenPayment::Mpp(challenge))
        }
        Ok(pay_kit::SelectedPayment::X402Exact { .. }) => x402_alternative
            .cloned()
            .map(|c| ChosenPayment::X402(Box::new(c)))
            .ok_or_else(|| Error::Mpp("x402 exact selected but no challenge available".into())),
        // The router picks the specific upto currency; build that one.
        Ok(pay_kit::SelectedPayment::X402Upto { requirement, .. }) => Ok(ChosenPayment::X402Upto(
            Box::new(crate::client::x402::UptoChallenge {
                requirements: *requirement,
            }),
        )),
        Err(e) => Err(Error::PaymentRejected(e.to_string())),
    }
}

#[derive(Debug, Clone)]
struct DecodedChargeCandidate {
    index: usize,
    amount: u64,
    currency: String,
    mint: String,
    network: String,
    embedded_blockhash: Option<String>,
    user_opted_into_sandbox: bool,
}

fn decoded_charge_candidates(
    challenges: &[Challenge],
    network_override: Option<&str>,
) -> Result<Vec<DecodedChargeCandidate>> {
    let mut candidates = Vec::new();

    for (index, challenge) in challenges.iter().enumerate() {
        if !pay_kit::mpp::client::is_solana_charge_challenge(challenge) {
            continue;
        }

        let request: ChargeRequest = challenge
            .request
            .decode()
            .map_err(|e| Error::Mpp(format!("Failed to decode challenge request: {e}")))?;
        let details: pay_kit::mpp::protocol::solana::MethodDetails = request
            .method_details
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| Error::Mpp(format!("Failed to decode Solana method details: {e}")))?
            .unwrap_or_default();

        let challenge_network = details
            .network
            .clone()
            .unwrap_or_else(|| "mainnet".to_string());
        let challenge_network = normalize_network(&challenge_network).to_string();
        if let Some(forced) = network_override {
            if forced != challenge_network {
                continue;
            }
            check_client_network_intent(
                Some(forced),
                &challenge_network,
                details.recent_blockhash.as_deref(),
            )?;
        }

        let network = network_override
            .map(str::to_string)
            .unwrap_or(challenge_network);
        let Some(mint) = resolve_challenge_mint(&request.currency, &network) else {
            continue;
        };
        let embedded_blockhash = details.recent_blockhash;
        let user_opted_into_sandbox =
            should_auto_fund_surfpool(network_override, embedded_blockhash.as_deref());

        candidates.push(DecodedChargeCandidate {
            index,
            amount: request
                .amount
                .parse()
                .map_err(|_| Error::Mpp(format!("Invalid challenge amount: {}", request.amount)))?,
            currency: request.currency,
            mint,
            network,
            embedded_blockhash,
            user_opted_into_sandbox,
        });
    }

    Ok(candidates)
}

fn resolve_challenge_mint(currency: &str, network: &str) -> Option<String> {
    if currency.eq_ignore_ascii_case("SOL") {
        return None;
    }
    if let Some(stablecoin) = Stablecoin::parse_symbol(currency) {
        return Some(stablecoin.mint(Some(network)).to_string());
    }
    if Stablecoin::from_mint(currency).is_some() {
        return Some(currency.to_string());
    }
    pay_kit::mpp::protocol::solana::resolve_stablecoin_mint(currency, Some(network))
        .map(str::to_string)
}

fn select_candidate_index_for_balances(
    candidates: &[DecodedChargeCandidate],
    balances: &crate::client::balance::AccountBalances,
) -> Option<usize> {
    candidates
        .iter()
        .position(|candidate| has_sufficient_balance(candidate, balances))
}

fn has_sufficient_balance(
    candidate: &DecodedChargeCandidate,
    balances: &crate::client::balance::AccountBalances,
) -> bool {
    balances
        .tokens
        .iter()
        .any(|token| token.mint == candidate.mint && token.raw_amount >= candidate.amount)
}

fn account_pubkey_for_network(
    store: &dyn AccountsStore,
    network: &str,
    account_override: Option<&str>,
) -> Result<Option<String>> {
    let file = store.load()?;
    if let Some(name) = account_override {
        return Ok(file
            .named_account_for_network(network, name)
            .and_then(|account| account.pubkey.clone()));
    }

    match resolve_account_for_network(network, &file) {
        AccountChoice::Resolved { account, .. } => Ok(account.pubkey),
        AccountChoice::Missing => Ok(None),
    }
}

fn resolve_rpc_url(network: &str, embedded_blockhash: Option<&str>) -> String {
    std::env::var("PAY_RPC_URL").unwrap_or_else(|_| {
        if network == "localnet"
            && embedded_blockhash.is_some_and(|h| h.starts_with(SURFPOOL_BLOCKHASH_PREFIX))
        {
            crate::config::SANDBOX_RPC_URL.to_string()
        } else {
            default_rpc_url(network).to_string()
        }
    })
}

fn normalize_network(network: &str) -> &str {
    match network {
        "mainnet-beta" => "mainnet",
        other => other,
    }
}

pub(crate) fn should_auto_fund_surfpool(
    network_override: Option<&str>,
    embedded_blockhash: Option<&str>,
) -> bool {
    network_override.is_some_and(is_sandbox_network)
        || embedded_blockhash.is_some_and(|hash| hash.starts_with(SURFPOOL_BLOCKHASH_PREFIX))
}

fn is_sandbox_network(network: &str) -> bool {
    matches!(normalize_network(network), "localnet" | "sandbox")
}

fn charge_prompt_reason<'a>(
    request_description: Option<&'a str>,
    challenge_description: Option<&'a str>,
) -> Option<&'a str> {
    request_description.or(challenge_description)
}

/// Base58 prefix that the Surfpool sandbox embeds in every blockhash it
/// returns. The same constant lives in the SDK's server-side check; we
/// duplicate it here so the client doesn't pull in a server-only feature.
pub const SURFPOOL_BLOCKHASH_PREFIX: &str = "SURFNETxSAFEHASH";

/// Pure check: refuse to sign a credential when the user explicitly
/// forced a network slug (via `--sandbox`/`--mainnet`) but the server's
/// challenge advertises a different one.
///
/// Two failure modes:
///
/// 1. **Slug mismatch** — the user said `--sandbox` (forces `localnet`)
///    but the server's `methodDetails.network` says `mainnet`. The user
///    is trying to pay a real-money endpoint with a sandbox flag — abort.
///
/// 2. **Embedded-blockhash mismatch** — the user forced `localnet` AND
///    the slug agrees, but the server pre-fetched a non-Surfpool
///    blockhash and embedded it in the challenge. That means the server
///    is on a *different* localnet (real `solana-test-validator`, not
///    Surfpool). Signing against it would build a tx with a non-sandbox
///    blockhash, which contradicts the user's `--sandbox` intent.
///
/// Returns `Ok(())` if no override is set (the no-flag default behavior
/// trusts the challenge). Returns `Err(Error::PaymentRejected)` so the
/// CLI renders the result through the existing `Payment rejected by
/// verifier` notice.
pub(crate) fn check_client_network_intent(
    network_override: Option<&str>,
    challenge_network: &str,
    embedded_blockhash: Option<&str>,
) -> Result<()> {
    let Some(forced) = network_override else {
        return Ok(());
    };
    if forced != challenge_network {
        return Err(Error::PaymentRejected(format!(
            "you forced network `{forced}` but the server expects `{challenge_network}`. \
             Drop the flag, or talk to a server that's on `{forced}`."
        )));
    }
    // Even when slugs match, defend against the case where the server
    // pre-fetches a blockhash from a non-Surfpool localnet RPC. The
    // user said `--sandbox`, so the embedded blockhash must look like
    // a Surfpool blockhash.
    if forced == "localnet"
        && let Some(hash) = embedded_blockhash
        && !hash.starts_with(SURFPOOL_BLOCKHASH_PREFIX)
    {
        return Err(Error::PaymentRejected(format!(
            "--sandbox/--local expects a Surfpool localnet but the server's \
             challenge embeds blockhash `{hash}`, which does not start with \
             the Surfpool prefix `{SURFPOOL_BLOCKHASH_PREFIX}`. The server is \
             on a different localnet."
        )));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // 1000000 = 1.0 USDC
        assert_eq!(format_amount("1000000", "USDC"), "$1.00");
    }

    #[test]
    fn format_amount_usdc_with_fee_fraction() {
        assert_eq!(format_amount("1001500", "USDC"), "$1.0015");
    }

    #[test]
    fn format_amount_sol() {
        // 1000000000 = 1.0 SOL
        assert_eq!(format_amount("1000000000", "SOL"), "$1.00");
    }

    #[test]
    fn format_amount_zero() {
        assert_eq!(format_amount("0", "USDC"), "$0");
    }

    #[test]
    fn format_amount_invalid() {
        assert_eq!(format_amount("not_a_number", "USDC"), "$0");
    }

    #[test]
    fn format_amount_sol_small() {
        // 1000000 lamports = 0.001 SOL
        assert_eq!(format_amount("1000000", "SOL"), "$0.001");
    }

    #[test]
    fn parse_returns_none_for_invalid() {
        assert!(parse("not a valid header").is_none());
    }

    fn challenge_for_currency(currency: &str, amount: &str) -> Challenge {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "amount": amount,
            "currency": currency,
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": { "network": "mainnet" }
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let header = format!(
            "Payment id=\"{currency}\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
        );
        parse(&header).unwrap()
    }

    #[test]
    fn parse_all_extracts_repeated_stablecoin_payment_challenges() {
        let usdc =
            pay_kit::mpp::format_www_authenticate(&challenge_for_currency("USDC", "1000000"))
                .unwrap();
        let cash =
            pay_kit::mpp::format_www_authenticate(&challenge_for_currency("CASH", "1000000"))
                .unwrap();
        let usdt =
            pay_kit::mpp::format_www_authenticate(&challenge_for_currency("USDT", "1000000"))
                .unwrap();

        let parsed = parse_all([usdc.as_str(), cash.as_str(), usdt.as_str()]);
        assert_eq!(parsed.len(), 3);
        let currencies: Vec<String> = parsed
            .into_iter()
            .map(|challenge| {
                let request: ChargeRequest = challenge.request.decode().unwrap();
                request.currency
            })
            .collect();
        assert_eq!(currencies, ["USDC", "CASH", "USDT"]);
    }

    fn token_balance(
        mint: &str,
        raw_amount: u64,
        symbol: &'static str,
    ) -> crate::client::balance::TokenBalance {
        crate::client::balance::TokenBalance {
            mint: mint.to_string(),
            raw_amount,
            ui_amount: raw_amount as f64 / 1_000_000.0,
            symbol: Some(symbol.to_string()),
        }
    }

    #[test]
    fn decoded_charge_candidates_skip_sol_challenges() {
        let challenges = vec![
            challenge_for_currency("SOL", "1000000000"),
            challenge_for_currency("USDC", "1000000"),
        ];
        let candidates = decoded_charge_candidates(&challenges, None).unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].currency, "USDC");
        assert_eq!(
            candidates[0].mint.as_str(),
            pay_kit::mpp::protocol::solana::mints::USDC_MAINNET
        );
    }

    #[test]
    fn balance_selector_picks_first_funded_currency() {
        let challenges = vec![
            challenge_for_currency("USDC", "1000000"),
            challenge_for_currency("USDT", "1000000"),
        ];
        let candidates = decoded_charge_candidates(&challenges, None).unwrap();
        let balances = crate::client::balance::AccountBalances {
            sol_lamports: 0,
            tokens: vec![token_balance(
                pay_kit::mpp::protocol::solana::mints::USDT_MAINNET,
                2_000_000,
                "USDT",
            )],
            tokens_unavailable: false,
        };

        let selected = select_candidate_index_for_balances(&candidates, &balances).unwrap();
        assert_eq!(candidates[selected].currency, "USDT");
    }

    #[test]
    fn balance_selector_resolves_usdg_symbol_to_supported_mint() {
        let challenges = vec![challenge_for_currency("USDG", "1000000")];
        let candidates = decoded_charge_candidates(&challenges, None).unwrap();
        let balances = crate::client::balance::AccountBalances {
            sol_lamports: 0,
            tokens: vec![token_balance(
                pay_types::stablecoin_mints::USDG_MAINNET,
                1_000_000,
                "USDG",
            )],
            tokens_unavailable: false,
        };

        let selected = select_candidate_index_for_balances(&candidates, &balances).unwrap();
        assert_eq!(candidates[selected].currency, "USDG");
        assert_eq!(
            candidates[selected].mint.as_str(),
            pay_types::stablecoin_mints::USDG_MAINNET
        );
    }

    #[test]
    fn balance_selector_picks_cash_from_usdc_cash_usdt_when_cash_is_first_funded() {
        let challenges = vec![
            challenge_for_currency("USDC", "1000000"),
            challenge_for_currency("CASH", "1000000"),
            challenge_for_currency("USDT", "1000000"),
        ];
        let candidates = decoded_charge_candidates(&challenges, None).unwrap();
        let balances = crate::client::balance::AccountBalances {
            sol_lamports: 0,
            tokens: vec![
                token_balance(
                    pay_kit::mpp::protocol::solana::mints::USDC_MAINNET,
                    999_999,
                    "USDC",
                ),
                token_balance(
                    pay_kit::mpp::protocol::solana::mints::CASH_MAINNET,
                    1_000_000,
                    "CASH",
                ),
                token_balance(
                    pay_kit::mpp::protocol::solana::mints::USDT_MAINNET,
                    5_000_000,
                    "USDT",
                ),
            ],
            tokens_unavailable: false,
        };

        let selected = select_candidate_index_for_balances(&candidates, &balances).unwrap();
        assert_eq!(candidates[selected].currency, "CASH");
    }

    #[test]
    fn balance_selector_skips_underfunded_cash_and_picks_usdt() {
        let challenges = vec![
            challenge_for_currency("USDC", "1000000"),
            challenge_for_currency("CASH", "1000000"),
            challenge_for_currency("USDT", "1000000"),
        ];
        let candidates = decoded_charge_candidates(&challenges, None).unwrap();
        let balances = crate::client::balance::AccountBalances {
            sol_lamports: 0,
            tokens: vec![
                token_balance(
                    pay_kit::mpp::protocol::solana::mints::USDC_MAINNET,
                    999_999,
                    "USDC",
                ),
                token_balance(
                    pay_kit::mpp::protocol::solana::mints::CASH_MAINNET,
                    999_999,
                    "CASH",
                ),
                token_balance(
                    pay_kit::mpp::protocol::solana::mints::USDT_MAINNET,
                    1_000_000,
                    "USDT",
                ),
            ],
            tokens_unavailable: false,
        };

        let selected = select_candidate_index_for_balances(&candidates, &balances).unwrap();
        assert_eq!(candidates[selected].currency, "USDT");
    }

    #[test]
    fn balance_selector_returns_none_when_no_currency_is_funded() {
        let challenges = vec![
            challenge_for_currency("USDC", "1000000"),
            challenge_for_currency("USDT", "1000000"),
        ];
        let candidates = decoded_charge_candidates(&challenges, None).unwrap();
        let balances = crate::client::balance::AccountBalances {
            sol_lamports: 0,
            tokens: vec![token_balance(
                pay_kit::mpp::protocol::solana::mints::USDT_MAINNET,
                999_999,
                "USDT",
            )],
            tokens_unavailable: false,
        };

        assert!(select_candidate_index_for_balances(&candidates, &balances).is_none());
    }

    // ── check_client_network_intent ────────────────────────────────────────
    //
    // Pure function — covers every quadrant of (override, challenge_network,
    // embedded_blockhash) plus a few edge cases.

    fn must_err(r: Result<()>) -> String {
        match r {
            Ok(()) => panic!("expected Err, got Ok"),
            Err(Error::PaymentRejected(s)) => s,
            Err(other) => panic!("expected PaymentRejected, got {other:?}"),
        }
    }

    #[test]
    fn intent_check_passes_when_no_override() {
        // Without an explicit flag, the client trusts whatever the
        // challenge says. Both slug-mismatch and weird-blockhash
        // scenarios are accepted.
        assert!(check_client_network_intent(None, "mainnet", None).is_ok());
        assert!(check_client_network_intent(None, "localnet", Some("anything")).is_ok());
        assert!(check_client_network_intent(None, "mainnet", Some("9zrUHnA1nCByPksy")).is_ok());
    }

    #[test]
    fn intent_check_passes_when_override_matches_slug() {
        assert!(check_client_network_intent(Some("mainnet"), "mainnet", None).is_ok());
        assert!(
            check_client_network_intent(
                Some("localnet"),
                "localnet",
                Some("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad")
            )
            .is_ok()
        );
        // Forced localnet with no embedded blockhash → accept (the
        // client will fetch one from its own RPC).
        assert!(check_client_network_intent(Some("localnet"), "localnet", None).is_ok());
    }

    #[test]
    fn intent_check_rejects_sandbox_against_mainnet_server() {
        // The user-reported scenario: `pay --sandbox curl ...` against
        // a server with `network: mainnet`. Must abort BEFORE signing
        // with a clear "you forced X but server expects Y" message.
        let msg = must_err(check_client_network_intent(
            Some("localnet"),
            "mainnet",
            Some("9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F"),
        ));
        assert!(msg.contains("forced"), "missing forced-side: {msg}");
        assert!(msg.contains("`localnet`"), "missing forced network: {msg}");
        assert!(msg.contains("`mainnet`"), "missing server network: {msg}");
    }

    #[test]
    fn intent_check_rejects_mainnet_flag_against_sandbox_server() {
        // Reverse: --mainnet against a localnet server.
        let msg = must_err(check_client_network_intent(
            Some("mainnet"),
            "localnet",
            Some("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad"),
        ));
        assert!(msg.contains("`mainnet`"));
        assert!(msg.contains("`localnet`"));
    }

    #[test]
    fn intent_check_rejects_sandbox_with_non_surfpool_blockhash() {
        // Both sides agree on `localnet` slug, but the server pre-
        // fetched a non-Surfpool blockhash. The user explicitly said
        // `--sandbox`, so the server must be on Surfpool — abort.
        let msg = must_err(check_client_network_intent(
            Some("localnet"),
            "localnet",
            Some("9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F"),
        ));
        assert!(
            msg.contains("Surfpool"),
            "missing Surfpool reference: {msg}"
        );
        assert!(
            msg.contains(SURFPOOL_BLOCKHASH_PREFIX),
            "missing prefix: {msg}"
        );
    }

    #[test]
    fn intent_check_accepts_sandbox_with_surfpool_blockhash() {
        // Happy path: --sandbox + localnet challenge + Surfpool-prefixed
        // embedded blockhash. Pin the design intent.
        assert!(
            check_client_network_intent(
                Some("localnet"),
                "localnet",
                Some("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx1892bcad"),
            )
            .is_ok()
        );
    }

    #[test]
    fn intent_check_does_not_check_blockhash_for_non_localnet_overrides() {
        // The blockhash check only applies when forcing localnet.
        // Forcing mainnet against a mainnet server with any embedded
        // blockhash should pass.
        assert!(
            check_client_network_intent(Some("mainnet"), "mainnet", Some("anything-goes-here"))
                .is_ok()
        );
    }

    #[test]
    fn intent_check_partial_prefix_does_not_satisfy_sandbox_requirement() {
        // "SURFNETx" alone (8 chars) is NOT the full prefix.
        let msg = must_err(check_client_network_intent(
            Some("localnet"),
            "localnet",
            Some("SURFNETxNotARealHash"),
        ));
        assert!(msg.contains(SURFPOOL_BLOCKHASH_PREFIX));
    }

    // ── Surfpool detection & RPC fallback ─────────────────────────────────
    //
    // Tests for the auto-detection of sandbox challenges via the embedded
    // Surfpool blockhash prefix. Covers:
    // - `user_opted_into_sandbox` derivation
    // - RPC URL fallback to SANDBOX_RPC_URL
    // - Behavior with and without `--sandbox` flag

    fn surfpool_hash() -> &'static str {
        "SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx18b8dc98"
    }

    fn mainnet_hash() -> &'static str {
        "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F"
    }

    fn is_sandbox(network_override: Option<&str>, embedded_blockhash: Option<&str>) -> bool {
        should_auto_fund_surfpool(network_override, embedded_blockhash)
    }

    #[test]
    fn charge_prompt_reason_prefers_request_description() {
        assert_eq!(
            charge_prompt_reason(Some("Send 1 USDC to address abc"), Some("API access")),
            Some("Send 1 USDC to address abc")
        );
        assert_eq!(
            charge_prompt_reason(None, Some("API access")),
            Some("API access")
        );
    }

    /// Helper: compute RPC URL using the same logic as `build_credential`.
    fn resolve_rpc(
        network: &str,
        embedded_blockhash: Option<&str>,
        pay_rpc_url: Option<&str>,
    ) -> String {
        if let Some(url) = pay_rpc_url {
            url.to_string()
        } else if network == "localnet"
            && embedded_blockhash.is_some_and(|h| h.starts_with(SURFPOOL_BLOCKHASH_PREFIX))
        {
            crate::config::SANDBOX_RPC_URL.to_string()
        } else {
            default_rpc_url(network).to_string()
        }
    }

    // ── user_opted_into_sandbox detection ──

    #[test]
    fn sandbox_detected_with_explicit_flag() {
        // --sandbox sets network_override = Some("localnet")
        assert!(is_sandbox(Some("localnet"), None));
        assert!(is_sandbox(Some("localnet"), Some(surfpool_hash())));
    }

    #[test]
    fn sandbox_not_detected_with_mainnet_flag() {
        assert!(!is_sandbox(Some("mainnet"), None));
    }

    #[test]
    fn sandbox_detected_via_surfpool_blockhash_without_flag() {
        // No flag but challenge has surfpool blockhash → sandbox
        assert!(is_sandbox(None, Some(surfpool_hash())));
    }

    #[test]
    fn sandbox_not_detected_without_flag_or_surfpool() {
        // No flag, mainnet blockhash → not sandbox
        assert!(!is_sandbox(None, None));
        assert!(!is_sandbox(None, Some(mainnet_hash())));
    }

    #[test]
    fn sandbox_not_detected_with_partial_surfpool_prefix() {
        // Partial prefix doesn't count
        assert!(!is_sandbox(None, Some("SURFNETxNotTheRealPrefix")));
    }

    // ── RPC URL resolution ──

    #[test]
    fn rpc_uses_env_var_when_set() {
        let url = resolve_rpc(
            "localnet",
            Some(surfpool_hash()),
            Some("http://custom:8899"),
        );
        assert_eq!(url, "http://custom:8899");
    }

    #[test]
    fn rpc_falls_back_to_sandbox_for_surfpool_challenge() {
        let url = resolve_rpc("localnet", Some(surfpool_hash()), None);
        assert_eq!(url, crate::config::SANDBOX_RPC_URL);
    }

    #[test]
    fn rpc_falls_back_to_localhost_for_non_surfpool_localnet() {
        let url = resolve_rpc("localnet", Some(mainnet_hash()), None);
        assert_eq!(url, "http://localhost:8899");
    }

    #[test]
    fn rpc_falls_back_to_localhost_for_localnet_no_blockhash() {
        let url = resolve_rpc("localnet", None, None);
        assert_eq!(url, "http://localhost:8899");
    }

    #[test]
    fn rpc_falls_back_to_mainnet_for_mainnet_network() {
        let url = resolve_rpc("mainnet", None, None);
        assert_eq!(url, "https://api.mainnet-beta.solana.com");
    }

    #[test]
    fn rpc_falls_back_to_devnet_for_devnet_network() {
        let url = resolve_rpc("devnet", None, None);
        assert_eq!(url, "https://api.devnet.solana.com");
    }

    #[test]
    fn rpc_ignores_surfpool_blockhash_for_non_localnet() {
        // Even if blockhash looks like surfpool, non-localnet uses default
        let url = resolve_rpc("mainnet", Some(surfpool_hash()), None);
        assert_eq!(url, "https://api.mainnet-beta.solana.com");
    }
}
