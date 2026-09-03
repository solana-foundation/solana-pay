//! Pay-side helpers for the MPP `authenticate` intent (SIWMPP).
//!
//! Pairs with [`crate::server::authenticate`] on the server side: a
//! subscription-gated endpoint emits both a `subscription` and an
//! `authenticate` challenge in its 402 response, plus a fresh
//! `authenticate` challenge in the success response of a successful
//! activation. The helpers in this module let pay clients:
//!
//! - extract the authenticate challenge from a multi-WWW-Authenticate
//!   header set ([`pick_authenticate_challenge`]),
//! - sign a credential against it and persist the resulting
//!   `Authorization: Payment …` header for re-use across requests
//!   ([`sign_and_persist`]),
//! - look up a previously-cached header for a given resource URL
//!   ([`cached_header_for_resource`]).
//!
//! The runner / CLI surfaces that actually attach the header on
//! outgoing requests are wired separately; this module is the
//! self-contained protocol layer.

use std::sync::Arc;

use pay_kit::mpp::{
    PaymentChallenge, parse_www_authenticate,
    program::subscriptions::{default_program_id, find_subscription_pda, parse_pubkey},
    solana_keychain::SolanaSigner,
};

use crate::accounts::{AccountsStore, Subscription, SubscriptionStatus};
use crate::{Error, Result};

/// Pick the `authenticate`-intent challenge out of a 402 header set.
///
/// `www_auth_headers` is the raw set of `WWW-Authenticate` header
/// values returned by the server (RFC 7235 allows multiple).
/// Returns `Some(challenge)` for the first parseable challenge whose
/// `intent == "authenticate"`, `None` otherwise. Malformed entries
/// are skipped silently — the subscription challenge in the same
/// response is what the caller falls back to.
pub fn pick_authenticate_challenge<I, S>(www_auth_headers: I) -> Option<PaymentChallenge>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    www_auth_headers
        .into_iter()
        .filter_map(|h| parse_www_authenticate(h.as_ref()).ok())
        .find(|c| c.intent.as_str() == "authenticate")
}

/// Sign an authenticate credential against the given challenge and
/// persist it on the matching subscription record in `accounts.yml`.
///
/// `subscriber_pubkey` is the signing wallet's base58 pubkey; we
/// derive the SubscriptionDelegation PDA from `(plan_id, subscriber)`
/// and pass it through to the SDK's credential builder. The token's
/// expiration is read back from the challenge so the cached row's
/// `authenticate_expires_at` matches what the server will accept.
///
/// On success returns the `Authorization: Payment …` header value
/// the caller MAY attach to the immediate retry. The same value is
/// also written to `accounts.yml` for subsequent requests.
#[allow(clippy::too_many_arguments)]
pub async fn sign_and_persist(
    store: &dyn AccountsStore,
    network: &str,
    account_name: &str,
    subscription_id: &str,
    plan_id: &str,
    program_id_override: Option<&str>,
    challenge: &PaymentChallenge,
    signer: Arc<dyn SolanaSigner>,
) -> Result<String> {
    let plan_pubkey = parse_pubkey(plan_id, "plan_id")
        .map_err(|e| Error::Mpp(format!("Invalid plan_id: {e}")))?;
    let program_pubkey = match program_id_override {
        Some(p) => parse_pubkey(p, "program_id")
            .map_err(|e| Error::Mpp(format!("Invalid program_id: {e}")))?,
        None => default_program_id(),
    };
    let subscriber_pubkey = signer.pubkey();
    let (derived_pda, _) = find_subscription_pda(&plan_pubkey, &subscriber_pubkey, &program_pubkey);
    if derived_pda.to_string() != subscription_id {
        return Err(Error::Mpp(format!(
            "subscription_id `{subscription_id}` doesn't match the PDA derived from \
             plan_id + signer pubkey (`{derived_pda}`). The cached subscription is \
             bound to a different wallet."
        )));
    }

    let header = pay_kit::mpp::client::build_authenticate_credential_header(
        signer.as_ref(),
        challenge,
        subscription_id,
    )
    .await
    .map_err(|e| Error::Mpp(format!("Failed to build authenticate credential: {e}")))?;

    // Read the server-set expiration time straight off the challenge
    // request payload so the cache TTL matches the server's
    // `period_end` exactly.
    let request: pay_kit::mpp::AuthenticateRequest = challenge
        .request
        .decode()
        .map_err(|e| Error::Mpp(format!("Decoding authenticate request: {e}")))?;
    let expires_at = request.expiration_time;

    persist_token(
        store,
        network,
        account_name,
        subscription_id,
        &header,
        &expires_at,
    )?;
    Ok(header)
}

/// Write the cached token + expiry to the subscription's row in
/// `accounts.yml`. Idempotent; later calls overwrite earlier ones.
pub fn persist_token(
    store: &dyn AccountsStore,
    network: &str,
    account_name: &str,
    subscription_id: &str,
    token: &str,
    expires_at: &str,
) -> Result<()> {
    let mut file = store.load()?;
    let Some(sub) = file
        .accounts
        .get(network)
        .and_then(|m| m.get(account_name))
        .and_then(|a| a.subscriptions.get(subscription_id))
        .cloned()
    else {
        return Err(Error::Config(format!(
            "no subscription `{subscription_id}` on {network}/{account_name} to attach \
             an authenticate token to"
        )));
    };
    let mut updated = sub;
    updated.authenticate_token = Some(token.to_string());
    updated.authenticate_expires_at = Some(expires_at.to_string());
    file.upsert_subscription(network, account_name, updated)?;
    store.save(&file)
}

/// Look up a cached `Authorization: Payment …` header for the given
/// resource URL. Returns `Some(header)` when a tracked subscription
/// matches the URL AND has a non-expired token, `None` otherwise.
///
/// The URL match is prefix-based: a stored subscription's
/// `resource_url` matches any request URL that starts with it. This
/// covers both exact matches (`https://api.example.com/v1`) and
/// sub-paths (`https://api.example.com/v1/resource`).
pub fn cached_header_for_resource(store: &dyn AccountsStore, resource_url: &str) -> Option<String> {
    let file = store.load().ok()?;
    let now = chrono::Utc::now();
    for accounts in file.accounts.values() {
        for account in accounts.values() {
            for sub in account.subscriptions.values() {
                if !is_token_usable_for(sub, resource_url, now) {
                    continue;
                }
                if let Some(token) = sub.authenticate_token.as_deref() {
                    return Some(token.to_string());
                }
            }
        }
    }
    None
}

/// Decide whether `request_url` is the stored resource or a path
/// beneath it, with a hard boundary at the end of the stored URL.
///
/// Raw `starts_with` would treat `https://api.example.com.attacker.com/`
/// as a sub-resource of `https://api.example.com`, which would leak the
/// SIWMPP token to an attacker-controlled host. We require the byte
/// immediately following the stored URL to be a path/query/fragment
/// boundary (or end-of-string) so the host stays bound to what the
/// activation actually paid for.
fn url_is_sub_resource(request_url: &str, stored_url: &str) -> bool {
    let Some(suffix) = request_url.strip_prefix(stored_url) else {
        return false;
    };
    // Stored URL already ends with a boundary character → safe.
    if let Some(last) = stored_url.chars().last()
        && matches!(last, '/' | '?' | '#')
    {
        return true;
    }
    // Otherwise the FIRST char of the request URL past the stored
    // prefix must itself be a boundary, or there's no suffix at all
    // (exact match).
    match suffix.chars().next() {
        None => true,
        Some('/' | '?' | '#') => true,
        Some(_) => false,
    }
}

fn is_token_usable_for(
    sub: &Subscription,
    resource_url: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if !matches!(sub.status, SubscriptionStatus::Active) {
        return false;
    }
    let Some(token) = sub.authenticate_token.as_deref() else {
        return false;
    };
    if token.is_empty() {
        return false;
    }
    let Some(stored_url) = sub.resource_url.as_deref() else {
        return false;
    };
    if !url_is_sub_resource(resource_url, stored_url) {
        return false;
    }
    let Some(expires_at) = sub.authenticate_expires_at.as_deref() else {
        return false;
    };
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(t) => t.with_timezone(&chrono::Utc) > now,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{Account, AccountsFile, Keystore, MemoryAccountsStore};
    use std::collections::BTreeMap;

    fn make_sub(
        id: &str,
        resource_url: Option<&str>,
        token: Option<&str>,
        expires_at: Option<&str>,
        status: SubscriptionStatus,
    ) -> Subscription {
        Subscription {
            subscription_id: id.to_string(),
            plan_id: "Amp9FrnEX17tVeZ7QnHX1Hh4TynhH4sXLRSde797vdKR".to_string(),
            program_id: None,
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            currency: Some("USDC".to_string()),
            amount_per_period: "9990000".to_string(),
            period_unit: "day".to_string(),
            period_count: 30,
            recipient: "6ayEJCQB7gwzwdbWLi65DR9RTRTrS3QunK6j9h2WjQjW".to_string(),
            puller: "6ayEJCQB7gwzwdbWLi65DR9RTRTrS3QunK6j9h2WjQjW".to_string(),
            network: "mainnet".to_string(),
            status,
            activated_at: "2026-06-01T00:00:00Z".to_string(),
            activation_signature: String::new(),
            last_charged_period: Some(0),
            expires_at: None,
            resource_url: resource_url.map(str::to_string),
            description: None,
            authenticate_token: token.map(str::to_string),
            authenticate_expires_at: expires_at.map(str::to_string),
        }
    }

    fn store_with(sub: Subscription) -> MemoryAccountsStore {
        let mut subscriptions = BTreeMap::new();
        subscriptions.insert(sub.subscription_id.clone(), sub);
        let mut accounts_map = BTreeMap::new();
        accounts_map.insert(
            "default".to_string(),
            Account {
                keystore: Keystore::Ephemeral,
                provider: None,
                active: false,
                auth_required: Some(false),
                pubkey: Some("12YtVRbxyhBVceYVtALMeSyro5jTLEsqHgm78K721WH3".to_string()),
                vault: None,
                account: None,
                path: None,
                secret_key_b58: None,
                created_at: None,
                subscriptions,
            },
        );
        let mut accounts = BTreeMap::new();
        accounts.insert("mainnet".to_string(), accounts_map);
        let file = AccountsFile {
            version: 2,
            accounts,
        };
        MemoryAccountsStore::with_file(file)
    }

    #[test]
    fn cached_header_returns_token_when_url_prefix_matches_and_not_expired() {
        let token = "Payment eyJfYWtlfQ==";
        let expires = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let sub = make_sub(
            "DerivedPda",
            Some("https://api.example.com/v1"),
            Some(token),
            Some(&expires),
            SubscriptionStatus::Active,
        );
        let store = store_with(sub);
        let hit = cached_header_for_resource(&store, "https://api.example.com/v1/resource");
        assert_eq!(hit.as_deref(), Some(token));
    }

    #[test]
    fn cached_header_returns_none_when_token_expired() {
        let expired = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let sub = make_sub(
            "DerivedPda",
            Some("https://api.example.com/v1"),
            Some("Payment expired"),
            Some(&expired),
            SubscriptionStatus::Active,
        );
        let store = store_with(sub);
        assert!(cached_header_for_resource(&store, "https://api.example.com/v1").is_none());
    }

    #[test]
    fn cached_header_returns_none_when_status_not_active() {
        let expires = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let sub = make_sub(
            "DerivedPda",
            Some("https://api.example.com/v1"),
            Some("Payment ok"),
            Some(&expires),
            SubscriptionStatus::Cancelled,
        );
        let store = store_with(sub);
        assert!(cached_header_for_resource(&store, "https://api.example.com/v1").is_none());
    }

    #[test]
    fn cached_header_returns_none_when_url_does_not_match() {
        let expires = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let sub = make_sub(
            "DerivedPda",
            Some("https://api.example.com/v1"),
            Some("Payment ok"),
            Some(&expires),
            SubscriptionStatus::Active,
        );
        let store = store_with(sub);
        assert!(cached_header_for_resource(&store, "https://other.example.com/v1").is_none());
    }

    #[test]
    fn cached_header_rejects_hostname_suffix_attack() {
        // PR #374 security review: raw `starts_with` matches
        // `https://api.example.com.attacker.com/x` against stored
        // `https://api.example.com`. The boundary fix MUST reject
        // these even though the byte prefix matches.
        let expires = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let sub = make_sub(
            "DerivedPda",
            Some("https://api.example.com"),
            Some("Payment ok"),
            Some(&expires),
            SubscriptionStatus::Active,
        );
        let store = store_with(sub);
        assert!(
            cached_header_for_resource(&store, "https://api.example.com.attacker.com/x").is_none(),
            "hostname-suffix attack must be rejected"
        );
        // But a real sub-resource still matches.
        assert!(
            cached_header_for_resource(&store, "https://api.example.com/v1/resource").is_some()
        );
        // Exact match also OK.
        assert!(cached_header_for_resource(&store, "https://api.example.com").is_some());
        // Query / fragment past the host also OK.
        assert!(cached_header_for_resource(&store, "https://api.example.com?a=1").is_some());
        assert!(cached_header_for_resource(&store, "https://api.example.com#frag").is_some());
    }

    #[test]
    fn cached_header_returns_none_when_no_token_stored() {
        let sub = make_sub(
            "DerivedPda",
            Some("https://api.example.com/v1"),
            None,
            None,
            SubscriptionStatus::Active,
        );
        let store = store_with(sub);
        assert!(cached_header_for_resource(&store, "https://api.example.com/v1").is_none());
    }

    #[test]
    fn pick_authenticate_challenge_skips_subscription_challenge() {
        // Build two challenges via the SDK; pick should grab the
        // authenticate one regardless of header order.
        let sub_challenge = pay_kit::mpp::PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            "solana",
            "subscription",
            pay_kit::mpp::Base64UrlJson::from_typed(&pay_kit::mpp::SubscriptionRequest {
                amount: "1".into(),
                currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                period_unit: pay_kit::mpp::SubscriptionPeriodUnit::Day,
                period_count: "30".into(),
                recipient: "6ayEJCQB7gwzwdbWLi65DR9RTRTrS3QunK6j9h2WjQjW".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        let auth_challenge = pay_kit::mpp::PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            "solana",
            "authenticate",
            pay_kit::mpp::Base64UrlJson::from_typed(&pay_kit::mpp::AuthenticateRequest {
                domain: "api.example.com".into(),
                uri: "https://api.example.com/v1".into(),
                version: pay_kit::mpp::SIWMPP_VERSION.into(),
                nonce: "abc".into(),
                issued_at: "2026-06-01T00:00:00Z".into(),
                expiration_time: "2026-07-01T00:00:00Z".into(),
                ..Default::default()
            })
            .unwrap(),
        );

        let sub_h = pay_kit::mpp::format_www_authenticate(&sub_challenge).unwrap();
        let auth_h = pay_kit::mpp::format_www_authenticate(&auth_challenge).unwrap();

        let hit = pick_authenticate_challenge(vec![sub_h.clone(), auth_h.clone()])
            .expect("authenticate present");
        assert_eq!(hit.intent.as_str(), "authenticate");

        // Header order shouldn't matter.
        let hit = pick_authenticate_challenge(vec![auth_h, sub_h]).expect("present");
        assert_eq!(hit.intent.as_str(), "authenticate");
    }

    #[test]
    fn pick_authenticate_challenge_returns_none_when_only_subscription_present() {
        let sub_challenge = pay_kit::mpp::PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            "solana",
            "subscription",
            pay_kit::mpp::Base64UrlJson::from_typed(&pay_kit::mpp::SubscriptionRequest {
                amount: "1".into(),
                currency: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".into(),
                period_unit: pay_kit::mpp::SubscriptionPeriodUnit::Day,
                period_count: "30".into(),
                recipient: "6ayEJCQB7gwzwdbWLi65DR9RTRTrS3QunK6j9h2WjQjW".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        let h = pay_kit::mpp::format_www_authenticate(&sub_challenge).unwrap();
        assert!(pick_authenticate_challenge(vec![h]).is_none());
    }

    #[test]
    fn pick_authenticate_challenge_skips_malformed_entries() {
        let auth_challenge = pay_kit::mpp::PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            "solana",
            "authenticate",
            pay_kit::mpp::Base64UrlJson::from_typed(&pay_kit::mpp::AuthenticateRequest {
                domain: "api.example.com".into(),
                uri: "https://api.example.com/v1".into(),
                version: pay_kit::mpp::SIWMPP_VERSION.into(),
                nonce: "abc".into(),
                issued_at: "2026-06-01T00:00:00Z".into(),
                expiration_time: "2026-07-01T00:00:00Z".into(),
                ..Default::default()
            })
            .unwrap(),
        );
        let auth_h = pay_kit::mpp::format_www_authenticate(&auth_challenge).unwrap();

        let hit =
            pick_authenticate_challenge(vec!["not a www-authenticate header".to_string(), auth_h])
                .expect("authenticate present");
        assert_eq!(hit.intent.as_str(), "authenticate");
    }
}
