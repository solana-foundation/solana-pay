//! Openfort backend wallet support — remote signing via Openfort's API.
//!
//! The private key lives in Openfort's TEE and never exists locally. pay
//! stores only the project's API credentials (secret key + wallet secret)
//! as a credential blob in the platform secret store, gated by the same
//! auth path as local keypairs (Touch ID / Windows Hello / polkit).
//!
//! Because signing is a policy-checked HTTPS call, an Openfort account can
//! be constrained server-side (spend limits, allowed programs/mints) via
//! Openfort's policy engine — the credentials on this machine are
//! revocable and never sufficient to extract the key.
//!
//! The signer itself is `solana-keychain`'s [`OpenfortSigner`] (`openfort`
//! feature): it builds the ES256 `x-wallet-auth` JWT, calls
//! `POST /v2/accounts/backend/{id}/sign`, and verifies the returned
//! ed25519 signature against the address pinned at init. This module owns
//! what pay adds on top: credential storage and accounts.yml resolution.

pub use solana_keychain::OpenfortSigner;

use serde::{Deserialize, Serialize};
use solana_keychain::SolanaSigner;

use crate::accounts::Account;
use crate::keystore::AuthIntent;
use crate::signer::{AuthOverride, ResolvedSigner};
use crate::{Error, Result};

/// API credentials for an Openfort backend wallet, serialized as a JSON
/// credential blob in the platform secret store.
#[derive(Serialize, Deserialize)]
pub struct OpenfortCredentials {
    /// Project secret key (`sk_live_…` / `sk_test_…`).
    pub secret_key: String,
    /// ECDSA P-256 wallet secret (base64 PKCS#8 DER or PEM) that signs the
    /// `x-wallet-auth` JWT on each request.
    pub wallet_secret: String,
}

// ── Credential storage ──────────────────────────────────────────────────────

/// Build the platform secret store for Openfort credential blobs.
///
/// `gated` selects whether loads pass through the platform auth prompt;
/// `auth_override` (MCP elicitation) replaces the platform gate when
/// present, mirroring the keypair backends.
fn platform_keystore(
    gated: bool,
    auth_override: AuthOverride,
) -> Result<(crate::keystore::Keystore, &'static str)> {
    #[cfg(target_os = "macos")]
    {
        let ks = if gated {
            match auth_override {
                Some(gate) => crate::keystore::Keystore::from_boxed_auth(
                    gate,
                    Box::new(crate::keystore::macos::AppleKeychainStore),
                    true,
                ),
                None => crate::keystore::Keystore::apple_keychain(),
            }
        } else {
            crate::keystore::Keystore::new(
                crate::keystore::auth::NoAuth,
                crate::keystore::macos::AppleKeychainStore,
                false,
            )
        };
        Ok((ks, "keychain"))
    }
    #[cfg(target_os = "linux")]
    {
        let ks = if gated {
            match auth_override {
                Some(gate) => crate::keystore::Keystore::from_boxed_auth(
                    gate,
                    Box::new(crate::keystore::linux::SecretServiceStore),
                    true,
                ),
                None => crate::keystore::Keystore::gnome_keyring(),
            }
        } else {
            crate::keystore::Keystore::new(
                crate::keystore::auth::NoAuth,
                crate::keystore::linux::SecretServiceStore,
                false,
            )
        };
        Ok((ks, "gnome-keyring"))
    }
    #[cfg(target_os = "windows")]
    {
        let ks = if gated {
            match auth_override {
                Some(gate) => crate::keystore::Keystore::from_boxed_auth(
                    gate,
                    Box::new(crate::keystore::windows::WindowsCredentialStore),
                    true,
                ),
                None => crate::keystore::Keystore::windows_hello(),
            }
        } else {
            crate::keystore::Keystore::new(
                crate::keystore::auth::NoAuth,
                crate::keystore::windows::WindowsCredentialStore,
                false,
            )
        };
        Ok((ks, "windows-hello"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (gated, auth_override);
        Err(Error::Config(
            "Openfort accounts require a platform secret store (Keychain, GNOME Keyring, or \
             Windows Credential Manager), which is unavailable on this platform."
                .to_string(),
        ))
    }
}

/// Store credentials through an already-built platform keystore. The CLI
/// builds the keystore itself so setup-time gating fallbacks (e.g. no
/// enrolled Touch ID) stay in one place.
pub fn store_credentials(
    ks: &crate::keystore::Keystore,
    name: &str,
    credentials: &OpenfortCredentials,
    intent: &AuthIntent,
) -> Result<()> {
    let blob = serde_json::to_vec(credentials)
        .map_err(|e| Error::Config(format!("Failed to serialize Openfort credentials: {e}")))?;
    ks.import_credential_with_intent(name, &blob, intent)
        .map_err(|e| Error::Config(format!("Failed to store Openfort credentials: {e}")))
}

/// Check whether Openfort credentials exist for this account name in the
/// platform secret store. Never prompts.
pub fn credentials_exist(name: &str) -> bool {
    platform_keystore(false, None).is_ok_and(|(ks, _)| ks.credential_exists(name))
}

/// Delete the credential blob for this account name from the platform
/// secret store, passing through the platform auth prompt.
pub fn delete_credentials(name: &str, intent: &AuthIntent) -> Result<()> {
    let (ks, backend) = platform_keystore(true, None)?;
    ks.delete_credential_with_intent(name, intent)
        .map_err(|e| crate::signer::map_keystore_backend_error(backend, e))
}

fn load_credentials(
    name: &str,
    gated: bool,
    auth_override: AuthOverride,
    intent: &AuthIntent,
) -> Result<OpenfortCredentials> {
    let (ks, backend) = platform_keystore(gated, auth_override)?;
    if !ks.credential_exists(name) {
        return Err(Error::Config(format!(
            "No Openfort credentials stored for account `{name}`.\n\
             Run `pay account new {name} --backend openfort` to connect the backend wallet."
        )));
    }
    let blob = ks
        .load_credential_with_intent(name, intent)
        .map_err(|e| crate::signer::map_keystore_backend_error(backend, e))?;
    serde_json::from_slice(&blob).map_err(|e| {
        Error::Config(format!(
            "Stored Openfort credentials for `{name}` are corrupted ({e}). \
             Re-connect the wallet: `pay account destroy {name}` then \
             `pay account new {name} --backend openfort`."
        ))
    })
}

// ── Account resolution ──────────────────────────────────────────────────────

/// Build an initialized [`OpenfortSigner`] and return its Solana address
/// (base58). Used at setup time to validate credentials and cache the
/// address in `accounts.yml`.
pub fn fetch_wallet_address(credentials: &OpenfortCredentials, account_id: &str) -> Result<String> {
    let signer = build_signer(credentials, account_id)?;
    Ok(signer.pubkey().to_string())
}

/// Resolve an Openfort account into a ready-to-sign [`ResolvedSigner`].
///
/// Loads the credential blob (through the platform auth gate when the
/// account requires auth on this network), initializes the remote signer
/// (which fetches and pins the wallet's Solana address), and cross-checks
/// the address against the `pubkey` cached in `accounts.yml`.
///
/// Like the rest of the signer-resolution surface and the MPP/x402
/// payment builders, this is synchronous and blocks on network I/O
/// (it drives the init round-trip on an internal runtime). Callers
/// on async workers must isolate it with `tokio::task::spawn_blocking`
/// — the same contract the payer proxy and MCP tools already follow
/// for `build_credential` / `build_payment`.
pub fn load_openfort_signer(
    account: &Account,
    name: &str,
    network: &str,
    intent: &AuthIntent,
    auth_override: AuthOverride,
) -> Result<ResolvedSigner> {
    let account_id = account.account.clone().ok_or_else(|| {
        Error::Config(format!(
            "Openfort account `{name}` is missing its `account` field (the Openfort \
             account ID, `acc_…`) in accounts.yml."
        ))
    })?;

    let gated = account.auth_required_for_network(network);
    let account_intent = intent.with_account_context(name);
    let credentials = load_credentials(name, gated, auth_override, &account_intent)?;

    let signer = build_signer(&credentials, &account_id)?;

    let address = signer.pubkey().to_string();
    if let Some(expected) = account.pubkey.as_deref()
        && expected != address
    {
        return Err(Error::Config(format!(
            "Openfort account `{name}` resolves to address {address}, but accounts.yml \
             caches {expected}. The backend wallet behind `{account_id}` changed — \
             re-connect it: `pay account destroy {name}` then \
             `pay account new {name} --backend openfort`."
        )));
    }

    Ok(ResolvedSigner::Openfort(signer))
}

/// Build and initialize the remote signer (fetches the wallet address from
/// Openfort, validating the credentials in the process).
fn build_signer(credentials: &OpenfortCredentials, account_id: &str) -> Result<OpenfortSigner> {
    let mut signer = OpenfortSigner::new(
        credentials.secret_key.clone(),
        account_id.to_string(),
        credentials.wallet_secret.clone(),
    )
    .map_err(|e| Error::Config(format!("Invalid Openfort credentials for `{account_id}`: {e}")))?;

    // The payment client paths are synchronous and create their own tokio
    // runtimes for header building, so a throwaway current-thread runtime
    // for the init round-trip is safe here.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Config(format!("Failed to create runtime: {e}")))?;

    rt.block_on(signer.init()).map_err(|e| {
        Error::Config(format!(
            "Could not reach the Openfort backend wallet `{account_id}`: {e}.\n\
             Check the secret key, wallet secret, and account ID, and that the \
             account is on a Solana (SVM) chain."
        ))
    })?;
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Keystore as KeystoreKind;
    use std::collections::BTreeMap;

    fn openfort_account(account_id: Option<&str>, pubkey: Option<&str>) -> Account {
        Account {
            keystore: KeystoreKind::Openfort,
            active: false,
            auth_required: Some(false),
            pubkey: pubkey.map(str::to_string),
            vault: None,
            account: account_id.map(str::to_string),
            path: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: BTreeMap::new(),
        }
    }

    #[test]
    fn credentials_json_roundtrip() {
        let creds = OpenfortCredentials {
            secret_key: "sk_test_abc".to_string(),
            wallet_secret: "BASE64DER".to_string(),
        };
        let blob = serde_json::to_vec(&creds).unwrap();
        let back: OpenfortCredentials = serde_json::from_slice(&blob).unwrap();
        assert_eq!(back.secret_key, "sk_test_abc");
        assert_eq!(back.wallet_secret, "BASE64DER");
    }

    #[test]
    fn load_openfort_signer_requires_account_id() {
        let account = openfort_account(None, None);
        let err = load_openfort_signer(
            &account,
            "default",
            "mainnet",
            &AuthIntent::default_payment(),
            None,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(err.to_string().contains("missing its `account` field"));
    }

    #[test]
    fn store_credentials_roundtrip_through_keystore() {
        let ks = crate::keystore::Keystore::in_memory();
        let intent = AuthIntent::from_reason("test");
        let creds = OpenfortCredentials {
            secret_key: "sk_test_abc".to_string(),
            wallet_secret: "BASE64DER".to_string(),
        };

        store_credentials(&ks, "default", &creds, &intent).unwrap();
        assert!(ks.credential_exists("default"));

        let blob = ks.load_credential_with_intent("default", &intent).unwrap();
        let back: OpenfortCredentials = serde_json::from_slice(&blob).unwrap();
        assert_eq!(back.secret_key, "sk_test_abc");
    }
}
