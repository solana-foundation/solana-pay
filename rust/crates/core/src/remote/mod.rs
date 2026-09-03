//! Remote signing backends — wallets whose private key never reaches this
//! machine.
//!
//! A remote backend holds the key in a provider's custody (TEE, HSM, MPC)
//! and signs over HTTPS. pay stores only that provider's API credentials,
//! as a credential blob in the platform secret store, gated by the same
//! auth path as local keypairs (Touch ID / Windows Hello / polkit). The
//! credentials are revocable and never sufficient to extract the key.
//!
//! Everything in this module is provider-agnostic: credential storage,
//! the setup flow's prompting and wallet discovery, and accounts.yml
//! resolution. A provider supplies only what is genuinely specific to it
//! by implementing [`RemoteProvider`] — see `openfort.rs` for the
//! reference implementation, and [`provider`] for the registry a new
//! backend registers itself in.
//!
//! ## Adding a provider
//!
//! 1. Implement [`RemoteProvider`] in `remote/<name>.rs`, declaring the
//!    credentials it needs ([`CredentialField`]), how to list the wallets
//!    those credentials can sign with, and how to connect one.
//! 2. Add it to [`PROVIDERS`].
//!
//! Nothing else in pay changes: `accounts.yml` stores the provider as a
//! free-text `provider` field beside `keystore: remote`, the CLI prompts
//! from the declared fields, and `{PROVIDER}_{FIELD}` environment
//! variables work automatically. `solana-keychain` already ships signers
//! for a dozen custody providers, so an implementation is usually a thin
//! wrapper over one of those.

pub mod openfort;

use std::collections::BTreeMap;

use pay_kit::solana_keychain::SolanaSigner;

use crate::accounts::Account;
use crate::keystore::AuthIntent;
use crate::signer::{AuthOverride, ResolvedSigner};
use crate::{Error, Result};

/// The registered remote backends, by [`RemoteProvider::id`].
static PROVIDERS: &[&dyn RemoteProvider] = &[&openfort::Openfort];

/// Look up a backend by id (`openfort`), or `None` if unregistered.
pub fn provider(id: &str) -> Option<&'static dyn RemoteProvider> {
    PROVIDERS.iter().copied().find(|p| p.id() == id)
}

/// Every registered backend id, for CLI help and error messages.
pub fn provider_ids() -> Vec<&'static str> {
    providers().map(|p| p.id()).collect()
}

/// Every registered backend, for menus built from the registry.
pub fn providers() -> impl Iterator<Item = &'static dyn RemoteProvider> {
    PROVIDERS.iter().copied()
}

/// One credential a provider needs in order to sign — an API key, a
/// secret, a project id.
pub struct CredentialField {
    /// Storage key, also the environment-variable suffix: `secret_key`
    /// is read from `{PROVIDER}_SECRET_KEY`.
    pub key: &'static str,
    /// Prompt text shown during setup.
    pub label: &'static str,
    /// Whether input is masked and never echoed.
    pub secret: bool,
}

/// A wallet a provider's credentials can sign with.
pub struct RemoteWallet {
    /// Provider-side wallet id, stored in `accounts.yml` as `account`.
    pub id: String,
    /// The wallet's Solana address, base58.
    pub address: String,
}

/// A provider's credentials, keyed by [`CredentialField::key`].
pub type Credentials = BTreeMap<String, String>;

/// A remote signing backend.
///
/// Implementations are stateless descriptors: they declare what pay must
/// collect, then turn those credentials into wallet listings and signers.
/// Everything else — prompting, storage, the auth gate, accounts.yml — is
/// handled generically by this module.
pub trait RemoteProvider: Send + Sync {
    /// Stable id used by `--backend`, `accounts.yml`, and env vars.
    fn id(&self) -> &'static str;

    /// Human-readable name for CLI output ("Openfort backend wallet").
    fn display_name(&self) -> &'static str;

    /// The credentials to collect, in prompt order.
    fn credential_fields(&self) -> &'static [CredentialField];

    /// One line telling the user where to obtain the credentials.
    fn credentials_hint(&self) -> &'static str;

    /// Reject a malformed credential as soon as it is entered, so a typo
    /// costs one prompt rather than a failed round trip.
    fn validate_credential(&self, _key: &str, _value: &str) -> Result<()> {
        Ok(())
    }

    /// Reject a malformed wallet id supplied by flag or environment.
    fn validate_wallet_id(&self, _id: &str) -> Result<()> {
        Ok(())
    }

    /// List the Solana wallets these credentials can sign with.
    ///
    /// Called before the full credential set is collected when possible,
    /// so it doubles as an early check that the credentials are valid.
    /// Return only wallets the provider can actually sign for.
    fn discover(&self, credentials: &Credentials) -> Result<Vec<RemoteWallet>>;

    /// What to tell the user when [`discover`](Self::discover) finds no
    /// usable wallet — typically how to create one.
    fn no_wallets_hint(&self) -> &'static str;

    /// Connect to a wallet, resolving and pinning its address.
    fn connect(&self, credentials: &Credentials, wallet_id: &str) -> Result<Box<dyn SolanaSigner>>;
}

// ── Credential storage ──────────────────────────────────────────────────────

/// Build the platform secret store for remote credential blobs.
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
            "Remote backend accounts require a platform secret store (Keychain, GNOME \
             Keyring, or Windows Credential Manager), which is unavailable on this platform."
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
    credentials: &Credentials,
    intent: &AuthIntent,
) -> Result<()> {
    let blob = serde_json::to_vec(credentials)
        .map_err(|e| Error::Config(format!("Failed to serialize credentials: {e}")))?;
    ks.import_credential_with_intent(name, &blob, intent)
        .map_err(|e| Error::Config(format!("Failed to store credentials: {e}")))
}

/// Check whether credentials exist for this account name in the platform
/// secret store. Never prompts.
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
    provider_id: &str,
    gated: bool,
    auth_override: AuthOverride,
    intent: &AuthIntent,
) -> Result<Credentials> {
    let (ks, backend) = platform_keystore(gated, auth_override)?;
    if !ks.credential_exists(name) {
        return Err(Error::Config(format!(
            "No credentials stored for account `{name}`.\n\
             Run `pay account new {name} --backend {provider_id}` to connect it."
        )));
    }
    let blob = ks
        .load_credential_with_intent(name, intent)
        .map_err(|e| crate::signer::map_keystore_backend_error(backend, e))?;
    serde_json::from_slice(&blob).map_err(|e| {
        Error::Config(format!(
            "Stored credentials for `{name}` are corrupted ({e}). \
             Re-connect the wallet: `pay account destroy {name}` then \
             `pay account new {name} --backend {provider_id}`."
        ))
    })
}

// ── Account resolution ──────────────────────────────────────────────────────

/// Read an account's provider id, or explain that it is missing.
fn account_provider(account: &Account, name: &str) -> Result<&'static dyn RemoteProvider> {
    let id = account.provider.as_deref().ok_or_else(|| {
        Error::Config(format!(
            "Remote account `{name}` is missing its `provider` field in accounts.yml \
             (one of: {}).",
            provider_ids().join(", ")
        ))
    })?;
    provider(id).ok_or_else(|| {
        Error::Config(format!(
            "Account `{name}` names an unknown remote backend `{id}`. \
             This build of pay supports: {}.",
            provider_ids().join(", ")
        ))
    })
}

/// Connect a wallet and return its Solana address (base58). Used at setup
/// time to validate credentials and cache the address in `accounts.yml`.
pub fn fetch_wallet_address(
    provider: &dyn RemoteProvider,
    credentials: &Credentials,
    wallet_id: &str,
) -> Result<String> {
    Ok(provider
        .connect(credentials, wallet_id)?
        .pubkey()
        .to_string())
}

/// Resolve a remote account into a ready-to-sign [`ResolvedSigner`].
///
/// Loads the credential blob (through the platform auth gate when the
/// account requires auth on this network), connects the provider's signer
/// (which resolves and pins the wallet's address), and cross-checks that
/// address against the `pubkey` cached in `accounts.yml`.
///
/// Like the rest of the signer-resolution surface and the MPP/x402
/// payment builders, this is synchronous and blocks on network I/O.
/// Callers on async workers must isolate it with
/// `tokio::task::spawn_blocking` — the same contract the payer proxy and
/// MCP tools already follow for `build_credential` / `build_payment`.
pub fn load_remote_signer(
    account: &Account,
    name: &str,
    network: &str,
    intent: &AuthIntent,
    auth_override: AuthOverride,
) -> Result<ResolvedSigner> {
    let provider = account_provider(account, name)?;

    let wallet_id = account.account.clone().ok_or_else(|| {
        Error::Config(format!(
            "Remote account `{name}` is missing its `account` field (the {} wallet id) \
             in accounts.yml.",
            provider.display_name()
        ))
    })?;

    let gated = account.auth_required_for_network(network);
    let account_intent = intent.with_account_context(name);
    let credentials = load_credentials(name, provider.id(), gated, auth_override, &account_intent)?;

    let signer = provider
        .connect(&credentials, &wallet_id)
        .map_err(|e| explain_connect_failure(provider, &credentials, &wallet_id, name, e))?;

    let address = signer.pubkey().to_string();
    if let Some(expected) = account.pubkey.as_deref()
        && expected != address
    {
        return Err(Error::Config(format!(
            "Account `{name}` resolves to address {address}, but accounts.yml caches \
             {expected}. The wallet behind `{wallet_id}` changed — re-connect it: \
             `pay account destroy {name}` then \
             `pay account new {name} --backend {}`.",
            provider.id()
        )));
    }

    Ok(ResolvedSigner::Remote(signer))
}

/// Explain a failed [`RemoteProvider::connect`] in terms of what is
/// actually wrong.
///
/// `connect` can only report what its HTTP call said — typically a bare
/// 401 — but the two everyday causes are distinguishable, and both are
/// invisible in that status: credentials that no longer authenticate at
/// all (rotated, revoked), and credentials that authenticate fine but
/// belong to a different project than the one holding this wallet.
/// Discovery separates them: it takes the same stored credentials and
/// lists the wallets they can sign for.
fn explain_connect_failure(
    provider: &dyn RemoteProvider,
    credentials: &Credentials,
    wallet_id: &str,
    name: &str,
    original: Error,
) -> Error {
    let id = provider.id();
    let display_name = provider.display_name();
    let reconnect = format!("pay account new {name} --backend {id} --force");

    let Ok(wallets) = provider.discover(credentials) else {
        return Error::Config(format!(
            "The {display_name} credentials stored for account `{name}` neither signed nor \
             listed the project's wallets, so they were most likely rotated or revoked.\n\
             {original}\nRe-connect it:\n  {reconnect}"
        ));
    };

    if wallets.is_empty() {
        return Error::Config(format!(
            "The {display_name} credentials stored for account `{name}` can sign with no \
             Solana wallet.\n{}",
            provider.no_wallets_hint()
        ));
    }

    if wallets.iter().any(|w| w.id == wallet_id) {
        return original;
    }

    let listed = wallets
        .iter()
        .map(|w| format!("{} ({})", w.id, w.address))
        .collect::<Vec<_>>()
        .join("\n  ");

    Error::Config(format!(
        "Account `{name}` points at wallet `{wallet_id}`, which the {display_name} \
         credentials stored on this machine cannot see. They can sign with:\n  {listed}\n\
         The credentials were replaced, or they belong to a different project than the \
         wallet.\nRe-connect it:\n  {reconnect}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Keystore as KeystoreKind;
    use std::collections::BTreeMap;

    fn remote_account(provider: Option<&str>, wallet_id: Option<&str>) -> Account {
        Account {
            keystore: KeystoreKind::Remote,
            provider: provider.map(str::to_string),
            active: false,
            auth_required: Some(false),
            pubkey: None,
            vault: None,
            account: wallet_id.map(str::to_string),
            path: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: BTreeMap::new(),
        }
    }

    #[test]
    fn registry_resolves_known_providers_only() {
        assert_eq!(provider("openfort").map(|p| p.id()), Some("openfort"));
        assert!(provider("not-a-backend").is_none());
        assert!(provider_ids().contains(&"openfort"));
    }

    /// Every registered provider must declare at least one credential and
    /// a unique id — the CLI drives its whole prompt flow from these.
    #[test]
    fn registered_providers_are_well_formed() {
        let ids = provider_ids();
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "provider ids must be unique");

        for p in PROVIDERS {
            assert!(!p.credential_fields().is_empty(), "{}", p.id());
            assert!(!p.display_name().is_empty(), "{}", p.id());
        }
    }

    #[test]
    fn missing_provider_field_is_reported() {
        let account = remote_account(None, Some("acc_x"));
        let Err(err) = account_provider(&account, "agent") else {
            panic!("expected a missing-provider error");
        };
        assert!(err.to_string().contains("missing its `provider` field"));
    }

    #[test]
    fn unknown_provider_lists_supported_backends() {
        let account = remote_account(Some("acme-custody"), Some("acc_x"));
        let Err(err) = account_provider(&account, "agent") else {
            panic!("expected an unknown-provider error");
        };
        let msg = err.to_string();
        assert!(msg.contains("unknown remote backend `acme-custody`"));
        assert!(msg.contains("openfort"));
    }

    #[test]
    fn load_remote_signer_requires_wallet_id() {
        let account = remote_account(Some("openfort"), None);
        let err = load_remote_signer(
            &account,
            "agent",
            "mainnet",
            &AuthIntent::default_payment(),
            None,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(err.to_string().contains("missing its `account` field"));
    }

    /// A provider whose discovery result the test controls; `Err` stands
    /// for credentials the provider rejects outright.
    struct FakeProvider(std::result::Result<Vec<&'static str>, ()>);

    impl RemoteProvider for FakeProvider {
        fn id(&self) -> &'static str {
            "fake"
        }
        fn display_name(&self) -> &'static str {
            "Fake custody"
        }
        fn credential_fields(&self) -> &'static [CredentialField] {
            &[]
        }
        fn credentials_hint(&self) -> &'static str {
            "hint"
        }
        fn no_wallets_hint(&self) -> &'static str {
            "Create one first."
        }
        fn discover(&self, _credentials: &Credentials) -> Result<Vec<RemoteWallet>> {
            match &self.0 {
                Ok(ids) => Ok(ids
                    .iter()
                    .map(|id| RemoteWallet {
                        id: (*id).to_string(),
                        address: format!("addr-for-{id}"),
                    })
                    .collect()),
                Err(()) => Err(Error::Config("credentials rejected".to_string())),
            }
        }
        fn connect(&self, _c: &Credentials, _w: &str) -> Result<Box<dyn SolanaSigner>> {
            unimplemented!("tests only exercise the failure path")
        }
    }

    fn explain(discovery: std::result::Result<Vec<&'static str>, ()>, wallet: &str) -> String {
        explain_connect_failure(
            &FakeProvider(discovery),
            &Credentials::new(),
            wallet,
            "demo",
            Error::Config("Remote API error".to_string()),
        )
        .to_string()
    }

    /// The failure that costs the most time to diagnose: the stored
    /// credentials work, but against a project without this wallet.
    #[test]
    fn wallet_outside_the_credentials_project_is_named() {
        let msg = explain(Ok(vec!["acc_live"]), "acc_stale");
        assert!(msg.contains("acc_stale"), "{msg}");
        assert!(msg.contains("acc_live (addr-for-acc_live)"), "{msg}");
        assert!(
            msg.contains("pay account new demo --backend fake --force"),
            "{msg}"
        );
    }

    #[test]
    fn rejected_credentials_are_reported_as_such() {
        let msg = explain(Err(()), "acc_live");
        assert!(msg.contains("rotated or revoked"), "{msg}");
        assert!(msg.contains("Remote API error"), "{msg}");
        assert!(
            msg.contains("pay account new demo --backend fake --force"),
            "{msg}"
        );
    }

    #[test]
    fn empty_project_points_at_wallet_creation() {
        let msg = explain(Ok(vec![]), "acc_live");
        assert!(msg.contains("Create one first."), "{msg}");
    }

    /// When the wallet *is* there, the provider's own error is the real
    /// story and must not be replaced by a guess.
    #[test]
    fn reachable_wallet_keeps_the_original_error() {
        let msg = explain(Ok(vec!["acc_live"]), "acc_live");
        assert_eq!(
            msg,
            Error::Config("Remote API error".to_string()).to_string()
        );
    }

    #[test]
    fn store_credentials_roundtrip_through_keystore() {
        let ks = crate::keystore::Keystore::in_memory();
        let intent = AuthIntent::from_reason("test");
        let creds = Credentials::from([
            ("secret_key".to_string(), "sk_test_abc".to_string()),
            ("wallet_secret".to_string(), "BASE64DER".to_string()),
        ]);

        store_credentials(&ks, "default", &creds, &intent).unwrap();
        assert!(ks.credential_exists("default"));

        let blob = ks.load_credential_with_intent("default", &intent).unwrap();
        let back: Credentials = serde_json::from_slice(&blob).unwrap();
        assert_eq!(back["secret_key"], "sk_test_abc");
        assert_eq!(back["wallet_secret"], "BASE64DER");
    }
}
