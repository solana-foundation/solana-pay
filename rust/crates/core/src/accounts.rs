//! Account registry + per-network routing — `~/.config/pay/accounts.yml`.
//!
//! Single source of truth for named wallets, organised by network.
//!
//! ```yaml
//! version: 2
//!
//! accounts:
//!   mainnet:
//!     default:
//!       keystore: apple-keychain
//!       auth_required: true
//!       pubkey: 7xKX...abc
//!     work:
//!       keystore: 1password
//!       vault: Work
//!       pubkey: 9yLM...def
//!   localnet:
//!     default:
//!       keystore: ephemeral
//!       auth_required: false
//!       pubkey: ABc...
//!       secret_key_b58: 5Kj...
//!       created_at: 2026-04-10T12:34:56Z
//! ```
//!
//! When a network has multiple accounts, the "active" one (used for
//! payments) is the one with `active: true`, or else the first one
//! alphabetically (BTreeMap ordering).
//!
//! ## Testability
//!
//! Filesystem access goes through the [`AccountsStore`] trait. The real
//! impl ([`FileAccountsStore`]) reads/writes the YAML file with strict
//! permissions; tests use [`MemoryAccountsStore`] which holds the config
//! in memory and counts save calls so we can assert "we resolved an
//! ephemeral but forgot to persist it" never happens.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

use crate::{Error, Result};

const ACCOUNTS_FILE: &str = "~/.config/pay/accounts.yml";

/// Current schema version. Bumped on incompatible changes.
pub const ACCOUNTS_SCHEMA_VERSION: u32 = 2;

/// Default account name created by `pay setup`.
pub const DEFAULT_ACCOUNT_NAME: &str = "default";

/// Solana mainnet network slug — used as the lookup key for "the user's
/// real-money wallet" throughout the rest of the codebase.
pub const MAINNET_NETWORK: &str = "mainnet";

/// Default auth-gate policy for a network.
pub fn default_auth_required_for_network(network: &str) -> bool {
    network == MAINNET_NETWORK
}

// ── Keystore + Account ──────────────────────────────────────────────────────

/// Which keystore backend holds the secret key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Keystore {
    AppleKeychain,
    GnomeKeyring,
    WindowsHello,
    OnePassword,
    File,
    /// Inline ephemeral keypair stored directly in this file. Used for
    /// throwaway test wallets on sandbox/devnet/localnet.
    Ephemeral,
}

impl std::fmt::Display for Keystore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Keystore::AppleKeychain => write!(f, "apple-keychain"),
            Keystore::GnomeKeyring => write!(f, "gnome-keyring"),
            Keystore::WindowsHello => write!(f, "windows-hello"),
            Keystore::OnePassword => write!(f, "1password"),
            Keystore::File => write!(f, "file"),
            Keystore::Ephemeral => write!(f, "ephemeral"),
        }
    }
}

fn is_false(b: &bool) -> bool {
    !b
}

/// A single account entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Account {
    /// Which keystore backend stores the secret key.
    pub keystore: Keystore,

    /// Whether this account is the active one for its network. Only one
    /// account per network should have this set. If none is set, the first
    /// one alphabetically is used. Omitted from YAML when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub active: bool,

    /// Whether loading the secret key should pass through the backend's
    /// auth gate (Touch ID, Windows Hello, polkit, etc.). When omitted,
    /// defaults to `true` for `mainnet` and `false` for other networks.
    /// Ignored for ephemeral accounts, which are intentionally ungated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_required: Option<bool>,

    /// Base-58 public key (cached for display without auth).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,

    /// 1Password vault name (only for `keystore: 1password`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,

    /// 1Password account identifier (UUID or shorthand) used to sign in/out
    /// of the correct `op` session. Only for `keystore: 1password`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    /// File path (only for `keystore: file`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Base58-encoded full keypair (64 bytes: secret || public). Only set
    /// for `keystore: ephemeral` — these wallets live entirely in this
    /// file with no external secret storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key_b58: Option<String>,

    /// RFC 3339 timestamp of when this account was first created. Only
    /// set for ephemeral entries (where it's load-bearing — older
    /// ephemerals may have less SOL because faucets reset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,

    /// Active MPP subscriptions held by this account, keyed by
    /// `subscription_id` (the base58 `SubscriptionDelegation` PDA from the
    /// `Payment-Receipt` header). Omitted from YAML when empty so the
    /// `accounts.yml` shape stays unchanged for accounts without
    /// subscriptions.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub subscriptions: BTreeMap<String, Subscription>,
}

/// On-disk lifecycle marker for a stored subscription. Mirrors the spec's
/// state machine: a delegation is active until cancelled or expired, after
/// which it cannot be used to gate access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionStatus {
    /// Activation settled and the on-chain `SubscriptionDelegation` is
    /// usable for renewals.
    Active,
    /// Cancellation has been scheduled or has taken effect on-chain.
    Cancelled,
    /// Either the HTTP-layer `subscription_expires` has been reached or
    /// the on-chain delegation was otherwise invalidated.
    Expired,
}

impl SubscriptionStatus {
    /// True when the subscription is in a state where the server should
    /// still be able to honour or renew it.
    pub fn is_active(self) -> bool {
        matches!(self, SubscriptionStatus::Active)
    }
}

impl std::fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionStatus::Active => write!(f, "active"),
            SubscriptionStatus::Cancelled => write!(f, "cancelled"),
            SubscriptionStatus::Expired => write!(f, "expired"),
        }
    }
}

/// An MPP `subscription`-intent delegation owned by an account.
///
/// All amounts and periods are stored exactly as the spec wire form so we
/// can round-trip them into the SDK's `SubscriptionRequest` /
/// `SubscriptionReceiptExtensions` without lossy reformatting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    /// Base58 of the on-chain `SubscriptionDelegation` PDA — the stable
    /// identifier returned in `Payment-Receipt.subscriptionId`.
    pub subscription_id: String,

    /// Base58 of the on-chain `Plan` PDA (the spec's `externalId`).
    pub plan_id: String,

    /// Subscriptions program ID. Omitted from YAML when it's the canonical
    /// mainnet deployment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_id: Option<String>,

    /// SPL Token / Token-2022 mint (base58).
    pub mint: String,

    /// Display-only symbolic currency (e.g. "USDC"). Kept for `pay
    /// subscriptions list` and never relied on for routing decisions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,

    /// Per-period charge amount in mint base units, decimal string (per spec).
    pub amount_per_period: String,

    /// Billing period unit: `"day"` or `"week"` (the Solana profile rejects
    /// `month`).
    pub period_unit: String,

    /// Positive integer count of `period_unit` values per billing period.
    pub period_count: u32,

    /// Recipient wallet pubkey bound at activation time.
    pub recipient: String,

    /// Server's puller pubkey (`plan.owner` or in `plan.pullers`).
    pub puller: String,

    /// Solana network slug, normalised the same way as `Account`'s parent
    /// network key (`mainnet`, `devnet`, `sandbox`, `localnet`).
    pub network: String,

    /// Lifecycle state.
    pub status: SubscriptionStatus,

    /// RFC 3339 timestamp of successful activation.
    pub activated_at: String,

    /// Base58 of the activation transaction signature.
    pub activation_signature: String,

    /// Most recent billing-period index the server has reported a successful
    /// renewal for. `0` corresponds to the activation charge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_charged_period: Option<u64>,

    /// HTTP-layer subscription expiry, mirroring the challenge's optional
    /// `subscriptionExpires` field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Resource URL the subscription was activated against. Set when the
    /// activation came from a 402 negotiation; unset for flag-driven
    /// `pay subscriptions new`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_url: Option<String>,

    /// Human-readable description echoed from the challenge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Cached `authenticate`-intent credential. When present and unexpired,
    /// the client attaches it as `Authorization: Payment <token>` to
    /// subscription-gated requests so the server can authorise without
    /// the wallet re-signing. Generated once per billing period during
    /// activation (or lazily on the first 402 of the period).
    ///
    /// The token shape is the full `Payment <base64url(credential)>`
    /// header value — callers MAY attach it verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticate_token: Option<String>,

    /// RFC 3339 expiry timestamp on the cached authenticate token. Used
    /// to gate attachment: the client MUST treat the token as missing
    /// once the wall clock crosses this value. Typically equal to the
    /// current billing period's end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticate_expires_at: Option<String>,
}

impl Account {
    /// Whether this account should require backend auth on secret-key access.
    pub fn auth_required_for_network(&self, network: &str) -> bool {
        self.keystore != Keystore::Ephemeral
            && self
                .auth_required
                .unwrap_or_else(|| default_auth_required_for_network(network))
    }

    /// Build the signer source string used by `pay_core::signer::load_signer`
    /// for keystore-backed accounts. Returns `None` for ephemeral accounts
    /// — those must be loaded via [`Account::pubkey`] + the inline secret
    /// rather than through the external loader.
    pub fn signer_source(&self, name: &str) -> Option<String> {
        match self.keystore {
            Keystore::AppleKeychain => Some(format!("keychain:{name}")),
            Keystore::GnomeKeyring => Some(format!("gnome-keyring:{name}")),
            Keystore::WindowsHello => Some(format!("windows-hello:{name}")),
            Keystore::OnePassword => Some(format!("1password:{name}")),
            Keystore::File => Some(self.path.clone().unwrap_or_else(|| {
                FileAccountsStore::default_keypair_path(name)
                    .to_string_lossy()
                    .into_owned()
            })),
            Keystore::Ephemeral => None,
        }
    }

    /// Convenience: returns the inline secret bytes for an ephemeral
    /// account, decoded from base58. Returns `None` for non-ephemeral
    /// accounts (which don't store the secret in this file).
    pub fn ephemeral_keypair_bytes(&self) -> Option<Vec<u8>> {
        if self.keystore != Keystore::Ephemeral {
            return None;
        }
        bs58::decode(self.secret_key_b58.as_deref()?)
            .into_vec()
            .ok()
    }
}

// ── AccountsFile ────────────────────────────────────────────────────────────

/// The top-level accounts file — wallets nested by network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountsFile {
    /// Schema version. Bumped on incompatible changes.
    #[serde(default = "default_version")]
    pub version: u32,

    /// All registered accounts, keyed by network slug → account name.
    #[serde(default)]
    pub accounts: BTreeMap<String, BTreeMap<String, Account>>,
}

impl Default for AccountsFile {
    fn default() -> Self {
        Self {
            version: ACCOUNTS_SCHEMA_VERSION,
            accounts: BTreeMap::new(),
        }
    }
}

fn default_version() -> u32 {
    ACCOUNTS_SCHEMA_VERSION
}

impl AccountsFile {
    /// Load from the default location (`~/.config/pay/accounts.yml`), or
    /// return an empty file if it doesn't exist.
    pub fn load() -> Result<Self> {
        FileAccountsStore::default_path().load()
    }

    /// Save to the default location with restricted permissions.
    pub fn save(&self) -> Result<()> {
        FileAccountsStore::default_path().save(self)
    }

    /// Look up the account that should be used for the given network.
    ///
    /// Selection rule:
    /// 1. Account with `active: true` (if any).
    /// 2. Otherwise the first account alphabetically (BTreeMap order).
    ///
    /// Returns `(account_name, account)` or `None` if the network has no
    /// accounts configured.
    pub fn account_for_network(&self, network: &str) -> Option<(&str, &Account)> {
        let network_accounts = self.accounts.get(network)?;
        if network_accounts.is_empty() {
            return None;
        }
        // Prefer explicitly active account.
        if let Some((name, acct)) = network_accounts.iter().find(|(_, a)| a.active) {
            return Some((name.as_str(), acct));
        }
        // Fall back to first alphabetically.
        network_accounts.iter().next().map(|(n, a)| (n.as_str(), a))
    }

    /// Look up a specific named account within a network.
    pub fn named_account_for_network(&self, network: &str, name: &str) -> Option<&Account> {
        self.accounts.get(network)?.get(name)
    }

    /// Convenience: the account mapped to mainnet — i.e. the user's
    /// "default" wallet for real-money flows. Returns `None` if no
    /// mainnet account has been configured (e.g. user hasn't run
    /// `pay setup` yet).
    pub fn default_account(&self) -> Option<(&str, &Account)> {
        self.account_for_network(MAINNET_NETWORK)
    }

    /// Add or update an account within a network.
    pub fn upsert(&mut self, network: &str, name: &str, account: Account) {
        self.accounts
            .entry(network.to_string())
            .or_default()
            .insert(name.to_string(), account);
    }

    /// Remove an account from a network. Also removes the network entry
    /// if it becomes empty. Returns the removed account, or `None`.
    pub fn remove(&mut self, network: &str, name: &str) -> Option<Account> {
        let network_accounts = self.accounts.get_mut(network)?;
        let removed = network_accounts.remove(name);
        if network_accounts.is_empty() {
            self.accounts.remove(network);
        }
        removed
    }

    /// Set `active: true` on the named account in a network, clearing it
    /// from all other accounts in the same network.
    pub fn set_active(&mut self, network: &str, name: &str) {
        if let Some(network_accounts) = self.accounts.get_mut(network) {
            for (acct_name, acct) in network_accounts.iter_mut() {
                acct.active = acct_name == name;
            }
        }
    }

    /// Insert or update a `Subscription` under an existing account.
    ///
    /// Returns `Ok(())` on success and an error if the network or account is
    /// not registered. We refuse to lazily create the account here because
    /// subscriptions inherit the keystore + auth gate of an existing wallet;
    /// silently creating a placeholder account would leave a half-initialised
    /// entry on disk.
    pub fn upsert_subscription(
        &mut self,
        network: &str,
        account_name: &str,
        subscription: Subscription,
    ) -> Result<()> {
        let network_accounts = self.accounts.get_mut(network).ok_or_else(|| {
            Error::Config(format!(
                "Cannot attach subscription: no accounts registered for network `{network}`"
            ))
        })?;
        let account = network_accounts.get_mut(account_name).ok_or_else(|| {
            Error::Config(format!(
                "Cannot attach subscription: no account `{account_name}` on network `{network}`"
            ))
        })?;
        account
            .subscriptions
            .insert(subscription.subscription_id.clone(), subscription);
        Ok(())
    }

    /// Remove a subscription from an account by id, returning the previous
    /// entry if it existed.
    pub fn remove_subscription(
        &mut self,
        network: &str,
        account_name: &str,
        subscription_id: &str,
    ) -> Option<Subscription> {
        self.accounts
            .get_mut(network)?
            .get_mut(account_name)?
            .subscriptions
            .remove(subscription_id)
    }

    /// Mutate a subscription's status in place. No-op when the subscription
    /// isn't tracked locally — the on-chain delegation remains the source of
    /// truth and a missing local entry just means we never recorded it.
    pub fn set_subscription_status(
        &mut self,
        network: &str,
        account_name: &str,
        subscription_id: &str,
        status: SubscriptionStatus,
    ) {
        let Some(network_accounts) = self.accounts.get_mut(network) else {
            return;
        };
        let Some(account) = network_accounts.get_mut(account_name) else {
            return;
        };
        if let Some(sub) = account.subscriptions.get_mut(subscription_id) {
            sub.status = status;
        }
    }

    /// Look up a subscription by id within an account.
    pub fn find_subscription(
        &self,
        network: &str,
        account_name: &str,
        subscription_id: &str,
    ) -> Option<&Subscription> {
        self.accounts
            .get(network)?
            .get(account_name)?
            .subscriptions
            .get(subscription_id)
    }

    /// Iterate every subscription tracked across the whole file, yielding
    /// `(network, account_name, &Subscription)`. Used by
    /// `pay subscriptions list` when no filter is provided.
    pub fn all_subscriptions(&self) -> impl Iterator<Item = (&str, &str, &Subscription)> {
        self.accounts.iter().flat_map(|(network, accounts)| {
            accounts.iter().flat_map(move |(name, account)| {
                account
                    .subscriptions
                    .values()
                    .map(move |sub| (network.as_str(), name.as_str(), sub))
            })
        })
    }
}

// ── Resolution ──────────────────────────────────────────────────────────────

/// Result of looking up an account for a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountChoice {
    /// Network has an account configured.
    Resolved { name: String, account: Account },
    /// Network has no entry in the accounts map at all. Caller may
    /// choose to lazily create one (for ephemeral networks like
    /// sandbox/devnet/localnet) or surface "no wallet configured".
    Missing,
}

/// Pure resolver: given a config snapshot and a network slug, return
/// the account choice for it. Does no I/O.
pub fn resolve_account_for_network(network: &str, file: &AccountsFile) -> AccountChoice {
    match file.account_for_network(network) {
        Some((name, account)) => AccountChoice::Resolved {
            name: name.to_string(),
            account: account.clone(),
        },
        None => AccountChoice::Missing,
    }
}

// ── Storage trait + impls ───────────────────────────────────────────────────

/// Read/write abstraction for the accounts file. Real impl is
/// [`FileAccountsStore`]; tests use [`MemoryAccountsStore`].
pub trait AccountsStore: Send + Sync {
    fn load(&self) -> Result<AccountsFile>;
    fn save(&self, file: &AccountsFile) -> Result<()>;
}

/// On-disk YAML store at `~/.config/pay/accounts.yml`.
pub struct FileAccountsStore {
    path: PathBuf,
}

impl FileAccountsStore {
    /// Store rooted at the default config path.
    pub fn default_path() -> Self {
        Self {
            path: PathBuf::from(shellexpand::tilde(ACCOUNTS_FILE).into_owned()),
        }
    }

    /// Default owner-only keypair path alongside `accounts.yml`.
    pub fn default_keypair_path(account_name: &str) -> PathBuf {
        Self::default_path()
            .path
            .with_file_name(format!("{account_name}.json"))
    }

    /// Store rooted at an explicit path (used by tests and non-default deployments).
    pub fn at(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl AccountsStore for FileAccountsStore {
    fn load(&self) -> Result<AccountsFile> {
        if !self.path.exists() {
            return Ok(AccountsFile::default());
        }
        let raw = std::fs::read_to_string(&self.path)
            .map_err(|e| Error::Config(format!("Failed to read {}: {e}", self.path.display())))?;
        if raw.trim().is_empty() {
            return Ok(AccountsFile::default());
        }
        serde_yml::from_str(&raw)
            .map_err(|e| Error::Config(format!("Invalid {}: {e}", self.path.display())))
    }

    fn save(&self, file: &AccountsFile) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Config(format!("Failed to create dir: {e}")))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }
        let yaml = serde_yml::to_string(file)
            .map_err(|e| Error::Config(format!("YAML serialize: {e}")))?;
        write_private(&self.path, yaml.as_bytes())
            .map_err(|e| Error::Config(format!("Failed to write {}: {e}", self.path.display())))
    }
}

/// In-memory store for tests. Counts `save()` calls so tests can assert
/// the store was actually persisted to (catches the "we resolved an
/// ephemeral but forgot to call save" bug class).
#[derive(Default)]
pub struct MemoryAccountsStore {
    inner: RwLock<AccountsFile>,
    save_count: Mutex<u32>,
}

impl MemoryAccountsStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_file(file: AccountsFile) -> Self {
        Self {
            inner: RwLock::new(file),
            save_count: Mutex::new(0),
        }
    }

    pub fn save_count(&self) -> u32 {
        *self.save_count.lock().unwrap()
    }

    pub fn snapshot(&self) -> AccountsFile {
        self.inner.read().unwrap().clone()
    }
}

impl AccountsStore for MemoryAccountsStore {
    fn load(&self) -> Result<AccountsFile> {
        Ok(self.inner.read().unwrap().clone())
    }
    fn save(&self, file: &AccountsFile) -> Result<()> {
        *self.inner.write().unwrap() = file.clone();
        *self.save_count.lock().unwrap() += 1;
        Ok(())
    }
}

// ── Lazy ephemeral creation ─────────────────────────────────────────────────

/// Result of resolving (or creating) an ephemeral wallet for a network.
/// `created` is true iff this call generated a new entry — the CLI uses
/// it to decide whether to print a "Generated <network> wallet" notice.
#[derive(Debug, Clone)]
pub struct ResolvedEphemeral {
    pub network: String,
    pub account_name: String,
    pub account: Account,
    pub created: bool,
}

/// Look up the ephemeral wallet for a network, generating + persisting
/// one if no entry exists.
///
/// Behavior:
/// - **No account for the network** → generate a fresh ephemeral named
///   "default", insert under `accounts[network]["default"]`, persist,
///   return with `created = true`.
/// - **Account is ephemeral** → return cache hit with `created = false`.
/// - **Account is non-ephemeral** → error. The caller should resolve
///   through `signer::load_signer` instead so the user's real wallet
///   is used.
pub fn load_or_create_ephemeral_for_network(
    network: &str,
    store: &dyn AccountsStore,
) -> Result<ResolvedEphemeral> {
    load_or_create_ephemeral_for_network_as(network, DEFAULT_ACCOUNT_NAME, store)
}

/// Named variant of [`load_or_create_ephemeral_for_network`].
pub fn load_or_create_ephemeral_for_network_as(
    network: &str,
    account_name: &str,
    store: &dyn AccountsStore,
) -> Result<ResolvedEphemeral> {
    let mut file = store.load()?;

    if let Some(account) = file
        .named_account_for_network(network, account_name)
        .cloned()
    {
        if account.keystore != Keystore::Ephemeral {
            return Err(Error::Config(format!(
                "Network `{network}` account `{account_name}` is \
                 `{}`-backed, not ephemeral. Resolve via the keystore loader \
                 instead of generating a fresh wallet.",
                account.keystore
            )));
        }
        return Ok(ResolvedEphemeral {
            network: network.to_string(),
            account_name: account_name.to_string(),
            account,
            created: false,
        });
    }

    if account_name == DEFAULT_ACCOUNT_NAME {
        match resolve_account_for_network(network, &file) {
            AccountChoice::Resolved { name, account } => {
                if account.keystore != Keystore::Ephemeral {
                    return Err(Error::Config(format!(
                        "Network `{network}` is mapped to account `{name}` which is \
                         `{}`-backed, not ephemeral. Resolve via the keystore loader \
                         instead of generating a fresh wallet.",
                        account.keystore
                    )));
                }
                return Ok(ResolvedEphemeral {
                    network: network.to_string(),
                    account_name: name,
                    account,
                    created: false,
                });
            }
            AccountChoice::Missing => {}
        }
    }

    let account = generate_ephemeral_account();
    file.accounts
        .entry(network.to_string())
        .or_default()
        .insert(account_name.to_string(), account.clone());
    store.save(&file)?;
    Ok(ResolvedEphemeral {
        network: network.to_string(),
        account_name: account_name.to_string(),
        account,
        created: true,
    })
}

/// Ensure an exact named ephemeral account exists for a network.
///
/// Unlike [`load_or_create_ephemeral_for_network_as`], this never falls back
/// to another account when `account_name` is `default`. It is used when two
/// local roles must remain distinct, such as a sandbox gateway fee payer and
/// a sandbox client payer.
pub fn load_or_create_exact_ephemeral_for_network_as(
    network: &str,
    account_name: &str,
    store: &dyn AccountsStore,
) -> Result<ResolvedEphemeral> {
    let mut file = store.load()?;

    if let Some(account) = file
        .named_account_for_network(network, account_name)
        .cloned()
    {
        if account.keystore != Keystore::Ephemeral {
            return Err(Error::Config(format!(
                "Network `{network}` account `{account_name}` is \
                 `{}`-backed, not ephemeral. Resolve via the keystore loader \
                 instead of generating a fresh wallet.",
                account.keystore
            )));
        }
        return Ok(ResolvedEphemeral {
            network: network.to_string(),
            account_name: account_name.to_string(),
            account,
            created: false,
        });
    }

    let account = generate_ephemeral_account();
    file.accounts
        .entry(network.to_string())
        .or_default()
        .insert(account_name.to_string(), account.clone());
    store.save(&file)?;
    Ok(ResolvedEphemeral {
        network: network.to_string(),
        account_name: account_name.to_string(),
        account,
        created: true,
    })
}

fn generate_ephemeral_account() -> Account {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let mut full = Vec::with_capacity(64);
    full.extend_from_slice(&signing_key.to_bytes());
    full.extend_from_slice(&verifying_key.to_bytes());
    Account {
        keystore: Keystore::Ephemeral,
        active: false,
        auth_required: Some(false),
        pubkey: Some(bs58::encode(verifying_key.to_bytes()).into_string()),
        vault: None,
        account: None,
        path: None,
        secret_key_b58: Some(bs58::encode(&full).into_string()),
        created_at: Some(now_rfc3339()),
        subscriptions: BTreeMap::new(),
    }
}

/// Format `SystemTime::now()` as a UTC RFC 3339 timestamp without
/// pulling in a date crate. Granularity is seconds. Implements
/// Hinnant's civil-from-days for any year in [1970, 9999].
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    format_unix_seconds_utc(secs)
}

fn format_unix_seconds_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400) as u32;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

// ── On-disk helpers ─────────────────────────────────────────────────────────

/// Write data to a file with `0600` permissions (owner-only).
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)
    }

    #[cfg(not(unix))]
    std::fs::write(path, data)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn keychain_account(pubkey: &str) -> Account {
        Account {
            keystore: Keystore::AppleKeychain,
            active: false,
            auth_required: None,
            pubkey: Some(pubkey.to_string()),
            vault: None,
            path: None,
            account: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: BTreeMap::new(),
        }
    }

    fn fake_ephemeral(pubkey: &str) -> Account {
        Account {
            keystore: Keystore::Ephemeral,
            active: false,
            auth_required: Some(false),
            pubkey: Some(pubkey.to_string()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some("test-secret-bytes-base58".to_string()),
            created_at: Some("2026-04-10T00:00:00Z".to_string()),
            subscriptions: BTreeMap::new(),
        }
    }

    fn fake_subscription(id: &str, plan: &str) -> Subscription {
        Subscription {
            subscription_id: id.to_string(),
            plan_id: plan.to_string(),
            program_id: None,
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            currency: Some("USDC".to_string()),
            amount_per_period: "10000000".to_string(),
            period_unit: "day".to_string(),
            period_count: 30,
            recipient: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin".to_string(),
            puller: "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h".to_string(),
            network: "mainnet".to_string(),
            status: SubscriptionStatus::Active,
            activated_at: "2026-05-29T12:00:00Z".to_string(),
            activation_signature: "5J8Activation".to_string(),
            last_charged_period: Some(0),
            expires_at: None,
            resource_url: None,
            description: None,
            authenticate_token: None,
            authenticate_expires_at: None,
        }
    }

    // ── Keystore display + serde ──────────────────────────────────────────

    #[test]
    fn keystore_display_includes_ephemeral() {
        assert_eq!(Keystore::AppleKeychain.to_string(), "apple-keychain");
        assert_eq!(Keystore::Ephemeral.to_string(), "ephemeral");
    }

    #[test]
    fn keystore_serde_roundtrip_all_variants() {
        for ks in [
            Keystore::AppleKeychain,
            Keystore::GnomeKeyring,
            Keystore::WindowsHello,
            Keystore::OnePassword,
            Keystore::File,
            Keystore::Ephemeral,
        ] {
            let yaml = serde_yml::to_string(&ks).unwrap();
            let back: Keystore = serde_yml::from_str(&yaml).unwrap();
            assert_eq!(back, ks);
        }
    }

    // ── Account::signer_source ────────────────────────────────────────────

    #[test]
    fn signer_source_keychain() {
        assert_eq!(
            keychain_account("pk").signer_source("default"),
            Some("keychain:default".to_string())
        );
    }

    #[test]
    fn signer_source_ephemeral_returns_none() {
        assert_eq!(fake_ephemeral("pk").signer_source("sandbox"), None);
    }

    #[test]
    fn signer_source_file_uses_path_when_set() {
        let acct = Account {
            keystore: Keystore::File,
            active: false,
            auth_required: None,
            pubkey: None,
            vault: None,
            path: Some("/home/me/.config/solana/id.json".to_string()),
            account: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: BTreeMap::new(),
        };
        assert_eq!(
            acct.signer_source("legacy"),
            Some("/home/me/.config/solana/id.json".to_string())
        );
    }

    #[test]
    fn signer_source_file_falls_back_to_default_path() {
        let acct = Account {
            keystore: Keystore::File,
            active: false,
            auth_required: None,
            pubkey: None,
            vault: None,
            path: None,
            account: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: BTreeMap::new(),
        };
        assert_eq!(
            acct.signer_source("myacct"),
            Some(
                FileAccountsStore::default_keypair_path("myacct")
                    .to_string_lossy()
                    .into_owned()
            )
        );
    }

    #[test]
    fn ephemeral_keypair_bytes_roundtrip() {
        let raw_bytes: Vec<u8> = (0u8..64).collect();
        let acct = Account {
            keystore: Keystore::Ephemeral,
            active: false,
            auth_required: Some(false),
            pubkey: Some("pk".to_string()),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: Some(bs58::encode(&raw_bytes).into_string()),
            created_at: Some("2026-04-10T00:00:00Z".to_string()),
            subscriptions: BTreeMap::new(),
        };
        assert_eq!(acct.ephemeral_keypair_bytes(), Some(raw_bytes));
    }

    #[test]
    fn ephemeral_keypair_bytes_none_for_keychain_account() {
        assert!(keychain_account("pk").ephemeral_keypair_bytes().is_none());
    }

    #[test]
    fn auth_required_defaults_to_true_on_mainnet() {
        let acct = keychain_account("pk");
        assert!(acct.auth_required_for_network(MAINNET_NETWORK));
    }

    #[test]
    fn auth_required_defaults_to_false_off_mainnet() {
        let acct = keychain_account("pk");
        assert!(!acct.auth_required_for_network("devnet"));
    }

    #[test]
    fn auth_required_explicit_override_wins() {
        let mut acct = keychain_account("pk");
        acct.auth_required = Some(false);
        assert!(!acct.auth_required_for_network(MAINNET_NETWORK));
    }

    #[test]
    fn auth_required_is_always_false_for_ephemeral_accounts() {
        let mut acct = keychain_account("pk");
        acct.keystore = Keystore::Ephemeral;
        acct.auth_required = Some(true);
        assert!(!acct.auth_required_for_network(MAINNET_NETWORK));
    }

    // ── AccountsFile mutation ─────────────────────────────────────────────

    #[test]
    fn upsert_inserts_under_network() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        assert!(
            f.accounts
                .get(MAINNET_NETWORK)
                .unwrap()
                .contains_key("default")
        );
    }

    #[test]
    fn upsert_second_account_in_same_network() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        f.upsert(MAINNET_NETWORK, "work", keychain_account("pk2"));
        let net = f.accounts.get(MAINNET_NETWORK).unwrap();
        assert_eq!(net.len(), 2);
    }

    #[test]
    fn upsert_overwrites_existing_account() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("old"));
        f.upsert(MAINNET_NETWORK, "default", keychain_account("new"));
        let net = f.accounts.get(MAINNET_NETWORK).unwrap();
        assert_eq!(net.len(), 1);
        assert_eq!(net["default"].pubkey.as_deref(), Some("new"));
    }

    #[test]
    fn remove_account_removes_network_when_empty() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));
        f.remove(MAINNET_NETWORK, "default");
        assert!(!f.accounts.contains_key(MAINNET_NETWORK));
    }

    #[test]
    fn remove_account_leaves_network_with_remaining_accounts() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        f.upsert(MAINNET_NETWORK, "work", keychain_account("pk2"));
        f.remove(MAINNET_NETWORK, "default");
        let net = f.accounts.get(MAINNET_NETWORK).unwrap();
        assert_eq!(net.len(), 1);
        assert!(net.contains_key("work"));
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));
        assert!(f.remove(MAINNET_NETWORK, "ghost").is_none());
        assert!(f.accounts.contains_key(MAINNET_NETWORK));
    }

    #[test]
    fn set_active_marks_correct_account() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        f.upsert(MAINNET_NETWORK, "work", keychain_account("pk2"));
        f.set_active(MAINNET_NETWORK, "work");
        let net = f.accounts.get(MAINNET_NETWORK).unwrap();
        assert!(net["work"].active);
        assert!(!net["default"].active);
    }

    #[test]
    fn set_active_clears_previous_active() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        f.upsert(MAINNET_NETWORK, "work", keychain_account("pk2"));
        f.set_active(MAINNET_NETWORK, "default");
        f.set_active(MAINNET_NETWORK, "work");
        let net = f.accounts.get(MAINNET_NETWORK).unwrap();
        assert!(!net["default"].active);
        assert!(net["work"].active);
    }

    // ── Lookups ───────────────────────────────────────────────────────────

    #[test]
    fn account_for_network_returns_first_when_no_active() {
        let mut f = AccountsFile::default();
        // BTreeMap is sorted: "default" < "work"
        f.upsert(
            MAINNET_NETWORK,
            "default",
            keychain_account("DefaultPubkey"),
        );
        f.upsert(MAINNET_NETWORK, "work", keychain_account("WorkPubkey"));
        let (name, acct) = f.account_for_network(MAINNET_NETWORK).unwrap();
        assert_eq!(name, "default");
        assert_eq!(acct.pubkey.as_deref(), Some("DefaultPubkey"));
    }

    #[test]
    fn account_for_network_prefers_active() {
        let mut f = AccountsFile::default();
        f.upsert(
            MAINNET_NETWORK,
            "default",
            keychain_account("DefaultPubkey"),
        );
        f.upsert(MAINNET_NETWORK, "work", keychain_account("WorkPubkey"));
        f.set_active(MAINNET_NETWORK, "work");
        let (name, acct) = f.account_for_network(MAINNET_NETWORK).unwrap();
        assert_eq!(name, "work");
        assert_eq!(acct.pubkey.as_deref(), Some("WorkPubkey"));
    }

    #[test]
    fn default_account_is_shim_for_mainnet_lookup() {
        let mut f = AccountsFile::default();
        f.upsert(
            MAINNET_NETWORK,
            "default",
            keychain_account("DefaultPubkey"),
        );
        let (name, acct) = f.default_account().unwrap();
        assert_eq!(name, "default");
        assert_eq!(acct.pubkey.as_deref(), Some("DefaultPubkey"));
    }

    #[test]
    fn default_account_returns_none_when_no_mainnet() {
        let f = AccountsFile::default();
        assert!(f.default_account().is_none());
    }

    // ── resolve_account_for_network (pure) ────────────────────────────────

    #[test]
    fn resolve_returns_resolved_for_existing_account() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));
        match resolve_account_for_network(MAINNET_NETWORK, &f) {
            AccountChoice::Resolved { name, account } => {
                assert_eq!(name, "default");
                assert_eq!(account.pubkey.as_deref(), Some("pk"));
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_returns_missing_for_unmapped_network() {
        let f = AccountsFile::default();
        assert_eq!(
            resolve_account_for_network("sandbox", &f),
            AccountChoice::Missing
        );
    }

    #[test]
    fn resolve_does_not_cross_networks() {
        let mut f = AccountsFile::default();
        f.upsert("devnet", "default", fake_ephemeral("DevPk"));
        // localnet has no account — must NOT fall back to devnet.
        assert_eq!(
            resolve_account_for_network("localnet", &f),
            AccountChoice::Missing
        );
    }

    // ── load_or_create_ephemeral_for_network ──────────────────────────────

    #[test]
    fn load_or_create_creates_when_missing_and_persists() {
        let store = MemoryAccountsStore::new();
        let resolved = load_or_create_ephemeral_for_network("devnet", &store).unwrap();

        assert!(resolved.created, "should report creation");
        assert_eq!(resolved.network, "devnet");
        assert_eq!(resolved.account_name, DEFAULT_ACCOUNT_NAME);
        assert_eq!(resolved.account.keystore, Keystore::Ephemeral);
        assert!(resolved.account.pubkey.is_some());
        assert!(resolved.account.secret_key_b58.is_some());
        assert!(
            resolved
                .account
                .created_at
                .as_deref()
                .unwrap_or("")
                .starts_with("20")
        );

        // Persisted: account stored under accounts[devnet][default]
        assert_eq!(store.save_count(), 1);
        let snap = store.snapshot();
        assert!(
            snap.accounts
                .get("devnet")
                .unwrap()
                .contains_key(DEFAULT_ACCOUNT_NAME)
        );
    }

    #[test]
    fn load_or_create_reuses_existing_ephemeral() {
        let mut f = AccountsFile::default();
        f.upsert("sandbox", DEFAULT_ACCOUNT_NAME, fake_ephemeral("ReusedPk"));
        let store = MemoryAccountsStore::with_file(f);

        let resolved = load_or_create_ephemeral_for_network("sandbox", &store).unwrap();
        assert!(!resolved.created);
        assert_eq!(resolved.account.pubkey.as_deref(), Some("ReusedPk"));
        assert_eq!(store.save_count(), 0, "must not persist on cache hit");
    }

    #[test]
    fn exact_load_or_create_default_does_not_reuse_other_named_account() {
        let mut f = AccountsFile::default();
        f.upsert("localnet", "gateway", fake_ephemeral("GatewayPk"));
        let store = MemoryAccountsStore::with_file(f);

        let resolved =
            load_or_create_exact_ephemeral_for_network_as("localnet", DEFAULT_ACCOUNT_NAME, &store)
                .unwrap();

        assert!(resolved.created);
        assert_eq!(resolved.account_name, DEFAULT_ACCOUNT_NAME);
        assert_ne!(resolved.account.pubkey.as_deref(), Some("GatewayPk"));

        let snapshot = store.snapshot();
        assert!(
            snapshot
                .named_account_for_network("localnet", "gateway")
                .is_some()
        );
        assert!(
            snapshot
                .named_account_for_network("localnet", DEFAULT_ACCOUNT_NAME)
                .is_some()
        );
    }

    #[test]
    fn load_or_create_errors_when_mapped_to_keychain_account() {
        // mainnet points at the user's real keychain wallet.
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("Real"));
        let store = MemoryAccountsStore::with_file(f);

        let err = load_or_create_ephemeral_for_network(MAINNET_NETWORK, &store).unwrap_err();
        assert!(
            err.to_string().contains("not ephemeral"),
            "error should mention non-ephemeral keystore: {err}"
        );
        assert_eq!(store.save_count(), 0);
    }

    #[test]
    fn load_or_create_generates_distinct_keys_per_network() {
        let store = MemoryAccountsStore::new();
        let dev = load_or_create_ephemeral_for_network("devnet", &store).unwrap();
        let sb = load_or_create_ephemeral_for_network("sandbox", &store).unwrap();
        assert_ne!(dev.account.pubkey, sb.account.pubkey);
        assert_ne!(dev.account.secret_key_b58, sb.account.secret_key_b58);
        assert_eq!(store.save_count(), 2);

        // Cache hits don't write.
        let dev2 = load_or_create_ephemeral_for_network("devnet", &store).unwrap();
        assert_eq!(dev2.account.pubkey, dev.account.pubkey);
        assert!(!dev2.created);
        assert_eq!(store.save_count(), 2);
    }

    // ── FileAccountsStore round-trip ──────────────────────────────────────

    #[test]
    fn file_store_round_trip_via_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.yml");
        let store = FileAccountsStore::at(path.clone());

        // Empty file → empty AccountsFile.
        let empty = store.load().unwrap();
        assert_eq!(empty.version, 2);
        assert!(empty.accounts.is_empty());

        // Lazy-create writes account under accounts[sandbox][default].
        let resolved = load_or_create_ephemeral_for_network("sandbox", &store).unwrap();
        assert!(resolved.created);
        assert!(path.exists());

        // Re-open with a fresh store handle to confirm persistence.
        let store2 = FileAccountsStore::at(path.clone());
        let resolved2 = load_or_create_ephemeral_for_network("sandbox", &store2).unwrap();
        assert!(!resolved2.created);
        assert_eq!(resolved2.account.pubkey, resolved.account.pubkey);
    }

    #[test]
    fn file_store_handles_missing_file_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileAccountsStore::at(dir.path().join("does-not-exist.yml"));
        let f = store.load().unwrap();
        assert_eq!(f.version, 2);
        assert!(f.accounts.is_empty());
    }

    #[test]
    fn file_store_handles_empty_file_as_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("accounts.yml");
        std::fs::write(&path, "").unwrap();
        let store = FileAccountsStore::at(path);
        let f = store.load().unwrap();
        assert!(f.accounts.is_empty());
    }

    // ── YAML shape ────────────────────────────────────────────────────────

    #[test]
    fn yaml_shape_has_version_and_accounts_nested() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        let yaml = serde_yml::to_string(&f).unwrap();
        assert!(yaml.contains("version:"));
        assert!(yaml.contains("accounts:"));
        assert!(yaml.contains("mainnet:"));
        assert!(yaml.contains("default:"));
        assert!(yaml.contains("apple-keychain"));
        // No top-level 'networks:' key
        assert!(!yaml.contains("\nnetworks:"));
    }

    #[test]
    fn yaml_skips_none_fields() {
        let acct = keychain_account("pk");
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(!yaml.contains("auth_required"));
        assert!(!yaml.contains("vault"));
        assert!(!yaml.contains("path"));
        assert!(!yaml.contains("secret_key_b58"));
        assert!(!yaml.contains("created_at"));
    }

    #[test]
    fn yaml_skips_active_when_false() {
        let acct = keychain_account("pk");
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(!yaml.contains("active"));
    }

    #[test]
    fn yaml_includes_active_when_true() {
        let mut acct = keychain_account("pk");
        acct.active = true;
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(yaml.contains("active: true"));
    }

    #[test]
    fn yaml_includes_auth_required_when_set() {
        let mut acct = keychain_account("pk");
        acct.auth_required = Some(false);
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(yaml.contains("auth_required: false"));
    }

    #[test]
    fn yaml_includes_ephemeral_fields() {
        let acct = fake_ephemeral("EphPk");
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(yaml.contains("ephemeral"));
        assert!(yaml.contains("secret_key_b58"));
        assert!(yaml.contains("created_at"));
    }

    // ── Subscriptions ──────────────────────────────────────────────────────

    #[test]
    fn yaml_skips_subscriptions_when_empty() {
        let acct = keychain_account("pk");
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(
            !yaml.contains("subscriptions"),
            "empty subscriptions map should be omitted: {yaml}"
        );
    }

    #[test]
    fn yaml_round_trip_with_subscription() {
        let mut acct = keychain_account("pk");
        acct.subscriptions.insert(
            "BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE".to_string(),
            fake_subscription("BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE", "PlanPDAa"),
        );
        let yaml = serde_yml::to_string(&acct).unwrap();
        assert!(yaml.contains("subscriptions:"));
        assert!(yaml.contains("BXQGmO5VwTrl5RfFr6Y8XQZ4nPj9QqMOiKkRn3pZ4ZE"));
        assert!(yaml.contains("status: active"));
        // Optional `program_id` is omitted when None.
        assert!(!yaml.contains("program_id:"));

        let back: Account = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(back.subscriptions.len(), 1);
        let sub = back.subscriptions.values().next().unwrap();
        assert_eq!(sub.status, SubscriptionStatus::Active);
        assert_eq!(sub.period_unit, "day");
        assert_eq!(sub.period_count, 30);
    }

    #[test]
    fn upsert_subscription_attaches_to_named_account() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));

        f.upsert_subscription(
            MAINNET_NETWORK,
            "default",
            fake_subscription("Sub1", "Plan1"),
        )
        .unwrap();

        let stored = f
            .find_subscription(MAINNET_NETWORK, "default", "Sub1")
            .unwrap();
        assert_eq!(stored.plan_id, "Plan1");
    }

    #[test]
    fn upsert_subscription_overwrites_existing_id() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));

        let mut sub = fake_subscription("Sub1", "Plan1");
        f.upsert_subscription(MAINNET_NETWORK, "default", sub.clone())
            .unwrap();

        sub.last_charged_period = Some(3);
        f.upsert_subscription(MAINNET_NETWORK, "default", sub.clone())
            .unwrap();

        let stored = f
            .find_subscription(MAINNET_NETWORK, "default", "Sub1")
            .unwrap();
        assert_eq!(stored.last_charged_period, Some(3));
        // Still exactly one entry, not duplicated.
        let acct = f
            .accounts
            .get(MAINNET_NETWORK)
            .unwrap()
            .get("default")
            .unwrap();
        assert_eq!(acct.subscriptions.len(), 1);
    }

    #[test]
    fn upsert_subscription_errors_when_account_missing() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));

        let err = f
            .upsert_subscription(MAINNET_NETWORK, "ghost", fake_subscription("Sub1", "Plan1"))
            .unwrap_err();
        assert!(format!("{err}").contains("ghost"));

        let err = f
            .upsert_subscription("devnet", "default", fake_subscription("Sub1", "Plan1"))
            .unwrap_err();
        assert!(format!("{err}").contains("devnet"));
    }

    #[test]
    fn remove_subscription_returns_previous_entry() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));
        f.upsert_subscription(
            MAINNET_NETWORK,
            "default",
            fake_subscription("Sub1", "Plan1"),
        )
        .unwrap();

        let removed = f
            .remove_subscription(MAINNET_NETWORK, "default", "Sub1")
            .unwrap();
        assert_eq!(removed.plan_id, "Plan1");
        assert!(
            f.find_subscription(MAINNET_NETWORK, "default", "Sub1")
                .is_none()
        );
    }

    #[test]
    fn set_subscription_status_flips_lifecycle() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));
        f.upsert_subscription(
            MAINNET_NETWORK,
            "default",
            fake_subscription("Sub1", "Plan1"),
        )
        .unwrap();

        f.set_subscription_status(
            MAINNET_NETWORK,
            "default",
            "Sub1",
            SubscriptionStatus::Cancelled,
        );
        let s = f
            .find_subscription(MAINNET_NETWORK, "default", "Sub1")
            .unwrap();
        assert_eq!(s.status, SubscriptionStatus::Cancelled);
        assert!(!s.status.is_active());
    }

    #[test]
    fn set_subscription_status_is_noop_for_unknown_id() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk"));
        f.set_subscription_status(
            MAINNET_NETWORK,
            "default",
            "Ghost",
            SubscriptionStatus::Cancelled,
        );
        // Nothing to assert besides "did not panic".
        let acct = f
            .accounts
            .get(MAINNET_NETWORK)
            .unwrap()
            .get("default")
            .unwrap();
        assert!(acct.subscriptions.is_empty());
    }

    #[test]
    fn all_subscriptions_flattens_across_networks_and_accounts() {
        let mut f = AccountsFile::default();
        f.upsert(MAINNET_NETWORK, "default", keychain_account("pk1"));
        f.upsert(MAINNET_NETWORK, "work", keychain_account("pk2"));
        f.upsert("devnet", "default", fake_ephemeral("pk3"));

        f.upsert_subscription(
            MAINNET_NETWORK,
            "default",
            fake_subscription("SubA", "PlanA"),
        )
        .unwrap();
        f.upsert_subscription(MAINNET_NETWORK, "work", fake_subscription("SubB", "PlanB"))
            .unwrap();
        f.upsert_subscription("devnet", "default", fake_subscription("SubC", "PlanC"))
            .unwrap();

        let mut seen: Vec<(&str, &str, &str)> = f
            .all_subscriptions()
            .map(|(net, name, sub)| (net, name, sub.subscription_id.as_str()))
            .collect();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                ("devnet", "default", "SubC"),
                ("mainnet", "default", "SubA"),
                ("mainnet", "work", "SubB"),
            ]
        );
    }

    #[test]
    fn subscription_status_kebab_case_serializes_round_trip() {
        for s in [
            SubscriptionStatus::Active,
            SubscriptionStatus::Cancelled,
            SubscriptionStatus::Expired,
        ] {
            let yaml = serde_yml::to_string(&s).unwrap();
            let back: SubscriptionStatus = serde_yml::from_str(&yaml).unwrap();
            assert_eq!(back, s);
        }
    }
}
