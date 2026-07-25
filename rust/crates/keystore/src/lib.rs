//! pay-keystore — pluggable secure storage for Solana keypairs.
//!
//! Separates two concerns:
//! - **AuthGate** — how the user proves identity (Touch ID, Windows Hello, polkit, none)
//! - **SecretStore** — where encrypted bytes live (Keychain, Credential Manager, 1Password, memory)
//!
//! The `Keystore` struct composes them with shared logic (keypair validation, pubkey separation).

pub mod auth;
mod error;
pub mod store;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

pub use auth::{AuthGate, AuthIntent, PaymentLimit};
pub use error::{Error, Result};
pub use store::SecretStore;
pub use zeroize::Zeroizing;

/// Controls whether the key syncs to cloud storage.
#[derive(Debug, Clone, Copy, Default)]
pub enum SyncMode {
    /// Key stays on this device only (default).
    #[default]
    ThisDeviceOnly,
    /// Key syncs to cloud (iCloud Keychain, 1Password, etc.).
    CloudSync,
}

/// Composed keystore: auth gate + secret store + shared logic.
///
/// # Security note
///
/// The auth gate is an **advisory** layer — callers can construct a
/// `Keystore` with [`NoAuth`](auth::NoAuth) paired with any platform
/// store. The real security boundary is the OS credential store itself
/// (Keychain ACLs, DPAPI, Secret Service encryption). The auth gate
/// provides UX-level protection (biometric prompts) but does not prevent
/// programmatic access by code running in the same process.
pub struct Keystore {
    auth: Box<dyn AuthGate>,
    store: Box<dyn SecretStore>,
    auth_on_write: bool,
}

impl Keystore {
    /// Create a keystore from any auth gate and secret store.
    pub fn new(
        auth: impl AuthGate + 'static,
        store: impl SecretStore + 'static,
        auth_on_write: bool,
    ) -> Self {
        Self {
            auth: Box::new(auth),
            store: Box::new(store),
            auth_on_write,
        }
    }

    /// In-memory keystore for testing. No auth, no persistence.
    pub fn in_memory() -> Self {
        Self::new(auth::NoAuth, store::InMemoryStore::new(), false)
    }

    /// Owner-only Solana JSON keypair file without a setup-time auth prompt.
    ///
    /// The file is not encrypted. Callers persisting a mainnet account should
    /// keep `auth_required` enabled so runtime access is approved separately.
    pub fn file(path: impl Into<std::path::PathBuf>) -> Self {
        Self::new(auth::NoAuth, store::FileStore::new(path), false)
    }

    /// 1Password via `op` CLI with signout/signin auth cycle.
    pub fn onepassword(account: Option<String>) -> Self {
        Self::new(
            store::OnePasswordAuth::new(account.clone()),
            store::OnePasswordStore::new(account),
            true,
        )
    }

    /// 1Password targeting a specific vault.
    pub fn onepassword_with_vault(vault: impl Into<String>, account: Option<String>) -> Self {
        Self::new(
            store::OnePasswordAuth::new(account.clone()),
            store::OnePasswordStore::with_vault(vault, account),
            true,
        )
    }

    /// Check if 1Password CLI is available.
    pub fn onepassword_available() -> bool {
        store::OnePasswordStore::is_available()
    }

    /// macOS Keychain + Touch ID.
    #[cfg(target_os = "macos")]
    pub fn apple_keychain() -> Self {
        Self::new(macos::TouchId, macos::AppleKeychainStore, true)
    }

    /// Check if Touch ID is available (macOS only).
    #[cfg(target_os = "macos")]
    pub fn apple_touchid_available() -> bool {
        macos::TouchId.is_available()
    }

    /// GNOME Keyring + polkit auth.
    #[cfg(target_os = "linux")]
    pub fn gnome_keyring() -> Self {
        Self::new(linux::Polkit, linux::SecretServiceStore, true)
    }

    /// GNOME Keyring storage without a local Polkit gate.
    ///
    /// This is intended for explicit account setup/import in a headless
    /// session, or when a higher layer supplies its own authentication gate.
    /// Runtime signing should keep `auth_required` enabled and provide that
    /// gate rather than silently bypassing approval.
    #[cfg(target_os = "linux")]
    pub fn gnome_keyring_no_auth() -> Self {
        Self::new(auth::NoAuth, linux::SecretServiceStore, false)
    }

    /// Check if GNOME Secret Service storage is reachable (Linux only).
    #[cfg(target_os = "linux")]
    pub fn gnome_keyring_available() -> bool {
        linux::SecretServiceStore::is_available()
    }

    /// Check if this process has a local graphical Polkit prompt path.
    ///
    /// This is deliberately separate from Secret Service reachability: a
    /// headless service can have an unlocked keyring without having any local
    /// UI that can approve a signing request.
    #[cfg(target_os = "linux")]
    pub fn gnome_keyring_local_auth_available() -> bool {
        linux::Polkit.is_available()
    }

    /// Windows Credential Manager + Windows Hello.
    #[cfg(target_os = "windows")]
    pub fn windows_hello() -> Self {
        Self::new(
            windows::WindowsHelloAuth,
            windows::WindowsCredentialStore,
            true,
        )
    }

    /// Check if Windows Hello is available.
    #[cfg(target_os = "windows")]
    pub fn windows_hello_available() -> bool {
        windows::WindowsHelloAuth::is_available()
    }

    /// True when any platform biometric gate (Touch ID / Windows Hello /
    /// polkit) is usable on this machine. Cross-platform; used by
    /// callers that want to fall back to a remote approval channel
    /// (e.g. MCP elicitation) only when no local biometric exists.
    pub fn any_biometric_available() -> bool {
        #[cfg(target_os = "macos")]
        {
            if Self::apple_touchid_available() {
                return true;
            }
        }
        #[cfg(target_os = "linux")]
        {
            if Self::gnome_keyring_local_auth_available() {
                return true;
            }
        }
        #[cfg(target_os = "windows")]
        {
            if Self::windows_hello_available() {
                return true;
            }
        }
        false
    }

    /// Construct a keystore from already-boxed auth and store implementations.
    ///
    /// Useful when callers hold a `Box<dyn AuthGate + Send + Sync>` (e.g. an
    /// auth-gate override threaded down from a higher layer) and need to pair
    /// it with a platform-specific store without re-boxing through
    /// [`Keystore::new`]'s `impl AuthGate + 'static` parameter.
    pub fn from_boxed_auth(
        auth: Box<dyn AuthGate>,
        store: Box<dyn SecretStore>,
        auth_on_write: bool,
    ) -> Self {
        Self {
            auth,
            store,
            auth_on_write,
        }
    }

    // ── Public API ──────────────────────────────────────────────────────

    /// Import a 64-byte keypair (32 secret + 32 public).
    pub fn import(&self, account: &str, keypair_bytes: &[u8], _sync: SyncMode) -> Result<()> {
        self.import_with_intent(
            account,
            keypair_bytes,
            _sync,
            &AuthIntent::create_account(account),
        )
    }

    /// Import with a custom auth prompt reason shown to the user.
    pub fn import_with_reason(
        &self,
        account: &str,
        keypair_bytes: &[u8],
        _sync: SyncMode,
        reason: &str,
    ) -> Result<()> {
        self.import_with_intent(
            account,
            keypair_bytes,
            _sync,
            &AuthIntent::from_reason(reason),
        )
    }

    /// Import with a typed auth intent shown to the user where supported.
    pub fn import_with_intent(
        &self,
        account: &str,
        keypair_bytes: &[u8],
        _sync: SyncMode,
        intent: &AuthIntent,
    ) -> Result<()> {
        validate_account_name(account)?;
        validate_keypair(keypair_bytes)?;

        if self.auth_on_write {
            self.auth.authenticate(intent)?;
        }

        self.store.store(&keypair_key(account), keypair_bytes)?;
        self.store
            .store(&pubkey_key(account), &keypair_bytes[32..64])?;
        Ok(())
    }

    /// Check if a keypair exists for this account.
    pub fn exists(&self, account: &str) -> bool {
        validate_account_name(account).is_ok() && self.store.exists(&keypair_key(account))
    }

    /// Delete a keypair. `reason` is shown in the OS auth prompt (Touch ID, etc.).
    pub fn delete(&self, account: &str, reason: &str) -> Result<()> {
        self.delete_with_intent(account, &AuthIntent::from_reason(reason))
    }

    /// Delete a keypair with a typed auth intent.
    pub fn delete_with_intent(&self, account: &str, intent: &AuthIntent) -> Result<()> {
        validate_account_name(account)?;
        if self.auth_on_write {
            self.auth.authenticate(intent)?;
        }

        self.store.delete(&keypair_key(account))?;
        let _ = self.store.delete(&pubkey_key(account));
        Ok(())
    }

    /// Get the 32-byte public key without requiring auth.
    pub fn pubkey(&self, account: &str) -> Result<Vec<u8>> {
        validate_account_name(account)?;
        let pubkey = self.store.load(&pubkey_key(account))?;
        validate_pubkey(&pubkey)?;
        Ok(pubkey.to_vec())
    }

    /// Load the full 64-byte keypair. Triggers auth prompt.
    pub fn load_keypair(&self, account: &str, reason: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.load_keypair_with_intent(account, &AuthIntent::from_reason(reason))
    }

    /// Load the full 64-byte keypair with a typed auth intent.
    pub fn load_keypair_with_intent(
        &self,
        account: &str,
        intent: &AuthIntent,
    ) -> Result<Zeroizing<Vec<u8>>> {
        validate_account_name(account)?;
        self.auth.authenticate(intent)?;
        let keypair = self.store.load(&keypair_key(account))?;
        validate_keypair(&keypair)?;
        Ok(keypair)
    }

    /// Authenticate without loading anything (for standalone prompts).
    pub fn authenticate(&self, reason: &str) -> Result<()> {
        self.authenticate_intent(&AuthIntent::from_reason(reason))
    }

    /// Authenticate without loading anything using a typed auth intent.
    pub fn authenticate_intent(&self, intent: &AuthIntent) -> Result<()> {
        self.auth.authenticate(intent)
    }

    /// Check if the auth mechanism is available.
    pub fn auth_available(&self) -> bool {
        self.auth.is_available()
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────────

const KEYPAIR_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;
const KEYPAIR_KEY_PREFIX: &str = "keypair:";
const PUBKEY_KEY_PREFIX: &str = "pubkey:";
const RESERVED_PUBKEY_SUFFIX: &str = ".pubkey";

fn validate_account_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidKeypair(
            "account name cannot be empty".to_string(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        return Err(Error::InvalidKeypair(format!(
            "account name contains invalid characters: {name:?} (allowed: a-z, 0-9, '.', '_', '-')"
        )));
    }
    if name.to_ascii_lowercase().ends_with(RESERVED_PUBKEY_SUFFIX) {
        return Err(Error::InvalidKeypair(format!(
            "account name uses reserved suffix: {RESERVED_PUBKEY_SUFFIX}"
        )));
    }
    Ok(())
}

fn validate_keypair(bytes: &[u8]) -> Result<()> {
    if bytes.len() != KEYPAIR_LEN {
        return Err(Error::InvalidKeypair(format!(
            "expected {KEYPAIR_LEN} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn validate_pubkey(bytes: &[u8]) -> Result<()> {
    if bytes.len() != PUBKEY_LEN {
        return Err(Error::InvalidKeypair(format!(
            "expected {PUBKEY_LEN} public key bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn keypair_key(account: &str) -> String {
    format!("{KEYPAIR_KEY_PREFIX}{account}")
}

fn pubkey_key(account: &str) -> String {
    format!("{PUBKEY_KEY_PREFIX}{account}")
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> Vec<u8> {
        let mut bytes = vec![0xAA; 32];
        bytes.extend_from_slice(&[0xBB; 32]);
        bytes
    }

    #[test]
    fn in_memory_import_and_exists() {
        let ks = Keystore::in_memory();
        assert!(!ks.exists("test"));
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        assert!(ks.exists("test"));
    }

    #[test]
    fn in_memory_pubkey() {
        let ks = Keystore::in_memory();
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        let pubkey = ks.pubkey("test").unwrap();
        assert_eq!(pubkey, vec![0xBB; 32]);
    }

    #[test]
    fn in_memory_load_keypair() {
        let ks = Keystore::in_memory();
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        let kp = ks.load_keypair("test", "unit test").unwrap();
        assert_eq!(kp.len(), 64);
        assert_eq!(&kp[..32], &[0xAA; 32]);
        assert_eq!(&kp[32..], &[0xBB; 32]);
    }

    #[test]
    fn in_memory_delete() {
        let ks = Keystore::in_memory();
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        assert!(ks.exists("test"));
        ks.delete("test", "test").unwrap();
        assert!(!ks.exists("test"));
    }

    #[test]
    fn in_memory_load_nonexistent() {
        let ks = Keystore::in_memory();
        assert!(ks.load_keypair("missing", "test").is_err());
    }

    #[test]
    fn in_memory_pubkey_nonexistent() {
        let ks = Keystore::in_memory();
        assert!(ks.pubkey("missing").is_err());
    }

    #[test]
    fn validate_keypair_wrong_size() {
        let ks = Keystore::in_memory();
        let result = ks.import("test", &[0u8; 32], SyncMode::ThisDeviceOnly);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 64 bytes")
        );
    }

    #[test]
    fn validate_keypair_empty() {
        let ks = Keystore::in_memory();
        assert!(ks.import("test", &[], SyncMode::ThisDeviceOnly).is_err());
    }

    #[test]
    fn in_memory_multiple_accounts() {
        let ks = Keystore::in_memory();
        let mut kp1 = vec![0x11; 32];
        kp1.extend_from_slice(&[0x22; 32]);
        let mut kp2 = vec![0x33; 32];
        kp2.extend_from_slice(&[0x44; 32]);

        ks.import("acct1", &kp1, SyncMode::ThisDeviceOnly).unwrap();
        ks.import("acct2", &kp2, SyncMode::ThisDeviceOnly).unwrap();

        assert_eq!(ks.pubkey("acct1").unwrap(), vec![0x22; 32]);
        assert_eq!(ks.pubkey("acct2").unwrap(), vec![0x44; 32]);

        ks.delete("acct1", "test").unwrap();
        assert!(!ks.exists("acct1"));
        assert!(ks.exists("acct2"));
    }

    #[test]
    fn in_memory_overwrite() {
        let ks = Keystore::in_memory();
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();

        let mut kp2 = vec![0xCC; 32];
        kp2.extend_from_slice(&[0xDD; 32]);
        ks.import("test", &kp2, SyncMode::ThisDeviceOnly).unwrap();

        assert_eq!(ks.pubkey("test").unwrap(), vec![0xDD; 32]);
    }

    #[test]
    fn auth_on_write() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingAuth(Arc<AtomicU32>);
        impl AuthGate for CountingAuth {
            fn authenticate(&self, _intent: &AuthIntent) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn is_available(&self) -> bool {
                true
            }
        }

        let counter = Arc::new(AtomicU32::new(0));
        let ks = Keystore {
            auth: Box::new(CountingAuth(counter.clone())),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: true,
        };

        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1); // import calls auth

        ks.load_keypair("test", "test").unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2); // load_keypair calls auth

        ks.delete("test", "test").unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 3); // delete calls auth
    }

    #[test]
    fn no_auth_on_write() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        struct CountingAuth(Arc<AtomicU32>);
        impl AuthGate for CountingAuth {
            fn authenticate(&self, _intent: &AuthIntent) -> Result<()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            fn is_available(&self) -> bool {
                true
            }
        }

        let counter = Arc::new(AtomicU32::new(0));
        let ks = Keystore {
            auth: Box::new(CountingAuth(counter.clone())),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: false,
        };

        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 0); // import does NOT call auth

        ks.load_keypair("test", "test").unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1); // load_keypair calls auth

        ks.delete("test", "test").unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1); // delete does NOT call auth
    }

    #[test]
    fn no_auth_is_always_available() {
        let ks = Keystore::in_memory();
        assert!(ks.auth_available());
    }

    #[test]
    fn authenticate_standalone() {
        let ks = Keystore::in_memory();
        ks.authenticate("test reason").unwrap();
    }

    #[test]
    fn delete_nonexistent_succeeds() {
        let ks = Keystore::in_memory();
        ks.delete("nonexistent", "test").unwrap();
    }

    #[test]
    fn sync_mode_default_is_this_device_only() {
        assert!(matches!(SyncMode::default(), SyncMode::ThisDeviceOnly));
    }

    #[test]
    fn keypair_key_naming() {
        assert_eq!(keypair_key("default"), "keypair:default");
        assert_eq!(pubkey_key("default"), "pubkey:default");
    }

    #[test]
    fn reserved_pubkey_suffix_is_rejected() {
        let ks = Keystore::in_memory();
        let result = ks.import("victim.pubkey", &test_keypair(), SyncMode::ThisDeviceOnly);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved suffix"));
        assert!(!ks.exists("victim.pubkey"));
    }

    #[test]
    fn pubkey_rejects_private_keypair_sized_value() {
        let ks = Keystore::in_memory();
        ks.store
            .store(&pubkey_key("victim"), &test_keypair())
            .unwrap();

        let result = ks.pubkey("victim");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 32 public key bytes")
        );
    }

    #[test]
    fn typed_storage_keys_do_not_alias_valid_account_names() {
        let ks = Keystore::in_memory();
        ks.import("victim", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();

        assert!(ks.exists("victim"));
        assert!(!ks.exists("keypair:victim"));
        assert!(!ks.exists("pubkey:victim"));
    }

    #[test]
    fn hex_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = store::hex_encode(&data);
        assert_eq!(&*hex, "deadbeef");
        let decoded = store::hex_decode(&hex).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hex_decode_odd_length() {
        assert!(store::hex_decode("abc").is_err());
    }

    #[test]
    fn hex_decode_invalid_chars() {
        assert!(store::hex_decode("zzzz").is_err());
    }

    // ── Auth denial tests ───────────────────────────────────────────────

    struct DenyAuth;
    impl AuthGate for DenyAuth {
        fn authenticate(&self, _intent: &AuthIntent) -> Result<()> {
            Err(Error::AuthDenied("denied by test".to_string()))
        }
        fn is_available(&self) -> bool {
            true
        }
    }

    #[test]
    fn import_denied_when_auth_on_write() {
        let ks = Keystore {
            auth: Box::new(DenyAuth),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: true,
        };
        let result = ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("denied"));
        // Nothing should be stored
        assert!(!ks.exists("test"));
    }

    #[test]
    fn import_succeeds_without_auth_when_auth_on_write_false() {
        let ks = Keystore {
            auth: Box::new(DenyAuth),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: false,
        };
        // DenyAuth would reject, but auth_on_write=false skips it for import
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        assert!(ks.exists("test"));
    }

    #[test]
    fn load_keypair_denied() {
        let ks = Keystore {
            auth: Box::new(DenyAuth),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: false,
        };
        // Import works (no auth on write)
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        // But loading requires auth — should be denied
        let result = ks.load_keypair("test", "test reason");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("denied"));
    }

    #[test]
    fn delete_denied_when_auth_on_write() {
        let ks = Keystore {
            auth: Box::new(DenyAuth),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: true,
        };
        // Manually store without going through import (which would also be denied)
        ks.store
            .store(&keypair_key("test"), &test_keypair())
            .unwrap();
        ks.store.store(&pubkey_key("test"), &[0xBB; 32]).unwrap();

        let result = ks.delete("test", "test");
        assert!(result.is_err());
        // Key should still exist
        assert!(ks.exists("test"));
    }

    #[test]
    fn pubkey_does_not_require_auth() {
        let ks = Keystore {
            auth: Box::new(DenyAuth),
            store: Box::new(store::InMemoryStore::new()),
            auth_on_write: false,
        };
        ks.import("test", &test_keypair(), SyncMode::ThisDeviceOnly)
            .unwrap();
        // pubkey should work even with DenyAuth — no auth required for pubkey
        let pk = ks.pubkey("test").unwrap();
        assert_eq!(pk, vec![0xBB; 32]);
    }

    // ── Full lifecycle test ─────────────────────────────────────────────

    #[test]
    fn full_lifecycle_import_read_delete() {
        let ks = Keystore::in_memory();

        // Generate a realistic keypair
        let secret = [0x42u8; 32];
        let public = [0x7Fu8; 32];
        let mut keypair = Vec::new();
        keypair.extend_from_slice(&secret);
        keypair.extend_from_slice(&public);

        // Import
        ks.import("alice", &keypair, SyncMode::ThisDeviceOnly)
            .unwrap();
        assert!(ks.exists("alice"));
        assert!(!ks.exists("bob"));

        // Read pubkey (no auth)
        assert_eq!(ks.pubkey("alice").unwrap(), public);

        // Load full keypair (auth required — NoAuth passes)
        let loaded = ks.load_keypair("alice", "test").unwrap();
        assert_eq!(&loaded[..32], &secret);
        assert_eq!(&loaded[32..], &public);

        // Delete
        ks.delete("alice", "test").unwrap();
        assert!(!ks.exists("alice"));
        assert!(ks.pubkey("alice").is_err());
        assert!(ks.load_keypair("alice", "test").is_err());
    }
}
