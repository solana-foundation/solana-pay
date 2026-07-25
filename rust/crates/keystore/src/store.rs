//! Secret storage backends — where secret bytes are persisted.

use crate::{Error, Result, Zeroizing};

/// Where secrets are stored. Each impl handles raw byte storage only — no auth.
pub trait SecretStore: Send + Sync {
    fn store(&self, key: &str, data: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn exists(&self, key: &str) -> bool;
    fn delete(&self, key: &str) -> Result<()>;
}

// ── In-memory store (testing) ───────────────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory secret store for testing. Not persistent.
pub struct InMemoryStore {
    data: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for InMemoryStore {
    fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        self.data
            .lock()
            .unwrap()
            .insert(key.to_string(), Zeroizing::new(data.to_vec()));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.data
            .lock()
            .unwrap()
            .get(key)
            .map(|z| Zeroizing::new(z.to_vec()))
            .ok_or_else(|| Error::Backend(format!("key not found: {key}")))
    }

    fn exists(&self, key: &str) -> bool {
        self.data.lock().unwrap().contains_key(key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.data.lock().unwrap().remove(key);
        Ok(())
    }
}

// ── Owner-only keypair file ────────────────────────────────────────────────

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static FILE_STORE_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// A Solana JSON keypair file protected by owner-only filesystem permissions.
///
/// This backend is intentionally not encrypted. It is a pragmatic fallback for
/// headless service users that have no Secret Service session. Higher layers
/// should keep runtime authentication enabled (for example, MCP elicitation).
pub struct FileStore {
    path: PathBuf,
}

impl FileStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read_keypair(&self) -> Result<Zeroizing<Vec<u8>>> {
        let raw = Zeroizing::new(std::fs::read_to_string(&self.path).map_err(|e| {
            Error::Backend(format!("read keypair file {}: {e}", self.path.display()))
        })?);
        let bytes: Vec<u8> = serde_json::from_str(&raw).map_err(|e| {
            Error::Backend(format!("parse keypair file {}: {e}", self.path.display()))
        })?;
        if bytes.len() != 64 {
            return Err(Error::InvalidKeypair(format!(
                "keypair file {} contains {} bytes; expected 64",
                self.path.display(),
                bytes.len()
            )));
        }
        Ok(Zeroizing::new(bytes))
    }

    fn write_keypair(&self, data: &[u8]) -> Result<()> {
        if data.len() != 64 {
            return Err(Error::InvalidKeypair(format!(
                "file backend expected 64 keypair bytes, got {}",
                data.len()
            )));
        }

        if std::fs::symlink_metadata(&self.path).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return Err(Error::Backend(format!(
                "refusing to overwrite symlinked keypair file {}",
                self.path.display()
            )));
        }

        let parent = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Backend(format!(
                "create keypair directory {}: {e}",
                parent.display()
            ))
        })?;
        set_private_directory_permissions(parent)?;

        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("keypair.json");
        let temp_id = FILE_STORE_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{file_name}.pay-tmp-{}-{temp_id}",
            std::process::id()
        ));

        let result = write_temp_keypair(&temp_path, data).and_then(|()| {
            #[cfg(windows)]
            if self.path.exists() {
                std::fs::remove_file(&self.path)?;
            }
            std::fs::rename(&temp_path, &self.path)?;
            set_private_file_permissions(&self.path)
        });

        if result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
        }
        result
            .map_err(|e| Error::Backend(format!("write keypair file {}: {e}", self.path.display())))
    }
}

impl SecretStore for FileStore {
    fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        if key.starts_with("keypair:") {
            return self.write_keypair(data);
        }
        if key.starts_with("pubkey:") {
            if data.len() != 32 {
                return Err(Error::InvalidKeypair(format!(
                    "file backend expected 32 public-key bytes, got {}",
                    data.len()
                )));
            }
            let keypair = self.read_keypair()?;
            if keypair[32..] != data[..] {
                return Err(Error::InvalidKeypair(
                    "public key does not match the stored keypair".to_string(),
                ));
            }
            return Ok(());
        }
        Err(Error::Backend(format!("unsupported file-store key: {key}")))
    }

    fn load(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let keypair = self.read_keypair()?;
        if key.starts_with("keypair:") {
            return Ok(keypair);
        }
        if key.starts_with("pubkey:") {
            return Ok(Zeroizing::new(keypair[32..].to_vec()));
        }
        Err(Error::Backend(format!("unsupported file-store key: {key}")))
    }

    fn exists(&self, key: &str) -> bool {
        (key.starts_with("keypair:") || key.starts_with("pubkey:")) && self.path.exists()
    }

    fn delete(&self, key: &str) -> Result<()> {
        if key.starts_with("pubkey:") {
            return Ok(());
        }
        if !key.starts_with("keypair:") {
            return Err(Error::Backend(format!("unsupported file-store key: {key}")));
        }
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Backend(format!(
                "delete keypair file {}: {e}",
                self.path.display()
            ))),
        }
    }
}

fn write_temp_keypair(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    serde_json::to_writer(&mut file, data).map_err(std::io::Error::other)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn set_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            Error::Backend(format!(
                "set keypair directory permissions {}: {e}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ── Shared hex helpers ──────────────────────────────────────────────────────

pub fn hex_encode(data: &[u8]) -> Zeroizing<String> {
    use std::fmt::Write;
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        write!(s, "{b:02x}").unwrap();
    }
    Zeroizing::new(s)
}

pub fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::InvalidKeypair("odd hex length".to_string()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| Error::InvalidKeypair(format!("hex: {e}")))
        })
        .collect()
}

// ── 1Password via `op` CLI (cross-platform) ─────────────────────────────────

use std::process::Command;

const OP_TAG: &str = "pay";

/// Auth gate for 1Password that signs out and back in on every access,
/// forcing biometric/password via the 1Password desktop app integration.
pub struct OnePasswordAuth {
    /// 1Password account UUID or shorthand (e.g. "my.1password.com").
    account: Option<String>,
}

impl OnePasswordAuth {
    pub fn new(account: Option<String>) -> Self {
        Self { account }
    }

    fn signout(&self) {
        let mut cmd = Command::new("op");
        cmd.arg("signout");
        if let Some(acct) = &self.account {
            cmd.arg(format!("--account={acct}"));
        }
        let _ = cmd.output(); // best-effort
    }

    fn signin(&self) -> crate::Result<()> {
        let mut cmd = Command::new("op");
        cmd.arg("signin");
        if let Some(acct) = &self.account {
            cmd.arg(format!("--account={acct}"));
        }
        let output = cmd
            .output()
            .map_err(|e| crate::Error::Backend(format!("op signin: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            let err = stderr_str(&output.stderr);
            if err.contains("cancel") || err.contains("denied") || err.contains("dismissed") {
                Err(crate::Error::AuthDenied(err))
            } else {
                Err(crate::Error::Backend(format!(
                    "1Password sign-in failed: {err}"
                )))
            }
        }
    }
}

impl crate::AuthGate for OnePasswordAuth {
    fn authenticate(&self, _intent: &crate::AuthIntent) -> crate::Result<()> {
        self.signout();
        self.signin()
    }

    fn is_available(&self) -> bool {
        Command::new("op")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }
}

/// 1Password storage via the `op` CLI.
///
/// The auth gate (`OnePasswordAuth`) handles signout→signin before each
/// Keystore API call. Store methods use the active session without signing out.
pub struct OnePasswordStore {
    vault: Option<String>,
    account: Option<String>,
}

impl OnePasswordStore {
    pub fn new(account: Option<String>) -> Self {
        Self {
            vault: None,
            account,
        }
    }

    pub fn with_vault(vault: impl Into<String>, account: Option<String>) -> Self {
        Self {
            vault: Some(vault.into()),
            account,
        }
    }

    pub fn is_available() -> bool {
        Command::new("op")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn item_title(key: &str) -> String {
        format!("pay/{key}")
    }

    /// Build an `op` command with the account flag pre-set.
    fn op_cmd(&self) -> Command {
        let mut cmd = Command::new("op");
        if let Some(acct) = &self.account {
            cmd.arg(format!("--account={acct}"));
        }
        cmd
    }
}

impl SecretStore for OnePasswordStore {
    fn store(&self, key: &str, data: &[u8]) -> Result<()> {
        // The pubkey is already embedded in the Crypto Wallet's walletAddress
        // field, so skip creating a separate `.pubkey` item in 1Password.
        if key.ends_with(".pubkey") {
            return Ok(());
        }

        let title = Self::item_title(key);
        let hex = hex_encode(data);

        // Derive the base58 public key from the keypair for display in 1Password.
        let wallet_address = if data.len() == 64 {
            bs58::encode(&data[32..64]).into_string()
        } else {
            String::new()
        };

        // Best-effort delete before create to avoid duplicates.
        let _ = self.delete(key);

        let mut cmd = self.op_cmd();
        cmd.args([
            "item",
            "create",
            "--category=Crypto Wallet",
            &format!("--title={title}"),
            &format!("--tags={OP_TAG}"),
            &format!("recoveryPhrase[concealed]={}", *hex),
        ]);
        if !wallet_address.is_empty() {
            cmd.arg(format!("Wallet.wallet address[text]={wallet_address}"));
        }
        if let Some(vault) = &self.vault {
            cmd.arg(format!("--vault={vault}"));
        }

        let output = cmd.output().map_err(|e| {
            Error::Backend(format!(
                "Failed to run `op` CLI: {e}. Is 1Password CLI installed?"
            ))
        })?;

        if !output.status.success() {
            return Err(Error::Backend(format!(
                "op item create failed: {}",
                stderr_str(&output.stderr)
            )));
        }
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Zeroizing<Vec<u8>>> {
        let title = Self::item_title(key);
        let mut cmd = self.op_cmd();
        cmd.args(["item", "get", &title, "--fields=recoveryPhrase", "--reveal"]);
        if let Some(vault) = &self.vault {
            cmd.arg(format!("--vault={vault}"));
        }
        let output = cmd
            .output()
            .map_err(|e| Error::Backend(format!("op: {e}")))?;

        if !output.status.success() {
            let err = stderr_str(&output.stderr);
            if err.contains("authorization") || err.contains("denied") || err.contains("cancel") {
                return Err(Error::AuthDenied(err));
            }
            return Err(Error::Backend(format!("op item get failed: {err}")));
        }
        let hex = Zeroizing::new(String::from_utf8_lossy(&output.stdout).trim().to_string());
        hex_decode(&hex).map(Zeroizing::new)
    }

    fn exists(&self, key: &str) -> bool {
        let title = Self::item_title(key);
        let mut cmd = self.op_cmd();
        cmd.args(["item", "get", &title, "--format=json"]);
        if let Some(vault) = &self.vault {
            cmd.arg(format!("--vault={vault}"));
        }
        cmd.output().is_ok_and(|o| o.status.success())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let title = Self::item_title(key);
        let mut cmd = self.op_cmd();
        cmd.args(["item", "delete", &title]);
        if let Some(vault) = &self.vault {
            cmd.arg(format!("--vault={vault}"));
        }
        let output = cmd
            .output()
            .map_err(|e| Error::Backend(format!("op: {e}")))?;

        if !output.status.success() {
            let err = stderr_str(&output.stderr);
            if err.contains("not found") || err.contains("isn't an item") {
                return Ok(());
            }
            return Err(Error::Backend(format!("op item delete failed: {err}")));
        }
        Ok(())
    }
}

fn stderr_str(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_store_roundtrips_keypair_and_derived_pubkey() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("pay").join("server.json");
        let store = FileStore::new(path.clone());
        let keypair: Vec<u8> = (0..64).collect();

        store.store("keypair:server", &keypair).unwrap();
        store.store("pubkey:server", &keypair[32..]).unwrap();

        assert_eq!(&*store.load("keypair:server").unwrap(), &keypair);
        assert_eq!(&*store.load("pubkey:server").unwrap(), &keypair[32..]);
        assert!(store.exists("keypair:server"));
        assert!(store.exists("pubkey:server"));

        let serialized: Vec<u8> =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(serialized, keypair);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        store.delete("keypair:server").unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn file_store_rejects_mismatched_pubkey() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("server.json");
        let store = FileStore::new(path);
        let keypair: Vec<u8> = (0..64).collect();

        store.store("keypair:server", &keypair).unwrap();
        let error = store.store("pubkey:server", &[0; 32]).unwrap_err();

        assert!(
            matches!(error, Error::InvalidKeypair(message) if message.contains("does not match"))
        );
    }
}
