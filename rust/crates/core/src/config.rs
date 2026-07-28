use figment::Figment;
use figment::providers::{Env, Format, Serialized, Toml};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const LOCAL_RPC_URL: &str = "http://localhost:8899";
pub const SANDBOX_RPC_URL: &str = "https://402.surfnet.dev:8899";

/// Logging format for operational logs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Application configuration, loaded from config file and environment variables.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Whether to automatically pay 402 challenges without prompting.
    pub auto_pay: bool,

    /// Path to the Solana keypair file.
    pub keypair: Option<String>,

    /// RPC URL used for local development commands.
    pub rpc_url: Option<String>,

    /// Logging format for operational logs.
    pub log_format: LogFormat,
}

impl Config {
    /// Load configuration from the first existing config file and `PAY_` prefixed env vars.
    pub fn load() -> crate::Result<Self> {
        let config_path = find_config_path()?;
        Self::load_from_path(config_path.as_deref())
    }

    /// Load configuration from an explicit file path and `PAY_` prefixed env vars.
    pub fn load_from_path(path: Option<&Path>) -> crate::Result<Self> {
        let mut figment = Figment::new().merge(Serialized::defaults(Config::default()));
        if let Some(path) = path {
            figment = figment.merge(Toml::file(path));
        }

        figment
            .merge(Env::prefixed("PAY_"))
            .extract()
            .map_err(|e| crate::Error::Config(e.to_string()))
    }

    /// Get the keypair path if configured.
    pub fn keypair_path(&self) -> Option<&str> {
        self.keypair
            .as_deref()
            .filter(|path| !path.trim().is_empty())
    }

    /// Resolve the configured RPC URL or fall back to the local default.
    pub fn rpc_url(&self) -> &str {
        self.rpc_url
            .as_deref()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or(LOCAL_RPC_URL)
    }

    /// Resolve the preferred keypair source for commands that need to sign.
    ///
    /// Resolution order:
    /// 1. `accounts.yml` default account
    /// 2. `PAY_ACTIVE_ACCOUNT` env var
    /// 3. Config file `keypair` field
    /// 4. Legacy: probe platform-native keystores directly
    pub fn default_active_account_name(&self) -> Option<String> {
        // 1. accounts.yml — only return a source string for keystore-backed
        //    accounts. Ephemeral accounts have no signer source string and
        //    must be loaded via the network-aware path instead, so they're
        //    intentionally invisible to this fallback.
        if let Ok(accounts) = crate::accounts::AccountsFile::load()
            && let Some((name, account)) = accounts.default_account()
            && let Some(source) = account.signer_source(name)
        {
            return Some(source);
        }

        // 2. PAY_ACTIVE_ACCOUNT env var
        if let Ok(path) = std::env::var("PAY_ACTIVE_ACCOUNT") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }

        self.legacy_keypair_source()
    }

    /// Resolve only legacy raw signer configuration.
    ///
    /// Unlike [`Self::default_active_account_name`], this deliberately skips
    /// `accounts.yml` and `PAY_ACTIVE_ACCOUNT`; callers that need account
    /// policy must resolve those names through the network-aware signer path.
    pub fn legacy_keypair_source(&self) -> Option<String> {
        if let Some(path) = self.keypair_path() {
            return Some(expand_path(path).to_string());
        }

        // Legacy: probe platform-native keystores directly (no
        // accounts.yml yet). Do not probe 1Password here: `op item get`
        // can show a desktop auth prompt just to answer "does this item
        // exist?", which is surprising for commands like `pay claude` on a
        // machine with no pay account configured.
        #[cfg(target_os = "macos")]
        {
            let ks = crate::keystore::Keystore::apple_keychain();
            if ks.exists("default") {
                return Some("keychain:default".to_string());
            }
        }
        #[cfg(target_os = "linux")]
        {
            let ks = crate::keystore::Keystore::gnome_keyring();
            if ks.exists("default") {
                return Some("gnome-keyring:default".to_string());
            }
        }
        None
    }
}

fn find_config_path() -> crate::Result<Option<PathBuf>> {
    if let Ok(path) = std::env::var("PAY_CONFIG") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            let expanded = PathBuf::from(expand_path(trimmed).into_owned());
            if !expanded.exists() {
                return Err(crate::Error::Config(format!(
                    "Config file not found: {}",
                    expanded.display()
                )));
            }
            return Ok(Some(expanded));
        }
    }

    let local = PathBuf::from("pay.toml");
    if local.exists() {
        return Ok(Some(local));
    }

    let home = PathBuf::from(expand_path("~/.config/pay/pay.toml").into_owned());
    if home.exists() {
        return Ok(Some(home));
    }

    Ok(None)
}

fn expand_path(path: &str) -> std::borrow::Cow<'_, str> {
    shellexpand::tilde(path)
}

#[cfg(test)]
mod tests {
    use super::{Config, LogFormat};
    use serial_test::serial;
    use std::io::Write;

    #[test]
    fn keypair_path_ignores_blank_strings() {
        let config = Config {
            keypair: Some("   ".to_string()),
            ..Config::default()
        };

        assert_eq!(config.keypair_path(), None);
    }

    #[test]
    fn rpc_url_falls_back_to_default() {
        let config = Config::default();

        assert_eq!(config.rpc_url(), super::LOCAL_RPC_URL);
    }

    #[test]
    #[serial]
    fn load_from_path_reads_config_file() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config_path = temp_dir.path().join("pay.toml");
        let mut file = std::fs::File::create(&config_path).expect("create config");
        writeln!(
            file,
            "auto_pay = true\nkeypair = \"~/.config/solana/id.json\"\nrpc_url = \"https://rpc.example.com\"\nlog_format = \"json\""
        )
        .expect("write config");

        let config = Config::load_from_path(Some(&config_path)).expect("load config");

        assert!(config.auto_pay);
        assert_eq!(config.keypair_path(), Some("~/.config/solana/id.json"));
        assert_eq!(config.rpc_url(), "https://rpc.example.com");
        assert_eq!(config.log_format, LogFormat::Json);
    }

    #[test]
    #[serial]
    fn load_from_path_with_none_uses_defaults() {
        let config = Config::load_from_path(None).expect("load default config");
        assert!(!config.auto_pay);
        assert_eq!(config.keypair_path(), None);
        assert_eq!(config.rpc_url(), super::LOCAL_RPC_URL);
        assert_eq!(config.log_format, LogFormat::Text);
    }

    #[test]
    fn keypair_path_returns_valid_path() {
        let config = Config {
            keypair: Some("/home/user/.config/solana/id.json".to_string()),
            ..Config::default()
        };
        assert_eq!(
            config.keypair_path(),
            Some("/home/user/.config/solana/id.json")
        );
    }

    #[test]
    fn keypair_path_ignores_empty_string() {
        let config = Config {
            keypair: Some("".to_string()),
            ..Config::default()
        };
        assert_eq!(config.keypair_path(), None);
    }

    #[test]
    fn keypair_path_none_when_not_set() {
        let config = Config::default();
        assert_eq!(config.keypair_path(), None);
    }

    #[test]
    fn rpc_url_ignores_blank() {
        let config = Config {
            rpc_url: Some("   ".to_string()),
            ..Config::default()
        };
        assert_eq!(config.rpc_url(), super::LOCAL_RPC_URL);
    }

    #[test]
    fn rpc_url_uses_custom() {
        let config = Config {
            rpc_url: Some("https://custom.rpc.com".to_string()),
            ..Config::default()
        };
        assert_eq!(config.rpc_url(), "https://custom.rpc.com");
    }

    #[test]
    fn config_default_values() {
        let config = Config::default();
        assert!(!config.auto_pay);
        assert!(config.keypair.is_none());
        assert!(config.rpc_url.is_none());
        assert_eq!(config.log_format, LogFormat::Text);
    }

    #[test]
    fn log_format_serde_roundtrip() {
        for fmt in [LogFormat::Text, LogFormat::Json] {
            let json = serde_json::to_string(&fmt).unwrap();
            let back: LogFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(back, fmt);
        }
    }

    #[test]
    #[serial]
    fn load_partial_config() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let config_path = temp_dir.path().join("pay.toml");
        let mut file = std::fs::File::create(&config_path).expect("create config");
        writeln!(file, "auto_pay = true").expect("write config");

        let config = Config::load_from_path(Some(&config_path)).expect("load config");
        assert!(config.auto_pay);
        // Other fields should be defaults
        assert_eq!(config.keypair_path(), None);
        assert_eq!(config.rpc_url(), super::LOCAL_RPC_URL);
    }

    // Note: find_config_path() and default_active_account_name() depend on env vars
    // (PAY_CONFIG, PAY_ACTIVE_ACCOUNT) and machine state (accounts.yml, keystores).
    // Env-based tests are flaky under parallel execution, so we test the
    // deterministic parts and trust the integration tests for the rest.

    #[test]
    fn default_active_account_name_returns_some_or_none() {
        let config = Config::default();
        let _ = config.default_active_account_name();
    }

    #[test]
    fn expand_path_expands_tilde() {
        let expanded = super::expand_path("~/test");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.ends_with("/test"));
    }
}
