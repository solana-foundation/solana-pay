//! `pay account import` — import an account from a JSON key file.

use dialoguer::{Confirm, theme::ColorfulTheme};
use owo_colors::OwoColorize;
use pay_core::keystore::Keystore;

/// Import an account from a JSON key file into a secure keystore.
#[derive(clap::Args)]
pub struct ImportCommand {
    /// Account name (required).
    pub name: String,

    /// Path to the JSON key file.
    pub file: String,

    /// Storage backend: "keychain", "gnome-keyring", "windows-hello", or
    /// "file" (headless fallback).
    #[arg(long)]
    pub backend: Option<String>,

    /// Legacy vault name.
    #[arg(long, hide = true)]
    pub vault: Option<String>,
}

impl ImportCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let theme = ColorfulTheme::default();

        // 1. Read and validate keypair
        let expanded = shellexpand::tilde(&self.file);
        let data = std::fs::read_to_string(expanded.as_ref())
            .map_err(|e| pay_core::Error::Config(format!("Failed to read {}: {e}", self.file)))?;
        let keypair_bytes: Vec<u8> = serde_json::from_str(&data)
            .map_err(|e| pay_core::Error::Config(format!("Invalid keypair JSON: {e}")))?;

        if keypair_bytes.len() != 64 {
            return Err(pay_core::Error::Config(format!(
                "Expected 64 bytes, got {}",
                keypair_bytes.len()
            )));
        }

        let pubkey_b58 = bs58::encode(&keypair_bytes[32..64]).into_string();

        // 2. Display balance
        eprintln!();
        eprintln!("  {} {pubkey_b58}", "Pubkey:".dimmed());
        display_balance(&pubkey_b58);
        eprintln!();

        // 3. Check if this pubkey is already registered
        let mut accounts = pay_core::accounts::AccountsFile::load()?;
        if let Some((network, existing_name)) = find_account_by_pubkey(&accounts, &pubkey_b58) {
            let proceed = Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "This key is already registered as \"{}\" on {}. Import anyway?",
                    existing_name.yellow(),
                    network.yellow(),
                ))
                .default(false)
                .interact()
                .unwrap_or(false);

            if !proceed {
                eprintln!("Import cancelled.");
                return Ok(());
            }
        }

        // 4. Resolve account name — confirm overwrite if it already exists.
        let name = resolve_name(&theme, &self.name, &accounts)?;

        // 4. Pick backend and import
        let backend_id = match &self.backend {
            Some(b) => b.clone(),
            None => super::new::pick_backend()?,
        };

        let (ks, keystore_kind, _) =
            super::import::build_keystore(&backend_id, self.vault.as_deref(), &name)?;

        if backend_id == "file" && ks.exists(&name) {
            return Err(pay_core::Error::Config(format!(
                "Keypair file {} already exists. Choose another account name or remove the file explicitly before importing.",
                super::new::file_backend_path(&name).display()
            )));
        }

        let sync = if backend_id == "1password" {
            pay_core::keystore::SyncMode::CloudSync
        } else {
            pay_core::keystore::SyncMode::ThisDeviceOnly
        };

        let intent = pay_core::keystore::AuthIntent::import_account(&name);
        ks.import_with_intent(&name, &keypair_bytes, sync, &intent)
            .map_err(|e| pay_core::Error::Config(format!("{e}")))?;

        // 5. Save to accounts.yml under mainnet
        let is_first = accounts
            .accounts
            .get(pay_core::accounts::MAINNET_NETWORK)
            .is_none_or(|net| net.is_empty());

        accounts.upsert(
            pay_core::accounts::MAINNET_NETWORK,
            &name,
            pay_core::accounts::Account {
                keystore: keystore_kind,
                active: false,
                auth_required: Some(true),
                pubkey: Some(pubkey_b58),
                vault: self.vault,
                path: None,
                account: None,
                secret_key_b58: None,
                created_at: None,
                subscriptions: std::collections::BTreeMap::new(),
            },
        );

        // 6. Prompt for active (= mainnet default) if not the only account.
        let current_mainnet = accounts.default_account().map(|(n, _)| n.to_string());
        if !is_first && current_mainnet.as_deref() != Some(name.as_str()) {
            let make_default = Confirm::with_theme(&theme)
                .with_prompt(format!("Set '{}' as the default account?", name.green()))
                .default(false)
                .interact()
                .unwrap_or(false);

            if make_default {
                accounts.set_active(pay_core::accounts::MAINNET_NETWORK, &name);
            }
        }

        accounts.save()?;

        // 7. Show the account list with the new entry highlighted
        super::list::print_account_list(
            &accounts,
            Some(super::list::Highlight::Green {
                network: pay_core::accounts::MAINNET_NETWORK,
                name: &name,
            }),
        );

        Ok(())
    }
}

fn find_account_by_pubkey<'a>(
    accounts: &'a pay_core::accounts::AccountsFile,
    pubkey: &str,
) -> Option<(&'a str, &'a str)> {
    for (network, net_accounts) in &accounts.accounts {
        for (name, account) in net_accounts {
            if account.pubkey.as_deref() == Some(pubkey) {
                return Some((network, name));
            }
        }
    }
    None
}

fn display_balance(pubkey: &str) {
    let config = pay_core::Config::load().unwrap_or_default();
    let rpc_url = config
        .rpc_url
        .clone()
        .unwrap_or_else(pay_core::balance::mainnet_rpc_url);
    let bal = super::list::fetch_balance(pubkey);
    let display = super::list::format_balance_display(bal.as_ref(), Some(pubkey), &rpc_url);
    eprintln!("  {}  {}", "Balance:".dimmed(), display);
}

fn resolve_name(
    theme: &ColorfulTheme,
    name: &str,
    accounts: &pay_core::accounts::AccountsFile,
) -> pay_core::Result<String> {
    let has_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let exists = accounts
        .accounts
        .get(pay_core::accounts::MAINNET_NETWORK)
        .is_some_and(|net| net.contains_key(name));

    if exists && has_tty {
        let overwrite = Confirm::with_theme(theme)
            .with_prompt(format!(
                "Account '{}' already exists. Overwrite?",
                name.yellow()
            ))
            .default(false)
            .interact()
            .map_err(|e| pay_core::Error::Config(format!("Prompt error: {e}")))?;

        if !overwrite {
            return Err(pay_core::Error::Config("Import cancelled.".to_string()));
        }
    }
    Ok(name.to_string())
}

pub(super) fn build_keystore(
    backend_id: &str,
    vault: Option<&str>,
    account_name: &str,
) -> pay_core::Result<(Keystore, pay_core::accounts::Keystore, &'static str)> {
    match backend_id {
        #[cfg(target_os = "macos")]
        "keychain" => Ok((
            Keystore::apple_keychain(),
            pay_core::accounts::Keystore::AppleKeychain,
            "Stored in macOS Keychain.",
        )),
        #[cfg(not(target_os = "macos"))]
        "keychain" => Err(pay_core::Error::Config(
            "Keychain is only available on macOS".into(),
        )),

        #[cfg(target_os = "linux")]
        "gnome-keyring" => {
            let ks = super::new::gnome_keyring_for_account_write()?;
            Ok((
                ks,
                pay_core::accounts::Keystore::GnomeKeyring,
                "Stored in GNOME Keyring.",
            ))
        }
        #[cfg(not(target_os = "linux"))]
        "gnome-keyring" => Err(pay_core::Error::Config(
            "GNOME Keyring is only available on Linux".into(),
        )),

        #[cfg(target_os = "windows")]
        "windows-hello" => Ok((
            Keystore::windows_hello(),
            pay_core::accounts::Keystore::WindowsHello,
            "Stored in Windows Credential Manager.",
        )),
        #[cfg(not(target_os = "windows"))]
        "windows-hello" => Err(pay_core::Error::Config(
            "Windows Hello is only available on Windows".into(),
        )),

        "file" => Ok((
            Keystore::file(super::new::file_backend_path(account_name)),
            pay_core::accounts::Keystore::File,
            "Stored in an owner-only keypair file.",
        )),

        "1password" => {
            let op_account = super::new::resolve_op_account()?;
            let ks = match vault {
                Some(v) => Keystore::onepassword_with_vault(v, op_account),
                None => Keystore::onepassword(op_account),
            };
            Ok((
                ks,
                pay_core::accounts::Keystore::OnePassword,
                "Stored in 1Password.",
            ))
        }

        other => Err(pay_core::Error::Config(format!("Unknown backend: {other}"))),
    }
}
