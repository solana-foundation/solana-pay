//! `pay destroy` — remove an account and its keys.

use dialoguer::Confirm;
use owo_colors::OwoColorize;
use pay_core::accounts::{Account, AccountsFile, Keystore as KeystoreKind, MAINNET_NETWORK};
use pay_core::keystore::Keystore;

/// Permanently delete an account and its secret key.
///
/// Suggests exporting the keypair first. Removes the key from the
/// keystore backend and the entry from accounts.yml.
#[derive(clap::Args)]
pub struct DestroyCommand {
    /// Account name to destroy (required).
    #[arg(value_name = "NAME")]
    pub account: String,

    /// Remove from the sandbox (localnet) network instead of mainnet.
    #[arg(long)]
    pub sandbox: bool,

    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

impl DestroyCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let mut accounts = AccountsFile::load()?;

        let network = if self.sandbox {
            "localnet"
        } else {
            MAINNET_NETWORK
        };

        // Fall back to legacy keystore probe for mainnet accounts not yet in accounts.yml.
        let in_file = accounts
            .accounts
            .get(network)
            .and_then(|net| net.get(&self.account))
            .is_some();

        if !in_file
            && network == MAINNET_NETWORK
            && let Some(discovered) = discover_legacy_account(&self.account)
        {
            accounts.upsert(MAINNET_NETWORK, &self.account, discovered);
        }

        let entry = accounts
            .accounts
            .get(network)
            .and_then(|net| net.get(&self.account))
            .ok_or_else(|| {
                let available: Vec<String> = accounts
                    .accounts
                    .get(network)
                    .map(|net| net.keys().cloned().collect())
                    .unwrap_or_default();
                if available.is_empty() {
                    pay_core::Error::Config(format!("No {network} accounts found."))
                } else {
                    pay_core::Error::Config(format!(
                        "Account '{}' not found in {network}. Available: {}",
                        self.account,
                        available.join(", ")
                    ))
                }
            })?;

        let _pubkey = entry
            .pubkey
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let keystore_kind = entry.keystore.clone();
        let op_account = entry.account.clone();

        // Show account list with the target in red
        super::list::print_account_list(
            &accounts,
            Some(super::list::Highlight::Red {
                network,
                name: &self.account,
            }),
        );

        if !self.yes {
            let theme = dialoguer::theme::ColorfulTheme::default();

            // Offer to export first. Openfort accounts have no local
            // keypair to export — skip the offer.
            let export = keystore_kind != KeystoreKind::Openfort
                && Confirm::with_theme(&theme)
                    .with_prompt(format!(
                        "Export '{}' before removing?",
                        self.account.yellow()
                    ))
                    .default(true)
                    .interact()
                    .unwrap_or(false);

            if export {
                let export_path = format!("backup-{}.json", self.account);
                let export_cmd = super::export::ExportCommand {
                    name: self.account.clone(),
                    path: Some(export_path.clone()),
                };
                // Try exporting, but don't fail the whole remove if it errors
                match export_cmd.run() {
                    Ok(()) => {}
                    Err(e) => eprintln!("  {}", format!("Export failed: {e}").dimmed()),
                }
            }

            let confirmed = Confirm::with_theme(&theme)
                .with_prompt(format!(
                    "Permanently delete '{}'? This cannot be undone",
                    self.account.red()
                ))
                .default(false)
                .interact()
                .map_err(|e| pay_core::Error::Config(format!("Prompt error: {e}")))?;

            if !confirmed {
                eprintln!("{}", "  Cancelled.".dimmed());
                return Ok(());
            }
        }

        // Delete from keystore backend
        if keystore_kind == KeystoreKind::Openfort {
            // Remove the API credential blob from the platform secret
            // store. The backend wallet itself stays intact at Openfort.
            let intent = pay_core::keystore::AuthIntent::delete_account(&self.account);
            pay_core::openfort::delete_credentials(&self.account, &intent)
                .map_err(|e| pay_core::Error::Config(format!("{keystore_kind} delete: {e}")))?;
            eprintln!(
                "{}",
                "  Openfort credentials removed. The backend wallet still exists at Openfort."
                    .dimmed()
            );
        } else if let Some(ks) = keystore_for_kind(&keystore_kind, op_account)? {
            let intent = pay_core::keystore::AuthIntent::delete_account(&self.account);
            ks.delete_with_intent(&self.account, &intent)
                .map_err(|e| pay_core::Error::Config(format!("{keystore_kind} delete: {e}")))?;
        } else {
            // File-based or ephemeral — don't delete user-managed files
            eprintln!(
                "{}",
                "  File-based keypair left on disk (remove it manually if needed).".dimmed()
            );
        }

        // Check if this was the active mainnet account before removing.
        let was_default = accounts
            .default_account()
            .map(|(name, _)| name == self.account)
            .unwrap_or(false);

        accounts.remove(MAINNET_NETWORK, &self.account);

        // If we deleted the mainnet-default and there are remaining
        // accounts, prompt for a new active account.
        let remaining: Vec<String> = accounts
            .accounts
            .get(MAINNET_NETWORK)
            .map(|net| net.keys().cloned().collect())
            .unwrap_or_default();

        if was_default && !remaining.is_empty() {
            let has_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
            if has_tty {
                let selection =
                    dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                        .with_prompt("Choose new default account (mainnet)")
                        .items(&remaining)
                        .default(0)
                        .interact()
                        .ok();

                if let Some(idx) = selection {
                    accounts.set_active(MAINNET_NETWORK, &remaining[idx]);
                }
            }
        }

        accounts.save()?;

        let mainnet_empty = accounts
            .accounts
            .get(MAINNET_NETWORK)
            .is_none_or(|net| net.is_empty());

        if mainnet_empty {
            eprintln!();
            eprintln!(
                "{}",
                "  No accounts remaining. Run `pay account new` to create one.".dimmed()
            );
            eprintln!();
        } else {
            super::list::print_account_list(&accounts, None::<super::list::Highlight>);
        }

        Ok(())
    }
}

/// Build a Keystore for the given kind, or None for File-based/Ephemeral.
fn keystore_for_kind(
    kind: &KeystoreKind,
    op_account: Option<String>,
) -> pay_core::Result<Option<Keystore>> {
    match kind {
        #[cfg(target_os = "macos")]
        KeystoreKind::AppleKeychain => Ok(Some(Keystore::apple_keychain())),
        #[cfg(not(target_os = "macos"))]
        KeystoreKind::AppleKeychain => Err(pay_core::Error::Config(
            "Cannot delete Keychain entries on this platform".to_string(),
        )),

        #[cfg(target_os = "linux")]
        KeystoreKind::GnomeKeyring => Ok(Some(Keystore::gnome_keyring())),
        #[cfg(not(target_os = "linux"))]
        KeystoreKind::GnomeKeyring => Err(pay_core::Error::Config(
            "Cannot delete GNOME Keyring entries on this platform".to_string(),
        )),

        #[cfg(target_os = "windows")]
        KeystoreKind::WindowsHello => Ok(Some(Keystore::windows_hello())),
        #[cfg(not(target_os = "windows"))]
        KeystoreKind::WindowsHello => Err(pay_core::Error::Config(
            "Cannot delete Windows Hello entries on this platform".to_string(),
        )),

        KeystoreKind::OnePassword => Ok(Some(Keystore::onepassword(op_account))),
        KeystoreKind::File => Ok(None),
        // Ephemeral keypairs live entirely inside accounts.yml — there's
        // no external keystore to delete from. The earlier `accounts.remove`
        // call already wiped the entry, so we just no-op here.
        KeystoreKind::Ephemeral => Ok(None),
        // Openfort credential blobs are deleted through
        // `pay_core::openfort::delete_credentials` before this is called.
        KeystoreKind::Openfort => Ok(None),
    }
}

/// Probe keystores for a legacy account that predates accounts.yml.
fn discover_legacy_account(name: &str) -> Option<Account> {
    #[cfg(target_os = "macos")]
    {
        let ks = Keystore::apple_keychain();
        if ks.exists(name) {
            let pubkey = ks.pubkey(name).ok().map(|b| bs58::encode(&b).into_string());
            return Some(Account {
                keystore: KeystoreKind::AppleKeychain,
                active: false,
                auth_required: Some(true),
                pubkey,
                vault: None,
                account: None,
                path: None,
                secret_key_b58: None,
                created_at: None,
                subscriptions: std::collections::BTreeMap::new(),
            });
        }
    }

    #[cfg(target_os = "linux")]
    {
        let ks = Keystore::gnome_keyring();
        if ks.exists(name) {
            let pubkey = ks.pubkey(name).ok().map(|b| bs58::encode(&b).into_string());
            return Some(Account {
                keystore: KeystoreKind::GnomeKeyring,
                active: false,
                auth_required: Some(true),
                pubkey,
                vault: None,
                account: None,
                path: None,
                secret_key_b58: None,
                created_at: None,
                subscriptions: std::collections::BTreeMap::new(),
            });
        }
    }

    {
        let ks = Keystore::onepassword(None);
        if ks.exists(name) {
            let pubkey = ks.pubkey(name).ok().map(|b| bs58::encode(&b).into_string());
            return Some(Account {
                keystore: KeystoreKind::OnePassword,
                active: false,
                auth_required: Some(true),
                pubkey,
                vault: None,
                account: None,
                path: None,
                secret_key_b58: None,
                created_at: None,
                subscriptions: std::collections::BTreeMap::new(),
            });
        }
    }

    None
}
