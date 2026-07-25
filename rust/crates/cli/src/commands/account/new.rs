//! `pay account new` — generate a fresh keypair and store it.

use dialoguer::Select;
use owo_colors::OwoColorize;
use pay_core::keystore::Keystore;

/// Generate a new keypair and store it securely.
#[derive(clap::Args)]
pub struct NewCommand {
    /// Account name (required).
    pub name: String,

    /// Storage backend: "keychain" (macOS), "gnome-keyring" (Linux),
    /// "windows-hello" (Windows), or "file" (headless fallback).
    #[arg(long)]
    pub backend: Option<String>,

    /// Legacy vault name.
    #[arg(long, hide = true)]
    pub vault: Option<String>,

    /// Replace existing account.
    #[arg(long)]
    pub force: bool,
}

impl NewCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let (pubkey, backend_name) = create_account(
            &self.name,
            self.backend.as_deref(),
            self.vault.as_deref(),
            self.force,
        )?;
        eprintln!();

        let config = pay_core::Config::load().unwrap_or_default();
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(pay_core::balance::mainnet_rpc_url);
        let completion = crate::tui::run_topup_flow(&pubkey, &rpc_url, &self.name)?;
        print_next_steps(
            &self.name,
            backend_name,
            completion.as_ref().map(|c| &c.received),
        );
        Ok(())
    }
}

/// Core account creation logic. Returns the base58 pubkey on success.
/// Shared by `pay account new` and `pay setup`.
/// Returns `(pubkey_b58, backend_display_name)`.
pub fn create_account(
    name: &str,
    backend: Option<&str>,
    vault: Option<&str>,
    force: bool,
) -> pay_core::Result<(String, &'static str)> {
    let backend_id = resolve_backend(backend)?;

    let (ks, keystore_kind, backend_display, op_info) = build_keystore(&backend_id, vault, name)?;

    if ks.exists(name) && !force {
        let pubkey = ks
            .pubkey(name)
            .map_err(|e| pay_core::Error::Config(format!("{e}")))?;
        let pubkey_b58 = bs58::encode(&pubkey).into_string();
        eprintln!();
        crate::components::print_notice(
            crate::components::NoticeLevel::Info,
            "Account already exists",
            &format!(
                "`{name}` is already stored in {backend_display}.\nUse --force to replace it."
            ),
        );

        // Ensure the account is registered in accounts.yml even if the
        // keypair already exists in the keystore (e.g. after a reset).
        save_account(
            name,
            keystore_kind,
            &pubkey_b58,
            op_info.as_ref().and_then(|i| i.vault.clone()),
            None,
            op_info.as_ref().and_then(|i| i.account.clone()),
        )?;

        return Ok((pubkey_b58, backend_display));
    }

    let (keypair_bytes, pubkey_b58) = generate_keypair();

    let sync = if backend_id == "1password" {
        pay_core::keystore::SyncMode::CloudSync
    } else {
        pay_core::keystore::SyncMode::ThisDeviceOnly
    };

    let intent = pay_core::keystore::AuthIntent::create_account(name);
    ks.import_with_intent(name, &keypair_bytes, sync, &intent)
        .map_err(|e| pay_core::Error::Config(format!("{e}")))?;

    save_account(
        name,
        keystore_kind,
        &pubkey_b58,
        op_info
            .as_ref()
            .and_then(|i| i.vault.clone())
            .or(vault.map(|v| v.to_string())),
        None,
        op_info.as_ref().and_then(|i| i.account.clone()),
    )?;

    Ok((pubkey_b58, backend_display))
}

/// Resolved 1Password account info for storing in accounts.yml.
pub struct OpAccountInfo {
    pub vault: Option<String>,
    pub account: Option<String>,
}

fn build_keystore(
    backend_id: &str,
    vault: Option<&str>,
    account_name: &str,
) -> pay_core::Result<(
    Keystore,
    pay_core::accounts::Keystore,
    &'static str,
    Option<OpAccountInfo>,
)> {
    match backend_id {
        #[cfg(target_os = "macos")]
        "keychain" => {
            // When Touch ID is unavailable (no enrolled biometry — common
            // on VMs, CI runners, headless servers), the keychain store is
            // still usable, but the biometric gate has nothing to gate
            // with. Fall back to NoAuth so account setup can proceed.
            // Runtime signing still routes through the platform gate
            // (or the MCP elicitation override when invoked through
            // pay-mcp), so security at use-time is unchanged — only the
            // initial setup step relaxes when biometry is missing.
            let ks = if Keystore::apple_touchid_available() {
                Keystore::apple_keychain()
            } else {
                eprintln!(
                    "Note: Touch ID is not enrolled on this Mac; storing the new account in Apple Keychain without a biometric gate. Runtime signing will still require approval via the configured auth path."
                );
                Keystore::new(
                    pay_core::keystore::auth::NoAuth,
                    pay_core::keystore::macos::AppleKeychainStore,
                    false,
                )
            };
            Ok((
                ks,
                pay_core::accounts::Keystore::AppleKeychain,
                "Apple Keychain",
                None,
            ))
        }
        #[cfg(not(target_os = "macos"))]
        "keychain" => Err(pay_core::Error::Config(
            "Keychain is only available on macOS".to_string(),
        )),

        #[cfg(target_os = "linux")]
        "gnome-keyring" => {
            let ks = gnome_keyring_for_account_write()?;
            Ok((
                ks,
                pay_core::accounts::Keystore::GnomeKeyring,
                "GNOME Keyring",
                None,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        "gnome-keyring" => Err(pay_core::Error::Config(
            "GNOME Keyring is only available on Linux".to_string(),
        )),

        #[cfg(target_os = "windows")]
        "windows-hello" => {
            if !Keystore::windows_hello_available() {
                return Err(pay_core::Error::Config(
                    "Windows Hello is not configured.".to_string(),
                ));
            }
            Ok((
                Keystore::windows_hello(),
                pay_core::accounts::Keystore::WindowsHello,
                "Windows Hello",
                None,
            ))
        }
        #[cfg(not(target_os = "windows"))]
        "windows-hello" => Err(pay_core::Error::Config(
            "Windows Hello is only available on Windows".to_string(),
        )),

        "file" => Ok((
            Keystore::file(file_backend_path(account_name)),
            pay_core::accounts::Keystore::File,
            "owner-only keypair file",
            None,
        )),

        "1password" => {
            if !Keystore::onepassword_available() {
                return Err(pay_core::Error::Config(
                    "1Password CLI (`op`) is not installed or not signed in.".to_string(),
                ));
            }
            let op_account = resolve_op_account()?;
            let ks = match vault {
                Some(v) => Keystore::onepassword_with_vault(v, op_account.clone()),
                None => Keystore::onepassword(op_account.clone()),
            };
            Ok((
                ks,
                pay_core::accounts::Keystore::OnePassword,
                "1Password",
                Some(OpAccountInfo {
                    vault: vault.map(|v| v.to_string()),
                    account: op_account,
                }),
            ))
        }

        other => Err(pay_core::Error::Config(format!(
            "Unknown backend: {other}. Use {}.",
            available_backends_hint()
        ))),
    }
}

/// Comma-separated list of backends that work on the current OS.
/// Used in error messages so we don't suggest `keychain` to a Linux user.
fn available_backends_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "'keychain'"
    }
    #[cfg(target_os = "linux")]
    {
        if Keystore::gnome_keyring_available() {
            "'gnome-keyring'"
        } else {
            "'file'"
        }
    }
    #[cfg(target_os = "windows")]
    {
        "'windows-hello'"
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        "a supported platform backend"
    }
}

pub(super) fn file_backend_path(account_name: &str) -> std::path::PathBuf {
    pay_core::accounts::FileAccountsStore::default_keypair_path(account_name)
}

/// Resolve and preflight the backend before setup performs any unrelated
/// configuration writes.
pub fn resolve_backend(backend: Option<&str>) -> pay_core::Result<String> {
    let backend = match backend {
        Some(backend) => backend.to_string(),
        None => pick_backend()?,
    };

    #[cfg(target_os = "linux")]
    if backend == "gnome-keyring" && !Keystore::gnome_keyring_available() {
        return Err(gnome_keyring_unavailable_error());
    }

    Ok(backend)
}

#[cfg(target_os = "linux")]
fn gnome_keyring_unavailable_error() -> pay_core::Error {
    pay_core::Error::Config(
        "GNOME Keyring Secret Service is not reachable in this session.\n\
         On a headless Linux server, run and pre-unlock GNOME Keyring as the same service user, \
         then ensure pay/Hermes inherits that session's DBUS_SESSION_BUS_ADDRESS.\n\
         Install the `gnome-keyring` package if it is missing, then retry with \
         `pay setup --backend gnome-keyring`. Pay will not start or unlock the service automatically."
            .to_string(),
    )
}

/// Build the GNOME store for an explicit create/import operation.
///
/// A headless process may have an already-unlocked Secret Service but no
/// Polkit agent. The command itself is explicit consent to write the key, so
/// skip only this setup-time auth gate. The persisted account remains
/// `auth_required: true`; runtime MCP signing is still approved via elicitation.
#[cfg(target_os = "linux")]
pub(super) fn gnome_keyring_for_account_write() -> pay_core::Result<Keystore> {
    if !Keystore::gnome_keyring_available() {
        return Err(gnome_keyring_unavailable_error());
    }

    if Keystore::gnome_keyring_local_auth_available() {
        crate::commands::setup::install_linux_polkit_policy_if_needed()?;
        return Ok(Keystore::gnome_keyring());
    }

    eprintln!(
        "Note: No local Polkit prompt is available; using the already-unlocked GNOME Keyring without a setup-time prompt. Runtime signing still requires MCP approval or a configured Polkit agent."
    );
    Ok(Keystore::gnome_keyring_no_auth())
}

/// Resolve which 1Password account to use. If only one account is
/// configured, use it automatically. If multiple, prompt the user.
pub fn resolve_op_account() -> pay_core::Result<Option<String>> {
    let output = std::process::Command::new("op")
        .args(["account", "list", "--format=json"])
        .output()
        .map_err(|e| pay_core::Error::Config(format!("op account list: {e}")))?;

    if !output.status.success() {
        return Ok(None);
    }

    #[derive(serde::Deserialize)]
    struct OpAccount {
        account_uuid: String,
        email: String,
        url: String,
    }

    let accounts: Vec<OpAccount> = serde_json::from_slice(&output.stdout).unwrap_or_default();

    match accounts.len() {
        0 => Ok(None),
        1 => Ok(Some(accounts[0].account_uuid.clone())),
        _ => {
            let labels: Vec<String> = accounts
                .iter()
                .map(|a| format!("{} ({})", a.email, a.url))
                .collect();

            let selection =
                dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
                    .with_prompt("Which 1Password account?")
                    .items(&labels)
                    .default(0)
                    .interact()
                    .map_err(|e| pay_core::Error::Config(format!("Prompt error: {e}")))?;

            Ok(Some(accounts[selection].account_uuid.clone()))
        }
    }
}

/// Interactive backend picker. Returns the backend id string.
pub fn pick_backend() -> pay_core::Result<String> {
    let has_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    if !has_tty {
        return Err(pay_core::Error::Config(format!(
            "No --backend specified and no interactive terminal available.\n  \
             Pass --backend=<one of {}>.",
            available_backends_hint()
        )));
    }

    struct Opt {
        id: &'static str,
        label: String,
    }

    // Only show platform-native backend on the current OS
    #[cfg(target_os = "macos")]
    let options = [Opt {
        id: "keychain",
        label: "macOS Keychain (requires Touch ID)".into(),
    }];

    #[cfg(target_os = "linux")]
    let options = {
        if Keystore::gnome_keyring_available() {
            vec![Opt {
                id: "gnome-keyring",
                label: "GNOME Keyring (password prompt)".into(),
            }]
        } else {
            vec![Opt {
                id: "file",
                label: "Owner-only keypair file (not encrypted)".into(),
            }]
        }
    };

    #[cfg(target_os = "windows")]
    let options = {
        if Keystore::windows_hello_available() {
            vec![Opt {
                id: "windows-hello",
                label: "Windows Hello (fingerprint / face / PIN)".into(),
            }]
        } else {
            Vec::new()
        }
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let options: Vec<Opt> = Vec::new();

    if options.is_empty() {
        #[cfg(target_os = "linux")]
        return Err(gnome_keyring_unavailable_error());

        #[cfg(not(target_os = "linux"))]
        return Err(pay_core::Error::Config(
            "No supported keystore backend is available on this system.".to_string(),
        ));
    }

    let items: Vec<String> = options.iter().map(|o| o.label.clone()).collect();

    eprintln!();
    let selection = Select::new()
        .with_prompt("Where should pay store your account?")
        .items(&items)
        .default(0)
        .interact()
        .map_err(|e| pay_core::Error::Config(format!("Selection cancelled: {e}")))?;

    Ok(options[selection].id.to_string())
}

pub fn save_account(
    name: &str,
    keystore: pay_core::accounts::Keystore,
    pubkey: &str,
    vault: Option<String>,
    path: Option<String>,
    account: Option<String>,
) -> pay_core::Result<()> {
    let mut accounts = pay_core::accounts::AccountsFile::load()?;
    accounts.upsert(
        pay_core::accounts::MAINNET_NETWORK,
        name,
        pay_core::accounts::Account {
            keystore,
            active: false,
            auth_required: Some(true),
            pubkey: Some(pubkey.to_string()),
            vault,
            account,
            path,
            secret_key_b58: None,
            created_at: None,
            subscriptions: std::collections::BTreeMap::new(),
        },
    );
    accounts.save()
}

/// Print the post-setup summary and next-step hints.
///
/// Shows `✔` confirmation lines for keystore and (if funded) the received
/// amount. Skips the topup hint when the user already funded during setup.
pub fn print_next_steps(
    name: &str,
    backend_name: &str,
    received: Option<&pay_core::client::balance::ReceivedFunds>,
) {
    eprintln!();
    eprintln!(
        "  {} Account secured in {}",
        "✔".green(),
        backend_name.green()
    );

    if let Some(r) = received {
        let amount = format_received(r);
        if !amount.is_empty() {
            eprintln!("  {} Account funded with {}", "✔".green(), amount.green());
        }
        eprintln!();
        crate::components::print_notice(
            crate::components::NoticeLevel::Info,
            "Ready to go. Time to make HTTP pay for itself.",
            "$ claude -p \"what can i do with pay?\"",
        );
    } else {
        eprintln!();
        crate::components::print_notice(
            crate::components::NoticeLevel::Warning,
            "Top-up required",
            &topup_required_body(name),
        );
    }

    eprintln!();
}

fn topup_required_body(name: &str) -> String {
    format!(
        "A top-up is required before making paid requests.\n$ {}",
        crate::commands::topup::topup_retry_command(name)
    )
}

pub fn format_received(r: &pay_core::client::balance::ReceivedFunds) -> String {
    if let Some(usdc) = r.tokens.iter().find(|t| t.is_symbol("USDC")) {
        return format!("${:.2}", usdc.ui_amount);
    }
    if let Some(token) = r.tokens.first() {
        let sym = token.symbol_or("tokens");
        return format!("{:.2} {sym}", token.ui_amount);
    }
    if r.sol_lamports > 0 {
        return format!("{:.4} SOL", r.sol_lamports as f64 / 1_000_000_000.0);
    }
    String::new()
}

pub fn generate_keypair() -> (Vec<u8>, String) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut keypair_bytes = Vec::with_capacity(64);
    keypair_bytes.extend_from_slice(&signing_key.to_bytes());
    keypair_bytes.extend_from_slice(&verifying_key.to_bytes());

    let pubkey_b58 = bs58::encode(&verifying_key.to_bytes()).into_string();
    (keypair_bytes, pubkey_b58)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_keyring_error_explains_headless_session_requirements() {
        let message = gnome_keyring_unavailable_error().to_string();

        assert!(message.contains("Secret Service is not reachable"));
        assert!(message.contains("pre-unlock"));
        assert!(message.contains("DBUS_SESSION_BUS_ADDRESS"));
    }

    #[test]
    fn file_backend_path_matches_account_default() {
        assert_eq!(
            file_backend_path("server"),
            pay_core::accounts::FileAccountsStore::default_keypair_path("server")
        );
    }

    #[test]
    fn topup_required_body_uses_default_topup_command_for_default_account() {
        assert_eq!(
            topup_required_body("default"),
            "A top-up is required before making paid requests.\n$ pay topup"
        );
    }

    #[test]
    fn topup_required_body_uses_named_account_topup_command() {
        assert_eq!(
            topup_required_body("test-2"),
            "A top-up is required before making paid requests.\n$ pay topup --account test-2"
        );
    }
}
