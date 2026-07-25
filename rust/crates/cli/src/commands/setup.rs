//! `pay setup` — generate a keypair, store it, and fund your account.
//!
//! Convenience command that combines `pay account new` + `pay topup`.

use dialoguer::Confirm;
use owo_colors::OwoColorize;
use toml_edit::{Array, DocumentMut, Item, Table, Value, value};

#[cfg(target_os = "linux")]
const POLKIT_POLICY_PATH: &str = "/usr/share/polkit-1/actions/sh.pay.unlock-keypair.policy";

#[cfg(target_os = "linux")]
const POLKIT_POLICY: &str = include_str!("../../../../config/polkit/sh.pay.unlock-keypair.policy");

/// Generate a keypair, store it securely, and fund your account.
#[derive(clap::Args)]
pub struct SetupCommand {
    /// Replace existing account with a new one.
    #[arg(long)]
    pub force: bool,

    /// Storage backend: "keychain" (macOS), "gnome-keyring" (Linux),
    /// "windows-hello" (Windows), or "file" (headless fallback).
    #[arg(long)]
    pub backend: Option<String>,

    /// Legacy vault name.
    #[arg(long, hide = true)]
    pub vault: Option<String>,

    /// Re-install MCP configs and agent skill without creating a new account.
    #[arg(long)]
    pub update: bool,

    /// Redeem an activation campaign code. Skips the MoonPay/onramp
    /// topup TUI and asks the pay-api gateway to fund this account
    /// from its hot wallet. Reuses an existing account when present.
    #[arg(long, value_name = "CODE")]
    pub redeem: Option<String>,
}

/// Per-request timeout for the redemption POST.
const REDEEM_TIMEOUT_SECS: u64 = 30;

impl SetupCommand {
    pub fn run(self) -> pay_core::Result<()> {
        if self.update {
            return run_update();
        }

        // Account name comes from the system user (`$USER` / `$USERNAME` /
        // `whoami`), sanitised. Cross-platform — works on Windows, macOS,
        // Linux. Falls back to "default" if nothing is resolvable.
        let account_name = crate::system::current_user_account_name();

        // Activation-campaign path. Reuses an existing account when one is
        // already configured for `account_name` on mainnet; otherwise
        // creates the keypair and registers it the same way the plain
        // setup flow does, then asks the pay-api to fund it from its hot
        // wallet. The MoonPay/onramp TUI is intentionally skipped — the
        // code is the funding source.
        if let Some(code) = &self.redeem {
            return self.run_redeem(&account_name, code);
        }

        // Abort before any prompts if this user already has an account.
        if !self.force
            && let Ok(accounts) = pay_core::accounts::AccountsFile::load()
            && accounts
                .accounts
                .get(pay_core::accounts::MAINNET_NETWORK)
                .is_some_and(|net| net.contains_key(&account_name))
        {
            super::account::list::print_account_list(
                &accounts,
                None::<super::account::list::Highlight>,
            );
            crate::components::print_notice(
                crate::components::NoticeLevel::Info,
                "Account already exists",
                &format!(
                    "`{account_name}` is already configured.\n\
                     Use --force to replace it, or `pay account new <NAME>` to add another.\n\
                     To fund this existing keypair with a campaign code, run \
                     `pay setup --redeem <CODE>`."
                ),
            );
            eprintln!();
            return Ok(());
        }

        // Resolve the backend first so an unavailable headless Secret Service
        // does not leave MCP/agent configuration partially installed.
        let backend = super::account::new::resolve_backend(self.backend.as_deref())?;

        // Offer to install the agent skill if npx is available.
        maybe_install_skill();

        // Install MCP configs into Claude / Codex / Claude Desktop.
        install_mcp_configs();

        let (pubkey, backend_name) = super::account::new::create_account(
            &account_name,
            Some(&backend),
            self.vault.as_deref(),
            self.force,
        )?;

        let config = pay_core::Config::load().unwrap_or_default();
        let rpc_url = config
            .rpc_url
            .clone()
            .unwrap_or_else(pay_core::balance::mainnet_rpc_url);

        // Headless setup path: when there's no biometric backend available
        // on this platform (VM / CI / server), we already fell back to
        // NoAuth in `create_account`, and the interactive top-up TUI has
        // nothing useful to render. Skip it and print the aborted-style
        // notice instead — the user can fund the account later via
        // `pay topup` once they have a TTY.
        let skip_tui = !has_biometric_backend();
        let completion = if skip_tui {
            None
        } else {
            crate::tui::run_topup_flow(&pubkey, &rpc_url, &account_name)?
        };
        if let Some(completion) = completion {
            print_setup_success(backend_name, &completion, &rpc_url);
        } else {
            print_setup_aborted(&account_name, backend_name);
        }
        Ok(())
    }

    fn run_redeem(&self, account_name: &str, code: &str) -> pay_core::Result<()> {
        // 1. Resolve the destination pubkey. Reuse an existing mainnet
        //    account if present; otherwise create one. `--force` still
        //    forces a fresh keypair (e.g. for testing).
        let existing = pay_core::accounts::AccountsFile::load().ok().and_then(|f| {
            f.accounts
                .get(pay_core::accounts::MAINNET_NETWORK)
                .and_then(|net| net.get(account_name).cloned())
        });

        let (pubkey, used_existing): (String, bool) = if !self.force
            && let Some(account) = existing
            && let Some(pk) = account.pubkey.clone()
        {
            (pk, true)
        } else {
            maybe_install_skill();
            install_mcp_configs();
            let (pk, _backend_name) = super::account::new::create_account(
                account_name,
                self.backend.as_deref(),
                self.vault.as_deref(),
                self.force,
            )?;
            (pk, false)
        };

        // 2. POST to pay-api's `/v1/redeem`. Honors `PAY_API_URL` via
        //    the same helper the `/v1/send` client uses, so override
        //    semantics match the rest of the CLI.
        let api_url = pay_core::client::balance::pay_api_url();
        let api_url = api_url.trim().trim_end_matches('/');

        let response = match post_redeem(api_url, code, &pubkey) {
            Ok(r) => r,
            Err(e) if !used_existing => {
                // The keypair was created moments ago and is now
                // persisted but unfunded. Surface a recovery hint so
                // the user isn't stuck behind the "Account already
                // exists" guard on the next `pay setup` run.
                return Err(pay_core::Error::Config(format!(
                    "{e}\n\nYour keypair was created and is preserved. Once you have a valid \
                     code, retry with `pay setup --redeem <CODE>` to fund this same keypair."
                )));
            }
            Err(e) => return Err(e),
        };

        // 3. Surface the result.
        print_redeem_success(account_name, &pubkey, &response, used_existing);
        Ok(())
    }
}

/// Returns true if the current platform exposes a biometric auth backend
/// that pay can drive. Mirrors the check used in
/// [`crate::commands::account::new::build_keystore`] so the TUI is skipped
/// on the same hosts where biometric account creation is unavailable.
fn has_biometric_backend() -> bool {
    #[cfg(target_os = "macos")]
    {
        pay_core::keystore::Keystore::apple_touchid_available()
    }
    #[cfg(target_os = "linux")]
    {
        pay_core::keystore::Keystore::gnome_keyring_local_auth_available()
    }
    #[cfg(target_os = "windows")]
    {
        pay_core::keystore::Keystore::windows_hello_available()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

fn print_setup_success(
    backend_name: &str,
    completion: &crate::tui::TopupCompletion,
    rpc_url: &str,
) {
    crate::components::print_notice(
        crate::components::NoticeLevel::Success,
        "Setup complete",
        &setup_success_body(backend_name, completion, rpc_url),
    );
    print_ready_hint();
}

fn setup_success_body(
    backend_name: &str,
    completion: &crate::tui::TopupCompletion,
    _rpc_url: &str,
) -> String {
    let mut lines = vec![format!("Account secured in {backend_name}")];
    if let Some(amount) = super::topup::topup_received_amount(&completion.received) {
        lines.push(format!("Account funded with {amount}"));
    }
    if let Some(hash) = &completion.tx_hash {
        // Setup-time topup always lands on mainnet (real funds). pay.sh
        // resolves the signature server-side; no rpc_url needed.
        lines.push(format!(
            "{} {hash}",
            crate::components::solana_transaction_link(hash, "mainnet")
        ));
    }
    lines.join("\n")
}

fn print_setup_aborted(account_name: &str, backend_name: &str) {
    crate::components::print_notice(
        crate::components::NoticeLevel::Warning,
        "Setup aborted",
        &setup_aborted_body(account_name, backend_name),
    );
}

fn setup_aborted_body(account_name: &str, backend_name: &str) -> String {
    let topup_cmd = crate::commands::topup::topup_retry_command(account_name);
    format!(
        "Account secured in {backend_name}\nA top-up is required before making paid requests.\n$ {topup_cmd}"
    )
}

// ── Activation-campaign redemption ─────────────────────────────────────────

#[derive(serde::Deserialize, Debug)]
struct RedeemSuccess {
    signature: String,
    destination: String,
    /// USDC funded by the activation campaign, formatted by pay-api
    /// (e.g. `"$0.10"`). Optional so older API versions still
    /// deserialize cleanly — the success notice just elides the
    /// amount when missing.
    #[serde(default)]
    amount: Option<String>,
}

/// Pay-api may return a non-2xx with `{ "error": "...", "signature": "..." }`
/// (the 409-already-redeemed case carries the prior signature). Capture
/// both fields so we can route the user appropriately.
#[derive(serde::Deserialize, Debug, Default)]
struct RedeemErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    signature: Option<String>,
}

fn post_redeem(api_url: &str, code: &str, destination: &str) -> pay_core::Result<RedeemSuccess> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(REDEEM_TIMEOUT_SECS))
        .build()
        .map_err(|e| pay_core::Error::Config(format!("Failed to build HTTP client: {e}")))?;

    let body = serde_json::json!({ "code": code, "destination": destination });
    let resp = client
        .post(format!("{api_url}/v1/redeem"))
        .json(&body)
        .send()
        .map_err(|e| pay_core::Error::Config(format!("pay-api {api_url} unreachable: {e}")))?;

    let status = resp.status();
    if status.is_success() {
        let parsed: RedeemSuccess = resp.json().map_err(|e| {
            pay_core::Error::Config(format!("pay-api returned malformed JSON: {e}"))
        })?;
        return Ok(parsed);
    }

    // Best-effort decode of the error body so the user sees the real reason.
    let err_body: RedeemErrorBody = resp.json().unwrap_or_default();
    let msg = err_body.error.unwrap_or_else(|| status.to_string());
    if status.as_u16() == 409
        && let Some(prior_sig) = err_body.signature
    {
        return Err(pay_core::Error::Config(format!(
            "Code already redeemed. Prior transaction: {prior_sig}"
        )));
    }
    Err(pay_core::Error::Config(format!(
        "pay-api redemption failed ({status}): {msg}"
    )))
}

fn print_redeem_success(
    account_name: &str,
    pubkey: &str,
    response: &RedeemSuccess,
    used_existing: bool,
) {
    // If the gateway funded a different address than the one we
    // submitted (API bug, misconfiguration, tampered response), surface
    // the mismatch and drop the success framing so the user isn't told
    // the local account is funded when it isn't.
    let destination_matches = response.destination == pubkey;

    use owo_colors::OwoColorize;

    let mut lines = Vec::new();
    if destination_matches {
        let suffix = match response.amount.as_deref() {
            Some(amount) => format!(" 🎉 {}", amount.green().bold()),
            None => " 🎉".to_string(),
        };
        let verb = if used_existing {
            "funded (existing keypair)"
        } else {
            "funded"
        };
        lines.push(format!(
            "Account `{account_name}` ({short}) {verb}{suffix}",
            short = shorten_pubkey(pubkey),
        ));
    } else {
        lines.push(format!(
            "Gateway funded {gateway_dest}, not local pubkey {local_pk}.",
            gateway_dest = response.destination,
            local_pk = pubkey,
        ));
        lines.push(format!(
            "Investigate before assuming `{account_name}` is usable — the funds did not land on \
             this device's keypair."
        ));
    }
    lines.push(format!(
        "{} {sig}",
        crate::components::solana_transaction_link(&response.signature, "mainnet"),
        sig = response.signature,
    ));

    let (level, title) = if destination_matches {
        (
            crate::components::NoticeLevel::Success,
            "Activation complete",
        )
    } else {
        (
            crate::components::NoticeLevel::Warning,
            "Activation funded the wrong address",
        )
    };
    crate::components::print_notice(level, title, &lines.join("\n"));

    if destination_matches {
        print_ready_hint();
    }
}

/// Emit the "next step" hint as its own info notice (blue rail) so the
/// callout reads as guidance, not a continuation of the success body.
/// The title carries the white, non-dimmed copy; the body shows the
/// command the user should try.
fn print_ready_hint() {
    crate::components::print_notice(
        crate::components::NoticeLevel::Info,
        "Ready to go. Time to make HTTP pay for itself.",
        "$ claude -p \"what can i do with pay?\"",
    );
}

fn shorten_pubkey(pk: &str) -> String {
    if pk.len() <= 8 {
        return pk.to_string();
    }
    format!("{}…{}", &pk[..4], &pk[pk.len() - 4..])
}

/// `pay setup --update`: re-install MCP configs and agent skill.
fn run_update() -> pay_core::Result<()> {
    eprintln!();
    maybe_install_skill();
    install_mcp_configs();
    eprintln!("  {}", "Update complete.".dimmed());
    eprintln!();
    Ok(())
}

// ── MCP config installation ────────────────────────────────────────────────

/// Well-known MCP config locations for each supported app.
fn mcp_config_targets() -> Vec<(&'static str, std::path::PathBuf)> {
    let mut targets = Vec::new();

    // Claude Code: ~/.claude.json
    if let Some(home) = home_dir() {
        targets.push(("Claude Code", home.join(".claude.json")));
    }

    // Claude Desktop
    if let Some(path) = claude_desktop_config_path() {
        targets.push(("Claude Desktop", path));
    }

    // Qoder IDE
    if let Some(path) = qoder_ide_config_path() {
        targets.push(("Qoder IDE", path));
    }

    targets
}

fn claude_desktop_config_path() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home_dir().map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json")
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(|appdata| {
            std::path::PathBuf::from(appdata)
                .join("Claude")
                .join("claude_desktop_config.json")
        })
    }
    #[cfg(target_os = "linux")]
    {
        home_dir().map(|h| {
            h.join(".config")
                .join("Claude")
                .join("claude_desktop_config.json")
        })
    }
}

fn codex_config_path() -> Option<std::path::PathBuf> {
    home_dir().map(|h| h.join(".codex").join("config.toml"))
}

/// Qoder IDE (the desktop app) reads its MCP server list from a shared
/// client cache directory.
fn qoder_ide_config_path() -> Option<std::path::PathBuf> {
    qoder_ide_data_dir().map(|d| d.join("mcp.json"))
}

/// Shared client cache directory used by Qoder IDE.
fn qoder_ide_data_dir() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home_dir().map(|h| {
            h.join("Library")
                .join("Application Support")
                .join("Qoder")
                .join("SharedClientCache")
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(|d| {
            std::path::PathBuf::from(d)
                .join("Qoder")
                .join("SharedClientCache")
        })
    }
    #[cfg(target_os = "linux")]
    {
        home_dir().map(|h| h.join(".config").join("Qoder").join("SharedClientCache"))
    }
}

/// Path to qodercli's user-level settings file.
fn qodercli_settings_path() -> Option<std::path::PathBuf> {
    home_dir().map(|h| h.join(".qoder").join("settings.json"))
}

fn home_dir() -> Option<std::path::PathBuf> {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(std::path::PathBuf::from)
}

/// Resolve the `pay` binary path for the MCP config.
fn pay_command() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "pay".to_string())
}

/// Install the pay MCP server entry into all detected app configs.
fn install_mcp_configs() {
    let pay_bin = pay_command();
    let targets = mcp_config_targets();
    let mut installed_any = false;

    for (app_name, config_path) in &targets {
        // Only install into apps the user actually has (config dir exists).
        if let Some(parent) = config_path.parent()
            && !parent.exists()
        {
            continue;
        }

        match add_mcp_entry(config_path, &pay_bin) {
            Ok(McpInstallResult::Added) => {
                eprintln!("  {} pay MCP added to {app_name}", "✔".green());
                installed_any = true;
            }
            Ok(McpInstallResult::AlreadyPresent) => {
                eprintln!("  {} pay MCP already configured in {app_name}", "✔".green());
                installed_any = true;
            }
            Ok(McpInstallResult::Updated) => {
                eprintln!("  {} pay MCP updated in {app_name}", "✔".green());
                installed_any = true;
            }
            Err(e) => {
                eprintln!("  {} Failed to configure {app_name}: {e}", "!".yellow());
            }
        }
    }

    if let Some(config_path) = codex_config_path()
        && config_path.parent().is_none_or(|parent| parent.exists())
    {
        match add_codex_mcp_entry(&config_path, &pay_bin) {
            Ok(McpInstallResult::Added) => {
                eprintln!("  {} pay MCP added to Codex", "✔".green());
                installed_any = true;
            }
            Ok(McpInstallResult::AlreadyPresent) => {
                eprintln!("  {} pay MCP already configured in Codex", "✔".green());
                installed_any = true;
            }
            Ok(McpInstallResult::Updated) => {
                eprintln!("  {} pay MCP updated in Codex", "✔".green());
                installed_any = true;
            }
            Err(e) => {
                eprintln!("  {} Failed to configure Codex: {e}", "!".yellow());
            }
        }
    }

    // Qoder CLI (`qodercli`): write pay MCP entry into
    // ~/.qoder/settings.json so users who launch `qodercli` directly
    // (without `pay qodercli`) also get pay MCP available.
    if let Some(settings_path) = qodercli_settings_path()
        && (settings_path.exists() || settings_path.parent().is_some_and(|d| d.exists()))
    {
        match add_qodercli_mcp_entry(&settings_path, &pay_bin) {
            Ok(McpInstallResult::Added) => {
                eprintln!("  {} pay MCP added to Qoder CLI", "\u{2714}".green());
                installed_any = true;
            }
            Ok(McpInstallResult::AlreadyPresent) => {
                eprintln!(
                    "  {} pay MCP already configured in Qoder CLI",
                    "\u{2714}".green()
                );
                installed_any = true;
            }
            Ok(McpInstallResult::Updated) => {
                eprintln!("  {} pay MCP updated in Qoder CLI", "\u{2714}".green());
                installed_any = true;
            }
            Err(e) => {
                eprintln!("  {} Failed to configure Qoder CLI: {e}", "!".yellow());
            }
        }
    }

    if !installed_any {
        eprintln!(
            "{}",
            "  No supported apps found. Add pay MCP manually:".dimmed()
        );
        eprintln!(
            "{}",
            "  https://github.com/solana-foundation/pay#mcp-server".dimmed()
        );
    }
    eprintln!();
}

enum McpInstallResult {
    Added,
    AlreadyPresent,
    Updated,
}

/// Add or update the `pay` MCP server entry in a JSON config file.
fn add_mcp_entry(config_path: &std::path::Path, pay_bin: &str) -> Result<McpInstallResult, String> {
    let mut config: serde_json::Value = if config_path.exists() {
        let raw = std::fs::read_to_string(config_path)
            .map_err(|e| format!("read {}: {e}", config_path.display()))?;
        if raw.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&raw)
                .map_err(|e| format!("parse {}: {e}", config_path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    let servers = config
        .as_object_mut()
        .ok_or("config is not a JSON object")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    let new_entry = serde_json::json!({
        "command": pay_bin,
        "args": ["mcp"]
    });

    let result = if let Some(existing) = servers.get("pay") {
        if existing.get("command").and_then(|v| v.as_str()) == Some(pay_bin)
            && existing.get("args") == Some(&serde_json::json!(["mcp"]))
        {
            McpInstallResult::AlreadyPresent
        } else {
            servers["pay"] = new_entry;
            McpInstallResult::Updated
        }
    } else {
        servers
            .as_object_mut()
            .ok_or("mcpServers is not an object")?
            .insert("pay".to_string(), new_entry);
        McpInstallResult::Added
    };

    if !matches!(result, McpInstallResult::AlreadyPresent) {
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(config_path, json + "\n")
            .map_err(|e| format!("write {}: {e}", config_path.display()))?;
    }

    Ok(result)
}

/// Add or update the `pay` MCP server entry in qodercli's settings.json.
fn add_qodercli_mcp_entry(
    settings_path: &std::path::Path,
    pay_bin: &str,
) -> Result<McpInstallResult, String> {
    let mut config: serde_json::Value = if settings_path.exists() {
        let raw = std::fs::read_to_string(settings_path)
            .map_err(|e| format!("read {}: {e}", settings_path.display()))?;
        if raw.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&raw)
                .map_err(|e| format!("parse {}: {e}", settings_path.display()))?
        }
    } else {
        serde_json::json!({})
    };

    let servers = config
        .as_object_mut()
        .ok_or("settings is not a JSON object")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    let new_entry = serde_json::json!({
        "command": pay_bin,
        "args": ["mcp"]
    });

    let result = if let Some(existing) = servers.get("pay") {
        let matches = existing.get("command").and_then(|v| v.as_str()) == Some(pay_bin)
            && existing.get("args") == Some(&serde_json::json!(["mcp"]));
        if matches {
            McpInstallResult::AlreadyPresent
        } else {
            servers["pay"] = new_entry;
            McpInstallResult::Updated
        }
    } else {
        servers
            .as_object_mut()
            .ok_or("mcpServers is not an object")?
            .insert("pay".to_string(), new_entry);
        McpInstallResult::Added
    };

    if !matches!(result, McpInstallResult::AlreadyPresent) {
        if let Some(parent) = settings_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(&config).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(settings_path, json + "\n")
            .map_err(|e| format!("write {}: {e}", settings_path.display()))?;
    }

    Ok(result)
}

/// Add or update the `pay` MCP server entry in Codex's TOML config.
fn add_codex_mcp_entry(
    config_path: &std::path::Path,
    pay_bin: &str,
) -> Result<McpInstallResult, String> {
    let raw = if config_path.exists() {
        std::fs::read_to_string(config_path)
            .map_err(|e| format!("read {}: {e}", config_path.display()))?
    } else {
        String::new()
    };
    let mut config = if raw.trim().is_empty() {
        DocumentMut::new()
    } else {
        raw.parse::<DocumentMut>()
            .map_err(|e| format!("parse {}: {e}", config_path.display()))?
    };

    let existed = codex_pay_entry_exists(&config);
    let already_present = codex_pay_entry_matches(&config, pay_bin);
    if already_present {
        return Ok(McpInstallResult::AlreadyPresent);
    }

    {
        let mcp_servers = ensure_toml_table(&mut config["mcp_servers"]);
        let pay = ensure_toml_table(&mut mcp_servers["pay"]);
        pay["command"] = value(pay_bin);
        pay["args"] = string_array_item(&["mcp"]);
        pay["enabled"] = value(true);
        pay["enabled_tools"] = string_array_item(super::codex::PAY_MCP_ENABLED_TOOLS);
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
    }
    std::fs::write(config_path, config.to_string())
        .map_err(|e| format!("write {}: {e}", config_path.display()))?;

    Ok(if existed {
        McpInstallResult::Updated
    } else {
        McpInstallResult::Added
    })
}

fn ensure_toml_table(item: &mut Item) -> &mut Table {
    if !item.is_table() {
        *item = Item::Table(Table::new());
    }
    item.as_table_mut().expect("item was just set to a table")
}

fn string_array_item(values: &[&str]) -> Item {
    let mut array = Array::new();
    for value in values {
        array.push(*value);
    }
    Item::Value(Value::Array(array))
}

fn codex_pay_entry_exists(config: &DocumentMut) -> bool {
    config
        .get("mcp_servers")
        .and_then(Item::as_table)
        .and_then(|servers| servers.get("pay"))
        .is_some()
}

fn codex_pay_entry_matches(config: &DocumentMut, pay_bin: &str) -> bool {
    let Some(pay) = config
        .get("mcp_servers")
        .and_then(Item::as_table)
        .and_then(|servers| servers.get("pay"))
        .and_then(Item::as_table)
    else {
        return false;
    };

    let command_matches = pay
        .get("command")
        .and_then(Item::as_str)
        .is_some_and(|command| command == pay_bin);
    let args_match = item_string_array(pay.get("args")).is_some_and(|args| args == ["mcp"]);
    let enabled_matches = pay
        .get("enabled")
        .and_then(Item::as_bool)
        .unwrap_or_default();
    let enabled_tools_match = item_string_array(pay.get("enabled_tools"))
        .is_some_and(|tools| tools == super::codex::PAY_MCP_ENABLED_TOOLS);

    command_matches && args_match && enabled_matches && enabled_tools_match
}

fn item_string_array(item: Option<&Item>) -> Option<Vec<&str>> {
    item?
        .as_array()?
        .iter()
        .map(|value| value.as_str())
        .collect()
}

// ── Skill installation ─────────────────────────────────────────────────────

/// If `npx` is on PATH, offer to install the pay agent skill for coding agents.
fn maybe_install_skill() {
    let npx_bin = if cfg!(windows) { "npx.cmd" } else { "npx" };
    let has_npx = std::process::Command::new(npx_bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());

    if !has_npx {
        return;
    }

    eprintln!();
    let install = Confirm::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Install pay skill for your coding agents? (Claude Code, Cursor, …)")
        .default(true)
        .interact()
        .unwrap_or(false);

    if !install {
        return;
    }

    eprintln!();
    let status = std::process::Command::new(npx_bin)
        .args([
            "-y",
            "skills",
            "add",
            "https://github.com/solana-foundation/pay",
            "--skill",
            "pay",
            "-y",
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            eprintln!("  {} Skill installed", "✔".green());
        }
        _ => {
            eprintln!(
                "{}",
                "  Skill install failed — you can retry later with:".dimmed()
            );
            eprintln!(
                "{}",
                "  npx -y skills add https://github.com/solana-foundation/pay --skill pay -y"
                    .dimmed()
            );
        }
    }
    eprintln!();
}

// ── Linux polkit ───────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub(crate) fn install_linux_polkit_policy_if_needed() -> pay_core::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if std::fs::read_to_string(POLKIT_POLICY_PATH).is_ok_and(|installed| installed == POLKIT_POLICY)
    {
        return Ok(());
    }

    eprintln!();
    eprintln!(
        "{}",
        "  Installing Linux authentication prompts for pay (polkit policy)...".dimmed()
    );

    let mut child = Command::new("pkexec")
        .args(["tee", POLKIT_POLICY_PATH])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| {
            pay_core::Error::Config(format!(
                "Failed to launch pkexec to install the pay polkit policy: {e}.\n\n\
                 Install it manually with:\n\
                 \x20 sudo tee {POLKIT_POLICY_PATH} >/dev/null <<'EOF'\n\
                 {POLKIT_POLICY}EOF"
            ))
        })?;

    {
        let mut stdin = child.stdin.take().expect("pkexec stdin");
        stdin
            .write_all(POLKIT_POLICY.as_bytes())
            .map_err(|e| pay_core::Error::Config(format!("Failed to write polkit policy: {e}")))?;
    }

    let status = child
        .wait()
        .map_err(|e| pay_core::Error::Config(format!("pkexec failed: {e}")))?;

    if status.success() {
        eprintln!("  {} Linux authentication prompts installed", "✔".green());
        Ok(())
    } else {
        Err(pay_core::Error::Config(format!(
            "Failed to install the pay polkit policy (pkexec exited with {status}).\n\n\
             Install it manually with:\n\
             \x20 sudo cp rust/config/polkit/sh.pay.unlock-keypair.policy {POLKIT_POLICY_PATH}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_mcp_entry_includes_enabled_tools() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"model = "gpt-5"

[mcp_servers.other]
command = "other"
"#,
        )
        .unwrap();

        let result = add_codex_mcp_entry(&config_path, "/usr/local/bin/pay").unwrap();

        assert!(matches!(result, McpInstallResult::Added));
        let raw = std::fs::read_to_string(&config_path).unwrap();
        assert!(raw.contains(r#"model = "gpt-5""#));
        assert!(raw.contains("enabled_tools"));
        let parsed = raw.parse::<DocumentMut>().unwrap();
        assert!(codex_pay_entry_matches(&parsed, "/usr/local/bin/pay"));
    }

    #[test]
    fn codex_mcp_entry_updates_existing_without_allowlist() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"[mcp_servers.pay]
command = "pay"
args = ["mcp"]
enabled = true
"#,
        )
        .unwrap();

        let result = add_codex_mcp_entry(&config_path, "pay").unwrap();

        assert!(matches!(result, McpInstallResult::Updated));
        let raw = std::fs::read_to_string(&config_path).unwrap();
        assert!(raw.contains("enabled_tools"));
        let parsed = raw.parse::<DocumentMut>().unwrap();
        assert!(codex_pay_entry_matches(&parsed, "pay"));
    }

    #[test]
    fn codex_mcp_entry_is_idempotent_when_allowlist_matches() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("config.toml");

        assert!(matches!(
            add_codex_mcp_entry(&config_path, "pay").unwrap(),
            McpInstallResult::Added
        ));
        assert!(matches!(
            add_codex_mcp_entry(&config_path, "pay").unwrap(),
            McpInstallResult::AlreadyPresent
        ));
    }

    #[test]
    fn mcp_entry_creates_new_config() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("mcp.json");

        let result = add_mcp_entry(&config_path, "/usr/local/bin/pay").unwrap();

        assert!(matches!(result, McpInstallResult::Added));
        let raw = std::fs::read_to_string(&config_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["mcpServers"]["pay"]["command"], "/usr/local/bin/pay");
        assert_eq!(v["mcpServers"]["pay"]["args"][0], "mcp");
    }

    #[test]
    fn mcp_entry_already_present() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("mcp.json");

        add_mcp_entry(&config_path, "/usr/local/bin/pay").unwrap();
        let result = add_mcp_entry(&config_path, "/usr/local/bin/pay").unwrap();

        assert!(matches!(result, McpInstallResult::AlreadyPresent));
    }

    #[test]
    fn mcp_entry_updates_when_command_changes() {
        let temp = tempfile::tempdir().unwrap();
        let config_path = temp.path().join("mcp.json");

        add_mcp_entry(&config_path, "/old/path/pay").unwrap();
        let result = add_mcp_entry(&config_path, "/new/path/pay").unwrap();

        assert!(matches!(result, McpInstallResult::Updated));
        let raw = std::fs::read_to_string(&config_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["mcpServers"]["pay"]["command"], "/new/path/pay");
    }

    #[test]
    fn qodercli_mcp_entry_creates_new_settings() {
        let temp = tempfile::tempdir().unwrap();
        let settings_path = temp.path().join("settings.json");

        let result = add_qodercli_mcp_entry(&settings_path, "/usr/local/bin/pay").unwrap();

        assert!(matches!(result, McpInstallResult::Added));
        let raw = std::fs::read_to_string(&settings_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["mcpServers"]["pay"]["command"], "/usr/local/bin/pay");
        assert_eq!(v["mcpServers"]["pay"]["args"][0], "mcp");
    }

    #[test]
    fn qodercli_mcp_entry_preserves_existing_servers() {
        let temp = tempfile::tempdir().unwrap();
        let settings_path = temp.path().join("settings.json");
        std::fs::write(
            &settings_path,
            r#"{"mcpServers":{"other":{"command":"other-cmd","args":[]}}}"#,
        )
        .unwrap();

        let result = add_qodercli_mcp_entry(&settings_path, "pay").unwrap();

        assert!(matches!(result, McpInstallResult::Added));
        let raw = std::fs::read_to_string(&settings_path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "other-cmd");
        assert_eq!(v["mcpServers"]["pay"]["command"], "pay");
    }
}
