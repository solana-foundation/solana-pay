//! Setup-time registration of Pay as a Buzz custom ACP harness.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};

use super::agent::{AlternateClient, AlternateProviderOption, discover_acp_provider_options};

const BUZZ_APP_ID: &str = "xyz.block.buzz.app";
const HARNESS_ID: &str = "pay-acp";
const HARNESS_FILE: &str = "pay-acp.json";
const PROVIDER_ENV: &str = "PAY_ACP_PROVIDER";
const MODEL_ENV: &str = "PAY_ACP_MODEL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcpRuntime {
    Goose,
    Claude,
    Codex,
}

impl AcpRuntime {
    const ALL: [Self; 3] = [Self::Goose, Self::Claude, Self::Codex];

    fn slug(self) -> &'static str {
        match self {
            Self::Goose => "goose",
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Goose => "Goose",
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
        }
    }

    fn command(self) -> &'static str {
        match self {
            Self::Goose => "goose",
            Self::Claude => "claude-agent-acp",
            Self::Codex => "codex-acp",
        }
    }

    fn alternate_client(self) -> AlternateClient {
        match self {
            Self::Goose => AlternateClient::Goose,
            Self::Claude => AlternateClient::Claude,
            Self::Codex => AlternateClient::Codex,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|runtime| runtime.slug() == value)
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct BuzzHarnessDefinition {
    id: String,
    label: String,
    command: String,
    args: Vec<String>,
    env: BTreeMap<String, String>,
    install_instructions_url: String,
    install_hint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HarnessWriteResult {
    Added,
    AlreadyPresent,
    Updated,
}

/// Detect Buzz Desktop and offer to register a deterministic Pay-backed ACP
/// harness. Setup remains successful when this optional integration is skipped
/// or cannot be configured.
pub(crate) fn maybe_configure() {
    let Some(app_data_dir) = detect_buzz_app_data_dir() else {
        return;
    };

    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        eprintln!(
            "  {} Buzz detected; run `pay setup --update` in a terminal to configure its Pay ACP harness.",
            "!".yellow()
        );
        return;
    }

    if let Err(error) = configure_interactively(&app_data_dir) {
        eprintln!("  {} Failed to configure Buzz: {error}", "!".yellow());
    }
}

fn configure_interactively(app_data_dir: &Path) -> Result<(), String> {
    eprintln!();
    let theme = ColorfulTheme::default();
    let configure = Confirm::with_theme(&theme)
        .with_prompt("Configure Pay as a custom ACP harness in Buzz?")
        .default(true)
        .interact()
        .map_err(|error| format!("Buzz setup prompt: {error}"))?;
    if !configure {
        return Ok(());
    }

    let harness_path = app_data_dir.join("custom_harnesses").join(HARNESS_FILE);
    let existing = read_harness(&harness_path);
    let runtimes = installed_runtimes();
    if runtimes.is_empty() {
        return Err(
            "no supported ACP runtime found; install Goose, claude-agent-acp, or codex-acp first"
                .to_string(),
        );
    }

    let previous_runtime = existing
        .as_ref()
        .and_then(|definition| definition.args.get(1))
        .and_then(|slug| AcpRuntime::parse(slug));
    let runtime_default = previous_runtime
        .and_then(|selected| runtimes.iter().position(|runtime| *runtime == selected))
        .unwrap_or_default();
    let runtime_labels = runtimes
        .iter()
        .map(|runtime| runtime.label())
        .collect::<Vec<_>>();
    let runtime_index = Select::with_theme(&theme)
        .with_prompt("ACP runtime for Buzz")
        .items(&runtime_labels)
        .default(runtime_default)
        .interact()
        .map_err(|error| format!("runtime selection: {error}"))?;
    let runtime = runtimes[runtime_index];

    eprintln!("  {}", "Discovering compatible Pay providers…".dimmed());
    let providers = discover_acp_provider_options(runtime.alternate_client())
        .map_err(|error| format!("provider discovery: {error}"))?;
    if providers.is_empty() {
        return Err(format!(
            "no compatible Pay provider is currently available for {}",
            runtime.label()
        ));
    }

    let previous_provider = existing
        .as_ref()
        .and_then(|definition| definition.env.get(PROVIDER_ENV));
    let provider_default = previous_provider
        .and_then(|slug| {
            providers
                .iter()
                .position(|provider| provider.slug.eq_ignore_ascii_case(slug))
        })
        .unwrap_or_default();
    let provider_labels = providers
        .iter()
        .map(|provider| format!("{} ({})", provider.title, provider.slug))
        .collect::<Vec<_>>();
    let provider_index = Select::with_theme(&theme)
        .with_prompt("Pay provider")
        .items(&provider_labels)
        .default(provider_default)
        .interact()
        .map_err(|error| format!("provider selection: {error}"))?;
    let provider = &providers[provider_index];

    let previous_model = existing
        .as_ref()
        .and_then(|definition| definition.env.get(MODEL_ENV))
        .map(String::as_str);
    let model = select_model(&theme, provider, previous_model)?;
    let pay_bin = std::env::current_exe()
        .map_err(|error| format!("resolve current pay executable: {error}"))?
        .to_string_lossy()
        .to_string();
    let definition = harness_definition(runtime, &provider.slug, &model, &pay_bin);

    let result = write_harness(&harness_path, &definition)?;
    let status = match result {
        HarnessWriteResult::Added => "added to",
        HarnessWriteResult::AlreadyPresent => "already configured in",
        HarnessWriteResult::Updated => "updated in",
    };
    eprintln!("  {} Pay + {} {status} Buzz", "✔".green(), runtime.label());
    eprintln!(
        "  {}",
        "Open Buzz Settings → Harnesses to select the new runtime.".dimmed()
    );
    eprintln!();
    Ok(())
}

fn select_model(
    theme: &ColorfulTheme,
    provider: &AlternateProviderOption,
    previous_model: Option<&str>,
) -> Result<String, String> {
    if provider.models.is_empty() {
        return Input::<String>::with_theme(theme)
            .with_prompt("Model")
            .with_initial_text(previous_model.unwrap_or_default())
            .validate_with(|value: &String| -> Result<(), &str> {
                if value.trim().is_empty() {
                    Err("model must not be empty")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map(|value| value.trim().to_string())
            .map_err(|error| format!("model input: {error}"));
    }

    let default = previous_model
        .and_then(|model| {
            provider
                .models
                .iter()
                .position(|candidate| candidate == model)
        })
        .unwrap_or_default();
    let index = Select::with_theme(theme)
        .with_prompt("Model")
        .items(&provider.models)
        .default(default)
        .interact()
        .map_err(|error| format!("model selection: {error}"))?;
    Ok(provider.models[index].clone())
}

fn harness_definition(
    runtime: AcpRuntime,
    provider: &str,
    model: &str,
    pay_bin: &str,
) -> BuzzHarnessDefinition {
    BuzzHarnessDefinition {
        id: HARNESS_ID.to_string(),
        label: format!("Pay + {}", runtime.label()),
        command: pay_bin.to_string(),
        args: vec!["acp".to_string(), runtime.slug().to_string()],
        env: BTreeMap::from([
            (PROVIDER_ENV.to_string(), provider.to_string()),
            (MODEL_ENV.to_string(), model.to_string()),
        ]),
        install_instructions_url: "https://github.com/solana-foundation/pay".to_string(),
        install_hint: "Run `pay setup --update` to reconfigure this harness.".to_string(),
    }
}

fn read_harness(path: &Path) -> Option<BuzzHarnessDefinition> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_harness(
    path: &Path,
    definition: &BuzzHarnessDefinition,
) -> Result<HarnessWriteResult, String> {
    if read_harness(path).as_ref() == Some(definition) {
        return Ok(HarnessWriteResult::AlreadyPresent);
    }
    let existed = path.exists();
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create {}: {error}", parent.display()))?;
    let json = serde_json::to_string_pretty(definition)
        .map_err(|error| format!("serialize Buzz harness: {error}"))?;
    std::fs::write(path, json + "\n")
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(if existed {
        HarnessWriteResult::Updated
    } else {
        HarnessWriteResult::Added
    })
}

fn installed_runtimes() -> Vec<AcpRuntime> {
    AcpRuntime::ALL
        .into_iter()
        .filter(|runtime| command_on_path(runtime.command()))
        .collect()
}

fn command_on_path(command: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    let extensions: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd", ".bat"]
    } else {
        &[""]
    };
    std::env::split_paths(&path).any(|directory| {
        extensions
            .iter()
            .any(|extension| directory.join(format!("{command}{extension}")).is_file())
    })
}

fn detect_buzz_app_data_dir() -> Option<PathBuf> {
    let app_data_dir = buzz_app_data_dir()?;
    if app_data_dir.exists() || buzz_install_markers().iter().any(|path| path.exists()) {
        Some(app_data_dir)
    } else {
        None
    }
}

fn buzz_app_data_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        home_dir().map(|home| {
            home.join("Library")
                .join("Application Support")
                .join(BUZZ_APP_ID)
        })
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|path| path.join(BUZZ_APP_ID))
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|home| home.join(".local").join("share")))
            .map(|path| path.join(BUZZ_APP_ID))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        None
    }
}

fn buzz_install_markers() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut markers = vec![PathBuf::from("/Applications/Buzz.app")];
        if let Some(home) = home_dir() {
            markers.push(home.join("Applications").join("Buzz.app"));
        }
        markers
    }
    #[cfg(target_os = "windows")]
    {
        ["ProgramFiles", "LOCALAPPDATA"]
            .into_iter()
            .filter_map(std::env::var_os)
            .map(PathBuf::from)
            .map(|path| path.join("Buzz").join("Buzz.exe"))
            .collect()
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/bin/buzz"),
            PathBuf::from("/usr/local/bin/buzz"),
            PathBuf::from("/opt/Buzz/buzz"),
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Vec::new()
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buzz_harness_matches_custom_harness_schema() {
        let definition = harness_definition(
            AcpRuntime::Goose,
            "modelstudio",
            "qwen3.7-plus",
            "/usr/local/bin/pay",
        );
        let json = serde_json::to_value(&definition).unwrap();

        assert_eq!(json["id"], "pay-acp");
        assert_eq!(json["label"], "Pay + Goose");
        assert_eq!(json["command"], "/usr/local/bin/pay");
        assert_eq!(json["args"], serde_json::json!(["acp", "goose"]));
        assert_eq!(json["env"][PROVIDER_ENV], "modelstudio");
        assert_eq!(json["env"][MODEL_ENV], "qwen3.7-plus");
        assert!(json.get("installInstructionsUrl").is_some());
        assert!(json.get("installHint").is_some());
    }

    #[test]
    fn harness_write_adds_updates_and_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("custom_harnesses").join(HARNESS_FILE);
        let first = harness_definition(AcpRuntime::Goose, "modelstudio", "qwen", "/bin/pay");
        let second = harness_definition(AcpRuntime::Codex, "openai", "gpt-5", "/new/pay");

        assert_eq!(
            write_harness(&path, &first).unwrap(),
            HarnessWriteResult::Added
        );
        assert_eq!(
            write_harness(&path, &first).unwrap(),
            HarnessWriteResult::AlreadyPresent
        );
        assert_eq!(
            write_harness(&path, &second).unwrap(),
            HarnessWriteResult::Updated
        );
        assert_eq!(read_harness(&path), Some(second));
    }

    #[test]
    fn runtime_parser_accepts_only_supported_acp_runtime_slugs() {
        assert_eq!(AcpRuntime::parse("goose"), Some(AcpRuntime::Goose));
        assert_eq!(AcpRuntime::parse("claude"), Some(AcpRuntime::Claude));
        assert_eq!(AcpRuntime::parse("codex"), Some(AcpRuntime::Codex));
        assert_eq!(AcpRuntime::parse("unknown"), None);
    }
}
