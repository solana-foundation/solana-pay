//! `pay acp <harness>` — run an ACP adapter through Pay's payer proxy.
//!
//! ACP uses stdin/stdout for JSON-RPC. Launches are transparent outside Buzz;
//! Buzz-managed launches add a stream middleware that publishes final assistant
//! text when the model did not invoke `buzz messages send` itself. Provider
//! selection uses the existing stderr-backed TUI when interactive, while
//! `--provider`/`--model` (or their environment equivalents) make managed,
//! headless launches deterministic.

use std::process::{Command, Stdio};

use clap::{Args, ValueEnum};

use super::agent::{AlternateClient, AlternateProvider, prepare_alternate_provider_for};
use super::claude::claude_env;
use super::codex::write_model_catalog_file;
use super::goose::goose_provider_env;

const ACP_PROVIDER_ENV: &str = "PAY_ACP_PROVIDER";
const ACP_MODEL_ENV: &str = "PAY_ACP_MODEL";
const CODEX_PROVIDER_ID: &str = "pay_acp";

/// Run an ACP-compatible agent harness with paid inference routing.
#[derive(Args)]
pub struct AcpCommand {
    /// ACP harness to launch.
    #[arg(value_enum)]
    pub harness: AcpHarness,

    /// Pay inference-provider slug. Required for headless launches when more
    /// than one compatible provider is available.
    #[arg(long, value_name = "SLUG")]
    pub provider: Option<String>,

    /// Model exposed by the selected provider.
    #[arg(short, long, value_name = "MODEL")]
    pub model: Option<String>,

    /// Arguments forwarded to the ACP adapter. Place them after `--`.
    #[arg(last = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

/// ACP runtimes whose inference configuration Pay knows how to override.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AcpHarness {
    Goose,
    Claude,
    Codex,
}

impl AcpHarness {
    fn alternate_client(self) -> AlternateClient {
        match self {
            Self::Goose => AlternateClient::Goose,
            Self::Claude => AlternateClient::Claude,
            Self::Codex => AlternateClient::Codex,
        }
    }

    fn adapter_program(self) -> &'static str {
        match self {
            Self::Goose => "goose",
            Self::Claude => "claude-agent-acp",
            Self::Codex => "codex-acp",
        }
    }

    fn install_hint(self) -> &'static str {
        match self {
            Self::Goose => {
                "Install Goose: https://block.github.io/goose/docs/getting-started/installation"
            }
            Self::Claude => {
                "Install the adapter: npm install -g @agentclientprotocol/claude-agent-acp"
            }
            Self::Codex => "Install the adapter: npm install -g @agentclientprotocol/codex-acp",
        }
    }
}

impl AcpCommand {
    pub fn run(
        self,
        active_account_name: Option<&str>,
        network_override: Option<&str>,
    ) -> pay_core::Result<i32> {
        let provider =
            effective_override(self.provider.as_deref(), std::env::var(ACP_PROVIDER_ENV));
        let model = effective_override(self.model.as_deref(), std::env::var(ACP_MODEL_ENV));
        let selection_args = model
            .as_ref()
            .map(|model| vec!["--model".to_string(), model.clone()])
            .unwrap_or_default();

        let alternate = prepare_alternate_provider_for(
            self.harness.alternate_client(),
            &selection_args,
            network_override,
            active_account_name,
            provider.as_deref(),
        )?;
        let launch = AcpLaunch::new(self.harness, alternate, self.args)?;
        launch.run(active_account_name)
    }
}

fn effective_override(
    cli: Option<&str>,
    env: Result<String, std::env::VarError>,
) -> Option<String> {
    cli.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            env.ok()
                .map(|value| value.trim().to_string())
                .filter(|v| !v.is_empty())
        })
}

#[derive(Debug)]
struct AcpLaunch {
    harness: AcpHarness,
    args: Vec<String>,
    env: Vec<(String, String)>,
    // Codex reads this file throughout the adapter process lifetime.
    _model_catalog_file: Option<tempfile::NamedTempFile>,
}

impl AcpLaunch {
    fn new(
        harness: AcpHarness,
        alternate: AlternateProvider,
        extra_args: Vec<String>,
    ) -> pay_core::Result<Self> {
        let model = alternate.model.as_deref().ok_or_else(|| {
            pay_core::Error::Config(format!(
                "{} ACP routing requires a model; pass `--model <MODEL>` or set {ACP_MODEL_ENV}",
                harness.adapter_program()
            ))
        })?;

        let mut model_catalog_file = None;
        let (args, env) = match harness {
            AcpHarness::Goose => {
                let mut args = vec!["acp".to_string()];
                args.extend(extra_args);
                let mut env = goose_provider_env(&alternate, model);
                env.push(("GOOSE_MODE".to_string(), "auto".to_string()));
                (args, env)
            }
            AcpHarness::Claude => {
                let mut env = claude_env(&alternate.base_url, Some(model));
                // The ACP adapter does not receive Claude's `--model` flag.
                // These variables both select the model and make arbitrary
                // gateway model IDs visible in its ACP model options.
                env.extend([
                    ("ANTHROPIC_MODEL".to_string(), model.to_string()),
                    (
                        "ANTHROPIC_CUSTOM_MODEL_OPTION".to_string(),
                        model.to_string(),
                    ),
                ]);
                (extra_args, env)
            }
            AcpHarness::Codex => {
                let catalog = write_model_catalog_file(model)?;
                let env = codex_acp_env(&alternate, model, catalog.path())?;
                model_catalog_file = Some(catalog);
                (extra_args, env)
            }
        };

        Ok(Self {
            harness,
            args,
            env,
            _model_catalog_file: model_catalog_file,
        })
    }

    fn run(self, active_account_name: Option<&str>) -> pay_core::Result<i32> {
        let mut command = adapter_command(self.harness);
        command.args(&self.args).envs(self.env);

        if let Some(account) = active_account_name {
            command.env("PAY_ACTIVE_ACCOUNT", account);
        }

        let result = if super::acp_middleware::buzz_delivery_available() {
            super::acp_middleware::run(command)
        } else {
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map(|status| status.code().unwrap_or(1))
        };
        result.map_err(|error| {
            pay_core::Error::Config(format!(
                "Failed to launch `{}`: {error}. {}",
                self.harness.adapter_program(),
                self.harness.install_hint()
            ))
        })
    }
}

fn codex_acp_env(
    alternate: &AlternateProvider,
    model: &str,
    model_catalog_path: &std::path::Path,
) -> pay_core::Result<Vec<(String, String)>> {
    let config = serde_json::json!({
        "model": model,
        "model_provider": CODEX_PROVIDER_ID,
        "model_reasoning_effort": "none",
        "model_catalog_json": model_catalog_path,
        "model_providers": {
            CODEX_PROVIDER_ID: {
                "name": "Pay ACP provider",
                "base_url": alternate.base_url,
                "wire_api": "responses",
                "env_key": "OPENAI_API_KEY",
                "requires_openai_auth": false
            }
        }
    });

    Ok(vec![
        ("CODEX_CONFIG".to_string(), serde_json::to_string(&config)?),
        ("MODEL_PROVIDER".to_string(), CODEX_PROVIDER_ID.to_string()),
        ("OPENAI_API_KEY".to_string(), "pay".to_string()),
        ("CODEX_API_KEY".to_string(), "pay".to_string()),
        ("NO_BROWSER".to_string(), "1".to_string()),
    ])
}

#[cfg(not(windows))]
fn adapter_command(harness: AcpHarness) -> Command {
    Command::new(harness.adapter_program())
}

// npm-installed ACP adapters are `.cmd` shims on Windows. Run those through
// cmd.exe while keeping stdin/stdout inherited so ACP JSON-RPC remains
// transparent. Goose is a native executable and does not need the shell.
#[cfg(windows)]
fn adapter_command(harness: AcpHarness) -> Command {
    if harness == AcpHarness::Goose {
        return Command::new(harness.adapter_program());
    }
    let mut command = Command::new("cmd.exe");
    command.args(["/D", "/S", "/C", harness.adapter_program()]);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alternate(model: Option<&str>) -> AlternateProvider {
        AlternateProvider {
            base_url: "http://127.0.0.1:54321/v1".to_string(),
            model: model.map(str::to_string),
        }
    }

    #[test]
    fn cli_override_wins_over_environment() {
        assert_eq!(
            effective_override(Some(" modelstudio "), Ok("other".to_string())),
            Some("modelstudio".to_string())
        );
        assert_eq!(
            effective_override(None, Ok(" qwen3.7-plus ".to_string())),
            Some("qwen3.7-plus".to_string())
        );
    }

    #[test]
    fn goose_launches_its_native_acp_subcommand() {
        let launch =
            AcpLaunch::new(AcpHarness::Goose, alternate(Some("qwen3.7-plus")), vec![]).unwrap();

        assert_eq!(launch.args, ["acp"]);
        assert!(
            launch
                .env
                .contains(&("GOOSE_PROVIDER".to_string(), "openai".to_string()))
        );
        assert!(
            launch
                .env
                .contains(&("GOOSE_MODEL".to_string(), "qwen3.7-plus".to_string()))
        );
    }

    #[test]
    fn claude_acp_receives_gateway_and_custom_model_environment() {
        let launch =
            AcpLaunch::new(AcpHarness::Claude, alternate(Some("qwen3.7-plus")), vec![]).unwrap();

        assert!(launch.env.contains(&(
            "ANTHROPIC_BASE_URL".to_string(),
            "http://127.0.0.1:54321/v1".to_string()
        )));
        assert!(
            launch
                .env
                .contains(&("ANTHROPIC_MODEL".to_string(), "qwen3.7-plus".to_string()))
        );
    }

    #[test]
    fn codex_acp_receives_pay_model_provider_config() {
        let launch = AcpLaunch::new(AcpHarness::Codex, alternate(Some("gpt-5.4")), vec![]).unwrap();
        let config = launch
            .env
            .iter()
            .find(|(key, _)| key == "CODEX_CONFIG")
            .map(|(_, value)| value)
            .unwrap();
        let config: serde_json::Value = serde_json::from_str(config).unwrap();

        assert_eq!(config["model"], "gpt-5.4");
        assert_eq!(config["model_provider"], CODEX_PROVIDER_ID);
        let catalog_path = config["model_catalog_json"].as_str().unwrap();
        assert!(std::path::Path::new(catalog_path).is_file());
        assert_eq!(
            config["model_providers"][CODEX_PROVIDER_ID]["base_url"],
            "http://127.0.0.1:54321/v1"
        );
        assert_eq!(
            config["model_providers"][CODEX_PROVIDER_ID]["wire_api"],
            "responses"
        );
    }

    #[test]
    fn headless_gateway_fallback_requires_a_model() {
        let error = AcpLaunch::new(AcpHarness::Goose, alternate(None), vec![]).unwrap_err();

        assert!(error.to_string().contains(ACP_MODEL_ENV));
    }
}
