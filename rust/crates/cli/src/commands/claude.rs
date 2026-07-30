//! `pay claude` — launch Claude Code with Pay MCP and optional alternate
//! inference routing.

use std::process::{Command, Stdio};

use clap::Args;

use super::agent::{AlternateClient, prepare_alternate_provider};
use super::agent_args::model_arg;

const ALLOWED_TOOLS: &str = "mcp__pay__curl,mcp__pay__search_catalog,mcp__pay__list_catalog,mcp__pay__get_catalog_entry,mcp__pay__get_balance,mcp__pay__topup,mcp__pay__create_skill";
const ANTHROPIC_BASE_URL_ENV: &str = "ANTHROPIC_BASE_URL";
const ANTHROPIC_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";
const ANTHROPIC_AUTH_TOKEN_ENV: &str = "ANTHROPIC_AUTH_TOKEN";
const CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION_ENV: &str = "CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION";
const CLAUDE_CODE_DISABLE_TERMINAL_TITLE_ENV: &str = "CLAUDE_CODE_DISABLE_TERMINAL_TITLE";
const OLLAMA_AUTH_TOKEN: &str = "ollama";

/// Run Claude Code with 402 payment support.
///
/// Launches Claude Code with the pay MCP server injected automatically.
/// All arguments are passed through to the `claude` binary.
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct ClaudeCommand {
    /// Arguments forwarded to claude.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

impl ClaudeCommand {
    pub fn run(
        self,
        pay_bin: &str,
        active_account_name: Option<&str>,
        network_override: Option<&str>,
        alternate_provider: bool,
    ) -> pay_core::Result<i32> {
        let launch = prepare_claude_launch(
            &self.args,
            alternate_provider,
            network_override,
            active_account_name,
        )?;

        let mut mcp_server = serde_json::json!({
            "command": pay_bin,
            "args": ["mcp"]
        });

        let mut env = serde_json::Map::new();
        if let Some(source) = active_account_name {
            env.insert(
                "PAY_ACTIVE_ACCOUNT".to_string(),
                serde_json::Value::String(source.to_string()),
            );
        }
        if let Ok(url) = std::env::var("PAY_RPC_URL") {
            env.insert("PAY_RPC_URL".to_string(), serde_json::Value::String(url));
        }
        if let Ok(network) = std::env::var("PAY_NETWORK_ENFORCED") {
            env.insert(
                "PAY_NETWORK_ENFORCED".to_string(),
                serde_json::Value::String(network),
            );
        }
        if let Ok(protocol) = std::env::var("PAY_PROTOCOL_ENFORCED") {
            env.insert(
                "PAY_PROTOCOL_ENFORCED".to_string(),
                serde_json::Value::String(protocol),
            );
        }
        if let Ok(proxy) = std::env::var("PAY_DEBUGGER_PROXY") {
            env.insert(
                "PAY_DEBUGGER_PROXY".to_string(),
                serde_json::Value::String(proxy),
            );
        }
        if !env.is_empty() {
            mcp_server["env"] = serde_json::Value::Object(env);
        }

        let mcp_config = serde_json::json!({
            "mcpServers": {
                "pay": mcp_server
            }
        });

        #[cfg(windows)]
        return launch_windows(
            mcp_config,
            &launch.args,
            launch.base_url.as_deref(),
            launch.model.as_deref(),
        );

        #[cfg(not(windows))]
        {
            let mut command = Command::new("claude");
            command
                .arg("--mcp-config")
                .arg(mcp_config.to_string())
                .arg("--strict-mcp-config")
                .arg("--allowedTools")
                .arg(ALLOWED_TOOLS)
                .arg("--append-system-prompt")
                .arg(pay_core::instructions::INSTRUCTIONS)
                .args(&launch.args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());

            if let Some(base_url) = launch.base_url.as_deref() {
                command.envs(claude_env(base_url, launch.model.as_deref()));
            }

            let status = command.status().map_err(|e| {
                pay_core::Error::Config(format!("Failed to launch claude: {e}. Is it installed?"))
            })?;

            Ok(status.code().unwrap_or(1))
        }
    }
}

struct ClaudeLaunch {
    base_url: Option<String>,
    model: Option<String>,
    args: Vec<String>,
}

fn prepare_claude_launch(
    args: &[String],
    alternate_provider: bool,
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> pay_core::Result<ClaudeLaunch> {
    if !alternate_provider {
        return Ok(ClaudeLaunch {
            base_url: None,
            model: None,
            args: args.to_vec(),
        });
    }

    if claude_metadata_requested(args) {
        return Ok(ClaudeLaunch {
            base_url: None,
            model: None,
            args: args.to_vec(),
        });
    }

    let alternate = prepare_alternate_provider(
        AlternateClient::Claude,
        args,
        network_override,
        account_override,
    )?;
    let args = claude_args_with_model(args, alternate.model.as_deref());

    Ok(ClaudeLaunch {
        base_url: Some(alternate.base_url),
        model: alternate.model,
        args,
    })
}

fn claude_metadata_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help" | "--version" | "-v"))
}

fn claude_args_with_model(args: &[String], model: Option<&str>) -> Vec<String> {
    let Some(model) = model else {
        return args.to_vec();
    };
    if model_arg(args).is_some() {
        return args.to_vec();
    }
    let mut out = vec!["--model".to_string(), model.to_string()];
    out.extend(args.iter().cloned());
    out
}

pub(crate) fn claude_env(base_url: &str, model: Option<&str>) -> Vec<(String, String)> {
    let mut env = vec![
        (ANTHROPIC_BASE_URL_ENV.to_string(), base_url.to_string()),
        (ANTHROPIC_API_KEY_ENV.to_string(), String::new()),
        (
            ANTHROPIC_AUTH_TOKEN_ENV.to_string(),
            OLLAMA_AUTH_TOKEN.to_string(),
        ),
        (
            "CLAUDE_CODE_ATTRIBUTION_HEADER".to_string(),
            "0".to_string(),
        ),
        (
            CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION_ENV.to_string(),
            "false".to_string(),
        ),
        (
            CLAUDE_CODE_DISABLE_TERMINAL_TITLE_ENV.to_string(),
            "1".to_string(),
        ),
    ];

    if let Some(model) = model {
        env.extend([
            (
                "ANTHROPIC_DEFAULT_OPUS_MODEL".to_string(),
                model.to_string(),
            ),
            (
                "ANTHROPIC_DEFAULT_SONNET_MODEL".to_string(),
                model.to_string(),
            ),
            (
                "ANTHROPIC_DEFAULT_HAIKU_MODEL".to_string(),
                model.to_string(),
            ),
            ("CLAUDE_CODE_SUBAGENT_MODEL".to_string(), model.to_string()),
        ]);
    }

    env
}

#[cfg(windows)]
fn launch_windows(
    mcp_config: serde_json::Value,
    extra_args: &[String],
    base_url: Option<&str>,
    model: Option<&str>,
) -> pay_core::Result<i32> {
    let tmp_dir = std::env::temp_dir();

    let config_path = tmp_dir.join("pay_mcp_config.json");
    std::fs::write(&config_path, mcp_config.to_string())
        .map_err(|e| pay_core::Error::Config(format!("Failed to write MCP config: {e}")))?;
    let config_path_str = config_path.to_string_lossy().replace('\'', "''");
    let script = format!(
        "& claude --mcp-config '{config_path_str}' --strict-mcp-config --allowedTools '{ALLOWED_TOOLS}' --append-system-prompt @'\n{instructions}\n'@ @args\n",
        instructions = pay_core::instructions::INSTRUCTIONS,
    );

    let script_path = tmp_dir.join("pay_claude_launcher.ps1");
    std::fs::write(&script_path, &script)
        .map_err(|e| pay_core::Error::Config(format!("Failed to write launcher script: {e}")))?;

    let mut command = Command::new("powershell");
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script_path)
        .args(extra_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(base_url) = base_url {
        command.envs(claude_env(base_url, model));
    }

    let status = command.status().map_err(|e| {
        pay_core::Error::Config(format!(
            "Failed to launch `claude`: {e}. Install: `npm install -g @anthropic-ai/claude-code` (or see https://claude.com/claude-code)."
        ))
    })?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_tools_include_all_pay_mcp_tools() {
        for tool in [
            "mcp__pay__curl",
            "mcp__pay__search_catalog",
            "mcp__pay__list_catalog",
            "mcp__pay__get_catalog_entry",
            "mcp__pay__get_balance",
            "mcp__pay__topup",
            "mcp__pay__create_skill",
        ] {
            assert!(ALLOWED_TOOLS.split(',').any(|allowed| allowed == tool));
        }
    }

    #[test]
    fn native_launch_preserves_args_without_provider_overrides() {
        let args = vec!["--model".into(), "sonnet".into(), "hello".into()];
        let launch = prepare_claude_launch(&args, false, None, None).unwrap();

        assert_eq!(launch.args, args);
        assert_eq!(launch.base_url, None);
        assert_eq!(launch.model, None);
    }

    #[test]
    fn claude_args_inject_model_when_missing() {
        assert_eq!(
            claude_args_with_model(&["-p".into(), "hi".into()], Some("llama3.2")),
            vec!["--model", "llama3.2", "-p", "hi"]
        );
        assert_eq!(
            claude_args_with_model(&["--model".into(), "qwen3.5".into()], Some("llama3.2")),
            vec!["--model", "qwen3.5"]
        );
    }

    #[test]
    fn claude_env_points_anthropic_to_gateway_and_model_tiers() {
        let env = claude_env("http://127.0.0.1:1402", Some("llama3.2"));

        assert!(env.contains(&(
            ANTHROPIC_BASE_URL_ENV.to_string(),
            "http://127.0.0.1:1402".to_string()
        )));
        assert!(env.contains(&(ANTHROPIC_API_KEY_ENV.to_string(), String::new())));
        assert!(env.contains(&(
            ANTHROPIC_AUTH_TOKEN_ENV.to_string(),
            OLLAMA_AUTH_TOKEN.to_string()
        )));
        assert!(env.contains(&(
            "ANTHROPIC_DEFAULT_SONNET_MODEL".to_string(),
            "llama3.2".to_string()
        )));
        assert!(env.contains(&(
            "CLAUDE_CODE_SUBAGENT_MODEL".to_string(),
            "llama3.2".to_string()
        )));
        assert!(env.contains(&(
            CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION_ENV.to_string(),
            "false".to_string()
        )));
        assert!(env.contains(&(
            CLAUDE_CODE_DISABLE_TERMINAL_TITLE_ENV.to_string(),
            "1".to_string()
        )));
    }
}
