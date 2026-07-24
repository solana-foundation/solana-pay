//! `pay goose` — launch Goose with the pay MCP server and optional paid
//! alternate-provider routing.

use std::process::{Command, Stdio};

use clap::Args;

use super::agent_args::args_without_model;
use super::claude::{AlternateClient, AlternateProvider, prepare_alternate_provider};

const GOOSE_PROVIDER_ENV: &str = "GOOSE_PROVIDER";
const GOOSE_MODEL_ENV: &str = "GOOSE_MODEL";
const OPENAI_HOST_ENV: &str = "OPENAI_HOST";
const OPENAI_API_KEY_ENV: &str = "OPENAI_API_KEY";
const OPENAI_BASE_PATH_ENV: &str = "OPENAI_BASE_PATH";
const GOOSE_DISABLE_SESSION_NAMING_ENV: &str = "GOOSE_DISABLE_SESSION_NAMING";

/// Run Goose with 402 payment support.
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct GooseCommand {
    /// Arguments forwarded to `goose session`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

impl GooseCommand {
    pub fn run(
        self,
        pay_bin: &str,
        active_account_name: Option<&str>,
        network_override: Option<&str>,
        _alternate_provider: bool,
    ) -> pay_core::Result<i32> {
        if goose_version_requested(&self.args) {
            return launch_goose(&self.args, None, active_account_name);
        }
        if goose_help_requested(&self.args) {
            let mut args = vec!["session".to_string()];
            args.extend(self.args);
            return launch_goose(&args, None, active_account_name);
        }

        // Goose is intentionally alternate-first: both `pay goose` and
        // `pay --alt goose` select a paid provider and use the payer proxy.
        let alternate = prepare_alternate_provider(
            AlternateClient::Goose,
            &self.args,
            network_override,
            active_account_name,
        )?;
        let mut args = vec!["session".to_string(), "--with-extension".to_string()];
        args.push(pay_mcp_command(pay_bin));
        args.extend(args_without_model(&self.args));
        launch_goose(&args, Some(&alternate), active_account_name)
    }
}

fn launch_goose(
    args: &[String],
    alternate: Option<&AlternateProvider>,
    active_account_name: Option<&str>,
) -> pay_core::Result<i32> {
    let mut command = Command::new("goose");
    command
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    if let Some(account) = active_account_name {
        command.env("PAY_ACTIVE_ACCOUNT", account);
    }
    if let Some(alternate) = alternate {
        let model = alternate.model.as_deref().ok_or_else(|| {
            pay_core::Error::Config(
                "Goose alternate-provider routing requires a selected model".to_string(),
            )
        })?;
        command.envs(goose_provider_env(alternate, model));
    }

    let status = command.status().map_err(|e| {
        pay_core::Error::Config(format!(
            "Failed to launch Goose: {e}. Install: https://block.github.io/goose/docs/getting-started/installation"
        ))
    })?;
    Ok(status.code().unwrap_or(1))
}

fn goose_provider_env(alternate: &AlternateProvider, model: &str) -> Vec<(String, String)> {
    vec![
        (GOOSE_PROVIDER_ENV.to_string(), "openai".to_string()),
        (GOOSE_MODEL_ENV.to_string(), model.to_string()),
        (OPENAI_HOST_ENV.to_string(), alternate.base_url.clone()),
        (OPENAI_API_KEY_ENV.to_string(), "pay".to_string()),
        (
            OPENAI_BASE_PATH_ENV.to_string(),
            "v1/chat/completions".to_string(),
        ),
        // Goose otherwise makes a second, hidden model request after each of
        // the first few turns to generate a session title. With a paid
        // provider that request opens and settles its own payment channel.
        (
            GOOSE_DISABLE_SESSION_NAMING_ENV.to_string(),
            "true".to_string(),
        ),
    ]
}

fn goose_version_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--version" | "-V"))
}

fn goose_help_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
}

fn pay_mcp_command(pay_bin: &str) -> String {
    #[cfg(windows)]
    return format!("\"{}\" mcp", pay_bin.replace('"', "\"\""));

    #[cfg(not(windows))]
    format!("'{}' mcp", pay_bin.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternate_provider_uses_goose_openai_environment() {
        let provider = AlternateProvider {
            base_url: "http://127.0.0.1:54321".to_string(),
            model: Some("qwen3.7-plus".to_string()),
        };
        let env = goose_provider_env(&provider, "qwen3.7-plus");

        assert!(env.contains(&(GOOSE_PROVIDER_ENV.to_string(), "openai".to_string())));
        assert!(env.contains(&(
            OPENAI_HOST_ENV.to_string(),
            "http://127.0.0.1:54321".to_string()
        )));
        assert!(env.contains(&(
            OPENAI_BASE_PATH_ENV.to_string(),
            "v1/chat/completions".to_string()
        )));
        assert!(env.contains(&(
            GOOSE_DISABLE_SESSION_NAMING_ENV.to_string(),
            "true".to_string()
        )));
    }

    #[test]
    fn metadata_requests_do_not_start_alternate_routing() {
        assert!(goose_version_requested(&["--version".into()]));
        assert!(goose_help_requested(&["--help".into()]));
        assert!(!goose_version_requested(&["hello".into()]));
        assert!(!goose_help_requested(&["hello".into()]));
    }

    #[test]
    fn mcp_command_quotes_spaces() {
        let command = pay_mcp_command("/tmp/Pay Tools/pay");
        assert!(command.contains("Pay Tools"));
        assert!(command.ends_with(" mcp"));
    }
}
