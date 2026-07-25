#[cfg(windows)]
use std::path::PathBuf;
use std::process::{Command, Stdio};

use clap::Args;

use super::claude::{AlternateClient, AlternateProvider, prepare_alternate_provider};

const ALTERNATE_PROVIDER_ID: &str = "pay_alt";
const ALTERNATE_BASE_INSTRUCTIONS: &str = "You are Codex, a coding agent working with the user in the current workspace. Follow the developer instructions. Use the provided tools to inspect and modify files when requested, verify your work, and report results concisely. Do not invent tool results.";

pub(crate) const PAY_MCP_ENABLED_TOOLS: &[&str] = &[
    "curl",
    "search_catalog",
    "list_catalog",
    "get_catalog_entry",
    "get_balance",
    "topup",
    "create_skill",
];

/// Run Codex with 402 payment support.
///
/// Launches Codex with the pay MCP server injected automatically.
/// All arguments are passed through to the `codex` binary.
#[derive(Args)]
#[command(disable_help_flag = true)]
pub struct CodexCommand {
    /// Arguments forwarded to codex.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

impl CodexCommand {
    pub fn run(
        self,
        pay_bin: &str,
        active_account_name: Option<&str>,
        network_override: Option<&str>,
        alternate_provider: bool,
    ) -> pay_core::Result<i32> {
        let alternate = if alternate_provider && !codex_metadata_requested(&self.args) {
            Some(prepare_alternate_provider(
                AlternateClient::Codex,
                &self.args,
                network_override,
                active_account_name,
            )?)
        } else {
            None
        };

        let model_catalog_file = alternate
            .as_ref()
            .and_then(|provider| provider.model.as_deref())
            .map(write_model_catalog_file)
            .transpose()?;
        let codex_args = build_codex_args(
            pay_bin,
            active_account_name,
            alternate.as_ref(),
            model_catalog_file.as_ref().map(|file| file.path()),
            &self.args,
        );

        #[cfg(windows)]
        return launch_windows(&codex_args);

        #[cfg(not(windows))]
        {
            let status = Command::new("codex")
                .args(&codex_args)
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map_err(|e| {
                    pay_core::Error::Config(format!(
                        "Failed to launch codex: {e}. Is it installed?"
                    ))
                })?;

            Ok(status.code().unwrap_or(1))
        }
    }
}

fn codex_metadata_requested(args: &[String]) -> bool {
    args.iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help" | "--version" | "-V"))
}

fn build_codex_args(
    pay_bin: &str,
    active_account_name: Option<&str>,
    alternate: Option<&AlternateProvider>,
    model_catalog_path: Option<&std::path::Path>,
    extra_args: &[String],
) -> Vec<String> {
    let mut args = vec![
        "-c".to_string(),
        config_string("mcp_servers.pay.command", pay_bin),
        "-c".to_string(),
        "mcp_servers.pay.args=[\"mcp\"]".to_string(),
        "-c".to_string(),
        format!(
            "mcp_servers.pay.enabled_tools={}",
            toml_string_array(PAY_MCP_ENABLED_TOOLS)
        ),
    ];

    if let Some(alternate) = alternate {
        args.extend([
            "-c".to_string(),
            config_string("model_provider", ALTERNATE_PROVIDER_ID),
            "-c".to_string(),
            config_string(
                &format!("model_providers.{ALTERNATE_PROVIDER_ID}.name"),
                "Pay alternate provider",
            ),
            "-c".to_string(),
            config_string(
                &format!("model_providers.{ALTERNATE_PROVIDER_ID}.base_url"),
                &alternate.base_url,
            ),
            "-c".to_string(),
            config_string(
                &format!("model_providers.{ALTERNATE_PROVIDER_ID}.wire_api"),
                "responses",
            ),
        ]);
        if let Some(model) = alternate.model.as_deref() {
            args.extend([
                "-c".to_string(),
                config_string("model", model),
                "-c".to_string(),
                config_string("model_reasoning_effort", "none"),
            ]);
        }
        if let Some(path) = model_catalog_path {
            args.extend([
                "-c".to_string(),
                config_string("model_catalog_json", &path.to_string_lossy()),
            ]);
        }
    }

    // Pass config to MCP server via env.
    let mut env_parts = Vec::new();
    if let Some(source) = active_account_name {
        env_parts.push(format!("PAY_ACTIVE_ACCOUNT={}", toml_string(source)));
    }
    if let Ok(url) = std::env::var("PAY_RPC_URL") {
        env_parts.push(format!("PAY_RPC_URL={}", toml_string(&url)));
    }
    if let Ok(network) = std::env::var("PAY_NETWORK_ENFORCED") {
        env_parts.push(format!("PAY_NETWORK_ENFORCED={}", toml_string(&network)));
    }
    if let Ok(protocol) = std::env::var("PAY_PROTOCOL_ENFORCED") {
        env_parts.push(format!("PAY_PROTOCOL_ENFORCED={}", toml_string(&protocol)));
    }
    if let Ok(proxy) = std::env::var("PAY_DEBUGGER_PROXY") {
        env_parts.push(format!("PAY_DEBUGGER_PROXY={}", toml_string(&proxy)));
    }
    if !env_parts.is_empty() {
        args.push("-c".to_string());
        args.push(format!("mcp_servers.pay.env={{{}}}", env_parts.join(",")));
    }

    // This is additive to Codex's model prompt. `model_instructions_file`
    // replaces the model prompt and leaves alternate models without Codex's
    // core agent instructions.
    args.push("-c".to_string());
    args.push(config_string(
        "developer_instructions",
        pay_core::instructions::INSTRUCTIONS,
    ));
    args.extend(extra_args.iter().cloned());
    args
}

fn write_model_catalog_file(model: &str) -> pay_core::Result<tempfile::NamedTempFile> {
    use std::io::Write;

    let mut file = tempfile::Builder::new()
        .prefix("pay_codex_model_catalog_")
        .suffix(".json")
        .tempfile()?;
    let catalog = build_model_catalog(model);
    serde_json::to_writer(&mut file, &catalog)?;
    file.flush()?;
    Ok(file)
}

fn build_model_catalog(model: &str) -> serde_json::Value {
    serde_json::json!({
        "models": [{
            "slug": model,
            "display_name": model,
            "description": "OpenAI-compatible model routed through Pay",
            "default_reasoning_level": null,
            "supported_reasoning_levels": [],
            "shell_type": "default",
            "visibility": "list",
            "supported_in_api": true,
            "priority": 1,
            "availability_nux": null,
            "upgrade": null,
            "base_instructions": ALTERNATE_BASE_INSTRUCTIONS,
            "supports_reasoning_summaries": false,
            "default_reasoning_summary": "none",
            "support_verbosity": false,
            "default_verbosity": null,
            "apply_patch_tool_type": null,
            "web_search_tool_type": "text",
            "truncation_policy": {"mode": "bytes", "limit": 10000},
            "supports_parallel_tool_calls": false,
            "supports_image_detail_original": false,
            "context_window": 1000000,
            "max_context_window": 1000000,
            "effective_context_window_percent": 95,
            "experimental_supported_tools": [],
            "input_modalities": ["text"],
            "supports_search_tool": false,
            "use_responses_lite": false
        }]
    })
}

fn config_string(key: &str, value: &str) -> String {
    format!("{key}={}", toml_string(value))
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("serializing a string cannot fail")
}

fn toml_string_array(values: &[&str]) -> String {
    serde_json::to_string(values).expect("serializing a string array cannot fail")
}

// On Windows, npm's codex.cmd wrapper forwards %* through cmd.exe. The pay
// instructions include spaces, quotes, and <...> placeholders, which cmd can
// split into stray prompt arguments like "from". Bypass npm shims and run the
// Codex Node entrypoint directly when that layout is present.
#[cfg(windows)]
fn launch_windows(codex_args: &[String]) -> pay_core::Result<i32> {
    let (program, mut args) = windows_codex_command();
    args.extend(codex_args.iter().cloned());

    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| {
            pay_core::Error::Config(format!(
                "Failed to launch `codex`: {e}. Install: `npm install -g @openai/codex` (or see https://github.com/openai/codex)."
            ))
        })?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(windows)]
fn windows_codex_command() -> (PathBuf, Vec<String>) {
    if let Some((node, codex_js)) = find_npm_codex_entrypoint() {
        return (node, vec![codex_js.to_string_lossy().to_string()]);
    }

    (PathBuf::from("codex.exe"), Vec::new())
}

#[cfg(windows)]
fn find_npm_codex_entrypoint() -> Option<(PathBuf, PathBuf)> {
    for shim in ["codex.cmd", "codex.ps1", "codex"] {
        let Some(shim_path) = find_on_path(shim) else {
            continue;
        };
        let Some(base) = shim_path.parent() else {
            continue;
        };
        for codex_js in codex_js_candidates(base) {
            if codex_js.is_file() {
                let bundled_node = base.join("node.exe");
                let node = if bundled_node.is_file() {
                    bundled_node
                } else {
                    PathBuf::from("node.exe")
                };
                return Some((node, codex_js));
            }
        }
    }

    None
}

#[cfg(windows)]
fn codex_js_candidates(base: &Path) -> [PathBuf; 2] {
    [
        base.join("node_modules")
            .join("@openai")
            .join("codex")
            .join("bin")
            .join("codex.js"),
        base.join("..")
            .join("@openai")
            .join("codex")
            .join("bin")
            .join("codex.js"),
    ]
}

#[cfg(windows)]
fn find_on_path(file_name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(file_name))
            .find(|candidate| candidate.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_string_escapes_quotes_and_angle_examples() {
        let value = r#"Call get_catalog_entry("<fqn>") then use "<url from results>"."#;

        assert_eq!(
            config_string("instructions", value),
            r#"instructions="Call get_catalog_entry(\"<fqn>\") then use \"<url from results>\".""#
        );
    }

    #[test]
    fn build_args_escapes_windows_paths_as_toml() {
        let args = build_codex_args(r#"C:\Users\me\pay.exe"#, Some("default"), None, None, &[]);

        assert!(args.contains(&r#"mcp_servers.pay.command="C:\\Users\\me\\pay.exe""#.to_string()));
        assert!(args.contains(
            &r#"mcp_servers.pay.enabled_tools=["curl","search_catalog","list_catalog","get_catalog_entry","get_balance","topup","create_skill"]"#.to_string()
        ));
        assert!(
            args.contains(&r#"mcp_servers.pay.env={PAY_ACTIVE_ACCOUNT="default"}"#.to_string())
        );
        assert!(
            args.iter()
                .any(|arg| arg.starts_with("developer_instructions="))
        );
    }

    #[test]
    fn build_args_routes_codex_through_alternate_responses_provider() {
        let alternate = AlternateProvider {
            base_url: "http://127.0.0.1:54321/v1".to_string(),
            model: Some("qwen3-coder-next".to_string()),
        };
        let args = build_codex_args(
            "pay",
            None,
            Some(&alternate),
            Some(std::path::Path::new("/tmp/pay-model-catalog.json")),
            &[],
        );

        assert!(args.contains(&"model_provider=\"pay_alt\"".to_string()));
        assert!(args.contains(
            &"model_providers.pay_alt.base_url=\"http://127.0.0.1:54321/v1\"".to_string()
        ));
        assert!(args.contains(&"model_providers.pay_alt.wire_api=\"responses\"".to_string()));
        assert!(args.contains(&"model=\"qwen3-coder-next\"".to_string()));
        assert!(args.contains(&"model_reasoning_effort=\"none\"".to_string()));
        assert!(args.contains(&"model_catalog_json=\"/tmp/pay-model-catalog.json\"".to_string()));
    }

    #[test]
    fn alternate_model_catalog_disables_unsupported_openai_features() {
        let catalog = build_model_catalog("qwen3.7-plus");
        let model = &catalog["models"][0];

        assert_eq!(model["slug"], "qwen3.7-plus");
        assert_eq!(model["supported_reasoning_levels"], serde_json::json!([]));
        assert_eq!(model["supports_reasoning_summaries"], false);
        assert_eq!(model["supports_parallel_tool_calls"], false);
        assert_eq!(model["input_modalities"], serde_json::json!(["text"]));
    }

    #[test]
    fn metadata_requests_skip_alternate_provider_selection() {
        assert!(codex_metadata_requested(&["--version".to_string()]));
        assert!(codex_metadata_requested(&["-h".to_string()]));
        assert!(!codex_metadata_requested(&["hello".to_string()]));
    }

    #[cfg(windows)]
    #[test]
    fn codex_js_candidates_cover_global_and_local_npm_layouts() {
        let candidates = codex_js_candidates(Path::new(r"C:\Users\me\AppData\Roaming\npm"));

        assert_eq!(
            candidates[0],
            PathBuf::from(r"C:\Users\me\AppData\Roaming\npm")
                .join("node_modules")
                .join("@openai")
                .join("codex")
                .join("bin")
                .join("codex.js")
        );
        assert_eq!(
            candidates[1],
            PathBuf::from(r"C:\Users\me\AppData\Roaming\npm")
                .join("..")
                .join("@openai")
                .join("codex")
                .join("bin")
                .join("codex.js")
        );
    }
}
