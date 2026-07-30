//! `pay server demo` — start the gateway with a bundled demo paywall.
//!
//! Extracts the embedded payment-debugger.yml to `./pay-demo.yaml` in the
//! current working directory, then invokes `pay gate api` with sandbox and
//! debugger implied.

use crate::commands::server::start::StartCommand;

const DEMO_PAYWALL: &str = include_str!("payment-debugger.yml");

#[derive(clap::Args)]
pub struct DemoCommand {
    /// Address to bind to.
    #[arg(long, default_value = "0.0.0.0:1402")]
    pub bind: String,

    /// Recipient wallet address for payments.
    #[arg(long)]
    pub recipient: Option<String>,

    /// Payment currency (SOL, USDC, etc.).
    #[arg(long, default_value = "USDC")]
    pub currency: String,

    /// Use local Surfpool (http://localhost:8899) instead of hosted sandbox.
    #[arg(long)]
    pub local: bool,

    /// Export traces and metrics to an OTLP HTTP sidecar at HOST:PORT.
    #[arg(long, value_name = "HOST:PORT")]
    pub otlp_sidecar: Option<String>,
}

impl DemoCommand {
    pub fn run(
        self,
        legacy_signer_source: Option<&str>,
        account_override: Option<&str>,
        _sandbox: bool,
    ) -> pay_core::Result<()> {
        // Extract the embedded paywall to ./pay-demo.yaml.
        let paywall_path = std::path::PathBuf::from("pay-demo.yaml");
        std::fs::write(&paywall_path, DEMO_PAYWALL)
            .map_err(|e| pay_core::Error::Config(format!("Failed to write pay-demo.yaml: {e}")))?;

        // Demo mode always runs on sandbox. Default to hosted Surfpool;
        // --local overrides to localhost.
        let rpc_url = if self.local {
            Some(pay_core::config::LOCAL_RPC_URL.to_string())
        } else {
            Some(pay_core::config::SANDBOX_RPC_URL.to_string())
        };

        let cmd = StartCommand {
            paywall: paywall_path.to_string_lossy().into_owned(),
            bind: self.bind,
            recipient: self.recipient,
            currency: self.currency,
            rpc_url,
            debugger: true,
            otlp_sidecar: self.otlp_sidecar,
            openapi: None,
            public_url: None,
            no_register: false,
            scaffolded_paywall: Some("./pay-demo.yaml".to_string()),
        };
        cmd.run(legacy_signer_source, account_override, true)
    }
}
