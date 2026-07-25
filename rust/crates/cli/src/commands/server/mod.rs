pub mod demo;
pub mod inference;
pub mod local_registration;
pub(crate) mod payments;
pub mod plans;
pub(crate) mod provider_registration;
pub mod scaffold;
pub mod start;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum ServerCommand {
    /// Start a local demo with a dashboard for tracing payments.
    Demo(demo::DemoCommand),
    /// Start a proxy that enables stablecoin payments for your API.
    Start(start::StartCommand),
    /// Discover local AI inference servers (Ollama, LM Studio, llama.cpp,
    /// vLLM, exo) and proxy them with live request tracking.
    Inference(inference::InferenceCommand),
    /// Create a YAML file that defines endpoints and payment requirements.
    Scaffold(scaffold::ScaffoldCommand),
    /// Derive (and optionally write back) the on-chain `Plan` PDAs for
    /// subscription endpoints declared in pay-demo.yaml.
    Plans {
        #[command(subcommand)]
        command: PlansCommand,
    },
}

#[derive(Subcommand)]
pub enum PlansCommand {
    /// Derive Plan PDAs from pay-demo.yaml. Pass `--write` to update the
    /// YAML in place once the Plan accounts have been published on-chain.
    Publish(plans::PublishCommand),
}

impl ServerCommand {
    pub fn otlp_sidecar(&self) -> Option<&str> {
        match self {
            Self::Demo(cmd) => cmd.otlp_sidecar.as_deref(),
            Self::Start(cmd) => cmd.otlp_sidecar.as_deref(),
            Self::Inference(_) => None,
            Self::Scaffold(_) => None,
            Self::Plans { .. } => None,
        }
    }

    pub fn run(self, active_account_name: Option<&str>, sandbox: bool) -> pay_core::Result<()> {
        match self {
            Self::Demo(cmd) => cmd.run(active_account_name, sandbox),
            Self::Start(cmd) => cmd.run(active_account_name, sandbox),
            Self::Inference(cmd) => cmd.run(active_account_name, sandbox),
            Self::Scaffold(cmd) => cmd.run(),
            Self::Plans { command } => match command {
                PlansCommand::Publish(cmd) => cmd.run(),
            },
        }
    }
}
