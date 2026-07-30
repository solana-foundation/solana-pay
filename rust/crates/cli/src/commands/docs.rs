//! `pay docs` — generate documentation artifacts from the pay sources.
//!
//! Currently exposes `pay docs schema`, which emits the JSON Schema for a
//! paywall YAML spec. The schema is derived from the `ApiSpec` Rust types
//! (via `schemars`), so it never drifts from the actual deserializer: editors
//! can validate specs against it, and the docs site can host it as the
//! source-of-truth reference.

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum DocsCommand {
    /// Print the provider-spec JSON Schema (generated from the Rust types).
    Schema(SchemaCommand),
}

/// Emit the JSON Schema for a paywall YAML spec (`ApiSpec`) to stdout.
///
/// Pipe it to a file to host or validate against, e.g.
/// `pay docs schema > provider.schema.json`.
#[derive(Args)]
pub struct SchemaCommand {}

impl DocsCommand {
    pub fn run(self) -> pay_core::Result<()> {
        match self {
            Self::Schema(cmd) => cmd.run(),
        }
    }
}

impl SchemaCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let schema = schemars::schema_for!(pay_types::metering::ApiSpec);
        println!("{}", serde_json::to_string_pretty(&schema)?);
        Ok(())
    }
}
