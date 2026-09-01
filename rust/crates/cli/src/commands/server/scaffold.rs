//! `pay server scaffold` — generate a starter paywall YAML spec.

/// Generate a starter paywall YAML spec file.
#[derive(clap::Args)]
pub struct ScaffoldCommand {
    /// Output file path. Defaults to "paywall.yml".
    #[arg(default_value = "paywall.yml")]
    pub output: String,
}

const TEMPLATE: &str = r#"name: my-api
subdomain: myapi
title: "My API"
description: "API description"
category: ai_ml
version: v1
routing:
  type: proxy
  url: https://api.example.com
accounting: pooled

endpoints:
  # Free endpoint — no payment required
  - method: GET
    path: "v1/health"
    description: "Health check"

  # Metered endpoint — requires payment
  - method: POST
    path: "v1/generate"
    description: "Generate content"
    metering:
      dimensions:
        - direction: usage
          unit: requests
          scale: 1
          tiers:
            - price_usd: 0.001
"#;

impl ScaffoldCommand {
    pub fn run(self) -> pay_core::Result<()> {
        if std::path::Path::new(&self.output).exists() {
            return Err(pay_core::Error::Config(format!(
                "{} already exists. Delete it first or choose a different name.",
                self.output
            )));
        }

        std::fs::write(&self.output, TEMPLATE).map_err(|e| {
            pay_core::Error::Config(format!("Failed to write {}: {e}", self.output))
        })?;

        eprintln!("Created {}", self.output);
        eprintln!();
        eprintln!("  Edit the file, then start the gateway:");
        eprintln!("  pay gate api {}", self.output);
        eprintln!();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TEMPLATE;
    use pay_types::metering::{ApiSpec, RoutingConfig};

    #[test]
    fn scaffold_template_uses_the_current_routing_schema() {
        let spec: ApiSpec = serde_yml::from_str(TEMPLATE).expect("template must parse as ApiSpec");
        assert!(matches!(
            spec.routing,
            RoutingConfig::Proxy { ref url, .. } if url == "https://api.example.com"
        ));
    }
}
