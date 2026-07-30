use std::fs;
use std::path::PathBuf;

use clap::Subcommand;
use owo_colors::OwoColorize;

#[derive(Subcommand)]
pub enum ProviderCommand {
    /// Sync runtime paywall YAMLs into registry .md files.
    Sync(SyncCommand),
}

impl ProviderCommand {
    pub fn run(self) -> pay_core::Result<()> {
        match self {
            Self::Sync(cmd) => cmd.run(),
        }
    }
}

/// Sync runtime .yml specs into registry .md files.
///
/// Reads .yml files (the `pay gate api` format), extracts the
/// registry-relevant fields, translates metering → pricing, drops
/// runtime config, and writes .md files with YAML frontmatter.
#[derive(clap::Args)]
pub struct SyncCommand {
    /// Paths to .yml files or glob patterns (e.g. `providers/google/*.yml`).
    #[arg(required = true)]
    pub paths: Vec<String>,

    /// Output directory. Files are written to `<out>/<operator>/<origin>/<name>.md`.
    /// Defaults to `providers/` in the current directory.
    #[arg(long, short, default_value = "providers")]
    pub out: PathBuf,

    /// The operator/aggregator serving these APIs (e.g. `solana-foundation`).
    #[arg(long)]
    pub operator: String,

    /// Override the origin org. By default, inferred from the parent directory
    /// of each input file.
    #[arg(long)]
    pub origin: Option<String>,

    /// Template for service_url (production). Use `{name}` as placeholder.
    /// If omitted, falls back to the routing.url from the YAML spec.
    #[arg(long)]
    pub service_url: Option<String>,

    /// Template for sandbox_service_url. Use `{name}` as placeholder.
    /// Example: `https://sandbox-pay-google-{name}-123883807128.us-central1.run.app`
    #[arg(long)]
    pub sandbox_service_url: Option<String>,
}

impl SyncCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let files = expand_paths(&self.paths)?;

        if files.is_empty() {
            eprintln!("{}", "No .yml files matched.".red());
            std::process::exit(1);
        }

        eprintln!(
            "Syncing {} file(s) → {}/",
            files.len().to_string().bold(),
            self.out.display()
        );
        eprintln!();

        let mut written = 0;
        let mut skipped = 0;

        for file in &files {
            let name = match file.file_stem().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => {
                    eprintln!("  {} skipping {}: no filename", "-".red(), file.display());
                    skipped += 1;
                    continue;
                }
            };

            let origin = self.origin.clone().unwrap_or_else(|| {
                file.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            });

            let text = match fs::read_to_string(file) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("  {} {}: {e}", "-".red(), file.display());
                    skipped += 1;
                    continue;
                }
            };

            let spec: serde_json::Value = match serde_yml::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  {} {}: YAML parse error: {e}", "-".red(), file.display());
                    skipped += 1;
                    continue;
                }
            };

            // Validate metering/splits config against the typed ApiSpec.
            if let Ok(api_spec) = serde_yml::from_str::<pay_types::metering::ApiSpec>(&text) {
                let validation_errs = pay_types::metering::validate_api_spec(&api_spec);
                if !validation_errs.is_empty() {
                    for err in &validation_errs {
                        eprintln!("  {} {}: {err}", "✗".red(), name);
                    }
                    skipped += 1;
                    continue;
                }
            }

            let md = convert_to_registry_md(
                &spec,
                &name,
                self.service_url.as_deref(),
                self.sandbox_service_url.as_deref(),
            );

            let out_path = self
                .out
                .join(&self.operator)
                .join(&origin)
                .join(format!("{name}.md"));
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    pay_core::Error::Config(format!("mkdir {}: {e}", parent.display()))
                })?;
            }
            fs::write(&out_path, md).map_err(|e| {
                pay_core::Error::Config(format!("write {}: {e}", out_path.display()))
            })?;

            let fqn = format!("{}/{origin}/{name}", self.operator);
            eprintln!("  {} {}", "+".green(), fqn);
            written += 1;
        }

        eprintln!();
        eprintln!(
            "Done: {} written, {} skipped",
            written.to_string().green(),
            if skipped > 0 {
                skipped.to_string().red().to_string()
            } else {
                skipped.to_string()
            }
        );

        Ok(())
    }
}

fn expand_paths(patterns: &[String]) -> pay_core::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for pattern in patterns {
        let matches: Vec<_> = glob::glob(pattern)
            .map_err(|e| pay_core::Error::Config(format!("invalid glob `{pattern}`: {e}")))?
            .filter_map(|r| r.ok())
            .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("yml"))
            .collect();

        if matches.is_empty() {
            let p = PathBuf::from(pattern);
            if p.is_file() {
                files.push(p);
            } else {
                eprintln!(
                    "  {} no files matched: {pattern}",
                    "warning:".yellow().bold()
                );
            }
        } else {
            files.extend(matches);
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// Convert a runtime paywall YAML (serde_json::Value) to a registry .md string.
fn convert_to_registry_md(
    spec: &serde_json::Value,
    name: &str,
    service_url_template: Option<&str>,
    sandbox_service_url_template: Option<&str>,
) -> String {
    let obj = spec.as_object().expect("spec must be an object");

    let title = obj.get("title").and_then(|v| v.as_str()).unwrap_or(name);
    let description = obj
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let category = obj
        .get("category")
        .and_then(|v| v.as_str())
        .unwrap_or("other");
    let use_case = obj.get("use_case").and_then(|v| v.as_str());
    let version = obj.get("version").and_then(|v| v.as_str()).unwrap_or("");

    let service_url = match service_url_template {
        Some(tpl) => tpl.replace("{name}", name),
        None => obj
            .get("routing")
            .and_then(|r| r.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    };

    let endpoints = obj
        .get("endpoints")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let translated_endpoints: Vec<serde_json::Value> = endpoints
        .into_iter()
        .map(|ep| {
            let mut out = serde_json::Map::new();
            if let Some(m) = ep.get("method") {
                out.insert("method".into(), m.clone());
            }
            if let Some(p) = ep.get("path") {
                out.insert("path".into(), p.clone());
            }
            if let Some(r) = ep.get("resource") {
                out.insert("resource".into(), r.clone());
            }
            if let Some(d) = ep.get("description") {
                out.insert("description".into(), d.clone());
            }
            if let Some(metering) = ep.get("metering") {
                let mut pricing = serde_json::Map::new();
                if let Some(dims) = metering.get("dimensions") {
                    let cleaned = strip_splits(dims);
                    pricing.insert("dimensions".into(), cleaned);
                }
                if !pricing.is_empty() {
                    out.insert("pricing".into(), serde_json::Value::Object(pricing));
                }
            }
            serde_json::Value::Object(out)
        })
        .collect();

    let mut fm = serde_json::Map::new();
    fm.insert("name".into(), serde_json::Value::String(name.into()));
    fm.insert("title".into(), serde_json::Value::String(title.into()));
    fm.insert(
        "description".into(),
        serde_json::Value::String(description.into()),
    );
    fm.insert(
        "category".into(),
        serde_json::Value::String(category.into()),
    );
    fm.insert("service_url".into(), serde_json::Value::String(service_url));
    if let Some(uc) = use_case {
        fm.insert("use_case".into(), serde_json::Value::String(uc.to_string()));
    }
    if let Some(tpl) = sandbox_service_url_template {
        fm.insert(
            "sandbox_service_url".into(),
            serde_json::Value::String(tpl.replace("{name}", name)),
        );
    }
    if !version.is_empty() {
        fm.insert("version".into(), serde_json::Value::String(version.into()));
    }
    fm.insert(
        "endpoints".into(),
        serde_json::Value::Array(translated_endpoints),
    );

    let yaml = serde_yml::to_string(&serde_json::Value::Object(fm)).unwrap_or_default();

    format!("---\n{yaml}---\n")
}

/// Recursively strip `splits` keys from a JSON value (metering dimensions/tiers).
fn strip_splits(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let cleaned: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .filter(|(k, _)| k.as_str() != "splits")
                .map(|(k, v)| (k.clone(), strip_splits(v)))
                .collect();
            serde_json::Value::Object(cleaned)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(strip_splits).collect())
        }
        other => other.clone(),
    }
}
