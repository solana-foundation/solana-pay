//! Per-model input/output token pricing for `pay gate inference`.
//!
//! This is a **display-only** overlay: it expresses per-model token rates
//! (USD per 1M tokens), validates them against the models a provider actually
//! serves, and surfaces them in the provider picker. It does **not** change
//! charging or settlement — the synthesized charge spec and the flat
//! `--price-usd` path are untouched. Per-token metering is a deferred
//! follow-up that needs response-side usage extraction.
//!
//! Two input forms feed the same [`PricingConfig`]:
//!
//! - a dead-simple YAML file ([`PricingConfig::from_yaml_file`]):
//!   ```yaml
//!   default: { in: 0.10, out: 0.30 }
//!   models:
//!     "gemma4": { in: 0.15, out: 0.60 }
//!     "qwen3:8b": { in: 0.50, out: 1.50 }
//!   ```
//! - an inline shorthand ([`PricingConfig::from_inline`]):
//!   `gemma4=0.15/0.60,qwen3:8b=0.5/1.5,*=0.1/0.3`
//!
//! Prices are USD per 1M tokens in both forms.

use std::collections::BTreeMap;

use serde::Deserialize;

/// USD-per-1M-token rate for one model (or the default).
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
pub struct TokenRate {
    /// USD per 1M input (prompt) tokens.
    #[serde(rename = "in")]
    pub input_per_1m: f64,
    /// USD per 1M output (completion) tokens.
    #[serde(rename = "out")]
    pub output_per_1m: f64,
}

/// Per-model token pricing, with an optional catch-all `default`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct PricingConfig {
    /// Fallback rate for any model without an explicit entry.
    #[serde(default)]
    pub default: Option<TokenRate>,
    /// Explicit per-model rates, keyed by model name (may be a base name
    /// like `gemma4` that matches a tagged `gemma4:latest`).
    #[serde(default, rename = "models")]
    pub per_model: BTreeMap<String, TokenRate>,
}

impl PricingConfig {
    /// Load a [`PricingConfig`] from the dead-simple YAML file described in
    /// the module docs.
    pub fn from_yaml_file(path: &str) -> pay_core::Result<Self> {
        let expanded = shellexpand::tilde(path).to_string();
        let contents = std::fs::read_to_string(&expanded)
            .map_err(|e| pay_core::Error::Config(format!("read paywall file {path}: {e}")))?;
        serde_yml::from_str(&contents)
            .map_err(|e| pay_core::Error::Config(format!("parse paywall file {path}: {e}")))
    }

    /// Parse the inline shorthand: comma-separated `model=in/out` items.
    /// `*=in/out` or a bare `in/out` sets the `default`. Prices are USD per
    /// 1M tokens.
    ///
    /// e.g. `gemma4=0.15/0.60,qwen3:8b=0.5/1.5,*=0.1/0.3`.
    pub fn from_inline(spec: &str) -> pay_core::Result<Self> {
        let mut config = PricingConfig::default();
        for raw in spec.split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            // A `model=in/out` item, or a bare `in/out` (→ default). Split on
            // the FIRST `=` so model names may not contain one (they don't),
            // while `qwen3:8b` keeps its `:`.
            let (key, rate_str) = match item.split_once('=') {
                Some((key, rate)) => (Some(key.trim()), rate.trim()),
                None => (None, item),
            };
            let rate = parse_rate(rate_str, item)?;
            match key {
                None | Some("*") => config.default = Some(rate),
                Some("") => {
                    return Err(pay_core::Error::Config(format!(
                        "--price: empty model name in `{item}`"
                    )));
                }
                Some(model) => {
                    config.per_model.insert(model.to_string(), rate);
                }
            }
        }
        Ok(config)
    }

    /// Resolve the rate for `model`.
    ///
    /// Precedence: an exact `per_model` key → a `per_model` key that equals
    /// the model's base name (the part before `:`, so config `qwen3` matches
    /// served `qwen3:8b`) → the `default`.
    pub fn resolve(&self, model: &str) -> Option<TokenRate> {
        self.resolve_with_variant(model).map(|(_, rate)| rate)
    }

    /// Resolve the rate plus the configured variant label that matched.
    pub fn resolve_with_variant(&self, model: &str) -> Option<(String, TokenRate)> {
        if let Some(rate) = self.per_model.get(model) {
            return Some((model.to_string(), *rate));
        }
        let base = model.split(':').next().unwrap_or(model);
        if base != model
            && let Some(rate) = self.per_model.get(base)
        {
            return Some((base.to_string(), *rate));
        }
        self.default.map(|rate| ("default".to_string(), rate))
    }

    /// Validate this config against the models a provider actually serves,
    /// mirroring [`pay_types::metering::validate_api_spec`]'s style: returns
    /// human-readable error strings, empty means ok.
    ///
    /// Matching rule for a `per_model` key: an available model matches when
    /// it equals the key exactly OR starts with `"{key}:"` (so config
    /// `gemma4` matches served `gemma4:latest`). A key that matches nothing
    /// served is an error; so are non-finite or non-positive rates.
    pub fn validate(&self, provider: &str, available_models: &[String]) -> Vec<String> {
        let mut errs = Vec::new();

        let check_rate = |rate: &TokenRate, label: &str, errs: &mut Vec<String>| {
            for (dir, v) in [("in", rate.input_per_1m), ("out", rate.output_per_1m)] {
                if !v.is_finite() || v <= 0.0 {
                    errs.push(format!(
                        "pricing: {label} {dir} rate must be a positive USD-per-1M-tokens \
                         amount, got {v}"
                    ));
                }
            }
        };

        if let Some(rate) = &self.default {
            check_rate(rate, "default", &mut errs);
        }

        for (key, rate) in &self.per_model {
            check_rate(rate, &format!("model \"{key}\""), &mut errs);
            let matched = available_models
                .iter()
                .any(|m| m == key || m.starts_with(&format!("{key}:")));
            if !matched {
                errs.push(format!(
                    "pricing: model \"{key}\" is not served by {provider} (available: {})",
                    available_models.join(", ")
                ));
            }
        }

        errs
    }
}

/// Parse an `in/out` rate pair. `item` is the full offending token, quoted
/// back to the operator on error.
fn parse_rate(rate: &str, item: &str) -> pay_core::Result<TokenRate> {
    let (input, output) = rate.split_once('/').ok_or_else(|| {
        pay_core::Error::Config(format!(
            "--price: expected `in/out` rate in `{item}` (e.g. 0.15/0.60)"
        ))
    })?;
    let input_per_1m = input
        .trim()
        .parse::<f64>()
        .map_err(|_| pay_core::Error::Config(format!("--price: invalid input rate in `{item}`")))?;
    let output_per_1m = output.trim().parse::<f64>().map_err(|_| {
        pay_core::Error::Config(format!("--price: invalid output rate in `{item}`"))
    })?;
    Ok(TokenRate {
        input_per_1m,
        output_per_1m,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(input: f64, output: f64) -> TokenRate {
        TokenRate {
            input_per_1m: input,
            output_per_1m: output,
        }
    }

    #[test]
    fn parses_the_yaml_file_shape() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("pay-inference-paywall-{}.yml", std::process::id()));
        std::fs::write(
            &path,
            "default: { in: 0.10, out: 0.30 }\n\
             models:\n\
             \x20 \"gemma4\": { in: 0.15, out: 0.60 }\n\
             \x20 \"qwen3:8b\": { in: 0.50, out: 1.50 }\n",
        )
        .unwrap();

        let config = PricingConfig::from_yaml_file(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(config.default, Some(rate(0.10, 0.30)));
        assert_eq!(config.per_model.get("gemma4"), Some(&rate(0.15, 0.60)));
        assert_eq!(config.per_model.get("qwen3:8b"), Some(&rate(0.50, 1.50)));
    }

    #[test]
    fn parses_the_inline_shorthand() {
        let config =
            PricingConfig::from_inline("gemma4=0.15/0.60,qwen3:8b=0.5/1.5,*=0.1/0.3").unwrap();
        assert_eq!(config.per_model.get("gemma4"), Some(&rate(0.15, 0.60)));
        assert_eq!(config.per_model.get("qwen3:8b"), Some(&rate(0.5, 1.5)));
        assert_eq!(config.default, Some(rate(0.1, 0.3)));
    }

    #[test]
    fn inline_default_forms_both_set_default() {
        // `*=in/out` form.
        let star = PricingConfig::from_inline("*=0.2/0.8").unwrap();
        assert_eq!(star.default, Some(rate(0.2, 0.8)));
        assert!(star.per_model.is_empty());

        // Bare `in/out` form.
        let bare = PricingConfig::from_inline("0.2/0.8").unwrap();
        assert_eq!(bare.default, Some(rate(0.2, 0.8)));
        assert!(bare.per_model.is_empty());

        // Whitespace + a trailing empty item are tolerated.
        let spaced = PricingConfig::from_inline(" gemma4 = 0.15 / 0.60 , ").unwrap();
        assert_eq!(spaced.per_model.get("gemma4"), Some(&rate(0.15, 0.60)));
    }

    #[test]
    fn inline_rejects_bad_tokens() {
        // Missing the `/` separator.
        let err = PricingConfig::from_inline("gemma4=0.15").unwrap_err();
        assert!(err.to_string().contains("gemma4=0.15"), "{err}");

        // Non-numeric rate.
        let err = PricingConfig::from_inline("gemma4=lo/hi").unwrap_err();
        assert!(err.to_string().contains("gemma4=lo/hi"), "{err}");

        // Empty model name.
        assert!(PricingConfig::from_inline("=0.1/0.2").is_err());
    }

    #[test]
    fn resolve_precedence_exact_then_base_then_default_then_none() {
        let mut config = PricingConfig {
            default: Some(rate(0.1, 0.3)),
            per_model: BTreeMap::new(),
        };
        config.per_model.insert("qwen3:8b".into(), rate(0.5, 1.5));
        config.per_model.insert("gemma4".into(), rate(0.15, 0.6));

        // Exact match wins.
        assert_eq!(config.resolve("qwen3:8b"), Some(rate(0.5, 1.5)));
        // Base-name match: served `gemma4:latest` resolves via `gemma4` key.
        assert_eq!(config.resolve("gemma4:latest"), Some(rate(0.15, 0.6)));
        // No exact/base match → default.
        assert_eq!(config.resolve("llama3.2:3b"), Some(rate(0.1, 0.3)));

        // No default → None when nothing matches.
        let no_default = PricingConfig {
            default: None,
            per_model: config.per_model.clone(),
        };
        assert_eq!(no_default.resolve("llama3.2:3b"), None);
    }

    #[test]
    fn validate_hit_miss_tagged_match_and_bad_rate() {
        let available = vec!["llama3.2:3b".to_string(), "qwen3:8b".to_string()];

        // Exact hit + tagged match: `gemma4` would miss, but `qwen3` matches
        // the tagged `qwen3:8b` served model.
        let mut config = PricingConfig::default();
        config.per_model.insert("qwen3".into(), rate(0.5, 1.5));
        assert_eq!(config.validate("ollama", &available), Vec::<String>::new());

        // Exact hit on a tagged key.
        let mut exact = PricingConfig::default();
        exact.per_model.insert("llama3.2:3b".into(), rate(0.1, 0.3));
        assert_eq!(exact.validate("ollama", &available), Vec::<String>::new());

        // Miss: not served.
        let mut miss = PricingConfig::default();
        miss.per_model.insert("gemma4".into(), rate(0.15, 0.6));
        let errs = miss.validate("ollama", &available);
        assert_eq!(errs.len(), 1);
        assert!(
            errs[0].contains(
                "model \"gemma4\" is not served by ollama (available: llama3.2:3b, qwen3:8b)"
            ),
            "{}",
            errs[0]
        );

        // Bad rate: non-positive / non-finite are rejected.
        let mut bad = PricingConfig::default();
        bad.per_model.insert("qwen3".into(), rate(0.0, 1.5));
        bad.default = Some(rate(f64::NAN, 0.3));
        let errs = bad.validate("ollama", &available);
        assert!(
            errs.iter()
                .any(|e| e.contains("model \"qwen3\" in rate must be a positive")),
            "{errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("default in rate must be a positive")),
            "{errs:?}"
        );
    }
}
