//! Local inference provider discovery — probes well-known ports with
//! provider-specific identify endpoints and reads model lists.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use super::pricing::PricingConfig;
use super::providers::{self, CustomProvider, InferenceProvider, PricingHint};

/// User override/extension file, merged over the built-ins by slug.
const USER_REGISTRY_PATH: &str = "~/.config/pay/inference-providers.yml";

/// Providers in probe priority order: user entries first (they override
/// built-ins by slug and win contested ports), then the built-ins.
pub type ProviderRegistry = Vec<Arc<dyn InferenceProvider>>;

/// Schema of the user registry file.
#[derive(Debug, Clone, Deserialize)]
struct UserRegistryFile {
    providers: Vec<CustomProvider>,
}

#[derive(Clone)]
pub struct DiscoveredProvider {
    pub provider: Arc<dyn InferenceProvider>,
    /// e.g. `http://127.0.0.1:11434`.
    pub base_url: String,
    pub models: Vec<String>,
    /// Server-reported version when the identify response carries one.
    pub version: Option<String>,
    /// Per-model token pricing from a rates file or `--price`.
    /// When set and it resolves the picked model, the picker shows real
    /// in/out token rates for that model instead of the provider's own
    /// (trait) hint. `None` keeps the pre-existing hosted behavior.
    pub pricing: Option<PricingConfig>,
    /// Display-only price metadata supplied by a running pay inference
    /// gateway. Used by `pay claude` when it connects to the gateway instead
    /// of the raw local provider.
    pub model_pricing: Vec<pay_pdb::types::ModelPricingSummary>,
}

impl DiscoveredProvider {
    pub fn slug(&self) -> &str {
        self.provider.slug()
    }

    pub fn title(&self) -> &str {
        self.provider.title()
    }

    pub fn color(&self) -> Option<&str> {
        self.provider.color()
    }

    /// Hosted (catalog-backed) providers probe no local ports; their
    /// `base_url` is a remote gateway that is its own payer-proxy upstream.
    pub fn hosted(&self) -> bool {
        self.provider.ports().is_empty()
    }

    pub fn pricing_hint(&self) -> Option<PricingHint> {
        self.provider.pricing_hint()
    }

    /// Price for `model`, unifying the two pricing sources at one call site:
    ///
    /// 1. When a display-only [`PricingConfig`] overlay
    ///    (rates file or `--price`) resolves the model, build a per-model
    ///    in/out [`PricingHint`] from its token rates.
    /// 2. Otherwise fall back to the provider's own (trait) hint — the
    ///    pre-existing hosted-catalog behavior, unchanged when no overlay is
    ///    set.
    ///
    /// `None` model falls back to the provider aggregate.
    pub fn pricing_hint_for_model(&self, model: Option<&str>) -> Option<PricingHint> {
        if let (Some(config), Some(model)) = (&self.pricing, model)
            && let Some((variant, rate)) = config.resolve_with_variant(model)
        {
            return Some(PricingHint {
                display: None,
                min_usd: rate.input_per_1m,
                max_usd: rate.output_per_1m,
                unit: "tokens".to_string(),
                variant: Some(variant),
                description: None,
                io: Some((rate.input_per_1m, rate.output_per_1m)),
            });
        }
        if let Some(model) = model
            && let Some(summary) = self
                .model_pricing
                .iter()
                .find(|summary| summary.model == model)
            && let Some(price) = &summary.price
        {
            return Some(PricingHint {
                display: Some(price.clone()),
                min_usd: 0.0,
                max_usd: 0.0,
                unit: "tokens".to_string(),
                variant: summary.variant.clone(),
                description: summary.description.clone(),
                io: None,
            });
        }
        self.provider.pricing_hint_for_model(model)
    }

    pub fn summary(&self, up: bool) -> pay_pdb::types::ProviderSummary {
        let model_pricing = if self.model_pricing.is_empty() {
            self.models
                .iter()
                .map(|model| {
                    let hint = self.pricing_hint_for_model(Some(model));
                    pay_pdb::types::ModelPricingSummary {
                        model: model.clone(),
                        variant: hint.as_ref().and_then(|hint| hint.variant.clone()),
                        price: hint.as_ref().map(ToString::to_string),
                        description: hint.and_then(|hint| hint.description),
                    }
                })
                .collect()
        } else {
            self.model_pricing.clone()
        };
        pay_pdb::types::ProviderSummary {
            slug: self.slug().to_string(),
            title: self.title().to_string(),
            base_url: self.base_url.clone(),
            up,
            models: self.models.clone(),
            version: self.version.clone(),
            color: self.color().map(str::to_string),
            model_pricing,
        }
    }
}

/// Load the built-in providers, merged with the user's override file when
/// present. User entries replace built-ins with the same slug and otherwise
/// append (at higher priority for contested ports).
pub fn load_registry() -> pay_core::Result<ProviderRegistry> {
    let user_path = shellexpand::tilde(USER_REGISTRY_PATH).to_string();
    let user: Vec<Arc<dyn InferenceProvider>> = match std::fs::read_to_string(&user_path) {
        Ok(contents) => {
            let file: UserRegistryFile = serde_yml::from_str(&contents)
                .map_err(|e| pay_core::Error::Config(format!("{user_path} invalid: {e}")))?;
            file.providers
                .into_iter()
                .map(|p| Arc::new(p) as Arc<dyn InferenceProvider>)
                .collect()
        }
        Err(_) => Vec::new(),
    };

    Ok(merge_registries(providers::builtin_providers(), user))
}

fn merge_registries(builtin: ProviderRegistry, user: ProviderRegistry) -> ProviderRegistry {
    let user_slugs: Vec<String> = user.iter().map(|p| p.slug().to_string()).collect();
    let mut merged = user;
    merged.extend(
        builtin
            .into_iter()
            .filter(|p| !user_slugs.iter().any(|slug| slug == p.slug())),
    );
    merged
}

/// Hard cap on one provider's whole probe pass (all ports + model list) so a
/// slow-to-accept server can't stall discovery.
const PROVIDER_PROBE_BUDGET: Duration = Duration::from_secs(1);

/// Progress events emitted by [`discover_with`] as each provider is probed.
pub enum ProbeEvent<'a> {
    Started(&'a dyn InferenceProvider),
    Found(&'a DiscoveredProvider),
    Missed(&'a dyn InferenceProvider),
}

/// Probe registry providers in order and return those that identified
/// positively. A port is claimed by the first provider that identifies on
/// it, so contested ports (8080) resolve deterministically by registry
/// order. Each provider gets at most [`PROVIDER_PROBE_BUDGET`].
pub async fn discover(
    registry: &ProviderRegistry,
    timeout: Duration,
    restrict: Option<&[String]>,
) -> Vec<DiscoveredProvider> {
    discover_with(registry, timeout, restrict, |_| {}).await
}

/// [`discover`] with a per-provider progress callback (drives the startup
/// spinner).
pub async fn discover_with(
    registry: &ProviderRegistry,
    timeout: Duration,
    restrict: Option<&[String]>,
    mut on_event: impl FnMut(ProbeEvent<'_>),
) -> Vec<DiscoveredProvider> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .expect("reqwest client");

    let mut claimed_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut discovered = Vec::new();

    for provider in registry {
        if let Some(allowed) = restrict
            && !allowed.iter().any(|s| s == provider.slug())
        {
            continue;
        }
        on_event(ProbeEvent::Started(provider.as_ref()));

        let found = tokio::time::timeout(
            PROVIDER_PROBE_BUDGET,
            probe_provider(&client, provider, &claimed_ports),
        )
        .await
        .ok()
        .flatten();

        match found {
            Some((found, port)) => {
                claimed_ports.insert(port);
                on_event(ProbeEvent::Found(&found));
                discovered.push(found);
            }
            None => on_event(ProbeEvent::Missed(provider.as_ref())),
        }
    }

    discovered
}

/// Try each of the provider's ports (skipping ones already claimed by an
/// earlier provider); first identify hit wins.
async fn probe_provider(
    client: &reqwest::Client,
    provider: &Arc<dyn InferenceProvider>,
    claimed_ports: &std::collections::HashSet<u16>,
) -> Option<(DiscoveredProvider, u16)> {
    for port in provider.ports() {
        if claimed_ports.contains(port) {
            continue;
        }
        let base_url = format!("http://127.0.0.1:{port}");
        if let Some(version) = provider.identify(client, &base_url).await {
            let models = provider.list_models(client, &base_url).await;
            return Some((
                DiscoveredProvider {
                    provider: provider.clone(),
                    base_url,
                    models,
                    version,
                    pricing: None,
                    model_pricing: Vec::new(),
                },
                *port,
            ));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::providers::test_support::stub;
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Delegating wrapper that overrides a built-in's ports so tests can
    /// point providers at ephemeral stub servers.
    struct WithPorts {
        inner: Arc<dyn InferenceProvider>,
        ports: Vec<u16>,
    }

    #[async_trait::async_trait]
    impl InferenceProvider for WithPorts {
        fn slug(&self) -> &str {
            self.inner.slug()
        }
        fn title(&self) -> &str {
            self.inner.title()
        }
        fn ports(&self) -> &[u16] {
            &self.ports
        }
        fn color(&self) -> Option<&str> {
            self.inner.color()
        }
        async fn identify(
            &self,
            client: &reqwest::Client,
            base_url: &str,
        ) -> Option<Option<String>> {
            self.inner.identify(client, base_url).await
        }
        async fn list_models(&self, client: &reqwest::Client, base_url: &str) -> Vec<String> {
            self.inner.list_models(client, base_url).await
        }
        fn paid_endpoints(&self) -> Vec<providers::PaidEndpoint> {
            self.inner.paid_endpoints()
        }
        fn endpoint_kind(&self, path: &str) -> &'static str {
            self.inner.endpoint_kind(path)
        }
    }

    /// All built-ins, each with its ports replaced by the matching entries
    /// in `ports` (empty — never probed successfully — when unlisted).
    fn registry_with_ports(ports: &[(&str, u16)]) -> ProviderRegistry {
        providers::builtin_providers()
            .into_iter()
            .map(|inner| {
                let ports = ports
                    .iter()
                    .filter(|(slug, _)| *slug == inner.slug())
                    .map(|(_, port)| *port)
                    .collect();
                Arc::new(WithPorts { inner, ports }) as Arc<dyn InferenceProvider>
            })
            .collect()
    }

    #[test]
    fn discovers_ollama_with_models_and_version() {
        rt().block_on(async {
            let port = stub(vec![
                ("/api/version", r#"{"version":"0.9.1"}"#),
                (
                    "/api/tags",
                    r#"{"models":[{"name":"llama3.2:3b"},{"name":"nomic-embed-text"}]}"#,
                ),
            ])
            .await;

            let registry = registry_with_ports(&[("ollama", port)]);
            let found = discover(&registry, Duration::from_millis(400), None).await;

            assert_eq!(found.len(), 1);
            assert_eq!(found[0].slug(), "ollama");
            assert_eq!(found[0].base_url, format!("http://127.0.0.1:{port}"));
            assert_eq!(found[0].version.as_deref(), Some("0.9.1"));
            assert_eq!(found[0].models, vec!["llama3.2:3b", "nomic-embed-text"]);
        });
    }

    #[test]
    fn generic_200_server_is_not_identified() {
        rt().block_on(async {
            // A dev server answering 200 HTML on every llama.cpp probe path.
            let port = stub(vec![
                ("/props", "<html>hello</html>"),
                ("/v1/models", "<html>hello</html>"),
            ])
            .await;

            let registry = registry_with_ports(&[("llama-cpp", port)]);
            let found = discover(&registry, Duration::from_millis(400), None).await;
            assert!(found.is_empty(), "bare 200s must not identify a provider");
        });
    }

    #[test]
    fn contested_port_resolves_by_registry_order() {
        rt().block_on(async {
            // A llama.cpp server: /props matches; exo's /v1/models probe would
            // also match (llama.cpp serves OpenAI-compat /v1/models with data).
            let port = stub(vec![
                ("/props", r#"{"default_generation_settings":{}}"#),
                ("/v1/models", r#"{"data":[{"id":"qwen2.5-7b"}]}"#),
            ])
            .await;

            // Both candidates on the same port; llama-cpp comes first in the
            // registry so it must win.
            let registry = registry_with_ports(&[("llama-cpp", port), ("exo", port)]);
            let found = discover(&registry, Duration::from_millis(400), None).await;

            assert_eq!(found.len(), 1);
            assert_eq!(found[0].slug(), "llama-cpp");
            assert_eq!(found[0].models, vec!["qwen2.5-7b"]);
        });
    }

    #[test]
    fn down_provider_is_absent() {
        rt().block_on(async {
            // Nothing listens on this port (bind + drop to reserve a dead one).
            let dead = {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                listener.local_addr().unwrap().port()
            };
            let registry = registry_with_ports(&[("ollama", dead)]);
            let found = discover(&registry, Duration::from_millis(200), None).await;
            assert!(found.is_empty());
        });
    }

    #[test]
    fn restrict_filters_providers() {
        rt().block_on(async {
            let port = stub(vec![("/api/version", r#"{"version":"0.9.1"}"#)]).await;
            let registry = registry_with_ports(&[("ollama", port)]);

            let found = discover(
                &registry,
                Duration::from_millis(400),
                Some(&["vllm".to_string()]),
            )
            .await;
            assert!(found.is_empty(), "--providers vllm must skip ollama probes");
        });
    }

    #[test]
    fn probe_events_fire_in_registry_order() {
        rt().block_on(async {
            let port = stub(vec![("/api/version", r#"{"version":"0.9.1"}"#)]).await;
            let registry = registry_with_ports(&[("ollama", port)]);

            let mut events: Vec<String> = Vec::new();
            let found = discover_with(&registry, Duration::from_millis(400), None, |event| {
                events.push(match event {
                    ProbeEvent::Started(provider) => format!("started:{}", provider.slug()),
                    ProbeEvent::Found(found) => format!("found:{}", found.slug()),
                    ProbeEvent::Missed(provider) => format!("missed:{}", provider.slug()),
                });
            })
            .await;

            assert_eq!(found.len(), 1);
            assert_eq!(
                events,
                vec![
                    "started:ollama",
                    "found:ollama",
                    "started:lm-studio",
                    "missed:lm-studio",
                    "started:llama-cpp",
                    "missed:llama-cpp",
                    "started:vllm",
                    "missed:vllm",
                    "started:exo",
                    "missed:exo",
                ]
            );
        });
    }

    #[test]
    fn pricing_overlay_resolves_to_in_out_hint_else_falls_back() {
        let config = PricingConfig::from_inline("gemma4=0.15/0.60,*=0.1/0.3").unwrap();
        let discovered = DiscoveredProvider {
            provider: Arc::new(providers::ollama::Ollama),
            base_url: "http://127.0.0.1:11434".into(),
            models: vec!["gemma4:latest".into(), "llama3.2:3b".into()],
            version: None,
            pricing: Some(config),
            model_pricing: Vec::new(),
        };

        // Overlay resolves the base-name → real per-model in/out rates.
        let gemma = discovered
            .pricing_hint_for_model(Some("gemma4:latest"))
            .unwrap();
        assert_eq!(gemma.io, Some((0.15, 0.60)));
        assert_eq!(gemma.unit, "tokens");
        assert_eq!(gemma.variant.as_deref(), Some("gemma4"));
        assert_eq!(gemma.to_string(), "input $0.15 · output $0.60 / 1M tokens");

        // A model with no explicit entry resolves via the `*` default.
        let other = discovered
            .pricing_hint_for_model(Some("llama3.2:3b"))
            .unwrap();
        assert_eq!(other.io, Some((0.1, 0.3)));
        assert_eq!(other.variant.as_deref(), Some("default"));

        // Provider summaries are what the inference TUI receives, including
        // watch refreshes after the overlay is re-applied.
        let summary = discovered.summary(true);
        let gemma_summary = summary
            .model_pricing
            .iter()
            .find(|pricing| pricing.model == "gemma4:latest")
            .unwrap();
        assert_eq!(
            gemma_summary.price.as_deref(),
            Some("input $0.15 · output $0.60 / 1M tokens")
        );
        assert_eq!(gemma_summary.variant.as_deref(), Some("gemma4"));

        // No overlay → the provider's own (trait) hint. Local Ollama has
        // none, so no chip — the pre-existing behavior is preserved.
        let no_overlay = DiscoveredProvider {
            pricing: None,
            ..discovered.clone()
        };
        assert_eq!(
            no_overlay.pricing_hint_for_model(Some("gemma4:latest")),
            None
        );
    }

    #[test]
    fn user_registry_overrides_by_slug_and_appends() {
        let user_file: UserRegistryFile = serde_yml::from_str(
            r#"
providers:
  - slug: ollama
    title: Ollama (custom port)
    ports: [11500]
    identify:
      - { path: /api/version, expect_json_key: version }
  - slug: jan
    title: Jan
    ports: [1337]
    identify:
      - { path: /v1/models, expect_json_key: data }
"#,
        )
        .unwrap();
        let user: ProviderRegistry = user_file
            .providers
            .into_iter()
            .map(|p| Arc::new(p) as Arc<dyn InferenceProvider>)
            .collect();

        let merged = merge_registries(providers::builtin_providers(), user);
        let ollama = merged.iter().find(|p| p.slug() == "ollama").unwrap();
        assert_eq!(ollama.ports(), [11500]);
        assert_eq!(ollama.title(), "Ollama (custom port)");
        assert!(merged.iter().any(|p| p.slug() == "jan"));
        // No duplicate ollama entry from the built-ins.
        assert_eq!(merged.iter().filter(|p| p.slug() == "ollama").count(), 1);
        // User entries come first: they take probe priority on contested
        // ports; the remaining built-ins keep their relative order.
        let slugs: Vec<&str> = merged.iter().map(|p| p.slug()).collect();
        assert_eq!(
            slugs,
            vec!["ollama", "jan", "lm-studio", "llama-cpp", "vllm", "exo"]
        );
    }
}
