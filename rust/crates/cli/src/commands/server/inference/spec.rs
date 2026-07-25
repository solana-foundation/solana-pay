//! Synthesize an [`ApiSpec`] per discovered provider.
//!
//! Without pricing, specs have no metered endpoints, so every request is
//! `GateDecision::Passthrough`: forwarded upstream unmetered but still
//! captured by the proxy's `record_exchange` hook into PDB.
//!
//! With per-model token pricing (`--price`/`--pricing`, sandbox), the
//! registry's `paid` endpoints are emitted as **x402-upto** metered
//! endpoints: the client opens a channel with a per-request USD ceiling
//! ([`MAX_REQUEST_USD`]), the gateway serves the response, and the operator
//! settles the ACTUAL token cost after the fact from the observed token
//! usage (`input_tokens × in_rate + output_tokens × out_rate`). Each priced
//! endpoint carries per-model `variants[]` plus a top-level `dimensions`
//! fallback synthesized from the config's `default` rate. Everything not
//! listed stays passthrough.

use pay_types::metering::{
    ApiCategory, ApiSpec, BillingUnit, Endpoint, MeterDimension, MeterDirection, MeterVariant,
    Metering, MissingUsagePolicy, OperatorConfig, PriceTier, RoutingConfig, Scheme, UptoMetering,
    UsageMeter, UsageMeterSource,
};

use super::discovery::DiscoveredProvider;
use super::pricing::{PricingConfig, TokenRate};
use super::providers::PaidEndpoint;

/// Per-request USD ceiling the client authorizes when opening the x402-upto
/// channel. Settlement debits the ACTUAL measured token cost (well under this
/// for typical requests) and refunds the remainder. Tunable: raise it if a
/// single large-context request could exceed this cap (which would clamp the
/// settled amount to the ceiling).
pub const MAX_REQUEST_USD: f64 = 0.50;

/// Price is quoted per 1M tokens (`price_usd` is the charge for `scale`
/// tokens; the aggregate `Σ quantity/scale × price` is rounded once at
/// settlement).
const TOKEN_SCALE: u64 = 1_000_000;

/// Pricing input for monetized spec synthesis.
pub struct SpecPricing {
    /// Per-model input/output token rates (USD per 1M tokens).
    pub config: PricingConfig,
    /// Payout wallet — the gateway's own sandbox wallet.
    pub recipient: String,
}

/// Build the proxy spec for one discovered provider. Routed by subdomain:
/// `http://{slug}.localhost:{bind_port}/…`. With `pricing`, the provider's
/// registry `paid` endpoints become x402-upto per-token metered endpoints on
/// a localnet operator; without it (`None`), the spec is pure free
/// passthrough.
pub fn provider_spec(provider: &DiscoveredProvider, pricing: Option<&SpecPricing>) -> ApiSpec {
    let endpoints = pricing
        .map(|p| {
            provider
                .provider
                .paid_endpoints()
                .iter()
                .map(|endpoint| paid_endpoint(endpoint, &p.config))
                .collect()
        })
        .unwrap_or_default();

    let mut api = ApiSpec {
        name: provider.slug().to_string(),
        subdomain: provider.slug().to_string(),
        title: provider.title().to_string(),
        description: format!(
            "Local {} inference proxied by pay serve inference",
            provider.title()
        ),
        category: ApiCategory::AiMl,
        version: provider.version.clone().unwrap_or_else(|| "v1".into()),
        env: Default::default(),
        routing: RoutingConfig::Proxy {
            url: provider.base_url.clone(),
            path_rewrites: Vec::new(),
            auth: None,
        },
        accounting: Default::default(),
        endpoints,
        free_tier: None,
        quotas: None,
        notes: None,
        operator: pricing.map(|p| sandbox_operator(&p.recipient)),
        recipients: Default::default(),
        session: None,
    };
    // Resolve per-endpoint scheme defaults so the gate, challenge builder, and
    // verifier all read the same scheme set — same as `server start` does right
    // after loading a YAML spec. Priced endpoints already carry an explicit
    // `[x402-upto]` scheme, so this only fills unset (free) ones.
    api.apply_scheme_defaults();
    api
}

/// One x402-upto per-token metered endpoint. Carries an `upto` ceiling, one
/// `variant` per configured per-model rate, and a top-level `dimensions`
/// fallback from the config `default` (used when no variant matches).
fn paid_endpoint(paid: &PaidEndpoint, config: &PricingConfig) -> Endpoint {
    let variants: Vec<MeterVariant> = config
        .per_model
        .iter()
        .map(|(model, rate)| MeterVariant {
            param: "model".to_string(),
            value: model.clone(),
            description: None,
            dimensions: token_dimensions(rate, paid),
        })
        .collect();

    // Fallback dimensions: the config `default` rate when no variant matches.
    let dimensions = config
        .default
        .as_ref()
        .map(|rate| token_dimensions(rate, paid))
        .unwrap_or_default();

    Endpoint {
        method: paid.method.clone(),
        path: paid.path.clone(),
        description: None,
        // The resource makes each challenge's settlement memo unique
        // (`resource#nonce`) so same-price payments in one blockhash-cache
        // window don't build byte-identical transactions.
        resource: Some(paid.path.clone()),
        routing: None,
        metering: Some(Metering {
            dimensions,
            variants,
            schemes: Some(vec![Scheme::X402Upto]),
            upto: Some(UptoMetering {
                max_usd: Some(MAX_REQUEST_USD),
                // Observer-fed token counts are always available on a served
                // response; if a request somehow yields no usage, refund
                // rather than over-charge.
                missing_usage: MissingUsagePolicy::Refund,
                ..Default::default()
            }),
            ..Default::default()
        }),
        subscription: None,
    }
}

/// Input + output token dimensions for one rate. Each carries a `meter` with a
/// response-JSON pointer to the OpenAI/Anthropic usage field: this makes
/// `upto_uses_response_usage` true (so the gate builds an `UptoSettlementPlan`)
/// and serves as the JSON fallback for the buffered/axum path. At runtime the
/// streamed Pingora path supersedes it with the observer's token counts.
fn token_dimensions(rate: &TokenRate, paid: &PaidEndpoint) -> Vec<MeterDimension> {
    let profile = pay_core::server::profiles::openai_endpoint(&paid.path);
    let input_path = profile
        .and_then(|endpoint| endpoint.input_tokens)
        .unwrap_or_else(|| {
            if paid.path == "v1/messages" {
                "/usage/input_tokens"
            } else {
                "/usage/prompt_tokens"
            }
        });
    let output_path = profile
        .map(|endpoint| endpoint.output_tokens)
        .unwrap_or_else(|| {
            Some(if paid.path == "v1/messages" {
                "/usage/output_tokens"
            } else {
                "/usage/completion_tokens"
            })
        });

    let mut dimensions = vec![token_dim(
        MeterDirection::Input,
        rate.input_per_1m,
        input_path,
    )];
    if let Some(path) = output_path {
        dimensions.push(token_dim(MeterDirection::Output, rate.output_per_1m, path));
    }
    dimensions
}

fn token_dim(direction: MeterDirection, price_per_1m: f64, json_pointer: &str) -> MeterDimension {
    MeterDimension {
        direction,
        unit: BillingUnit::Tokens,
        scale: TOKEN_SCALE,
        period: None,
        tiers: vec![PriceTier {
            up_to: None,
            price_usd: price_per_1m,
            condition: None,
            notes: None,
            splits: Vec::new(),
        }],
        meter: Some(UsageMeter {
            source: UsageMeterSource::ResponseJson,
            path: Some(json_pointer.to_string()),
            header: None,
        }),
    }
}

/// Sandbox operator: explicitly `network: localnet` (which is also what the
/// `--sandbox` guard demands), paying out to the gateway's own wallet, with
/// the gateway sponsoring transaction fees. USDC is spelled out rather than
/// defaulted so a dumped spec stays self-describing.
fn sandbox_operator(recipient: &str) -> OperatorConfig {
    OperatorConfig {
        signer: None,
        recipient: Some(recipient.to_string()),
        currencies: [("usd".to_string(), vec!["USDC".to_string()])]
            .into_iter()
            .collect(),
        rpc_url: None,
        network: Some("localnet".to_string()),
        fee_payer: true,
        challenge_binding_secret: None,
        realm: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::server::inference::providers::ollama::Ollama;
    use pay_types::metering::HttpMethod;
    use std::collections::BTreeMap;

    fn discovered() -> DiscoveredProvider {
        DiscoveredProvider {
            provider: std::sync::Arc::new(Ollama),
            base_url: "http://127.0.0.1:11434".into(),
            models: vec!["llama3.2:3b".into()],
            version: Some("0.9.1".into()),
            pricing: None,
            model_pricing: Vec::new(),
        }
    }

    fn pricing() -> SpecPricing {
        let mut per_model = BTreeMap::new();
        per_model.insert(
            "gemma4".to_string(),
            TokenRate {
                input_per_1m: 0.15,
                output_per_1m: 0.60,
            },
        );
        per_model.insert(
            "qwen3:8b".to_string(),
            TokenRate {
                input_per_1m: 0.50,
                output_per_1m: 1.50,
            },
        );
        SpecPricing {
            config: PricingConfig {
                default: Some(TokenRate {
                    input_per_1m: 0.10,
                    output_per_1m: 0.30,
                }),
                per_model,
            },
            recipient: "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY".into(),
        }
    }

    #[test]
    fn synthesized_spec_is_passthrough_proxy() {
        let spec = provider_spec(&discovered(), None);

        assert_eq!(spec.name, "ollama");
        assert_eq!(spec.subdomain, "ollama");
        assert!(
            spec.endpoints.is_empty(),
            "no metered endpoints — everything must be Passthrough"
        );
        assert!(spec.operator.is_none(), "no payments without pricing");
        match &spec.routing {
            RoutingConfig::Proxy {
                url,
                path_rewrites,
                auth,
            } => {
                assert_eq!(url, "http://127.0.0.1:11434");
                assert!(path_rewrites.is_empty());
                assert!(auth.is_none());
            }
            other => panic!("expected proxy routing, got {other:?}"),
        }
    }

    #[test]
    fn priced_spec_meters_paid_endpoints_with_x402_upto_per_token() {
        let spec = provider_spec(&discovered(), Some(&pricing()));

        // Exactly the provider's `paid_endpoints` list — nothing else gets an
        // endpoint entry, so unlisted paths (e.g. /api/tags) stay passthrough.
        let paths: Vec<&str> = spec.endpoints.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "api/chat",
                "api/generate",
                "api/embed",
                "v1/responses",
                "v1/chat/completions",
                "v1/embeddings",
                "v1/completions",
                "v1/messages",
            ]
        );

        for endpoint in &spec.endpoints {
            assert!(matches!(endpoint.method, HttpMethod::Post));
            let meter = endpoint.metering.as_ref().expect("paid endpoint metered");

            // Scheme is x402-upto (mpp-charge cannot settle post-response).
            assert_eq!(meter.accepted_schemes(), [Scheme::X402Upto]);
            assert!(meter.schemes.is_some(), "scheme defaults must be resolved");

            // Upto ceiling set.
            let upto = meter.upto.as_ref().expect("x402-upto has upto block");
            assert_eq!(upto.max_usd, Some(MAX_REQUEST_USD));

            // Per-model variants (sorted by BTreeMap key: gemma4, qwen3:8b).
            let variant_values: Vec<&str> =
                meter.variants.iter().map(|v| v.value.as_str()).collect();
            assert_eq!(variant_values, ["gemma4", "qwen3:8b"]);

            for variant in &meter.variants {
                assert_eq!(variant.param, "model");
                let has_output = endpoint.path != "v1/embeddings";
                assert_eq!(variant.dimensions.len(), if has_output { 2 } else { 1 });
                let input = &variant.dimensions[0];
                assert_eq!(input.direction, MeterDirection::Input);
                assert_eq!(input.unit, BillingUnit::Tokens);
                assert_eq!(input.scale, TOKEN_SCALE);
                assert!(input.meter.is_some(), "token dim carries a usage meter");
                if has_output {
                    let output = &variant.dimensions[1];
                    assert_eq!(output.direction, MeterDirection::Output);
                    assert_eq!(output.unit, BillingUnit::Tokens);
                }
            }

            let has_output = endpoint.path != "v1/embeddings";
            // gemma4 rates: in 0.15, out 0.60 where the operation reports output.
            let gemma = meter.variants.iter().find(|v| v.value == "gemma4").unwrap();
            assert_eq!(gemma.dimensions[0].tiers[0].price_usd, 0.15);
            if has_output {
                assert_eq!(gemma.dimensions[1].tiers[0].price_usd, 0.60);
            }
            // qwen3:8b rates: in 0.50, out 1.50.
            let qwen = meter
                .variants
                .iter()
                .find(|v| v.value == "qwen3:8b")
                .unwrap();
            assert_eq!(qwen.dimensions[0].tiers[0].price_usd, 0.50);
            if has_output {
                assert_eq!(qwen.dimensions[1].tiers[0].price_usd, 1.50);
            }

            // Top-level dimensions fall back to the config default (0.10/0.30).
            assert_eq!(meter.dimensions.len(), if has_output { 2 } else { 1 });
            assert_eq!(meter.dimensions[0].tiers[0].price_usd, 0.10);
            if has_output {
                assert_eq!(meter.dimensions[1].tiers[0].price_usd, 0.30);
            }

            assert_eq!(
                endpoint.resource.as_deref(),
                Some(endpoint.path.as_str()),
                "paid endpoints must carry a resource for memo uniqueness"
            );
        }

        let meter_paths = |path: &str| {
            spec.endpoints
                .iter()
                .find(|endpoint| endpoint.path == path)
                .unwrap()
                .metering
                .as_ref()
                .unwrap()
                .dimensions
                .iter()
                .map(|dimension| {
                    dimension
                        .meter
                        .as_ref()
                        .and_then(|meter| meter.path.as_deref())
                        .unwrap()
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            meter_paths("v1/responses"),
            ["/usage/input_tokens", "/usage/output_tokens"]
        );
        assert_eq!(
            meter_paths("v1/chat/completions"),
            ["/usage/prompt_tokens", "/usage/completion_tokens"]
        );
        assert_eq!(meter_paths("v1/embeddings"), ["/usage/prompt_tokens"]);

        let operator = spec.operator.as_ref().expect("priced spec has operator");
        assert_eq!(operator.network.as_deref(), Some("localnet"));
        assert_eq!(
            operator.recipient.as_deref(),
            Some("CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY")
        );
        assert!(operator.fee_payer);

        // The full spec passes the same validation `server start` runs — no
        // precision errors (the token-bucket precision fix is in crates/types).
        assert_eq!(
            pay_types::metering::validate_api_spec(&spec),
            Vec::<String>::new()
        );
    }

    #[test]
    fn priced_spec_uses_response_usage_so_gate_builds_a_settlement_plan() {
        // The synthesized token dims must make `upto_uses_response_usage` true,
        // which is what makes the gate build an UptoSettlementPlan (rather than
        // settling a fixed amount) and lets the observer path feed it.
        let spec = provider_spec(&discovered(), Some(&pricing()));
        for endpoint in &spec.endpoints {
            let meter = endpoint.metering.as_ref().unwrap();
            assert!(
                pay_core::server::metering::upto_uses_response_usage(meter, None),
                "token dims with a meter must trigger response-usage settlement"
            );
        }
    }

    #[test]
    fn priced_spec_passes_the_sandbox_guard() {
        let spec = provider_spec(&discovered(), Some(&pricing()));
        let network = spec.operator.as_ref().and_then(|o| o.network.as_deref());
        assert_eq!(network, Some("localnet"));
    }

    #[test]
    fn synthesized_spec_survives_yaml_roundtrip() {
        for pricing in [None, Some(pricing())] {
            let spec = provider_spec(&discovered(), pricing.as_ref());
            let yaml = serde_yml::to_string(&spec).unwrap();
            let reloaded: ApiSpec = serde_yml::from_str(&yaml).unwrap();
            assert_eq!(reloaded.name, spec.name);
            assert_eq!(reloaded.endpoints.len(), spec.endpoints.len());
            assert!(matches!(reloaded.routing, RoutingConfig::Proxy { .. }));
        }
    }
}
