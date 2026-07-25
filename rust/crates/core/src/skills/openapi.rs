//! Resolve a [`OpenapiSource`] into a list of [`EndpointSpec`] entries.
//!
//! Provider specs can declare their endpoints in one of two mutually-exclusive
//! ways: an inline `endpoints:` list, or an `openapi:` source pointing to (or
//! inlining) an OpenAPI 3 document. When the latter is set the prober walks
//! `paths × methods` to synthesize the candidate endpoint list, which the
//! probe pipeline then hits to determine which are stablecoin-gated.
//!
//! Body generation: for POST/PUT/PATCH operations we also extract (or
//! synthesize) a request body so the probe doesn't get rejected with a 400
//! before reaching the paywall. Priority order:
//!   1. `requestBody.content."application/json".example`
//!   2. `requestBody.content."application/json".examples.<first>.value`
//!   3. `requestBody.content."application/json".schema.example`
//!   4. `requestBody.content."application/json".schema.examples[0]` (3.1)
//!   5. schema-derived dummy values (required fields only, `$ref`-resolved,
//!      format-aware: `email`, `uri`, `date-time`, `uuid`).

use std::time::Duration;

use pay_types::registry::{EndpointSpec, OpenapiSource, ProviderFrontmatter};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::blocking::Client;
use serde_json::{Map, Value, json};
use tracing::debug;

use crate::{Error, Result};

const HTTP_METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];
const FETCH_TIMEOUT_SECS: u64 = 15;
const MAX_SCHEMA_DEPTH: u32 = 6;
const MAX_COMMITTED_OPENAPI_BYTES: u64 = 1_048_576;

/// One endpoint resolved from an OpenAPI document — both the spec entry that
/// gets published to the index and the optional probe body extracted from
/// `requestBody`.
#[derive(Debug, Clone)]
pub struct ResolvedEndpoint {
    pub spec: EndpointSpec,
    /// Serialized JSON body. `None` for GET/DELETE or when the OpenAPI doc
    /// does not declare a request body for the operation.
    pub body_example: Option<String>,
    /// Concrete example path assembled from `in: path` parameter examples.
    /// Used for probing only; the published `spec.path` remains templated.
    pub path_example: Option<String>,
    /// Example query string (without a leading `?`) assembled from the
    /// operation's `in: query` parameters that carry an example value, e.g.
    /// `country_code=us&brand_name=Amazon.com`. Appended to the probe URL only
    /// — `spec.path` stays clean for publishing. `None` when the operation
    /// declares no example-bearing query parameters. Without this, any GET that
    /// requires a query string is probed bare, 4xx/5xx's before reaching the
    /// paywall, and gets pruned from the published catalog.
    pub query_example: Option<String>,
}

/// Fetch / read the document referenced by `source` and synthesize an
/// endpoint list from it.
///
/// `service_url` is used to resolve [`OpenapiSource::Path`] (treated as a path
/// relative to the provider's `service_url`).
pub fn resolve_endpoints(
    source: &OpenapiSource,
    service_url: &str,
) -> Result<Vec<ResolvedEndpoint>> {
    let body = load_document(source, service_url, None)?;
    parse_endpoints(&body)
}

/// Pure parser — no I/O. Synthesize endpoint specs from an OpenAPI JSON body.
///
/// Dispatches on the document's shape:
/// - **OpenAPI 3 / Swagger 2** (`openapi:` or `swagger:` key): walk
///   `paths.{path}.{method}`.
/// - **Google Discovery** (`kind: discovery#restDescription`): walk
///   `resources.*.methods.*` recursively (and any top-level `methods`).
///
/// Description is taken from the operation's `summary` first, then
/// `description`, falling back to `"<METHOD> <path>"`.
pub fn parse_endpoints(body: &str) -> Result<Vec<ResolvedEndpoint>> {
    let doc: Value = serde_json::from_str(body)
        .map_err(|e| Error::Mpp(format!("OpenAPI document is not valid JSON: {e}")))?;

    let mut endpoints = if doc.get("openapi").is_some() || doc.get("swagger").is_some() {
        parse_openapi3_endpoints(&doc)?
    } else if doc
        .get("kind")
        .and_then(|v| v.as_str())
        .is_some_and(|k| k.starts_with("discovery#"))
    {
        parse_discovery_endpoints(&doc)?
    } else if doc.get("paths").is_some() {
        // Best-effort fallback for OpenAPI-shaped docs missing the marker.
        parse_openapi3_endpoints(&doc)?
    } else if doc.get("resources").is_some() || doc.get("methods").is_some() {
        // Discovery-shaped doc that didn't ship the `kind` marker.
        parse_discovery_endpoints(&doc)?
    } else {
        return Err(Error::Mpp(
            "OpenAPI document has no `paths` (OpenAPI 3) or `resources`/`methods` (Discovery) entries".into(),
        ));
    };

    endpoints.sort_by(|a, b| {
        a.spec
            .path
            .cmp(&b.spec.path)
            .then_with(|| a.spec.method.cmp(&b.spec.method))
    });
    Ok(endpoints)
}

fn parse_openapi3_endpoints(doc: &Value) -> Result<Vec<ResolvedEndpoint>> {
    let paths = doc
        .get("paths")
        .and_then(|v| v.as_object())
        .ok_or_else(|| Error::Mpp("OpenAPI document has no `paths` object".to_string()))?;

    let mut endpoints = Vec::new();
    for (path, item) in paths {
        let item_obj = match item.as_object() {
            Some(obj) => obj,
            None => continue,
        };
        for &method in HTTP_METHODS {
            let Some(op) = item_obj.get(method) else {
                continue;
            };
            let description = op
                .get("summary")
                .and_then(|v| v.as_str())
                .or_else(|| op.get("description").and_then(|v| v.as_str()))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("{} {}", method.to_uppercase(), path));

            let path = normalize_path(path);
            let path_example = extract_path_example(&path, item_obj, op);

            let spec = EndpointSpec {
                method: method.to_uppercase(),
                path,
                description,
                resource: op
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                // Inline pricing declared on the operation via the
                // `x-pay-metering` extension (see [`extract_pricing_extension`]).
                // Carries per-model `variants[]` that a live probe can't
                // observe — e.g. Gemini's x402-upto endpoints advertise only a
                // spending ceiling at challenge time, not the per-model token
                // table the gateway settles against.
                pricing: extract_pricing_extension(op),
            };

            let body_example = if matches!(method, "post" | "put" | "patch") {
                extract_or_generate_body(op, doc).map(|v| v.to_string())
            } else {
                None
            };

            let query_example = extract_query_example(item_obj, op);

            endpoints.push(ResolvedEndpoint {
                spec,
                body_example,
                path_example,
                query_example,
            });
        }
    }
    Ok(endpoints)
}

/// Operation-level pricing declared via the
/// [`pay_types::metering::X_PAY_METERING_EXTENSION`] OpenAPI extension. Its
/// value is a registry [`Metering`] block
/// (`pay_types::metering::Metering`) — the same `dimensions`/`variants`
/// shape the runtime gateway settles against — so operators can publish
/// per-model pricing that a live probe can't observe (an `x402-upto`
/// challenge advertises only a ceiling, not the per-model token table).
///
/// Only accepted when it deserializes cleanly into `Metering`; a malformed
/// extension is dropped (probe-derived pricing then applies) rather than
/// publishing a broken pricing object.
fn extract_pricing_extension(op: &Value) -> Option<Value> {
    let raw = op.get(pay_types::metering::X_PAY_METERING_EXTENSION)?;
    match serde_json::from_value::<pay_types::metering::Metering>(raw.clone()) {
        Ok(_) => Some(raw.clone()),
        Err(e) => {
            tracing::debug!(error = %e, "ignoring malformed x-pay-metering extension");
            None
        }
    }
}

/// Substitute examples for every `{path}` placeholder so live probes exercise
/// a concrete URL while the published endpoint keeps its OpenAPI shape.
fn extract_path_example(path: &str, item_obj: &Map<String, Value>, op: &Value) -> Option<String> {
    let placeholders = path_placeholders(path);
    if placeholders.is_empty() {
        return None;
    }

    let mut values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let sources = [op.get("parameters"), item_obj.get("parameters")];
    for params in sources.into_iter().flatten() {
        let Some(arr) = params.as_array() else {
            continue;
        };
        for param in arr {
            if param.get("in").and_then(Value::as_str) != Some("path") {
                continue;
            }
            let Some(name) = param.get("name").and_then(Value::as_str) else {
                continue;
            };
            if values.contains_key(name) {
                continue; // operation-level parameters win
            }
            if let Some(value) = param_example_value(param) {
                values.insert(name.to_string(), value);
            }
        }
    }

    if !placeholders.iter().all(|name| values.contains_key(name)) {
        return None;
    }

    const PATH_SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let mut concrete = path.to_string();
    for name in placeholders {
        let value = values.get(&name)?;
        let encoded = utf8_percent_encode(value, PATH_SET).to_string();
        concrete = concrete.replace(&format!("{{{name}}}"), &encoded);
    }
    Some(concrete)
}

fn path_placeholders(path: &str) -> Vec<String> {
    let mut placeholders = Vec::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        let after_start = &rest[start + 1..];
        let Some(end) = after_start.find('}') else {
            break;
        };
        let name = &after_start[..end];
        if !name.is_empty() {
            placeholders.push(name.to_string());
        }
        rest = &after_start[end + 1..];
    }
    placeholders
}

/// Assemble an example query string from an operation's `in: query`
/// parameters. Parameters are merged from the path-item level and the
/// operation level (operation wins on `name` collisions, per OpenAPI), and a
/// parameter is included only when it carries a resolvable example value.
/// Returns `None` when no query parameter has an example. `$ref` parameters
/// are skipped — committed specs are expected to inline their parameters.
fn extract_query_example(item_obj: &Map<String, Value>, op: &Value) -> Option<String> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Operation-level first so it shadows path-item params of the same name.
    let sources = [op.get("parameters"), item_obj.get("parameters")];
    for params in sources.into_iter().flatten() {
        let Some(arr) = params.as_array() else {
            continue;
        };
        for param in arr {
            if param.get("in").and_then(Value::as_str) != Some("query") {
                continue;
            }
            let Some(name) = param.get("name").and_then(Value::as_str) else {
                continue;
            };
            if !seen.insert(name.to_string()) {
                continue; // already taken from a higher-precedence source
            }
            if let Some(value) = param_example_value(param) {
                pairs.push((name.to_string(), value));
            }
        }
    }

    if pairs.is_empty() {
        return None;
    }
    // Keep RFC3986 unreserved characters (`-._~`) literal so common key names
    // like `country_code` and values like `Amazon.com` aren't mangled into
    // `country%5Fcode` / `Amazon%2Ecom`; encode everything else.
    const QUERY_SET: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    let encode = |s: &str| utf8_percent_encode(s, QUERY_SET).to_string();
    Some(
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
            .collect::<Vec<_>>()
            .join("&"),
    )
}

/// Resolve a single parameter's example to a query-string value. Priority:
/// `example`, then `schema.example`, then the first `examples.<name>.value`
/// (OpenAPI object form), then `schema.examples[0]` (3.1 array form). Only
/// scalar JSON (string/number/bool) is usable in a query string.
fn param_example_value(param: &Value) -> Option<String> {
    let candidate = param
        .get("example")
        .or_else(|| param.pointer("/schema/example"))
        .or_else(|| {
            param
                .get("examples")
                .and_then(Value::as_object)
                .and_then(|m| m.values().next())
                .and_then(|first| first.get("value"))
        })
        .or_else(|| {
            param
                .pointer("/schema/examples")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
        })?;
    scalar_to_query_value(candidate)
}

/// Stringify a scalar JSON value for use in a query string. Returns `None` for
/// objects, arrays, and null — those can't be represented as a flat query param.
fn scalar_to_query_value(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Length window for the reason text shown on the OS biometric prompt.
///
/// The prompt truncates at 64 chars (`AuthIntent::authorize_payment_details`
/// in pay-keystore). Below 24 chars the line is too generic to authorize a
/// debit on — it's all an attacker needs to slip past a hurried user.
pub const SUMMARY_MIN_LEN: usize = 24;
pub const SUMMARY_MAX_LEN: usize = 63;

/// Generic placeholders that must not appear as an operation's effective
/// reason text. Compared case-insensitively. `"<METHOD> <path>"` is checked
/// separately because it depends on the operation.
const GENERIC_PLACEHOLDERS: &[&str] = &[
    "api access",
    "endpoint",
    "request",
    "call",
    "todo",
    "fixme",
    "tbd",
];

const TEMPLATE_TOKENS: &[&str] = &["{{", "<todo>", "fixme", "tbd", "xxx"];
const ACTION_VERBS: &[&str] = &[
    "run",
    "search",
    "get",
    "fetch",
    "list",
    "create",
    "submit",
    "send",
    "generate",
    "solve",
    "translate",
    "validate",
    "verify",
    "lookup",
    "look",
    "resolve",
    "score",
    "detect",
    "classify",
    "extract",
    "parse",
    "analyze",
    "check",
    "find",
    "read",
    "poll",
    "start",
    "cancel",
    "upload",
    "download",
    "convert",
    "render",
    "capture",
    "transcribe",
    "synthesize",
    "moderate",
    "enrich",
    "compare",
    "calculate",
    "estimate",
    "simulate",
    "buy",
    "renew",
    "deploy",
    "host",
    "report",
    "update",
    "delete",
    "modify",
    "remove",
    "replace",
    "add",
    "purchase",
    "register",
    "tip",
    "pay",
    "schedule",
    "post",
    "patch",
    "put",
    "merge",
    "import",
    "export",
    "monitor",
    "trace",
    "recognize",
    "annotate",
    "summarize",
    "embed",
    "complete",
    "browse",
    "scrape",
    "publish",
    "approve",
    "reject",
];
const MARKETING_WORDS: &[&str] = &["best", "fastest", "cheapest", "unlimited", "free"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogFindingSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogFinding {
    pub severity: CatalogFindingSeverity,
    pub message: String,
}

impl CatalogFinding {
    fn error(message: String) -> Self {
        Self {
            severity: CatalogFindingSeverity::Error,
            message,
        }
    }

    fn warning(message: String) -> Self {
        Self {
            severity: CatalogFindingSeverity::Warning,
            message,
        }
    }
}

/// Walk every operation in `doc` and validate the `summary` / `description`
/// text that becomes the OS payment prompt reason.
///
/// Blocking errors enforce S1-S7 from the pay-skills contributing guide.
/// Warnings enforce S8-S10: distinct summaries, action-verb starts, and no
/// marketing superlatives.
pub fn validate_operation_summaries(doc: &Value) -> Vec<String> {
    validate_operation_summary_findings(doc)
        .into_iter()
        .filter(|finding| finding.severity == CatalogFindingSeverity::Error)
        .map(|finding| finding.message)
        .collect()
}

pub fn validate_operation_summary_findings(doc: &Value) -> Vec<CatalogFinding> {
    let mut findings = Vec::new();
    let mut valid_summaries = Vec::new();
    collect_operation_summary_findings(doc, &mut findings, &mut valid_summaries);
    add_duplicate_summary_warnings(&mut findings, &valid_summaries);
    findings
}

pub fn validate_committed_openapi_document(
    source: &OpenapiSource,
    doc: &Value,
    spec_dir: Option<&std::path::Path>,
    service_url: &str,
    sandbox_service_url: Option<&str>,
) -> Vec<CatalogFinding> {
    let mut findings = Vec::new();
    match source {
        OpenapiSource::Url { url } => findings.push(CatalogFinding::error(format!(
            "openapi.url is not allowed in the public registry\n  \
             got: `{url}`\n  \
             commit the spec next to PAY.md and use `openapi: {{ path: openapi.json }}`"
        ))),
        OpenapiSource::Path { path } => {
            let Some(dir) = spec_dir else {
                findings.push(CatalogFinding::error(format!(
                    "openapi.path ({path}) requires a PAY.md directory anchor"
                )));
                return findings;
            };
            let resolved = dir.join(path);
            match std::fs::metadata(&resolved) {
                Ok(meta) if meta.len() > MAX_COMMITTED_OPENAPI_BYTES => {
                    findings.push(CatalogFinding::error(format!(
                        "openapi.path `{path}` is too large ({} bytes, max {MAX_COMMITTED_OPENAPI_BYTES})\n  \
                         trim the committed spec to the operations exposed through this gateway",
                        meta.len()
                    )));
                }
                Ok(_) => {}
                Err(e) => findings.push(CatalogFinding::error(format!(
                    "openapi.path metadata failed for {}: {e}",
                    resolved.display()
                ))),
            }
        }
        OpenapiSource::Content { content } => {
            let len = content.len() as u64;
            if len > MAX_COMMITTED_OPENAPI_BYTES {
                findings.push(CatalogFinding::error(format!(
                    "openapi.content is too large ({len} bytes, max {MAX_COMMITTED_OPENAPI_BYTES})\n  \
                     use a committed `openapi.path` sidecar and trim it to the offered operations"
                )));
            }
        }
    }

    if !is_openapi3_document(doc) && !is_discovery_document(doc) {
        findings.push(CatalogFinding::error(
            "OpenAPI document must be valid OpenAPI 3.0 or 3.1\n  \
             expected an `openapi` field starting with `3.0.` or `3.1.`, \
             or a Discovery doc with `kind: discovery#restDescription`"
                .into(),
        ));
    }

    for reference in remote_refs(doc) {
        findings.push(CatalogFinding::error(format!(
            "OpenAPI document contains remote `$ref` `{reference}`\n  \
             use same-document refs or committed relative sidecars only"
        )));
    }

    findings.extend(validate_server_urls(doc, service_url, sandbox_service_url));
    findings
}

#[derive(Debug, Clone)]
struct OperationSummary {
    label: String,
    effective: String,
}

fn collect_operation_summary_findings(
    doc: &Value,
    findings: &mut Vec<CatalogFinding>,
    valid_summaries: &mut Vec<OperationSummary>,
) {
    if let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) {
        for (path, item) in paths {
            let Some(item_obj) = item.as_object() else {
                continue;
            };
            for &method in HTTP_METHODS {
                let Some(op) = item_obj.get(method) else {
                    continue;
                };
                validate_one_operation(op, method, path, findings, valid_summaries);
            }
        }
    }
    // Discovery docs (Google APIs): walk resources.*.methods.* recursively
    // and any top-level `methods`. The effective field is `description` —
    // Discovery has no `summary`.
    if let Some(resources) = doc.get("resources").and_then(|v| v.as_object()) {
        validate_discovery_resources(resources, findings, valid_summaries);
    }
    if let Some(methods) = doc.get("methods").and_then(|v| v.as_object()) {
        validate_discovery_methods(methods, findings, valid_summaries);
    }
}

fn validate_discovery_resources(
    resources: &Map<String, Value>,
    findings: &mut Vec<CatalogFinding>,
    valid_summaries: &mut Vec<OperationSummary>,
) {
    for resource in resources.values() {
        if let Some(methods) = resource.get("methods").and_then(|v| v.as_object()) {
            validate_discovery_methods(methods, findings, valid_summaries);
        }
        if let Some(nested) = resource.get("resources").and_then(|v| v.as_object()) {
            validate_discovery_resources(nested, findings, valid_summaries);
        }
    }
}

fn validate_discovery_methods(
    methods: &Map<String, Value>,
    findings: &mut Vec<CatalogFinding>,
    valid_summaries: &mut Vec<OperationSummary>,
) {
    for (name, method) in methods {
        let http_method = method
            .get("httpMethod")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let path = method
            .get("path")
            .or_else(|| method.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or(name);
        validate_one_operation(method, http_method, path, findings, valid_summaries);
    }
}

fn validate_one_operation(
    op: &Value,
    method: &str,
    path: &str,
    findings: &mut Vec<CatalogFinding>,
    valid_summaries: &mut Vec<OperationSummary>,
) {
    let summary = op
        .get("summary")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let description = op
        .get("description")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let label = format!("{} {}", method.to_uppercase(), path);

    // S1: at least one non-empty field.
    let raw = match summary.or(description) {
        Some(s) => s,
        None => {
            findings.push(CatalogFinding::error(format!(
                "{label}: operation has no `summary` or `description`\n  \
                 add a concrete `summary` (24–63 chars) — this becomes the `reason:` line \
                 on the user's biometric payment prompt\n"
            )));
            return;
        }
    };

    // Collapse internal whitespace to count what the user will actually see.
    let effective: String = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let len = effective.chars().count();

    // S2 / S3: length window.
    if len < SUMMARY_MIN_LEN {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary too short ({len} chars, min {SUMMARY_MIN_LEN})\n  \
             got: \"{effective}\"\n  \
             write a concrete sentence, verb-first, naming the domain object — \
             this becomes the `reason:` line on the user's biometric payment prompt\n"
        )));
        return;
    }
    if len > SUMMARY_MAX_LEN {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary too long ({len} chars, max {SUMMARY_MAX_LEN})\n  \
             got: \"{effective}\"\n  \
             trim it — the OS biometric prompt truncates at 64 chars and shows `…`\n"
        )));
        return;
    }

    // S4: generic placeholders and METHOD-path echo.
    let lowered = effective.to_ascii_lowercase();
    if GENERIC_PLACEHOLDERS
        .iter()
        .any(|p| lowered == *p || lowered == format!("the {p}"))
    {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary is a generic placeholder \"{effective}\"\n  \
             write a specific verb-first sentence (e.g. `Run a BigQuery SQL query`)\n"
        )));
        return;
    }
    let method_path_echo = format!("{} {}", method.to_uppercase(), path).to_ascii_lowercase();
    if lowered == method_path_echo {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary echoes the method/path \"{effective}\"\n  \
             write a sentence about what the call does, not its URL shape\n"
        )));
        return;
    }

    // S5: template tokens.
    if let Some(token) = TEMPLATE_TOKENS.iter().find(|t| lowered.contains(*t)) {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary contains unresolved template token `{token}`\n  \
             got: \"{effective}\"\n  \
             replace the placeholder with the real text\n"
        )));
        return;
    }

    // S6: markdown link syntax.
    if effective.contains("](") {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary contains markdown link syntax `](`\n  \
             got: \"{effective}\"\n  \
             the OS payment prompt renders plain text — drop the link\n"
        )));
        return;
    }

    // S7: ASCII-printable only.
    if let Some(c) = effective.chars().find(|c| !matches!(c, '\x20'..='\x7E')) {
        findings.push(CatalogFinding::error(format!(
            "{label}: operation summary contains non-ASCII character `{c}` (U+{:04X})\n  \
             got: \"{effective}\"\n  \
             use plain ASCII — smart quotes, emoji, and zero-width chars render unpredictably\n",
            c as u32
        )));
        return;
    }

    if let Some(first) = first_token(&effective)
        && !ACTION_VERBS.contains(&first.to_ascii_lowercase().as_str())
    {
        findings.push(CatalogFinding::warning(format!(
            "{label}: operation summary should start with an action verb\n  \
             got: \"{effective}\"\n  \
             start with a concrete verb such as `Search`, `Create`, `Fetch`, or `Generate`\n"
        )));
    }

    if let Some(word) = marketing_word(&effective) {
        findings.push(CatalogFinding::warning(format!(
            "{label}: operation summary contains marketing language `{word}`\n  \
             got: \"{effective}\"\n  \
             describe the paid action plainly without superlatives or cost claims\n"
        )));
    }

    valid_summaries.push(OperationSummary { label, effective });
}

fn add_duplicate_summary_warnings(
    findings: &mut Vec<CatalogFinding>,
    summaries: &[OperationSummary],
) {
    for (idx, summary) in summaries.iter().enumerate() {
        if summaries[..idx]
            .iter()
            .any(|other| other.effective.eq_ignore_ascii_case(&summary.effective))
        {
            continue;
        }
        let duplicates: Vec<&OperationSummary> = summaries
            .iter()
            .filter(|other| other.effective.eq_ignore_ascii_case(&summary.effective))
            .collect();
        if duplicates.len() < 2 {
            continue;
        }
        let labels = duplicates
            .iter()
            .map(|op| op.label.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(CatalogFinding::warning(format!(
            "{}: operation summary is reused across multiple operations\n  \
             got: \"{}\"\n  \
             duplicate operations: {labels}\n",
            summary.label, summary.effective
        )));
    }
}

fn first_token(value: &str) -> Option<&str> {
    value
        .split(|c: char| !c.is_ascii_alphabetic())
        .find(|part| !part.is_empty())
}

fn marketing_word(value: &str) -> Option<&'static str> {
    for token in value.split(|c: char| !c.is_ascii_alphanumeric()) {
        for word in MARKETING_WORDS {
            if token.eq_ignore_ascii_case(word) {
                return Some(word);
            }
        }
    }
    None
}

fn is_openapi3_document(doc: &Value) -> bool {
    doc.get("openapi")
        .and_then(Value::as_str)
        .is_some_and(|version| version.starts_with("3.0.") || version.starts_with("3.1."))
}

/// True for a Google Discovery REST description (`kind: discovery#restDescription`).
/// These docs ship instead of OpenAPI from Google's APIs and are accepted as a
/// known spec format throughout the build pipeline.
fn is_discovery_document(doc: &Value) -> bool {
    doc.get("kind")
        .and_then(Value::as_str)
        .is_some_and(|k| k.starts_with("discovery#"))
}

fn remote_refs(doc: &Value) -> Vec<String> {
    let mut refs = Vec::new();
    collect_remote_refs(doc, &mut refs);
    refs.sort();
    refs.dedup();
    refs
}

fn collect_remote_refs(value: &Value, refs: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref"
                    && let Some(reference) = value.as_str()
                    && (reference.starts_with("http://")
                        || reference.starts_with("https://")
                        || reference.starts_with("//"))
                {
                    refs.push(reference.to_string());
                }
                collect_remote_refs(value, refs);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_remote_refs(value, refs);
            }
        }
        _ => {}
    }
}

fn validate_server_urls(
    doc: &Value,
    service_url: &str,
    sandbox_service_url: Option<&str>,
) -> Vec<CatalogFinding> {
    let Some(servers) = doc.get("servers").and_then(Value::as_array) else {
        return Vec::new();
    };
    let allowed = [Some(service_url), sandbox_service_url];
    let mut findings = Vec::new();
    for server in servers {
        let Some(url) = server.get("url").and_then(Value::as_str) else {
            continue;
        };
        if url.starts_with('/') || url.contains('{') {
            continue;
        }
        if !allowed
            .iter()
            .flatten()
            .any(|allowed| same_origin_or_base(url, allowed))
        {
            findings.push(CatalogFinding::warning(format!(
                "OpenAPI servers[] entry does not match service_url or sandbox_service_url\n  \
                 got: `{url}`\n  \
                 expected base URL under `{service_url}`"
            )));
        }
    }
    findings
}

fn same_origin_or_base(server_url: &str, expected_base: &str) -> bool {
    let server = server_url.trim_end_matches('/');
    let expected = expected_base.trim_end_matches('/');
    server == expected || server.starts_with(&format!("{expected}/"))
}

fn parse_discovery_endpoints(doc: &Value) -> Result<Vec<ResolvedEndpoint>> {
    let mut endpoints = Vec::new();
    if let Some(resources) = doc.get("resources").and_then(|v| v.as_object()) {
        walk_discovery_resources(resources, doc, None, &mut endpoints);
    }
    if let Some(methods) = doc.get("methods").and_then(|v| v.as_object()) {
        emit_discovery_methods(methods, doc, None, &mut endpoints);
    }
    Ok(endpoints)
}

fn walk_discovery_resources(
    resources: &Map<String, Value>,
    root: &Value,
    parent_resource: Option<&str>,
    endpoints: &mut Vec<ResolvedEndpoint>,
) {
    for (name, resource) in resources {
        let resource_path = match parent_resource {
            Some(p) => format!("{p}.{name}"),
            None => name.clone(),
        };
        if let Some(methods) = resource.get("methods").and_then(|v| v.as_object()) {
            emit_discovery_methods(methods, root, Some(&resource_path), endpoints);
        }
        if let Some(nested) = resource.get("resources").and_then(|v| v.as_object()) {
            walk_discovery_resources(nested, root, Some(&resource_path), endpoints);
        }
    }
}

fn emit_discovery_methods(
    methods: &Map<String, Value>,
    root: &Value,
    resource_path: Option<&str>,
    endpoints: &mut Vec<ResolvedEndpoint>,
) {
    for (_, m) in methods {
        let http_method = m
            .get("httpMethod")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_uppercase();
        let path = m
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if path.is_empty() {
            continue;
        }
        let description = m
            .get("description")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{} {}", http_method, path));

        let body_example = if matches!(http_method.as_str(), "POST" | "PUT" | "PATCH") {
            extract_or_generate_discovery_body(m, root).map(|v| v.to_string())
        } else {
            None
        };

        endpoints.push(ResolvedEndpoint {
            spec: EndpointSpec {
                method: http_method,
                path: normalize_path(&path),
                description,
                resource: resource_path.map(str::to_string),
                pricing: None,
            },
            body_example,
            path_example: None,
            // Discovery endpoints carry their query inputs in the request body
            // shape, not OpenAPI-style `in: query` parameters.
            query_example: None,
        });
    }
}

/// Discovery `request` fields look like `{"$ref": "SchemaName"}` indexing
/// into the top-level `schemas` bucket. Walk that schema with the existing
/// schema-based generator (which tolerates Discovery's `$ref` form because
/// `generate_from_schema` handles unrecognized strings as opaque names).
fn extract_or_generate_discovery_body(method: &Value, root: &Value) -> Option<Value> {
    let request = method.get("request")?;
    let ref_name = request.get("$ref").and_then(|v| v.as_str())?;
    let schema = root.get("schemas").and_then(|s| s.get(ref_name))?.clone();
    // Convert Discovery's `$ref: "Foo"` (bare name) to the JSON-Pointer form
    // `generate_from_schema` understands when it recurses for nested refs.
    let normalized = rewrite_discovery_refs(schema);
    let example = generate_from_schema(&normalized, root, 0);
    if example.is_null() {
        None
    } else {
        Some(example)
    }
}

/// Rewrite every `$ref: "Name"` (Discovery form) inside `schema` to
/// `$ref: "#/schemas/Name"` so [`resolve_ref`] finds the target via
/// `doc.pointer`.
fn rewrite_discovery_refs(mut value: Value) -> Value {
    rewrite_refs_in_place(&mut value);
    value
}

fn rewrite_refs_in_place(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(s)) = map.get_mut("$ref")
                && !s.starts_with('#')
                && !s.starts_with("http")
            {
                *s = format!("#/schemas/{s}");
            }
            for (_, v) in map.iter_mut() {
                rewrite_refs_in_place(v);
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                rewrite_refs_in_place(v);
            }
        }
        _ => {}
    }
}

/// Return the effective endpoint list for a provider spec.
///
/// If `spec.openapi` is set, fetch/parse the OpenAPI document and synthesize
/// endpoints from it. Otherwise return `spec.endpoints` as-is wrapped without
/// body examples.
///
/// Use [`effective_openapi`] when you also need the parsed OpenAPI document
/// itself (e.g. to embed it in the published index for offline consumers).
pub fn effective_endpoints(spec: &ProviderFrontmatter) -> Result<Vec<ResolvedEndpoint>> {
    Ok(effective_openapi(spec)?.endpoints)
}

/// Like [`effective_endpoints`], but resolves [`OpenapiSource::Path`] relative
/// to `spec_dir` (the directory containing the provider's `.md`/`PAY.md`
/// file). Use this in build/probe paths where the spec file's location is
/// known.
pub fn effective_endpoints_relative_to(
    spec: &ProviderFrontmatter,
    spec_dir: Option<&std::path::Path>,
) -> Result<Vec<ResolvedEndpoint>> {
    Ok(effective_openapi_relative_to(spec, spec_dir)?.endpoints)
}

/// Resolved openapi for one provider spec — both the synthesized endpoint
/// list and (when one was loaded) the parsed source document.
#[derive(Debug, Clone)]
pub struct ResolvedOpenapi {
    pub endpoints: Vec<ResolvedEndpoint>,
    /// The parsed OpenAPI / Discovery JSON. `None` when the spec uses
    /// inline `endpoints:` (no source document) — present whenever
    /// `openapi:` is set and the document fetched/parsed successfully.
    pub document: Option<Value>,
}

/// Like [`effective_endpoints`] but also returns the parsed source document
/// when one was loaded. Used by `pay skills build` to inline the full
/// OpenAPI doc in each provider's detail JSON so consumers get schemas and
/// types without a follow-up HTTP round-trip after `pay skills update`.
pub fn effective_openapi(spec: &ProviderFrontmatter) -> Result<ResolvedOpenapi> {
    effective_openapi_relative_to(spec, None)
}

/// Same as [`effective_openapi`], but `OpenapiSource::Path` values are read
/// relative to `spec_dir` (typically the directory holding the provider's
/// `PAY.md`). When `spec_dir` is `None`, behaves like [`effective_openapi`]
/// (Path is rejected because there's no anchor to resolve against).
pub fn effective_openapi_relative_to(
    spec: &ProviderFrontmatter,
    spec_dir: Option<&std::path::Path>,
) -> Result<ResolvedOpenapi> {
    match &spec.openapi {
        Some(source) => {
            let body = load_document(source, &spec.meta.service_url, spec_dir)?;
            let endpoints = parse_endpoints(&body)?;
            let document = serde_json::from_str::<Value>(&body).ok();
            Ok(ResolvedOpenapi {
                endpoints,
                document,
            })
        }
        None => Ok(ResolvedOpenapi {
            endpoints: spec
                .endpoints
                .iter()
                .cloned()
                .map(|spec| ResolvedEndpoint {
                    spec,
                    body_example: None,
                    path_example: None,
                    // Inline `endpoints:` declare a clean path; no query
                    // examples to synthesize.
                    query_example: None,
                })
                .collect(),
            document: None,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestValidationOutcome {
    Valid,
    NotInSpec,
    Invalid(RequestValidationFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestValidationFailure {
    pub method: String,
    pub path: String,
    pub problems: Vec<String>,
    pub example: Option<String>,
    pub allowed_methods: Vec<String>,
}

/// Validate a request body against a cached OpenAPI / Discovery document.
///
/// Returns [`RequestValidationOutcome::NotInSpec`] when the path cannot be
/// matched to the document; callers should treat that as "no local validation"
/// rather than as a request error.
pub fn validate_request(
    doc: &Value,
    method: &str,
    relative_path: &str,
    query_params: &[(String, String)],
    body: Option<&str>,
) -> RequestValidationOutcome {
    validate_request_with_body_validation(
        doc,
        method,
        relative_path,
        query_params,
        body,
        true,
        None,
    )
}

/// Validate a request's method, path, and query parameters while optionally
/// skipping JSON-schema validation for an opaque, non-JSON request body.
pub fn validate_request_with_body_validation(
    doc: &Value,
    method: &str,
    relative_path: &str,
    query_params: &[(String, String)],
    body: Option<&str>,
    validate_body: bool,
    opaque_content_type: Option<&str>,
) -> RequestValidationOutcome {
    let method = method.trim().to_ascii_uppercase();
    let relative_path = normalize_path(relative_path);
    if doc.get("openapi").is_some() || doc.get("swagger").is_some() || doc.get("paths").is_some() {
        return validate_openapi3_request(
            doc,
            &method,
            &relative_path,
            query_params,
            body,
            validate_body,
            opaque_content_type,
        );
    }
    if doc.get("resources").is_some() || doc.get("methods").is_some() {
        return validate_discovery_request(
            doc,
            &method,
            &relative_path,
            body,
            validate_body,
            opaque_content_type,
        );
    }
    RequestValidationOutcome::NotInSpec
}

pub fn validate_request_body(
    doc: &Value,
    method: &str,
    relative_path: &str,
    body: Option<&str>,
) -> RequestValidationOutcome {
    validate_request(doc, method, relative_path, &[], body)
}

fn validate_openapi3_request(
    doc: &Value,
    method: &str,
    relative_path: &str,
    query_params: &[(String, String)],
    body: Option<&str>,
    validate_body: bool,
    opaque_content_type: Option<&str>,
) -> RequestValidationOutcome {
    let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) else {
        return RequestValidationOutcome::NotInSpec;
    };
    // Multiple templates can match one URL — notably Google-style custom verbs
    // (`/models/{modelsId}` GET vs `/models/{modelsId}:generateContent` POST)
    // where the generic template also matches the `:verb` URL. Prefer the
    // template that declares the requested method, then the most specific
    // (most literal, non-placeholder characters), so we validate against the
    // right operation instead of the first one in iteration order.
    let method_key = method.to_ascii_lowercase();
    let Some((spec_path, item)) = paths
        .iter()
        .filter(|(path, _)| path_template_matches(&normalize_path(path), relative_path))
        .max_by_key(|(path, item)| {
            let declares_method = item
                .as_object()
                .map(|obj| obj.contains_key(&method_key))
                .unwrap_or(false);
            (declares_method, path_literal_len(&normalize_path(path)))
        })
    else {
        return RequestValidationOutcome::NotInSpec;
    };

    let Some(item_obj) = item.as_object() else {
        return RequestValidationOutcome::NotInSpec;
    };
    let allowed_methods = allowed_methods(item_obj);
    let Some(operation) = item_obj.get(&method_key) else {
        return RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: normalize_path(spec_path),
            problems: vec![format!(
                "method `{method}` is not declared for this endpoint; allowed methods: {}",
                if allowed_methods.is_empty() {
                    "(none)".to_string()
                } else {
                    allowed_methods.join(", ")
                }
            )],
            example: None,
            allowed_methods,
        });
    };

    let spec_path = normalize_path(spec_path);
    let mut query_problems =
        validate_openapi_query_parameters(doc, item_obj, operation, query_params);
    let body_outcome = if validate_body {
        validate_openapi_operation_body(doc, method, &spec_path, operation, body)
    } else {
        validate_openapi_opaque_body(doc, method, &spec_path, operation, opaque_content_type)
    };
    match body_outcome {
        RequestValidationOutcome::Valid if query_problems.is_empty() => {
            RequestValidationOutcome::Valid
        }
        RequestValidationOutcome::Valid => {
            RequestValidationOutcome::Invalid(RequestValidationFailure {
                method: method.to_string(),
                path: spec_path,
                problems: query_problems,
                example: None,
                allowed_methods: Vec::new(),
            })
        }
        RequestValidationOutcome::Invalid(mut failure) => {
            query_problems.append(&mut failure.problems);
            failure.problems = query_problems;
            RequestValidationOutcome::Invalid(failure)
        }
        RequestValidationOutcome::NotInSpec => RequestValidationOutcome::NotInSpec,
    }
}

fn validate_discovery_request(
    doc: &Value,
    method: &str,
    relative_path: &str,
    body: Option<&str>,
    validate_body: bool,
    _opaque_content_type: Option<&str>,
) -> RequestValidationOutcome {
    let mut methods = Vec::new();
    if let Some(resources) = doc.get("resources").and_then(|v| v.as_object()) {
        collect_discovery_methods(resources, &mut methods);
    }
    if let Some(top_level_methods) = doc.get("methods").and_then(|v| v.as_object()) {
        for method_doc in top_level_methods.values() {
            methods.push(method_doc);
        }
    }

    let path_matches: Vec<_> = methods
        .into_iter()
        .filter_map(|method_doc| {
            let path = method_doc.get("path").and_then(|v| v.as_str())?;
            path_template_matches(&normalize_path(path), relative_path)
                .then_some((normalize_path(path), method_doc))
        })
        .collect();
    let Some((spec_path, method_doc)) = path_matches
        .iter()
        .find(|(_, method_doc)| {
            method_doc
                .get("httpMethod")
                .and_then(|v| v.as_str())
                .unwrap_or("GET")
                .eq_ignore_ascii_case(method)
        })
        .map(|(path, method_doc)| (path.as_str(), *method_doc))
    else {
        if path_matches.is_empty() {
            return RequestValidationOutcome::NotInSpec;
        }
        let mut allowed: Vec<String> = path_matches
            .iter()
            .filter_map(|(_, method_doc)| method_doc.get("httpMethod").and_then(|v| v.as_str()))
            .map(|method| method.to_ascii_uppercase())
            .collect();
        allowed.sort();
        allowed.dedup();
        return RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: path_matches[0].0.clone(),
            problems: vec![format!(
                "method `{method}` is not declared for this endpoint; allowed methods: {}",
                allowed.join(", ")
            )],
            example: None,
            allowed_methods: allowed,
        });
    };

    if validate_body {
        validate_discovery_operation_body(doc, method, spec_path, method_doc, body)
    } else if method_doc.get("request").is_some() {
        RequestValidationOutcome::Valid
    } else {
        RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: spec_path.to_string(),
            problems: vec!["Discovery operation does not declare a request body.".to_string()],
            example: None,
            allowed_methods: Vec::new(),
        })
    }
}

fn validate_openapi_opaque_body(
    doc: &Value,
    method: &str,
    spec_path: &str,
    operation: &Value,
    content_type: Option<&str>,
) -> RequestValidationOutcome {
    let Some(request_body) = operation
        .get("requestBody")
        .and_then(|body| resolve_request_body(body, doc))
    else {
        return RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: spec_path.to_string(),
            problems: vec!["OpenAPI operation does not declare a request body.".to_string()],
            example: None,
            allowed_methods: Vec::new(),
        });
    };
    let media = content_type
        .unwrap_or("application/octet-stream")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    let accepts_media = request_body
        .get("content")
        .and_then(Value::as_object)
        .is_some_and(|content| {
            content
                .keys()
                .any(|declared| declared.eq_ignore_ascii_case(media))
        });
    if accepts_media {
        RequestValidationOutcome::Valid
    } else {
        RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: spec_path.to_string(),
            problems: vec![format!(
                "OpenAPI requestBody does not accept Content-Type `{media}`."
            )],
            example: None,
            allowed_methods: Vec::new(),
        })
    }
}

fn validate_openapi_query_parameters(
    doc: &Value,
    path_item: &Map<String, Value>,
    operation: &Value,
    query_params: &[(String, String)],
) -> Vec<String> {
    let parameters = collect_openapi_query_parameters(
        doc,
        path_item.get("parameters"),
        operation.get("parameters"),
    );
    let mut problems = Vec::new();
    for parameter in parameters {
        let name = match parameter.get("name").and_then(|v| v.as_str()) {
            Some(name) if !name.is_empty() => name,
            _ => continue,
        };
        let values = query_param_values(query_params, name);
        let required = parameter
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let schema = parameter.get("schema");
        if values.is_empty() {
            if required {
                let provided = provided_query_params(query_params);
                let suffix = if provided.is_empty() {
                    String::new()
                } else {
                    format!("; provided query parameters: {provided}")
                };
                problems.push(format!("query.{name} is required{suffix}"));
            }
            continue;
        }
        let value = query_value_for_schema(&values, schema);
        if let Some(schema) = schema {
            validate_schema_value(
                &format!("query.{name}"),
                &value,
                schema,
                doc,
                &mut problems,
                0,
            );
        }
    }
    problems
}

fn collect_openapi_query_parameters(
    doc: &Value,
    path_parameters: Option<&Value>,
    operation_parameters: Option<&Value>,
) -> Vec<Value> {
    let mut by_name = Map::new();
    for parameter in path_parameters
        .into_iter()
        .chain(operation_parameters)
        .filter_map(|parameters| parameters.as_array())
        .flatten()
        .filter_map(|parameter| resolve_parameter(parameter, doc))
    {
        if parameter.get("in").and_then(|v| v.as_str()) != Some("query") {
            continue;
        }
        if let Some(name) = parameter.get("name").and_then(|v| v.as_str()) {
            by_name.insert(name.to_string(), parameter);
        }
    }
    by_name.into_values().collect()
}

fn resolve_parameter(parameter: &Value, doc: &Value) -> Option<Value> {
    if let Some(ref_str) = parameter.get("$ref").and_then(|v| v.as_str()) {
        return resolve_ref(ref_str, doc);
    }
    Some(parameter.clone())
}

fn query_param_values<'a>(query_params: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    query_params
        .iter()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
        .collect()
}

fn provided_query_params(query_params: &[(String, String)]) -> String {
    let mut names: Vec<&str> = query_params.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    names.join(", ")
}

fn query_value_for_schema(values: &[&str], schema: Option<&Value>) -> Value {
    if schema.is_some_and(|schema| schema_type_names(schema).iter().any(|ty| ty == "array")) {
        let item_schema = schema.and_then(|schema| schema.get("items"));
        return Value::Array(
            values
                .iter()
                .map(|value| coerce_query_scalar(value, item_schema))
                .collect(),
        );
    }
    coerce_query_scalar(values.first().copied().unwrap_or_default(), schema)
}

fn coerce_query_scalar(value: &str, schema: Option<&Value>) -> Value {
    let types = schema.map(schema_type_names).unwrap_or_default();
    if types.iter().any(|ty| ty == "integer")
        && let Ok(n) = value.parse::<i64>()
    {
        return json!(n);
    }
    if types.iter().any(|ty| ty == "number")
        && let Ok(n) = value.parse::<f64>()
    {
        return json!(n);
    }
    if types.iter().any(|ty| ty == "boolean")
        && let Ok(b) = value.parse::<bool>()
    {
        return json!(b);
    }
    json!(value)
}

fn collect_discovery_methods<'a>(resources: &'a Map<String, Value>, methods: &mut Vec<&'a Value>) {
    for resource in resources.values() {
        if let Some(resource_methods) = resource.get("methods").and_then(|v| v.as_object()) {
            methods.extend(resource_methods.values());
        }
        if let Some(nested) = resource.get("resources").and_then(|v| v.as_object()) {
            collect_discovery_methods(nested, methods);
        }
    }
}

fn validate_openapi_operation_body(
    doc: &Value,
    method: &str,
    spec_path: &str,
    operation: &Value,
    body: Option<&str>,
) -> RequestValidationOutcome {
    let body = non_empty_body(body);
    let request_body = operation
        .get("requestBody")
        .and_then(|request_body| resolve_request_body(request_body, doc));

    let Some(request_body) = request_body else {
        if body.is_some() {
            return RequestValidationOutcome::Invalid(RequestValidationFailure {
                method: method.to_string(),
                path: spec_path.to_string(),
                problems: vec![
                    "OpenAPI operation does not declare a request body; remove the body or select an endpoint that accepts one".to_string(),
                ],
                example: None,
                allowed_methods: Vec::new(),
            });
        }
        return RequestValidationOutcome::Valid;
    };

    let required = request_body
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let content = request_body.get("content").and_then(|v| v.as_object());
    let Some(json_media) = content.and_then(select_json_media) else {
        let content_types = content
            .map(|content| content.keys().cloned().collect::<Vec<_>>().join(", "))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "(none declared)".to_string());
        if required || body.is_some() {
            return RequestValidationOutcome::Invalid(RequestValidationFailure {
                method: method.to_string(),
                path: spec_path.to_string(),
                problems: vec![format!(
                    "OpenAPI requestBody does not declare an application/json schema; declared content types: {content_types}"
                )],
                example: None,
                allowed_methods: Vec::new(),
            });
        }
        return RequestValidationOutcome::Valid;
    };

    let schema = json_media.get("schema");
    validate_body_against_schema(
        doc,
        method,
        spec_path,
        body,
        required,
        schema,
        extract_or_generate_body(operation, doc).map(|value| value.to_string()),
    )
}

fn validate_discovery_operation_body(
    doc: &Value,
    method: &str,
    spec_path: &str,
    operation: &Value,
    body: Option<&str>,
) -> RequestValidationOutcome {
    let body = non_empty_body(body);
    let request_ref = operation
        .get("request")
        .and_then(|request| request.get("$ref"))
        .and_then(|v| v.as_str());
    let schema = request_ref
        .and_then(|name| doc.get("schemas").and_then(|schemas| schemas.get(name)))
        .cloned()
        .map(rewrite_discovery_refs);
    let example = extract_or_generate_discovery_body(operation, doc).map(|value| value.to_string());

    if schema.is_none() && body.is_some() {
        return RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: spec_path.to_string(),
            problems: vec![
                "Discovery operation does not declare a request schema; remove the body or select an endpoint that accepts one".to_string(),
            ],
            example: None,
            allowed_methods: Vec::new(),
        });
    }

    validate_body_against_schema(
        doc,
        method,
        spec_path,
        body,
        false,
        schema.as_ref(),
        example,
    )
}

fn validate_body_against_schema(
    doc: &Value,
    method: &str,
    spec_path: &str,
    body: Option<&str>,
    request_body_required: bool,
    schema: Option<&Value>,
    example: Option<String>,
) -> RequestValidationOutcome {
    let schema_requires_body = schema.is_some_and(schema_has_required_fields);
    let Some(body) = body else {
        if request_body_required || schema_requires_body {
            return RequestValidationOutcome::Invalid(RequestValidationFailure {
                method: method.to_string(),
                path: spec_path.to_string(),
                problems: vec![required_body_message(schema)],
                example,
                allowed_methods: Vec::new(),
            });
        }
        return RequestValidationOutcome::Valid;
    };

    let Some(schema) = schema else {
        return RequestValidationOutcome::Valid;
    };
    let value = match serde_json::from_str::<Value>(body) {
        Ok(value) => value,
        Err(err) => {
            return RequestValidationOutcome::Invalid(RequestValidationFailure {
                method: method.to_string(),
                path: spec_path.to_string(),
                problems: vec![format!(
                    "body must be valid JSON for this catalog endpoint: {err}"
                )],
                example,
                allowed_methods: Vec::new(),
            });
        }
    };

    let mut problems = Vec::new();
    validate_schema_value("body", &value, schema, doc, &mut problems, 0);
    if problems.is_empty() {
        RequestValidationOutcome::Valid
    } else {
        RequestValidationOutcome::Invalid(RequestValidationFailure {
            method: method.to_string(),
            path: spec_path.to_string(),
            problems,
            example,
            allowed_methods: Vec::new(),
        })
    }
}

fn non_empty_body(body: Option<&str>) -> Option<&str> {
    body.map(str::trim).filter(|body| !body.is_empty())
}

fn resolve_request_body(request_body: &Value, doc: &Value) -> Option<Value> {
    if let Some(ref_str) = request_body.get("$ref").and_then(|v| v.as_str()) {
        return resolve_ref(ref_str, doc);
    }
    Some(request_body.clone())
}

fn select_json_media(content: &Map<String, Value>) -> Option<&Value> {
    content.get("application/json").or_else(|| {
        content
            .iter()
            .find(|(content_type, _)| {
                let content_type = content_type
                    .split(';')
                    .next()
                    .unwrap_or(content_type)
                    .trim()
                    .to_ascii_lowercase();
                content_type.ends_with("+json") || content_type.ends_with("/json")
            })
            .map(|(_, media)| media)
    })
}

fn allowed_methods(item: &Map<String, Value>) -> Vec<String> {
    let mut methods: Vec<String> = HTTP_METHODS
        .iter()
        .filter(|method| item.contains_key(**method))
        .map(|method| method.to_ascii_uppercase())
        .collect();
    methods.sort();
    methods
}

fn required_body_message(schema: Option<&Value>) -> String {
    let required = schema
        .and_then(required_fields)
        .filter(|fields| !fields.is_empty())
        .map(|fields| format!(" Required fields: {}.", fields.join(", ")))
        .unwrap_or_default();
    format!("request body is required by the catalog OpenAPI schema.{required}")
}

fn schema_has_required_fields(schema: &Value) -> bool {
    required_fields(schema).is_some_and(|fields| !fields.is_empty())
}

fn required_fields(schema: &Value) -> Option<Vec<String>> {
    schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|fields| {
            fields
                .iter()
                .filter_map(|field| field.as_str().map(str::to_string))
                .collect()
        })
}

fn validate_schema_value(
    path: &str,
    value: &Value,
    schema: &Value,
    doc: &Value,
    problems: &mut Vec<String>,
    depth: u32,
) {
    if depth > MAX_SCHEMA_DEPTH {
        return;
    }
    if value.is_null() && schema_allows_null(schema) {
        return;
    }
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(ref_str, doc) {
            validate_schema_value(path, value, &resolved, doc, problems, depth + 1);
        }
        return;
    }

    if let Some(arr) = schema.get("allOf").and_then(|v| v.as_array()) {
        for item in arr {
            validate_schema_value(path, value, item, doc, problems, depth + 1);
        }
    }
    for combinator in ["anyOf", "oneOf"] {
        if let Some(arr) = schema.get(combinator).and_then(|v| v.as_array()) {
            let matched = arr.iter().any(|item| {
                let mut nested = Vec::new();
                validate_schema_value(path, value, item, doc, &mut nested, depth + 1);
                nested.is_empty()
            });
            if !matched {
                problems.push(format!(
                    "{path} must match one of the `{combinator}` schema variants"
                ));
            }
            return;
        }
    }

    if let Some(expected) = schema.get("const")
        && expected != value
    {
        problems.push(format!("{path} must equal `{expected}`"));
    }
    if let Some(enums) = schema.get("enum").and_then(|v| v.as_array())
        && !enums.iter().any(|candidate| candidate == value)
    {
        let values = enums
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        problems.push(format!("{path} must be one of: {values}"));
    }

    let expected_types = schema_type_names(schema);
    if !expected_types.is_empty()
        && !expected_types
            .iter()
            .any(|ty| value_matches_type(value, ty))
    {
        problems.push(format!(
            "{path} must be {}, got {}",
            expected_types.join(" or "),
            value_type_name(value)
        ));
        return;
    }

    if value.is_object() || schema.get("properties").is_some() {
        validate_object(path, value, schema, doc, problems, depth);
    } else if let Some(arr) = value.as_array()
        && let Some(items) = schema.get("items")
    {
        for (idx, item) in arr.iter().enumerate() {
            validate_schema_value(
                &format!("{path}[{idx}]"),
                item,
                items,
                doc,
                problems,
                depth + 1,
            );
        }
    }
    validate_scalar_constraints(path, value, schema, problems);
}

fn validate_object(
    path: &str,
    value: &Value,
    schema: &Value,
    doc: &Value,
    problems: &mut Vec<String>,
    depth: u32,
) {
    let Some(obj) = value.as_object() else {
        return;
    };
    if let Some(required) = required_fields(schema) {
        for field in required {
            if !obj.contains_key(&field) {
                problems.push(format!("{path}.{field} is required"));
            }
        }
    }
    let props = schema.get("properties").and_then(|v| v.as_object());
    if let Some(props) = props {
        for (field, field_schema) in props {
            if let Some(field_value) = obj.get(field) {
                validate_schema_value(
                    &format!("{path}.{field}"),
                    field_value,
                    field_schema,
                    doc,
                    problems,
                    depth + 1,
                );
            }
        }
    }
    match schema.get("additionalProperties") {
        Some(Value::Bool(false)) => {
            if let Some(props) = props {
                for field in obj.keys() {
                    if !props.contains_key(field) {
                        problems.push(format!("{path}.{field} is not allowed"));
                    }
                }
            }
        }
        Some(schema @ Value::Object(_)) => {
            if let Some(props) = props {
                for (field, field_value) in obj {
                    if !props.contains_key(field) {
                        validate_schema_value(
                            &format!("{path}.{field}"),
                            field_value,
                            schema,
                            doc,
                            problems,
                            depth + 1,
                        );
                    }
                }
            }
        }
        _ => {}
    }
}

fn validate_scalar_constraints(
    path: &str,
    value: &Value,
    schema: &Value,
    problems: &mut Vec<String>,
) {
    if let Some(min_len) = schema.get("minLength").and_then(|v| v.as_u64())
        && let Some(value) = value.as_str()
        && value.chars().count() < min_len as usize
    {
        problems.push(format!("{path} must have at least {min_len} characters"));
    }
    if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64())
        && let Some(value) = value.as_f64()
        && value < min
    {
        problems.push(format!("{path} must be >= {min}"));
    }
}

fn schema_type_names(schema: &Value) -> Vec<String> {
    match schema.get("type") {
        Some(Value::String(ty)) if ty != "null" => vec![ty.clone()],
        Some(Value::Array(types)) => types
            .iter()
            .filter_map(|ty| ty.as_str())
            .filter(|ty| *ty != "null")
            .map(str::to_string)
            .collect(),
        _ if schema.get("properties").is_some() => vec!["object".to_string()],
        _ if schema.get("items").is_some() => vec!["array".to_string()],
        _ => Vec::new(),
    }
}

fn schema_allows_null(schema: &Value) -> bool {
    schema
        .get("nullable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || matches!(
            schema.get("type"),
            Some(Value::String(ty)) if ty == "null"
        )
        || schema
            .get("type")
            .and_then(|v| v.as_array())
            .is_some_and(|types| types.iter().any(|ty| ty.as_str() == Some("null")))
}

fn value_matches_type(value: &Value, ty: &str) -> bool {
    match ty {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn path_template_matches(template: &str, target: &str) -> bool {
    let template = template.trim_matches('/');
    let target = target.trim_matches('/');
    if template == target {
        return true;
    }

    let template_parts: Vec<_> = if template.is_empty() {
        Vec::new()
    } else {
        template.split('/').collect()
    };
    let target_parts: Vec<_> = if target.is_empty() {
        Vec::new()
    } else {
        target.split('/').collect()
    };
    template_parts.len() == target_parts.len()
        && template_parts
            .iter()
            .zip(target_parts.iter())
            .all(|(template, target)| path_segment_matches(template, target))
}

/// Count the literal (non-placeholder) characters in a path template — a
/// specificity score used to break ties when several templates match one URL.
/// `/models/{id}:generateContent` scores higher than `/models/{id}` because its
/// `:generateContent` literal makes it the more specific match.
fn path_literal_len(template: &str) -> usize {
    let mut count = 0usize;
    let mut in_placeholder = false;
    for ch in template.chars() {
        match ch {
            '{' => in_placeholder = true,
            '}' => in_placeholder = false,
            _ if !in_placeholder => count += 1,
            _ => {}
        }
    }
    count
}

fn path_segment_matches(template: &str, target: &str) -> bool {
    if template.starts_with('{') && template.ends_with('}') {
        return !target.is_empty();
    }
    if !template.contains('{') {
        return template == target;
    }

    segment_template_matches(template, target)
}

fn segment_template_matches(template: &str, target: &str) -> bool {
    let mut template_rest = template;
    let mut target_rest = target;

    loop {
        let Some(open) = template_rest.find('{') else {
            return target_rest == template_rest;
        };
        let literal = &template_rest[..open];
        if !target_rest.starts_with(literal) {
            return false;
        }
        target_rest = &target_rest[literal.len()..];

        let after_open = &template_rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return false;
        };
        let after_placeholder = &after_open[close + 1..];
        if after_placeholder.is_empty() {
            return !target_rest.is_empty();
        }

        let next_literal_end = after_placeholder
            .find('{')
            .unwrap_or(after_placeholder.len());
        let next_literal = &after_placeholder[..next_literal_end];
        if next_literal.is_empty() {
            template_rest = after_placeholder;
            continue;
        }

        let Some(next_literal_pos) = target_rest.find(next_literal) else {
            return false;
        };
        if next_literal_pos == 0 {
            return false;
        }
        target_rest = &target_rest[next_literal_pos..];
        template_rest = after_placeholder;
    }
}

fn load_document(
    source: &OpenapiSource,
    _service_url: &str,
    spec_dir: Option<&std::path::Path>,
) -> Result<String> {
    match source {
        OpenapiSource::Url { url } => {
            // Registry providers must use a fully-qualified https:// URL —
            // validation rejects anything else. We don't accept relative URLs
            // because the registry is consumed remotely and resolving against
            // `service_url` would be fragile/ambiguous.
            fetch(url)
        }
        OpenapiSource::Path { path } => {
            let resolved = match spec_dir {
                Some(dir) => {
                    let candidate = std::path::Path::new(path);
                    if candidate.is_absolute() {
                        candidate.to_path_buf()
                    } else {
                        dir.join(candidate)
                    }
                }
                None => {
                    return Err(Error::Mpp(format!(
                        "openapi.path ({path}) requires a spec-file anchor; \
                         no spec_dir was provided to load_document"
                    )));
                }
            };
            std::fs::read_to_string(&resolved).map_err(|e| {
                Error::Mpp(format!(
                    "openapi.path read failed for {}: {e}",
                    resolved.display()
                ))
            })
        }
        OpenapiSource::Content { content } => Ok(content.clone()),
    }
}

fn fetch(url: &str) -> Result<String> {
    debug!(%url, "Fetching OpenAPI document");
    let client = Client::builder()
        .user_agent(format!("pay-skills/{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create HTTP client: {e}")))?;

    let resp = client
        .get(url)
        .send()
        .map_err(|e| Error::Mpp(format!("OpenAPI fetch failed for {url}: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .map_err(|e| Error::Mpp(format!("OpenAPI fetch read body failed for {url}: {e}")))?;
    if !status.is_success() {
        return Err(Error::Mpp(format!(
            "OpenAPI fetch returned {status} for {url}"
        )));
    }
    Ok(body)
}

#[cfg(test)]
fn join_url(service_url: &str, path: &str) -> String {
    let base = service_url.trim_end_matches('/');
    let suffix = path.trim_start_matches('/');
    format!("{base}/{suffix}")
}

/// OpenAPI paths are absolute (`/foo/bar`); the registry stores them
/// relative to `service_url` (`foo/bar`). Trim the leading `/` to match.
fn normalize_path(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

// ── Body example extraction & schema-driven generation ──────────────────────

/// Extract a JSON request body example for an operation. Returns `None` when
/// no `application/json` requestBody is declared (and `None` when the body
/// would be a useless `null`).
fn extract_or_generate_body(op: &Value, doc: &Value) -> Option<Value> {
    let content = op.get("requestBody")?.get("content")?;
    // Pick application/json if present, else first content type.
    let json_media = content
        .get("application/json")
        .or_else(|| content.as_object().and_then(|m| m.values().next()))?;

    // 1. Operation-level example
    if let Some(ex) = json_media.get("example") {
        return Some(ex.clone());
    }
    // 2. Operation-level examples map (named) — pick the first
    if let Some(ex) = json_media
        .get("examples")
        .and_then(|v| v.as_object())
        .and_then(|m| m.values().next())
        .and_then(|v| v.get("value"))
    {
        return Some(ex.clone());
    }
    // 3-4. Schema-level example/examples
    let schema = json_media.get("schema")?;
    if let Some(ex) = schema.get("example") {
        return Some(ex.clone());
    }
    if let Some(first) = schema
        .get("examples")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
    {
        return Some(first.clone());
    }
    // 5. Generate from schema (with $ref resolution + required-only fields).
    let generated = generate_from_schema(schema, doc, 0);
    if generated.is_null() {
        None
    } else {
        Some(generated)
    }
}

/// Walk a JSON Schema object and produce a minimal example value.
///
/// - resolves `$ref` (only `#/components/schemas/...` form)
/// - fills `required` fields, omits optional ones
/// - format-aware string values (`email`, `uri`, `uuid`, `date-time`, `date`)
/// - depth-limited to avoid infinite recursion through self-referential
///   schemas (e.g. tree-like structures)
fn generate_from_schema(schema: &Value, doc: &Value, depth: u32) -> Value {
    if depth > MAX_SCHEMA_DEPTH {
        return Value::Null;
    }

    // $ref — resolve once and recurse on the target.
    if let Some(ref_str) = schema.get("$ref").and_then(|v| v.as_str()) {
        if let Some(resolved) = resolve_ref(ref_str, doc) {
            return generate_from_schema(&resolved, doc, depth + 1);
        }
        return Value::Null;
    }

    // anyOf/oneOf/allOf — pick the first variant to get *something*.
    for combinator in ["anyOf", "oneOf", "allOf"] {
        if let Some(arr) = schema.get(combinator).and_then(|v| v.as_array())
            && let Some(first) = arr.first()
        {
            return generate_from_schema(first, doc, depth + 1);
        }
    }

    // Enum first — gives the most realistic example.
    if let Some(first) = schema
        .get("enum")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        return first.clone();
    }
    // const
    if let Some(c) = schema.get("const") {
        return c.clone();
    }

    let ty = schema.get("type").and_then(|v| v.as_str());
    match ty {
        Some("string") => string_example(schema),
        Some("integer") => integer_example(schema),
        Some("number") => number_example(schema),
        Some("boolean") => json!(false),
        Some("array") => array_example(schema, doc, depth),
        Some("object") | None => object_example(schema, doc, depth),
        Some(other) => {
            debug!(unknown_type = other, "openapi schema: unknown type");
            Value::Null
        }
    }
}

fn string_example(schema: &Value) -> Value {
    let format = schema.get("format").and_then(|v| v.as_str()).unwrap_or("");
    let value = match format {
        "email" => "test@example.com",
        "uri" | "url" | "uri-reference" => "https://example.com",
        "uuid" => "00000000-0000-0000-0000-000000000000",
        "date-time" => "2026-01-01T00:00:00Z",
        "date" => "2026-01-01",
        "ipv4" => "127.0.0.1",
        "ipv6" => "::1",
        "hostname" => "example.com",
        "byte" => "dGVzdA==",
        "binary" => "test",
        _ => "test",
    };
    json!(value)
}

fn integer_example(schema: &Value) -> Value {
    if let Some(min) = schema.get("minimum").and_then(|v| v.as_i64()) {
        return json!(min);
    }
    if let Some(min) = schema.get("exclusiveMinimum").and_then(|v| v.as_i64()) {
        return json!(min + 1);
    }
    json!(1)
}

fn number_example(schema: &Value) -> Value {
    if let Some(min) = schema.get("minimum").and_then(|v| v.as_f64()) {
        return json!(min);
    }
    json!(1)
}

fn array_example(schema: &Value, doc: &Value, depth: u32) -> Value {
    let Some(items) = schema.get("items") else {
        return json!([]);
    };
    let item = generate_from_schema(items, doc, depth + 1);
    if item.is_null() {
        json!([])
    } else {
        json!([item])
    }
}

fn object_example(schema: &Value, doc: &Value, depth: u32) -> Value {
    let mut obj = Map::new();
    let required: Vec<String> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let props = schema.get("properties").and_then(|v| v.as_object());

    // 1. Required properties — must be present for validation to pass.
    if let Some(props) = props {
        for key in &required {
            if let Some(prop_schema) = props.get(key) {
                let value = generate_from_schema(prop_schema, doc, depth + 1);
                obj.insert(key.clone(), value);
            }
        }
    }

    // 2. If no required fields and no properties, return an empty object.
    if obj.is_empty() && required.is_empty() && props.is_none_or(|p| p.is_empty()) {
        return json!({});
    }

    Value::Object(obj)
}

/// Resolve a `$ref` like `"#/components/schemas/Foo"` against the root doc.
/// Returns `None` for external refs or malformed pointers.
fn resolve_ref(ref_str: &str, doc: &Value) -> Option<Value> {
    let pointer = ref_str.strip_prefix('#')?;
    doc.pointer(pointer).cloned()
}

// ─────────────────────────────────────────────────────────────────────
// Operation documentation validation
//
// Catches the documentation gaps that prevent an agent from forming a
// valid request: undeclared path placeholders, parameters or required
// body properties without enough signal (description, format, enum,
// pattern, example, title) to disambiguate the intended value.
// ─────────────────────────────────────────────────────────────────────

const MAX_DOC_WALK_DEPTH: u32 = 8;

/// Walk every operation in the document and flag parameter / body
/// documentation gaps. Errors block PR landing; warnings surface in the
/// step summary.
pub fn validate_operation_documentation(doc: &Value) -> Vec<CatalogFinding> {
    let mut findings = Vec::new();
    let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) else {
        return findings;
    };
    for (path, item) in paths {
        let Some(item_obj) = item.as_object() else {
            continue;
        };
        let path_level_params: Vec<Value> = item_obj
            .get("parameters")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for &method in HTTP_METHODS {
            let Some(op) = item_obj.get(method) else {
                continue;
            };
            validate_operation_documentation_one(
                doc,
                op,
                method,
                path,
                &path_level_params,
                &mut findings,
            );
        }
    }
    findings
}

fn validate_operation_documentation_one(
    doc: &Value,
    op: &Value,
    method: &str,
    path: &str,
    path_level_params: &[Value],
    findings: &mut Vec<CatalogFinding>,
) {
    let label = format!("{} {}", method.to_uppercase(), path);

    // Resolve all parameters (path-level + op-level, $ref-dereffed).
    let mut all_params: Vec<Value> = path_level_params.to_vec();
    if let Some(arr) = op.get("parameters").and_then(|v| v.as_array()) {
        all_params.extend(arr.iter().cloned());
    }
    let resolved_params: Vec<Value> = all_params
        .iter()
        .map(|p| {
            if let Some(r) = p.get("$ref").and_then(|v| v.as_str()) {
                resolve_ref(r, doc).unwrap_or_else(|| p.clone())
            } else {
                p.clone()
            }
        })
        .collect();

    // Path placeholders must be declared.
    let url_placeholders = extract_url_placeholders(path);
    let declared_path: std::collections::HashSet<String> = resolved_params
        .iter()
        .filter(|p| p.get("in").and_then(|v| v.as_str()) == Some("path"))
        .filter_map(|p| p.get("name").and_then(|v| v.as_str()).map(String::from))
        .collect();
    for placeholder in &url_placeholders {
        if !declared_path.contains(placeholder) {
            findings.push(CatalogFinding::error(format!(
                "{label}: path placeholder `{{{placeholder}}}` is not declared in `parameters[]`\n  \
                 add `{{ in: path, name: {placeholder}, required: true, schema: {{ type: string }}, description: \"…\" }}` to the operation or path-level parameters\n"
            )));
        }
    }

    // Each parameter needs a description (or an equivalent semantic signal).
    for p in &resolved_params {
        let Some(pname) = p.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let ploc = p.get("in").and_then(|v| v.as_str()).unwrap_or("");
        let is_required = p
            .get("required")
            .and_then(|v| v.as_bool())
            .unwrap_or(ploc == "path");
        if parameter_is_documented(doc, p) {
            continue;
        }
        let severity = if is_required {
            CatalogFindingSeverity::Error
        } else {
            CatalogFindingSeverity::Warning
        };
        findings.push(CatalogFinding {
            severity,
            message: format!(
                "{label}: parameter `{ploc}.{pname}` has no description (and no enum/format/pattern/example to disambiguate it)\n  \
                 add `description: \"…\"` to the parameter (or to its referenced schema) so agents know what value to send\n"
            ),
        });
    }

    // Request body (POST/PUT/PATCH) checks: present schema, non-empty object,
    // required props all documented.
    if !matches!(method, "post" | "put" | "patch") {
        return;
    }
    let Some(rb) = op.get("requestBody") else {
        return;
    };
    let rb = if let Some(r) = rb.get("$ref").and_then(|v| v.as_str()) {
        resolve_ref(r, doc).unwrap_or_else(|| rb.clone())
    } else {
        rb.clone()
    };
    let Some(content) = rb.get("content").and_then(|v| v.as_object()) else {
        return;
    };
    for (ct, c) in content {
        if !ct.starts_with("application/json") {
            continue;
        }
        let schema = c.get("schema").cloned().unwrap_or(Value::Null);
        let has_example = c.get("example").is_some() || c.get("examples").is_some();
        if schema.is_null() && !has_example {
            findings.push(CatalogFinding::error(format!(
                "{label}: request body `{ct}` has no `schema` or `example`\n  \
                 agents can't form the request — add a schema or at least a concrete example\n"
            )));
            continue;
        }
        let resolved_schema = deref_schema(&schema, doc);

        // Empty-object schema: tell the agent it's intentional.
        let is_object = resolved_schema.get("type").and_then(|v| v.as_str()) == Some("object");
        let has_props = resolved_schema
            .get("properties")
            .and_then(|v| v.as_object())
            .map(|o| !o.is_empty())
            .unwrap_or(false);
        let has_additional = resolved_schema.get("additionalProperties").is_some();
        let has_ref = resolved_schema.get("$ref").is_some();
        let has_combo = ["allOf", "anyOf", "oneOf"].iter().any(|k| {
            resolved_schema
                .get(*k)
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty())
        });
        if is_object && !has_props && !has_additional && !has_ref && !has_combo {
            findings.push(CatalogFinding::warning(format!(
                "{label}: request body schema is an empty `object` with no `properties`, `additionalProperties`, or `$ref`\n  \
                 if the endpoint takes no parameters, set `additionalProperties: false` and add a short `description`; \
                 otherwise list the expected properties\n"
            )));
        }

        let mut undescribed_required: Vec<String> = Vec::new();
        walk_required_props(doc, &resolved_schema, "", 0, &mut undescribed_required);
        if !undescribed_required.is_empty() {
            let shown: String = undescribed_required
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = if undescribed_required.len() > 5 {
                format!(", … +{}", undescribed_required.len() - 5)
            } else {
                String::new()
            };
            findings.push(CatalogFinding::error(format!(
                "{label}: request body `{ct}` has required fields without descriptions: [{shown}{more}]\n  \
                 each required field needs `description`, `enum`, `format`, `pattern`, `const`, `example`, or `title` so agents know what value to send\n"
            )));
        }
    }
}

fn extract_url_placeholders(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{'
            && let Some(end) = bytes[i + 1..].iter().position(|&b| b == b'}')
        {
            if let Ok(name) = std::str::from_utf8(&bytes[i + 1..i + 1 + end])
                && !name.is_empty()
            {
                out.push(name.to_string());
            }
            i += end + 2;
            continue;
        }
        i += 1;
    }
    out
}

fn deref_schema(schema: &Value, doc: &Value) -> Value {
    if let Some(r) = schema.get("$ref").and_then(|v| v.as_str())
        && let Some(target) = resolve_ref(r, doc)
    {
        return target;
    }
    schema.clone()
}

fn parameter_is_documented(doc: &Value, param: &Value) -> bool {
    if param
        .get("description")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
    {
        return true;
    }
    if param.get("example").is_some() || param.get("examples").is_some() {
        return true;
    }
    let Some(schema) = param.get("schema") else {
        return false;
    };
    schema_provides_signal(&deref_schema(schema, doc))
}

fn schema_provides_signal(schema: &Value) -> bool {
    if schema
        .get("description")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
    {
        return true;
    }
    for key in [
        "enum", "const", "format", "pattern", "example", "examples", "title",
    ] {
        if schema.get(key).is_some() {
            return true;
        }
    }
    if let Some(items) = schema.get("items")
        && schema_provides_signal(items)
    {
        return true;
    }
    false
}

fn walk_required_props(
    doc: &Value,
    schema: &Value,
    prefix: &str,
    depth: u32,
    undescribed: &mut Vec<String>,
) {
    if depth > MAX_DOC_WALK_DEPTH {
        return;
    }
    let schema = deref_schema(schema, doc);
    let required: std::collections::HashSet<String> = schema
        .get("required")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
        for (name, prop) in props {
            let dotted = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}.{name}")
            };
            let prop_resolved_once = deref_schema(prop, doc);
            // Follow a second level of `$ref` in case the first resolved
            // target is itself a `$ref` alias (`Alias → Base`). Without
            // this, walking stops at the alias node and the inner
            // `type == "object"` / `properties` check below silently
            // skips required fields one level deeper.
            let prop_resolved = deref_schema(&prop_resolved_once, doc);
            // A property entry may carry its own `description` alongside a
            // `$ref`; OpenAPI 3.1 allows it. Check the inline prop, the
            // first-resolved target, *and* the second-resolved target so
            // we don't flag a documented `$ref`'d field at any depth.
            let documented = schema_provides_signal(prop)
                || schema_provides_signal(&prop_resolved_once)
                || schema_provides_signal(&prop_resolved);
            if required.contains(name) && !documented {
                undescribed.push(dotted.clone());
            }
            let t = prop_resolved.get("type").and_then(|v| v.as_str());
            if t == Some("object") || prop_resolved.get("properties").is_some() {
                walk_required_props(doc, &prop_resolved, &dotted, depth + 1, undescribed);
            } else if t == Some("array")
                && let Some(items) = prop_resolved.get("items")
            {
                walk_required_props(doc, items, &format!("{dotted}[]"), depth + 1, undescribed);
            }
        }
    }

    for combo in ["allOf", "anyOf", "oneOf"] {
        if let Some(arr) = schema.get(combo).and_then(|v| v.as_array()) {
            for sub in arr {
                walk_required_props(doc, sub, prefix, depth + 1, undescribed);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Committed spec file formatting
//
// `pay catalog check` requires committed openapi.json sidecars to be
// pretty-printed (multi-line, indented). Reviewers need diffable specs;
// minified one-liners hide intent in PR review.
// ─────────────────────────────────────────────────────────────────────

pub fn validate_committed_spec_formatting(
    source: &OpenapiSource,
    spec_dir: Option<&std::path::Path>,
) -> Vec<CatalogFinding> {
    let mut findings = Vec::new();
    let OpenapiSource::Path { path } = source else {
        return findings;
    };
    let Some(dir) = spec_dir else {
        return findings;
    };
    let resolved = dir.join(path);
    let body = match std::fs::read_to_string(&resolved) {
        Ok(b) => b,
        Err(_) => return findings,
    };
    // Tiny single-line objects are fine — only flag anything substantial.
    if body.len() < 256 {
        return findings;
    }
    if is_pretty_printed(&body) {
        return findings;
    }
    findings.push(CatalogFinding::warning(format!(
        "openapi.path `{path}` is minified — committed specs should be pretty-printed so PR diffs are reviewable\n  \
         reformat with: `jq . {path} > {path}.tmp && mv {path}.tmp {path}` (or any `python3 -m json.tool` equivalent)\n"
    )));
    findings
}

fn is_pretty_printed(body: &str) -> bool {
    // A pretty-printed JSON document has at least one newline followed by an
    // indent (1+ space or tab) in its first 1 KiB. Indent width is irrelevant —
    // `jq .` uses 2, `python -m json.tool` uses 4, both pass.
    //
    // Back off until we land on a UTF-8 char boundary: a `description` or
    // `title` field whose multi-byte glyph (accented letter, emoji) crosses
    // the 1 KiB mark would otherwise panic on `&body[..prefix_end]`.
    let mut prefix_end = body.len().min(1024);
    while prefix_end > 0 && !body.is_char_boundary(prefix_end) {
        prefix_end -= 1;
    }
    let prefix = &body[..prefix_end];
    let mut chars = prefix.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n'
            && let Some(&next) = chars.peek()
            && (next == ' ' || next == '\t')
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_pay_metering_extension_becomes_endpoint_pricing() {
        // Mirrors the Gemini gateway: per-model token variants declared on
        // the operation as `x-pay-metering` — the runtime settlement shape a
        // live probe can't observe.
        let doc = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/v1beta/models/{modelsId}:generateContent": {
                    "post": {
                        "summary": "Generate a Gemini response from multimodal input.",
                        "x-pay-metering": {
                            "schemes": ["x402-upto"],
                            "variants": [
                                {
                                    "param": "model",
                                    "value": "gemini-2.5-flash",
                                    "description": "Fast Gemini model for low-latency generation.",
                                    "dimensions": [
                                        { "direction": "input", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 0.345 }] },
                                        { "direction": "output", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": 2.875 }] }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        });

        let endpoints = parse_endpoints(&doc.to_string()).unwrap();
        let generate = endpoints
            .iter()
            .find(|e| e.spec.path.ends_with(":generateContent"))
            .expect("generateContent endpoint");
        let pricing = generate
            .spec
            .pricing
            .as_ref()
            .expect("inline pricing present");
        let variants = pricing["variants"].as_array().unwrap();
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0]["value"], "gemini-2.5-flash");
        assert_eq!(
            variants[0]["description"],
            "Fast Gemini model for low-latency generation."
        );
        assert_eq!(variants[0]["dimensions"][1]["tiers"][0]["price_usd"], 2.875);
    }

    #[test]
    fn malformed_x_pay_metering_is_dropped_not_published() {
        let doc = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/v1/thing": {
                    "post": {
                        "summary": "Do a thing with a broken metering block.",
                        // `dimensions` must be an array of MeterDimension; a
                        // bare string can't deserialize into Metering.
                        "x-pay-metering": { "dimensions": "nope" }
                    }
                }
            }
        });

        let endpoints = parse_endpoints(&doc.to_string()).unwrap();
        let ep = endpoints
            .iter()
            .find(|e| e.spec.path == "v1/thing")
            .unwrap();
        assert!(
            ep.spec.pricing.is_none(),
            "malformed extension must not publish pricing"
        );
    }

    #[test]
    fn path_literal_len_scores_specificity() {
        // The custom-verb template has more literal characters, so it's the
        // more specific match.
        assert!(
            path_literal_len("v1beta/models/{modelsId}:generateContent")
                > path_literal_len("v1beta/models/{modelsId}")
        );
        // A bare placeholder contributes no literal characters.
        assert_eq!(path_literal_len("{modelsId}"), 0);
        assert_eq!(path_literal_len("a/{x}/b"), 4); // 'a','/','/','b'
    }

    #[test]
    fn validate_request_prefers_custom_verb_post_over_generic_get() {
        // Mirrors the Gemini gateway: a generic GET template and a custom-verb
        // POST template both match `…/{modelsId}:generateContent`.
        let doc = serde_json::json!({
            "openapi": "3.0.0",
            "paths": {
                "/v1beta/models/{modelsId}": { "get": {} },
                "/v1beta/models/{modelsId}:generateContent": { "post": {} }
            }
        });

        // POST to the custom-verb URL must validate against the POST template,
        // not be rejected by the generic GET-only one (the bug we fixed).
        let out = validate_request(
            &doc,
            "POST",
            "v1beta/models/gemini-2.5-flash-image:generateContent",
            &[],
            None,
        );
        assert_eq!(out, RequestValidationOutcome::Valid, "POST custom verb");

        // The bare model URL still validates against the GET template.
        let out = validate_request(
            &doc,
            "GET",
            "v1beta/models/gemini-2.5-flash-image",
            &[],
            None,
        );
        assert_eq!(out, RequestValidationOutcome::Valid, "GET bare model");

        // A genuinely undeclared method on the bare URL is still rejected.
        let out = validate_request(
            &doc,
            "POST",
            "v1beta/models/gemini-2.5-flash-image",
            &[],
            None,
        );
        assert!(
            matches!(out, RequestValidationOutcome::Invalid(_)),
            "POST bare model should be invalid, got {out:?}"
        );
    }

    #[test]
    fn parse_endpoints_walks_paths_and_methods() {
        let doc = r#"{
            "openapi": "3.1.0",
            "paths": {
                "/api/register": {
                    "post": {
                        "summary": "Register a new domain",
                        "tags": ["domains"]
                    }
                },
                "/api/domain/dns": {
                    "get": { "summary": "Read DNS records" },
                    "post": { "summary": "Update DNS records" }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(endpoints.len(), 3);

        let by_path: std::collections::HashMap<_, _> = endpoints
            .iter()
            .map(|e| ((e.spec.method.as_str(), e.spec.path.as_str()), e))
            .collect();
        assert_eq!(
            by_path[&("POST", "api/register")].spec.description,
            "Register a new domain"
        );
        assert_eq!(
            by_path[&("POST", "api/register")].spec.resource.as_deref(),
            Some("domains")
        );
        assert!(by_path.contains_key(&("GET", "api/domain/dns")));
        assert!(by_path.contains_key(&("POST", "api/domain/dns")));
    }

    #[test]
    fn parse_endpoints_falls_back_to_method_path_when_no_description() {
        let doc = r#"{ "paths": { "/x": { "get": {} } } }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].spec.description, "GET /x");
    }

    #[test]
    fn parse_endpoints_prefers_summary_over_description() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "get": {
                        "summary": "short summary",
                        "description": "long description"
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(endpoints[0].spec.description, "short summary");
    }

    #[test]
    fn parse_endpoints_skips_non_method_keys() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "summary": "common summary",
                    "parameters": [],
                    "get": { "summary": "g" }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].spec.method, "GET");
    }

    #[test]
    fn validate_request_body_accepts_matching_json() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/v1/search": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["query"],
                                        "properties": {
                                            "query": { "type": "string", "minLength": 1 },
                                            "limit": { "type": "integer", "minimum": 1 }
                                        },
                                        "additionalProperties": false
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        assert_eq!(
            validate_request_body(
                &doc,
                "POST",
                "v1/search",
                Some(r#"{"query":"solana","limit":1}"#)
            ),
            RequestValidationOutcome::Valid
        );
    }

    #[test]
    fn validate_request_body_reports_required_fields_and_type_errors() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/v1/search": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["query"],
                                        "properties": {
                                            "query": { "type": "string" },
                                            "limit": { "type": "integer" }
                                        },
                                        "additionalProperties": false
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let outcome = validate_request_body(
            &doc,
            "POST",
            "v1/search",
            Some(r#"{"limit":"many","extra":true}"#),
        );
        let RequestValidationOutcome::Invalid(failure) = outcome else {
            panic!("expected invalid body");
        };
        assert!(
            failure
                .problems
                .iter()
                .any(|problem| problem == "body.query is required")
        );
        assert!(
            failure
                .problems
                .iter()
                .any(|problem| problem == "body.limit must be integer, got string")
        );
        assert!(
            failure
                .problems
                .iter()
                .any(|problem| problem == "body.extra is not allowed")
        );
    }

    #[test]
    fn validate_request_body_reports_missing_body_with_example() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/v1/search": {
                    "post": {
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["query"],
                                        "properties": {
                                            "query": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let outcome = validate_request_body(&doc, "POST", "v1/search", None);
        let RequestValidationOutcome::Invalid(failure) = outcome else {
            panic!("expected invalid body");
        };
        assert_eq!(
            failure.problems,
            vec!["request body is required by the catalog OpenAPI schema. Required fields: query."]
        );
        assert_eq!(failure.example.as_deref(), Some(r#"{"query":"test"}"#));
    }

    #[test]
    fn opaque_body_validation_keeps_method_and_query_validation() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/upload": {
                    "post": {
                        "parameters": [{
                            "in": "query",
                            "name": "name",
                            "required": true,
                            "schema": { "type": "string" }
                        }],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": { "schema": { "type": "object" } }
                            }
                        }
                    }
                }
            }
        });

        assert_eq!(
            validate_request_with_body_validation(
                &doc,
                "POST",
                "/upload",
                &[("name".to_string(), "photo".to_string())],
                None,
                false,
                Some("application/json"),
            ),
            RequestValidationOutcome::Valid
        );
        assert!(matches!(
            validate_request_with_body_validation(
                &doc,
                "POST",
                "/upload",
                &[],
                None,
                false,
                Some("application/json"),
            ),
            RequestValidationOutcome::Invalid(_)
        ));
    }

    #[test]
    fn validate_request_body_rejects_wrong_method_for_known_path() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/v1/search": {
                    "post": {}
                }
            }
        });

        let outcome = validate_request_body(&doc, "GET", "v1/search", None);
        let RequestValidationOutcome::Invalid(failure) = outcome else {
            panic!("expected invalid method");
        };
        assert_eq!(failure.allowed_methods, vec!["POST"]);
        assert!(failure.problems[0].contains("method `GET` is not declared for this endpoint"));
    }

    #[test]
    fn validate_request_reports_missing_required_query_parameter() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/x402/search": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "q",
                                "required": true,
                                "schema": {
                                    "type": "string",
                                    "minLength": 1
                                }
                            },
                            {
                                "in": "query",
                                "name": "page",
                                "schema": {
                                    "type": "integer",
                                    "minimum": 1
                                }
                            }
                        ]
                    }
                }
            }
        });

        let outcome = validate_request(
            &doc,
            "GET",
            "x402/search",
            &[
                ("query".to_string(), "bottled water".to_string()),
                ("limit".to_string(), "5".to_string()),
            ],
            None,
        );
        let RequestValidationOutcome::Invalid(failure) = outcome else {
            panic!("expected invalid query");
        };
        assert_eq!(failure.path, "x402/search");
        assert!(failure.problems.iter().any(
            |problem| problem == "query.q is required; provided query parameters: limit, query"
        ));
    }

    #[test]
    fn validate_request_accepts_and_type_checks_query_parameters() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/x402/search": {
                    "get": {
                        "parameters": [
                            {
                                "in": "query",
                                "name": "q",
                                "required": true,
                                "schema": { "type": "string", "minLength": 1 }
                            },
                            {
                                "in": "query",
                                "name": "page",
                                "schema": { "type": "integer", "minimum": 1 }
                            }
                        ]
                    }
                }
            }
        });

        assert_eq!(
            validate_request(
                &doc,
                "GET",
                "x402/search",
                &[
                    ("q".to_string(), "bottled water".to_string()),
                    ("page".to_string(), "2".to_string()),
                ],
                None,
            ),
            RequestValidationOutcome::Valid
        );

        let outcome = validate_request(
            &doc,
            "GET",
            "x402/search",
            &[
                ("q".to_string(), "bottled water".to_string()),
                ("page".to_string(), "zero".to_string()),
            ],
            None,
        );
        let RequestValidationOutcome::Invalid(failure) = outcome else {
            panic!("expected invalid query type");
        };
        assert!(
            failure
                .problems
                .iter()
                .any(|problem| problem == "query.page must be integer, got string")
        );
    }

    #[test]
    fn parse_endpoints_rejects_missing_paths() {
        let doc = r#"{ "openapi": "3.1.0" }"#;
        let err = parse_endpoints(doc).unwrap_err();
        assert!(format!("{err:?}").contains("`paths`"));
    }

    #[test]
    fn parse_endpoints_rejects_invalid_json() {
        let err = parse_endpoints("{not json").unwrap_err();
        assert!(format!("{err:?}").contains("not valid JSON"));
    }

    #[test]
    fn parse_endpoints_emits_stable_ordering() {
        let doc = r#"{
            "paths": {
                "/b": { "post": {} },
                "/a": { "get": {} },
                "/a/sub": { "get": {} }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let order: Vec<_> = endpoints
            .iter()
            .map(|e| (e.spec.method.as_str(), e.spec.path.as_str()))
            .collect();
        assert_eq!(order, vec![("GET", "a"), ("GET", "a/sub"), ("POST", "b"),]);
    }

    #[test]
    fn join_url_handles_trailing_and_leading_slashes() {
        assert_eq!(
            join_url("https://api.example.com/", "/openapi.json"),
            "https://api.example.com/openapi.json"
        );
        assert_eq!(
            join_url("https://api.example.com", "openapi.json"),
            "https://api.example.com/openapi.json"
        );
    }

    #[test]
    fn load_document_returns_inline_content() {
        let content = "{\"paths\": {}}".to_string();
        let src = OpenapiSource::Content {
            content: content.clone(),
        };
        let body = load_document(&src, "https://api.example.com", None).unwrap();
        assert_eq!(body, content);
    }

    #[test]
    fn operation_summary_findings_include_warnings() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/v1/a": {
                    "post": { "summary": "Best customer enrichment report" }
                },
                "/v1/b": {
                    "post": { "summary": "Best customer enrichment report" }
                }
            }
        });

        let findings = validate_operation_summary_findings(&doc);
        assert!(
            findings
                .iter()
                .all(|finding| finding.severity == CatalogFindingSeverity::Warning),
            "expected only warnings, got: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("should start with an action verb")),
            "expected action-verb warning, got: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("marketing language `best`")),
            "expected marketing warning, got: {findings:?}"
        );
        assert!(
            findings.iter().any(|finding| finding
                .message
                .contains("reused across multiple operations")),
            "expected duplicate warning, got: {findings:?}"
        );
    }

    #[test]
    fn committed_openapi_validation_rejects_remote_refs_and_non_openapi3() {
        let doc = json!({
            "swagger": "2.0",
            "paths": {},
            "components": {
                "schemas": {
                    "External": { "$ref": "https://example.com/schema.json" }
                }
            }
        });
        let source = OpenapiSource::Content {
            content: doc.to_string(),
        };

        let findings = validate_committed_openapi_document(
            &source,
            &doc,
            None,
            "https://api.example.com",
            None,
        );

        assert!(
            findings.iter().any(|finding| {
                finding.severity == CatalogFindingSeverity::Error
                    && finding.message.contains("OpenAPI 3.0 or 3.1")
            }),
            "expected OpenAPI version error, got: {findings:?}"
        );
        assert!(
            findings.iter().any(|finding| {
                finding.severity == CatalogFindingSeverity::Error
                    && finding.message.contains("remote `$ref`")
            }),
            "expected remote ref error, got: {findings:?}"
        );
    }

    #[test]
    fn committed_openapi_validation_warns_on_server_mismatch() {
        let doc = json!({
            "openapi": "3.1.0",
            "servers": [{ "url": "https://upstream.example.com" }],
            "paths": {}
        });
        let source = OpenapiSource::Content {
            content: doc.to_string(),
        };

        let findings = validate_committed_openapi_document(
            &source,
            &doc,
            None,
            "https://api.example.com",
            None,
        );

        assert!(
            findings.iter().any(|finding| {
                finding.severity == CatalogFindingSeverity::Warning
                    && finding.message.contains("servers[] entry does not match")
            }),
            "expected servers[] mismatch warning, got: {findings:?}"
        );
    }

    // ── Operation-documentation tests ──

    #[test]
    fn operation_doc_validation_flags_undeclared_path_placeholder() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/users/{userId}": {
                    "get": {
                        "summary": "Get a user by their identifier",
                        "parameters": []
                    }
                }
            }
        });
        let findings = validate_operation_documentation(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == CatalogFindingSeverity::Error
                    && f.message.contains("{userId}")
                    && f.message.contains("not declared")),
            "expected undeclared-path-param error, got: {findings:?}"
        );
    }

    #[test]
    fn operation_doc_validation_flags_undescribed_required_param() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/lookup": {
                    "get": {
                        "summary": "Look up something by id",
                        "parameters": [
                            { "in": "query", "name": "id", "required": true,
                              "schema": { "type": "string" } }
                        ]
                    }
                }
            }
        });
        let findings = validate_operation_documentation(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == CatalogFindingSeverity::Error
                    && f.message.contains("query.id")
                    && f.message.contains("no description")),
            "expected required-param error, got: {findings:?}"
        );
    }

    #[test]
    fn operation_doc_validation_accepts_schema_signal() {
        // A required parameter without a top-level description is OK if its
        // schema carries enough signal (description / enum / format / pattern).
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/x": {
                    "get": {
                        "summary": "Read X with a typed query parameter",
                        "parameters": [
                            { "in": "query", "name": "mode", "required": true,
                              "schema": { "type": "string", "enum": ["fast","slow"] } },
                            { "in": "query", "name": "email", "required": true,
                              "schema": { "type": "string", "format": "email" } },
                            { "in": "query", "name": "uid", "required": true,
                              "schema": { "$ref": "#/components/schemas/UserId" } }
                        ]
                    }
                }
            },
            "components": {
                "schemas": {
                    "UserId": { "type": "string", "description": "Opaque user identifier." }
                }
            }
        });
        let findings = validate_operation_documentation(&doc);
        assert!(
            !findings
                .iter()
                .any(|f| f.severity == CatalogFindingSeverity::Error),
            "expected no errors, got: {findings:?}"
        );
    }

    #[test]
    fn operation_doc_validation_flags_required_body_props() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/register": {
                    "post": {
                        "summary": "Register a new account from inputs",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["domain","email"],
                                        "properties": {
                                            "domain": { "type": "string" },
                                            "email": { "type": "string", "format": "email" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let findings = validate_operation_documentation(&doc);
        let err = findings
            .iter()
            .find(|f| {
                f.severity == CatalogFindingSeverity::Error
                    && f.message.contains("required fields without descriptions")
            })
            .expect("expected required-body-prop error");
        assert!(err.message.contains("[domain]"), "got: {}", err.message);
        // email has format:email → considered documented, so should NOT appear.
        assert!(
            !err.message.contains("email"),
            "email should not be flagged: {}",
            err.message
        );
    }

    #[test]
    fn operation_doc_validation_warns_on_empty_object_body() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/trending": {
                    "post": {
                        "summary": "List trending items globally",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object", "properties": {} }
                                }
                            }
                        }
                    }
                }
            }
        });
        let findings = validate_operation_documentation(&doc);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == CatalogFindingSeverity::Warning
                    && f.message.contains("empty `object`")),
            "expected empty-object warning, got: {findings:?}"
        );
    }

    #[test]
    fn operation_doc_validation_recurses_into_nested_required_props() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/place": {
                    "post": {
                        "summary": "Create a place from coordinates",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["center"],
                                        "properties": {
                                            "center": {
                                                "type": "object",
                                                "description": "Center point.",
                                                "required": ["latitude","longitude"],
                                                "properties": {
                                                    "latitude": { "type": "number" },
                                                    "longitude": { "type": "number" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let findings = validate_operation_documentation(&doc);
        let err = findings
            .iter()
            .find(|f| {
                f.severity == CatalogFindingSeverity::Error
                    && f.message.contains("required fields without descriptions")
            })
            .expect("expected nested-required error");
        assert!(
            err.message.contains("center.latitude"),
            "got: {}",
            err.message
        );
        assert!(
            err.message.contains("center.longitude"),
            "got: {}",
            err.message
        );
    }

    // ── Pretty-print formatting tests ──

    #[test]
    fn pretty_print_detector_recognizes_pretty_and_minified() {
        let pretty = "{\n  \"openapi\": \"3.1.0\",\n  \"paths\": {}\n}";
        let minified =
            r#"{"openapi":"3.1.0","paths":{},"components":{"schemas":{"X":{"type":"string"}}}}"#;
        assert!(is_pretty_printed(pretty));
        assert!(!is_pretty_printed(minified));
    }

    #[test]
    fn pretty_print_detector_handles_multi_byte_at_1kib_boundary() {
        // A multi-byte UTF-8 glyph straddling the 1 KiB prefix end used
        // to panic on `&body[..1024]`. Pad to byte 1022 then drop a
        // 4-byte emoji so byte 1024 lands mid-codepoint, and verify
        // the detector returns without panicking.
        let mut body = String::with_capacity(1100);
        body.push_str(r#"{"openapi":"3.1.0","#);
        while body.len() < 1022 {
            body.push('x');
        }
        body.push('🦀'); // 4 bytes
        body.push_str(r#","paths":{}}"#);
        // Truncating mid-glyph would split bytes 1022..1024 off
        // the 4-byte sequence — exactly the panic the audit
        // comment flagged.
        assert!(!body.is_char_boundary(1024));
        let _ = is_pretty_printed(&body);
    }

    #[test]
    fn formatting_validation_warns_on_minified_committed_spec() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openapi.json");
        // Make sure the file is large enough to trip the "trivial size" guard.
        let mut body =
            String::from(r#"{"openapi":"3.1.0","info":{"title":"X","version":"1"},"paths":{}"#);
        body.push_str(",\"components\":{\"schemas\":{");
        for i in 0..32 {
            if i > 0 {
                body.push(',');
            }
            body.push_str(&format!(
                "\"Schema{i}\":{{\"type\":\"object\",\"properties\":{{}}}}"
            ));
        }
        body.push_str("}}}");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        drop(f);

        let source = OpenapiSource::Path {
            path: "openapi.json".to_string(),
        };
        let findings = validate_committed_spec_formatting(&source, Some(dir.path()));
        assert!(
            findings
                .iter()
                .any(|f| f.severity == CatalogFindingSeverity::Warning
                    && f.message.contains("minified")
                    && f.message.contains("jq .")),
            "expected minified warning with jq hint, got: {findings:?}"
        );
    }

    #[test]
    fn formatting_validation_is_silent_for_pretty_printed_committed_spec() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("openapi.json");
        let body = serde_json::to_string_pretty(&json!({
            "openapi": "3.1.0",
            "info": { "title": "X", "version": "1" },
            "paths": {},
            "components": { "schemas": { "Pad": { "type": "string", "description": "pad pad pad pad pad pad pad pad pad pad pad pad pad pad pad" }}}
        })).unwrap();
        std::fs::File::create(&path)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();

        let source = OpenapiSource::Path {
            path: "openapi.json".to_string(),
        };
        let findings = validate_committed_spec_formatting(&source, Some(dir.path()));
        assert!(findings.is_empty(), "expected silence, got: {findings:?}");
    }

    // ── Body example tests ──

    #[test]
    fn body_example_uses_operation_level_example() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "example": { "domain": "example.com" }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({"domain": "example.com"})
        );
    }

    #[test]
    fn body_example_uses_named_examples_first_value() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "examples": {
                                        "default": { "value": { "name": "alice" } }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({"name": "alice"})
        );
    }

    #[test]
    fn body_example_falls_back_to_schema_example() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "example": { "k": 1 } }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap(),
            json!({"k": 1})
        );
    }

    #[test]
    fn body_example_generates_from_required_schema_fields() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["domain", "tld"],
                                        "properties": {
                                            "domain": { "type": "string" },
                                            "tld": { "type": "string", "enum": ["com", "org"] },
                                            "optional_field": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        let parsed: Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["domain"], json!("test"));
        assert_eq!(parsed["tld"], json!("com"));
        // Optional field is not included.
        assert!(parsed.get("optional_field").is_none());
    }

    #[test]
    fn body_example_uses_format_hints() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["email", "url", "id"],
                                        "properties": {
                                            "email": { "type": "string", "format": "email" },
                                            "url": { "type": "string", "format": "uri" },
                                            "id": { "type": "string", "format": "uuid" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        let parsed: Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["email"], json!("test@example.com"));
        assert_eq!(parsed["url"], json!("https://example.com"));
        assert_eq!(parsed["id"], json!("00000000-0000-0000-0000-000000000000"));
    }

    #[test]
    fn body_example_resolves_refs() {
        let doc = r##"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": { "$ref": "#/components/schemas/Foo" }
                                }
                            }
                        }
                    }
                }
            },
            "components": {
                "schemas": {
                    "Foo": {
                        "type": "object",
                        "required": ["bar"],
                        "properties": {
                            "bar": { "type": "integer", "minimum": 5 }
                        }
                    }
                }
            }
        }"##;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        let parsed: Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["bar"], json!(5));
    }

    #[test]
    fn body_example_handles_arrays_and_nested_objects() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["items"],
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "required": ["name"],
                                                    "properties": {
                                                        "name": { "type": "string" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        let body = endpoints[0].body_example.as_deref().unwrap();
        let parsed: Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["items"], json!([{"name": "test"}]));
    }

    #[test]
    fn body_example_is_none_for_get() {
        let doc = r#"{
            "paths": {
                "/x": {
                    "get": {
                        "requestBody": {
                            "content": {
                                "application/json": { "example": { "k": 1 } }
                            }
                        }
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert!(endpoints[0].body_example.is_none());
    }

    #[test]
    fn body_example_is_none_when_no_request_body() {
        let doc = r#"{ "paths": { "/x": { "post": {} } } }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert!(endpoints[0].body_example.is_none());
    }

    #[test]
    fn query_example_assembled_from_param_examples() {
        // Mirrors the cryptorefills catalog endpoint: required + optional query
        // params, each with an example. Both are emitted; spec.path stays clean.
        let doc = r#"{
            "paths": {
                "/v1/catalog": {
                    "get": {
                        "parameters": [
                            {"name": "country_code", "in": "query", "required": true, "example": "us"},
                            {"name": "brand_name", "in": "query", "required": false, "schema": {"example": "Amazon.com"}}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        // `normalize_path` strips the leading slash for the published path.
        assert_eq!(endpoints[0].spec.path, "v1/catalog");
        assert_eq!(
            endpoints[0].query_example.as_deref(),
            Some("country_code=us&brand_name=Amazon.com")
        );
    }

    #[test]
    fn query_example_is_none_without_examples_or_query_params() {
        // A required query param with no example is skipped; a path param with
        // an example is not a query param. Result: no query string.
        let doc = r#"{
            "paths": {
                "/v1/items/{id}": {
                    "get": {
                        "parameters": [
                            {"name": "filter", "in": "query", "required": true},
                            {"name": "id", "in": "path", "required": true, "example": "abc"}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert!(endpoints[0].query_example.is_none());
    }

    #[test]
    fn path_example_substitutes_path_param_examples() {
        let doc = r#"{
            "paths": {
                "/v1/tip/{recipient}": {
                    "get": {
                        "parameters": [
                            {"name": "recipient", "in": "path", "required": true, "example": "jack"}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(endpoints[0].spec.path, "v1/tip/{recipient}");
        assert_eq!(endpoints[0].path_example.as_deref(), Some("v1/tip/jack"));
    }

    #[test]
    fn query_example_operation_param_shadows_path_item_param() {
        // OpenAPI lets parameters live at the path-item level; an operation
        // param of the same name overrides it. The operation's example wins.
        let doc = r#"{
            "paths": {
                "/v1/brands": {
                    "parameters": [
                        {"name": "country_code", "in": "query", "example": "it"}
                    ],
                    "get": {
                        "parameters": [
                            {"name": "country_code", "in": "query", "example": "us"}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(
            endpoints[0].query_example.as_deref(),
            Some("country_code=us")
        );
    }

    #[test]
    fn query_example_uses_examples_object_and_scalar_number() {
        // `examples.<name>.value` form, plus a numeric example coerced to text.
        let doc = r#"{
            "paths": {
                "/v1/price": {
                    "get": {
                        "parameters": [
                            {"name": "country_code", "in": "query",
                             "examples": {"default": {"value": "us"}}},
                            {"name": "product_value", "in": "query", "example": 50}
                        ]
                    }
                }
            }
        }"#;
        let endpoints = parse_endpoints(doc).unwrap();
        assert_eq!(
            endpoints[0].query_example.as_deref(),
            Some("country_code=us&product_value=50")
        );
    }
}
