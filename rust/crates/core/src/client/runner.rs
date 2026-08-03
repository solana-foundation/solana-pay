use std::process::{Command, Stdio};

use tempfile::NamedTempFile;
use tracing::{debug, info};

use crate::client::mpp;
use crate::client::subscription;
use crate::client::x402;
use crate::{ClientApp, Error, Result};

/// Payment challenges advertised by the first 402 response, decoded into
/// JSON and grouped by wire protocol for verbose CLI diagnostics.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct DecodedPaymentChallenges {
    /// Every x402 offer from the decoded `accepts` list (or the legacy
    /// single-requirement payload), in server order.
    pub x402: Vec<serde_json::Value>,
    /// Every MPP challenge with its base64url payload fields decoded as JSON.
    pub mpp: Vec<serde_json::Value>,
}

impl DecodedPaymentChallenges {
    pub fn is_empty(&self) -> bool {
        self.x402.is_empty() && self.mpp.is_empty()
    }
}

/// The outcome of running a wrapped command.
#[derive(Debug)]
pub enum RunOutcome {
    /// The server returned 402 with an MPP charge challenge.
    ///
    /// `x402_alternative` carries an x402 charge option advertised on the same
    /// 402, when present. MPP is preferred by default, but a balance-aware
    /// selector may settle the x402 option instead when the wallet can't fund
    /// any MPP challenge (e.g. MPP wants USDG, wallet holds only USDC offered
    /// via x402). See [`mpp::choose_payment`](crate::client::mpp::choose_payment).
    MppChallenge {
        challenge: Box<mpp::Challenge>,
        alternatives: Vec<mpp::Challenge>,
        x402_alternative: Option<Box<x402::Challenge>>,
        /// Every x402 `upto` currency advertised on the same 402, carried so the
        /// balance- and cost-aware selector can settle whichever is cheapest (or
        /// the only fundable one) — not just the first. See [`mpp::choose_payment`].
        x402_upto_accepts: Vec<pay_kit::x402::upto::UptoRequirements>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 with an MPP session challenge (intent="session").
    /// Reusable session clients open a Solana payment channel, then cache its
    /// authorization for later requests.
    SessionChallenge {
        challenge: Box<mpp::Challenge>,
        /// x402 alternatives advertised beside the session, retained so a
        /// client can fall back when it cannot reuse this session shape.
        x402_alternative: Option<Box<x402::Challenge>>,
        x402_upto_accepts: Vec<pay_kit::x402::upto::UptoRequirements>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 with an MPP subscription challenge
    /// (intent="subscription"). The activation transaction creates the
    /// recurring delegation and collects the first-period charge in one
    /// atomic transaction; renewals are server-driven and don't pass back
    /// through this enum.
    ///
    /// `authenticate` carries the sibling `intent="authenticate"`
    /// challenge from the same 402 response when the server emitted one
    /// (pay-server emits both). The caller signs it in the same Touch ID
    /// session as the activation tx and caches the resulting token in
    /// `accounts.yml` so subsequent requests within the billing period
    /// skip the 402 dance entirely.
    SubscriptionChallenge {
        challenge: Box<mpp::Challenge>,
        authenticate: Option<Box<mpp::Challenge>>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 with an x402 challenge.
    X402Challenge {
        challenge: Box<x402::Challenge>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 with an x402 `upto` (usage-metered) challenge —
    /// authorize a ceiling via a payment channel; the operator settles the
    /// actual amount after serving.
    X402UptoChallenge {
        challenge: Box<x402::UptoChallenge>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 with an x402 `sign-in-with-x` challenge.
    ///
    /// When the same 402 also offered a payment option, `payment_fallback`
    /// carries it: the client prefers signing in (to spend existing credits)
    /// but can fall back to paying if sign-in doesn't grant access (e.g. the
    /// wallet hasn't paid / has no credits yet).
    X402SignInChallenge {
        challenge: Box<x402::SiwxAuthChallenge>,
        payment_fallback: Option<Box<x402::Challenge>>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 but without a recognized payment protocol.
    UnknownPaymentRequired {
        headers: Vec<(String, String)>,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The server returned 402 with a `verification_failed` body — this is a
    /// retry response telling the client *why* the previously-submitted payment
    /// was rejected (wrong network, expired, double-spend, etc.).
    PaymentRejected {
        reason: String,
        retryable: bool,
        advertised_challenges: DecodedPaymentChallenges,
        resource_url: String,
    },
    /// The command completed (any status other than 402).
    Completed {
        exit_code: i32,
        /// Response body (only set by the built-in fetch, not by curl/wget
        /// wrappers). Held as raw bytes so binary responses round-trip
        /// without UTF-8 mangling. Use [`String::from_utf8_lossy`] to get
        /// a text view when the content-type guarantees UTF-8 (e.g. JSON).
        body: Option<Vec<u8>>,
        /// `content-type` header value (when known). Set by the built-in
        /// fetch path; `None` for the external curl/wget/httpie wrappers.
        /// Lets consumers route
        /// binary responses (image/*, application/pdf, …) differently
        /// from text — see `pay-mcp`'s curl tool.
        content_type: Option<String>,
        /// Final response headers, retained so callers can decode settlement
        /// receipts after a paid retry.
        response_headers: Vec<(String, String)>,
    },
}

/// Run `curl` with the given user args, detecting 402 + MPP challenges.
///
/// Appends `-D <tempfile>` after user args to capture response headers.
/// stdout/stderr/stdin are inherited so the user sees normal curl output.
pub fn run_curl(user_args: &[String]) -> Result<RunOutcome> {
    if is_passthrough_metadata_request(user_args) {
        return run_plain_command("curl", user_args);
    }

    validate_curl_args_against_catalog(user_args)?;
    let pre = pre_attach_cached_auth(user_args, ToolKind::Curl);
    run_curl_inner(user_args, &pre)
}

/// Run `curl` with extra headers injected (used for retry after payment).
pub fn run_curl_with_headers(user_args: &[String], extra_headers: &[String]) -> Result<RunOutcome> {
    run_curl_inner(user_args, extra_headers)
}

/// Validate a curl invocation against cached Pay catalog OpenAPI metadata.
pub fn validate_curl_args_against_catalog(user_args: &[String]) -> Result<()> {
    let request = ParsedCurlRequest::from_args(user_args);
    if let Some(url) = request.url.as_deref() {
        crate::skills::validate_cached_catalog_request(
            &request.method,
            url,
            request.body.as_deref(),
        )?;
    }
    Ok(())
}

fn run_curl_inner(user_args: &[String], extra_headers: &[String]) -> Result<RunOutcome> {
    check_command_exists("curl")?;

    let header_file = NamedTempFile::new()?;
    let header_path = header_file.path();
    let body_file = NamedTempFile::new()?;
    let body_path = body_file.path();

    let headers = headers_with_default_user_agent(user_args, extra_headers, ToolKind::Curl);

    debug!(args = ?user_args, extra = ?headers, "Running curl");

    // Body goes to `-o body_file` so we can swallow it on 402; stdout is piped
    // so curl's `-w` writeout (which it emits to stdout after the transfer) is
    // captured and re-emitted on the success path. Without this, `pay curl -w
    // '%{http_code}'` silently drops the writeout because we'd discard stdout.
    let mut cmd = Command::new("curl");
    cmd.args(user_args);
    for h in &headers {
        cmd.arg("-H").arg(h);
    }
    cmd.arg("-D").arg(header_path);
    cmd.arg("-o").arg(body_path);
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output()?;
    let exit_code = output.status.code().unwrap_or(1);
    let headers_raw = std::fs::read_to_string(header_path).unwrap_or_default();
    // Read body as raw bytes — `read_to_string` is lossy on non-UTF-8 and
    // would silently mangle binary responses (images, PDFs, …) before we
    // ever print them.
    let body = std::fs::read(body_path).unwrap_or_default();
    let (status_code, headers) = parse_http_headers(&headers_raw);
    let url = find_url_in_args(user_args).unwrap_or_default();

    debug!(?status_code, exit_code, "curl finished");

    if status_code == Some(402) {
        // Swallow stderr/stdout/body on 402 — CLI handles display.
        // 402 challenge bodies are JSON per spec; lossy decode is fine.
        let body_text = String::from_utf8_lossy(&body);
        return Ok(classify_402(&headers, Some(&body_text), &url));
    }

    // Not 402 — re-emit stderr (progress bar etc.), body, then any -w writeout.
    // `write_all(&body)` so binary bytes pass through untouched; print!
    // would route through Display which goes through UTF-8.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    let _ = std::io::Write::write_all(&mut std::io::stdout(), &body);
    let writeout = String::from_utf8_lossy(&output.stdout);
    if !writeout.is_empty() {
        print!("{writeout}");
    }
    Ok(RunOutcome::Completed {
        exit_code,
        body: None,
        content_type: None,
        response_headers: headers,
    })
}

/// Run `wget` with the given user args, detecting 402 + MPP challenges.
pub fn run_wget(user_args: &[String]) -> Result<RunOutcome> {
    if is_passthrough_metadata_request(user_args) {
        return run_plain_command("wget", user_args);
    }

    validate_wget_args_against_catalog(user_args)?;
    let pre = pre_attach_cached_auth(user_args, ToolKind::Wget);
    run_wget_inner(user_args, &pre)
}

/// Run `http` (HTTPie) with the given user args, detecting 402 + MPP challenges.
///
/// HTTPie uses positional `Header:Value` request items rather than `-H` flags,
/// so `extra_headers` for retry are appended as positional args.
pub fn run_httpie(user_args: &[String]) -> Result<RunOutcome> {
    if is_passthrough_metadata_request(user_args) {
        return run_plain_command("http", user_args);
    }

    let pre = pre_attach_cached_auth(user_args, ToolKind::Httpie);
    run_httpie_inner(user_args, &pre)
}

/// Run `http` with extra headers injected (used for retry after payment).
///
/// Each entry in `extra_headers` is the literal HTTPie request item
/// (e.g. `"Authorization:Bearer …"`), already formatted by the caller.
pub fn run_httpie_with_headers(
    user_args: &[String],
    extra_headers: &[String],
) -> Result<RunOutcome> {
    run_httpie_inner(user_args, extra_headers)
}

/// Run `wget` with extra headers injected (used for retry after payment).
pub fn run_wget_with_headers(user_args: &[String], extra_headers: &[String]) -> Result<RunOutcome> {
    run_wget_inner(user_args, extra_headers)
}

/// Validate a wget invocation against cached Pay catalog OpenAPI metadata.
pub fn validate_wget_args_against_catalog(user_args: &[String]) -> Result<()> {
    let request = ParsedWgetRequest::from_args(user_args);
    if let Some(url) = request.url.as_deref() {
        crate::skills::validate_cached_catalog_request(
            &request.method,
            url,
            request.body.as_deref(),
        )?;
    }
    Ok(())
}

fn run_wget_inner(user_args: &[String], extra_headers: &[String]) -> Result<RunOutcome> {
    check_command_exists("wget")?;

    let has_server_response = user_args
        .iter()
        .any(|a| a == "-S" || a == "--server-response");

    let headers = headers_with_default_user_agent(user_args, extra_headers, ToolKind::Wget);

    let mut cmd = Command::new("wget");
    if !has_server_response {
        cmd.arg("--server-response");
    }
    cmd.args(user_args);
    for h in &headers {
        cmd.arg("--header").arg(h);
    }
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::piped());

    debug!(args = ?user_args, extra = ?headers, "Running wget");

    let output = cmd.output()?;
    let exit_code = output.status.code().unwrap_or(1);
    let stderr_text = String::from_utf8_lossy(&output.stderr);

    let (status_code, headers) = parse_wget_headers(&stderr_text);
    let url = find_url_in_args(user_args).unwrap_or_default();

    debug!(?status_code, exit_code, "wget finished");

    if status_code == Some(402) {
        // Swallow stderr on 402. NOTE: wget writes the body to a file in cwd
        // by default, which we don't want to clobber by injecting -O. As a
        // result, we can't surface server `verification_failed` reasons for
        // wget retries (only curl/fetch). The retry path falls back to a
        // generic "still 402" message.
        return Ok(classify_402(&headers, None, &url));
    }

    // Re-emit stderr on success
    eprint!("{stderr_text}");
    Ok(RunOutcome::Completed {
        exit_code,
        body: None,
        content_type: None,
        response_headers: headers,
    })
}

fn run_httpie_inner(user_args: &[String], extra_headers: &[String]) -> Result<RunOutcome> {
    use std::io::IsTerminal;

    check_command_exists("http")?;

    let headers = headers_with_default_user_agent(user_args, extra_headers, ToolKind::Httpie);

    debug!(args = ?user_args, extra = ?headers, "Running httpie");

    // HTTPie has no `-D <file>` equivalent, so we capture stdout and parse the
    // response status from the first `HTTP/x.y <code>` line. We force three flags
    // *after* the user's args so they always win:
    //   - `--no-all` — print only the final exchange. `-v` implies `--all`, whose
    //     combined history cannot be distinguished safely from response body.
    //   - `--print=hb` — httpie's default when piped is body-only, which would
    //     hide the status line our parser needs.
    //   - `--pretty=all` — only when our parent stdout is a TTY, so the user
    //     sees colors despite our pipe (httpie would otherwise auto-disable
    //     them). We strip ANSI codes for parsing.
    let stdout_is_tty = std::io::stdout().is_terminal();
    let stdin_is_tty = std::io::stdin().is_terminal();
    let mut cmd = Command::new("http");
    cmd.args(user_args);
    for h in &headers {
        cmd.arg(h);
    }
    cmd.arg("--no-all");
    cmd.arg("--print=hb");
    if stdout_is_tty {
        cmd.arg("--pretty=all");
    }
    // When parent stdin isn't a real TTY (e.g. CI / agent shell), httpie reads
    // it as request body and conflicts with `field=value` items. Tell it to
    // ignore stdin in that case; if a user is genuinely piping data in,
    // they're expected to pass `--ignore-stdin` themselves or use `@file`.
    if !stdin_is_tty {
        cmd.arg("--ignore-stdin");
    }
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = cmd.output()?;
    let exit_code = output.status.code().unwrap_or(1);
    let stdout_text = String::from_utf8_lossy(&output.stdout);
    let stderr_text = String::from_utf8_lossy(&output.stderr);
    // HTTPie accepts `:port/path` and `host[:port]/path` shorthand;
    // expand both so the URL persisted alongside an activated
    // subscription matches what the next request will hit (the SIWMPP
    // cache lookup is a URL-prefix match).
    let url = resolve_request_url(user_args, ToolKind::Httpie).unwrap_or_default();

    let (status_code, headers, body) = parse_httpie_output(&stdout_text);

    debug!(?status_code, exit_code, "httpie finished");

    if status_code == Some(402) {
        // Swallow stdout/stderr on 402 — CLI handles display
        return Ok(classify_402(&headers, body.as_deref(), &url));
    }

    if !stderr_text.is_empty() {
        eprint!("{stderr_text}");
    }
    print!("{stdout_text}");
    Ok(RunOutcome::Completed {
        exit_code,
        body: None,
        content_type: None,
        response_headers: headers,
    })
}

/// Parse HTTPie's combined stdout into `(status, response_headers, body)`.
///
/// HTTPie writes the response as:
/// ```text
/// HTTP/1.1 <code> <reason>
/// Header: value
/// …
/// <blank line>
/// <body>
/// ```
/// The runner forces `--no-all --print=hb`, so the first line beginning with
/// `HTTP/` is the final response status. Once its header block ends, all
/// remaining lines are body. In particular, an `HTTP/` line in the body must
/// never be interpreted as another response. The parser also tolerates a
/// verbose request prelude for callers that exercise it directly.
/// ANSI escapes (from `--pretty=all`) are stripped before parsing.
pub(crate) fn parse_httpie_output(
    raw: &str,
) -> (Option<u16>, Vec<(String, String)>, Option<String>) {
    let cleaned = strip_ansi(raw);
    let lines: Vec<&str> = cleaned.lines().collect();

    let mut status_code = None;
    let mut headers = Vec::new();
    let mut body_start = None;
    let mut in_response_headers = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed_full = line.trim();

        if status_code.is_none() && trimmed_full.starts_with("HTTP/") {
            let parsed_status = trimmed_full
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok());
            if parsed_status.is_some() {
                status_code = parsed_status;
                in_response_headers = true;
            }
            continue;
        }

        if in_response_headers {
            if trimmed_full.is_empty() {
                body_start = Some(i + 1);
                break;
            }
            if let Some((k, v)) = trimmed_full.split_once(':') {
                let key = k.trim();
                if !key.is_empty() && !key.contains(' ') {
                    headers.push((key.to_lowercase(), v.trim().to_string()));
                }
            }
        }
    }

    let body = body_start.map(|start| lines[start..].join("\n"));
    (status_code, headers, body)
}

/// Strip ANSI CSI escape sequences (`\x1b[...m` and friends) from a string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Caller's preference for which payment protocol to use when a 402
/// advertises more than one. `Auto` mirrors the historical defaults
/// (MPP first for one-shot Solana charges, fall back to x402). The
/// `Only*` variants come from the user passing `--mpp` or `--x402` on
/// the CLI (or any wrapper that sets `PAY_PROTOCOL_ENFORCED`) and turn
/// "fall back" into "error" so the operator gets explicit feedback
/// instead of a silent switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolPreference {
    Auto,
    OnlyMpp,
    OnlyX402,
}

impl ProtocolPreference {
    /// Read the preference from `PAY_PROTOCOL_ENFORCED`. The CLI sets
    /// this from `--mpp` / `--x402`; the MCP launchers (`pay claude`,
    /// `pay codex`) forward it so nested invocations stay consistent.
    pub fn from_env() -> Self {
        match std::env::var("PAY_PROTOCOL_ENFORCED").ok().as_deref() {
            Some("mpp") => Self::OnlyMpp,
            Some("x402") => Self::OnlyX402,
            _ => Self::Auto,
        }
    }
}

/// Decode every payment challenge advertised by a 402 response without
/// applying protocol or network selection. This is intentionally separate
/// from [`classify_402`]: verbose diagnostics should show what the server
/// returned, including offers the caller did not choose.
pub fn decode_payment_challenges(
    headers: &[(String, String)],
    body: Option<&str>,
) -> DecodedPaymentChallenges {
    let mpp = mpp::parse_headers(headers)
        .into_iter()
        .map(|challenge| {
            let mut value = serde_json::to_value(&challenge).unwrap_or_else(|_| {
                serde_json::json!({
                    "id": challenge.id,
                    "realm": challenge.realm,
                    "method": challenge.method.as_str(),
                    "intent": challenge.intent.as_str(),
                })
            });
            if let Some(object) = value.as_object_mut() {
                if let Ok(request) = challenge.request.decode_value() {
                    object.insert("request".to_string(), request);
                }
                if let Some(opaque) = challenge.opaque.as_ref()
                    && let Ok(decoded) = opaque.decode_value()
                {
                    object.insert("opaque".to_string(), decoded);
                }
            }
            value
        })
        .collect();

    let mut x402 = Vec::new();
    for (name, value) in headers {
        if (name.eq_ignore_ascii_case(pay_kit::x402::PAYMENT_REQUIRED_HEADER)
            || name.eq_ignore_ascii_case(pay_kit::x402::X402_V1_PAYMENT_REQUIRED_HEADER))
            && let Some(decoded) = decode_json_value(value)
        {
            append_x402_challenges(&mut x402, decoded, true);
        }
    }

    // x402 also permits the payment-required envelope in the response body.
    // Only treat it as such when it self-identifies, so an arbitrary JSON
    // error body is never mislabeled as a payment challenge.
    if x402.is_empty()
        && let Some(decoded) = body.and_then(decode_json_value)
    {
        append_x402_challenges(&mut x402, decoded, false);
    }

    DecodedPaymentChallenges { x402, mpp }
}

fn append_x402_challenges(
    output: &mut Vec<serde_json::Value>,
    decoded: serde_json::Value,
    trusted_header: bool,
) {
    let self_identifies = decoded.get("x402Version").is_some()
        || decoded.get("scheme").is_some()
        || (decoded.get("network").is_some()
            && (decoded.get("amount").is_some() || decoded.get("maxAmountRequired").is_some()));

    if let Some(accepts) = decoded.get("accepts").and_then(serde_json::Value::as_array) {
        if accepts.is_empty() {
            // SIWX-only x402 challenges carry their challenge in `extensions`
            // and legitimately advertise no payment accepts. Preserve the
            // envelope so verbose output still shows that decoded challenge.
            if (trusted_header || self_identifies) && !output.contains(&decoded) {
                output.push(decoded);
            }
            return;
        }
        for challenge in accepts {
            if !output.contains(challenge) {
                output.push(challenge.clone());
            }
        }
        return;
    }

    if (trusted_header || self_identifies) && !output.contains(&decoded) {
        output.push(decoded);
    }
}

fn decode_json_value(raw: &str) -> Option<serde_json::Value> {
    if let Ok(value) = serde_json::from_str(raw) {
        return Some(value);
    }

    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(raw.trim())
            && let Ok(value) = serde_json::from_slice(&bytes)
        {
            return Some(value);
        }
    }
    None
}

/// Given 402 headers (and optional body), determine the payment protocol.
///
/// Reads the user's protocol preference from the environment. Internal
/// callers in tests should prefer [`classify_402_with_preference`] so
/// they don't have to mutate process-global state.
pub fn classify_402(
    headers: &[(String, String)],
    body: Option<&str>,
    resource_url: &str,
) -> RunOutcome {
    classify_402_with_preference(headers, body, resource_url, ProtocolPreference::from_env())
}

/// Variant of [`classify_402`] that takes an explicit
/// [`ProtocolPreference`] rather than reading the env var. The `--mpp`
/// and `--x402` CLI flags map to `OnlyMpp` / `OnlyX402`; if the server
/// only offers the other protocol the function returns
/// `RunOutcome::PaymentRejected` rather than silently switching.
pub(crate) fn classify_402_with_preference(
    headers: &[(String, String)],
    body: Option<&str>,
    resource_url: &str,
    preference: ProtocolPreference,
) -> RunOutcome {
    let advertised_challenges = decode_payment_challenges(headers, body);

    // A `verification_failed` body wins over a fresh challenge: it means the
    // server saw our payment header and rejected it. We must surface the
    // reason instead of looping into a second pay-and-retry.
    if let Some((reason, retryable)) = parse_verification_failure(body) {
        info!(resource = resource_url, %reason, "Server rejected payment");
        return RunOutcome::PaymentRejected {
            reason,
            retryable,
            advertised_challenges,
            resource_url: resource_url.to_string(),
        };
    }

    // Parse both protocols — multi-chain endpoints may advertise both
    // x402 (Solana + Base) and Tempo/MPP (EVM-only).
    //
    // Some servers use `payment-required` instead of `x-payment-required`
    // for x402. If the standard parse fails, try decoding `payment-required`
    // as base64 JSON and re-parse.
    let x402_challenge = x402::parse(headers, body).or_else(|| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(pay_kit::x402::PAYMENT_REQUIRED_HEADER))
            .and_then(|(_, v)| {
                use base64::Engine;
                let decoded = base64::engine::general_purpose::STANDARD.decode(v).ok()?;
                let json_str = String::from_utf8(decoded).ok()?;
                // Re-parse with the decoded JSON as the body
                x402::parse(&[], Some(&json_str))
            })
    });
    let mpp_challenges = mpp::parse_headers(headers);
    let x402_siwx_challenge = x402::parse_siwx_auth(headers, body);
    let x402_upto_accepts = x402::parse_upto_accepts(headers, body);
    let x402_alternative = if x402_upto_accepts.is_empty() {
        x402_challenge.clone().map(Box::new)
    } else {
        None
    };

    // x402::parse (from pay_kit::x402) only returns Some when a Solana-
    // compatible `accepts` entry exists — it's already a Solana filter.
    // MPP is chain-agnostic at the parse level, so we need to validate
    // the recipient is a valid Solana pubkey.
    // Session MPP: the method field ("solana") indicates chain support.
    // Session requests don't use ChargeRequest so mpp_is_solana doesn't apply.
    if preference != ProtocolPreference::OnlyX402
        && let Some(challenge) = mpp_challenges
            .iter()
            .find(|challenge| challenge.intent.as_str() == "session")
    {
        let is_solana_method = challenge.method.as_str() == "solana";
        if is_solana_method {
            debug!(
                resource = resource_url,
                "Detected MPP payment-channel challenge (Solana)"
            );
            return RunOutcome::SessionChallenge {
                challenge: Box::new(challenge.clone()),
                x402_alternative,
                x402_upto_accepts,
                advertised_challenges,
                resource_url: resource_url.to_string(),
            };
        }
        // Non-Solana session — fall through to x402 or error.
    }

    // Subscription challenge: checked before generic charge because the
    // intent is more specific. Solana is the only method profile pay
    // implements today, so we filter by both.
    if preference != ProtocolPreference::OnlyX402
        && let Some(challenge) = mpp_challenges
            .iter()
            .find(|c| subscription::is_subscription_challenge(c))
    {
        info!(
            resource = resource_url,
            "Detected MPP subscription challenge (Solana)"
        );
        let authenticate = mpp_challenges
            .iter()
            .find(|c| c.intent.as_str() == "authenticate" && c.method.as_str() == "solana")
            .cloned()
            .map(Box::new);
        return RunOutcome::SubscriptionChallenge {
            challenge: Box::new(challenge.clone()),
            authenticate,
            advertised_challenges,
            resource_url: resource_url.to_string(),
        };
    }

    // Default policy: prefer MPP for one-shot Solana payments (native
    // protocol), fall back to x402. `--mpp` keeps MPP and refuses the
    // x402 fallback; `--x402` skips the MPP selection entirely so we
    // land on x402 even when MPP is also offered.
    let mut charge_challenges: Vec<mpp::Challenge> = mpp_challenges
        .iter()
        .filter(|challenge| pay_kit::mpp::client::is_solana_charge_challenge(challenge))
        .cloned()
        .collect();
    if !charge_challenges.is_empty() && preference != ProtocolPreference::OnlyX402 {
        let challenge = charge_challenges.remove(0);
        info!(resource = resource_url, "Detected MPP challenge (Solana)");
        // An `upto`-only x402 offer also parses leniently as `exact`, so when a
        // real `upto` is present prefer that reading and drop the (bogus) exact
        // alternative — otherwise the selector could pick an `exact` the server
        // never advertised and the payment would be rejected.
        return RunOutcome::MppChallenge {
            challenge: Box::new(challenge),
            alternatives: charge_challenges,
            // Carry any x402 charge from the same 402 so the balance- and
            // cost-aware selector can settle it when it's cheaper or the only
            // fundable option.
            x402_alternative,
            x402_upto_accepts,
            advertised_challenges,
            resource_url: resource_url.to_string(),
        };
    }

    // Fall back to x402 if it has a Solana path. Skip when the user
    // pinned MPP via `--mpp`.
    if preference != ProtocolPreference::OnlyMpp {
        // Prefer `sign-in-with-x` when the server offers it: a wallet that
        // already holds credits (or has previously paid) should authenticate
        // and spend those rather than pay again. If the same 402 also
        // advertised a payment option, carry it as `payment_fallback` so the
        // caller can still pay when sign-in doesn't grant access (no credits).
        if let Some(siwx) = x402_siwx_challenge {
            info!(
                resource = resource_url,
                "Detected x402 sign-in challenge (preferring credits over payment)"
            );
            return RunOutcome::X402SignInChallenge {
                challenge: Box::new(siwx),
                payment_fallback: x402_challenge.map(Box::new),
                advertised_challenges,
                resource_url: resource_url.to_string(),
            };
        }

        // x402 `upto` (usage-metered) — checked before exact: an upto-only
        // challenge also parses leniently as exact, so prefer the upto reading
        // when the server advertises the `upto` scheme.
        if let Some(upto) = x402::parse_upto(headers, body) {
            debug!(
                resource = resource_url,
                "Detected x402 upto challenge (Solana)"
            );
            return RunOutcome::X402UptoChallenge {
                challenge: Box::new(upto),
                advertised_challenges,
                resource_url: resource_url.to_string(),
            };
        }

        if let Some(challenge) = x402_challenge {
            info!(resource = resource_url, "Detected x402 challenge (Solana)");
            return RunOutcome::X402Challenge {
                challenge: Box::new(challenge),
                advertised_challenges,
                resource_url: resource_url.to_string(),
            };
        }
    }

    // The user forced a protocol via `--mpp` / `--x402` but the server
    // only offers the other one. Surface that explicitly instead of
    // letting the request loop on an UnknownPaymentRequired.
    match preference {
        ProtocolPreference::OnlyMpp
            if x402_challenge.is_some() || x402_siwx_challenge.is_some() =>
        {
            return RunOutcome::PaymentRejected {
                reason: "Server only offers an x402 challenge, but --mpp was requested. \
                         Drop --mpp to settle via x402, or pick a server that advertises MPP."
                    .to_string(),
                retryable: false,
                advertised_challenges,
                resource_url: resource_url.to_string(),
            };
        }
        ProtocolPreference::OnlyX402
            if mpp_challenges
                .iter()
                .any(|challenge| challenge.method.as_str() == "solana") =>
        {
            return RunOutcome::PaymentRejected {
                reason: "Server only offers an MPP challenge, but --x402 was requested. \
                         Drop --x402 to settle via MPP, or pick a server that advertises x402."
                    .to_string(),
                retryable: false,
                advertised_challenges,
                resource_url: resource_url.to_string(),
            };
        }
        _ => {}
    }

    // Neither protocol supports Solana — tell the user clearly.
    if !mpp_challenges.is_empty() {
        return RunOutcome::PaymentRejected {
            reason: "Server requires payment but only accepts non-Solana chains \
                     (e.g. Base/EVM). This endpoint is not compatible with `pay`. \
                     Check if the provider supports Solana USDC."
                .to_string(),
            retryable: false,
            advertised_challenges,
            resource_url: resource_url.to_string(),
        };
    }

    RunOutcome::UnknownPaymentRequired {
        headers: headers.to_vec(),
        advertised_challenges,
        resource_url: resource_url.to_string(),
    }
}

/// Pure parser: pulls a payment rejection reason out of a 402 JSON body.
///
/// Returns `(message, retryable)` if the body matches the shape emitted by
/// the server emits for verification and session failures:
///
/// ```json
/// {"error": "session_failed", "message": "...", "retryable": true}
/// ```
///
/// Returns `None` for any other body shape (or absent body), so the caller
/// can fall through to the normal challenge-detection path.
pub(crate) fn parse_verification_failure(body: Option<&str>) -> Option<(String, bool)> {
    let body = body?.trim();
    if body.is_empty() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = v.get("error")?.as_str()?;
    if !matches!(error, "verification_failed" | "session_failed") {
        return None;
    }
    let message = v
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("payment verification failed")
        .to_string();
    let retryable = v
        .get("retryable")
        .and_then(|r| r.as_bool())
        .unwrap_or(false);
    Some((message, retryable))
}

fn check_command_exists(cmd: &str) -> Result<()> {
    match Command::new("which").arg(cmd).output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(Error::CommandNotFound {
            cmd: cmd.to_string(),
        }),
    }
}

/// Parse HTTP headers from curl's `-D` dump format.
///
/// Handles redirect chains by taking the LAST header block (the final response).
fn parse_http_headers(raw: &str) -> (Option<u16>, Vec<(String, String)>) {
    let blocks: Vec<&str> = raw.split("\r\n\r\n").filter(|b| !b.is_empty()).collect();
    let block = match blocks.last() {
        Some(b) => b,
        None => return (None, vec![]),
    };

    let mut status_code = None;
    let mut headers = Vec::new();

    for line in block.lines() {
        let line = line.trim();
        if line.starts_with("HTTP/") {
            status_code = line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok());
        } else if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_lowercase(), value.trim().to_string()));
        }
    }

    (status_code, headers)
}

/// Parse HTTP headers from wget's `--server-response` stderr output.
fn parse_wget_headers(stderr: &str) -> (Option<u16>, Vec<(String, String)>) {
    let mut status_code = None;
    let mut headers = Vec::new();

    let mut current_status = None;
    let mut current_headers = Vec::new();

    for line in stderr.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("HTTP/") {
            if current_status.is_some() {
                status_code = current_status;
                headers = std::mem::take(&mut current_headers);
            }
            current_status = trimmed
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok());
        } else if let Some((key, value)) = trimmed.split_once(':') {
            let key = key.trim();
            if !key.is_empty() && !key.contains(' ') {
                current_headers.push((key.to_lowercase(), value.trim().to_string()));
            }
        }
    }

    if current_status.is_some() {
        status_code = current_status;
        headers = current_headers;
    }

    (status_code, headers)
}

/// Heuristic: find the URL from command args.
fn find_url_in_args(args: &[String]) -> Option<String> {
    args.iter()
        .find(|a| a.starts_with("http://") || a.starts_with("https://"))
        .cloned()
}

/// Which external HTTP client the runner is feeding. The header
/// injection format and URL-extraction rules differ per tool.
#[derive(Debug, Clone, Copy)]
enum ToolKind {
    Curl,
    Wget,
    Httpie,
}

fn headers_with_default_user_agent(
    args: &[String],
    extra_headers: &[String],
    tool: ToolKind,
) -> Vec<String> {
    let mut headers = Vec::with_capacity(extra_headers.len() + 1);
    if !user_already_set_user_agent(args, tool)
        && !extra_headers
            .iter()
            .any(|header| is_header_name(header, "user-agent"))
    {
        headers.push(formatted_header(
            tool,
            "User-Agent",
            &ClientApp::Cli.user_agent(),
        ));
    }
    headers.extend(extra_headers.iter().cloned());
    headers
}

fn formatted_header(tool: ToolKind, name: &str, value: &str) -> String {
    match tool {
        ToolKind::Curl | ToolKind::Wget => format!("{name}: {value}"),
        ToolKind::Httpie => format!("{name}:{value}"),
    }
}

/// Best-effort URL extraction across the three CLI tools we wrap.
///
/// `curl`/`wget` require a fully-qualified URL on the command line —
/// `find_url_in_args` already covers that. `httpie` accepts shorthands
/// like `:1402/path` (host defaults to `localhost`) or `example.com/path`
/// (scheme defaults to `http://`). We canonicalise both forms so the
/// SIWMPP cache lookup (URL-prefix match against tracked subscriptions)
/// sees the same URL the request will actually hit.
fn resolve_request_url(args: &[String], tool: ToolKind) -> Option<String> {
    if let Some(u) = find_url_in_args(args) {
        return Some(u);
    }
    if !matches!(tool, ToolKind::Httpie) {
        return None;
    }
    args.iter().find_map(|a| httpie_url_shorthand(a))
}

/// HTTPie-specific URL shorthand expander.
///
/// Skips flags, body items (`field=value`, `field:=jsonvalue`,
/// `field==query`), headers (`Header:value`), and HTTP method tokens.
/// Returns `Some(canonical_url)` for `:port[/path]` and bare
/// `host[:port][/path]` forms.
fn httpie_url_shorthand(arg: &str) -> Option<String> {
    if arg.starts_with('-') || arg.is_empty() {
        return None;
    }
    if arg.contains('=') {
        return None; // body item: key=val, key:=jsonval, key==query
    }
    if matches!(
        arg,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    ) {
        return None;
    }

    // `:port[/path]` — host defaults to localhost.
    if let Some(rest) = arg.strip_prefix(':') {
        let first = rest.chars().next()?;
        if first.is_ascii_digit() {
            return Some(format!("http://localhost:{rest}"));
        }
        return None;
    }

    // Header item like `Foo:Bar` — colon present, but the part before is
    // a header name (letters/dashes), not a hostname.
    if let Some(colon) = arg.find(':') {
        let host_or_name = &arg[..colon];
        let after = arg[colon + 1..].chars().next();
        let port_like = after.is_some_and(|c| c.is_ascii_digit());
        let looks_hostlike = host_or_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        if !port_like || !looks_hostlike {
            return None;
        }
        // `host:port[/path]` → assume http://
        return Some(format!("http://{arg}"));
    }

    // Bare `host[/path]` — only treat as URL when it looks domain-ish
    // (contains a `.`), to avoid matching positional non-URL args.
    if arg.contains('.') {
        return Some(format!("http://{arg}"));
    }
    None
}

/// Pre-attach a cached SIWMPP `Authorization: Payment …` header to the
/// CLI command when a tracked subscription covers the request URL.
///
/// Returns the formatted header arg(s) to inject into the subprocess,
/// in the tool's native shape:
/// - curl/wget: `"Authorization: <token>"`
/// - httpie: `"Authorization:<token>"` (no space — HTTPie request-item form)
///
/// Empty vec when no tracked subscription matches the URL, so callers
/// pass it through to the existing inner runner unchanged.
fn pre_attach_cached_auth(args: &[String], tool: ToolKind) -> Vec<String> {
    let Some(url) = resolve_request_url(args, tool) else {
        return Vec::new();
    };
    // Skip pre-attach when the user already passed their own
    // Authorization header — their value wins.
    if user_already_set_auth(args, tool) {
        return Vec::new();
    }
    let store = crate::accounts::FileAccountsStore::default_path();
    let Some(token) = crate::client::authenticate::cached_header_for_resource(&store, &url) else {
        return Vec::new();
    };
    vec![formatted_header(tool, "Authorization", &token)]
}

/// True when the user already passed an Authorization header through
/// the wrapper's args, so we don't clobber it with a cached token.
fn user_already_set_auth(args: &[String], tool: ToolKind) -> bool {
    user_already_set_header(args, tool, "authorization")
}

fn user_already_set_user_agent(args: &[String], tool: ToolKind) -> bool {
    if user_already_set_header(args, tool, "user-agent") {
        return true;
    }
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match tool {
            ToolKind::Curl => {
                if arg == "-A" || arg == "--user-agent" {
                    return iter.peek().is_some();
                }
                if arg.starts_with("-A") && arg.len() > 2 {
                    return true;
                }
                if arg.starts_with("--user-agent=") {
                    return true;
                }
            }
            ToolKind::Wget => {
                if arg == "-U" || arg == "--user-agent" {
                    return iter.peek().is_some();
                }
                if arg.starts_with("-U") && arg.len() > 2 {
                    return true;
                }
                if arg.starts_with("--user-agent=") {
                    return true;
                }
            }
            ToolKind::Httpie => {}
        }
    }
    false
}

fn user_already_set_header(args: &[String], tool: ToolKind, header_name: &str) -> bool {
    let mut iter = args.iter().peekable();
    while let Some(arg) = iter.next() {
        match tool {
            ToolKind::Curl => {
                if (arg == "-H" || arg == "--header")
                    && let Some(next) = iter.peek()
                    && is_header_name(next, header_name)
                {
                    return true;
                }
                if let Some(val) = arg
                    .strip_prefix("-H")
                    .or_else(|| arg.strip_prefix("--header="))
                    && is_header_name(val, header_name)
                {
                    return true;
                }
            }
            ToolKind::Wget => {
                if let Some(val) = arg.strip_prefix("--header=")
                    && is_header_name(val, header_name)
                {
                    return true;
                }
                if arg == "--header"
                    && let Some(next) = iter.peek()
                    && is_header_name(next, header_name)
                {
                    return true;
                }
            }
            ToolKind::Httpie => {
                if is_header_name(arg, header_name) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_header_name(header: &str, expected: &str) -> bool {
    header
        .split_once(':')
        .map(|(name, _)| name.trim().eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

#[cfg(test)]
mod pre_attach_tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn httpie_shorthand_with_port_resolves_to_localhost() {
        let args = s(&["-v", "POST", ":1402/", "jsonrpc=2.0", "id:=1"]);
        assert_eq!(
            resolve_request_url(&args, ToolKind::Httpie),
            Some("http://localhost:1402/".to_string())
        );
    }

    #[test]
    fn httpie_shorthand_with_host_port_resolves_with_default_scheme() {
        let args = s(&["GET", "example.com:8080/api"]);
        assert_eq!(
            resolve_request_url(&args, ToolKind::Httpie),
            Some("http://example.com:8080/api".to_string())
        );
    }

    #[test]
    fn httpie_skips_header_items_and_body_fields() {
        let args = s(&["POST", "Authorization:Bearer x", "field=value", ":1402/"]);
        assert_eq!(
            resolve_request_url(&args, ToolKind::Httpie),
            Some("http://localhost:1402/".to_string())
        );
    }

    #[test]
    fn user_auth_overrides_curl_pre_attach() {
        let args = s(&["-H", "Authorization: Bearer existing", "http://example.com"]);
        assert!(user_already_set_auth(&args, ToolKind::Curl));
    }

    #[test]
    fn user_auth_overrides_httpie_pre_attach() {
        let args = s(&["GET", ":1402/", "Authorization:Bearer existing"]);
        assert!(user_already_set_auth(&args, ToolKind::Httpie));
    }

    #[test]
    fn curl_injects_default_cli_user_agent() {
        let args = s(&["https://example.com"]);
        let headers = headers_with_default_user_agent(&args, &[], ToolKind::Curl);
        assert_eq!(
            headers,
            vec![format!("User-Agent: {}", ClientApp::Cli.user_agent())]
        );
    }

    #[test]
    fn httpie_injects_default_cli_user_agent_in_request_item_form() {
        let args = s(&["GET", "example.com"]);
        let headers = headers_with_default_user_agent(&args, &[], ToolKind::Httpie);
        assert_eq!(
            headers,
            vec![format!("User-Agent:{}", ClientApp::Cli.user_agent())]
        );
    }

    #[test]
    fn user_agent_header_overrides_default_for_wget() {
        let args = s(&[
            "--header",
            "User-Agent: custom-client",
            "https://example.com",
        ]);
        let headers = headers_with_default_user_agent(&args, &[], ToolKind::Wget);
        assert!(headers.is_empty());
    }

    #[test]
    fn curl_user_agent_flag_overrides_default() {
        let args = s(&["-A", "custom-client", "https://example.com"]);
        let headers = headers_with_default_user_agent(&args, &[], ToolKind::Curl);
        assert!(headers.is_empty());
    }

    #[test]
    fn extra_user_agent_header_overrides_default() {
        let args = s(&["https://example.com"]);
        let extra = s(&["User-Agent: retry-client"]);
        let headers = headers_with_default_user_agent(&args, &extra, ToolKind::Curl);
        assert_eq!(headers, extra);
    }

    #[test]
    fn no_url_means_no_pre_attach() {
        let args = s(&["--help"]);
        assert_eq!(resolve_request_url(&args, ToolKind::Httpie), None);
        assert!(pre_attach_cached_auth(&args, ToolKind::Httpie).is_empty());
    }
}

fn is_passthrough_metadata_request(args: &[String]) -> bool {
    args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-h" | "--help" | "--manual" | "-V" | "--version"
        ) || arg.starts_with("--help=")
    })
}

fn run_plain_command(program: &str, args: &[String]) -> Result<RunOutcome> {
    check_command_exists(program)?;

    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()?;

    Ok(RunOutcome::Completed {
        exit_code: status.code().unwrap_or(1),
        body: None,
        content_type: None,
        response_headers: Vec::new(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCurlRequest {
    url: Option<String>,
    method: String,
    body: Option<String>,
}

impl ParsedCurlRequest {
    fn from_args(args: &[String]) -> Self {
        let mut url = None;
        let mut explicit_method = None;
        let mut body = None;
        let mut force_get = false;
        let mut i = 0;

        while i < args.len() {
            let arg = &args[i];
            match arg.as_str() {
                "-X" | "--request" => {
                    if let Some(value) = args.get(i + 1) {
                        explicit_method = Some(value.to_ascii_uppercase());
                        i += 1;
                    }
                }
                "--url" => {
                    if let Some(value) = args.get(i + 1) {
                        url = Some(value.clone());
                        i += 1;
                    }
                }
                "-d" | "--data" | "--data-raw" | "--data-binary" | "--data-ascii"
                | "--data-urlencode" | "--json" => {
                    if let Some(value) = args.get(i + 1) {
                        append_curl_body(&mut body, value);
                        i += 1;
                    }
                }
                "-G" | "--get" => {
                    force_get = true;
                }
                "-I" | "--head" => {
                    explicit_method = Some("HEAD".to_string());
                }
                _ => {
                    if let Some(value) = arg.strip_prefix("--request=") {
                        explicit_method = Some(value.to_ascii_uppercase());
                    } else if let Some(value) = arg.strip_prefix("--url=") {
                        url = Some(value.to_string());
                    } else if let Some(value) = arg.strip_prefix("--data=") {
                        append_curl_body(&mut body, value);
                    } else if let Some(value) = arg.strip_prefix("--data-raw=") {
                        append_curl_body(&mut body, value);
                    } else if let Some(value) = arg.strip_prefix("--data-binary=") {
                        append_curl_body(&mut body, value);
                    } else if let Some(value) = arg.strip_prefix("--data-ascii=") {
                        append_curl_body(&mut body, value);
                    } else if let Some(value) = arg.strip_prefix("--data-urlencode=") {
                        append_curl_body(&mut body, value);
                    } else if let Some(value) = arg.strip_prefix("--json=") {
                        append_curl_body(&mut body, value);
                    } else if arg.starts_with("-X") && arg.len() > 2 {
                        explicit_method = Some(arg[2..].to_ascii_uppercase());
                    } else if arg.starts_with("-d") && arg.len() > 2 {
                        append_curl_body(&mut body, &arg[2..]);
                    } else if url.is_none()
                        && (arg.starts_with("http://") || arg.starts_with("https://"))
                    {
                        url = Some(arg.clone());
                    }
                }
            }
            i += 1;
        }

        let method = explicit_method.unwrap_or_else(|| {
            if force_get || body.is_none() {
                "GET".to_string()
            } else {
                "POST".to_string()
            }
        });

        Self { url, method, body }
    }
}

fn append_curl_body(body: &mut Option<String>, value: &str) {
    match body {
        Some(body) if !body.is_empty() => {
            body.push('&');
            body.push_str(value);
        }
        Some(body) => body.push_str(value),
        None => *body = Some(value.to_string()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedWgetRequest {
    url: Option<String>,
    method: String,
    body: Option<String>,
}

impl ParsedWgetRequest {
    fn from_args(args: &[String]) -> Self {
        let mut url = None;
        let mut explicit_method = None;
        let mut body = None;
        let mut post_body_seen = false;
        let mut i = 0;

        while i < args.len() {
            let arg = &args[i];
            match arg.as_str() {
                "--method" => {
                    if let Some(value) = args.get(i + 1) {
                        explicit_method = Some(value.to_ascii_uppercase());
                        i += 1;
                    }
                }
                "--post-data" | "--body-data" => {
                    if let Some(value) = args.get(i + 1) {
                        body = Some(value.clone());
                        post_body_seen = true;
                        i += 1;
                    }
                }
                "--spider" => {
                    explicit_method.get_or_insert_with(|| "HEAD".to_string());
                }
                _ => {
                    if let Some(value) = arg.strip_prefix("--method=") {
                        explicit_method = Some(value.to_ascii_uppercase());
                    } else if let Some(value) = arg.strip_prefix("--post-data=") {
                        body = Some(value.to_string());
                        post_body_seen = true;
                    } else if let Some(value) = arg.strip_prefix("--body-data=") {
                        body = Some(value.to_string());
                        post_body_seen = true;
                    } else if matches!(
                        arg.as_str(),
                        "--post-file" | "--body-file" | "--post-file=" | "--body-file="
                    ) {
                        post_body_seen = true;
                        if !arg.ends_with('=') && args.get(i + 1).is_some() {
                            i += 1;
                        }
                    } else if arg.starts_with("--post-file=") || arg.starts_with("--body-file=") {
                        post_body_seen = true;
                    } else if url.is_none()
                        && (arg.starts_with("http://") || arg.starts_with("https://"))
                    {
                        url = Some(arg.clone());
                    }
                }
            }
            i += 1;
        }

        let method = explicit_method.unwrap_or_else(|| {
            if post_body_seen {
                "POST".to_string()
            } else {
                "GET".to_string()
            }
        });

        Self { url, method, body }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_headers() {
        let raw = "HTTP/1.1 402 Payment Required\r\nX-Payment-Url: https://pay.example.com\r\nX-Payment-Amount: 1000\r\nX-Payment-Currency: USD\r\n\r\n";
        let (status, headers) = parse_http_headers(raw);
        assert_eq!(status, Some(402));
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k == "x-payment-url")
                .unwrap()
                .1,
            "https://pay.example.com"
        );
    }

    #[test]
    fn parse_redirect_chain_takes_last() {
        let raw = "HTTP/1.1 301 Moved\r\nLocation: https://new.example.com\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let (status, _headers) = parse_http_headers(raw);
        assert_eq!(status, Some(200));
    }

    #[test]
    fn parse_wget_server_response() {
        let stderr = r#"
--2026-03-20 10:00:00--  https://example.com/resource
Resolving example.com... 93.184.216.34
Connecting to example.com|93.184.216.34|:443... connected.
HTTP request sent, awaiting response...
  HTTP/1.1 402 Payment Required
  X-Payment-Url: https://pay.example.com
  X-Payment-Amount: 500
  X-Payment-Currency: SOL
  Content-Length: 0
"#;
        let (status, headers) = parse_wget_headers(stderr);
        assert_eq!(status, Some(402));
        assert_eq!(
            headers
                .iter()
                .find(|(k, _)| k == "x-payment-url")
                .unwrap()
                .1,
            "https://pay.example.com"
        );
    }

    #[test]
    fn passthrough_metadata_request_detects_help_and_version() {
        assert!(is_passthrough_metadata_request(&["--help".to_string()]));
        assert!(is_passthrough_metadata_request(&["-h".to_string()]));
        assert!(is_passthrough_metadata_request(&["--help=all".to_string()]));
        assert!(is_passthrough_metadata_request(&["--version".to_string()]));
        assert!(is_passthrough_metadata_request(&["-V".to_string()]));
    }

    #[test]
    fn passthrough_metadata_request_ignores_normal_requests() {
        let args = vec![
            "-H".to_string(),
            "X-Mode: help".to_string(),
            "https://example.com".to_string(),
        ];
        assert!(!is_passthrough_metadata_request(&args));
    }

    #[test]
    fn classify_402_with_mpp() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": {
                "network": "devnet"
            }
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"test-id\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
            ),
        )];

        let outcome = classify_402(&headers, None, "https://example.com/resource");
        assert!(matches!(outcome, RunOutcome::MppChallenge { .. }));
    }

    #[test]
    fn classify_402_preserves_multiple_mpp_charge_challenges() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header_for = |currency: &str| {
            let request_json = serde_json::json!({
                "amount": "1000000",
                "currency": currency,
                "recipient": "So11111111111111111111111111111111111111112",
                "methodDetails": { "network": "devnet" }
            });
            let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
            (
                "www-authenticate".to_string(),
                format!(
                    "Payment id=\"{currency}\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
                ),
            )
        };
        let headers = vec![header_for("USDC"), header_for("USDT"), header_for("CASH")];

        let outcome = classify_402(&headers, None, "https://example.com/resource");
        match outcome {
            RunOutcome::MppChallenge {
                challenge,
                alternatives,
                ..
            } => {
                let first: pay_kit::mpp::ChargeRequest = challenge.request.decode().unwrap();
                assert_eq!(first.currency, "USDC");
                assert_eq!(alternatives.len(), 2);
            }
            other => panic!("expected MppChallenge, got {other:?}"),
        }
    }

    #[test]
    fn classify_402_with_subscription_intent() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "amount": "10000000",
            "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            "methodDetails": {
                "planId": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
                "decimals": 6,
                "network": "mainnet"
            }
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"sub-1\", realm=\"test\", method=\"solana\", \
                 intent=\"subscription\", request=\"{b64}\""
            ),
        )];

        let outcome = classify_402(&headers, None, "https://example.com/resource");
        assert!(
            matches!(outcome, RunOutcome::SubscriptionChallenge { .. }),
            "expected SubscriptionChallenge, got {outcome:?}"
        );
    }

    #[test]
    fn classify_402_prefers_subscription_over_charge_when_both_present() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Charge challenge first.
        let charge = serde_json::json!({
            "amount": "1000000",
            "currency": "USDC",
            "recipient": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            "methodDetails": {"network": "mainnet"}
        });
        let charge_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&charge).unwrap());
        let charge_header = format!(
            "Payment id=\"c\", realm=\"r\", method=\"solana\", intent=\"charge\", \
             request=\"{charge_b64}\""
        );

        // Subscription challenge second.
        let sub = serde_json::json!({
            "amount": "10000000",
            "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "periodUnit": "day",
            "periodCount": "30",
            "recipient": "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            "methodDetails": {
                "planId": "8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT",
                "mint": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "puller": "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
                "decimals": 6,
                "network": "mainnet"
            }
        });
        let sub_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&sub).unwrap());
        let sub_header = format!(
            "Payment id=\"s\", realm=\"r\", method=\"solana\", intent=\"subscription\", \
             request=\"{sub_b64}\""
        );

        let headers = vec![
            ("www-authenticate".to_string(), charge_header),
            ("www-authenticate".to_string(), sub_header),
        ];

        let outcome = classify_402(&headers, None, "https://example.com/resource");
        assert!(
            matches!(outcome, RunOutcome::SubscriptionChallenge { .. }),
            "subscription must win over charge: {outcome:?}"
        );
    }

    #[test]
    fn classify_402_with_session_mpp() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "cap": "1000000",
            "currency": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "network": "localnet",
            "operator": "So11111111111111111111111111111111111111112",
            "recipient": "So11111111111111111111111111111111111111112",
            "modes": ["pull"]
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"test-id\", realm=\"test\", method=\"solana\", intent=\"session\", request=\"{b64}\""
            ),
        )];

        let outcome = classify_402(&headers, None, "https://example.com/resource");
        assert!(matches!(outcome, RunOutcome::SessionChallenge { .. }));
    }

    #[test]
    fn classify_402_with_x402_header() {
        let requirements = serde_json::json!({
            "network": "solana",
            "cluster": "devnet",
            "recipient": "So11111111111111111111111111111111111111112",
            "amount": "1000000",
            "currency": "USDC",
            "resource": "https://example.com/resource"
        });
        let headers = vec![(
            pay_kit::x402::X402_V1_PAYMENT_REQUIRED_HEADER.to_string(),
            requirements.to_string(),
        )];

        let outcome = classify_402(&headers, None, "https://example.com/resource");
        assert!(matches!(outcome, RunOutcome::X402Challenge { .. }));
    }

    /// Build a 402 with BOTH an MPP charge challenge AND an x402 header,
    /// so `classify_402_with_preference` has a real choice between the
    /// two protocols. Shared by the `--mpp` / `--x402` preference tests.
    fn dual_protocol_402() -> Vec<(String, String)> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let mpp_request = serde_json::json!({
            "amount": "1000000",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": { "network": "devnet" }
        });
        let mpp_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&mpp_request).unwrap());

        let x402_requirements = serde_json::json!({
            "network": "solana",
            "cluster": "devnet",
            "recipient": "So11111111111111111111111111111111111111112",
            "amount": "1000000",
            "currency": "USDC",
            "resource": "https://example.com/resource"
        });

        vec![
            (
                "www-authenticate".to_string(),
                format!(
                    "Payment id=\"dual\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{mpp_b64}\""
                ),
            ),
            (
                pay_kit::x402::X402_V1_PAYMENT_REQUIRED_HEADER.to_string(),
                x402_requirements.to_string(),
            ),
        ]
    }

    fn dual_protocol_session_402() -> Vec<(String, String)> {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let session_request = serde_json::json!({
            "cap": "1000000",
            "currency": "USDC",
            "network": "devnet",
            "operator": "So11111111111111111111111111111111111111112",
            "recipient": "So11111111111111111111111111111111111111112",
            "modes": ["pull"]
        });
        let session_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&session_request).unwrap());
        let mut headers = dual_protocol_402();
        headers[0].1 = format!(
            "Payment id=\"dual-session\", realm=\"test\", method=\"solana\", \
             intent=\"session\", request=\"{session_b64}\""
        );
        headers
    }

    #[test]
    fn decoded_challenges_group_mpp_and_x402_before_protocol_selection() {
        let headers = dual_protocol_402();
        let decoded = decode_payment_challenges(&headers, None);

        assert_eq!(decoded.mpp.len(), 1);
        assert_eq!(decoded.x402.len(), 1);
        assert_eq!(decoded.mpp[0]["intent"], "charge");
        assert_eq!(decoded.mpp[0]["request"]["currency"], "USDC");
        assert_eq!(decoded.x402[0]["currency"], "USDC");
        assert_eq!(decoded.x402[0]["cluster"], "devnet");
    }

    #[test]
    fn decoded_challenges_preserve_every_x402_accept() {
        use base64::Engine;

        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [
                {
                    "scheme": "exact",
                    "network": "solana:mainnet",
                    "amount": "10",
                    "asset": "USDC",
                    "payTo": "exact-recipient"
                },
                {
                    "scheme": "upto",
                    "network": "solana:mainnet",
                    "amount": "250000",
                    "asset": "USDC",
                    "payTo": "upto-recipient"
                }
            ]
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let headers = vec![(
            pay_kit::x402::PAYMENT_REQUIRED_HEADER.to_ascii_lowercase(),
            encoded,
        )];

        let decoded = decode_payment_challenges(&headers, None);
        assert_eq!(decoded.x402.len(), 2);
        assert_eq!(decoded.x402[0]["scheme"], "exact");
        assert_eq!(decoded.x402[1]["scheme"], "upto");
    }

    #[test]
    fn decoded_challenges_preserve_siwx_only_envelope() {
        use base64::Engine;

        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "example.com",
                        "nonce": "nonce-123"
                    }
                }
            }
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&envelope).unwrap());
        let headers = vec![(
            pay_kit::x402::PAYMENT_REQUIRED_HEADER.to_ascii_lowercase(),
            encoded,
        )];

        let decoded = decode_payment_challenges(&headers, None);
        assert_eq!(decoded.x402, vec![envelope]);
    }

    #[test]
    fn preference_auto_prefers_mpp_when_both_offered() {
        let outcome = classify_402_with_preference(
            &dual_protocol_402(),
            None,
            "https://example.com/resource",
            ProtocolPreference::Auto,
        );
        assert!(matches!(outcome, RunOutcome::MppChallenge { .. }));
    }

    #[test]
    fn preference_only_x402_picks_x402_when_both_offered() {
        let outcome = classify_402_with_preference(
            &dual_protocol_402(),
            None,
            "https://example.com/resource",
            ProtocolPreference::OnlyX402,
        );
        assert!(matches!(outcome, RunOutcome::X402Challenge { .. }));
    }

    #[test]
    fn preference_only_x402_skips_mpp_session_when_both_offered() {
        let outcome = classify_402_with_preference(
            &dual_protocol_session_402(),
            None,
            "https://example.com/resource",
            ProtocolPreference::OnlyX402,
        );
        assert!(matches!(outcome, RunOutcome::X402Challenge { .. }));
    }

    #[test]
    fn preference_auto_still_prefers_mpp_session_when_both_offered() {
        let outcome = classify_402_with_preference(
            &dual_protocol_session_402(),
            None,
            "https://example.com/resource",
            ProtocolPreference::Auto,
        );
        match outcome {
            RunOutcome::SessionChallenge {
                x402_alternative, ..
            } => assert!(x402_alternative.is_some()),
            other => panic!("expected session challenge, got {other:?}"),
        }
    }

    #[test]
    fn preference_only_mpp_keeps_mpp_when_both_offered() {
        let outcome = classify_402_with_preference(
            &dual_protocol_402(),
            None,
            "https://example.com/resource",
            ProtocolPreference::OnlyMpp,
        );
        assert!(matches!(outcome, RunOutcome::MppChallenge { .. }));
    }

    #[test]
    fn preference_only_x402_rejects_when_server_only_offers_mpp() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": { "network": "devnet" }
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"mpp-only\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
            ),
        )];

        let outcome = classify_402_with_preference(
            &headers,
            None,
            "https://example.com/resource",
            ProtocolPreference::OnlyX402,
        );
        match outcome {
            RunOutcome::PaymentRejected { reason, .. } => {
                assert!(reason.contains("--x402"), "reason was {reason:?}");
                assert!(reason.contains("MPP"), "reason was {reason:?}");
            }
            other => panic!("expected PaymentRejected, got {other:?}"),
        }
    }

    #[test]
    fn preference_only_mpp_rejects_when_server_only_offers_x402() {
        let requirements = serde_json::json!({
            "network": "solana",
            "cluster": "devnet",
            "recipient": "So11111111111111111111111111111111111111112",
            "amount": "1000000",
            "currency": "USDC",
            "resource": "https://example.com/resource"
        });
        let headers = vec![(
            pay_kit::x402::X402_V1_PAYMENT_REQUIRED_HEADER.to_string(),
            requirements.to_string(),
        )];

        let outcome = classify_402_with_preference(
            &headers,
            None,
            "https://example.com/resource",
            ProtocolPreference::OnlyMpp,
        );
        match outcome {
            RunOutcome::PaymentRejected { reason, .. } => {
                assert!(reason.contains("--mpp"), "reason was {reason:?}");
                assert!(reason.contains("x402"), "reason was {reason:?}");
            }
            other => panic!("expected PaymentRejected, got {other:?}"),
        }
    }

    #[test]
    fn classify_402_with_x402_siwx_auth_only_header() {
        use base64::Engine;

        let payment_required = serde_json::json!({
            pay_kit::x402::X402_VERSION_FIELD: pay_kit::x402::X402_VERSION_V2,
            "resource": {
                "url": "https://example.com/resource",
                "description": "API access"
            },
            "accepts": [],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "example.com",
                        "uri": "https://example.com",
                        "version": "1",
                        "nonce": "nonce-123",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": [{
                        "chainId": pay_kit::x402::exact::SOLANA_MAINNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(payment_required.to_string().as_bytes());
        let headers = vec![(pay_kit::x402::PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let outcome = classify_402(&headers, None, "https://example.com/resource");

        match outcome {
            RunOutcome::X402SignInChallenge {
                challenge,
                resource_url,
                ..
            } => {
                assert_eq!(challenge.extension.nonce, "nonce-123");
                assert_eq!(resource_url, "https://example.com/resource");
            }
            other => panic!("expected X402SignInChallenge, got {other:?}"),
        }
    }

    #[test]
    fn classify_402_prefers_signin_with_payment_fallback() {
        use base64::Engine;

        let selected = serde_json::json!({
            "scheme": pay_kit::x402::exact::EXACT_SCHEME,
            "network": pay_kit::x402::exact::SOLANA_MAINNET,
            "amount": "10000",
            "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "payTo": "6cvgmdrsVxyiuPzqMCSBnS7fAmA5Mk2VG4BcfVhC8jdC",
            "maxTimeoutSeconds": 300
        });
        let payment_required = serde_json::json!({
            pay_kit::x402::X402_VERSION_FIELD: pay_kit::x402::X402_VERSION_V2,
            "accepts": [selected],
            "extensions": {
                "sign-in-with-x": {
                    "info": {
                        "domain": "example.com",
                        "uri": "https://example.com",
                        "version": "1",
                        "nonce": "nonce-123",
                        "issuedAt": "2026-04-27T00:00:00Z"
                    },
                    "supportedChains": [{
                        "chainId": pay_kit::x402::exact::SOLANA_MAINNET,
                        "type": "ed25519",
                        "signatureScheme": "siws"
                    }]
                }
            }
        });
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(payment_required.to_string().as_bytes());
        let headers = vec![(pay_kit::x402::PAYMENT_REQUIRED_HEADER.to_string(), encoded)];

        let outcome = classify_402(&headers, None, "https://example.com/resource");

        // Prefer sign-in (spend credits) over paying when both are offered,
        // but keep the payment option as a fallback for the no-credits case.
        match outcome {
            RunOutcome::X402SignInChallenge {
                challenge,
                payment_fallback,
                ..
            } => {
                assert_eq!(challenge.extension.nonce, "nonce-123");
                let pay = payment_fallback.expect("payment option preserved as fallback");
                assert_eq!(pay.requirements.amount, "10000");
            }
            other => panic!("expected X402SignInChallenge, got {other:?}"),
        }
    }

    #[test]
    fn classify_402_rejects_evm_only_mpp_with_clear_error() {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // MPP challenge with EVM-style Tempo recipient (not Solana)
        let request_json = serde_json::json!({
            "amount": "10000",
            "currency": "0x20c00000000000000000000b9537d11c60e8b50",
            "methodDetails": { "chainId": 4217 },
            "recipient": "0x325bdF6F7efAB24a2210c48c1b64cAb2eAe1d430"
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"test\", realm=\"test\", method=\"tempo\", intent=\"charge\", request=\"{b64}\""
            ),
        )];

        // EVM-only MPP with no x402 fallback → clear rejection
        let outcome = classify_402(&headers, None, "https://evm-only.example.com/api");
        match outcome {
            RunOutcome::PaymentRejected { reason, .. } => {
                assert!(
                    reason.contains("non-Solana"),
                    "Expected non-Solana message, got: {reason}"
                );
            }
            other => panic!("Expected PaymentRejected, got: {other:?}"),
        }
    }

    #[test]
    fn classify_402_without_mpp() {
        let headers = vec![("content-type".to_string(), "text/html".to_string())];
        let outcome = classify_402(&headers, None, "https://example.com/resource");
        assert!(matches!(outcome, RunOutcome::UnknownPaymentRequired { .. }));
    }

    // ── parse_verification_failure ──────────────────────────────────────────

    #[test]
    fn parse_verification_failure_full_payload() {
        let body = r#"{"error":"verification_failed","message":"transaction not found on devnet","retryable":false}"#;
        let parsed = parse_verification_failure(Some(body));
        assert_eq!(
            parsed,
            Some(("transaction not found on devnet".to_string(), false))
        );
    }

    #[test]
    fn parse_verification_failure_retryable_true() {
        let body = r#"{"error":"verification_failed","message":"rpc temporarily unavailable","retryable":true}"#;
        let parsed = parse_verification_failure(Some(body));
        assert_eq!(
            parsed,
            Some(("rpc temporarily unavailable".to_string(), true))
        );
    }

    #[test]
    fn parse_verification_failure_accepts_session_failure() {
        let body = r#"{"error":"session_failed","message":"open transaction not visible","retryable":true}"#;
        let parsed = parse_verification_failure(Some(body));
        assert_eq!(
            parsed,
            Some(("open transaction not visible".to_string(), true))
        );
    }

    #[test]
    fn parse_verification_failure_missing_message_uses_default() {
        let body = r#"{"error":"verification_failed","retryable":false}"#;
        let parsed = parse_verification_failure(Some(body));
        assert_eq!(
            parsed,
            Some(("payment verification failed".to_string(), false))
        );
    }

    #[test]
    fn parse_verification_failure_missing_retryable_defaults_false() {
        let body = r#"{"error":"verification_failed","message":"bad signature"}"#;
        let parsed = parse_verification_failure(Some(body));
        assert_eq!(parsed, Some(("bad signature".to_string(), false)));
    }

    #[test]
    fn parse_verification_failure_wrong_error_field() {
        // First-call 402 challenge body — must NOT be treated as a rejection.
        let body = r#"{"error":"payment_required","message":"This endpoint requires payment."}"#;
        assert_eq!(parse_verification_failure(Some(body)), None);
    }

    #[test]
    fn parse_verification_failure_not_json() {
        assert_eq!(parse_verification_failure(Some("not json at all")), None);
    }

    #[test]
    fn parse_verification_failure_empty_string() {
        assert_eq!(parse_verification_failure(Some("")), None);
        assert_eq!(parse_verification_failure(Some("   ")), None);
    }

    #[test]
    fn parse_verification_failure_none() {
        assert_eq!(parse_verification_failure(None), None);
    }

    #[test]
    fn classify_402_verification_failed_wins_over_challenge() {
        // Even if a fresh www-authenticate challenge is present, a
        // verification_failed body must take precedence — otherwise the
        // client would loop into a second pay-and-retry instead of
        // surfacing why the first payment was rejected.
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": { "network": "devnet" }
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"test-id\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
            ),
        )];
        let body = r#"{"error":"verification_failed","message":"wrong network: expected localnet","retryable":false}"#;

        let outcome = classify_402(&headers, Some(body), "https://example.com/resource");
        match outcome {
            RunOutcome::PaymentRejected {
                reason, retryable, ..
            } => {
                assert_eq!(reason, "wrong network: expected localnet");
                assert!(!retryable);
            }
            other => panic!("expected PaymentRejected, got {other:?}"),
        }
    }

    #[test]
    fn classify_402_unrelated_body_falls_through_to_challenge() {
        // First-call 402 with a JSON body that isn't verification_failed —
        // we still detect the MPP challenge from headers.
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": { "network": "devnet" }
        });
        let b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request_json).unwrap());
        let headers = vec![(
            "www-authenticate".to_string(),
            format!(
                "Payment id=\"test-id\", realm=\"test\", method=\"solana\", intent=\"charge\", request=\"{b64}\""
            ),
        )];
        let body = r#"{"error":"payment_required","message":"This endpoint requires payment."}"#;

        let outcome = classify_402(&headers, Some(body), "https://example.com/resource");
        assert!(matches!(outcome, RunOutcome::MppChallenge { .. }));
    }

    #[test]
    fn find_url_from_args() {
        let args: Vec<String> = vec![
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "https://example.com/api",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        assert_eq!(
            find_url_in_args(&args),
            Some("https://example.com/api".to_string())
        );
    }

    #[test]
    fn parsed_curl_request_extracts_method_url_and_json_body() {
        let args = vec![
            "--json".to_string(),
            r#"{"query":"solana"}"#.to_string(),
            "https://example.com/api/search".to_string(),
        ];

        assert_eq!(
            ParsedCurlRequest::from_args(&args),
            ParsedCurlRequest {
                url: Some("https://example.com/api/search".to_string()),
                method: "POST".to_string(),
                body: Some(r#"{"query":"solana"}"#.to_string()),
            }
        );
    }

    #[test]
    fn parsed_curl_request_honors_explicit_request_and_url_flags() {
        let args = vec![
            "--request=PATCH".to_string(),
            "--data-raw".to_string(),
            r#"{"name":"pay"}"#.to_string(),
            "--url".to_string(),
            "https://example.com/api/item".to_string(),
        ];

        assert_eq!(
            ParsedCurlRequest::from_args(&args),
            ParsedCurlRequest {
                url: Some("https://example.com/api/item".to_string()),
                method: "PATCH".to_string(),
                body: Some(r#"{"name":"pay"}"#.to_string()),
            }
        );
    }

    #[test]
    fn parsed_wget_request_extracts_post_data() {
        let args = vec![
            "--post-data".to_string(),
            r#"{"productUrl":"https://example.com/item"}"#.to_string(),
            "https://api.example.com/x402/buy".to_string(),
        ];

        assert_eq!(
            ParsedWgetRequest::from_args(&args),
            ParsedWgetRequest {
                url: Some("https://api.example.com/x402/buy".to_string()),
                method: "POST".to_string(),
                body: Some(r#"{"productUrl":"https://example.com/item"}"#.to_string()),
            }
        );
    }

    #[test]
    fn parsed_wget_request_honors_explicit_method() {
        let args = vec![
            "--method=PUT".to_string(),
            "--body-data={\"name\":\"pay\"}".to_string(),
            "https://api.example.com/items/1".to_string(),
        ];

        assert_eq!(
            ParsedWgetRequest::from_args(&args),
            ParsedWgetRequest {
                url: Some("https://api.example.com/items/1".to_string()),
                method: "PUT".to_string(),
                body: Some(r#"{"name":"pay"}"#.to_string()),
            }
        );
    }

    #[test]
    fn parsed_wget_request_body_file_defaults_to_post_without_body_for_validation() {
        let args = vec![
            "--body-file".to_string(),
            "payload.json".to_string(),
            "https://api.example.com/items".to_string(),
        ];

        assert_eq!(
            ParsedWgetRequest::from_args(&args),
            ParsedWgetRequest {
                url: Some("https://api.example.com/items".to_string()),
                method: "POST".to_string(),
                body: None,
            }
        );
    }

    #[test]
    fn find_url_none_when_missing() {
        let args: Vec<String> = vec!["-v", "--compressed"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(find_url_in_args(&args), None);
    }

    #[test]
    fn find_url_http() {
        let args = vec!["http://localhost:8080/test".to_string()];
        assert_eq!(
            find_url_in_args(&args),
            Some("http://localhost:8080/test".to_string())
        );
    }

    #[test]
    fn find_url_returns_first_url_when_multiple_present() {
        let args = vec![
            "https://first.example.com".to_string(),
            "https://second.example.com".to_string(),
        ];
        assert_eq!(
            find_url_in_args(&args),
            Some("https://first.example.com".to_string())
        );
    }

    #[test]
    fn parse_empty_headers() {
        let (status, headers) = parse_http_headers("");
        assert_eq!(status, None);
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_status_only() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n";
        let (status, headers) = parse_http_headers(raw);
        assert_eq!(status, Some(200));
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_http2_status() {
        let raw = "HTTP/2 404 Not Found\r\nContent-Type: text/html\r\n\r\n";
        let (status, headers) = parse_http_headers(raw);
        assert_eq!(status, Some(404));
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn parse_headers_lowercase_keys() {
        let raw =
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Custom-Header: value\r\n\r\n";
        let (_, headers) = parse_http_headers(raw);
        // Keys should be lowercased
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
        assert!(headers.iter().any(|(k, _)| k == "x-custom-header"));
    }

    #[test]
    fn parse_headers_preserves_colons_in_values() {
        let raw = "HTTP/1.1 200 OK\r\nLocation: https://example.com/a:b\r\n\r\n";
        let (_, headers) = parse_http_headers(raw);
        assert_eq!(
            headers.iter().find(|(k, _)| k == "location").unwrap().1,
            "https://example.com/a:b"
        );
    }

    #[test]
    fn parse_http_headers_skips_lines_without_colon() {
        let raw = "HTTP/1.1 200 OK\r\nnot-a-header\r\nContent-Type: text/plain\r\n\r\n";
        let (_, headers) = parse_http_headers(raw);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "content-type");
    }

    #[test]
    fn parse_wget_empty() {
        let (status, headers) = parse_wget_headers("");
        assert_eq!(status, None);
        assert!(headers.is_empty());
    }

    #[test]
    fn parse_wget_redirect_chain() {
        let stderr = r#"
  HTTP/1.1 301 Moved Permanently
  Location: https://new.example.com
  HTTP/1.1 200 OK
  Content-Type: text/html
"#;
        let (status, headers) = parse_wget_headers(stderr);
        assert_eq!(status, Some(200));
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
    }

    #[test]
    fn parse_wget_skips_lines_with_spaces_in_key() {
        let stderr = r#"
  HTTP/1.1 200 OK
  Content-Type: text/html
  not a header line
"#;
        let (status, headers) = parse_wget_headers(stderr);
        assert_eq!(status, Some(200));
        // "not a header line" has spaces in key, should be skipped
        assert_eq!(headers.len(), 1);
    }

    #[test]
    fn parse_wget_returns_none_when_no_http_status_seen() {
        let stderr = "Resolving example.com... connected.";
        let (status, headers) = parse_wget_headers(stderr);
        assert_eq!(status, None);
        assert!(headers.is_empty());
    }

    #[test]
    fn classify_402_empty_headers() {
        let outcome = classify_402(&[], None, "https://example.com");
        assert!(matches!(outcome, RunOutcome::UnknownPaymentRequired { .. }));
    }

    #[test]
    fn classify_402_preserves_resource_url() {
        let outcome = classify_402(&[], None, "https://api.example.com/data");
        match outcome {
            RunOutcome::UnknownPaymentRequired { resource_url, .. } => {
                assert_eq!(resource_url, "https://api.example.com/data");
            }
            _ => panic!("Expected UnknownPaymentRequired"),
        }
    }

    // ── parse_httpie_output / strip_ansi ─────────────────────────────────

    #[test]
    fn strip_ansi_removes_csi_sequences() {
        let raw = "\x1b[34mHTTP\x1b[39;49;00m/\x1b[34m1.1\x1b[39;49;00m \x1b[34m200\x1b[39;49;00m \x1b[36mOK\x1b[39;49;00m";
        assert_eq!(strip_ansi(raw), "HTTP/1.1 200 OK");
    }

    #[test]
    fn strip_ansi_passes_through_plain_text() {
        assert_eq!(
            strip_ansi("plain text\nno escapes"),
            "plain text\nno escapes"
        );
    }

    #[test]
    fn parse_httpie_basic_response() {
        let raw = "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 13\n\n{\"ok\":true}\n";
        let (status, headers, body) = parse_httpie_output(raw);
        assert_eq!(status, Some(200));
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "content-type");
        // `lines()` strips line terminators; the rejoined body has no trailing \n.
        assert_eq!(body.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn parse_httpie_402_response() {
        let raw = "HTTP/1.1 402 Payment Required\nWWW-Authenticate: Payment realm=\"x\"\n\n{\"error\":\"verification_failed\",\"message\":\"bad\",\"retryable\":false}";
        let (status, headers, body) = parse_httpie_output(raw);
        assert_eq!(status, Some(402));
        assert!(headers.iter().any(|(k, _)| k == "www-authenticate"));
        assert!(body.as_deref().unwrap().contains("verification_failed"));
    }

    #[test]
    fn parse_httpie_verbose_mode_picks_response_status() {
        // -v prints request first (with `METHOD /path HTTP/1.1` line, NOT
        // starting with `HTTP/`), then response.
        let raw = "GET /api HTTP/1.1\nHost: example.com\nUser-Agent: HTTPie/3.2.4\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":1}";
        let (status, headers, body) = parse_httpie_output(raw);
        assert_eq!(status, Some(200));
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "application/json")
        );
        // Request headers (host, user-agent) must not bleed into response
        // headers — `Host` is set by the client, never echoed by the server here.
        assert!(!headers.iter().any(|(k, _)| k == "host"));
        assert_eq!(body.as_deref(), Some("{\"ok\":1}"));
    }

    #[test]
    fn parse_httpie_history_is_not_reparsed_from_response_body() {
        let raw = "HTTP/1.1 302 Found\nLocation: https://example.com/final\n\nredirecting\nHTTP/1.1 200 OK\nContent-Type: application/json\nPayment-Response: encoded-settlement\n\n{\"ok\":true}";
        let (status, headers, body) = parse_httpie_output(raw);

        assert_eq!(status, Some(302));
        assert!(
            headers.iter().any(|(name, value)| {
                name == "location" && value == "https://example.com/final"
            })
        );
        assert!(!headers.iter().any(|(name, _)| name == "payment-response"));
        assert_eq!(
            body.as_deref(),
            Some(
                "redirecting\nHTTP/1.1 200 OK\nContent-Type: application/json\nPayment-Response: encoded-settlement\n\n{\"ok\":true}"
            )
        );
    }

    #[test]
    fn parse_httpie_200_body_cannot_inject_payment_required_response() {
        let raw = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nharmless body\nHTTP/1.1 402 Payment Required\nPayment-Required: attacker-controlled-challenge\n\ncharge me";
        let (status, headers, body) = parse_httpie_output(raw);

        assert_eq!(status, Some(200));
        assert_eq!(headers, vec![("content-type".into(), "text/plain".into())]);
        assert_eq!(
            body.as_deref(),
            Some(
                "harmless body\nHTTP/1.1 402 Payment Required\nPayment-Required: attacker-controlled-challenge\n\ncharge me"
            )
        );
    }

    #[test]
    fn parse_httpie_http2_status() {
        let raw = "HTTP/2 404 Not Found\nContent-Type: text/html\n\n<html/>";
        let (status, _, _) = parse_httpie_output(raw);
        assert_eq!(status, Some(404));
    }

    #[test]
    fn parse_httpie_handles_pretty_ansi() {
        // Mimics --pretty=all output: status + first header colorized.
        let raw = "\x1b[34mHTTP\x1b[39;49;00m/\x1b[34m1.1\x1b[39;49;00m \x1b[34m402\x1b[39;49;00m \x1b[36mPayment Required\x1b[39;49;00m\n\x1b[36mContent-Type\x1b[39;49;00m: application/json\n\n{\"error\":\"x\"}";
        let (status, headers, body) = parse_httpie_output(raw);
        assert_eq!(status, Some(402));
        assert!(headers.iter().any(|(k, _)| k == "content-type"));
        assert_eq!(body.as_deref(), Some("{\"error\":\"x\"}"));
    }

    #[test]
    fn parse_httpie_no_body() {
        // HEAD response or 204: headers but no blank line + body.
        let raw = "HTTP/1.1 204 No Content\nDate: now\n";
        let (status, headers, body) = parse_httpie_output(raw);
        assert_eq!(status, Some(204));
        assert_eq!(headers.len(), 1);
        assert!(body.is_none());
    }

    #[test]
    fn parse_httpie_empty_input() {
        let (status, headers, body) = parse_httpie_output("");
        assert_eq!(status, None);
        assert!(headers.is_empty());
        assert!(body.is_none());
    }

    #[test]
    fn check_command_exists_finds_ls() {
        // `ls` should exist on any unix system
        assert!(check_command_exists("ls").is_ok());
    }

    #[test]
    fn check_command_exists_fails_for_nonexistent() {
        let result = check_command_exists("nonexistent_command_xyz_12345");
        assert!(result.is_err());
    }
}
