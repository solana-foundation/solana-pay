//! 402-paying local reverse proxy for agent launchers.
//!
//! Some agent CLIs cannot handle HTTP 402 payment challenges, so they cannot
//! talk to a priced inference gateway directly. This proxy sits between the
//! agent process and the upstream (`pay gate inference`, a hosted paid
//! provider, or a bare local provider in direct mode):
//!
//! 1. Every request is forwarded upstream, preserving method, path+query,
//!    and headers (minus hop-by-hop). The request body is buffered (capped
//!    at [`MAX_BODY_BYTES`]) so it can be replayed.
//! 2. When the upstream answers `402 Payment Required`, the proxy satisfies
//!    the configured payment protocol and retries the buffered request once.
//!    Hosted inference routes can require an MPP delegated session; the
//!    resulting channel authorization is cached for the lifetime of the agent
//!    process so subsequent completions do not create new on-chain payments.
//! 3. Response bodies stream back ([`Body::from_stream`]).
//! 4. If payment fails for any reason (mainnet challenge under
//!    `--sandbox`, insufficient funds, signer errors, …) the original 402
//!    is passed through untouched, with a `tracing::warn!` explaining why.
//!
//! Sandbox/network intent is enforced by the reused `build_credential`
//! path: with `--sandbox` the CLI forces `network_override = localnet`,
//! and `pay_core::mpp::check_client_network_intent` refuses to sign when
//! the challenge advertises a different network (e.g. mainnet).
//!
//! **Dialects.** The current caller is `pay claude`, which sends
//! Anthropic-shaped `POST /v1/messages` requests. When its upstream speaks
//! OpenAI chat completions ([`Dialect::OpenAiCompat`] — vLLM, LM Studio,
//! llama.cpp, Alibaba Model Studio's compatible mode), those requests are
//! translated to OpenAI shape (see [`crate::commands::agent::translate`]),
//! sent to the upstream's chat-completions path, and translated back to an
//! Anthropic envelope. The payment retry composes with translation: the
//! challenge fires on the translated request, so the retry replays the
//! translated body. Other requests and dialects pass through untouched.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use pay_core::accounts::{
    AccountChoice, AccountsStore, FileAccountsStore, MAINNET_NETWORK,
    load_or_create_ephemeral_for_network, load_or_create_ephemeral_for_network_as,
    resolve_account_for_network,
};
#[cfg(test)]
use pay_kit::x402::PAYMENT_RESPONSE_HEADER;

use super::agent::translate;
use crate::commands::server::inference::providers::Dialect;

/// Request bodies are buffered so the paid retry can replay them; cap the
/// buffer so a runaway client cannot exhaust memory.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// The payer proxy is an implementation detail shared only with the child
/// agent process. Never bind it to a LAN-reachable interface.
const PAYER_PROXY_BIND_IP: Ipv4Addr = Ipv4Addr::LOCALHOST;

/// Handle returned by [`start_background`].
pub struct PayerProxy {
    /// Base URL of the payer proxy, e.g. `http://127.0.0.1:52341`.
    pub base_url: String,
    /// Pubkey of the wallet that funds 402 retries, when resolvable at
    /// startup (in sandbox mode the ephemeral localnet wallet is created
    /// eagerly so the pubkey is always known).
    pub payer_pubkey: Option<String>,
}

/// Payment contract the local payer must enforce for its upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentProtocol {
    /// Preserve the generic payer behavior: MPP charge first, then x402
    /// `upto`, then x402 `exact`.
    Auto,
    /// Require a delegated MPP session and never fall back to x402.
    MppSession,
}

/// Where the payer forwards to, and how to talk to it.
#[derive(Clone)]
pub struct PayerUpstream {
    /// Upstream base URL, e.g. `http://127.0.0.1:11434` or
    /// `https://modelstudio.alibaba.gateway-402.com`.
    pub base_url: String,
    /// Optional Host header for the upstream leg. Used when connecting to a
    /// local gateway by IP while preserving its subdomain router.
    pub host_header: Option<String>,
    /// Chat-API wire dialect of the upstream. [`Dialect::Anthropic`]
    /// passes through; [`Dialect::OpenAiCompat`] translates
    /// `POST /v1/messages`; anything else passes through untranslated
    /// (the launcher warns about those picks).
    pub dialect: Dialect,
    /// Chat-completions path (gate convention, no leading slash) that
    /// translated requests are sent to, e.g. `v1/chat/completions` or
    /// Alibaba's `compatible-mode/v1/chat/completions`.
    pub chat_path: String,
    /// Responses API path used by Codex, e.g. `v1/responses`.
    pub responses_path: String,
    /// Refuse successful responses that were served without a 402 handshake.
    /// Hosted catalog providers set this so a gateway routing mistake cannot
    /// silently bypass metering and consume upstream credentials for free.
    pub require_payment: bool,
    /// Payment protocol required by this route.
    pub payment_protocol: PaymentProtocol,
}

/// Shared state for the proxy handlers.
struct PayerState {
    /// Upstream base URL without a trailing slash.
    upstream: String,
    /// Logical provider URL shown in session spending authorization.
    authorization_url: String,
    host_header: Option<HeaderValue>,
    dialect: Dialect,
    /// Chat-completions path without a leading slash (translation target).
    chat_path: String,
    responses_path: String,
    require_payment: bool,
    payment_protocol: PaymentProtocol,
    /// Cached delegated-session authorization. Holding the mutex serializes
    /// requests because the server reserves a session's remaining capacity
    /// while it meters a response.
    session_authorization: pay_core::session_manager::SessionSlot,
    session_opener: SessionOpener,
    client: reqwest::Client,
    store: Arc<dyn AccountsStore>,
    /// Forced network slug (`--sandbox` → `localnet`, `--mainnet` →
    /// `mainnet`). `None` trusts the challenge's `methodDetails.network`.
    network_override: Option<String>,
    /// `--account` override, same semantics as the curl/fetch retry path.
    account_override: Option<String>,
    /// Optional per-request spend cap (base units of the challenge asset). When
    /// set, an x402-upto ceiling above this is refused and the 402 passes
    /// through. `None` (today's default) authorizes whatever the challenge
    /// advertises, matching the MPP path's unbudgeted behavior.
    per_request_cap_base_units: Option<u128>,
}

impl PayerState {
    fn new(
        upstream: PayerUpstream,
        store: Arc<dyn AccountsStore>,
        network_override: Option<String>,
        account_override: Option<String>,
    ) -> pay_core::Result<Self> {
        let host_header = upstream
            .host_header
            .as_deref()
            .map(HeaderValue::from_str)
            .transpose()
            .map_err(|e| pay_core::Error::Config(format!("payer proxy Host header: {e}")))?;
        let parsed_upstream = reqwest::Url::parse(&upstream.base_url)
            .map_err(|e| pay_core::Error::Config(format!("payer proxy upstream URL: {e}")))?;
        let authorization_url = match upstream.host_header.as_deref() {
            Some(host) => format!("{}://{host}", parsed_upstream.scheme()),
            None => upstream.base_url.clone(),
        };
        // Do not impose a total request timeout: streamed completions may stay
        // open for minutes. Bound connection setup and silent read stalls so a
        // hung provider cannot retain the session mutex forever.
        // `no_proxy` keeps env proxies from hijacking localhost traffic.
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(300))
            .build()
            .map_err(|e| pay_core::Error::Config(format!("payer proxy HTTP client: {e}")))?;
        Ok(Self {
            upstream: upstream.base_url.trim_end_matches('/').to_string(),
            authorization_url,
            host_header,
            dialect: upstream.dialect,
            chat_path: upstream.chat_path.trim_start_matches('/').to_string(),
            responses_path: upstream.responses_path.trim_start_matches('/').to_string(),
            require_payment: upstream.require_payment,
            payment_protocol: upstream.payment_protocol,
            session_authorization: pay_core::session_manager::SessionSlot::default(),
            session_opener: build_session_authorization,
            client,
            store,
            network_override,
            account_override,
            per_request_cap_base_units: None,
        })
    }

    #[cfg(test)]
    fn with_session_opener(mut self, session_opener: SessionOpener) -> Self {
        self.session_opener = session_opener;
        self
    }
}

type SessionOpener =
    fn(&PayerState, &pay_core::mpp::Challenge) -> pay_core::Result<(PaidHeaders, String)>;

/// Start the payer proxy on an ephemeral 127.0.0.1 port, on a dedicated
/// runtime in a background thread (the `pay claude` main thread stays
/// sync and blocks on the `claude` child process). Returns once the
/// listener is bound.
pub fn start_background(
    upstream: PayerUpstream,
    network_override: Option<&str>,
    account_override: Option<&str>,
) -> pay_core::Result<PayerProxy> {
    let store: Arc<dyn AccountsStore> = Arc::new(FileAccountsStore::default_path());
    let state = Arc::new(PayerState::new(
        upstream,
        store,
        network_override.map(str::to_string),
        account_override.map(str::to_string),
    )?);
    let payer_pubkey = resolve_payer_pubkey(&state);

    let (tx, rx) = std::sync::mpsc::channel::<std::result::Result<SocketAddr, String>>();
    let serve_state = state.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                let _ = tx.send(Err(format!("payer proxy runtime: {e}")));
                return;
            }
        };
        rt.block_on(async move {
            let listener = match tokio::net::TcpListener::bind((PAYER_PROXY_BIND_IP, 0)).await {
                Ok(listener) => listener,
                Err(e) => {
                    let _ = tx.send(Err(format!("payer proxy bind: {e}")));
                    return;
                }
            };
            let addr = match listener.local_addr() {
                Ok(addr) => addr,
                Err(e) => {
                    let _ = tx.send(Err(format!("payer proxy local_addr: {e}")));
                    return;
                }
            };
            let _ = tx.send(Ok(addr));
            axum::serve(listener, router(serve_state)).await.ok();
        });
    });

    let addr = match rx.recv() {
        Ok(Ok(addr)) => addr,
        Ok(Err(e)) => return Err(pay_core::Error::Config(e)),
        Err(_) => {
            return Err(pay_core::Error::Config(
                "payer proxy thread exited before binding".to_string(),
            ));
        }
    };

    Ok(PayerProxy {
        base_url: format!("http://{addr}"),
        payer_pubkey,
    })
}

/// Resolve the pubkey that will fund payments, mirroring the wallet
/// routing of the curl/fetch retry path: `networks.<network>` mapping
/// first (honoring `--account`), then lazy ephemeral creation for
/// throwaway networks (`--sandbox` localnet uses the exact same wallet
/// `pay --sandbox curl` spends from). Never auto-creates a mainnet
/// wallet.
fn resolve_payer_pubkey(state: &PayerState) -> Option<String> {
    let network = state.network_override.as_deref().unwrap_or(MAINNET_NETWORK);
    let file = state.store.load().ok()?;

    if let Some(name) = state.account_override.as_deref() {
        if let Some(pubkey) = file
            .named_account_for_network(network, name)
            .and_then(|account| account.pubkey.clone())
        {
            return Some(pubkey);
        }
    } else if let AccountChoice::Resolved { account, .. } =
        resolve_account_for_network(network, &file)
        && account.pubkey.is_some()
    {
        return account.pubkey;
    }

    if matches!(network, "localnet" | "devnet") {
        let resolved = match state.account_override.as_deref() {
            Some(name) => {
                load_or_create_ephemeral_for_network_as(network, name, state.store.as_ref())
            }
            None => load_or_create_ephemeral_for_network(network, state.store.as_ref()),
        }
        .ok()?;
        return resolved.account.pubkey;
    }

    None
}

fn router(state: Arc<PayerState>) -> Router {
    Router::new().fallback(any(proxy)).with_state(state)
}

async fn proxy(State(state): State<Arc<PayerState>>, req: Request) -> Response {
    let method = req.method().clone();
    let headers = req.headers().clone();
    let path = req.uri().path().to_string();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    // Buffer the request body so a paid retry can replay it verbatim.
    let body = match axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(e) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("payer proxy: request body over {MAX_BODY_BYTES} bytes or unreadable: {e}"),
            )
                .into_response();
        }
    };

    // Normalize OpenAI Chat Completions before the send/402 loop so paid
    // retries replay the exact same compatible body. Goose uses the newer
    // `developer` role for GPT-5, while some compatible providers only
    // accept the older `system` role.
    let body = normalize_openai_chat_request(&state, &method, &path, &body);

    // Anthropic → OpenAI request translation for OpenAI-compatible
    // upstreams. This also happens before the send/402 loop.
    let (url, body, translated) = match translate_request(&state, &method, &path, &body) {
        Some(openai_body) => (
            format!("{}/{}", state.upstream, state.chat_path),
            openai_body,
            true,
        ),
        None => (
            passthrough_upstream_url(&state, &method, &path, &path_query),
            body,
            false,
        ),
    };

    // A delegated session is shared across every request made by this agent
    // process. Keep the guard until the gateway has accepted and metered this
    // response so two concurrent calls cannot reserve the same channel cap.
    let mut session_authorization = if state.payment_protocol == PaymentProtocol::MppSession {
        Some(state.session_authorization.acquire().await)
    } else {
        None
    };
    let cached_payment = session_authorization
        .as_ref()
        .and_then(pay_core::session_manager::SessionLease::authorization)
        .map(str::to_string)
        .map(PaidHeaders::mpp);
    let used_cached_session = cached_payment.is_some();

    let first = match send_upstream(
        &state,
        &method,
        &url,
        &headers,
        body.clone(),
        cached_payment.as_ref(),
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(%url, error = %e, "payer proxy: upstream request failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("payer proxy: upstream error: {e}"),
            )
                .into_response();
        }
    };

    if first.status() != StatusCode::PAYMENT_REQUIRED {
        if requires_payment_challenge(&state, &method, &path)
            && first.status().is_success()
            && !used_cached_session
        {
            tracing::error!(%url, status = %first.status(), "payer proxy: hosted provider bypassed its payment gate");
            let message = if path.trim_matches('/') == "v1/responses" {
                "payer proxy: the hosted Responses endpoint is not payment-enabled; deploy its Agent Gateway provider spec before using Codex"
            } else {
                "payer proxy: hosted provider returned success without a payment challenge; refusing an ungated response"
            };
            return (StatusCode::BAD_GATEWAY, message).into_response();
        }
        return deliver(first, translated, session_authorization.take()).await;
    }

    // Buffer the 402 so it can be passed through untouched when payment
    // is impossible. 402 bodies are small (a JSON error envelope).
    let mut status = first.status();
    let mut resp_headers = first.headers().clone();
    let mut resp_body = match first.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(%url, error = %e, "payer proxy: failed to read 402 body");
            return (
                StatusCode::BAD_GATEWAY,
                format!("payer proxy: upstream error: {e}"),
            )
                .into_response();
        }
    };

    let mut mpp_challenges = pay_core::mpp::parse_all(
        resp_headers
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    );

    let mut has_session_challenge = mpp_challenges.iter().any(|challenge| {
        challenge.method.as_str() == "solana" && challenge.intent.as_str() == "session"
    });

    if state.payment_protocol == PaymentProtocol::MppSession
        && used_cached_session
        && !has_session_challenge
        && retryable_cached_session_error(&resp_body)
    {
        tracing::info!(%url, "payer proxy: retrying transient cached MPP session rejection");
        tokio::time::sleep(Duration::from_millis(25)).await;
        let retried = match send_upstream(
            &state,
            &method,
            &url,
            &headers,
            body.clone(),
            cached_payment.as_ref(),
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%url, %error, "payer proxy: cached MPP session retry failed");
                return buffered_response(status, &resp_headers, resp_body);
            }
        };
        if retried.status() != StatusCode::PAYMENT_REQUIRED {
            return deliver(retried, translated, session_authorization.take()).await;
        }
        status = retried.status();
        resp_headers = retried.headers().clone();
        resp_body = match retried.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%url, %error, "payer proxy: failed to read cached MPP session retry");
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("payer proxy: upstream error: {error}"),
                )
                    .into_response();
            }
        };
        mpp_challenges = pay_core::mpp::parse_all(
            resp_headers
                .get_all(header::WWW_AUTHENTICATE)
                .iter()
                .filter_map(|value| value.to_str().ok()),
        );
        has_session_challenge = mpp_challenges.iter().any(|challenge| {
            challenge.method.as_str() == "solana" && challenge.intent.as_str() == "session"
        });
    }

    // A cached operator-signed session is represented by its reusable `use`
    // credential. Only a definitive terminal error or a fresh session
    // challenge proves that the cached channel should be replaced. Transient
    // store contention must preserve it for the next request.
    if state.payment_protocol == PaymentProtocol::MppSession
        && used_cached_session
        && !has_session_challenge
        && !terminal_cached_session_error(&resp_body)
    {
        tracing::warn!(%url, "payer proxy: preserving cached MPP session after non-terminal 402");
        return buffered_response(status, &resp_headers, resp_body);
    }

    if state.payment_protocol == PaymentProtocol::MppSession
        && used_cached_session
        && !has_session_challenge
    {
        if let Some(cached) = session_authorization.as_mut() {
            cached.clear();
        }
        tracing::info!(%url, "payer proxy: cached MPP session ended; requesting a fresh challenge");
        let refreshed = match send_upstream(&state, &method, &url, &headers, body.clone(), None)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(%url, %error, "payer proxy: failed to refresh MPP session challenge");
                return buffered_response(status, &resp_headers, resp_body);
            }
        };
        if refreshed.status() != StatusCode::PAYMENT_REQUIRED {
            if requires_payment_challenge(&state, &method, &path) && refreshed.status().is_success()
            {
                tracing::error!(%url, status = %refreshed.status(), "payer proxy: hosted provider bypassed its payment gate while refreshing a session");
                return (
                    StatusCode::BAD_GATEWAY,
                    "payer proxy: hosted provider returned success without a payment challenge; refusing an ungated response",
                )
                    .into_response();
            }
            return deliver(refreshed, translated, session_authorization.take()).await;
        }

        status = refreshed.status();
        resp_headers = refreshed.headers().clone();
        resp_body = match refreshed.bytes().await {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(%url, %error, "payer proxy: failed to read refreshed MPP session challenge");
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("payer proxy: upstream error: {error}"),
                )
                    .into_response();
            }
        };
        mpp_challenges = pay_core::mpp::parse_all(
            resp_headers
                .get_all(header::WWW_AUTHENTICATE)
                .iter()
                .filter_map(|value| value.to_str().ok()),
        );
    } else if state.payment_protocol == PaymentProtocol::MppSession
        && used_cached_session
        && let Some(cached) = session_authorization.as_mut()
    {
        cached.clear();
    }

    let charge_challenges: Vec<_> = mpp_challenges
        .iter()
        .filter(|challenge| pay_kit::mpp::client::is_solana_charge_challenge(challenge))
        .cloned()
        .collect();

    let payment = if state.payment_protocol == PaymentProtocol::MppSession {
        let Some(challenge) = mpp_challenges.into_iter().find(|challenge| {
            challenge.method.as_str() == "solana" && challenge.intent.as_str() == "session"
        }) else {
            tracing::error!(%url, "payer proxy: hosted route did not advertise the required MPP session");
            return (
                StatusCode::BAD_GATEWAY,
                "payer proxy: this hosted route requires MPP session, but the gateway did not advertise one",
            )
                .into_response();
        };
        let state = state.clone();
        tokio::task::spawn_blocking(move || {
            (state.session_opener)(&state, &challenge)
                .map(|(payment, authorization)| (payment, Some(authorization)))
        })
        .await
    } else if !charge_challenges.is_empty() {
        // Scheme precedence in auto mode: MPP charge first, then x402 upto,
        // then x402 exact.
        // `select_challenge_by_balance` / `build_credential` spin their own
        // runtimes and may block on RPC + signing — keep them off the async
        // workers.
        let state = state.clone();
        let resource_url = url.clone();
        tokio::task::spawn_blocking(move || {
            build_payment_authorization(&state, &charge_challenges, &resource_url)
                .map(|payment| (payment, None))
        })
        .await
    } else if let Some(upto) = parse_upto_challenge(&resp_headers, &resp_body) {
        // x402 `upto`: open a channel for the advertised ceiling; the gateway
        // settles the actual per-token cost after serving and refunds the rest.
        let state = state.clone();
        let resource_url = url.clone();
        tokio::task::spawn_blocking(move || {
            build_upto_authorization(&state, &upto, &resource_url).map(|payment| (payment, None))
        })
        .await
    } else if let Some(exact) = parse_exact_challenge(&resp_headers, &resp_body) {
        // x402 `exact`: sign this one request. Session and usage-metered
        // channels remain preferred, but an exact-only provider must still
        // work in auto mode.
        let state = state.clone();
        let resource_url = url.clone();
        tokio::task::spawn_blocking(move || {
            build_exact_authorization(&state, &exact, &resource_url).map(|payment| (payment, None))
        })
        .await
    } else {
        tracing::warn!(%url, "payer proxy: 402 without a supported MPP or x402 challenge — passing through");
        return buffered_response(status, &resp_headers, resp_body);
    };

    let (payment, new_session_authorization) = match payment {
        Ok(Ok(payment)) => payment,
        Ok(Err(e)) => {
            tracing::warn!(%url, error = %e, "payer proxy: could not pay 402 — passing it through");
            return buffered_response(status, &resp_headers, resp_body);
        }
        Err(e) => {
            tracing::warn!(%url, error = %e, "payer proxy: payment task failed — passing the 402 through");
            return buffered_response(status, &resp_headers, resp_body);
        }
    };
    tracing::info!(%url, "payer proxy: 402 paid — retrying once with payment credential");
    match send_upstream(&state, &method, &url, &headers, body, Some(&payment)).await {
        Ok(retry) => {
            // Only adopt the new credential once a request has actually gone
            // through on it. Caching it before this point risks stranding a
            // credential for a channel whose open transaction never landed
            // (or whose response was lost) — a use of that credential then
            // fails with a terminal-looking rejection (e.g. "unknown session
            // channel") that never clears without a manual restart.
            if retry.status() == StatusCode::PAYMENT_REQUIRED {
                if let Some(cache) = session_authorization.as_mut() {
                    cache.clear();
                }
            } else if let (Some(cache), Some(authorization)) = (
                session_authorization.as_mut(),
                new_session_authorization.as_ref(),
            ) {
                cache.adopt(authorization.clone());
            }
            deliver(retry, translated, session_authorization.take()).await
        }
        Err(e) => {
            // A transport failure here means we don't know whether the paid
            // request (and, for a first use, the channel open it carried)
            // landed upstream. Leave the cache exactly as it was before this
            // attempt — do not adopt the unconfirmed new credential — so the
            // next request renegotiates instead of reusing a channel that
            // may never have opened.
            tracing::warn!(%url, error = %e, "payer proxy: paid retry failed — preserving the prior session and returning the original 402");
            buffered_response(status, &resp_headers, resp_body)
        }
    }
}

fn cached_session_error_text(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            let error = value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let message = value
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            (!error.is_empty() || !message.is_empty()).then(|| format!("{error} {message}"))
        })
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned())
        .to_ascii_lowercase()
}

fn retryable_cached_session_error(body: &[u8]) -> bool {
    let text = cached_session_error_text(body);
    text.contains("concurrent channel update")
        || text.contains("retry the request")
        || text.contains("session_capacity_reserved")
}

fn terminal_cached_session_error(body: &[u8]) -> bool {
    use pay_core::server::session::terminal_errors;
    let text = cached_session_error_text(body);
    text.contains("session_cap_exhausted")
        || text.contains("session_close_pending")
        || text.contains("already sealed")
        || text.contains("close is pending")
        || text.contains("cap has been exhausted")
        || text.contains("exceeds available deposit")
        || text.contains(terminal_errors::UNKNOWN_CHANNEL)
        || text.contains(terminal_errors::CHALLENGE_ECHO_MISMATCH)
        || text.contains(terminal_errors::OPERATOR_ONLY)
        || text.contains(terminal_errors::PREDATES_PROOF_BINDING)
        || text.contains(terminal_errors::PROOF_MISMATCH)
}

/// Hosted providers must challenge successful inference requests, but model
/// discovery is intentionally public so harnesses can initialize before the
/// first paid completion.
fn requires_payment_challenge(state: &PayerState, method: &Method, path: &str) -> bool {
    state.require_payment && !(*method == Method::GET && path.trim_end_matches('/') == "/v1/models")
}

/// Map standard agent API paths to the selected provider's declared paths.
/// Hosted gateways may expose compatible APIs below a provider prefix.
fn passthrough_upstream_url(
    state: &PayerState,
    method: &Method,
    path: &str,
    path_query: &str,
) -> String {
    if *method == Method::POST {
        let incoming = path.trim_matches('/');
        let target = match incoming {
            "v1/chat/completions" => Some(state.chat_path.as_str()),
            "v1/responses" => Some(state.responses_path.as_str()),
            _ => None,
        };
        if let Some(target) = target
            && target.trim_matches('/') != incoming
        {
            let query = path_query.strip_prefix(path).unwrap_or_default();
            return format!("{}/{}{}", state.upstream, target.trim_matches('/'), query);
        }
    }
    format!("{}{}", state.upstream, path_query)
}

/// Parse an x402 `upto` challenge off the buffered 402 response. `parse_upto`
/// wants `(name, value)` string pairs and an optional body string; build them
/// from the response's headers and (UTF-8) body.
fn parse_upto_challenge(
    resp_headers: &HeaderMap,
    resp_body: &Bytes,
) -> Option<pay_core::client::x402::UptoChallenge> {
    let headers: Vec<(String, String)> = resp_headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let body = std::str::from_utf8(resp_body).ok();
    pay_core::client::x402::parse_upto(&headers, body)
}

/// Parse an x402 `exact` challenge after the preferred `upto` parser has had
/// first refusal. Some upto envelopes are intentionally accepted by the
/// lenient exact parser, so call order is significant.
fn parse_exact_challenge(
    resp_headers: &HeaderMap,
    resp_body: &Bytes,
) -> Option<pay_core::client::x402::Challenge> {
    let headers: Vec<(String, String)> = resp_headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let body = std::str::from_utf8(resp_body).ok();
    pay_core::client::x402::parse(&headers, body)
}

/// Normalize newer OpenAI Chat Completions fields for broadly compatible
/// providers. Invalid or unrelated bodies pass through untouched so the
/// upstream remains responsible for reporting request errors.
fn normalize_openai_chat_request(
    state: &PayerState,
    method: &Method,
    path: &str,
    body: &Bytes,
) -> Bytes {
    if state.dialect != Dialect::OpenAiCompat
        || method != Method::POST
        || path != "/v1/chat/completions"
    {
        return body.clone();
    }

    let Ok(mut request) = serde_json::from_slice::<serde_json::Value>(body) else {
        return body.clone();
    };
    let Some(messages) = request
        .get_mut("messages")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return body.clone();
    };

    let mut changed = false;
    for message in messages {
        if message.get("role").and_then(|role| role.as_str()) == Some("developer") {
            message["role"] = serde_json::Value::String("system".to_string());
            changed = true;
        }
    }
    if !changed {
        return body.clone();
    }

    serde_json::to_vec(&request)
        .map(Bytes::from)
        .unwrap_or_else(|_| body.clone())
}

/// When the upstream is OpenAI-compatible and the inbound request is
/// Claude Code's `POST /v1/messages`, return the translated OpenAI body.
/// `None` means pass through untranslated (wrong dialect/path, or a body
/// that isn't JSON — the upstream will produce the error).
fn translate_request(
    state: &PayerState,
    method: &Method,
    path: &str,
    body: &Bytes,
) -> Option<Bytes> {
    if state.dialect != Dialect::OpenAiCompat || method != Method::POST || path != "/v1/messages" {
        return None;
    }
    let anthropic: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, "payer proxy: /v1/messages body is not JSON — passing through untranslated");
            return None;
        }
    };
    let openai = translate::anthropic_to_openai_request(&anthropic);
    match serde_json::to_vec(&openai) {
        Ok(bytes) => Some(Bytes::from(bytes)),
        Err(e) => {
            tracing::warn!(error = %e, "payer proxy: failed to serialize translated request — passing through");
            None
        }
    }
}

/// Hand an upstream response back to Claude Code: translated (SSE or
/// buffered JSON) when the request was translated and succeeded,
/// streamed passthrough otherwise.
type SessionAuthorizationGuard = pay_core::session_manager::SessionLease;

async fn deliver(
    resp: reqwest::Response,
    translated: bool,
    session_guard: Option<SessionAuthorizationGuard>,
) -> Response {
    if !translated || !resp.status().is_success() {
        return stream_response(resp, session_guard);
    }
    let is_sse = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|ct| ct.contains("text/event-stream"));
    if is_sse {
        translate_stream_response(resp, session_guard)
    } else {
        translate_json_response(resp).await
    }
}

/// Buffer an OpenAI `chat.completion` JSON response and return the
/// Anthropic message envelope. Falls back to raw passthrough when the
/// body isn't JSON.
async fn translate_json_response(resp: reqwest::Response) -> Response {
    let status = resp.status();
    let upstream_headers = resp.headers().clone();
    let bytes = match resp.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::warn!(error = %e, "payer proxy: failed to read upstream response body");
            return (
                StatusCode::BAD_GATEWAY,
                format!("payer proxy: upstream error: {e}"),
            )
                .into_response();
        }
    };
    let openai: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, "payer proxy: upstream response is not JSON — passing through");
            return buffered_response(status, &upstream_headers, bytes);
        }
    };
    let anthropic = translate::openai_to_anthropic_response(&openai);
    let body = serde_json::to_vec(&anthropic).unwrap_or_default();
    let mut builder = Response::builder().status(status);
    if let Some(dst) = builder.headers_mut() {
        copy_translated_response_headers(dst, &upstream_headers);
        dst.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    builder.body(Body::from(body)).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "payer proxy: response build error",
        )
            .into_response()
    })
}

/// Wrap an OpenAI SSE response in the incremental Anthropic-SSE
/// translator — chunks flow as they arrive; a carry-over buffer inside
/// [`translate::StreamTranslator`] reassembles SSE lines split across
/// chunk boundaries.
fn translate_stream_response(
    resp: reqwest::Response,
    session_guard: Option<SessionAuthorizationGuard>,
) -> Response {
    let status = resp.status();
    let upstream_headers = resp.headers().clone();
    let stream_body = Body::from_stream(async_stream::stream! {
        let _session_guard = session_guard;
        let mut resp = resp;
        let mut translator = translate::StreamTranslator::new();
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => {
                    let out = translator.push(&chunk);
                    if !out.is_empty() {
                        yield Ok::<_, std::io::Error>(Bytes::from(out));
                    }
                }
                Ok(None) => {
                    let out = translator.finish();
                    if !out.is_empty() {
                        yield Ok(Bytes::from(out));
                    }
                    break;
                }
                Err(e) => {
                    yield Err(std::io::Error::other(e));
                    break;
                }
            }
        }
    });
    let mut builder = Response::builder().status(status);
    if let Some(dst) = builder.headers_mut() {
        copy_translated_response_headers(dst, &upstream_headers);
        dst.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        );
        dst.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    builder.body(stream_body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "payer proxy: response build error",
        )
            .into_response()
    })
}

/// The header(s) a paid retry must carry. MPP sets
/// `Authorization: Payment <credential>`; x402 `upto` and `exact` set their
/// version-appropriate payment header without clobbering an upstream key.
struct PaidHeaders {
    headers: Vec<(String, String)>,
}

impl PaidHeaders {
    /// The MPP charge credential goes into `Authorization: Payment …`.
    fn mpp(credential: String) -> Self {
        Self {
            headers: vec![(header::AUTHORIZATION.as_str().to_string(), credential)],
        }
    }

    fn x402(headers: Vec<(&'static str, String)>) -> Self {
        Self {
            headers: headers
                .into_iter()
                .map(|(name, value)| (name.to_string(), value))
                .collect(),
        }
    }
}

/// Open an operator-signed session and return the initial `open`
/// authorization plus the reusable `use` credential cached for all subsequent
/// requests handled by this payer proxy.
fn build_session_authorization(
    state: &PayerState,
    challenge: &pay_core::mpp::Challenge,
) -> pay_core::Result<(PaidHeaders, String)> {
    let sandbox = state.network_override.as_deref() == Some("localnet");
    let prepared = pay_core::session_manager::prepare_operator_session_with_override(
        challenge,
        state.store.as_ref(),
        state.network_override.as_deref(),
        state.account_override.as_deref(),
        &state.authorization_url,
        sandbox,
        None,
    )?;
    Ok((
        PaidHeaders::mpp(prepared.open_authorization),
        prepared.use_authorization,
    ))
}

/// Select a payable MPP challenge and build the `Authorization: Payment …`
/// header value — the same two calls `pay curl`'s
/// `pay_mpp_and_retry` makes (crates/cli/src/commands/mod.rs).
fn build_payment_authorization(
    state: &PayerState,
    challenges: &[pay_core::mpp::Challenge],
    resource_url: &str,
) -> pay_core::Result<PaidHeaders> {
    let store = state.store.as_ref();
    let network_override = state.network_override.as_deref();
    let account_override = state.account_override.as_deref();

    let challenge = pay_core::mpp::select_challenge_by_balance(
        challenges,
        store,
        network_override,
        account_override,
    )?
    .ok_or_else(|| {
        pay_core::Error::Mpp(format!(
            "no MPP challenge matched the payer's network context (forced: {})",
            network_override.unwrap_or("auto")
        ))
    })?;

    let (auth_header, ephemeral_notice) = pay_core::mpp::build_credential(
        challenge,
        store,
        network_override,
        account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = ephemeral_notice {
        tracing::info!(
            network = %resolved.network,
            pubkey = resolved.account.pubkey.as_deref().unwrap_or("(unknown)"),
            "payer proxy: generated ephemeral wallet"
        );
    }

    Ok(PaidHeaders::mpp(auth_header))
}

/// Open an x402 `upto` channel for the challenge's advertised ceiling and
/// return the `PAYMENT-SIGNATURE` retry header — the exact
/// [`pay_core::client::x402::build_upto_payment`] call `pay curl`'s
/// `pay_upto_and_retry` makes (crates/cli/src/commands/mod.rs). The authorized
/// deposit is the challenge's own `amount` (the ceiling), so a per-request cap,
/// when the payer grows one, is enforced here before signing.
fn build_upto_authorization(
    state: &PayerState,
    challenge: &pay_core::client::x402::UptoChallenge,
    resource_url: &str,
) -> pay_core::Result<PaidHeaders> {
    let store = state.store.as_ref();
    let network_override = state.network_override.as_deref();
    let account_override = state.account_override.as_deref();

    // The channel deposit the client signs is the challenge's advertised
    // ceiling; authorize exactly that. If the payer ever carries a per-request
    // budget cap, refuse (and pass the 402 through) when the ceiling exceeds
    // it — never silently open a larger channel than the caller allows.
    if let Some(cap) = state.per_request_cap_base_units {
        let ceiling: u128 = challenge.requirements.amount.parse().map_err(|_| {
            pay_core::Error::Mpp(format!(
                "x402-upto challenge advertised a non-numeric ceiling: {}",
                challenge.requirements.amount
            ))
        })?;
        if ceiling > cap {
            return Err(pay_core::Error::Mpp(format!(
                "x402-upto ceiling {ceiling} (base units of {}) exceeds the payer's per-request budget {cap}",
                challenge.requirements.asset
            )));
        }
    }

    let built = pay_core::client::x402::build_upto_payment(
        challenge,
        store,
        network_override,
        account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = built.ephemeral_notice {
        tracing::info!(
            network = %resolved.network,
            pubkey = resolved.account.pubkey.as_deref().unwrap_or("(unknown)"),
            "payer proxy: generated ephemeral wallet"
        );
    }

    Ok(PaidHeaders::x402(built.headers))
}

/// Sign a one-shot x402 `exact` payment and return its retry headers. This is
/// the final auto-mode fallback after MPP charge and x402 `upto`.
fn build_exact_authorization(
    state: &PayerState,
    challenge: &pay_core::client::x402::Challenge,
    resource_url: &str,
) -> pay_core::Result<PaidHeaders> {
    if let Some(cap) = state.per_request_cap_base_units {
        let amount: u128 = challenge.requirements.amount.parse().map_err(|_| {
            pay_core::Error::Mpp(format!(
                "x402-exact challenge advertised a non-numeric amount: {}",
                challenge.requirements.amount
            ))
        })?;
        if amount > cap {
            return Err(pay_core::Error::Mpp(format!(
                "x402-exact amount {amount} (base units of {}) exceeds the payer's per-request budget {cap}",
                challenge.requirements.currency
            )));
        }
    }

    let built = pay_core::client::x402::build_payment(
        challenge,
        state.store.as_ref(),
        state.network_override.as_deref(),
        state.account_override.as_deref(),
        Some(resource_url),
    )?;

    if let Some(resolved) = built.ephemeral_notice {
        tracing::info!(
            network = %resolved.network,
            pubkey = resolved.account.pubkey.as_deref().unwrap_or("(unknown)"),
            "payer proxy: generated ephemeral wallet"
        );
    }

    Ok(PaidHeaders::x402(built.headers))
}

/// Forward a request upstream, replaying `body`. When `payment` is `Some`,
/// its headers are applied to the paid retry: MPP replaces `Authorization`;
/// x402 adds its payment proof without replacing the caller's upstream key.
async fn send_upstream(
    state: &PayerState,
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body: Bytes,
    payment: Option<&PaidHeaders>,
) -> reqwest::Result<reqwest::Response> {
    let mut fwd = HeaderMap::new();
    for (name, value) in headers {
        if is_hop_by_hop_request_header(name.as_str()) {
            continue;
        }
        fwd.append(name.clone(), value.clone());
    }
    if let Some(host) = &state.host_header {
        fwd.insert(header::HOST, host.clone());
    }
    if let Some(payment) = payment {
        for (name, value) in &payment.headers {
            let (Ok(name), Ok(value)) = (
                axum::http::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) else {
                continue;
            };
            // A paid header replaces any inbound copy (MPP's `Authorization`,
            // an echoed `PAYMENT-SIGNATURE`) rather than appending a duplicate.
            fwd.remove(&name);
            fwd.insert(name, value);
        }
    }

    state
        .client
        .request(method.clone(), url)
        .headers(fwd)
        .body(body)
        .send()
        .await
}

/// Stream an upstream response back to the client without buffering —
/// SSE completion streams must flow chunk by chunk.
fn stream_response(
    resp: reqwest::Response,
    session_guard: Option<SessionAuthorizationGuard>,
) -> Response {
    let status = resp.status();
    let headers = resp.headers().clone();

    let mut builder = Response::builder().status(status);
    if let Some(dst) = builder.headers_mut() {
        copy_response_headers(dst, &headers);
    }
    let stream_body = Body::from_stream(async_stream::stream! {
        let _session_guard = session_guard;
        let mut resp = resp;
        loop {
            match resp.chunk().await {
                Ok(Some(chunk)) => yield Ok::<_, std::io::Error>(chunk),
                Ok(None) => break,
                Err(error) => {
                    yield Err(std::io::Error::other(error));
                    break;
                }
            }
        }
    });
    builder.body(stream_body).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "payer proxy: response build error",
        )
            .into_response()
    })
}

/// Rebuild a fully-buffered upstream response (the 402 passthrough path).
fn buffered_response(status: StatusCode, headers: &HeaderMap, body: Bytes) -> Response {
    let mut builder = Response::builder().status(status);
    if let Some(dst) = builder.headers_mut() {
        copy_response_headers(dst, headers);
    }
    builder.body(Body::from(body)).unwrap_or_else(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "payer proxy: response build error",
        )
            .into_response()
    })
}

fn copy_response_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    for (name, value) in src {
        if is_hop_by_hop_response_header(name.as_str()) {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn copy_translated_response_headers(dst: &mut HeaderMap, src: &HeaderMap) {
    for (name, value) in src {
        if is_hop_by_hop_response_header(name.as_str()) || is_translated_body_header(name.as_str())
        {
            continue;
        }
        dst.append(name.clone(), value.clone());
    }
}

fn is_translated_body_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-type")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("content-encoding")
}

/// Hop-by-hop request headers (RFC 9110 §7.6.1) plus `host` and
/// `content-length`, which reqwest regenerates for the upstream leg.
fn is_hop_by_hop_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("content-length")
}

fn is_hop_by_hop_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use pay_core::accounts::MemoryAccountsStore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[test]
    fn payer_proxy_bind_address_is_loopback_only() {
        assert!(PAYER_PROXY_BIND_IP.is_loopback());
        assert_eq!(PAYER_PROXY_BIND_IP, Ipv4Addr::LOCALHOST);
    }

    /// One case per real `session_failed` rejection the server can produce
    /// for a stale cached credential (see `pay_core::server::session`'s
    /// `verify_use_authentication` and `verify_challenge_echo`). Every one
    /// of these is terminal — the exact same cached credential will fail
    /// identically forever, so the proxy must discard it and renegotiate
    /// rather than preserve-and-retry. Pinned against the server's own
    /// error text so a rewording can't silently reopen the wedge.
    #[test]
    fn terminal_cached_session_error_recognizes_every_server_rejection() {
        use pay_core::server::session::terminal_errors;

        let session_failed_body = |message: &str| {
            serde_json::to_vec(&serde_json::json!({
                "error": "session_failed",
                "message": message,
                "retryable": true,
            }))
            .unwrap()
        };

        for message in [
            &format!("{}: 6y6WeJ8H4o", terminal_errors::UNKNOWN_CHANNEL),
            terminal_errors::CHALLENGE_ECHO_MISMATCH,
            terminal_errors::OPERATOR_ONLY,
            &format!(
                "session channel {}; open a new session",
                terminal_errors::PREDATES_PROOF_BINDING
            ),
            &format!("use authentication {}", terminal_errors::PROOF_MISMATCH),
        ] {
            let body = session_failed_body(message);
            assert!(
                terminal_cached_session_error(&body),
                "expected terminal classification for: {message}"
            );
        }
    }

    #[test]
    fn terminal_cached_session_error_does_not_misclassify_a_transient_store_error() {
        let body = serde_json::to_vec(&serde_json::json!({
            "error": "session_failed",
            "message": "failed to read session channel abc123: store timeout",
            "retryable": true,
        }))
        .unwrap();
        assert!(
            !terminal_cached_session_error(&body),
            "a store read hiccup must stay retryable, not be treated as terminal"
        );
    }

    /// A canned MPP charge challenge that signs fully offline: the
    /// embedded `recentBlockhash` skips the blockhash RPC and the
    /// embedded `tokenProgram` + `decimals` skip the mint-account RPC
    /// (verified against `pay_kit::mpp::client::charge::resolve_blockhash`
    /// / `resolve_token_program`).
    fn challenge_header(network: &str) -> String {
        let request = serde_json::json!({
            "amount": "10000",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": {
                "network": network,
                "recentBlockhash": "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F",
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "decimals": 6,
            },
        });
        let challenge = pay_core::mpp::Challenge::new(
            "USDC",
            "test",
            "solana",
            "charge",
            pay_kit::mpp::Base64UrlJson::from_value(&request).unwrap(),
        );
        pay_kit::mpp::format_www_authenticate(&challenge).unwrap()
    }

    fn session_challenge_header() -> String {
        let challenge = pay_core::mpp::Challenge::new(
            "USDC",
            "test",
            "solana",
            "session",
            pay_kit::mpp::Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        );
        pay_kit::mpp::format_www_authenticate(&challenge).unwrap()
    }

    /// A canned x402 `upto` challenge that signs fully offline: `network` is a
    /// devnet CAIP-2 (so with no `--sandbox`/`--mainnet` override the payer
    /// lazily mints a throwaway devnet wallet, exactly like the MPP test), the
    /// embedded `recentBlockhash` + `recentSlot` build the open transaction
    /// with no RPC, and `payTo == receiverAuthorizer` so no distribution split
    /// is derived. The blockhash is *not* Surfpool-prefixed, so no auto-fund
    /// network call fires.
    /// Returns the base64 `PAYMENT-REQUIRED` header value the gateway emits.
    fn upto_challenge_header(amount: &str) -> String {
        let payee = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let envelope = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "upto",
                "network": pay_kit::x402::exact::SOLANA_DEVNET,
                "amount": amount,
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "payTo": payee,
                "maxTimeoutSeconds": 300,
                "extra": {
                    "feePayer": payee,
                    "receiverAuthorizer": payee,
                    "withdrawDelay": 900,
                    "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                    "recentBlockhash": "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F",
                    "recentSlot": "123456789",
                },
            }],
        });
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(envelope.to_string().as_bytes())
    }

    /// A canned x402 `exact` challenge that can be signed offline for the same
    /// reason as [`upto_challenge_header`]: it carries a devnet network, fee
    /// payer, and recent blockhash.
    fn exact_challenge_header(amount: &str) -> String {
        let payee = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
        let envelope = serde_json::json!({
            "x402Version": 2,
            "resource": {
                "url": "http://127.0.0.1/v1/messages",
                "description": "test exact payment",
                "mimeType": "application/json"
            },
            "accepts": [{
                "scheme": "exact",
                "network": pay_kit::x402::exact::SOLANA_DEVNET,
                "amount": amount,
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "payTo": payee,
                "maxTimeoutSeconds": 300,
                "extra": {
                    "feePayer": payee,
                    "recentBlockhash": "9zrUHnA1nCByPksy3aL8tQ47vqdaG2vnFs4HrxgcZj4F",
                    "decimals": 6
                }
            }]
        });
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(envelope.to_string().as_bytes())
    }

    async fn spawn_server(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.ok();
        });
        format!("http://{addr}")
    }

    /// Spawn the payer with an in-memory accounts store so tests never
    /// touch (or create) the user's real `~/.config/pay/accounts.yml`.
    async fn spawn_payer_with(upstream: PayerUpstream, network_override: Option<&str>) -> String {
        let store: Arc<dyn AccountsStore> = Arc::new(MemoryAccountsStore::new());
        let state = Arc::new(
            PayerState::new(upstream, store, network_override.map(str::to_string), None).unwrap(),
        );
        spawn_server(router(state)).await
    }

    /// Anthropic-dialect payer (pure passthrough — no translation).
    async fn spawn_payer(upstream: String, network_override: Option<&str>) -> String {
        spawn_payer_with(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::Anthropic,
                chat_path: "v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: false,
                payment_protocol: PaymentProtocol::Auto,
            },
            network_override,
        )
        .await
    }

    /// OpenAI-compat payer targeting Alibaba's compatible-mode chat path.
    async fn spawn_openai_payer(upstream: String, network_override: Option<&str>) -> String {
        spawn_payer_with(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::OpenAiCompat,
                chat_path: "compatible-mode/v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: false,
                payment_protocol: PaymentProtocol::Auto,
            },
            network_override,
        )
        .await
    }

    #[tokio::test]
    async fn direct_openai_chat_uses_declared_provider_path() {
        let upstream = spawn_server(Router::new().route(
            "/compatible-mode/v1/chat/completions",
            axum::routing::post(|req: Request| async move {
                assert_eq!(req.uri().query(), Some("trace=1"));
                (StatusCode::OK, "provider path reached")
            }),
        ))
        .await;
        let payer = spawn_openai_payer(upstream, None).await;

        let response = reqwest::Client::new()
            .post(format!("{payer}/v1/chat/completions?trace=1"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "provider path reached");
    }

    #[tokio::test]
    async fn blockrun_chat_uses_api_v1_provider_path() {
        let seen = Arc::new(Mutex::new(None::<serde_json::Value>));
        let record = seen.clone();
        let upstream = spawn_server(Router::new().route(
            "/api/v1/chat/completions",
            axum::routing::post(move |body: axum::Json<serde_json::Value>| {
                let record = record.clone();
                async move {
                    *record.lock().unwrap() = Some(body.0);
                    (StatusCode::OK, "blockrun path reached")
                }
            }),
        ))
        .await;
        let payer = spawn_payer_with(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::OpenAiCompat,
                chat_path: "api/v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: false,
                payment_protocol: PaymentProtocol::Auto,
            },
            None,
        )
        .await;

        let response = reqwest::Client::new()
            .post(format!("{payer}/v1/chat/completions"))
            .json(&serde_json::json!({
                "model": "openai/gpt-5.6-sol",
                "messages": [
                    { "role": "developer", "content": "You are Goose." },
                    { "role": "user", "content": "test" }
                ]
            }))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "blockrun path reached");
        let body = seen.lock().unwrap().clone().unwrap();
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["role"], "user");
    }

    #[tokio::test]
    async fn direct_openai_responses_uses_declared_provider_path() {
        let upstream = spawn_server(Router::new().route(
            "/v1/responses",
            axum::routing::post(|req: Request| async move {
                assert_eq!(req.uri().query(), Some("trace=1"));
                (StatusCode::OK, "responses path reached")
            }),
        ))
        .await;
        let payer = spawn_openai_payer(upstream, None).await;

        let response = reqwest::Client::new()
            .post(format!("{payer}/v1/responses?trace=1"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "responses path reached");
    }

    #[test]
    fn parses_x402_exact_challenge_from_payment_required_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "payment-required",
            HeaderValue::from_str(&exact_challenge_header("28130")).unwrap(),
        );

        let challenge = parse_exact_challenge(&headers, &Bytes::new()).unwrap();

        assert_eq!(challenge.x402_version, 2);
        assert_eq!(challenge.requirements.amount, "28130");
        assert_eq!(
            challenge.requirements.resource,
            "http://127.0.0.1/v1/messages"
        );
    }

    #[tokio::test]
    async fn hosted_provider_success_without_payment_challenge_is_rejected() {
        let upstream = spawn_server(Router::new().fallback(any(|| async {
            (StatusCode::OK, "ungated upstream response")
        })))
        .await;
        let payer = spawn_payer_with(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::Anthropic,
                chat_path: "v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: true,
                payment_protocol: PaymentProtocol::Auto,
            },
            None,
        )
        .await;

        let response = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            response
                .text()
                .await
                .unwrap()
                .contains("refusing an ungated response")
        );
    }

    #[tokio::test]
    async fn hosted_provider_allows_public_model_discovery() {
        let upstream = spawn_server(Router::new().route(
            "/v1/models",
            axum::routing::get(|| async { (StatusCode::OK, r#"{"data":[]}"#) }),
        ))
        .await;
        let payer = spawn_payer_with(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::OpenAiCompat,
                chat_path: "v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: true,
                payment_protocol: PaymentProtocol::Auto,
            },
            None,
        )
        .await;

        let response = reqwest::Client::new()
            .get(format!("{payer}/v1/models"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), r#"{"data":[]}"#);
    }

    const OPENAI_COMPLETION_JSON: &str = r#"{
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "model": "qwen-max",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": "Hello!" },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 12, "completion_tokens": 3 }
    }"#;

    fn anthropic_request_body() -> serde_json::Value {
        serde_json::json!({
            "model": "qwen-max",
            "max_tokens": 100,
            "system": "be brief",
            "messages": [{ "role": "user", "content": "hi" }],
        })
    }

    #[derive(Default)]
    struct StubSeen {
        calls: usize,
        first_uri: Option<String>,
        first_host: Option<String>,
        retry_auth: Option<String>,
        retry_body: Option<Vec<u8>>,
    }

    async fn stub_402_then_ok(State(seen): State<Arc<Mutex<StubSeen>>>, req: Request) -> Response {
        let uri = req.uri().to_string();
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let auth = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();

        let mut seen = seen.lock().unwrap();
        seen.calls += 1;
        if seen.calls == 1 {
            seen.first_uri = Some(uri);
            seen.first_host = host;
            return Response::builder()
                .status(StatusCode::PAYMENT_REQUIRED)
                .header(header::WWW_AUTHENTICATE, challenge_header("localnet"))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"payment required"}"#))
                .unwrap();
        }
        seen.retry_auth = auth;
        seen.retry_body = Some(body.to_vec());
        (StatusCode::OK, "paid ok").into_response()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pays_mpp_402_once_and_replays_identical_body() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let app = Router::new()
            .fallback(any(stub_402_then_ok))
            .with_state(seen.clone());
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, None).await;

        let body = r#"{"model":"llama3.2","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages?beta=true"))
            .header("authorization", "Bearer ollama")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "paid ok");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "exactly one retry after the 402");
        assert_eq!(
            seen.first_uri.as_deref(),
            Some("/v1/messages?beta=true"),
            "path + query must be preserved"
        );
        let auth = seen
            .retry_auth
            .as_deref()
            .expect("retry must carry Authorization");
        assert!(
            auth.starts_with("Payment "),
            "retry must carry an MPP Payment credential, got: {auth}"
        );
        assert_eq!(
            seen.retry_body.as_deref(),
            Some(body.as_bytes()),
            "retry must replay the identical request body"
        );
    }

    /// Stub that answers the first request with an x402 `upto` 402 (a
    /// `PAYMENT-REQUIRED` header) and every retry with 200, recording the
    /// retry's `PAYMENT-SIGNATURE` header and body. `amount` is the advertised
    /// ceiling (base units).
    fn upto_stub(seen: Arc<Mutex<StubSeen>>, amount: &'static str) -> Router {
        Router::new().fallback(any(move |req: Request| {
            let seen = seen.clone();
            async move {
                let uri = req.uri().to_string();
                let sig = req
                    .headers()
                    .get("payment-signature")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let body = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
                    .await
                    .unwrap();
                let mut seen = seen.lock().unwrap();
                seen.calls += 1;
                if seen.calls == 1 {
                    seen.first_uri = Some(uri);
                    seen.retry_body = Some(body.to_vec()); // first (buffered) body
                    return Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header("payment-required", upto_challenge_header(amount))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap();
                }
                // The upto retry must replay the identical body and must NOT
                // clobber the caller's Authorization (upto uses its own
                // PAYMENT-SIGNATURE header).
                assert_eq!(
                    seen.retry_body.as_deref(),
                    Some(&body[..]),
                    "upto retry must replay the identical body"
                );
                seen.retry_auth = sig;
                (StatusCode::OK, "upto paid ok").into_response()
            }
        }))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pays_x402_upto_402_and_retries_with_payment_header() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        // $0.50 ceiling in USDC base units — the gateway's MAX_REQUEST_USD.
        let upstream = spawn_server(upto_stub(seen.clone(), "500000")).await;
        // No override: the devnet challenge lazily mints a throwaway wallet and
        // signs the channel-open offline (embedded, non-Surfpool blockhash).
        let payer = spawn_payer(upstream, None).await;

        let body = r#"{"model":"llama3.2","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages?beta=true"))
            .header("authorization", "Bearer upstream-key")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "upto paid ok");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "exactly one retry after the upto 402");
        assert_eq!(
            seen.first_uri.as_deref(),
            Some("/v1/messages?beta=true"),
            "path + query must be preserved"
        );
        let sig = seen
            .retry_auth
            .as_deref()
            .expect("upto retry must carry a PAYMENT-SIGNATURE header");
        assert!(!sig.is_empty(), "PAYMENT-SIGNATURE must be non-empty");
        assert_eq!(
            seen.retry_body.as_deref(),
            Some(body.as_bytes()),
            "upto retry must replay the identical request body"
        );
    }

    /// Stub that offers only x402 `exact`, matching BlockRun's payment
    /// protocol, then accepts the signed retry.
    fn exact_stub(seen: Arc<Mutex<StubSeen>>, amount: &'static str) -> Router {
        Router::new().fallback(any(move |req: Request| {
            let seen = seen.clone();
            async move {
                let uri = req.uri().to_string();
                let sig = req
                    .headers()
                    .get("payment-signature")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let body = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
                    .await
                    .unwrap();
                let mut seen = seen.lock().unwrap();
                seen.calls += 1;
                if seen.calls == 1 {
                    seen.first_uri = Some(uri);
                    seen.retry_body = Some(body.to_vec());
                    return Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header("payment-required", exact_challenge_header(amount))
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap();
                }
                assert_eq!(
                    seen.retry_body.as_deref(),
                    Some(&body[..]),
                    "exact retry must replay the identical body"
                );
                seen.retry_auth = sig;
                (StatusCode::OK, "exact paid ok").into_response()
            }
        }))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pays_x402_exact_402_and_retries_with_payment_header() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let upstream = spawn_server(exact_stub(seen.clone(), "28130")).await;
        let payer = spawn_payer(upstream, None).await;

        let body = r#"{"model":"openai/gpt-5.6-sol","messages":[{"role":"user","content":"hi"}]}"#;
        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .header("authorization", "Bearer upstream-key")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "exact paid ok");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "exactly one retry after the exact 402");
        let sig = seen
            .retry_auth
            .as_deref()
            .expect("exact retry must carry a PAYMENT-SIGNATURE header");
        assert!(!sig.is_empty(), "PAYMENT-SIGNATURE must be non-empty");
        assert_eq!(
            seen.retry_body.as_deref(),
            Some(body.as_bytes()),
            "exact retry must replay the identical request body"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn session_challenge_does_not_mask_coexisting_x402_upto() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let record = seen.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            async move {
                let sig = req
                    .headers()
                    .get("payment-signature")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await;
                let mut seen = record.lock().unwrap();
                seen.calls += 1;
                if seen.calls == 1 {
                    return Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::WWW_AUTHENTICATE, session_challenge_header())
                        .header("payment-required", upto_challenge_header("500000"))
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap();
                }
                seen.retry_auth = sig;
                (StatusCode::OK, "upto paid ok").into_response()
            }
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body(r#"{"messages":[]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "x402 upto must pay and retry once");
        assert!(
            seen.retry_auth
                .as_deref()
                .is_some_and(|sig| !sig.is_empty()),
            "session MPP must not prevent the x402 PAYMENT-SIGNATURE retry"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn enforced_session_is_opened_once_and_reused_without_x402() {
        fn open_test_session(
            _state: &PayerState,
            _challenge: &pay_core::mpp::Challenge,
        ) -> pay_core::Result<(PaidHeaders, String)> {
            let authorization = "Payment test-session".to_string();
            Ok((PaidHeaders::mpp(authorization.clone()), authorization))
        }

        let seen = Arc::new(Mutex::new(Vec::<(Option<String>, Option<String>)>::new()));
        let record = seen.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            async move {
                let authorization = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let payment_signature = req
                    .headers()
                    .get("payment-signature")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await;
                record
                    .lock()
                    .unwrap()
                    .push((authorization.clone(), payment_signature));
                if authorization
                    .as_deref()
                    .is_some_and(|value| value.starts_with("Payment "))
                {
                    return (StatusCode::OK, "session paid").into_response();
                }
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header(header::WWW_AUTHENTICATE, session_challenge_header())
                    .header("payment-required", upto_challenge_header("500000"))
                    .body(Body::from(r#"{"error":"payment required"}"#))
                    .unwrap()
            }
        }));
        let upstream = spawn_server(app).await;
        let store: Arc<dyn AccountsStore> = Arc::new(MemoryAccountsStore::new());
        let state = PayerState::new(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::Anthropic,
                chat_path: "v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: true,
                payment_protocol: PaymentProtocol::MppSession,
            },
            store,
            None,
            None,
        )
        .unwrap()
        .with_session_opener(open_test_session);
        let payer = spawn_server(router(Arc::new(state))).await;

        let client = reqwest::Client::new();
        for prompt in ["one", "two"] {
            let response = client
                .post(format!("{payer}/v1/messages"))
                .body(prompt)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            3,
            "only the first call should require a 402 retry"
        );
        let first_paid = seen[1].0.as_deref().expect("first session authorization");
        let reused = seen[2].0.as_deref().expect("reused session authorization");
        assert_eq!(first_paid, reused, "the same session must be reused");
        assert!(
            seen.iter().all(|(_, signature)| signature.is_none()),
            "session enforcement must never fall back to x402"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn session_open_credential_does_not_survive_a_paid_retry_transport_error() {
        fn open_test_session(
            _state: &PayerState,
            _challenge: &pay_core::mpp::Challenge,
        ) -> pay_core::Result<(PaidHeaders, String)> {
            let authorization = "Payment durable-open".to_string();
            Ok((PaidHeaders::mpp(authorization.clone()), authorization))
        }

        // Serve exactly the challenge response, then stop listening before the
        // paid retry. This models a connection failure after the open may or
        // may not have landed upstream — genuinely ambiguous, since nothing
        // confirms whether the retry was even received.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let challenge = session_challenge_header();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            drop(listener);
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let body = r#"{"error":"payment required"}"#;
            let response = format!(
                "HTTP/1.1 402 Payment Required\r\nWWW-Authenticate: {challenge}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let store: Arc<dyn AccountsStore> = Arc::new(MemoryAccountsStore::new());
        let state = Arc::new(
            PayerState::new(
                PayerUpstream {
                    base_url: format!("http://{addr}"),
                    host_header: None,
                    dialect: Dialect::Anthropic,
                    chat_path: "v1/chat/completions".to_string(),
                    responses_path: "v1/responses".to_string(),
                    require_payment: true,
                    payment_protocol: PaymentProtocol::MppSession,
                },
                store,
                None,
                None,
            )
            .unwrap()
            .with_session_opener(open_test_session),
        );
        let payer = spawn_server(router(state.clone())).await;

        let response = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            state.session_authorization.acquire().await.authorization(),
            None,
            "an unconfirmed open credential must not be cached — adopting it before \
             a paid retry proves it landed risks stranding a credential for a \
             channel that never opened; the next request must renegotiate instead \
             of trusting a credential no response ever confirmed"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cached_session_stays_locked_until_stream_body_finishes() {
        fn open_test_session(
            _state: &PayerState,
            _challenge: &pay_core::mpp::Challenge,
        ) -> pay_core::Result<(PaidHeaders, String)> {
            let authorization = "Payment streaming-session".to_string();
            Ok((PaidHeaders::mpp(authorization.clone()), authorization))
        }

        let calls = Arc::new(Mutex::new(0_usize));
        let release_stream = Arc::new(tokio::sync::Notify::new());
        let record = calls.clone();
        let release = release_stream.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            let release = release.clone();
            async move {
                let authorization = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await;
                let call = {
                    let mut calls = record.lock().unwrap();
                    *calls += 1;
                    *calls
                };
                match call {
                    1 => Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::WWW_AUTHENTICATE, session_challenge_header())
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap(),
                    2 => {
                        assert_eq!(authorization.as_deref(), Some("Payment streaming-session"));
                        let body = Body::from_stream(async_stream::stream! {
                            yield Ok::<_, std::io::Error>(Bytes::from_static(b"first "));
                            release.notified().await;
                            yield Ok(Bytes::from_static(b"done"));
                        });
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(body)
                            .unwrap()
                    }
                    3 => {
                        assert_eq!(authorization.as_deref(), Some("Payment streaming-session"));
                        (StatusCode::OK, "second response").into_response()
                    }
                    call => panic!("unexpected upstream call {call}"),
                }
            }
        }));
        let upstream = spawn_server(app).await;
        let store: Arc<dyn AccountsStore> = Arc::new(MemoryAccountsStore::new());
        let state = Arc::new(
            PayerState::new(
                PayerUpstream {
                    base_url: upstream,
                    host_header: None,
                    dialect: Dialect::Anthropic,
                    chat_path: "v1/chat/completions".to_string(),
                    responses_path: "v1/responses".to_string(),
                    require_payment: true,
                    payment_protocol: PaymentProtocol::MppSession,
                },
                store,
                None,
                None,
            )
            .unwrap()
            .with_session_opener(open_test_session),
        );
        let payer = spawn_server(router(state)).await;
        let client = reqwest::Client::new();

        let first = client
            .post(format!("{payer}/v1/messages"))
            .body("first")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let second_client = client.clone();
        let second_url = format!("{payer}/v1/messages");
        let second =
            tokio::spawn(async move { second_client.post(second_url).body("second").send().await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            *calls.lock().unwrap(),
            2,
            "the second request must not reach upstream while the first stream is active"
        );
        assert!(
            !second.is_finished(),
            "the second request must wait for the first stream's session lock"
        );

        release_stream.notify_one();
        assert_eq!(first.text().await.unwrap(), "first done");
        let second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second request should resume after the first stream")
            .unwrap()
            .unwrap();
        assert_eq!(second.text().await.unwrap(), "second response");
        assert_eq!(*calls.lock().unwrap(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn ended_cached_session_discovers_and_opens_a_replacement() {
        fn open_test_session(
            _state: &PayerState,
            _challenge: &pay_core::mpp::Challenge,
        ) -> pay_core::Result<(PaidHeaders, String)> {
            let authorization = "Payment test-session".to_string();
            Ok((PaidHeaders::mpp(authorization.clone()), authorization))
        }

        let seen = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let record = seen.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            async move {
                let authorization = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await;
                let mut seen = record.lock().unwrap();
                seen.push(authorization.clone());
                match seen.len() {
                    1 | 4 => Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::WWW_AUTHENTICATE, session_challenge_header())
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap(),
                    2 | 5 => (StatusCode::OK, "session paid").into_response(),
                    3 => Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"error":"session_failed","message":"channel is already sealed"}"#,
                        ))
                        .unwrap(),
                    call => panic!("unexpected upstream call {call}"),
                }
            }
        }));
        let upstream = spawn_server(app).await;
        let store: Arc<dyn AccountsStore> = Arc::new(MemoryAccountsStore::new());
        let state = PayerState::new(
            PayerUpstream {
                base_url: upstream,
                host_header: None,
                dialect: Dialect::Anthropic,
                chat_path: "v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: true,
                payment_protocol: PaymentProtocol::MppSession,
            },
            store,
            None,
            None,
        )
        .unwrap()
        .with_session_opener(open_test_session);
        let payer = spawn_server(router(Arc::new(state))).await;

        let client = reqwest::Client::new();
        for prompt in ["one", "two"] {
            let response = client
                .post(format!("{payer}/v1/messages"))
                .body(prompt)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                None,
                Some("Payment test-session".to_string()),
                Some("Payment test-session".to_string()),
                None,
                Some("Payment test-session".to_string()),
            ],
            "a terminal cached session must be followed by unauthenticated challenge discovery",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn retryable_cached_session_error_reuses_channel() {
        fn open_test_session(
            _state: &PayerState,
            _challenge: &pay_core::mpp::Challenge,
        ) -> pay_core::Result<(PaidHeaders, String)> {
            let authorization = "Payment retryable-session".to_string();
            Ok((PaidHeaders::mpp(authorization.clone()), authorization))
        }

        let seen = Arc::new(Mutex::new(Vec::<Option<String>>::new()));
        let record = seen.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            async move {
                let authorization = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await;
                let mut seen = record.lock().unwrap();
                seen.push(authorization.clone());
                match seen.len() {
                    1 => Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::WWW_AUTHENTICATE, session_challenge_header())
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap(),
                    2 | 4 => (StatusCode::OK, "session paid").into_response(),
                    3 => Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            r#"{"error":"session_failed","message":"Store error: Concurrent channel update; retry the request"}"#,
                        ))
                        .unwrap(),
                    call => panic!("unexpected upstream call {call}"),
                }
            }
        }));
        let upstream = spawn_server(app).await;
        let store: Arc<dyn AccountsStore> = Arc::new(MemoryAccountsStore::new());
        let state = Arc::new(
            PayerState::new(
                PayerUpstream {
                    base_url: upstream,
                    host_header: None,
                    dialect: Dialect::Anthropic,
                    chat_path: "v1/chat/completions".to_string(),
                    responses_path: "v1/responses".to_string(),
                    require_payment: true,
                    payment_protocol: PaymentProtocol::MppSession,
                },
                store,
                None,
                None,
            )
            .unwrap()
            .with_session_opener(open_test_session),
        );
        let payer = spawn_server(router(state.clone())).await;

        let client = reqwest::Client::new();
        for prompt in ["one", "two"] {
            let response = client
                .post(format!("{payer}/v1/messages"))
                .body(prompt)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                None,
                Some("Payment retryable-session".to_string()),
                Some("Payment retryable-session".to_string()),
                Some("Payment retryable-session".to_string()),
            ],
            "a retryable store conflict must retry the same channel without rediscovery",
        );
        assert_eq!(
            state.session_authorization.acquire().await.authorization(),
            Some("Payment retryable-session"),
            "a transient 402 must preserve the cached session"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pays_x402_upto_402_from_openai_upstream_and_replays_translated_body() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let record = seen.clone();
        let app = Router::new().route(
            "/compatible-mode/v1/chat/completions",
            axum::routing::post(move |req: Request| {
                let record = record.clone();
                async move {
                    let sig = req
                        .headers()
                        .get("payment-signature")
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    let body = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
                        .await
                        .unwrap();
                    let mut seen = record.lock().unwrap();
                    seen.calls += 1;
                    if seen.calls == 1 {
                        seen.retry_body = Some(body.to_vec()); // first (translated) body
                        return Response::builder()
                            .status(StatusCode::PAYMENT_REQUIRED)
                            .header("payment-required", upto_challenge_header("500000"))
                            .body(Body::from(r#"{"error":"payment required"}"#))
                            .unwrap();
                    }
                    assert_eq!(
                        seen.retry_body.as_deref(),
                        Some(&body[..]),
                        "upto retry must replay the exact translated body"
                    );
                    seen.retry_auth = sig;
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(PAYMENT_RESPONSE_HEADER, "translated-upto-receipt")
                        .body(Body::from(OPENAI_COMPLETION_JSON))
                        .unwrap()
                }
            }),
        );
        let upstream = spawn_server(app).await;
        let payer = spawn_openai_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .json(&anthropic_request_body())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(PAYMENT_RESPONSE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("translated-upto-receipt")
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["type"], "message", "paid retry comes back translated");
        assert_eq!(body["content"][0]["text"], "Hello!");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "exactly one upto retry");
        assert!(
            seen.retry_auth.as_deref().is_some_and(|s| !s.is_empty()),
            "upto retry carries PAYMENT-SIGNATURE"
        );
        // The body the 402 fired on — and the retry replayed — is the
        // translated OpenAI body.
        let translated: serde_json::Value =
            serde_json::from_slice(seen.retry_body.as_deref().unwrap()).unwrap();
        assert_eq!(translated["messages"][0]["role"], "system");
        assert_eq!(translated["messages"][1]["content"], "hi");
        assert!(translated.get("system").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn passes_upto_402_through_when_open_fails() {
        // A `--sandbox` (localnet-forced) payer facing a devnet upto challenge:
        // `check_client_network_intent` refuses to sign for a network the user
        // did not opt into, so the channel open fails and the original 402 must
        // pass through untouched with no retry.
        let calls = Arc::new(Mutex::new(0usize));
        let counter = calls.clone();
        let app = Router::new().fallback(any(move || {
            let counter = counter.clone();
            async move {
                *counter.lock().unwrap() += 1;
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("payment-required", upto_challenge_header("500000"))
                    .body(Body::from("upto money required"))
                    .unwrap()
            }
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, Some("localnet")).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(
            resp.headers().get("payment-required").is_some(),
            "original upto challenge must survive the passthrough"
        );
        assert_eq!(resp.text().await.unwrap(), "upto money required");
        assert_eq!(*calls.lock().unwrap(), 1, "no paid retry may be attempted");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn mpp_charge_takes_precedence_over_coexisting_upto_challenge() {
        // A 402 that advertises BOTH an MPP charge (WWW-Authenticate) and an
        // x402 upto (PAYMENT-REQUIRED). Scheme precedence: MPP wins, so the
        // retry carries an `Authorization: Payment …` credential, not a
        // PAYMENT-SIGNATURE.
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let record = seen.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            async move {
                let auth = req
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let has_sig = req.headers().get("payment-signature").is_some();
                let _ = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES).await;
                let mut seen = record.lock().unwrap();
                seen.calls += 1;
                if seen.calls == 1 {
                    return Response::builder()
                        .status(StatusCode::PAYMENT_REQUIRED)
                        .header(header::WWW_AUTHENTICATE, challenge_header("localnet"))
                        .header("payment-required", upto_challenge_header("500000"))
                        .body(Body::from(r#"{"error":"payment required"}"#))
                        .unwrap();
                }
                seen.retry_auth = auth;
                seen.first_uri = Some(has_sig.to_string()); // reuse slot: "true"/"false"
                (StatusCode::OK, "mpp paid ok").into_response()
            }
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body(r#"{"messages":[]}"#)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.text().await.unwrap(), "mpp paid ok");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "exactly one paid retry");
        let auth = seen
            .retry_auth
            .as_deref()
            .expect("MPP retry must carry Authorization");
        assert!(
            auth.starts_with("Payment "),
            "MPP charge must take precedence, got: {auth}"
        );
        assert_eq!(
            seen.first_uri.as_deref(),
            Some("false"),
            "the MPP retry must NOT also carry a PAYMENT-SIGNATURE header"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn passes_non_402_responses_through() {
        let app = Router::new().fallback(any(|| async {
            Response::builder()
                .status(StatusCode::CREATED)
                .header("x-upstream", "yes")
                .body(Body::from("hello upstream"))
                .unwrap()
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .get(format!("{payer}/v1/models"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::CREATED);
        assert_eq!(resp.headers().get("x-upstream").unwrap(), "yes");
        assert_eq!(resp.text().await.unwrap(), "hello upstream");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forwards_configured_upstream_host_header() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let record = seen.clone();
        let app = Router::new().fallback(any(move |req: Request| {
            let record = record.clone();
            async move {
                let host = req
                    .headers()
                    .get(header::HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                record.lock().unwrap().first_host = host;
                (StatusCode::OK, "host ok").into_response()
            }
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer_with(
            PayerUpstream {
                base_url: upstream,
                host_header: Some("ollama.localhost:1402".to_string()),
                dialect: Dialect::Anthropic,
                chat_path: "v1/chat/completions".to_string(),
                responses_path: "v1/responses".to_string(),
                require_payment: false,
                payment_protocol: PaymentProtocol::Auto,
            },
            None,
        )
        .await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            seen.lock().unwrap().first_host.as_deref(),
            Some("ollama.localhost:1402")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn passes_402_through_untouched_when_challenge_is_mainnet_in_sandbox_context() {
        let calls = Arc::new(Mutex::new(0usize));
        let counter = calls.clone();
        let app = Router::new().fallback(any(move || {
            let counter = counter.clone();
            async move {
                *counter.lock().unwrap() += 1;
                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header(header::WWW_AUTHENTICATE, challenge_header("mainnet"))
                    .body(Body::from("mainnet money required"))
                    .unwrap()
            }
        }));
        let upstream = spawn_server(app).await;
        // `--sandbox` context: network forced to localnet — the payer must
        // refuse to sign for a mainnet challenge and pass the 402 through.
        let payer = spawn_payer(upstream, Some("localnet")).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .body("{}")
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(
            resp.headers().get(header::WWW_AUTHENTICATE).is_some(),
            "original challenge must survive the passthrough"
        );
        assert_eq!(resp.text().await.unwrap(), "mainnet money required");
        assert_eq!(*calls.lock().unwrap(), 1, "no paid retry may be attempted");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn passes_402_without_mpp_challenge_through() {
        let app = Router::new().fallback(any(|| async {
            Response::builder()
                .status(StatusCode::PAYMENT_REQUIRED)
                .header(header::WWW_AUTHENTICATE, "Bearer realm=\"nope\"")
                .body(Body::from("not mpp"))
                .unwrap()
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .get(format!("{payer}/v1/models"))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(resp.text().await.unwrap(), "not mpp");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn streams_sse_bodies_incrementally() {
        // The upstream holds the second SSE chunk hostage until the test
        // proves it received the first — impossible if the payer buffers
        // the response instead of streaming it.
        let (gate_tx, gate_rx) = tokio::sync::oneshot::channel::<()>();
        let gate = Arc::new(Mutex::new(Some(gate_rx)));
        let app = Router::new().fallback(any(move || {
            let gate = gate.clone();
            async move {
                let gate_rx = gate.lock().unwrap().take();
                let stream = async_stream::stream! {
                    yield Ok::<_, std::io::Error>(Bytes::from_static(b"data: one\n\n"));
                    if let Some(rx) = gate_rx {
                        let _ = rx.await;
                    }
                    yield Ok(Bytes::from_static(b"data: two\n\n"));
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
        }));
        let upstream = spawn_server(app).await;
        let payer = spawn_payer(upstream, None).await;

        let mut resp = reqwest::Client::new()
            .get(format!("{payer}/v1/messages"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );

        let mut first = Vec::new();
        while !first.ends_with(b"data: one\n\n") {
            let chunk = tokio::time::timeout(Duration::from_secs(5), resp.chunk())
                .await
                .expect("payer buffered the SSE stream instead of forwarding chunks")
                .unwrap()
                .expect("stream ended before the first SSE event");
            first.extend_from_slice(&chunk);
        }

        gate_tx.send(()).unwrap();

        let mut rest = Vec::new();
        while let Some(chunk) = resp.chunk().await.unwrap() {
            rest.extend_from_slice(&chunk);
        }
        assert_eq!(&rest[..], b"data: two\n\n");
    }

    // ── OpenAI-compat dialect loopback ─────────────────────────────────────

    #[tokio::test(flavor = "multi_thread")]
    async fn translates_anthropic_request_and_openai_response_for_openai_upstream() {
        let seen = Arc::new(Mutex::new(Option::<serde_json::Value>::None));
        let record = seen.clone();
        let app = Router::new().route(
            "/compatible-mode/v1/chat/completions",
            axum::routing::post(move |body: axum::Json<serde_json::Value>| {
                let record = record.clone();
                async move {
                    *record.lock().unwrap() = Some(body.0);
                    (
                        [(header::CONTENT_TYPE, "application/json")],
                        OPENAI_COMPLETION_JSON,
                    )
                }
            }),
        );
        let upstream = spawn_server(app).await;
        let payer = spawn_openai_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages?beta=true"))
            .json(&anthropic_request_body())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["type"], "message");
        assert_eq!(body["role"], "assistant");
        assert_eq!(
            body["content"],
            serde_json::json!([{ "type": "text", "text": "Hello!" }])
        );
        assert_eq!(body["stop_reason"], "end_turn");
        assert_eq!(body["usage"]["input_tokens"], 12);
        assert_eq!(body["usage"]["output_tokens"], 3);

        // The upstream must have received the OpenAI shape.
        let sent = seen
            .lock()
            .unwrap()
            .clone()
            .expect("upstream saw the request");
        assert_eq!(
            sent["messages"],
            serde_json::json!([
                { "role": "system", "content": "be brief" },
                { "role": "user", "content": "hi" },
            ])
        );
        assert_eq!(sent["model"], "qwen-max");
        assert!(sent.get("system").is_none(), "system moved into messages");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn translates_openai_sse_stream_into_anthropic_events() {
        const OPENAI_SSE: &str = concat!(
            "data: {\"id\":\"chatcmpl-7\",\"model\":\"qwen-max\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":1}}\n\n",
            "data: [DONE]\n\n",
        );
        let app = Router::new().route(
            "/compatible-mode/v1/chat/completions",
            axum::routing::post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .header(PAYMENT_RESPONSE_HEADER, "translated-sse-receipt")
                    .body(Body::from(OPENAI_SSE))
                    .unwrap()
            }),
        );
        let upstream = spawn_server(app).await;
        let payer = spawn_openai_payer(upstream, None).await;

        let mut request = anthropic_request_body();
        request["stream"] = serde_json::json!(true);
        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .json(&request)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "text/event-stream"
        );
        assert_eq!(
            resp.headers()
                .get(PAYMENT_RESPONSE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("translated-sse-receipt")
        );

        let sse = resp.text().await.unwrap();
        let event_names: Vec<&str> = sse
            .lines()
            .filter_map(|line| line.strip_prefix("event: "))
            .collect();
        assert_eq!(
            event_names,
            [
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        assert!(
            sse.contains(r#""text":"Hello""#) && sse.contains(r#""text_delta""#),
            "text delta must survive translation: {sse}"
        );
        assert!(
            sse.contains(r#""output_tokens":1"#),
            "final usage must reach message_delta: {sse}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn pays_402_from_openai_upstream_and_replays_translated_body() {
        let seen = Arc::new(Mutex::new(StubSeen::default()));
        let record = seen.clone();
        let app = Router::new().route(
            "/compatible-mode/v1/chat/completions",
            axum::routing::post(move |req: Request| {
                let record = record.clone();
                async move {
                    let auth = req
                        .headers()
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_string);
                    let body = axum::body::to_bytes(req.into_body(), MAX_BODY_BYTES)
                        .await
                        .unwrap();
                    let mut seen = record.lock().unwrap();
                    seen.calls += 1;
                    if seen.calls == 1 {
                        seen.retry_body = Some(body.to_vec()); // first (translated) body
                        return Response::builder()
                            .status(StatusCode::PAYMENT_REQUIRED)
                            .header(header::WWW_AUTHENTICATE, challenge_header("localnet"))
                            .body(Body::from(r#"{"error":"payment required"}"#))
                            .unwrap();
                    }
                    let first_body = seen.retry_body.clone();
                    seen.retry_auth = auth;
                    assert_eq!(
                        first_body.as_deref(),
                        Some(&body[..]),
                        "retry must replay the exact translated body"
                    );
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(PAYMENT_RESPONSE_HEADER, "translated-mpp-receipt")
                        .body(Body::from(OPENAI_COMPLETION_JSON))
                        .unwrap()
                }
            }),
        );
        let upstream = spawn_server(app).await;
        let payer = spawn_openai_payer(upstream, None).await;

        let resp = reqwest::Client::new()
            .post(format!("{payer}/v1/messages"))
            .json(&anthropic_request_body())
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(PAYMENT_RESPONSE_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some("translated-mpp-receipt")
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["type"], "message",
            "paid retry must come back translated"
        );
        assert_eq!(body["content"][0]["text"], "Hello!");

        let seen = seen.lock().unwrap();
        assert_eq!(seen.calls, 2, "exactly one paid retry");
        let auth = seen
            .retry_auth
            .as_deref()
            .expect("retry carries Authorization");
        assert!(
            auth.starts_with("Payment "),
            "MPP credential expected, got: {auth}"
        );
        // The body the 402 fired on — and that the retry replayed — is
        // the *translated* OpenAI body.
        let translated: serde_json::Value =
            serde_json::from_slice(seen.retry_body.as_deref().unwrap()).unwrap();
        assert_eq!(translated["messages"][0]["role"], "system");
        assert_eq!(translated["messages"][1]["content"], "hi");
        assert!(translated.get("system").is_none());
    }
}
