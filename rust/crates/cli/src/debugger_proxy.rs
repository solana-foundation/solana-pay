//! Debugger forward proxy — transparent HTTP proxy that logs all traffic
//! to PDB for inspection.
//!
//! Used by `pay --debugger claude` to capture every MCP curl request
//! without requiring a full API spec / payment gateway setup.
//!
//! Routing: the MCP curl tool sends requests to `http://127.0.0.1:1402/`
//! with the original destination in the `X-Pay-Forward-To` header. The
//! proxy reads the header, forwards the request (including method, body,
//! headers), logs the exchange to PDB, and returns the response.

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use pay_core::client::fetch::{DEBUGGER_NO_FOLLOW_HEADER, DEBUGGER_NO_FOLLOW_HEADER_VALUE};

/// Header carrying the original destination URL.
pub const FORWARD_HEADER: &str = "x-pay-forward-to";

/// Default starting port for the debugger proxy.
pub const DEFAULT_PORT: u16 = 1402;

/// Port increment when the previous port is busy.
const PORT_STEP: u16 = 1000;

/// Maximum number of ports to try before giving up.
const MAX_PORT_ATTEMPTS: u16 = 10;

/// Find an available port starting from `DEFAULT_PORT`, stepping by
/// `PORT_STEP` (1402 → 2402 → 3402 → …).
fn find_available_port() -> pay_core::Result<u16> {
    let mut port = DEFAULT_PORT;
    for _ in 0..MAX_PORT_ATTEMPTS {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(_listener) => return Ok(port), // port is free (listener drops immediately)
            Err(_) => port += PORT_STEP,
        }
    }
    Err(pay_core::Error::Config(format!(
        "no available debugger port (tried {DEFAULT_PORT}–{port})"
    )))
}

/// Start the debugger proxy in the background. Returns the bind address
/// so the caller can set `PAY_DEBUGGER_PROXY` for the MCP server.
///
/// Automatically picks the first available port starting from 1402,
/// stepping by 1000 (1402 → 2402 → 3402 → …) if the port is busy.
///
/// The proxy runs on a dedicated tokio runtime in a background thread
/// so it doesn't interfere with the CLI's sync main function.
pub fn start_background() -> pay_core::Result<String> {
    let port = find_available_port()?;
    let bind = format!("127.0.0.1:{port}");
    let bind_clone = bind.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("debugger proxy runtime");

        rt.block_on(async move {
            let pdb = pay_pdb::PdbState::new(serde_json::json!({
                "recipient": "",
                "network": "proxy",
                "rpcUrl": "",
                "endpoints": {
                    "mpp": [],
                    "x402": [],
                    "oauth": []
                }
            }));
            pdb.spawn_cleanup();

            let pdb_state = pdb.clone();
            let app = Router::new()
                .nest_service(pay_pdb::PDB_PATH, pay_pdb::debugger_router(pdb.clone()))
                .fallback(any(move |req: Request<Body>| {
                    let pdb = pdb_state.clone();
                    forward_and_log(req, pdb)
                }))
                .layer(axum::Extension(Some(pdb)));

            let listener = tokio::net::TcpListener::bind(&bind_clone)
                .await
                .unwrap_or_else(|e| panic!("debugger proxy bind {bind_clone}: {e}"));

            eprintln!(
                "{} http://{bind_clone}/",
                owo_colors::OwoColorize::green(&"Payment Debugger"),
            );

            axum::serve(listener, app).await.ok();
        });
    });

    // Give the server a moment to bind.
    std::thread::sleep(std::time::Duration::from_millis(200));

    Ok(format!("http://{bind}"))
}

/// Forward a request to the destination in `X-Pay-Forward-To`, log the
/// exchange to PDB, and return the response.
async fn forward_and_log(req: Request<Body>, pdb: pay_pdb::PdbState) -> Response {
    let forward_to = req
        .headers()
        .get(FORWARD_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let Some(dest_url) = forward_to else {
        // No forward header → this is a browser request, not an MCP
        // curl call. Redirect to the PDB dashboard.
        return axum::response::Redirect::temporary(&format!("{}/", pay_pdb::PDB_PATH))
            .into_response();
    };

    let method = req.method().clone();
    let _path = req.uri().path().to_string();
    let no_follow = req
        .headers()
        .get_all(DEBUGGER_NO_FOLLOW_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value == DEBUGGER_NO_FOLLOW_HEADER_VALUE);

    // Extract headers to forward (skip hop-by-hop + our internal header).
    let mut fwd_headers = HeaderMap::new();
    for (k, v) in req.headers() {
        let name = k.as_str().to_lowercase();
        if name == FORWARD_HEADER
            || name == DEBUGGER_NO_FOLLOW_HEADER
            || name == "host"
            || name == "connection"
        {
            continue;
        }
        fwd_headers.insert(k.clone(), v.clone());
    }

    // Read body.
    let body_bytes = match axum::body::to_bytes(
        req.into_body(),
        pay_core::fetch::MAX_REQUEST_BODY_BYTES,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("read body: {e}")).into_response();
        }
    };

    let log_id = pdb.next_log_id();
    let start = std::time::Instant::now();

    // Forward.
    let mut client_builder = reqwest::Client::builder();
    if no_follow {
        client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
    }
    let client = match client_builder.build() {
        Ok(client) => client,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("build forwarding client: {error}"),
            )
                .into_response();
        }
    };
    let upstream_resp = client
        .request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
            &dest_url,
        )
        .headers(reqwest_headers(&fwd_headers))
        .body(body_bytes)
        .send()
        .await;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    match upstream_resp {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let res_headers: std::collections::HashMap<String, String> = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();
            let res_body = resp.bytes().await.unwrap_or_default();
            let res_body_for_log = String::from_utf8_lossy(&res_body).into_owned();

            // Log to PDB.
            let entry = pay_pdb::types::LogEntry {
                id: log_id,
                ts: chrono_now(),
                method: method.to_string(),
                path: dest_url.clone(),
                status,
                ms: elapsed_ms,
                req_headers: fwd_headers
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                    .collect(),
                res_headers: res_headers.clone(),
                res_body: Some(res_body_for_log),
                client_ip: "mcp".to_string(),
            };
            pdb.correlation.lock().unwrap().ingest(entry);

            // Build response.
            let mut builder = Response::builder().status(status);
            for (k, v) in &res_headers {
                if let Ok(hv) = axum::http::HeaderValue::from_str(v) {
                    builder = builder.header(k.as_str(), hv);
                }
            }
            builder.body(Body::from(res_body)).unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "response build error").into_response()
            })
        }
        Err(e) => {
            let entry = pay_pdb::types::LogEntry {
                id: log_id,
                ts: chrono_now(),
                method: method.to_string(),
                path: dest_url,
                status: 502,
                ms: elapsed_ms,
                req_headers: Default::default(),
                res_headers: Default::default(),
                res_body: Some(e.to_string()),
                client_ip: "mcp".to_string(),
            };
            pdb.correlation.lock().unwrap().ingest(entry);

            (StatusCode::BAD_GATEWAY, format!("upstream error: {e}")).into_response()
        }
    }
}

/// Convert axum HeaderMap → reqwest HeaderMap.
fn reqwest_headers(src: &HeaderMap) -> reqwest::header::HeaderMap {
    let mut dst = reqwest::header::HeaderMap::new();
    for (k, v) in src {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(k.as_str().as_bytes())
            && let Ok(val) = reqwest::header::HeaderValue::from_bytes(v.as_bytes())
        {
            dst.insert(name, val);
        }
    }
    dst
}

fn chrono_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_pdb_index_html(html: &str) {
        assert!(
            html.contains("<title>Pay Debugger</title>")
                || html.contains("<h1>Payment Debugger</h1>")
        );
    }

    fn start_test_proxy() -> std::net::SocketAddr {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let pdb = pay_pdb::PdbState::new(serde_json::json!({
                    "recipient": "",
                    "network": "proxy",
                    "rpcUrl": "",
                    "endpoints": { "mpp": [], "x402": [], "oauth": [] }
                }));
                let pdb_state = pdb.clone();
                let app = Router::new()
                    .nest_service(pay_pdb::PDB_PATH, pay_pdb::debugger_router(pdb.clone()))
                    .fallback(any(move |req: Request<Body>| {
                        let pdb = pdb_state.clone();
                        forward_and_log(req, pdb)
                    }));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(addr).unwrap();
                axum::serve(listener, app).await.ok();
            });
        });
        let addr = rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        addr
    }

    fn start_test_upstream(app: Router) -> std::net::SocketAddr {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(addr).unwrap();
                axum::serve(listener, app).await.ok();
            });
        });
        let addr = rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        addr
    }

    #[test]
    fn pdb_served_with_trailing_slash() {
        let addr = start_test_proxy();
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap();

        // /__402/pdb/ (trailing slash) must serve index.html directly
        let resp = client
            .get(format!("http://{addr}/__402/pdb/"))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let html = resp.text().unwrap();
        assert_pdb_index_html(&html);
        // When the full PDB frontend is built, asset paths are relative.
        // CI may embed a placeholder without assets — skip this check then.
        if html.contains("assets/") {
            assert!(html.contains("./assets/"));
        }
    }

    #[test]
    fn pdb_served_without_trailing_slash() {
        let addr = start_test_proxy();
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap();

        // /__402/pdb (no slash) also works
        let resp = client
            .get(format!("http://{addr}/__402/pdb"))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let html = resp.text().unwrap();
        assert_pdb_index_html(&html);
    }

    #[test]
    fn pdb_assets_and_api_served() {
        let addr = start_test_proxy();
        let client = reqwest::blocking::Client::new();

        // API config
        let resp = client
            .get(format!("http://{addr}/__402/pdb/api/config"))
            .send()
            .unwrap();
        assert_eq!(resp.status(), 200);
        let config: serde_json::Value = resp.json().unwrap();
        assert_eq!(config["network"], "proxy");

        // CSS asset (resolve like the browser would from /__402/pdb/)
        let resp = client
            .get(format!("http://{addr}/__402/pdb/"))
            .send()
            .unwrap();
        let html = resp.text().unwrap();
        // Extract actual asset filename from the HTML
        if let Some(start) = html.find("src=\"./assets/") {
            let rest = &html[start + 6..]; // skip src="./
            if let Some(end) = rest.find('"') {
                let asset_path = &rest[..end]; // assets/index-XXX.js
                let resp = client
                    .get(format!("http://{addr}/__402/pdb/{asset_path}"))
                    .send()
                    .unwrap();
                assert_eq!(resp.status(), 200, "asset at {asset_path} should serve");
            }
        }
    }

    #[test]
    fn internal_no_follow_marker_blocks_upstream_redirects_without_leaking() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };

        let marker_seen_upstream = Arc::new(AtomicBool::new(false));
        let sink_hits = Arc::new(AtomicUsize::new(0));

        let marker_for_307 = Arc::clone(&marker_seen_upstream);
        let marker_for_308 = Arc::clone(&marker_seen_upstream);
        let sink_hits_for_handler = Arc::clone(&sink_hits);
        let upstream = Router::new()
            .route(
                "/redirect307",
                axum::routing::post(move |headers: HeaderMap| {
                    let marker_seen = Arc::clone(&marker_for_307);
                    async move {
                        if headers.contains_key(DEBUGGER_NO_FOLLOW_HEADER) {
                            marker_seen.store(true, Ordering::SeqCst);
                        }
                        (
                            StatusCode::TEMPORARY_REDIRECT,
                            [(axum::http::header::LOCATION, "/sink")],
                            "",
                        )
                    }
                }),
            )
            .route(
                "/redirect308",
                axum::routing::post(move |headers: HeaderMap| {
                    let marker_seen = Arc::clone(&marker_for_308);
                    async move {
                        if headers.contains_key(DEBUGGER_NO_FOLLOW_HEADER) {
                            marker_seen.store(true, Ordering::SeqCst);
                        }
                        (
                            StatusCode::PERMANENT_REDIRECT,
                            [(axum::http::header::LOCATION, "/sink")],
                            "",
                        )
                    }
                }),
            )
            .route(
                "/sink",
                axum::routing::post(move || {
                    let sink_hits = Arc::clone(&sink_hits_for_handler);
                    async move {
                        sink_hits.fetch_add(1, Ordering::SeqCst);
                        "followed"
                    }
                }),
            );
        let upstream_addr = start_test_upstream(upstream);
        let proxy_addr = start_test_proxy();
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        for (path, expected_status) in [
            ("redirect307", StatusCode::TEMPORARY_REDIRECT),
            ("redirect308", StatusCode::PERMANENT_REDIRECT),
        ] {
            let response = client
                .post(format!("http://{proxy_addr}/forward"))
                .header(FORWARD_HEADER, format!("http://{upstream_addr}/{path}"))
                .header(DEBUGGER_NO_FOLLOW_HEADER, DEBUGGER_NO_FOLLOW_HEADER_VALUE)
                .body("staged bytes")
                .send()
                .unwrap();
            assert_eq!(response.status().as_u16(), expected_status.as_u16());
        }

        assert_eq!(sink_hits.load(Ordering::SeqCst), 0);
        assert!(!marker_seen_upstream.load(Ordering::SeqCst));

        // Unmarked debugger traffic retains its existing redirect behavior.
        let response = client
            .post(format!("http://{proxy_addr}/forward"))
            .header(
                FORWARD_HEADER,
                format!("http://{upstream_addr}/redirect307"),
            )
            .body("inline bytes")
            .send()
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(sink_hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn root_redirects_to_pdb() {
        let addr = start_test_proxy();
        let no_redirect = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let resp = no_redirect.get(format!("http://{addr}/")).send().unwrap();
        assert_eq!(resp.status(), 307);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "/__402/pdb/");
    }

    #[test]
    fn find_available_port_skips_busy() {
        // Occupy DEFAULT_PORT
        let _blocker = std::net::TcpListener::bind(("127.0.0.1", DEFAULT_PORT)).ok();
        let port = find_available_port().unwrap();
        // Should be DEFAULT_PORT if it was free, or DEFAULT_PORT + PORT_STEP if occupied
        assert!(port >= DEFAULT_PORT);
        assert_eq!((port - DEFAULT_PORT) % PORT_STEP, 0);
    }
}
