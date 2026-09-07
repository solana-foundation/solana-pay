//! Churn-free HTTP/2 transport for the load phase.
//!
//! reqwest's connection pool is `Ver::Auto`: when a burst of concurrent
//! requests hits a host with no idle connection, each request opens its own
//! TCP+TLS connection and only the ALPN-negotiated-h2 winner is kept — the
//! losers are discarded *after* completing a full handshake. Under sustained
//! high-concurrency load this degenerates into thousands of connections/sec of
//! pure handshake churn (measured: ~1.9 connections per user, ~5,700
//! concurrent for 3,000 users), which caps throughput far below the gateway's
//! actual capacity while both ends sit CPU-idle.
//!
//! [`StableH2Pool`] mirrors `h2load`'s design instead: open a FIXED set of
//! HTTP/2 connections once (real TLS + ALPN `h2`), then reuse them for the
//! whole run, multiplexing every request as a new stream over a round-robin
//! choice of connection. No connection is ever opened or closed inside the
//! measured window, so there is zero handshake churn — the client can then
//! drive the gateway to its true ceiling.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// A fixed pool of persistent HTTP/2 connections to one origin.
pub struct StableH2Pool {
    senders: Vec<SendRequest<Full<Bytes>>>,
    next: AtomicUsize,
}

impl StableH2Pool {
    /// Open `connections` persistent h2 connections to the authority in `url`.
    ///
    /// `ca_pem`, when present, is the only trust anchor (the benchmark's private
    /// CA); otherwise the webpki roots are used. All handshakes complete before
    /// this returns, so the caller's measured window starts with a warm pool.
    pub async fn connect(
        url: &str,
        ca_pem: Option<&[u8]>,
        connections: usize,
    ) -> Result<Arc<Self>> {
        // rustls 0.23 needs a process-default CryptoProvider; install ring once
        // (idempotent — Err just means one is already installed).
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let parsed = url::Url::parse(url).with_context(|| format!("parsing target url {url}"))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow!("target url {url} has no host"))?
            .to_string();
        let port = parsed.port().unwrap_or(443);

        let mut roots = RootCertStore::empty();
        if let Some(pem) = ca_pem {
            let mut rd = std::io::BufReader::new(pem);
            for cert in rustls_pemfile::certs(&mut rd) {
                roots
                    .add(cert.context("reading CA cert")?)
                    .context("adding CA cert")?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        let mut tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Insist on HTTP/2 via ALPN. Unlike reqwest's `http2_prior_knowledge`
        // (which skips ALPN and breaks against an ALPN-gated TLS listener), this
        // negotiates h2 the normal way — it just pins the pool size.
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(tls));

        let server_name = ServerName::try_from(host.clone())
            .with_context(|| format!("invalid server name {host}"))?
            .to_owned();

        let mut senders = Vec::with_capacity(connections);
        for i in 0..connections {
            let tcp = TcpStream::connect((host.as_str(), port))
                .await
                .with_context(|| format!("tcp connect {host}:{port} (conn {i})"))?;
            tcp.set_nodelay(true).ok();
            let tls_stream = connector
                .connect(server_name.clone(), tcp)
                .await
                .with_context(|| format!("tls handshake {host}:{port} (conn {i})"))?;
            let (sender, conn) = hyper::client::conn::http2::handshake(
                TokioExecutor::new(),
                TokioIo::new(tls_stream),
            )
            .await
            .with_context(|| format!("h2 handshake {host}:{port} (conn {i})"))?;
            // The connection future drives all streams on this connection for
            // the life of the run; it ends only when the connection closes.
            tokio::spawn(async move {
                let _ = conn.await;
            });
            senders.push(sender);
        }

        Ok(Arc::new(Self {
            senders,
            next: AtomicUsize::new(0),
        }))
    }

    /// Send one request over the next connection (round-robin) as a new h2
    /// stream, returning the response status and — on a non-2xx status only —
    /// the named response header's value (e.g. a scheme's corrective-challenge
    /// header), so a scheme can resynchronize without the cost of capturing it
    /// on every successful response. Ok/Err mirror the driver's existing
    /// status/error accounting.
    pub async fn send(
        &self,
        method: &str,
        url: &str,
        body: &str,
        headers: &[(String, String)],
        capture_header_on_error: &str,
    ) -> Result<(u16, Option<String>), String> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.senders.len();
        let mut sender = self.senders[idx].clone();
        // Blocks until the connection has stream capacity — this is what bounds
        // concurrent streams per connection (server SETTINGS_MAX_CONCURRENT_STREAMS),
        // exactly like h2load's `-m`, without ever opening a new connection.
        sender.ready().await.map_err(|e| classify(&e))?;

        let mut builder = Request::builder().method(method).uri(url);
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let req = builder
            .body(Full::new(Bytes::from(body.to_owned())))
            .map_err(|e| format!("request build: {e}"))?;

        let resp = sender.send_request(req).await.map_err(|e| classify(&e))?;
        let status = resp.status().as_u16();
        let captured = (!(200..300).contains(&status))
            .then(|| resp.headers().get(capture_header_on_error))
            .flatten()
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // Drain the body so the stream is released promptly for reuse.
        let _ = resp.into_body().collect().await;
        Ok((status, captured))
    }
}

fn classify(e: &hyper::Error) -> String {
    if e.is_timeout() {
        "timeout".into()
    } else if e.is_closed() {
        "closed".into()
    } else {
        "h2".into()
    }
}
