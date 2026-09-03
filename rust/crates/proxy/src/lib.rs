//! `pay-proxy` — the production data plane, as a library `pay` relies on.
//!
//! [`Http402Gate`] is a Pingora [`ProxyHttp`](pingora::proxy::ProxyHttp) that
//! runs the framework-agnostic `pay_core::server::gate::PaymentGate` and proxies
//! natively: metered traffic to the endpoint's real upstream, control-plane
//! paths to an internal axum service.
//!
//! Callers ([`run`]) build their own `PaymentState` + an internal axum
//! control-plane service, then hand the public bind to Pingora.

pub mod http402;
pub mod observer;

pub use http402::Http402Gate;

use pay_core::PaymentState;
use pingora::proxy::http_proxy_service;
use pingora::server::{RunArgs, Server};
#[cfg(unix)]
use {
    async_trait::async_trait,
    pingora::server::{ShutdownSignal, ShutdownSignalWatch},
};

/// Build and run the Pingora gateway on `bind`, fronting `state`'s
/// [`PaymentGate`] and forwarding control-plane traffic to `control_plane`
/// (the `host:port` of an internal axum service).
///
/// **Blocks forever** — Pingora owns its own runtimes, so this MUST be called
/// from a thread with no ambient tokio runtime (e.g. the main thread after the
/// caller's `block_on` has returned, with the axum control-plane already spawned
/// on its own thread/runtime).
pub fn run<S: PaymentState>(
    state: S,
    bind: &str,
    control_plane: String,
    threads: Option<usize>,
) -> anyhow::Result<()> {
    run_inner(state, bind, control_plane, threads, None)
}

/// Run the gateway with a native TLS listener.
///
/// The certificate must cover the host clients connect to (a DNS name or IP
/// SAN). HTTP/2 is advertised through ALPN; HTTP/1.1 remains available.
pub fn run_tls<S: PaymentState>(
    state: S,
    bind: &str,
    control_plane: String,
    threads: Option<usize>,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<()> {
    run_inner(
        state,
        bind,
        control_plane,
        threads,
        Some((cert_path, key_path)),
    )
}

fn run_inner<S: PaymentState>(
    state: S,
    bind: &str,
    control_plane: String,
    threads: Option<usize>,
    tls: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    // rustls 0.23 requires a process-default CryptoProvider. The dependency tree
    // enables BOTH ring (pingora) and aws-lc-rs (reqwest), so rustls can't pick
    // one automatically and pingora's TLS init panics. Install ring (what
    // pingora-rustls uses) once, before any pingora TLS setup. Idempotent — the
    // Err just means a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut server = Server::new(None).map_err(|e| anyhow::anyhow!("pingora server: {e}"))?;
    server.bootstrap();
    let gate = Http402Gate::new(state, control_plane);
    let mut svc = http_proxy_service(&server.configuration, gate);
    // Pingora services default to a single worker thread — match the core count
    // so it spreads across cores like the tokio proxy did.
    let cores = threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
    });
    svc.threads = Some(cores);
    let mut server_options = pingora::apps::HttpServerOptions::default();
    server_options.h2c = tls.is_none();
    svc.app_logic_mut()
        .expect("new Pingora service has app logic")
        .server_options = Some(server_options);
    if let Some((cert_path, key_path)) = tls {
        let mut settings = pingora::listeners::tls::TlsSettings::intermediate(cert_path, key_path)
            .map_err(|error| anyhow::anyhow!("pingora TLS config: {error}"))?;
        settings.enable_h2();
        svc.add_tls_with_settings(bind, None, settings);
    } else {
        svc.add_tcp(bind);
    }
    server.add_service(svc);
    tracing::info!(
        bind,
        threads = cores,
        tls = tls.is_some(),
        "pingora gateway up (Http402Gate)"
    );
    server.run_forever();
}

/// Like [`run`], but shuts down when `shutdown` flips to `true` (or on
/// SIGTERM) and **returns** instead of exiting the process.
///
/// For callers that own the terminal/process lifecycle — e.g. the inference
/// TUI, which runs Pingora on a spawned thread and must restore the terminal
/// after quit. Sends Pingora a fast shutdown (no grace-period sleep).
pub fn run_with_shutdown<S: PaymentState>(
    state: S,
    bind: &str,
    control_plane: String,
    threads: Option<usize>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut server = Server::new(None).map_err(|e| anyhow::anyhow!("pingora server: {e}"))?;
    server.bootstrap();
    let gate = Http402Gate::new(state, control_plane);
    let mut svc = http_proxy_service(&server.configuration, gate);
    let cores = threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(8)
    });
    svc.threads = Some(cores);
    let mut server_options = pingora::apps::HttpServerOptions::default();
    server_options.h2c = true;
    svc.app_logic_mut()
        .expect("new Pingora service has app logic")
        .server_options = Some(server_options);
    svc.add_tcp(bind);
    server.add_service(svc);
    tracing::info!(bind, threads = cores, "pingora gateway up (Http402Gate)");
    // Pingora's caller-driven shutdown (`RunArgs::shutdown_signal`) is unix-only;
    // on Windows the server can't be signalled programmatically, so we just run it
    // with defaults and drop the watcher.
    #[cfg(unix)]
    server.run(RunArgs {
        shutdown_signal: Box::new(WatchShutdown(shutdown)),
    });
    #[cfg(windows)]
    {
        let _ = shutdown;
        server.run(RunArgs::default());
    }
    Ok(())
}

/// Pingora shutdown watcher driven by a caller-owned watch channel, with
/// SIGTERM kept as a fallback so headless `kill` still works.
#[cfg(unix)]
struct WatchShutdown(tokio::sync::watch::Receiver<bool>);

#[cfg(unix)]
#[async_trait]
impl ShutdownSignalWatch for WatchShutdown {
    async fn recv(&self) -> ShutdownSignal {
        let mut rx = self.0.clone();
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("install SIGTERM handler");
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    match changed {
                        Ok(()) if *rx.borrow() => return ShutdownSignal::FastShutdown,
                        // Sender dropped: the controlling side is gone; shut down.
                        Err(_) => return ShutdownSignal::FastShutdown,
                        Ok(()) => continue,
                    }
                }
                _ = sigterm.recv() => return ShutdownSignal::GracefulTerminate,
            }
        }
    }
}
