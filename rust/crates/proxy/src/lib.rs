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
use pingora::server::Server;
#[cfg(unix)]
use {
    async_trait::async_trait,
    pingora::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch},
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
    ensure_proxy_runtime_supported()?;

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
    svc.add_tcp(bind);
    server.add_service(svc);
    tracing::info!(bind, threads = cores, "pingora gateway up (Http402Gate)");
    server.run_forever();
}

/// Like [`run`], but shuts down when `shutdown` flips to `true` (or on
/// SIGTERM) and **returns** instead of exiting the process.
///
/// For callers that own the terminal/process lifecycle — e.g. the inference
/// TUI, which runs Pingora on a spawned thread and must restore the terminal
/// after quit. Sends Pingora a fast shutdown (no grace-period sleep).
#[cfg(unix)]
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

/// Non-Unix builds fail closed before binding because Pingora 0.5 does not
/// expose its custom shutdown signal hook outside Unix.
#[cfg(not(unix))]
pub fn run_with_shutdown<S: PaymentState>(
    _state: S,
    _bind: &str,
    _control_plane: String,
    _threads: Option<usize>,
    _shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    ensure_proxy_runtime_supported()
}

#[cfg(unix)]
fn ensure_proxy_runtime_supported() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn ensure_proxy_runtime_supported() -> anyhow::Result<()> {
    anyhow::bail!("the Pingora proxy runtime is not supported on this platform")
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

#[cfg(test)]
mod platform_tests {
    use super::ensure_proxy_runtime_supported;

    #[test]
    fn proxy_runtime_support_is_explicit_for_the_host() {
        #[cfg(unix)]
        assert!(ensure_proxy_runtime_supported().is_ok());

        #[cfg(not(unix))]
        assert!(ensure_proxy_runtime_supported().is_err());
    }
}
