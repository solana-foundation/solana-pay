//! Lifecycle hooks that register a running `pay gate api` with the local
//! skills config so an MCP agent on the same host can discover it.
//!
//! - `sweep_dead_ephemeral_sources` runs at boot. It TCP-probes every
//!   ephemeral source in `~/.config/pay/skills.yaml` and removes the
//!   ones whose servers aren't reachable — the typical "previous run
//!   crashed without running the de-registration hook" case.
//! - `register` writes a fresh ephemeral entry pointing at this server's
//!   well-known catalog route.
//! - `deregister` removes that entry on graceful shutdown.
//!
//! The skills.yaml file is rewritten in place under each call. Two
//! concurrent gateway starts racing on the file are not currently locked
//! (relying on the underlying short critical section); a follow-up can
//! add a `.lock` sibling if that ever becomes a real issue.

use std::net::ToSocketAddrs;
use std::time::Duration;

use pay_core::skills::config::SkillsConfig;
use pay_core::skills::local::WELL_KNOWN_PATH;

/// Probe budget per ephemeral source during the boot sweep. Short
/// enough that a handful of dead entries don't visibly delay startup.
const SWEEP_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// Build the ephemeral source URL pointing at a server bound on `bind`
/// (e.g. `0.0.0.0:1402`, `127.0.0.1:1402`). The URL we register MUST
/// resolve from the agent's local machine, so we rewrite a wildcard
/// bind to loopback.
pub fn local_source_url(bind: &str) -> String {
    let host = bind.replace("0.0.0.0", "127.0.0.1");
    format!("http://{host}{WELL_KNOWN_PATH}")
}

/// Build the display name attached to the skills.yaml entry. Includes
/// the bound port so multiple concurrent servers each get a unique row.
pub fn local_source_name(subdomain: &str, bind: &str) -> String {
    let port = bind.rsplit_once(':').map(|(_, p)| p).unwrap_or(bind);
    format!("local/{subdomain}:{port}")
}

/// Best-effort: probe every ephemeral source in the config and drop
/// the ones that don't answer a TCP connect within
/// [`SWEEP_PROBE_TIMEOUT`]. Saves the file when it changed. Logs at
/// debug for individual probes — this runs on every `pay gate api` start, no
/// reason to be noisy.
pub fn sweep_dead_ephemeral_sources() -> Result<usize, pay_core::Error> {
    let mut cfg = SkillsConfig::load()?;
    let stale: Vec<(String, String)> = cfg
        .ephemeral_sources()
        .filter(|s| !probe_url_alive(&s.url))
        .map(|s| (s.name.clone(), s.url.clone()))
        .collect();
    if stale.is_empty() {
        return Ok(0);
    }
    let removed = stale.len();
    for (name, url) in &stale {
        tracing::debug!(name = %name, url = %url, "reaping dead ephemeral skills source");
        cfg.remove_source_by_url(url);
    }
    cfg.save()?;
    Ok(removed)
}

/// Register an ephemeral skills source pointing at the local server.
/// Idempotent — re-adding an existing URL is a no-op. Returns the
/// `(name, url)` tuple the caller stashes for the matching
/// `deregister` call.
pub fn register(subdomain: &str, bind: &str) -> Result<(String, String), pay_core::Error> {
    let name = local_source_name(subdomain, bind);
    let url = local_source_url(bind);
    let mut cfg = SkillsConfig::load()?;
    if cfg.add_ephemeral_source(&name, &url) {
        cfg.save()?;
    }
    Ok((name, url))
}

/// Remove the ephemeral entry written by `register`. Idempotent.
///
/// Currently unused: Pingora's `run_forever` owns the process exit so the
/// shutdown hook doesn't fire; stale entries are reaped by
/// `sweep_dead_ephemeral_sources()` on the next start. Retained for the planned
/// graceful-shutdown path.
#[allow(dead_code)]
pub fn deregister(url: &str) -> Result<bool, pay_core::Error> {
    let mut cfg = SkillsConfig::load()?;
    if cfg.remove_source_by_url(url) {
        cfg.save()?;
        return Ok(true);
    }
    Ok(false)
}

/// TCP-connect probe with a short timeout. Used by the boot sweep —
/// a full HTTP round-trip is overkill when "is the port listening"
/// is the question we're actually answering.
fn probe_url_alive(url: &str) -> bool {
    let Some(authority) = url
        .split_once("://")
        .map(|(_, rest)| rest.split_once('/').map(|(a, _)| a).unwrap_or(rest))
    else {
        return false;
    };
    let addrs = match authority.to_socket_addrs() {
        Ok(a) => a.collect::<Vec<_>>(),
        Err(_) => return false,
    };
    for addr in addrs {
        if std::net::TcpStream::connect_timeout(&addr, SWEEP_PROBE_TIMEOUT).is_ok() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_source_url_rewrites_wildcard_to_loopback() {
        assert_eq!(
            local_source_url("0.0.0.0:1402"),
            "http://127.0.0.1:1402/.well-known/pay-skills.json"
        );
    }

    #[test]
    fn local_source_url_preserves_explicit_loopback() {
        assert_eq!(
            local_source_url("127.0.0.1:9999"),
            "http://127.0.0.1:9999/.well-known/pay-skills.json"
        );
    }

    #[test]
    fn local_source_name_includes_port_for_uniqueness() {
        // Two pay-server instances on the same host but different
        // ports must produce distinct names — otherwise skills.yaml
        // would collapse them into one entry.
        let a = local_source_name("helius", "127.0.0.1:1402");
        let b = local_source_name("helius", "127.0.0.1:1403");
        assert_ne!(a, b);
        assert!(a.contains("1402"));
        assert!(b.contains("1403"));
    }

    #[test]
    fn probe_rejects_malformed_url() {
        assert!(!probe_url_alive("not a url"));
        assert!(!probe_url_alive(""));
    }

    #[test]
    fn probe_rejects_unreachable_port() {
        // Reserved port that's vanishingly unlikely to be listening on
        // a test runner. The 500ms timeout caps this at half a second.
        assert!(!probe_url_alive(
            "http://127.0.0.1:1/.well-known/pay-skills.json"
        ));
    }
}
