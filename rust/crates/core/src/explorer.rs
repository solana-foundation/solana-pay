//! pay.sh receipt-link helpers keyed off the `network` slug carried in
//! `accounts.yml` and challenge `methodDetails.network` fields.
//!
//! Centralised here so every command that surfaces an on-chain identifier
//! (subscription activation tx, charge signature, plan PDA, …) renders the
//! same link shape and stays in sync when we add networks.

use pay_kit::x402::exact::{SOLANA_DEVNET, SOLANA_MAINNET, SOLANA_TESTNET};

/// pay.sh receipt viewer base. Resolves the signature against the right
/// chain server-side; clients only need to thread the `network` query
/// param when it's not the implicit default (mainnet).
const PAY_RECEIPT_BASE: &str = "https://pay.sh/receipt";

/// Build a pay.sh receipt URL for a transaction signature on the given
/// network.
///
/// Mainnet is the implicit default and emits the bare URL; every other
/// known network adds `?network=<slug>` (using the pay.sh-side slug, which
/// maps `localnet`/`surfnet` → `sandbox`). Returns `None` for empty
/// signatures or networks we don't have a mapping for.
pub fn tx_url(network: &str, signature: &str) -> Option<String> {
    if signature.is_empty() {
        return None;
    }
    let suffix = match network_query(network)? {
        Some(slug) => format!("?network={slug}"),
        None => String::new(),
    };
    Some(format!("{PAY_RECEIPT_BASE}/{signature}{suffix}"))
}

/// Build an advanced-view pay.sh receipt URL for a transaction signature.
///
/// Unlike [`tx_url`], this always includes `view=advanced`. When an explicit
/// pay.sh network is needed, `network` is emitted first so URLs have the stable
/// shape `?network=<slug>&view=advanced` used by the debugger UI.
pub fn advanced_tx_url(network: &str, signature: &str) -> Option<String> {
    if signature.is_empty() {
        return None;
    }
    let query = match network_query(network)? {
        Some(slug) => format!("?network={slug}&view=advanced"),
        None => "?view=advanced".to_string(),
    };
    Some(format!("{PAY_RECEIPT_BASE}/{signature}{query}"))
}

/// Build a pay.sh address URL for an account / PDA on the given network.
///
/// Currently piggybacks on the receipt path — pay.sh routes both to the
/// same lookup. Update here if address pages move.
pub fn account_url(network: &str, address: &str) -> Option<String> {
    if address.is_empty() {
        return None;
    }
    let suffix = match network_query(network)? {
        Some(slug) => format!("?network={slug}"),
        None => String::new(),
    };
    Some(format!("{PAY_RECEIPT_BASE}/{address}{suffix}"))
}

/// Map a pay-side network slug to the pay.sh `?network=...` query value.
///
/// Returns `Some(None)` for mainnet (no query needed), `Some(Some(slug))`
/// for the explicit non-mainnet networks, and `None` for slugs we don't
/// recognise — callers fall back to printing the bare signature.
fn network_query(network: &str) -> Option<Option<&'static str>> {
    match network {
        "mainnet" | "mainnet-beta" | "solana" | SOLANA_MAINNET => Some(None),
        "devnet" | "solana-devnet" | SOLANA_DEVNET => Some(Some("devnet")),
        "testnet" | "solana-testnet" | SOLANA_TESTNET => Some(Some("testnet")),
        "localnet" | "surfnet" | "sandbox" | "local" | "solana-localnet" => Some(Some("sandbox")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_url_mainnet_has_no_query() {
        let url = tx_url("mainnet", "5J8signature").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/5J8signature");
    }

    #[test]
    fn tx_url_mainnet_beta_alias_has_no_query() {
        let url = tx_url("mainnet-beta", "sig").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/sig");
    }

    #[test]
    fn tx_url_devnet_carries_network_query() {
        let url = tx_url("devnet", "abc123").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/abc123?network=devnet");
    }

    #[test]
    fn tx_url_testnet_carries_network_query() {
        let url = tx_url("testnet", "sig").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/sig?network=testnet");
    }

    #[test]
    fn tx_url_surfnet_maps_to_sandbox() {
        let url = tx_url("surfnet", "sig").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/sig?network=sandbox");
    }

    #[test]
    fn tx_url_localnet_maps_to_sandbox() {
        let url = tx_url("localnet", "sig").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/sig?network=sandbox");
    }

    #[test]
    fn tx_url_supports_debugger_network_aliases() {
        assert_eq!(
            tx_url("sandbox", "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?network=sandbox")
        );
        assert_eq!(
            tx_url("solana-localnet", "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?network=sandbox")
        );
        assert_eq!(
            tx_url(SOLANA_MAINNET, "sig").as_deref(),
            Some("https://pay.sh/receipt/sig")
        );
        assert_eq!(
            tx_url(SOLANA_DEVNET, "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?network=devnet")
        );
        assert_eq!(
            tx_url(SOLANA_TESTNET, "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?network=testnet")
        );
    }

    #[test]
    fn advanced_tx_url_puts_network_before_view() {
        assert_eq!(
            advanced_tx_url("sandbox", "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?network=sandbox&view=advanced")
        );
        assert_eq!(
            advanced_tx_url(SOLANA_DEVNET, "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?network=devnet&view=advanced")
        );
    }

    #[test]
    fn advanced_tx_url_mainnet_only_adds_view() {
        assert_eq!(
            advanced_tx_url(SOLANA_MAINNET, "sig").as_deref(),
            Some("https://pay.sh/receipt/sig?view=advanced")
        );
    }

    #[test]
    fn advanced_tx_url_rejects_unknown_network_or_empty_signature() {
        assert!(advanced_tx_url("solana-bogus", "sig").is_none());
        assert!(advanced_tx_url("mainnet", "").is_none());
    }

    #[test]
    fn tx_url_unknown_network_returns_none() {
        assert!(tx_url("solana-bogus", "sig").is_none());
    }

    #[test]
    fn tx_url_empty_signature_returns_none() {
        assert!(tx_url("mainnet", "").is_none());
    }

    #[test]
    fn account_url_mainnet_round_trips() {
        let url = account_url("mainnet", "MyPDA").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/MyPDA");
    }

    #[test]
    fn account_url_sandbox_round_trips() {
        let url = account_url("localnet", "MyPDA").unwrap();
        assert_eq!(url, "https://pay.sh/receipt/MyPDA?network=sandbox");
    }
}
