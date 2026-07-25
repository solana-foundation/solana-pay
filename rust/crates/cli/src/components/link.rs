//! Terminal hyperlink helpers (OSC 8 escape sequences).
//!
//! Used to print clickable links in the terminal. Supported by iTerm2,
//! GNOME Terminal, kitty, WezTerm, and most modern terminal emulators.

use owo_colors::OwoColorize;

use crate::network::SolanaExplorerCluster;

use super::terminal::sanitize_terminal_text;

/// The character appended to visually indicate a clickable link.
pub const LINK_ARROW: &str = "↗";

/// Wrap `text` in an OSC 8 hyperlink pointing to `url`.
///
/// Note: the hyperlink covers only the exact `text` — no padding, no arrow.
/// Pairs well with [`link_with_arrow`] when you want a visible indicator.
pub fn link(text: &str, url: &str) -> String {
    let text = sanitize_terminal_text(text);
    let url = sanitize_terminal_text(url);
    format!("\x1b]8;;{url}\x1b\\{text}\x1b]8;;\x1b\\")
}

/// Wrap `text` in an OSC 8 hyperlink and append a dimmed `↗` arrow after it.
///
/// The link only covers `text`, not the arrow, so the visible indicator
/// is outside the clickable area (avoiding extra padding being clickable).
pub fn link_with_arrow(text: &str, url: &str) -> String {
    format!("{} {}", link(text, url), LINK_ARROW.dimmed())
}

/// Build the `?cluster=...` query suffix for Solana Explorer URLs.
///
/// Retained for the few places (e.g. server start's tokens-page link)
/// that still point at Solana Explorer for non-receipt views; receipts
/// route through pay.sh via [`solana_transaction_link`].
pub fn solana_explorer_cluster_query(cluster: &SolanaExplorerCluster) -> String {
    cluster.query_suffix()
}

/// Link to a transaction receipt on pay.sh.
///
/// `network` is the pay-side slug (`mainnet`, `devnet`, `testnet`,
/// `localnet`/`surfnet`). The pay.sh receipt page resolves the signature
/// to the right chain via the `?network=` query (sandbox for local).
/// Falls back to the bare signature when the network slug is unknown.
pub fn solana_transaction_link(signature: &str, network: &str) -> String {
    let signature = sanitize_terminal_text(signature);
    let network = sanitize_terminal_text(network);
    match pay_core::explorer::tx_url(&network, &signature) {
        Some(url) => link_with_arrow("Link to receipt", &url),
        None => signature.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solana_transaction_link_uses_pay_sh_for_mainnet() {
        let rendered = solana_transaction_link("sig123", "mainnet");
        assert!(rendered.contains("https://pay.sh/receipt/sig123"));
        assert!(!rendered.contains("network="));
        assert!(rendered.contains("Link to receipt"));
    }

    #[test]
    fn solana_transaction_link_marks_sandbox_for_localnet() {
        let rendered = solana_transaction_link("sig123", "localnet");
        assert!(rendered.contains("https://pay.sh/receipt/sig123?network=sandbox"));
    }

    #[test]
    fn solana_transaction_link_falls_back_to_bare_signature_for_unknown_network() {
        let rendered = solana_transaction_link("sig123", "solana-bogus");
        assert_eq!(rendered, "sig123");
    }

    #[test]
    fn links_do_not_embed_untrusted_terminal_controls() {
        let rendered = link("receipt\u{1b}[2J", "https://pay.sh/\u{1b}]8;;evil");

        assert_eq!(rendered.matches('\u{1b}').count(), 4);
        assert!(rendered.contains("receipt[2J"));
        assert!(!rendered.contains("\u{1b}[2J"));
    }
}
