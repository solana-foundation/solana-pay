//! Token metadata lookup.
//!
//! Resolution order:
//! 1. Pre-baked curated table for well-known stablecoins (works offline /
//!    sandbox).
//! 2. The configured stablecoin registry (for `symbol`/`decimals`).
//! 3. Optional Helius DAS `getAsset` lookup for unknown mints on mainnet —
//!    enabled when the configured RPC URL hosts the DAS extension.
//!
//! The DAS lookup is best-effort; failures fall back to "Unknown SPL Token"
//! without surfacing the underlying error.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::error::Result;
use crate::rpc::RpcClient;
use crate::stablecoin::Stablecoin;

/// Resolved token metadata.
#[derive(Debug, Clone, Default)]
pub struct TokenMetadata {
    pub symbol: Option<String>,
    pub name: Option<String>,
    pub logo_uri: Option<String>,
    pub decimals: Option<u8>,
}

impl TokenMetadata {
    pub fn merge_with(&mut self, other: &TokenMetadata) {
        if self.symbol.is_none() {
            self.symbol = other.symbol.clone();
        }
        if self.name.is_none() {
            self.name = other.name.clone();
        }
        if self.logo_uri.is_none() {
            self.logo_uri = other.logo_uri.clone();
        }
        if self.decimals.is_none() {
            self.decimals = other.decimals;
        }
    }
}

/// Native SOL "asset" identifier we use throughout the receipt path.
pub const SOL_ASSET: &str = "SOL";

/// Resolve metadata for a list of distinct mint addresses.
///
/// The returned map keys are mint addresses (or `"SOL"`).
pub async fn resolve_mints(
    rpc: &RpcClient,
    rpc_url: &str,
    network: pay_api_types::Network,
    stablecoins: &[Stablecoin],
    mints: &[String],
) -> HashMap<String, TokenMetadata> {
    let mut out = HashMap::new();
    for mint in mints {
        let mut meta = TokenMetadata::default();
        if mint == SOL_ASSET {
            meta.symbol = Some("SOL".to_string());
            meta.name = Some("Solana".to_string());
            meta.decimals = Some(9);
            meta.logo_uri = Some(SOL_LOGO.to_string());
            out.insert(mint.clone(), meta);
            continue;
        }
        if let Some(curated) = curated_lookup(mint) {
            meta.merge_with(&curated);
        }
        if let Some(coin) = stablecoins.iter().find(|c| c.mint.to_string() == *mint) {
            let from_registry = TokenMetadata {
                symbol: Some(coin.symbol.clone()),
                decimals: Some(coin.decimals),
                ..TokenMetadata::default()
            };
            meta.merge_with(&from_registry);
        }
        if !is_metadata_complete(&meta)
            && matches!(network, pay_api_types::Network::Mainnet)
            && let Some(remote) = fetch_das_metadata(rpc, rpc_url, mint).await.ok().flatten()
        {
            meta.merge_with(&remote);
        }
        out.insert(mint.clone(), meta);
    }
    out
}

fn is_metadata_complete(meta: &TokenMetadata) -> bool {
    meta.symbol.is_some() && meta.name.is_some() && meta.logo_uri.is_some()
}

/// Hardcoded metadata for the curated stablecoin set. Pulled from official
/// token-list assets so they render correctly even on sandbox runs.
fn curated_lookup(mint: &str) -> Option<TokenMetadata> {
    let entry = CURATED_TOKENS.iter().find(|t| t.mint == mint)?;
    Some(TokenMetadata {
        symbol: Some(entry.symbol.to_string()),
        name: Some(entry.name.to_string()),
        logo_uri: Some(entry.logo_uri.to_string()),
        decimals: Some(entry.decimals),
    })
}

const SOL_LOGO: &str = "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/So11111111111111111111111111111111111111112/logo.png";

struct Curated {
    mint: &'static str,
    symbol: &'static str,
    name: &'static str,
    logo_uri: &'static str,
    decimals: u8,
}

const CURATED_TOKENS: &[Curated] = &[
    Curated {
        mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        symbol: "USDC",
        name: "USD Coin",
        logo_uri: "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/logo.png",
        decimals: 6,
    },
    Curated {
        mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        symbol: "USDC",
        name: "USD Coin (devnet)",
        logo_uri: "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v/logo.png",
        decimals: 6,
    },
    Curated {
        mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        symbol: "USDT",
        name: "Tether USD",
        logo_uri: "https://raw.githubusercontent.com/solana-labs/token-list/main/assets/mainnet/Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB/logo.svg",
        decimals: 6,
    },
    Curated {
        mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
        symbol: "PYUSD",
        name: "PayPal USD",
        logo_uri: "https://token-icons.s3.amazonaws.com/2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo.png",
        decimals: 6,
    },
    Curated {
        mint: "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
        symbol: "PYUSD",
        name: "PayPal USD (devnet)",
        logo_uri: "https://token-icons.s3.amazonaws.com/2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo.png",
        decimals: 6,
    },
    Curated {
        mint: "2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH",
        symbol: "USDG",
        name: "Global Dollar",
        logo_uri: "https://token-icons.s3.amazonaws.com/2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH.png",
        decimals: 6,
    },
    Curated {
        mint: "4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7",
        symbol: "USDG",
        name: "Global Dollar (devnet)",
        logo_uri: "https://token-icons.s3.amazonaws.com/2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH.png",
        decimals: 6,
    },
    Curated {
        mint: "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
        symbol: "CASH",
        name: "Paxos Cash",
        logo_uri: "https://token-icons.s3.amazonaws.com/CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH.png",
        decimals: 6,
    },
];

async fn fetch_das_metadata(
    rpc: &RpcClient,
    rpc_url: &str,
    mint: &str,
) -> Result<Option<TokenMetadata>> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAsset",
        "params": { "id": mint, "displayOptions": { "showFungible": true } },
    });
    let Ok(value) = rpc.post_rpc_value_internal(rpc_url, body).await else {
        return Ok(None);
    };
    Ok(parse_das_metadata(&value))
}

fn parse_das_metadata(value: &Value) -> Option<TokenMetadata> {
    let mut meta = TokenMetadata::default();
    if let Some(symbol) = value
        .pointer("/token_info/symbol")
        .or_else(|| value.pointer("/content/metadata/symbol"))
        .and_then(Value::as_str)
    {
        meta.symbol = Some(symbol.to_string());
    }
    if let Some(name) = value
        .pointer("/content/metadata/name")
        .and_then(Value::as_str)
    {
        meta.name = Some(name.to_string());
    }
    if let Some(image) = value
        .pointer("/content/links/image")
        .and_then(Value::as_str)
    {
        meta.logo_uri = Some(image.to_string());
    } else if let Some(json_uri) = value.pointer("/content/json_uri").and_then(Value::as_str) {
        meta.logo_uri = Some(json_uri.to_string());
    }
    if let Some(decimals) = value
        .pointer("/token_info/decimals")
        .and_then(Value::as_u64)
    {
        meta.decimals = Some(decimals as u8);
    }
    if meta.symbol.is_some() || meta.name.is_some() || meta.logo_uri.is_some() {
        Some(meta)
    } else {
        None
    }
}
