//! Sandbox mode: generate a funded keypair via surfpool cheatcodes.

use std::io::Write;

use tempfile::NamedTempFile;
use tracing::info;

use crate::{Error, Result};

const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// A sandbox keypair with its temp file (kept alive for the process lifetime).
pub struct SandboxKeypair {
    /// Path to the JSON keypair file.
    pub path: String,
    /// Base58 public key.
    pub pubkey: String,
    /// Keep the temp file alive.
    _file: NamedTempFile,
}

/// Generate a fresh keypair, fund it on localnet, and return the path.
///
/// Uses surfpool cheatcodes:
/// - `surfnet_setAccount` for 100 SOL
/// - `surfnet_setTokenAccount` for 1000 USDC
pub async fn setup_sandbox_keypair(rpc_url: &str) -> Result<SandboxKeypair> {
    // Generate 64 random bytes (32 secret + 32 public via ed25519)
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut keypair_bytes = Vec::with_capacity(64);
    keypair_bytes.extend_from_slice(&signing_key.to_bytes());
    keypair_bytes.extend_from_slice(&verifying_key.to_bytes());

    // Write as JSON array to a temp file (standard solana-keygen format)
    let mut file = NamedTempFile::new()?;
    let json: Vec<u8> = keypair_bytes.clone();
    write!(file, "{}", serde_json::to_string(&json)?)?;

    let path = file.path().to_string_lossy().to_string();

    // Derive pubkey (base58)
    let pubkey = crate::b58::encode_32(&verifying_key.to_bytes());

    info!(pubkey = %pubkey, "Generated sandbox keypair");

    fund_via_surfpool(rpc_url, &pubkey).await?;

    Ok(SandboxKeypair {
        path,
        pubkey,
        _file: file,
    })
}

/// Fund an existing pubkey on a Surfpool RPC. Used by the network-aware
/// account routing path: when an ephemeral wallet is lazy-created for
/// `localnet` and the configured RPC is a Surfpool sandbox, we top it up
/// with SOL + USDC so the next payment broadcast doesn't fail with
/// "insufficient funds".
///
/// No-ops gracefully if the RPC isn't a Surfpool — caller decides
/// whether to ignore that or surface it.
pub async fn fund_via_surfpool(rpc_url: &str, pubkey: &str) -> Result<()> {
    check_surfpool(rpc_url).await?;
    fund_sol(rpc_url, pubkey).await?;
    fund_usdc(rpc_url, pubkey).await?;
    info!(pubkey = %pubkey, "Sandbox wallet funded (100 SOL + 1000 USDC)");
    Ok(())
}

/// Ensure an owner has a Surfpool USDC token account with the requested amount.
///
/// This is useful for recipient-only accounts in local demos: they do not need
/// SOL, but settlement/distribution instructions still validate their ATAs.
pub async fn set_surfpool_usdc_token_account(
    rpc_url: &str,
    pubkey: &str,
    amount: u64,
) -> Result<()> {
    check_surfpool(rpc_url).await?;
    set_usdc_amount(rpc_url, pubkey, amount).await?;
    info!(pubkey = %pubkey, amount, "Sandbox USDC token account ensured");
    Ok(())
}

async fn check_surfpool(rpc_url: &str) -> Result<()> {
    let resp = reqwest::Client::new()
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getHealth",
        }))
        .send()
        .await;

    if resp.is_err() {
        return Err(Error::Config(format!(
            "Could not connect to Surfpool at {rpc_url}\n\n\
             Install and start Surfpool:\n\n  \
             # Install Surfpool CLI\n  \
             curl -sL https://run.surfpool.run/ | bash\n\n  \
             # Start local Solana network\n  \
             surfpool start\n"
        )));
    }

    Ok(())
}

async fn rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<()> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let resp = reqwest::Client::new()
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| Error::Config(format!("RPC call to {rpc_url} failed: {e}")))?;

    let result: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| Error::Config(format!("Invalid RPC response: {e}")))?;

    if let Some(err) = result.get("error") {
        return Err(Error::Config(format!("RPC error: {err}")));
    }

    Ok(())
}

async fn fund_sol(rpc_url: &str, pubkey: &str) -> Result<()> {
    rpc_call(
        rpc_url,
        "surfnet_setAccount",
        serde_json::json!([pubkey, {
            "lamports": 100_000_000_000_u64,
            "data": "",
            "executable": false,
            "owner": "11111111111111111111111111111111",
        }]),
    )
    .await
}

const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

async fn fund_usdc(rpc_url: &str, pubkey: &str) -> Result<()> {
    set_usdc_amount(rpc_url, pubkey, 1_000_000_000_u64).await
}

async fn set_usdc_amount(rpc_url: &str, pubkey: &str, amount: u64) -> Result<()> {
    rpc_call(
        rpc_url,
        "surfnet_setTokenAccount",
        serde_json::json!([pubkey, USDC_MINT, {
            "amount": amount,
        }, TOKEN_PROGRAM]),
    )
    .await
}
