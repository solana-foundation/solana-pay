//! Thin Solana JSON-RPC client built around a shared [`reqwest::Client`].
//!
//! The client is cheap to clone — it wraps an `Arc` internally — so a single
//! instance is shared across all endpoints to amortise TLS handshakes and
//! enable HTTP/2 multiplexing.

use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};

#[derive(Clone)]
pub struct RpcClient {
    http: reqwest::Client,
    timeout: Duration,
}

impl RpcClient {
    pub fn new(timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .tcp_keepalive(Duration::from_secs(60))
            .http2_keep_alive_interval(Duration::from_secs(20))
            .http2_keep_alive_while_idle(true)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(Error::RpcTransport)?;
        Ok(Self { http, timeout })
    }

    /// `getMultipleAccounts` — fetch up to 100 accounts in one call. Returns
    /// `Some(data_bytes)` per account, or `None` if the account does not exist.
    pub async fn get_multiple_accounts(
        &self,
        rpc_url: &str,
        addresses: &[String],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [
                addresses,
                { "commitment": "confirmed", "encoding": "base64" }
            ],
        });

        let resp = self
            .http
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    Error::RpcTimeout {
                        timeout_ms: self.timeout.as_millis() as u64,
                    }
                } else {
                    Error::RpcTransport(e)
                }
            })?;

        if resp.status().as_u16() == 429 {
            return Err(Error::RpcRateLimited);
        }
        if !resp.status().is_success() {
            return Err(Error::RpcResponse(format!("HTTP {}", resp.status())));
        }

        let parsed: RpcEnvelope = resp.json().await.map_err(Error::RpcTransport)?;
        if let Some(err) = parsed.error {
            return Err(Error::RpcResponse(err.message));
        }
        let value = parsed.result.ok_or(Error::RpcMalformed)?.value;

        let mut out = Vec::with_capacity(value.len());
        for entry in value {
            match entry {
                None => out.push(None),
                Some(account) => {
                    // data is [base64_string, "base64"]
                    let b64 = account.data.first().ok_or(Error::RpcMalformed)?;
                    let bytes = base64_decode(b64)?;
                    out.push(Some(bytes));
                }
            }
        }
        Ok(out)
    }

    /// Helius DAS `getAsset` price lookup. The configured mainnet RPC URL must
    /// be a Helius endpoint; standard Solana RPC hosts do not expose DAS.
    pub async fn get_asset_price_per_token(&self, rpc_url: &str, asset_id: &str) -> Result<f64> {
        let body = asset_price_request_body(asset_id);
        let result = self.post_rpc_value(rpc_url, body).await?;
        parse_das_price_per_token(&result)
    }

    /// Best-effort SOL/USD spot price from CoinGecko's public API.
    ///
    /// Used as a fallback when the configured mainnet RPC isn't a Helius
    /// endpoint (so `get_asset_price_per_token` can't resolve a price). The
    /// returned value is the **current** spot price — it is not the price at
    /// the receipt's block_time. Callers should label it accordingly in any
    /// UI that surfaces it.
    pub async fn fetch_sol_usd_spot_via_coingecko(&self) -> Result<f64> {
        let resp = self
            .http
            .get("https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd")
            .header("accept", "application/json")
            // CoinGecko's public endpoint rejects requests without a descriptive
            // User-Agent. Identify ourselves so they can rate-limit us
            // appropriately instead of returning 403.
            .header("user-agent", "pay-api/0.1 (+https://pay.sh)")
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    Error::RpcTimeout {
                        timeout_ms: self.timeout.as_millis() as u64,
                    }
                } else {
                    Error::RpcTransport(e)
                }
            })?;
        if !resp.status().is_success() {
            return Err(Error::PriceUnavailable);
        }
        let body: Value = resp.json().await.map_err(Error::RpcTransport)?;
        body.pointer("/solana/usd")
            .and_then(json_number)
            .filter(|p| p.is_finite() && *p > 0.0)
            .ok_or(Error::PriceUnavailable)
    }

    /// `getMultipleAccounts` returning both `data` bytes and `owner` per
    /// account. Used by code paths that need to discover which candidate
    /// address actually belongs to a specific program (e.g. the channel PDA
    /// among an instruction's account list).
    pub async fn get_multiple_accounts_with_owner(
        &self,
        rpc_url: &str,
        addresses: &[String],
    ) -> Result<Vec<Option<AccountInfo>>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMultipleAccounts",
            "params": [
                addresses,
                { "commitment": "confirmed", "encoding": "base64" }
            ],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        let value = result
            .get("value")
            .and_then(Value::as_array)
            .ok_or(Error::RpcMalformed)?;
        let mut out = Vec::with_capacity(value.len());
        for entry in value {
            if entry.is_null() {
                out.push(None);
                continue;
            }
            let owner = entry
                .get("owner")
                .and_then(Value::as_str)
                .ok_or(Error::RpcMalformed)?
                .to_string();
            let data_array = entry
                .get("data")
                .and_then(Value::as_array)
                .ok_or(Error::RpcMalformed)?;
            let b64 = data_array
                .first()
                .and_then(Value::as_str)
                .ok_or(Error::RpcMalformed)?;
            let bytes = base64_decode(b64)?;
            out.push(Some(AccountInfo { owner, data: bytes }));
        }
        Ok(out)
    }

    /// Current confirmed slot.
    pub async fn get_slot(&self, rpc_url: &str) -> Result<u64> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSlot",
            "params": [{ "commitment": "confirmed" }],
        });
        self.post_rpc_value(rpc_url, body)
            .await?
            .as_u64()
            .ok_or(Error::RpcMalformed)
    }

    /// Scan fixed-size program accounts whose byte at `memcmp_offset` matches
    /// `memcmp_bytes`. Used by the channel reclaimer to discover only
    /// `Distributed` accounts, avoiding a separate durable queue.
    pub async fn get_program_accounts_filtered(
        &self,
        rpc_url: &str,
        program_id: &str,
        data_size: usize,
        memcmp_offset: usize,
        memcmp_bytes: &[u8],
    ) -> Result<Vec<ProgramAccount>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getProgramAccounts",
            "params": [
                program_id,
                {
                    "commitment": "confirmed",
                    "encoding": "base64",
                    "filters": [
                        { "dataSize": data_size },
                        {
                            "memcmp": {
                                "offset": memcmp_offset,
                                "bytes": bs58::encode(memcmp_bytes).into_string()
                            }
                        }
                    ]
                }
            ],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        let entries = result.as_array().ok_or(Error::RpcMalformed)?;
        entries
            .iter()
            .map(|entry| {
                let pubkey = entry
                    .get("pubkey")
                    .and_then(Value::as_str)
                    .ok_or(Error::RpcMalformed)?
                    .to_string();
                let data = entry
                    .pointer("/account/data/0")
                    .and_then(Value::as_str)
                    .ok_or(Error::RpcMalformed)
                    .and_then(base64_decode)?;
                Ok(ProgramAccount { pubkey, data })
            })
            .collect()
    }

    /// `getSignaturesForAddress` — return the confirmed signatures that touched
    /// `address`, newest first, as raw base58 strings. Used by the
    /// close-channels job to walk back to a channel's `open` (creation)
    /// transaction so it can recover the distribution preimage.
    ///
    /// `before` paginates: pass the oldest signature from the previous page to
    /// fetch the next (older) page. `limit` caps the page size (RPC max 1000).
    pub async fn get_signatures_for_address(
        &self,
        rpc_url: &str,
        address: &str,
        before: Option<&str>,
        limit: u32,
    ) -> Result<Vec<String>> {
        let mut opts = json!({
            "limit": limit,
            "commitment": "confirmed",
        });
        if let Some(before) = before {
            opts["before"] = Value::String(before.to_string());
        }
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignaturesForAddress",
            "params": [address, opts],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        let array = result.as_array().ok_or(Error::RpcMalformed)?;
        let mut out = Vec::with_capacity(array.len());
        for entry in array {
            let sig = entry
                .get("signature")
                .and_then(Value::as_str)
                .ok_or(Error::RpcMalformed)?;
            out.push(sig.to_string());
        }
        Ok(out)
    }

    /// `getTransaction` with `jsonParsed` encoding. Returns the entire RPC
    /// result so callers can pick the fields they need.
    ///
    /// Returns `Ok(None)` when the cluster does not know about the signature
    /// (404-equivalent for receipts), and an error for transport or RPC
    /// failures so the caller can map to 502/504/429.
    pub async fn get_transaction_json_parsed(
        &self,
        rpc_url: &str,
        signature: &str,
    ) -> Result<Option<Value>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "commitment": "confirmed",
                    "encoding": "jsonParsed",
                    "maxSupportedTransactionVersion": 0
                }
            ],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        if result.is_null() {
            return Ok(None);
        }
        Ok(Some(result))
    }

    /// `getTransaction` with `base64` encoding. Returns the base64 string of
    /// the raw (bincode-serialized) transaction message, or `Ok(None)` when the
    /// cluster doesn't know the signature.
    ///
    /// The close-channels job uses this to bincode-decode a channel's `open`
    /// transaction and read the raw `open` instruction data (the distribution
    /// preimage lives in those bytes; only its hash is stored on-chain).
    pub async fn get_transaction_base64(
        &self,
        rpc_url: &str,
        signature: &str,
    ) -> Result<Option<String>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {
                    "commitment": "confirmed",
                    "encoding": "base64",
                    "maxSupportedTransactionVersion": 0
                }
            ],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        if result.is_null() {
            return Ok(None);
        }
        let b64 = result
            .pointer("/transaction/0")
            .and_then(Value::as_str)
            .ok_or(Error::RpcMalformed)?;
        Ok(Some(b64.to_string()))
    }

    /// `getSignatureStatuses` with `searchTransactionHistory`. Returns the
    /// first status entry (which may itself be `null` if the signature is not
    /// known to the cluster).
    pub async fn get_signature_status(
        &self,
        rpc_url: &str,
        signature: &str,
    ) -> Result<Option<Value>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getSignatureStatuses",
            "params": [
                [signature],
                { "searchTransactionHistory": true }
            ],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        let entry = result.pointer("/value/0").cloned().unwrap_or(Value::Null);
        if entry.is_null() {
            return Ok(None);
        }
        Ok(Some(entry))
    }

    /// `getMinimumBalanceForRentExemption` for a byte length.
    pub async fn get_minimum_balance_for_rent_exemption(
        &self,
        rpc_url: &str,
        data_len: usize,
    ) -> Result<u64> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getMinimumBalanceForRentExemption",
            "params": [data_len],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        result.as_u64().ok_or(Error::RpcMalformed)
    }

    /// `getLatestBlockhash` — return the most recent blockhash the
    /// upstream cluster sees at `confirmed` commitment, base58-encoded.
    ///
    /// Used to seed the cancel-tx the gateway co-signs: the cancel
    /// challenge response embeds this so clients don't need their own
    /// Solana RPC connection to build the tx — same pattern MPP charge
    /// uses with `methodDetails.recentBlockhash`.
    pub async fn get_latest_blockhash(&self, rpc_url: &str) -> Result<String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getLatestBlockhash",
            "params": [{ "commitment": "confirmed" }],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        result
            .get("value")
            .and_then(|v| v.get("blockhash"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or(Error::RpcMalformed)
    }

    /// `sendTransaction` — submit a fully-signed, base64-encoded transaction.
    /// Returns the transaction signature on success.
    ///
    /// The `preflight_commitment` is fixed at `confirmed` so a missing
    /// SubscriptionAuthority / Plan / etc. surfaces as a simulation error
    /// before the gateway pays for an on-chain failure.
    pub async fn send_raw_transaction(
        &self,
        rpc_url: &str,
        signed_tx_base64: &str,
    ) -> Result<String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "sendTransaction",
            "params": [
                signed_tx_base64,
                {
                    "encoding": "base64",
                    "skipPreflight": false,
                    "preflightCommitment": "confirmed",
                    "maxRetries": 0,
                }
            ],
        });
        let result = self.post_rpc_value(rpc_url, body).await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or(Error::RpcMalformed)
    }

    /// Poll `getSignatureStatuses` until the supplied signature reaches the
    /// `confirmed` commitment or the deadline expires. Returns `Ok(())` on
    /// confirmation, `Err(Error::RpcResponse)` if the transaction landed
    /// but failed, `Err(Error::RpcTimeout)` if the deadline elapses.
    pub async fn confirm_signature(
        &self,
        rpc_url: &str,
        signature: &str,
        max_wait: Duration,
    ) -> Result<()> {
        // Total polling budget; we re-check on a short loop. Cancel-class
        // transactions usually land within 1–2 slots.
        let deadline = std::time::Instant::now() + max_wait;
        let mut backoff = Duration::from_millis(400);
        let max_backoff = Duration::from_millis(2_000);

        loop {
            let body = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSignatureStatuses",
                "params": [[signature], { "searchTransactionHistory": true }],
            });
            let result = self.post_rpc_value(rpc_url, body).await?;
            let entry = result
                .get("value")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .cloned()
                .unwrap_or(Value::Null);

            if !entry.is_null() {
                // If the tx failed on-chain `err` is non-null. Don't keep polling.
                if let Some(err) = entry.get("err")
                    && !err.is_null()
                {
                    return Err(Error::RpcResponse(format!(
                        "Transaction failed on-chain: {err}"
                    )));
                }
                let confirmation = entry
                    .get("confirmationStatus")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if confirmation == "confirmed" || confirmation == "finalized" {
                    return Ok(());
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(Error::RpcTimeout {
                    timeout_ms: max_wait.as_millis() as u64,
                });
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(max_backoff);
        }
    }

    /// Crate-internal helper used by the token-metadata module to run an
    /// ad-hoc JSON-RPC request (currently Helius DAS `getAsset`). Lives on the
    /// pooled client so it shares the same retry / rate-limit handling as the
    /// dedicated wrappers above. **Not exposed beyond `pay-api-core`** — the
    /// public surface for callers is the dedicated wrappers + receipt builder.
    pub(crate) async fn post_rpc_value_internal(
        &self,
        rpc_url: &str,
        body: Value,
    ) -> Result<Value> {
        self.post_rpc_value(rpc_url, body).await
    }

    async fn post_rpc_value(&self, rpc_url: &str, body: Value) -> Result<Value> {
        let resp = self
            .http
            .post(rpc_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    Error::RpcTimeout {
                        timeout_ms: self.timeout.as_millis() as u64,
                    }
                } else {
                    Error::RpcTransport(e)
                }
            })?;

        if resp.status().as_u16() == 429 {
            return Err(Error::RpcRateLimited);
        }
        if !resp.status().is_success() {
            return Err(Error::RpcResponse(format!("HTTP {}", resp.status())));
        }

        let parsed: ValueRpcEnvelope = resp.json().await.map_err(Error::RpcTransport)?;
        if let Some(err) = parsed.error {
            return Err(Error::RpcResponse(err.message));
        }
        parsed.result.ok_or(Error::RpcMalformed)
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::RpcMalformed)
}

fn asset_price_request_body(asset_id: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getAsset",
        "params": {
            "id": asset_id,
            "displayOptions": {
                "showFungible": true
            }
        },
    })
}

/// Account info with both decoded data and the owning program. Mirrors what
/// the Solana RPC returns in `getAccountInfo` / `getMultipleAccounts`.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub owner: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProgramAccount {
    pub pubkey: String,
    pub data: Vec<u8>,
}

#[derive(Deserialize)]
struct RpcEnvelope {
    result: Option<RpcResult>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcResult {
    value: Vec<Option<RpcAccount>>,
}

#[derive(Deserialize)]
struct RpcAccount {
    /// `[data_string, encoding]` — encoding is always "base64" for our request.
    data: Vec<String>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

#[derive(Deserialize)]
struct ValueRpcEnvelope {
    result: Option<Value>,
    error: Option<RpcError>,
}

fn parse_das_price_per_token(result: &Value) -> Result<f64> {
    let price = result
        .pointer("/token_info/price_info/price_per_token")
        .and_then(json_number)
        .ok_or(Error::PriceUnavailable)?;

    if price.is_finite() && price > 0.0 {
        Ok(price)
    } else {
        Err(Error::PriceUnavailable)
    }
}

fn json_number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|s| s.parse::<f64>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_das_price_per_token_reads_helius_shape() {
        let value = json!({
            "token_info": {
                "price_info": {
                    "price_per_token": 145.32,
                    "currency": "USDC"
                }
            }
        });

        assert_eq!(parse_das_price_per_token(&value).unwrap(), 145.32);
    }

    #[test]
    fn asset_price_request_body_uses_current_helius_display_option() {
        let body = asset_price_request_body("So11111111111111111111111111111111111111112");

        assert_eq!(
            body.pointer("/params/displayOptions/showFungible"),
            Some(&Value::Bool(true))
        );
        assert!(
            body.pointer("/params/displayOptions/showFungibleTokens")
                .is_none()
        );
    }

    #[test]
    fn parse_das_price_per_token_accepts_string_numbers() {
        let value = json!({
            "token_info": {
                "price_info": {
                    "price_per_token": "145.32"
                }
            }
        });

        assert_eq!(parse_das_price_per_token(&value).unwrap(), 145.32);
    }

    #[test]
    fn parse_das_price_per_token_rejects_missing_or_non_positive_price() {
        assert!(parse_das_price_per_token(&json!({})).is_err());
        assert!(
            parse_das_price_per_token(&json!({
                "token_info": { "price_info": { "price_per_token": 0 } }
            }))
            .is_err()
        );
    }
}
