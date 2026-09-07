//! Bounded, retrying RPC boundary for public-cluster fixture setup.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use pay_kit::core::tx_pipeline::{TxPipeline, TxPipelineConfig};
use pay_kit::mpp::solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_hash::Hash;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

/// Execution controls are deliberately part of the reviewable fixture plan.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecutionConfig {
    pub window_users: usize,
    pub reconcile_concurrency: usize,
    pub submit_concurrency: usize,
    pub rpc_requests_per_second: u32,
    pub rpc_burst: usize,
    pub request_timeout_seconds: u64,
    pub confirmation_timeout_seconds: u64,
    pub max_attempts: usize,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub jitter_ratio: f64,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            window_users: 32,
            reconcile_concurrency: 1,
            submit_concurrency: 1,
            rpc_requests_per_second: 20,
            rpc_burst: 5,
            request_timeout_seconds: 15,
            confirmation_timeout_seconds: 90,
            max_attempts: 8,
            initial_backoff_ms: 250,
            max_backoff_ms: 10_000,
            jitter_ratio: 0.20,
        }
    }
}

impl ExecutionConfig {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(self.window_users > 0, "execution.window_users must be > 0");
        anyhow::ensure!(
            self.reconcile_concurrency > 0,
            "execution.reconcile_concurrency must be > 0"
        );
        anyhow::ensure!(
            self.submit_concurrency > 0,
            "execution.submit_concurrency must be > 0"
        );
        anyhow::ensure!(
            self.rpc_requests_per_second > 0,
            "execution.rpc_requests_per_second must be > 0"
        );
        anyhow::ensure!(self.rpc_burst > 0, "execution.rpc_burst must be > 0");
        anyhow::ensure!(
            self.request_timeout_seconds > 0,
            "execution.request_timeout_seconds must be > 0"
        );
        anyhow::ensure!(
            self.confirmation_timeout_seconds > 0,
            "execution.confirmation_timeout_seconds must be > 0"
        );
        anyhow::ensure!(self.max_attempts > 0, "execution.max_attempts must be > 0");
        anyhow::ensure!(
            self.initial_backoff_ms > 0,
            "execution.initial_backoff_ms must be > 0"
        );
        anyhow::ensure!(
            self.initial_backoff_ms <= self.max_backoff_ms,
            "execution.initial_backoff_ms must be <= max_backoff_ms"
        );
        anyhow::ensure!(
            self.jitter_ratio.is_finite() && (0.0..=1.0).contains(&self.jitter_ratio),
            "execution.jitter_ratio must be between 0 and 1"
        );
        Ok(())
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    updated_at: Instant,
}

#[derive(Debug)]
struct RateLimiter {
    rate_per_second: f64,
    burst: f64,
    bucket: Mutex<Bucket>,
}

impl RateLimiter {
    fn new(rate_per_second: u32, burst: usize) -> Self {
        Self {
            rate_per_second: f64::from(rate_per_second),
            burst: burst as f64,
            bucket: Mutex::new(Bucket {
                tokens: burst as f64,
                updated_at: Instant::now(),
            }),
        }
    }

    async fn acquire(&self) {
        loop {
            let wait = {
                let mut bucket = self.bucket.lock().expect("rate limiter mutex poisoned");
                let now = Instant::now();
                let elapsed = now.duration_since(bucket.updated_at).as_secs_f64();
                bucket.tokens = (bucket.tokens + elapsed * self.rate_per_second).min(self.burst);
                bucket.updated_at = now;
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        (1.0 - bucket.tokens) / self.rate_per_second,
                    ))
                }
            };
            if let Some(wait) = wait {
                tokio::time::sleep(wait).await;
            } else {
                return;
            }
        }
    }
}

/// Shared async client with bounded requests and conservative retry policy.
pub struct FixtureRpc {
    client: Arc<RpcClient>,
    tx_pipeline: TxPipeline,
    limiter: RateLimiter,
    in_flight: Semaphore,
    config: ExecutionConfig,
}

impl FixtureRpc {
    pub fn new(url: String, config: ExecutionConfig) -> Self {
        let tx_pipeline = TxPipeline::new(
            url.clone(),
            TxPipelineConfig {
                max_send_concurrency: config.submit_concurrency,
                submission_max_attempts: config.max_attempts,
                submission_initial_backoff: Duration::from_millis(config.initial_backoff_ms),
                submission_max_backoff: Duration::from_millis(config.max_backoff_ms),
                send_interval: Duration::from_secs_f64(
                    1.0 / f64::from(config.rpc_requests_per_second),
                ),
                confirmation_timeout: Duration::from_secs(config.confirmation_timeout_seconds),
                account_read_retries: config.max_attempts.saturating_sub(1),
                ..TxPipelineConfig::default()
            },
        );
        Self {
            client: Arc::new(RpcClient::new(url)),
            tx_pipeline,
            limiter: RateLimiter::new(config.rpc_requests_per_second, config.rpc_burst),
            in_flight: Semaphore::new(config.reconcile_concurrency.max(config.submit_concurrency)),
            config,
        }
    }

    async fn call<T, F, Fut>(&self, method: &'static str, operation: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let attempts = self.config.max_attempts;
        for attempt in 1..=attempts {
            self.limiter.acquire().await;
            let permit = self
                .in_flight
                .acquire()
                .await
                .context("fixture RPC semaphore closed")?;
            let started = Instant::now();
            let result = timeout(
                Duration::from_secs(self.config.request_timeout_seconds),
                operation(),
            )
            .await
            .map_err(|_| anyhow!("{method} timed out"))
            .and_then(|result| result);
            drop(permit);
            let elapsed_ms = started.elapsed().as_millis() as u64;

            match result {
                Ok(value) => {
                    debug!(
                        method,
                        attempt,
                        elapsed_ms,
                        outcome = "ok",
                        "fixture RPC call completed"
                    );
                    return Ok(value);
                }
                Err(error) if attempt < attempts && retryable(&error) => {
                    let delay = self.backoff(attempt);
                    warn!(
                        method,
                        attempt,
                        elapsed_ms,
                        delay_ms = delay.as_millis() as u64,
                        retry_class = "transient",
                        error = %error,
                        "retrying fixture RPC call"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(error) => {
                    debug!(method, attempt, elapsed_ms, outcome = "error", error = %error, "fixture RPC call failed");
                    return Err(error).with_context(|| format!("fixture RPC {method}"));
                }
            }
        }
        unreachable!("attempts is validated to be positive")
    }

    fn backoff(&self, attempt: usize) -> Duration {
        let exponent = attempt.saturating_sub(1).min(20) as u32;
        let base = self
            .config
            .initial_backoff_ms
            .saturating_mul(1u64 << exponent)
            .min(self.config.max_backoff_ms);
        let jitter = (rand::random::<f64>() * 2.0 - 1.0) * self.config.jitter_ratio;
        Duration::from_millis((base as f64 * (1.0 + jitter)).max(1.0) as u64)
    }

    pub async fn minimum_balance_for_rent(&self, data_len: usize) -> Result<u64> {
        let client = Arc::clone(&self.client);
        self.call("getMinimumBalanceForRentExemption", move || {
            let client = Arc::clone(&client);
            async move {
                client
                    .get_minimum_balance_for_rent_exemption(data_len)
                    .await
                    .map_err(|error| anyhow!(error))
            }
        })
        .await
    }

    pub async fn balance(&self, address: &Pubkey) -> Result<u64> {
        let address = *address;
        let client = Arc::clone(&self.client);
        self.call("getBalance", move || {
            let client = Arc::clone(&client);
            async move {
                client
                    .get_balance(&address)
                    .await
                    .map_err(|error| anyhow!(error))
            }
        })
        .await
    }

    pub async fn accounts(
        &self,
        addresses: &[Pubkey],
    ) -> Result<Vec<Option<solana_account::Account>>> {
        let addresses = addresses.to_vec();
        let client = Arc::clone(&self.client);
        self.call("getMultipleAccounts", move || {
            let client = Arc::clone(&client);
            let addresses = addresses.clone();
            async move {
                client
                    .get_multiple_accounts(&addresses)
                    .await
                    .map_err(|error| anyhow!(error))
            }
        })
        .await
    }

    pub async fn latest_blockhash(&self) -> Result<(Hash, u64)> {
        let client = Arc::clone(&self.client);
        self.call("getLatestBlockhash", move || {
            let client = Arc::clone(&client);
            async move {
                // Public RPC URLs are commonly load-balanced across nodes. A
                // confirmed blockhash returned by one backend can still be
                // unknown to the backend that receives the transaction.
                client
                    .get_latest_blockhash_with_commitment(CommitmentConfig::finalized())
                    .await
                    .map_err(|error| anyhow!(error))
            }
        })
        .await
    }

    pub async fn submit_and_confirm(&self, transaction: &Transaction) -> Result<Signature> {
        self.tx_pipeline
            .submit_verified(transaction)
            .await
            .map(|confirmed| confirmed.signature)
            .map_err(anyhow::Error::new)
            .context("submitting and confirming fixture transaction")
    }

    pub async fn signature_status(
        &self,
        signature: Signature,
    ) -> Result<Option<solana_transaction_status_client_types::TransactionStatus>> {
        let client = Arc::clone(&self.client);
        self.call("getSignatureStatuses", move || {
            let client = Arc::clone(&client);
            async move {
                client
                    .get_signature_statuses(&[signature])
                    .await
                    .map(|statuses| statuses.value.into_iter().next().flatten())
                    .map_err(|error| anyhow!(error))
            }
        })
        .await
    }

    pub async fn block_height(&self) -> Result<u64> {
        let client = Arc::clone(&self.client);
        self.call("getBlockHeight", move || {
            let client = Arc::clone(&client);
            async move {
                client
                    .get_block_height_with_commitment(CommitmentConfig::finalized())
                    .await
                    .map_err(|error| anyhow!(error))
            }
        })
        .await
    }
}

/// Checks the whole cause chain, not just the top message: `anyhow!(error)`
/// wraps library errors (reqwest/hyper/io) whose own transient-ness (a reset
/// connection, a timeout) is often several `.source()` levels below the
/// wrapper's own Display text (e.g. reqwest's outer message is just "error
/// sending request for url (...)", with "connection"/"timeout" appearing only
/// in an inner cause) — checking only the top level under-retries real
/// transient errors as if they were permanent.
fn retryable(error: &anyhow::Error) -> bool {
    const NEEDLES: [&str; 13] = [
        "429",
        "500",
        "502",
        "503",
        "504",
        "timeout",
        "timed out",
        "transport",
        "connection",
        "node is unhealthy",
        "account in use",
        "blockhash not found",
        "service unavailable",
    ];
    error.chain().any(|cause| {
        let text = cause.to_string().to_ascii_lowercase();
        NEEDLES.iter().any(|needle| text.contains(needle))
    })
}

#[cfg(test)]
mod tests {
    use super::{ExecutionConfig, retryable};

    #[test]
    fn default_execution_policy_is_valid() {
        ExecutionConfig::default().validate().unwrap();
    }

    #[test]
    fn invalid_execution_policy_is_rejected() {
        let config = ExecutionConfig {
            rpc_burst: 0,
            ..ExecutionConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn retry_classification_is_conservative() {
        assert!(retryable(&anyhow::anyhow!("HTTP 429 rate limited")));
        assert!(retryable(&anyhow::anyhow!("request timed out")));
        assert!(!retryable(&anyhow::anyhow!("insufficient funds")));
    }

    #[test]
    fn retry_classification_checks_the_full_cause_chain() {
        // Mirrors a real reqwest/hyper/io chain: the outer message alone
        // ("error sending request for url (...)") carries none of the
        // retryable keywords — only a deeper cause ("connection error",
        // "Connection reset by peer") does.
        let io_error = std::io::Error::other("Connection reset by peer (os error 104)");
        let hyper_layer = anyhow::Error::new(io_error).context("connection error");
        let outer = hyper_layer.context("error sending request for url (https://example.com)");
        assert!(retryable(&outer));
        assert!(!retryable(
            &anyhow::anyhow!("insufficient funds").context("request failed")
        ));
    }
}
