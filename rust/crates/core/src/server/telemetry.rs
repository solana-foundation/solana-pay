//! Server telemetry helpers.
//!
//! The helpers emit OpenTelemetry-compatible metric events through `tracing`.
//! When the CLI installs the OTLP subscriber, these become exported metrics.
//! Without that subscriber they remain ordinary structured logs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use axum::http::StatusCode;
use serde_json::json;

pub const METRIC_402_RESPONSES: &str = "pay_402_responses_total";
pub const METRIC_402_SUCCESS: &str = "pay_402_requests_successful_total";
pub const METRIC_CHALLENGE_ERRORS: &str = "pay_402_challenge_errors_total";
pub const METRIC_SETTLEMENT_ERRORS: &str = "pay_payment_settlement_errors_total";
pub const METRIC_PAID_DELIVERY_ERRORS: &str = "pay_paid_delivery_errors_total";
pub const METRIC_UPSTREAM_ERRORS: &str = "pay_upstream_errors_total";
pub const METRIC_PAYMENTS_COLLECTED_USD: &str = "pay_payments_collected_usd_total";
pub const METRIC_CHALLENGE_AMOUNT_USD: &str = "pay_402_challenge_amount_usd";
pub const METRIC_FEE_PAYER_WALLET_SOL: &str = "pay_fee_payer_wallet_sol";
pub const METRIC_FEE_PAID_SOL: &str = "pay_fee_paid_sol_total";
pub const METRIC_FEE_PAYER_BALANCE_ERRORS: &str = "pay_fee_payer_balance_errors_total";

#[derive(Debug, Clone)]
pub struct PaymentAmount {
    pub currency: String,
    pub ui_amount: f64,
}

/// Periodic-probe failures are demoted to debug after this many
/// consecutive failures elapse without intermediate success — until that
/// threshold we only emit at debug. Request-driven failures (any reason
/// other than `"periodic"`) always warn so they surface for the
/// in-flight request that just lost telemetry.
const PERIODIC_WARN_AFTER_CONSECUTIVE_FAILURES: u64 = 5;
const MAX_METRIC_ERROR_LABEL_BYTES: usize = 512;

/// Timeout for a single `getBalance` round-trip. Without this, a stalled
/// RPC connection can hang the periodic probe forever and accumulate
/// warning noise on the next interval tick.
const RPC_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

#[derive(Clone)]
pub struct FeePayerWallet {
    rpc_url: String,
    address: String,
    client: reqwest::Client,
    last_lamports: Arc<AtomicU64>,
    has_observation: Arc<AtomicBool>,
    consecutive_failures: Arc<AtomicU64>,
}

impl FeePayerWallet {
    pub fn new(rpc_url: impl Into<String>, address: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(RPC_REQUEST_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            rpc_url: rpc_url.into(),
            address: address.into(),
            client,
            last_lamports: Arc::new(AtomicU64::new(0)),
            has_observation: Arc::new(AtomicBool::new(false)),
            consecutive_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn observe(&self, reason: &'static str, subdomain: &str, path: &str) {
        match self.fetch_lamports().await {
            Ok(lamports) => {
                let previous = self.last_lamports.swap(lamports, Ordering::Relaxed);
                let had_previous = self.has_observation.swap(true, Ordering::Relaxed);
                self.consecutive_failures.store(0, Ordering::Relaxed);
                let sol = lamports_to_sol(lamports);

                tracing::info!(
                    gauge.pay_fee_payer_wallet_sol = sol,
                    reason,
                    subdomain = %subdomain,
                    path = %path,
                    wallet = %self.address,
                    metric = METRIC_FEE_PAYER_WALLET_SOL,
                    "fee payer wallet balance observed",
                );

                if had_previous && previous > lamports {
                    let fee_paid_sol = lamports_to_sol(previous - lamports);
                    tracing::info!(
                        monotonic_counter.pay_fee_paid_sol_total = fee_paid_sol,
                        reason,
                        subdomain = %subdomain,
                        path = %path,
                        wallet = %self.address,
                        metric = METRIC_FEE_PAID_SOL,
                        "fee payer SOL spend observed",
                    );
                }
            }
            Err(error) => {
                // Periodic background polls hitting a flaky RPC are not
                // actionable noise — debug-log them until a sustained
                // outage crosses the warn threshold. Request-driven
                // observes (post-verify) always warn since they reflect
                // an actual in-flight request that just lost telemetry.
                let failures = self
                    .consecutive_failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                let is_periodic = reason == "periodic";
                let should_warn =
                    !is_periodic || failures >= PERIODIC_WARN_AFTER_CONSECUTIVE_FAILURES;
                if should_warn {
                    tracing::warn!(
                        monotonic_counter.pay_fee_payer_balance_errors_total = 1_u64,
                        reason,
                        subdomain = %subdomain,
                        path = %path,
                        wallet = %self.address,
                        consecutive_failures = failures,
                        error = %error,
                        metric = METRIC_FEE_PAYER_BALANCE_ERRORS,
                        "failed to observe fee payer wallet balance",
                    );
                } else {
                    tracing::debug!(
                        monotonic_counter.pay_fee_payer_balance_errors_total = 1_u64,
                        reason,
                        subdomain = %subdomain,
                        path = %path,
                        wallet = %self.address,
                        consecutive_failures = failures,
                        error = %error,
                        metric = METRIC_FEE_PAYER_BALANCE_ERRORS,
                        "failed to observe fee payer wallet balance (transient)",
                    );
                }
            }
        }
    }

    async fn fetch_lamports(&self) -> Result<u64, String> {
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [self.address],
            }))
            .send()
            .await
            .map_err(|e| format!("RPC request failed: {e}"))?;

        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| format!("RPC response was not JSON: {e}"))?;

        if !status.is_success() {
            return Err(format!("RPC returned {status}: {body}"));
        }

        body.get("result")
            .and_then(|result| result.get("value"))
            .and_then(|value| value.as_u64())
            .ok_or_else(|| format!("RPC response missing result.value: {body}"))
    }
}

pub fn payment_amount_from_raw(
    raw_amount: &str,
    decimals: u8,
    currency: impl Into<String>,
) -> Option<PaymentAmount> {
    Some(PaymentAmount {
        currency: currency.into(),
        ui_amount: raw_amount_to_ui(raw_amount, decimals)?,
    })
}

pub fn raw_amount_to_ui(raw_amount: &str, decimals: u8) -> Option<f64> {
    let raw = raw_amount.parse::<u64>().ok()?;
    Some(raw as f64 / 10f64.powi(decimals as i32))
}

pub fn record_402_challenge_sent(
    protocol: &'static str,
    subdomain: &str,
    path: &str,
    method: &str,
    amount_usd: Option<f64>,
    currencies: &str,
    challenge_count: usize,
) {
    if let Some(amount_usd) = amount_usd {
        tracing::info!(
            monotonic_counter.pay_402_responses_total = 1_u64,
            histogram.pay_402_challenge_amount_usd = amount_usd,
            protocol,
            subdomain = %subdomain,
            path = %path,
            http_method = %method,
            currency = %currencies,
            challenge_count = challenge_count as u64,
            metric = METRIC_402_RESPONSES,
            "402 payment challenge sent",
        );
    } else {
        tracing::info!(
            monotonic_counter.pay_402_responses_total = 1_u64,
            protocol,
            subdomain = %subdomain,
            path = %path,
            http_method = %method,
            currency = %currencies,
            challenge_count = challenge_count as u64,
            metric = METRIC_402_RESPONSES,
            "402 payment challenge sent",
        );
    }
}

pub fn record_challenge_error(protocol: &'static str, currency: &str, error: &str) {
    tracing::error!(
        monotonic_counter.pay_402_challenge_errors_total = 1_u64,
        protocol,
        currency = %currency,
        error = %error,
        metric = METRIC_CHALLENGE_ERRORS,
        "payment challenge generation failed",
    );
}

pub fn record_payment_collected(
    protocol: &'static str,
    subdomain: &str,
    path: &str,
    payment: Option<&PaymentAmount>,
    reference: &str,
) {
    match payment {
        Some(payment) => tracing::info!(
            monotonic_counter.pay_payments_collected_usd_total = payment.ui_amount,
            protocol,
            subdomain = %subdomain,
            path = %path,
            currency = %payment.currency,
            reference = %reference,
            metric = METRIC_PAYMENTS_COLLECTED_USD,
            "payment collected",
        ),
        None => tracing::info!(
            protocol,
            subdomain = %subdomain,
            path = %path,
            reference = %reference,
            "payment collected",
        ),
    }
}

pub fn record_paid_request_completed(
    protocol: &'static str,
    subdomain: &str,
    path: &str,
    status: StatusCode,
    payment: Option<&PaymentAmount>,
) {
    if is_paid_request_success(status) {
        match payment {
            Some(payment) => tracing::info!(
                monotonic_counter.pay_402_requests_successful_total = 1_u64,
                protocol,
                subdomain = %subdomain,
                path = %path,
                status = status.as_u16() as u64,
                currency = %payment.currency,
                amount_usd = payment.ui_amount,
                metric = METRIC_402_SUCCESS,
                "paid request completed",
            ),
            None => tracing::info!(
                monotonic_counter.pay_402_requests_successful_total = 1_u64,
                protocol,
                subdomain = %subdomain,
                path = %path,
                status = status.as_u16() as u64,
                metric = METRIC_402_SUCCESS,
                "paid request completed",
            ),
        }
    }

    if is_paid_delivery_error(status) {
        tracing::error!(
            monotonic_counter.pay_paid_delivery_errors_total = 1_u64,
            protocol,
            subdomain = %subdomain,
            path = %path,
            status = status.as_u16() as u64,
            metric = METRIC_PAID_DELIVERY_ERRORS,
            "paid upstream delivery failed",
        );
    }
}

pub fn record_settlement_error(
    protocol: &'static str,
    subdomain: &str,
    path: &str,
    error: &str,
    retryable: bool,
) {
    let error = bounded_metric_label(error, MAX_METRIC_ERROR_LABEL_BYTES);
    tracing::warn!(
        monotonic_counter.pay_payment_settlement_errors_total = 1_u64,
        protocol,
        subdomain = %subdomain,
        path = %path,
        retryable,
        error = %error,
        metric = METRIC_SETTLEMENT_ERRORS,
        "payment settlement failed",
    );
}

fn bounded_metric_label(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

pub fn record_upstream_error(subdomain: &str, path: &str, upstream: &str, error: &str) {
    tracing::error!(
        monotonic_counter.pay_upstream_errors_total = 1_u64,
        subdomain = %subdomain,
        path = %path,
        upstream = %upstream,
        error = %error,
        metric = METRIC_UPSTREAM_ERRORS,
        "upstream request failed",
    );
}

pub fn is_paid_request_success(status: StatusCode) -> bool {
    status.is_success()
}

pub fn is_paid_delivery_error(status: StatusCode) -> bool {
    status.is_server_error()
}

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_amount_to_ui_respects_decimals() {
        assert_eq!(raw_amount_to_ui("1000000", 6), Some(1.0));
        assert_eq!(raw_amount_to_ui("1500000", 6), Some(1.5));
        assert_eq!(raw_amount_to_ui("1000000000", 9), Some(1.0));
    }

    #[test]
    fn raw_amount_to_ui_rejects_invalid_amounts() {
        assert_eq!(raw_amount_to_ui("not-a-number", 6), None);
    }

    #[test]
    fn paid_request_success_is_only_2xx() {
        assert!(is_paid_request_success(StatusCode::OK));
        assert!(!is_paid_request_success(StatusCode::PAYMENT_REQUIRED));
        assert!(!is_paid_request_success(StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn paid_delivery_error_is_5xx() {
        assert!(is_paid_delivery_error(StatusCode::BAD_GATEWAY));
        assert!(!is_paid_delivery_error(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn metric_error_labels_are_bounded_on_utf8_boundaries() {
        let error = format!("{}failure", "é".repeat(300));
        let bounded = bounded_metric_label(&error, MAX_METRIC_ERROR_LABEL_BYTES);

        assert!(bounded.len() <= MAX_METRIC_ERROR_LABEL_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(bounded.len(), 512);
    }
}
