use pay_api_core::Receipt;
use pay_api_types::Network;
use tracing::{error, info, warn};

pub const METRIC_ONRAMP_REDIRECTS: &str = "pay_api_onramp_redirects_total";
pub const METRIC_ONRAMP_REQUESTS: &str = "pay_api_onramp_requests_total";
pub const METRIC_ONRAMP_ERRORS: &str = "pay_api_onramp_errors_total";
pub const METRIC_BALANCE_REQUESTS: &str = "pay_api_balance_requests_total";
pub const METRIC_BALANCE_ERRORS: &str = "pay_api_balance_errors_total";
pub const METRIC_RECEIPT_REQUESTS: &str = "pay_api_receipt_requests_total";
pub const METRIC_RECEIPT_ERRORS: &str = "pay_api_receipt_errors_total";

pub fn record_onramp_request(payment_method: &str) {
    info!(
        monotonic_counter.pay_api_onramp_requests_total = 1_u64,
        event = "pay_api.onramp.request",
        provider = "moonpay",
        endpoint = "/v1/onramp/start",
        payment_method = %payment_method,
        metric = METRIC_ONRAMP_REQUESTS,
        "MoonPay onramp request received",
    );
}

pub fn record_onramp_redirect(
    currency_code: &str,
    base_currency_amount: &str,
    external_transaction_id: &str,
    payment_method: &str,
    has_wallet_address: bool,
    has_redirect_url: bool,
) {
    info!(
        monotonic_counter.pay_api_onramp_redirects_total = 1_u64,
        event = "pay_api.onramp.redirect",
        provider = "moonpay",
        endpoint = "/v1/onramp/start",
        currency = %currency_code,
        payment_method = %payment_method,
        has_wallet_address,
        has_redirect_url,
        has_payment_method = payment_method != "unspecified",
        metric = METRIC_ONRAMP_REDIRECTS,
        "MoonPay onramp redirect created",
    );
    info!(
        event = "pay_api.onramp.redirect.details",
        provider = "moonpay",
        endpoint = "/v1/onramp/start",
        currency = %currency_code,
        base_currency_amount = %base_currency_amount,
        external_transaction_id = %external_transaction_id,
        payment_method = %payment_method,
        has_wallet_address,
        has_redirect_url,
        "MoonPay onramp redirect details",
    );
}

pub fn record_onramp_error(reason: &'static str) {
    error!(
        monotonic_counter.pay_api_onramp_errors_total = 1_u64,
        event = "pay_api.onramp.error",
        provider = "moonpay",
        endpoint = "/v1/onramp/start",
        reason,
        metric = METRIC_ONRAMP_ERRORS,
        "MoonPay onramp redirect failed",
    );
}

pub fn record_balance_request(network: Network, stablecoin_count: usize) {
    info!(
        monotonic_counter.pay_api_balance_requests_total = 1_u64,
        event = "pay_api.balance.success",
        endpoint = "/v1/balance/stablecoins",
        network = %network.as_str(),
        metric = METRIC_BALANCE_REQUESTS,
        "stablecoin balance request completed",
    );
    info!(
        event = "pay_api.balance.success.details",
        endpoint = "/v1/balance/stablecoins",
        network = %network.as_str(),
        stablecoin_count,
        "stablecoin balance request details",
    );
}

pub fn record_balance_error(status: u16, error: &str) {
    warn!(
        monotonic_counter.pay_api_balance_errors_total = 1_u64,
        event = "pay_api.balance.error",
        endpoint = "/v1/balance/stablecoins",
        status = status as u64,
        metric = METRIC_BALANCE_ERRORS,
        "stablecoin balance request failed",
    );
    warn!(
        event = "pay_api.balance.error.details",
        endpoint = "/v1/balance/stablecoins",
        status,
        error = %error,
        "stablecoin balance request error details",
    );
}

pub fn record_receipt_request(network: Network, receipt: &Receipt) {
    let intent = match receipt.intent.kind {
        pay_api_core::ReceiptIntentKind::X402Exact => "x402/exact",
        pay_api_core::ReceiptIntentKind::MppCharge => "mpp/charge",
        pay_api_core::ReceiptIntentKind::MppSession => "mpp/session",
        pay_api_core::ReceiptIntentKind::MppSubscription => "mpp/subscription",
        pay_api_core::ReceiptIntentKind::Transfer => "transfer",
    };
    info!(
        monotonic_counter.pay_api_receipt_requests_total = 1_u64,
        event = "pay_api.receipt.success",
        endpoint = "/v1/receipt",
        network = %network.as_str(),
        intent,
        metric = METRIC_RECEIPT_REQUESTS,
        "receipt request completed",
    );
    info!(
        event = "pay_api.receipt.success.details",
        endpoint = "/v1/receipt",
        network = %network.as_str(),
        intent,
        transfers = receipt.transfers.len(),
        splits = receipt.splits.len(),
        "receipt request details",
    );
}

pub fn record_receipt_error(status: u16, error: &str) {
    warn!(
        monotonic_counter.pay_api_receipt_errors_total = 1_u64,
        event = "pay_api.receipt.error",
        endpoint = "/v1/receipt",
        status = status as u64,
        metric = METRIC_RECEIPT_ERRORS,
        "receipt request failed",
    );
    warn!(
        event = "pay_api.receipt.error.details",
        endpoint = "/v1/receipt",
        status,
        error = %error,
        "receipt request error details",
    );
}
