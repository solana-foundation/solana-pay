use std::sync::Arc;

use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{Html, IntoResponse, Redirect};
use url::Url;
use url::form_urlencoded;
use uuid::Uuid;

use crate::config::MoonpayConfig;
use crate::state::AppState;
use crate::telemetry;

const MOONPAY_BUY_URL: &str = "https://buy.moonpay.com/v2/buy";
const ONRAMP_COMPLETE_HTML: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Pay top-up submitted</title>
    <style>
      :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: Canvas; color: CanvasText; }
      main { width: min(100% - 2rem, 34rem); text-align: center; }
      h1 { margin: 0 0 0.75rem; font-size: 2rem; line-height: 1.15; font-weight: 650; }
      p { margin: 0; color: color-mix(in srgb, CanvasText 68%, transparent); font-size: 1rem; line-height: 1.5; }
    </style>
  </head>
  <body>
    <main>
      <h1>Top-up submitted</h1>
      <p>You can close this tab and return to Pay.</p>
    </main>
  </body>
</html>"#;

pub async fn handler(
    State(state): State<Arc<AppState>>,
    uri: Uri,
) -> Result<impl IntoResponse, OnrampError> {
    let query = uri.query();
    let payment_method = payment_method_from_query(query);
    telemetry::record_onramp_request(&payment_method);

    let api_key = state
        .moonpay
        .publishable_api_key
        .as_deref()
        .ok_or(OnrampError::MissingApiKey)?;
    let external_transaction_id = new_onramp_external_transaction_id();
    let redirect_url =
        build_onramp_redirect_url(query, api_key, &state.moonpay, &external_transaction_id)?;

    telemetry::record_onramp_redirect(
        &state.moonpay.onramp_currency_code,
        &state.moonpay.onramp_base_currency_amount,
        &external_transaction_id,
        &payment_method,
        has_query_param(query, "walletAddress"),
        has_query_param(query, "redirectURL"),
    );

    Ok(Redirect::temporary(redirect_url.as_str()))
}

pub async fn complete_handler() -> Html<&'static str> {
    Html(ONRAMP_COMPLETE_HTML)
}

pub fn new_onramp_external_transaction_id() -> String {
    format!("pay-{}", Uuid::new_v4())
}

pub fn build_onramp_redirect_url(
    query: Option<&str>,
    api_key: &str,
    defaults: &MoonpayConfig,
    external_transaction_id: &str,
) -> Result<Url, OnrampError> {
    let mut redirect_url = Url::parse(MOONPAY_BUY_URL).map_err(OnrampError::InvalidBaseUrl)?;

    let mut query_pairs = query
        .map(|q| {
            form_urlencoded::parse(q.as_bytes())
                .into_owned()
                .filter(|(key, _)| !is_server_controlled_param(key))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    query_pairs.push((
        "currencyCode".to_string(),
        defaults.onramp_currency_code.clone(),
    ));
    query_pairs.push((
        "baseCurrencyAmount".to_string(),
        defaults.onramp_base_currency_amount.clone(),
    ));
    query_pairs.push((
        "externalTransactionId".to_string(),
        external_transaction_id.to_string(),
    ));
    query_pairs.push(("apiKey".to_string(), api_key.to_string()));

    {
        let mut pairs = redirect_url.query_pairs_mut();
        pairs.clear();
        for (key, value) in &query_pairs {
            pairs.append_pair(key, value);
        }
    }

    Ok(redirect_url)
}

fn has_query_param(query: Option<&str>, name: &str) -> bool {
    query
        .map(|q| {
            form_urlencoded::parse(q.as_bytes())
                .any(|(key, value)| key == name && !value.trim().is_empty())
        })
        .unwrap_or(false)
}

fn payment_method_from_query(query: Option<&str>) -> String {
    query
        .and_then(|q| {
            form_urlencoded::parse(q.as_bytes())
                .find(|(key, value)| key == "paymentMethod" && !value.trim().is_empty())
                .map(|(_, value)| normalize_payment_method(&value))
        })
        .unwrap_or_else(|| "unspecified".to_string())
}

fn normalize_payment_method(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "paypal" | "venmo" | "apple_pay" | "card" | "credit_debit_card" | "bank_transfer" => {
            normalized
        }
        "" => "unspecified".to_string(),
        _ => "other".to_string(),
    }
}

fn is_server_controlled_param(key: &str) -> bool {
    matches!(
        key,
        "apiKey" | "api_key" | "currencyCode" | "baseCurrencyAmount" | "externalTransactionId"
    )
}

#[derive(Debug, thiserror::Error)]
pub enum OnrampError {
    #[error("onramp is temporarily unavailable.")]
    MissingApiKey,

    #[error("onramp is temporarily unavailable.")]
    InvalidBaseUrl(#[source] url::ParseError),
}

impl IntoResponse for OnrampError {
    fn into_response(self) -> axum::response::Response {
        match &self {
            Self::MissingApiKey => telemetry::record_onramp_error("missing_moonpay_api_key"),
            Self::InvalidBaseUrl(_) => telemetry::record_onramp_error("invalid_moonpay_base_url"),
        }
        (StatusCode::SERVICE_UNAVAILABLE, self.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> MoonpayConfig {
        MoonpayConfig {
            publishable_api_key: Some("pk_live_123".to_string()),
            onramp_currency_code: "usdc_sol".to_string(),
            onramp_base_currency_amount: "20".to_string(),
        }
    }

    #[test]
    fn build_onramp_redirect_url_applies_server_side_defaults() {
        let url = build_onramp_redirect_url(
            Some(
                "walletAddress=wallet123&redirectURL=https%3A%2F%2Fpay.sh%2Fv1%2Fonramp%2Fcomplete&paymentMethod=paypal",
            ),
            "pk_live_123",
            &defaults(),
            "pay-server-abc",
        )
        .unwrap();
        let params = url.query_pairs().collect::<Vec<_>>();

        assert_eq!(
            url.origin().ascii_serialization(),
            "https://buy.moonpay.com"
        );
        assert_eq!(url.path(), "/v2/buy");
        assert!(params.contains(&("walletAddress".into(), "wallet123".into())));
        assert!(params.contains(&(
            "redirectURL".into(),
            "https://pay.sh/v1/onramp/complete".into()
        )));
        assert!(params.contains(&("paymentMethod".into(), "paypal".into())));
        assert!(params.contains(&("currencyCode".into(), "usdc_sol".into())));
        assert!(params.contains(&("baseCurrencyAmount".into(), "20".into())));
        assert!(params.contains(&("externalTransactionId".into(), "pay-server-abc".into())));
        assert!(params.contains(&("apiKey".into(), "pk_live_123".into())));
    }

    #[test]
    fn build_onramp_redirect_url_replaces_caller_supplied_control_params() {
        let url = build_onramp_redirect_url(
            Some(
                "apiKey=old-a&api_key=old-b&currencyCode=eth&baseCurrencyAmount=99&externalTransactionId=pay-cli-abc&walletAddress=wallet123",
            ),
            "pk_live_123",
            &defaults(),
            "pay-server-abc",
        )
        .unwrap();
        let params = url.query_pairs().collect::<Vec<_>>();

        assert_eq!(
            params
                .iter()
                .filter(|(key, _)| key.as_ref() == "apiKey")
                .count(),
            1
        );
        assert!(params.contains(&("apiKey".into(), "pk_live_123".into())));
        assert!(!params.iter().any(|(key, _)| key.as_ref() == "api_key"));
        assert!(params.contains(&("currencyCode".into(), "usdc_sol".into())));
        assert!(params.contains(&("baseCurrencyAmount".into(), "20".into())));
        assert!(params.contains(&("externalTransactionId".into(), "pay-server-abc".into())));
    }

    #[test]
    fn build_onramp_redirect_url_omits_payment_method_when_absent() {
        let url = build_onramp_redirect_url(
            Some("currencyCode=usdc_sol&walletAddress=wallet123"),
            "pk_live_123",
            &defaults(),
            "pay-server-abc",
        )
        .unwrap();

        assert!(
            !url.query_pairs()
                .any(|(key, _)| key.as_ref() == "paymentMethod")
        );
    }

    #[test]
    fn payment_method_from_query_normalizes_known_values() {
        assert_eq!(
            payment_method_from_query(Some("paymentMethod=Apple%20Pay")),
            "apple_pay"
        );
        assert_eq!(
            payment_method_from_query(Some("paymentMethod=credit-debit-card")),
            "credit_debit_card"
        );
    }

    #[test]
    fn payment_method_from_query_bounds_cardinality() {
        assert_eq!(
            payment_method_from_query(Some("paymentMethod=surprise-wallet")),
            "other"
        );
        assert_eq!(
            payment_method_from_query(Some("walletAddress=wallet123")),
            "unspecified"
        );
    }

    #[test]
    fn onramp_error_message_does_not_expose_secret_names() {
        let message = OnrampError::MissingApiKey.to_string();

        assert_eq!(message, "onramp is temporarily unavailable.");
        assert!(!message.contains("MOONPAY"));
        assert!(!message.contains("API_KEY"));
    }
}
