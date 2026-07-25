//! Decode payment receipts returned on successful HTTP retries.
//!
//! MPP and x402 use different response headers and wire encodings. This
//! module presents both as a single JSON-backed view for callers that need to
//! render verbose diagnostics or link to an on-chain receipt.

use std::fmt;

use pay_kit::mpp::{PAYMENT_RECEIPT_HEADER, ReceiptKind, base64url_decode, parse_receipt};
use pay_kit::x402::{PAYMENT_RESPONSE_HEADER, X402_V1_PAYMENT_RESPONSE_HEADER};
use serde_json::Value;

/// Payment protocol that produced a decoded response receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptProtocol {
    Mpp,
    X402,
}

impl ReceiptProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mpp => "mpp",
            Self::X402 => "x402",
        }
    }
}

impl fmt::Display for ReceiptProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Protocol-neutral view of a successful payment response header.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedReceipt {
    pub protocol: ReceiptProtocol,
    /// Decoded header payload. Direct x402 settlement references are exposed
    /// as JSON strings so callers can still render the exact wire value.
    pub decoded: Value,
    /// Best on-chain settlement signature/reference found in the payload.
    pub signature: Option<String>,
    /// Network embedded in the receipt, when the wire format carries one.
    pub network: Option<String>,
}

/// Decode the first recognized payment receipt in a response header list.
///
/// Header lookup is case-insensitive. MPP receipts are validated with
/// [`pay_kit::mpp::parse_receipt`]. x402 accepts standard or URL-safe base64
/// JSON (padded or unpadded), direct JSON, and direct settlement signatures.
/// MPP takes precedence when both protocols' headers are present, matching the
/// debugger UI's receipt selection order.
pub fn decode_response_receipt(headers: &[(String, String)]) -> Option<DecodedReceipt> {
    if let Some(header) = header_value(headers, PAYMENT_RECEIPT_HEADER)
        && let Some(receipt) = decode_mpp_receipt(header)
    {
        return Some(receipt);
    }

    [PAYMENT_RESPONSE_HEADER, X402_V1_PAYMENT_RESPONSE_HEADER]
        .into_iter()
        .find_map(|name| header_value(headers, name).and_then(decode_x402_receipt))
}

fn decode_mpp_receipt(header: &str) -> Option<DecodedReceipt> {
    let header = header.trim();
    if header.is_empty() {
        return None;
    }

    // Keep the SDK parser as the source of truth for MPP receipt validity and
    // intent-specific variants, while retaining the original JSON so unknown
    // extension fields remain visible in verbose output.
    let parsed = parse_receipt(header).ok()?;
    let decoded = base64url_decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .or_else(|| serde_json::to_value(&parsed).ok())?;
    let signature = receipt_signature(&decoded).or_else(|| receipt_reference(&parsed));
    let network = receipt_network(&decoded);

    Some(DecodedReceipt {
        protocol: ReceiptProtocol::Mpp,
        decoded,
        signature,
        network,
    })
}

fn decode_x402_receipt(header: &str) -> Option<DecodedReceipt> {
    let header = header.trim();
    if header.is_empty() {
        return None;
    }

    let decoded = base64url_decode(header)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .or_else(|| serde_json::from_str::<Value>(header).ok())
        .unwrap_or_else(|| Value::String(header.to_string()));
    let signature = receipt_signature(&decoded);
    let network = receipt_network(&decoded);

    Some(DecodedReceipt {
        protocol: ReceiptProtocol::X402,
        decoded,
        signature,
        network,
    })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn receipt_reference(receipt: &ReceiptKind) -> Option<String> {
    non_empty(receipt.base().reference.as_str())
}

fn receipt_network(receipt: &Value) -> Option<String> {
    receipt
        .get("network")
        .and_then(Value::as_str)
        .and_then(non_empty)
}

/// Extract the best settlement transaction signature across the response
/// shapes emitted by MPP, x402 exact/upto/batch, and legacy gateways.
fn receipt_signature(receipt: &Value) -> Option<String> {
    if let Some(reference) = receipt.as_str() {
        return non_empty(reference);
    }

    const DIRECT_KEYS: &[&str] = &[
        "settlementSignature",
        "settlementTransaction",
        "signature",
        "txSignature",
        "transaction",
        "transactionId",
    ];
    const NESTED_KEYS: &[&str] = &[
        "settlementSignature",
        "signature",
        "transaction",
        "transactionId",
    ];

    DIRECT_KEYS
        .iter()
        .find_map(|key| receipt.get(key).and_then(Value::as_str).and_then(non_empty))
        .or_else(|| nested_signature(receipt, "settlement", NESTED_KEYS))
        .or_else(|| nested_signature(receipt, "receipt", NESTED_KEYS))
        .or_else(|| {
            receipt
                .get("activationSignature")
                .and_then(Value::as_str)
                .and_then(non_empty)
        })
        .or_else(|| {
            receipt
                .get("reference")
                .and_then(Value::as_str)
                .and_then(non_empty)
        })
}

fn nested_signature(receipt: &Value, object: &str, keys: &[&str]) -> Option<String> {
    let nested = receipt.get(object)?;
    keys.iter()
        .find_map(|key| nested.get(key).and_then(Value::as_str).and_then(non_empty))
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use pay_kit::mpp::{MethodName, Receipt, ReceiptKind, format_receipt};

    use super::*;

    fn encoded_x402(value: &Value, url_safe: bool) -> String {
        let json = serde_json::to_vec(value).unwrap();
        if url_safe {
            URL_SAFE_NO_PAD.encode(json)
        } else {
            STANDARD.encode(json)
        }
    }

    #[test]
    fn decodes_mpp_receipt_case_insensitively() {
        let receipt = ReceiptKind::Charge(Receipt::success(
            MethodName::new("solana"),
            "mpp-signature",
            "challenge-1",
        ));
        let header = format_receipt(&receipt).unwrap();
        let headers = vec![("Payment-Receipt".to_string(), header)];

        let decoded = decode_response_receipt(&headers).unwrap();
        assert_eq!(decoded.protocol, ReceiptProtocol::Mpp);
        assert_eq!(decoded.signature.as_deref(), Some("mpp-signature"));
        assert_eq!(decoded.decoded["reference"], "mpp-signature");
        assert_eq!(decoded.network, None);
    }

    #[test]
    fn decodes_standard_base64_x402_receipt() {
        let value = serde_json::json!({
            "success": true,
            "transaction": "x402-signature",
            "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
            "amount": "11"
        });
        let headers = vec![("payment-response".to_string(), encoded_x402(&value, false))];

        let decoded = decode_response_receipt(&headers).unwrap();
        assert_eq!(decoded.protocol, ReceiptProtocol::X402);
        assert_eq!(decoded.decoded, value);
        assert_eq!(decoded.signature.as_deref(), Some("x402-signature"));
        assert_eq!(
            decoded.network.as_deref(),
            Some("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
        );
    }

    #[test]
    fn decodes_reported_x402_upto_receipt() {
        const HEADER: &str = "eyJzdWNjZXNzIjp0cnVlLCJwYXllciI6IkNIUEVnRjdYMWhZSmY2NG9SeDUzQUJVTDQzRFhwRWpUSkJ6QVltWldOdUtSIiwidHJhbnNhY3Rpb24iOiIzMkVUZU1aRDd3cjVnNTlqWlZFNHljVzZlTndWaTVSaHY5a1dBSFlWWlFBTWdMclJqeHNXWVFjc2ZaSEJGQkRGUWdFOHhEZzR0VDR1VENQcTdYNkpWWmlmIiwibmV0d29yayI6InNvbGFuYTo1ZXlrdDRVc0Z2OFA4TkpkVFJFcFkxdnpxS3FaS3ZkcCIsImFtb3VudCI6IjExIn0=";
        const SIGNATURE: &str = "32ETeMZD7wr5g59jZVE4ycW6eNwVi5Rhv9kWAHYVZQAMgLrRjxsWYQcsfZHBFBDFQgE8xDg4tT4uTCPq7X6JVZif";
        const NETWORK: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
        let headers = vec![("Payment-Response".to_string(), HEADER.to_string())];

        let decoded = decode_response_receipt(&headers).unwrap();
        assert_eq!(decoded.protocol, ReceiptProtocol::X402);
        assert_eq!(decoded.signature.as_deref(), Some(SIGNATURE));
        assert_eq!(decoded.network.as_deref(), Some(NETWORK));
        assert_eq!(decoded.decoded["success"], true);
        assert_eq!(decoded.decoded["amount"], "11");
        assert_eq!(decoded.decoded["transaction"], SIGNATURE);
    }

    #[test]
    fn decodes_url_safe_and_direct_json_x402_receipts() {
        let value = serde_json::json!({
            "settlement": { "transactionId": "nested-signature" },
            "network": "sandbox"
        });
        let encoded_headers = vec![("PAYMENT-RESPONSE".to_string(), encoded_x402(&value, true))];
        let direct_headers = vec![("payment-response".to_string(), value.to_string())];

        for headers in [encoded_headers, direct_headers] {
            let decoded = decode_response_receipt(&headers).unwrap();
            assert_eq!(decoded.decoded, value);
            assert_eq!(decoded.signature.as_deref(), Some("nested-signature"));
            assert_eq!(decoded.network.as_deref(), Some("sandbox"));
        }
    }

    #[test]
    fn falls_back_to_legacy_raw_x402_signature() {
        let headers = vec![(
            "X-Payment-Response".to_string(),
            "direct-settlement-signature".to_string(),
        )];

        let decoded = decode_response_receipt(&headers).unwrap();
        assert_eq!(decoded.protocol, ReceiptProtocol::X402);
        assert_eq!(
            decoded.decoded,
            Value::String("direct-settlement-signature".to_string())
        );
        assert_eq!(
            decoded.signature.as_deref(),
            Some("direct-settlement-signature")
        );
        assert_eq!(decoded.network, None);
    }

    #[test]
    fn signature_aliases_match_debugger_precedence() {
        let cases = [
            (
                serde_json::json!({
                    "settlementSignature": "settlement-signature",
                    "transaction": "transaction"
                }),
                "settlement-signature",
            ),
            (
                serde_json::json!({
                    "receipt": { "transaction": "nested-receipt-signature" },
                    "reference": "reference"
                }),
                "nested-receipt-signature",
            ),
            (
                serde_json::json!({
                    "activationSignature": "activation-signature",
                    "reference": "reference"
                }),
                "activation-signature",
            ),
        ];

        for (value, expected) in cases {
            assert_eq!(receipt_signature(&value).as_deref(), Some(expected));
        }
    }

    #[test]
    fn ignores_invalid_mpp_receipt_and_empty_x402_receipt() {
        let invalid_mpp = vec![(
            "payment-receipt".to_string(),
            "not-a-valid-receipt".to_string(),
        )];
        let empty_x402 = vec![("payment-response".to_string(), "  ".to_string())];

        assert!(decode_response_receipt(&invalid_mpp).is_none());
        assert!(decode_response_receipt(&empty_x402).is_none());
        assert!(decode_response_receipt(&[]).is_none());
    }
}
