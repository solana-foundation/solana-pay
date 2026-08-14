//! Wire contract for the gasless batch-transfer API
//! (`POST /api/v1/transfer-batches`).
//!
//! These are the only definitions of this contract — `pay-api-core` and
//! `pay-api` import from here rather than redefining a parallel copy. Every
//! request/response type is `#[serde(deny_unknown_fields)]` and derives
//! [`schemars::JsonSchema`] so `/api/v1/schemas/*` can serve a generated
//! schema instead of a hand-maintained one drifting from the real types.

use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A batch may carry 1..=8 transfers per chunk. Mirrors PayKit's
/// `mpp::protocol::solana::MAX_SPLITS`: a gasless chunk rides as one MPP
/// charge whose primary transfer is the fee-payer reimbursement, so every
/// user payout is a split, and PayKit caps a charge at 8 splits. Duplicated
/// as a plain constant (rather than a `pay-kit` dependency) because this
/// crate is the dependency-light wire-contract layer that both the CLI core
/// and the API server import; `pay-api-core` asserts this stays in sync with
/// `pay_kit::mpp::protocol::solana::MAX_SPLITS` in its own test suite.
pub const MIN_TRANSFER_BATCH_TRANSFERS: usize = 1;
pub const MAX_TRANSFER_BATCH_TRANSFERS: usize = 8;

/// A `batchId` is a BLAKE3 digest of the client's canonical CSV manifest:
/// 32 bytes, lowercase hex, so exactly 64 characters.
pub const BATCH_ID_HEX_LEN: usize = 64;

/// Canonical wire network identifier for the gasless batch-transfer API.
///
/// Deliberately distinct from the legacy `Network` (`mainnet` | `sandbox`)
/// used by `/v1/send`: those two enums serve different contracts on
/// purpose. `Network::Sandbox` conflates "no real cluster" with "localnet",
/// which would force a USDG *Devnet* batch to lie and claim to be the local
/// sandbox. `TransferNetwork` has no aliases and no legacy baggage — it is
/// exactly the three canonical MPP wire slugs (`mainnet`, `devnet`,
/// `localnet`), matching `pay_kit::mpp::protocol::solana::validate_network`
/// one-for-one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransferNetwork {
    Mainnet,
    Devnet,
    Localnet,
}

#[derive(Debug, thiserror::Error)]
#[error("unknown transfer network: {0}")]
pub struct UnknownTransferNetwork(pub String);

impl TransferNetwork {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
            Self::Localnet => "localnet",
        }
    }
}

impl FromStr for TransferNetwork {
    type Err = UnknownTransferNetwork;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Self::Mainnet),
            "devnet" => Ok(Self::Devnet),
            "localnet" => Ok(Self::Localnet),
            other => Err(UnknownTransferNetwork(other.to_string())),
        }
    }
}

/// One payout inside a `TransferBatchRequest`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransferBatchEntry {
    /// The CSV row identity this transfer settles. Echoed back verbatim in
    /// the confirmed response so the caller can reconcile against its own
    /// manifest without re-deriving row order.
    pub row_id: u64,
    /// Base58 recipient wallet address.
    pub recipient: String,
    /// Decimal amount string, parsed at the resolved mint's decimals
    /// (e.g. `"1.25"`). Never a raw base-unit integer — the caller doesn't
    /// need to know the mint's decimals to build this request.
    pub amount: String,
}

/// `POST /api/v1/transfer-batches` request body.
///
/// One request always represents exactly one previously-packed chunk of a
/// larger CSV batch: `batchId` identifies the manifest, `chunkIndex`
/// identifies this chunk within it, and `transfers` is 1..=8 payouts.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TransferBatchRequest {
    /// 32-byte manifest hash, lowercase hex (64 characters).
    pub batch_id: String,
    /// This chunk's position within the batch. Stamped into the on-chain
    /// memo alongside `batchId` so the settled transaction is
    /// self-describing.
    pub chunk_index: u32,
    /// Base58 sender wallet address — the token authority for every
    /// transfer in this chunk, and the application-level idempotency key's
    /// first component (`(sender, batchId, chunkIndex)`).
    pub sender: String,
    /// Stablecoin symbol or mint address (e.g. `"USDG"`).
    pub currency: String,
    pub network: TransferNetwork,
    pub transfers: Vec<TransferBatchEntry>,
}

/// Unauthenticated (402) response: enough structured pricing information for
/// the caller to decide whether to authorize and sign, without leaking
/// anything the client couldn't derive itself from a public quote.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferBatchChallengeBody {
    pub batch_id: String,
    pub chunk_index: u32,
    pub transfer_count: usize,
    /// Sum of the requested payouts, raw base units, as a string (preserves
    /// u64 precision in JSON).
    pub recipient_amount_raw: String,
    /// The primary transfer: one transaction-fee-and-rent reimbursement to
    /// pay-api's fee payer, converted to the batch's stablecoin and rounded
    /// up. Raw base units, as a string.
    pub fee_reimbursement_raw: String,
    /// `recipientAmountRaw + feeReimbursementRaw`, raw base units, as a
    /// string.
    pub total_amount_raw: String,
    pub estimated_fee_lamports: u64,
    /// Number of the `transfers` whose destination associated-token-account
    /// does not exist yet (and is therefore idempotently created, at the
    /// sender's-batch-reimbursed expense, alongside the transfer).
    pub missing_ata_count: usize,
    /// Base58 pay-api fee-payer key — the primary recipient of this charge.
    pub fee_payer: String,
    /// Base58-encoded recent blockhash the caller must build its chunk
    /// transaction against. Required (not just `challenge_last_valid_block_height`)
    /// because the caller has to compile and sign the exact message this
    /// blockhash was stamped into — a block height alone isn't enough to
    /// reconstruct it.
    pub recent_blockhash: String,
    /// RFC 3339 UTC timestamp after which this specific challenge can no
    /// longer be redeemed.
    pub challenge_expires_at: String,
    /// Last Solana block height at which the blockhash embedded in this
    /// challenge remains valid.
    pub challenge_last_valid_block_height: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransferBatchStatus {
    Confirmed,
}

/// Authorized (200) response.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferBatchResponse {
    pub batch_id: String,
    pub chunk_index: u32,
    /// The settled row IDs, in the same order as the request's `transfers`.
    pub row_ids: Vec<u64>,
    pub signature: String,
    pub status: TransferBatchStatus,
}

/// One shared, actionable error shape for every `/api/v1/transfer-batches`
/// failure.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TransferBatchErrorBody {
    pub error: TransferBatchErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TransferBatchErrorDetail {
    /// A stable, machine-matchable identifier, e.g. `"duplicate_recipient"`.
    pub code: String,
    /// Human-readable detail, safe to display.
    pub message: String,
    /// JSON-path-ish pointer to the offending field, e.g.
    /// `"transfers[3].recipient"`, when the error is field-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Whether an identical retry might succeed without any change to the
    /// request (e.g. a rate limit or a transient upstream failure).
    pub retryable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_network_round_trips_canonical_slugs() {
        for (slug, network) in [
            ("mainnet", TransferNetwork::Mainnet),
            ("devnet", TransferNetwork::Devnet),
            ("localnet", TransferNetwork::Localnet),
        ] {
            assert_eq!(slug.parse::<TransferNetwork>().unwrap(), network);
            assert_eq!(network.as_str(), slug);
            assert_eq!(
                serde_json::to_string(&network).unwrap(),
                format!("\"{slug}\"")
            );
        }
    }

    #[test]
    fn transfer_network_rejects_legacy_aliases() {
        // Unlike the legacy `Network` enum, there is no "sandbox" or
        // "surfpool" alias here — exactly the three canonical MPP slugs.
        for bad in ["mainnet-beta", "sandbox", "surfpool", "testnet", ""] {
            assert!(bad.parse::<TransferNetwork>().is_err(), "{bad}");
        }
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let value = serde_json::json!({
            "batchId": "a".repeat(64),
            "chunkIndex": 0,
            "sender": "sender",
            "currency": "USDG",
            "network": "mainnet",
            "transfers": [],
            "unexpectedField": true,
        });
        assert!(serde_json::from_value::<TransferBatchRequest>(value).is_err());
    }

    #[test]
    fn request_round_trips_camel_case_wire_shape() {
        let request = TransferBatchRequest {
            batch_id: "a".repeat(64),
            chunk_index: 3,
            sender: "Sender111111111111111111111111111111111111".to_string(),
            currency: "USDG".to_string(),
            network: TransferNetwork::Mainnet,
            transfers: vec![TransferBatchEntry {
                row_id: 2,
                recipient: "Recipient1111111111111111111111111111111111".to_string(),
                amount: "1.25".to_string(),
            }],
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["batchId"], serde_json::json!("a".repeat(64)));
        assert_eq!(value["chunkIndex"], serde_json::json!(3));
        assert_eq!(value["transfers"][0]["rowId"], serde_json::json!(2));
        let round_tripped: TransferBatchRequest = serde_json::from_value(value).unwrap();
        assert_eq!(round_tripped.chunk_index, request.chunk_index);
    }

    #[test]
    fn error_body_serializes_shared_shape() {
        let body = TransferBatchErrorBody {
            error: TransferBatchErrorDetail {
                code: "duplicate_recipient".to_string(),
                message: "transfers[3].recipient duplicates transfers[0].recipient".to_string(),
                field: Some("transfers[3].recipient".to_string()),
                retryable: false,
            },
        };
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(
            value["error"]["code"],
            serde_json::json!("duplicate_recipient")
        );
        assert_eq!(value["error"]["retryable"], serde_json::json!(false));
    }

    #[test]
    fn json_schemas_generate_for_request_and_response() {
        let request_schema = schemars::schema_for!(TransferBatchRequest);
        let response_schema = schemars::schema_for!(TransferBatchResponse);
        assert!(
            serde_json::to_value(&request_schema)
                .unwrap()
                .get("properties")
                .is_some()
        );
        assert!(
            serde_json::to_value(&response_schema)
                .unwrap()
                .get("properties")
                .is_some()
        );
    }
}
