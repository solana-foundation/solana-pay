//! Client-side channel state for the x402 `batch-settlement` scheme.
//!
//! Unlike `exact` and `upto`, `batch-settlement` is stateful across requests:
//! one escrow channel backs many cheap calls, and each request signs a voucher
//! for `previous cumulative + price`. The client therefore has to remember,
//! per channel, how much the server has confirmed charging.
//!
//! [`BatchChannelCache`] is that memory. It lives for the life of the process,
//! which is the same shape as the MPP session cache the MCP server keeps: a
//! long-lived host (the MCP server, a proxy) amortizes one deposit over many
//! requests, while a one-shot `pay curl` opens a channel, spends it, and can
//! force-close to recover the remainder.
//!
//! The watermark advances only when the server's `PAYMENT-RESPONSE` confirms
//! the exact commitment that was sent — see
//! [`pay_kit::x402::client::batch_settlement::BatchChannel::apply_payment_response`].
//! Advancing on send would desynchronize the client from the server whenever a
//! request failed in flight, and every later voucher would be rejected.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pay_kit::x402::batch_settlement::{BatchRequirements, BatchSettlementResponse, BatchVoucher};
use pay_kit::x402::client::batch_settlement::BatchChannel;

// Re-exported so hosts (the MCP server, a proxy) can hold and confirm
// batch-settlement state without taking a direct pay-kit dependency.
pub use pay_kit::x402::batch_settlement::{
    BatchRequirements as Requirements, BatchSettlementResponse as SettlementResponse,
    BatchVoucher as Voucher,
};

use crate::{Error, Result};

/// Identifies the channel that serves a given offer.
///
/// Every component is a channel-PDA seed or an immutable channel property, so
/// two offers that differ in any of them cannot share a channel — reusing one
/// across, say, two `payTo` addresses would sign vouchers redeemable by the
/// wrong receiver.
fn cache_key(requirements: &BatchRequirements) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        requirements.network,
        requirements.asset,
        requirements.pay_to,
        requirements.extra.fee_payer,
        requirements.extra.withdraw_delay,
    )
}

/// Process-lifetime cache of open `batch-settlement` channels.
#[derive(Clone, Default)]
pub struct BatchChannelCache {
    channels: Arc<Mutex<HashMap<String, BatchChannel>>>,
}

impl BatchChannelCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The channel already open for this offer, if any.
    pub fn get(&self, requirements: &BatchRequirements) -> Result<Option<BatchChannel>> {
        let channels = self.lock()?;
        Ok(channels.get(&cache_key(requirements)).cloned())
    }

    /// Remember a channel opened for this offer.
    pub fn insert(&self, requirements: &BatchRequirements, channel: BatchChannel) -> Result<()> {
        let mut channels = self.lock()?;
        channels.insert(cache_key(requirements), channel);
        Ok(())
    }

    /// Forget a channel — after a close, or when the server no longer
    /// recognizes it and the client must open a fresh one.
    pub fn remove(&self, requirements: &BatchRequirements) -> Result<()> {
        let mut channels = self.lock()?;
        channels.remove(&cache_key(requirements));
        Ok(())
    }

    /// Adopt the server's confirmation of a payment.
    ///
    /// Returns the new cumulative watermark. A response that confirms a
    /// different commitment, or a charge other than the advertised price, is
    /// rejected and the watermark is left alone: the next request then re-signs
    /// the same cumulative amount, which the server treats as the idempotent
    /// retry it is.
    pub fn apply_settlement(
        &self,
        requirements: &BatchRequirements,
        submitted: &BatchVoucher,
        response: &BatchSettlementResponse,
    ) -> Result<u64> {
        let mut channels = self.lock()?;
        let key = cache_key(requirements);
        let channel = channels.get_mut(&key).ok_or_else(|| {
            Error::Mpp("no cached batch-settlement channel for this offer".to_string())
        })?;
        channel
            .apply_payment_response(response, requirements, submitted)
            .map_err(|e| Error::Mpp(format!("batch-settlement settlement rejected: {e}")))?;
        Ok(channel.charged_cumulative_amount())
    }

    /// Resynchronize from a corrective 402.
    ///
    /// The server proves how much it has charged with a voucher this client
    /// signed; the channel refuses anything it cannot verify against its own
    /// authorizer key. A channel the server no longer knows about is dropped so
    /// the next attempt opens a fresh one.
    pub fn adopt_corrective(&self, requirements: &BatchRequirements) -> Result<Option<u64>> {
        let mut channels = self.lock()?;
        let key = cache_key(requirements);
        let Some(channel) = channels.get_mut(&key) else {
            return Ok(None);
        };
        match channel.adopt_corrective_state(requirements) {
            Ok(cumulative) => Ok(Some(cumulative)),
            Err(e) => {
                // Unverifiable: the safe move is to forget the channel rather
                // than keep signing against a watermark neither side agrees on.
                channels.remove(&key);
                Err(Error::Mpp(format!(
                    "batch-settlement corrective state rejected: {e}"
                )))
            }
        }
    }

    /// Adopt a settlement from a completed response's `PAYMENT-RESPONSE`
    /// header.
    ///
    /// Returns `Ok(None)` when the response carried no settlement header at
    /// all, which leaves the watermark untouched: the next request re-signs the
    /// same cumulative amount, and the server recognizes it as the idempotent
    /// retry it is.
    pub fn apply_settlement_from_headers(
        &self,
        requirements: &BatchRequirements,
        submitted: &BatchVoucher,
        response_headers: &[(String, String)],
    ) -> Result<Option<u64>> {
        let Some(response) = decode_settlement(response_headers) else {
            return Ok(None);
        };
        self.apply_settlement(requirements, submitted, &response)
            .map(Some)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, BatchChannel>>> {
        self.channels
            .lock()
            .map_err(|_| Error::Mpp("batch-settlement channel cache lock poisoned".to_string()))
    }
}

/// Decode the `PAYMENT-RESPONSE` settlement receipt from response headers.
fn decode_settlement(headers: &[(String, String)]) -> Option<BatchSettlementResponse> {
    let value = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("payment-response"))
        .map(|(_, value)| value)?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value).ok()?;
    serde_json::from_slice(&decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_kit::x402::batch_settlement::BatchExtra;

    fn requirements(pay_to: &str, fee_payer: &str) -> BatchRequirements {
        BatchRequirements {
            scheme: "batch-settlement".to_string(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".to_string(),
            amount: "1000".to_string(),
            asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            pay_to: pay_to.to_string(),
            max_timeout_seconds: 300,
            extra: BatchExtra {
                payment_flow: None,
                fee_payer: fee_payer.to_string(),
                receiver_authorizer: None,
                withdraw_delay: 3600,
                token_program: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
                memo: None,
                recent_blockhash: None,
                recent_slot: None,
                channel_state: None,
                voucher_state: None,
            },
        }
    }

    #[test]
    fn offers_that_differ_in_any_channel_seed_do_not_share_a_channel() {
        let base = requirements("payTo1", "feePayer1");
        // A channel is bound to its receiver and its sponsor; reusing one across
        // either would sign vouchers redeemable by the wrong party.
        assert_ne!(
            cache_key(&base),
            cache_key(&requirements("payTo2", "feePayer1"))
        );
        assert_ne!(
            cache_key(&base),
            cache_key(&requirements("payTo1", "feePayer2"))
        );

        let mut different_delay = requirements("payTo1", "feePayer1");
        different_delay.extra.withdraw_delay = 900;
        assert_ne!(cache_key(&base), cache_key(&different_delay));

        // The per-request price is not a channel property: the same channel
        // funds cheap and expensive routes alike.
        let mut different_price = requirements("payTo1", "feePayer1");
        different_price.amount = "5000".to_string();
        assert_eq!(cache_key(&base), cache_key(&different_price));
    }

    #[test]
    fn an_unknown_channel_reports_nothing_rather_than_failing() {
        let cache = BatchChannelCache::new();
        let requirements = requirements("payTo1", "feePayer1");
        assert!(cache.get(&requirements).unwrap().is_none());
        assert!(cache.adopt_corrective(&requirements).unwrap().is_none());
        // Removing something absent is a no-op, so a close is idempotent.
        cache.remove(&requirements).unwrap();
    }
}
