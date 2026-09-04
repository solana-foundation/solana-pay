//! Operator maintenance jobs for pay-kit payment-channel deployments.
//!
//! `close-channels` advances payment channels through closure and rent reclaim;
//! `settle-sessions` reconciles Redis-backed MPP and x402 batch-settlement
//! vouchers with on-chain watermarks and drives each scheme's lifecycle. See
//! the crate `README.md`.

pub mod channel;
pub mod config;
pub mod error;
pub mod signer;
pub mod telemetry;
