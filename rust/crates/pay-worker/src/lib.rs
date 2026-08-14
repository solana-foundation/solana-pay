//! Operator maintenance jobs for pay-kit tab deployments.
//!
//! `close-channels` advances tabs through closure and rent reclaim;
//! `settle-sessions` reconciles Redis-backed MPP vouchers with on-chain
//! watermarks. See the crate `README.md`.

pub mod channel;
pub mod config;
pub mod error;
pub mod signer;
pub mod telemetry;
