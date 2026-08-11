//! Error type for the close-channels job.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum JobError {
    #[error("config error: {0}")]
    Config(String),

    #[error(transparent)]
    ConfigLoad(#[from] crate::config::ConfigError),

    #[error("invalid base58 address: {0}")]
    InvalidAddress(String),

    #[error("fee-payer signer is unavailable")]
    FeePayerSigner,

    #[error("rpc error: {0}")]
    Rpc(#[from] pay_api_core::Error),

    #[error("could not locate the channel's open transaction")]
    OpenTxNotFound,

    #[error("could not decode the channel's open instruction: {0}")]
    OpenIxDecode(String),

    #[error(
        "distribution preimage hash mismatch: recovered preimage does not match the on-chain \
         distribution_hash"
    )]
    DistributionHashMismatch,

    #[error("failed to build/serialize transaction: {0}")]
    TxBuild(String),

    #[error("signing failed")]
    Signing,
}
