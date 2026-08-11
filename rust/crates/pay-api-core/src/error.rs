use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid base58 address")]
    InvalidAddress,

    #[error("invalid mint for stablecoin {symbol}: {mint}")]
    InvalidMint { symbol: String, mint: String },

    #[error("network not configured: {0}")]
    NetworkNotConfigured(String),

    #[error("send endpoint is not configured: {0}")]
    SendNotConfigured(String),

    #[error("unsupported stablecoin currency: {0}")]
    UnsupportedCurrency(String),

    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    #[error("SOL/USD price is unavailable")]
    PriceUnavailable,

    #[error("payment challenge failed")]
    PaymentChallenge,

    #[error("invalid payment credential")]
    InvalidPaymentCredential,

    #[error("fee-payer signer is unavailable")]
    FeePayerSigner,

    #[error(transparent)]
    UnknownNetwork(#[from] pay_api_types::UnknownNetwork),

    #[error("RPC transport error")]
    RpcTransport(#[source] reqwest::Error),

    #[error("RPC timeout after {timeout_ms}ms")]
    RpcTimeout { timeout_ms: u64 },

    #[error("RPC rate limited")]
    RpcRateLimited,

    #[error("RPC returned error: {0}")]
    RpcResponse(String),

    #[error("malformed RPC response")]
    RpcMalformed,

    #[error("malformed token account data")]
    TokenAccountDecode,
}

impl Error {
    /// Suggested HTTP status code for this error.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::InvalidAddress
            | Self::InvalidMint { .. }
            | Self::InvalidAmount(_)
            | Self::UnsupportedCurrency(_)
            | Self::UnknownNetwork(_)
            | Self::NetworkNotConfigured(_) => 400,
            Self::SendNotConfigured(_) => 503,
            Self::RpcRateLimited => 429,
            Self::InvalidPaymentCredential => 402,
            Self::RpcTimeout { .. } => 504,
            _ => 502,
        }
    }
}
