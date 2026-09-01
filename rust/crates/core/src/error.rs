use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Command not found: {cmd}. Is it installed?")]
    CommandNotFound { cmd: String },

    #[error("Failed to parse 402 challenge from response: {0}")]
    InvalidChallenge(String),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("MPP payment error: {0}")]
    Mpp(String),

    #[error("Payment rejected: {0}")]
    PaymentRejected(String),

    #[error("Request validation error: {0}")]
    RequestValidation(String),

    #[error("Delivery validation error: {0}")]
    DeliveryValidation(String),
}
