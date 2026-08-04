//! Shared fee-payer signer construction used by `/v1/send`,
//! `/v1/subscriptions/cancel`, and `/v1/redeem`.
//!
//! Two paths, env-var first:
//!
//! 1. **Sandbox / local testing.** If `LOCAL_FEE_PAYER_PRIVATE_KEY` is
//!    set, the api signs in-process with that keypair. The value can
//!    be a base58 secret key string or a `[1,2,3,...]` u8 array (the
//!    Solana CLI keypair JSON format). Useful for running against
//!    `402.surfnet.dev` without GCP infrastructure.
//!
//! 2. **Production.** The GCP-KMS-backed signer the rest of pay-api
//!    has always used. Pulls the key_name + pubkey from the supplied
//!    `FeePayerConfig`.
//!
//! The same env var unlocks every endpoint that touches the hot
//! wallet, so a single export makes a local pay-api able to sign
//! send + redeem (+ subscriptions cancel, if reused there).

use std::sync::Arc;

use pay_api_core::Error;
use pay_kit::mpp::solana_keychain::{Signer, SolanaSigner};

use crate::config::FeePayerConfig;

const LOCAL_PRIVATE_KEY_ENV: &str = "LOCAL_FEE_PAYER_PRIVATE_KEY";

/// Build a fee-payer `SolanaSigner` from config + env. See module docs.
pub async fn build_fee_payer_signer(
    fee_payer: &FeePayerConfig,
    missing_key_name_msg: &str,
    missing_pubkey_msg: &str,
) -> Result<Arc<dyn SolanaSigner>, Error> {
    if let Ok(key) = std::env::var(LOCAL_PRIVATE_KEY_ENV) {
        let key = key.trim();
        if !key.is_empty() {
            let signer = Signer::from_memory(key).map_err(|_| Error::FeePayerSigner)?;
            let expected_pubkey = fee_payer
                .pubkey
                .as_deref()
                .filter(|pubkey| !pubkey.trim().is_empty())
                .ok_or(Error::FeePayerSigner)?;
            if signer.pubkey().to_string() != expected_pubkey {
                tracing::warn!(
                    expected_pubkey,
                    actual_pubkey = %signer.pubkey(),
                    "rejecting local fee-payer key with unexpected pubkey"
                );
                return Err(Error::FeePayerSigner);
            }
            tracing::warn!(pubkey = %signer.pubkey(), "using local fee-payer private key");
            return Ok(Arc::new(signer));
        }
    }

    let key_name = fee_payer
        .key_name
        .as_deref()
        .ok_or_else(|| Error::SendNotConfigured(missing_key_name_msg.into()))?;
    let pubkey = fee_payer
        .pubkey
        .as_deref()
        .ok_or_else(|| Error::SendNotConfigured(missing_pubkey_msg.into()))?;
    let signer = Signer::from_gcp_kms(key_name.to_string(), pubkey.to_string())
        .await
        .map_err(|_| Error::FeePayerSigner)?;
    Ok(Arc::new(signer))
}
