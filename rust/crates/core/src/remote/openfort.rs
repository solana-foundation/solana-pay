//! Openfort backend wallets — the reference [`RemoteProvider`].
//!
//! The private key lives in Openfort's TEE and never exists locally; pay
//! stores only the project's API credentials. Because signing is a
//! policy-checked HTTPS call, the wallet can be constrained server-side
//! (spend limits, allowed programs and mints) through Openfort's policy
//! engine, and the credentials on this machine are revocable.
//!
//! The signer itself is `solana-keychain`'s `OpenfortSigner` (`openfort`
//! feature): it builds the ES256 `x-wallet-auth` JWT, calls
//! `POST /v2/accounts/backend/{id}/sign`, and verifies the returned
//! ed25519 signature against the address pinned at init.

use pay_kit::solana_keychain::{OpenfortSigner, SolanaSigner};
use serde::Deserialize;

use crate::remote::{CredentialField, Credentials, RemoteProvider, RemoteWallet};
use crate::{Error, Result};

const API_BASE: &str = "https://api.openfort.io";

/// The Openfort remote backend.
pub struct Openfort;

static FIELDS: &[CredentialField] = &[
    CredentialField {
        key: "secret_key",
        label: "Openfort secret key (sk_live_… / sk_test_…)",
        secret: true,
    },
    CredentialField {
        key: "wallet_secret",
        label: "Openfort wallet secret (base64 P-256 key)",
        secret: true,
    },
];

impl RemoteProvider for Openfort {
    fn id(&self) -> &'static str {
        "openfort"
    }

    fn display_name(&self) -> &'static str {
        "Openfort backend wallet"
    }

    fn credential_fields(&self) -> &'static [CredentialField] {
        FIELDS
    }

    fn credentials_hint(&self) -> &'static str {
        "Connect an Openfort backend wallet (dashboard.openfort.io → Developers → API keys)."
    }

    fn validate_credential(&self, key: &str, value: &str) -> Result<()> {
        if key == "secret_key" && !value.starts_with("sk_") {
            return Err(Error::Config(
                "The Openfort secret key must start with `sk_live_` or `sk_test_`.".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_wallet_id(&self, id: &str) -> Result<()> {
        if !id.starts_with("acc_") {
            return Err(Error::Config(
                "The Openfort account ID must start with `acc_` (a Solana backend wallet)."
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// `GET /v2/accounts` — needs only the secret key, no wallet secret
    /// and no JWT, so setup can call it before collecting everything else.
    fn discover(&self, credentials: &Credentials) -> Result<Vec<RemoteWallet>> {
        let secret_key = credentials
            .get("secret_key")
            .ok_or_else(|| Error::Config("Missing the Openfort secret key.".to_string()))?;

        // rustls explicitly: the Solana RPC crates force reqwest's
        // native-tls backend on in this workspace, and native-tls on macOS
        // tops out at TLS 1.2 while api.openfort.io requires 1.3.
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| Error::Config(format!("Failed to build HTTP client: {e}")))?;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Config(format!("Failed to create runtime: {e}")))?;

        let page: AccountsPage = rt.block_on(async {
            let response = client
                .get(format!("{API_BASE}/v2/accounts?limit=100"))
                .bearer_auth(secret_key)
                .send()
                .await
                .map_err(|e| Error::Config(format!("Could not reach Openfort: {e}")))?;

            let status = response.status();
            if !status.is_success() {
                return Err(Error::Config(match status.as_u16() {
                    401 | 403 => "Openfort rejected that secret key (HTTP 401/403). Check that \
                                  you copied a project secret key (`sk_live_…` / `sk_test_…`) \
                                  from dashboard.openfort.io → Developers → API keys."
                        .to_string(),
                    code => format!("Openfort API error {code} listing accounts."),
                }));
            }

            response.json::<AccountsPage>().await.map_err(|e| {
                Error::Config(format!("Failed to parse the Openfort account list: {e}"))
            })
        })?;

        Ok(signable_solana_wallets(page.data))
    }

    fn no_wallets_hint(&self) -> &'static str {
        "This Openfort project has no Solana backend wallet yet.\n\
         Create one at https://dashboard.openfort.io → Accounts → New account \
         (chain type: Solana / SVM), then run this command again."
    }

    fn connect(&self, credentials: &Credentials, wallet_id: &str) -> Result<Box<dyn SolanaSigner>> {
        let secret_key = credentials
            .get("secret_key")
            .ok_or_else(|| Error::Config("Missing the Openfort secret key.".to_string()))?;
        let wallet_secret = credentials
            .get("wallet_secret")
            .ok_or_else(|| Error::Config("Missing the Openfort wallet secret.".to_string()))?;

        let mut signer = OpenfortSigner::new(
            secret_key.clone(),
            wallet_id.to_string(),
            wallet_secret.clone(),
        )
        .map_err(|e| {
            Error::Config(format!(
                "Invalid Openfort credentials for `{wallet_id}`: {e}"
            ))
        })?;

        // The payment client paths are synchronous and create their own
        // tokio runtimes for header building, so a throwaway current-thread
        // runtime for the init round-trip is safe here.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Config(format!("Failed to create runtime: {e}")))?;

        rt.block_on(signer.init()).map_err(|e| {
            Error::Config(format!(
                "Could not reach the Openfort backend wallet `{wallet_id}`: {e}.\n\
                 Check the secret key, wallet secret, and account ID, and that the \
                 account is on a Solana (SVM) chain."
            ))
        })?;

        Ok(Box::new(signer))
    }
}

#[derive(Deserialize)]
struct AccountsPage {
    data: Vec<AccountRecord>,
}

#[derive(Deserialize)]
struct AccountRecord {
    id: String,
    address: String,
    #[serde(rename = "chainType")]
    chain_type: Option<String>,
    custody: Option<String>,
}

/// Narrow an account listing to the wallets pay can sign with: Solana
/// chain type and developer custody. `POST /v2/accounts/backend/{id}/sign`
/// rejects everything else, so offering them would only fail later.
fn signable_solana_wallets(records: Vec<AccountRecord>) -> Vec<RemoteWallet> {
    records
        .into_iter()
        .filter(|a| a.chain_type.as_deref() == Some("SVM"))
        .filter(|a| a.custody.as_deref().is_none_or(|c| c == "Developer"))
        .map(|a| RemoteWallet {
            id: a.id,
            address: a.address,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only wallets pay can actually sign with survive the filter: SVM
    /// chain type, developer custody. An EVM wallet or an end-user
    /// embedded wallet in the same project must not be offered.
    #[test]
    fn wallet_list_keeps_only_signable_solana_wallets() {
        let page: AccountsPage = serde_json::from_str(
            r#"{"data":[
                {"id":"acc_svm","address":"4LTNH","chainType":"SVM","custody":"Developer"},
                {"id":"acc_evm","address":"0xabc","chainType":"EVM","custody":"Developer"},
                {"id":"acc_user","address":"9xQeW","chainType":"SVM","custody":"User"},
                {"id":"acc_bare","address":"7uNbA","chainType":"SVM"}
            ]}"#,
        )
        .unwrap();

        let kept: Vec<String> = signable_solana_wallets(page.data)
            .into_iter()
            .map(|w| w.id)
            .collect();

        assert_eq!(kept, vec!["acc_svm", "acc_bare"]);
    }

    #[test]
    fn credentials_are_validated_as_entered() {
        assert!(
            Openfort
                .validate_credential("secret_key", "pk_test_x")
                .is_err()
        );
        assert!(
            Openfort
                .validate_credential("secret_key", "sk_test_x")
                .is_ok()
        );
        // Fields without a rule pass through.
        assert!(
            Openfort
                .validate_credential("wallet_secret", "anything")
                .is_ok()
        );
    }

    #[test]
    fn wallet_ids_are_validated() {
        assert!(Openfort.validate_wallet_id("0xabc").is_err());
        assert!(Openfort.validate_wallet_id("acc_0eb7e39b").is_ok());
    }
}
