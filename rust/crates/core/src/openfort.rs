//! Openfort backend wallet support — remote signing via Openfort's API.
//!
//! The private key lives in Openfort's TEE and never exists locally. pay
//! stores only the project's API credentials (secret key + wallet secret)
//! as a credential blob in the platform secret store, gated by the same
//! auth path as local keypairs (Touch ID / Windows Hello / polkit).
//! Signing calls `POST /v2/accounts/backend/{id}/sign` and verifies the
//! returned ed25519 signature against the wallet's pinned address.
//!
//! Because signing is a policy-checked HTTPS call, an Openfort account can
//! be constrained server-side (spend limits, allowed programs/mints) via
//! Openfort's policy engine — the credentials on this machine are
//! revocable and never sufficient to extract the key.
//!
//! The signer is implemented here rather than through `solana-keychain`'s
//! `openfort` feature because that implementation builds its HTTP client
//! with reqwest's ambient TLS default. In this workspace the Solana RPC
//! crates force reqwest's `default-tls` (native-tls) on, and native-tls on
//! macOS negotiates at most TLS 1.2 — while `api.openfort.io` only accepts
//! TLS 1.3. The client below selects rustls explicitly.

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pay_kit::solana_keychain::transaction_util::TransactionUtil;
use pay_kit::solana_keychain::{SignTransactionResult, SignerError, SolanaSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use std::str::FromStr;

use crate::accounts::Account;
use crate::keystore::AuthIntent;
use crate::signer::{AuthOverride, ResolvedSigner};
use crate::{Error, Result};

const OPENFORT_API_BASE: &str = "https://api.openfort.io";
const OPENFORT_API_HOST: &str = "api.openfort.io";
const JWT_LIFETIME_SECS: i64 = 120;
const SIGNATURE_LEN: usize = 64;

/// API credentials for an Openfort backend wallet, serialized as a JSON
/// credential blob in the platform secret store.
#[derive(Serialize, Deserialize)]
pub struct OpenfortCredentials {
    /// Project secret key (`sk_live_…` / `sk_test_…`).
    pub secret_key: String,
    /// ECDSA P-256 wallet secret (base64 PKCS#8 DER or PEM) that signs the
    /// `x-wallet-auth` JWT on each request.
    pub wallet_secret: String,
}

// ── Remote signer ───────────────────────────────────────────────────────────

/// Signs through Openfort's backend wallet API. The wallet's Solana
/// address is fetched and pinned at [`OpenfortSigner::connect`] time;
/// every returned signature is verified against it before use.
pub struct OpenfortSigner {
    secret_key: String,
    account_id: String,
    wallet_secret: String,
    address: Pubkey,
    client: reqwest::Client,
}

impl std::fmt::Debug for OpenfortSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenfortSigner")
            .field("account_id", &self.account_id)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct AccountInfo {
    address: String,
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

#[derive(Serialize)]
struct WalletClaims {
    uris: Vec<String>,
    iat: i64,
    nbf: i64,
    exp: i64,
    jti: String,
    #[serde(rename = "reqHash", skip_serializing_if = "Option::is_none")]
    req_hash: Option<String>,
}

/// Canonical JSON body for the sign call.
///
/// The server verifies the JWT's `reqHash` by re-serializing the body it
/// parsed — keys sorted, no whitespace — and hashing that. Any other
/// serialization (a single space after a colon is enough) fails with a
/// bare 401 "Authentication failed"; verified against the live API. This
/// body must therefore stay byte-identical to `JSON.stringify` of the
/// key-sorted object: compact separators, fields in alphabetical order.
/// `sign_body_is_canonical_json` pins the exact bytes — update it
/// consciously when the shape changes.
fn sign_request_body(message: &[u8]) -> std::result::Result<String, SignerError> {
    let data_hex = format!("0x{}", *crate::keystore::store::hex_encode(message));
    serde_json::to_string(&serde_json::json!({ "data": data_hex }))
        .map_err(|e| SignerError::SerializationError(format!("body: {e}")))
}

/// Normalize the wallet secret to a PEM string `jsonwebtoken` can parse.
/// Accepts either a full PEM (passed through) or a bare base64 PKCS#8 DER
/// body (the single-line form the Openfort dashboard hands out).
fn wallet_secret_to_pem(wallet_secret: &str) -> String {
    if wallet_secret.trim_start().starts_with("-----BEGIN") {
        return wallet_secret.to_string();
    }
    let stripped: String = wallet_secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    format!("-----BEGIN PRIVATE KEY-----\n{stripped}\n-----END PRIVATE KEY-----\n")
}

impl OpenfortSigner {
    /// Build the signer, fetch the wallet's Solana address from
    /// `GET /v2/accounts/{id}`, and pin it. Validates the secret key and
    /// account in the process.
    pub async fn connect(
        credentials: &OpenfortCredentials,
        account_id: &str,
    ) -> std::result::Result<Self, SignerError> {
        if credentials.secret_key.is_empty() || credentials.wallet_secret.is_empty() {
            return Err(SignerError::ConfigError(
                "Openfort credentials must not be empty".to_string(),
            ));
        }

        // rustls explicitly: the workspace also compiles reqwest's
        // native-tls backend (forced by the Solana RPC crates), which
        // cannot reach the TLS 1.3-only Openfort API on macOS.
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .https_only(true)
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|e| SignerError::ConfigError(format!("Failed to build HTTP client: {e}")))?;

        let mut signer = Self {
            secret_key: credentials.secret_key.clone(),
            account_id: account_id.to_string(),
            wallet_secret: credentials.wallet_secret.clone(),
            address: Pubkey::default(),
            client,
        };
        signer.address = signer.fetch_address().await?;
        Ok(signer)
    }

    /// `GET /v2/accounts/{id}` — bearer auth only, no wallet JWT.
    async fn fetch_address(&self) -> std::result::Result<Pubkey, SignerError> {
        let url = format!("{OPENFORT_API_BASE}/v2/accounts/{}", self.account_id);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.secret_key)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("Openfort request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(SignerError::RemoteApiError(format!(
                "Openfort API error {} fetching account {}",
                response.status().as_u16(),
                self.account_id
            )));
        }

        let info: AccountInfo = response.json().await.map_err(|_| {
            SignerError::SerializationError("Failed to parse Openfort account response".to_string())
        })?;
        Pubkey::from_str(&info.address).map_err(|_| {
            SignerError::InvalidPublicKey(format!(
                "Openfort returned a non-Solana address for {}: ensure the backend wallet \
                 is on a Solana (SVM) chain",
                self.account_id
            ))
        })
    }

    /// Build the `x-wallet-auth` ES256 JWT over `<METHOD> <host><path>` and
    /// the SHA-256 of the exact request body being sent.
    fn wallet_jwt(
        &self,
        method: &str,
        path: &str,
        body: &str,
    ) -> std::result::Result<String, SignerError> {
        let now = chrono::Utc::now().timestamp();
        let claims = WalletClaims {
            uris: vec![format!("{method} {OPENFORT_API_HOST}{path}")],
            iat: now,
            nbf: now,
            exp: now + JWT_LIFETIME_SECS,
            jti: uuid::Uuid::new_v4().to_string(),
            req_hash: Some(format!("{:x}", Sha256::digest(body.as_bytes()))),
        };

        let pem = wallet_secret_to_pem(&self.wallet_secret);
        let key = EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|_| {
            SignerError::InvalidPrivateKey(
                "Failed to parse the Openfort wallet secret as an EC P-256 private key \
                 (expected base64 PKCS#8 DER or PEM)"
                    .to_string(),
            )
        })?;

        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("JWT".to_string());
        encode(&header, &claims, &key).map_err(|_| {
            SignerError::SigningFailed("Failed to create the Openfort wallet JWT".to_string())
        })
    }

    /// `POST /v2/accounts/backend/{id}/sign` with hex-encoded message bytes.
    /// The body comes from [`sign_request_body`] and is reused verbatim
    /// for the JWT's request hash — see the canonicalization contract
    /// documented there.
    async fn call_sign(&self, message: &[u8]) -> std::result::Result<SignResponse, SignerError> {
        let path = format!("/v2/accounts/backend/{}/sign", self.account_id);
        let body = sign_request_body(message)?;
        let jwt = self.wallet_jwt("POST", &path, &body)?;

        let response = self
            .client
            .post(format!("{OPENFORT_API_BASE}{path}"))
            .bearer_auth(&self.secret_key)
            .header("x-wallet-auth", jwt)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| SignerError::HttpError(format!("Openfort request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(SignerError::RemoteApiError(format!(
                "Openfort API error {} signing with {}",
                response.status().as_u16(),
                self.account_id
            )));
        }

        response.json::<SignResponse>().await.map_err(|_| {
            SignerError::SerializationError("Failed to parse Openfort sign response".to_string())
        })
    }

    /// Sign arbitrary bytes remotely and verify the returned ed25519
    /// signature against the pinned address.
    async fn sign_bytes(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        let response = self.call_sign(message).await?;

        let sig_hex = response.signature.trim_start_matches("0x");
        let sig_bytes = crate::keystore::store::hex_decode(sig_hex).map_err(|_| {
            SignerError::SerializationError(
                "Failed to hex-decode the Openfort signature".to_string(),
            )
        })?;
        let sig_array: [u8; SIGNATURE_LEN] = sig_bytes.try_into().map_err(|_| {
            SignerError::SigningFailed(format!(
                "Invalid signature length from Openfort (expected {SIGNATURE_LEN} bytes)"
            ))
        })?;

        let signature = Signature::from(sig_array);
        if !signature.verify(&self.address.to_bytes(), message) {
            return Err(SignerError::SigningFailed(
                "Openfort returned a signature that does not verify against the wallet's \
                 address"
                    .to_string(),
            ));
        }
        Ok(signature)
    }
}

#[async_trait::async_trait]
impl SolanaSigner for OpenfortSigner {
    fn pubkey(&self) -> Pubkey {
        self.address
    }

    async fn sign_transaction(
        &self,
        tx: &mut Transaction,
    ) -> std::result::Result<SignTransactionResult, SignerError> {
        let signature = self.sign_bytes(&tx.message_data()).await?;
        TransactionUtil::add_signature_to_transaction(tx, &self.address, signature)?;
        let serialized = TransactionUtil::serialize_transaction(tx)?;
        Ok(TransactionUtil::classify_signed_transaction(
            tx,
            (serialized, signature),
        ))
    }

    async fn sign_message(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        self.sign_bytes(message).await
    }

    async fn is_available(&self) -> bool {
        match self.fetch_address().await {
            Ok(address) => address == self.address,
            Err(_) => false,
        }
    }
}

// ── Credential storage ──────────────────────────────────────────────────────

/// Build the platform secret store for Openfort credential blobs.
///
/// `gated` selects whether loads pass through the platform auth prompt;
/// `auth_override` (MCP elicitation) replaces the platform gate when
/// present, mirroring the keypair backends.
fn platform_keystore(
    gated: bool,
    auth_override: AuthOverride,
) -> Result<(crate::keystore::Keystore, &'static str)> {
    #[cfg(target_os = "macos")]
    {
        let ks = if gated {
            match auth_override {
                Some(gate) => crate::keystore::Keystore::from_boxed_auth(
                    gate,
                    Box::new(crate::keystore::macos::AppleKeychainStore),
                    true,
                ),
                None => crate::keystore::Keystore::apple_keychain(),
            }
        } else {
            crate::keystore::Keystore::new(
                crate::keystore::auth::NoAuth,
                crate::keystore::macos::AppleKeychainStore,
                false,
            )
        };
        Ok((ks, "keychain"))
    }
    #[cfg(target_os = "linux")]
    {
        let ks = if gated {
            match auth_override {
                Some(gate) => crate::keystore::Keystore::from_boxed_auth(
                    gate,
                    Box::new(crate::keystore::linux::SecretServiceStore),
                    true,
                ),
                None => crate::keystore::Keystore::gnome_keyring(),
            }
        } else {
            crate::keystore::Keystore::new(
                crate::keystore::auth::NoAuth,
                crate::keystore::linux::SecretServiceStore,
                false,
            )
        };
        Ok((ks, "gnome-keyring"))
    }
    #[cfg(target_os = "windows")]
    {
        let ks = if gated {
            match auth_override {
                Some(gate) => crate::keystore::Keystore::from_boxed_auth(
                    gate,
                    Box::new(crate::keystore::windows::WindowsCredentialStore),
                    true,
                ),
                None => crate::keystore::Keystore::windows_hello(),
            }
        } else {
            crate::keystore::Keystore::new(
                crate::keystore::auth::NoAuth,
                crate::keystore::windows::WindowsCredentialStore,
                false,
            )
        };
        Ok((ks, "windows-hello"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (gated, auth_override);
        Err(Error::Config(
            "Openfort accounts require a platform secret store (Keychain, GNOME Keyring, or \
             Windows Credential Manager), which is unavailable on this platform."
                .to_string(),
        ))
    }
}

/// Store credentials through an already-built platform keystore. The CLI
/// builds the keystore itself so setup-time gating fallbacks (e.g. no
/// enrolled Touch ID) stay in one place.
pub fn store_credentials(
    ks: &crate::keystore::Keystore,
    name: &str,
    credentials: &OpenfortCredentials,
    intent: &AuthIntent,
) -> Result<()> {
    let blob = serde_json::to_vec(credentials)
        .map_err(|e| Error::Config(format!("Failed to serialize Openfort credentials: {e}")))?;
    ks.import_credential_with_intent(name, &blob, intent)
        .map_err(|e| Error::Config(format!("Failed to store Openfort credentials: {e}")))
}

/// Check whether Openfort credentials exist for this account name in the
/// platform secret store. Never prompts.
pub fn credentials_exist(name: &str) -> bool {
    platform_keystore(false, None).is_ok_and(|(ks, _)| ks.credential_exists(name))
}

/// Delete the credential blob for this account name from the platform
/// secret store, passing through the platform auth prompt.
pub fn delete_credentials(name: &str, intent: &AuthIntent) -> Result<()> {
    let (ks, backend) = platform_keystore(true, None)?;
    ks.delete_credential_with_intent(name, intent)
        .map_err(|e| crate::signer::map_keystore_backend_error(backend, e))
}

fn load_credentials(
    name: &str,
    gated: bool,
    auth_override: AuthOverride,
    intent: &AuthIntent,
) -> Result<OpenfortCredentials> {
    let (ks, backend) = platform_keystore(gated, auth_override)?;
    if !ks.credential_exists(name) {
        return Err(Error::Config(format!(
            "No Openfort credentials stored for account `{name}`.\n\
             Run `pay account new {name} --backend openfort` to connect the backend wallet."
        )));
    }
    let blob = ks
        .load_credential_with_intent(name, intent)
        .map_err(|e| crate::signer::map_keystore_backend_error(backend, e))?;
    serde_json::from_slice(&blob).map_err(|e| {
        Error::Config(format!(
            "Stored Openfort credentials for `{name}` are corrupted ({e}). \
             Re-connect the wallet: `pay account destroy {name}` then \
             `pay account new {name} --backend openfort`."
        ))
    })
}

// ── Account resolution ──────────────────────────────────────────────────────

/// Build a connected [`OpenfortSigner`] and return its Solana address
/// (base58). Used at setup time to validate credentials and cache the
/// address in `accounts.yml`.
pub fn fetch_wallet_address(credentials: &OpenfortCredentials, account_id: &str) -> Result<String> {
    let signer = build_signer(credentials, account_id)?;
    Ok(signer.pubkey().to_string())
}

/// Resolve an Openfort account into a ready-to-sign [`ResolvedSigner`].
///
/// Loads the credential blob (through the platform auth gate when the
/// account requires auth on this network), connects the remote signer
/// (which fetches and pins the wallet's Solana address), and cross-checks
/// the address against the `pubkey` cached in `accounts.yml`.
///
/// Like the rest of the signer-resolution surface and the MPP/x402
/// payment builders, this is synchronous and blocks on network I/O
/// (it drives the connect round-trip on an internal runtime). Callers
/// on async workers must isolate it with `tokio::task::spawn_blocking`
/// — the same contract the payer proxy and MCP tools already follow
/// for `build_credential` / `build_payment`.
pub fn load_openfort_signer(
    account: &Account,
    name: &str,
    network: &str,
    intent: &AuthIntent,
    auth_override: AuthOverride,
) -> Result<ResolvedSigner> {
    let account_id = account.account.clone().ok_or_else(|| {
        Error::Config(format!(
            "Openfort account `{name}` is missing its `account` field (the Openfort \
             account ID, `acc_…`) in accounts.yml."
        ))
    })?;

    let gated = account.auth_required_for_network(network);
    let account_intent = intent.with_account_context(name);
    let credentials = load_credentials(name, gated, auth_override, &account_intent)?;

    let signer = build_signer(&credentials, &account_id)?;

    let address = signer.pubkey().to_string();
    if let Some(expected) = account.pubkey.as_deref()
        && expected != address
    {
        return Err(Error::Config(format!(
            "Openfort account `{name}` resolves to address {address}, but accounts.yml \
             caches {expected}. The backend wallet behind `{account_id}` changed — \
             re-connect it: `pay account destroy {name}` then \
             `pay account new {name} --backend openfort`."
        )));
    }

    Ok(ResolvedSigner::Openfort(signer))
}

/// Connect the remote signer (fetches the wallet address from Openfort,
/// validating the credentials in the process).
fn build_signer(credentials: &OpenfortCredentials, account_id: &str) -> Result<OpenfortSigner> {
    // The payment client paths are synchronous and create their own tokio
    // runtimes for header building, so a throwaway current-thread runtime
    // for the connect round-trip is safe here.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Config(format!("Failed to create runtime: {e}")))?;

    rt.block_on(OpenfortSigner::connect(credentials, account_id))
        .map_err(|e| {
            Error::Config(format!(
                "Could not reach the Openfort backend wallet `{account_id}`: {e}.\n\
                 Check the secret key, wallet secret, and account ID, and that the \
                 account is on a Solana (SVM) chain."
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Keystore as KeystoreKind;
    use std::collections::BTreeMap;

    fn openfort_account(account_id: Option<&str>, pubkey: Option<&str>) -> Account {
        Account {
            keystore: KeystoreKind::Openfort,
            active: false,
            auth_required: Some(false),
            pubkey: pubkey.map(str::to_string),
            vault: None,
            account: account_id.map(str::to_string),
            path: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: BTreeMap::new(),
        }
    }

    #[test]
    fn credentials_json_roundtrip() {
        let creds = OpenfortCredentials {
            secret_key: "sk_test_abc".to_string(),
            wallet_secret: "BASE64DER".to_string(),
        };
        let blob = serde_json::to_vec(&creds).unwrap();
        let back: OpenfortCredentials = serde_json::from_slice(&blob).unwrap();
        assert_eq!(back.secret_key, "sk_test_abc");
        assert_eq!(back.wallet_secret, "BASE64DER");
    }

    #[test]
    fn load_openfort_signer_requires_account_id() {
        let account = openfort_account(None, None);
        let err = load_openfort_signer(
            &account,
            "default",
            "mainnet",
            &AuthIntent::default_payment(),
            None,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(err.to_string().contains("missing its `account` field"));
    }

    #[test]
    fn store_credentials_roundtrip_through_keystore() {
        let ks = crate::keystore::Keystore::in_memory();
        let intent = AuthIntent::from_reason("test");
        let creds = OpenfortCredentials {
            secret_key: "sk_test_abc".to_string(),
            wallet_secret: "BASE64DER".to_string(),
        };

        store_credentials(&ks, "default", &creds, &intent).unwrap();
        assert!(ks.credential_exists("default"));

        let blob = ks.load_credential_with_intent("default", &intent).unwrap();
        let back: OpenfortCredentials = serde_json::from_slice(&blob).unwrap();
        assert_eq!(back.secret_key, "sk_test_abc");
    }

    #[test]
    fn wallet_secret_pem_passthrough_and_wrap() {
        let pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n";
        assert_eq!(wallet_secret_to_pem(pem), pem);

        let wrapped = wallet_secret_to_pem("ab cd\nef");
        assert!(wrapped.starts_with("-----BEGIN PRIVATE KEY-----\nabcdef\n"));
        assert!(wrapped.trim_end().ends_with("-----END PRIVATE KEY-----"));
    }

    /// Pins the sign body to the server's canonical serialization
    /// (key-sorted, whitespace-free). A drift here is a live 401: the
    /// server hashes its own canonical re-serialization for `reqHash`.
    #[test]
    fn sign_body_is_canonical_json() {
        let body = sign_request_body(&[0xde, 0xad, 0xbe, 0xef]).unwrap();
        assert_eq!(body, r#"{"data":"0xdeadbeef"}"#);
    }

    /// Known-answer test for the wallet JWT: ES256 header, the
    /// `<METHOD> <host><path>` uri claim, and reqHash = sha256(body).
    #[test]
    fn wallet_jwt_claims_shape() {
        // Minimal valid P-256 PKCS#8 DER (scalar = 1), base64-encoded.
        #[rustfmt::skip]
        const P256_PKCS8_DER: &[u8] = &[
            0x30, 0x41,
            0x02, 0x01, 0x00,
            0x30, 0x13,
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x04, 0x27,
            0x30, 0x25,
            0x02, 0x01, 0x01,
            0x04, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        ];
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        let signer = OpenfortSigner {
            secret_key: "sk_test_x".to_string(),
            account_id: "acc_x".to_string(),
            wallet_secret: b64.encode(P256_PKCS8_DER),
            address: Pubkey::default(),
            client: reqwest::Client::new(),
        };

        let body = r#"{"data":"0xdeadbeef"}"#;
        let jwt = signer
            .wallet_jwt("POST", "/v2/accounts/backend/acc_x/sign", body)
            .unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let decode = |s: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .unwrap()
        };
        let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");

        let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])).unwrap();
        assert_eq!(
            claims["uris"][0],
            "POST api.openfort.io/v2/accounts/backend/acc_x/sign"
        );
        assert_eq!(
            claims["reqHash"],
            format!("{:x}", Sha256::digest(body.as_bytes()))
        );
        assert!(claims["jti"].is_string());
        assert!(claims["iat"].is_i64());
        assert!(claims["nbf"].is_i64());
        assert!(claims["exp"].is_i64());
    }
}
