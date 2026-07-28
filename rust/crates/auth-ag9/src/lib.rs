//! Device-independent AG9 Palm authorization for Pay subscription activation.
//!
//! This crate is intentionally optional. Pay's core emits a typed
//! [`SubscriptionAuthorization`]; this backend binds those durable terms to a
//! fresh AG9 approval, verifies the returned Ed25519 JWT locally, and only then
//! lets the keystore unlock the subscriber key.

use std::io::Read;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use pay_keystore::{AuthGate, AuthIntent, Error as KeystoreError, SubscriptionAuthorization};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const DEFAULT_API_BASE_URL: &str = "https://api.ag9.ai";
const DEFAULT_ISSUER: &str = "api.ag9.ai";
const DEFAULT_AUDIENCE: &str = "pay.sh";
const HUMAN_SUBJECT: &str = "human_authorization_attestation";
const PALM_METHOD: &str = "veryai_oauth_palm";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(240);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(2_500);
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_RESPONSE_BYTES: u64 = 1_048_576;

/// Runtime settings for a registered AG9 agent identity.
#[derive(Debug, Clone)]
pub struct Ag9Config {
    pub api_base_url: String,
    pub jwks_url: String,
    pub issuer: String,
    pub audience: String,
    pub device_id: String,
    pub public_key: String,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub max_attestation_age: Duration,
    pub request_timeout: Duration,
}

impl Ag9Config {
    /// Load the AG9 backend from environment variables.
    ///
    /// Required: `AG9_DEVICE_ID` and `AG9_PUBLIC_KEY` (the existing demo
    /// aliases `AG9_DEMO_DEVICE_ID` / `AG9_DEMO_PUBLIC_KEY` also work).
    pub fn from_env() -> Result<Self, Ag9Error> {
        let api_base_url = first_env(&["PAY_AG9_API_BASE_URL", "AG9_API_BASE_URL"])
            .unwrap_or_else(|| DEFAULT_API_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        let jwks_url = first_env(&["PAY_AG9_JWKS_URL", "AG9_JWKS_URL"])
            .unwrap_or_else(|| format!("{api_base_url}/.well-known/jwks.json"));
        let issuer = first_env(&["PAY_AG9_ISSUER", "AG9_ISSUER"])
            .unwrap_or_else(|| DEFAULT_ISSUER.to_string());
        let audience = first_env(&["PAY_AG9_AUDIENCE", "AG9_AUDIENCE"])
            .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string());
        let device_id = required_env(&["AG9_DEVICE_ID", "AG9_DEMO_DEVICE_ID"])?;
        let public_key = required_env(&["AG9_PUBLIC_KEY", "AG9_DEMO_PUBLIC_KEY"])?;

        Ok(Self {
            api_base_url,
            jwks_url,
            issuer,
            audience,
            device_id,
            public_key,
            timeout: duration_env("PAY_AG9_TIMEOUT_SECONDS", DEFAULT_TIMEOUT)?,
            poll_interval: duration_env_millis("PAY_AG9_POLL_INTERVAL_MS", DEFAULT_POLL_INTERVAL)?,
            max_attestation_age: duration_env("PAY_AG9_MAX_AGE_SECONDS", DEFAULT_MAX_AGE)?,
            request_timeout: duration_env(
                "PAY_AG9_REQUEST_TIMEOUT_SECONDS",
                DEFAULT_REQUEST_TIMEOUT,
            )?,
        })
    }
}

/// Build an auth gate only when `PAY_AUTH_BACKEND=ag9` is explicitly set.
/// `platform`, `local`, and an unset value retain Pay's existing behavior.
pub fn configured_gate_from_env() -> Result<Option<Box<dyn AuthGate>>, Ag9Error> {
    let Some(backend) = std::env::var("PAY_AUTH_BACKEND").ok() else {
        return Ok(None);
    };
    match backend.trim().to_ascii_lowercase().as_str() {
        "" | "platform" | "local" => Ok(None),
        "ag9" => Ok(Some(Box::new(
            Ag9AuthGate::try_new(Ag9Config::from_env()?)?,
        ))),
        other => Err(Ag9Error::Configuration(format!(
            "unsupported PAY_AUTH_BACKEND `{other}`; expected `platform` or `ag9`"
        ))),
    }
}

/// AG9-backed implementation of Pay's synchronous auth gate.
pub struct Ag9AuthGate {
    config: Ag9Config,
    client: Client,
}

impl Ag9AuthGate {
    pub fn try_new(config: Ag9Config) -> Result<Self, Ag9Error> {
        let client = Client::builder()
            .timeout(config.request_timeout)
            // These endpoints establish the authorization result and its
            // signing keys. Never let an HTTP redirect silently change the
            // trust origin.
            .redirect(Policy::none())
            .build()
            .map_err(|e| Ag9Error::Configuration(format!("could not build HTTP client: {e}")))?;
        Ok(Self { config, client })
    }

    fn authorize(&self, intent: &AuthIntent) -> Result<(), Ag9Error> {
        let now = now_unix()?;
        let prepared = prepare_action(intent, &self.config, now, Uuid::new_v4().to_string())?;
        let init: InitResponse = read_json(
            self.client
                .post(format!(
                    "{}/v1/human/attestation/init",
                    self.config.api_base_url
                ))
                .json(&InitRequest {
                    device_id: &self.config.device_id,
                    public_key: &self.config.public_key,
                    audience: &self.config.audience,
                    action_hash: &prepared.action_hash,
                    action_description: &prepared.description,
                })
                .send()
                .map_err(|e| Ag9Error::Http(format!("could not start approval: {e}")))?,
            "start AG9 approval",
        )?;

        if init.session_id.trim().is_empty() || init.verification_url.trim().is_empty() {
            return Err(Ag9Error::Protocol(
                "AG9 approval response omitted session_id or verification_url".into(),
            ));
        }
        let verification_url =
            validate_verification_url(&self.config.api_base_url, &init.verification_url)?;

        eprintln!(
            "\nAG9 Palm approval required for this subscription:\n{}\n",
            verification_url
        );

        let jwt = self.wait_for_attestation(&init.session_id)?;
        let verification_time = now_unix()?;
        if verification_time >= prepared.authorization_expires_at {
            return Err(Ag9Error::Verification(
                "authorization action expired while waiting for approval".into(),
            ));
        }
        let jwks: Jwks = read_json(
            self.client
                .get(&self.config.jwks_url)
                .send()
                .map_err(|e| Ag9Error::Http(format!("could not fetch AG9 JWKS: {e}")))?,
            "fetch AG9 JWKS",
        )?;
        verify_attestation_jwt(
            &jwt,
            &jwks,
            &self.config,
            &prepared.action_hash,
            verification_time,
        )
    }

    fn wait_for_attestation(&self, session_id: &str) -> Result<String, Ag9Error> {
        let deadline = std::time::Instant::now() + self.config.timeout;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(Ag9Error::Timeout);
            }
            let status: StatusResponse = read_json(
                self.client
                    .get(status_url(&self.config.api_base_url, session_id)?)
                    .send()
                    .map_err(|e| Ag9Error::Http(format!("could not poll approval: {e}")))?,
                "poll AG9 approval",
            )?;

            match status.status.as_str() {
                "completed" => {
                    return status.attestation_jwt.ok_or_else(|| {
                        Ag9Error::Protocol("completed AG9 approval omitted attestation_jwt".into())
                    });
                }
                "failed" | "rejected" | "expired" | "cancelled" => {
                    return Err(Ag9Error::Denied(status.status));
                }
                "pending" | "created" | "waiting" | "scanning" => {
                    thread::sleep(self.config.poll_interval);
                }
                other => {
                    return Err(Ag9Error::Protocol(format!(
                        "AG9 returned unknown approval status `{other}`"
                    )));
                }
            }
        }
    }
}

impl AuthGate for Ag9AuthGate {
    fn authenticate(&self, intent: &AuthIntent) -> Result<(), KeystoreError> {
        self.authorize(intent)
            .map_err(|e| KeystoreError::AuthDenied(format!("AG9 authorization failed: {e}")))
    }

    fn is_available(&self) -> bool {
        true
    }
}

#[derive(Debug, Error)]
pub enum Ag9Error {
    #[error("configuration error: {0}")]
    Configuration(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("approval {0}")]
    Denied(String),
    #[error("timed out waiting for approval")]
    Timeout,
}

#[derive(Serialize)]
struct InitRequest<'a> {
    device_id: &'a str,
    public_key: &'a str,
    audience: &'a str,
    action_hash: &'a str,
    action_description: &'a str,
}

#[derive(Deserialize)]
struct InitResponse {
    session_id: String,
    verification_url: String,
}

#[derive(Deserialize)]
struct StatusResponse {
    status: String,
    attestation_jwt: Option<String>,
}

#[derive(Debug, Serialize)]
struct ActionEnvelope<'a> {
    namespace: &'static str,
    version: u8,
    audience: &'a str,
    agent_device_id: &'a str,
    authorization_nonce: String,
    authorization_expires_at: i64,
    subscription: &'a SubscriptionAuthorization,
}

#[derive(Debug)]
struct PreparedAction {
    action_hash: String,
    description: String,
    authorization_expires_at: i64,
}

fn prepare_action(
    intent: &AuthIntent,
    config: &Ag9Config,
    now: i64,
    nonce: String,
) -> Result<PreparedAction, Ag9Error> {
    let subscription = intent.subscription_authorization().ok_or_else(|| {
        Ag9Error::Verification(
            "AG9 is restricted to typed MPP subscription activation intents".into(),
        )
    })?;
    if subscription.subscriber.as_deref().is_none_or(str::is_empty) {
        return Err(Ag9Error::Verification(
            "subscription authorization is missing the subscriber wallet".into(),
        ));
    }

    let max_age = i64::try_from(config.max_attestation_age.as_secs())
        .map_err(|_| Ag9Error::Configuration("PAY_AG9_MAX_AGE_SECONDS is too large".into()))?;
    let authorization_expires_at = now
        .checked_add(max_age)
        .ok_or_else(|| Ag9Error::Protocol("authorization expiry overflowed".into()))?;
    let action = ActionEnvelope {
        namespace: "pay.mpp.subscription_activation",
        version: 1,
        audience: &config.audience,
        agent_device_id: &config.device_id,
        authorization_nonce: nonce,
        authorization_expires_at,
        subscription,
    };
    let value = serde_json::to_value(&action)
        .map_err(|e| Ag9Error::Protocol(format!("could not encode action: {e}")))?;
    let canonical = canonical_json(&value)?;
    let action_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    let description = format!(
        "Approve Pay MPP subscription: {} base units ({} decimals) of mint {} every {} {}(s), recipient {}, puller {}, plan {}, network {}, subscriber {}.",
        subscription.amount_base_units,
        subscription.decimals,
        subscription.mint,
        subscription.period_count,
        subscription.period_unit,
        subscription.recipient,
        subscription.puller,
        subscription.plan_id,
        subscription.network,
        subscription.subscriber.as_deref().unwrap_or("unknown"),
    );
    Ok(PreparedAction {
        action_hash,
        description,
        authorization_expires_at,
    })
}

fn canonical_json(value: &Value) -> Result<String, Ag9Error> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) => Ok(value.to_string()),
        Value::String(value) => serde_json::to_string(value)
            .map_err(|e| Ag9Error::Protocol(format!("could not encode string: {e}"))),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", values.join(",")))
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let fields = keys
                .into_iter()
                .map(|key| {
                    let encoded_key = serde_json::to_string(key).map_err(|e| {
                        Ag9Error::Protocol(format!("could not encode object key: {e}"))
                    })?;
                    let value = canonical_json(&values[key])?;
                    Ok(format!("{encoded_key}:{value}"))
                })
                .collect::<Result<Vec<_>, Ag9Error>>()?;
            Ok(format!("{{{}}}", fields.join(",")))
        }
    }
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
struct HumanClaims {
    iss: String,
    sub: String,
    aud: Value,
    human_id: String,
    device_id: String,
    action_hash: String,
    verification_method: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    alg: Option<String>,
}

fn verify_attestation_jwt(
    jwt: &str,
    jwks: &Jwks,
    config: &Ag9Config,
    expected_action_hash: &str,
    now: i64,
) -> Result<(), Ag9Error> {
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(Ag9Error::Verification("invalid JWT format".into()));
    }
    let header: JwtHeader = decode_json_segment(parts[0], "JWT header")?;
    if header.alg != "EdDSA" {
        return Err(Ag9Error::Verification(format!(
            "unexpected JWT alg `{}`",
            header.alg
        )));
    }
    let claims: HumanClaims = decode_json_segment(parts[1], "JWT claims")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|e| Ag9Error::Verification(format!("invalid JWT signature encoding: {e}")))?;
    let signature_bytes: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| Ag9Error::Verification("JWT signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&signature_bytes);
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    let mut eligible_keys = 0usize;
    let signature_valid = jwks.keys.iter().any(|key| {
        if key.kty != "OKP"
            || key.crv != "Ed25519"
            || key.key_use.as_deref().is_some_and(|usage| usage != "sig")
            || key.alg.as_deref().is_some_and(|alg| alg != "EdDSA")
            || header
                .kid
                .as_ref()
                .is_some_and(|kid| key.kid.as_deref() != Some(kid))
        {
            return false;
        }
        eligible_keys += 1;
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(&key.x) else {
            return false;
        };
        let Ok(bytes) = <Vec<u8> as TryInto<[u8; 32]>>::try_into(bytes) else {
            return false;
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&bytes) else {
            return false;
        };
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .is_ok()
    });
    if eligible_keys == 0 {
        return Err(Ag9Error::Verification(
            "AG9 JWKS contained no eligible Ed25519 key".into(),
        ));
    }
    if !signature_valid {
        return Err(Ag9Error::Verification(
            "AG9 JWT signature verification failed".into(),
        ));
    }

    if claims.iss != config.issuer {
        return Err(Ag9Error::Verification("issuer mismatch".into()));
    }
    if claims.sub != HUMAN_SUBJECT {
        return Err(Ag9Error::Verification("subject mismatch".into()));
    }
    if !audience_matches(&claims.aud, &config.audience) {
        return Err(Ag9Error::Verification("audience mismatch".into()));
    }
    if claims.human_id.trim().is_empty() {
        return Err(Ag9Error::Verification("human_id is missing".into()));
    }
    if claims.device_id != config.device_id {
        return Err(Ag9Error::Verification("device_id mismatch".into()));
    }
    if claims.action_hash != expected_action_hash {
        return Err(Ag9Error::Verification("action_hash mismatch".into()));
    }
    if claims.verification_method != PALM_METHOD {
        return Err(Ag9Error::Verification(
            "verification_method is not Palm".into(),
        ));
    }
    if claims.exp <= now {
        return Err(Ag9Error::Verification("attestation is expired".into()));
    }
    if claims.iat > now + CLOCK_SKEW_SECONDS {
        return Err(Ag9Error::Verification(
            "attestation iat is in the future".into(),
        ));
    }
    let max_age = i64::try_from(config.max_attestation_age.as_secs())
        .map_err(|_| Ag9Error::Configuration("PAY_AG9_MAX_AGE_SECONDS is too large".into()))?;
    if now.saturating_sub(claims.iat) > max_age {
        return Err(Ag9Error::Verification("attestation is too old".into()));
    }
    Ok(())
}

fn audience_matches(claim: &Value, expected: &str) -> bool {
    match claim {
        Value::String(value) => value == expected,
        Value::Array(values) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn decode_json_segment<T: DeserializeOwned>(segment: &str, label: &str) -> Result<T, Ag9Error> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|e| Ag9Error::Verification(format!("invalid {label} encoding: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Ag9Error::Verification(format!("invalid {label}: {e}")))
}

fn read_json<T: DeserializeOwned>(response: Response, operation: &str) -> Result<T, Ag9Error> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(Ag9Error::Protocol(format!(
            "{operation} response exceeded {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    let mut body = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| Ag9Error::Http(format!("{operation} response could not be read: {e}")))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Ag9Error::Protocol(format!(
            "{operation} response exceeded {MAX_RESPONSE_BYTES} bytes"
        )));
    }
    if !status.is_success() {
        let preview = String::from_utf8_lossy(&body)
            .chars()
            .filter(|character| !character.is_control())
            .take(300)
            .collect::<String>();
        return Err(Ag9Error::Http(format!(
            "{operation} returned HTTP {status}: {preview}"
        )));
    }
    serde_json::from_slice(&body)
        .map_err(|e| Ag9Error::Protocol(format!("{operation} returned invalid JSON: {e}")))
}

fn validate_verification_url(api_base_url: &str, raw: &str) -> Result<Url, Ag9Error> {
    let base = Url::parse(api_base_url)
        .map_err(|e| Ag9Error::Configuration(format!("invalid AG9 API base URL: {e}")))?;
    let verification = Url::parse(raw)
        .map_err(|e| Ag9Error::Protocol(format!("invalid AG9 verification URL: {e}")))?;
    if !matches!(verification.scheme(), "https" | "http") {
        return Err(Ag9Error::Protocol(
            "AG9 verification URL must use HTTP or HTTPS".into(),
        ));
    }
    if verification.origin() != base.origin() {
        return Err(Ag9Error::Protocol(
            "AG9 verification URL changed the configured API origin".into(),
        ));
    }
    Ok(verification)
}

fn status_url(api_base_url: &str, session_id: &str) -> Result<Url, Ag9Error> {
    let mut url = Url::parse(&format!(
        "{}/v1/human/attestation",
        api_base_url.trim_end_matches('/')
    ))
    .map_err(|e| Ag9Error::Configuration(format!("invalid AG9 API base URL: {e}")))?;
    url.path_segments_mut()
        .map_err(|_| Ag9Error::Configuration("AG9 API base URL cannot be a base".into()))?
        .push(session_id)
        .push("status");
    Ok(url)
}

fn first_env(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    })
}

fn required_env(names: &[&str]) -> Result<String, Ag9Error> {
    first_env(names)
        .ok_or_else(|| Ag9Error::Configuration(format!("one of {} is required", names.join(", "))))
}

fn duration_env(name: &str, default: Duration) -> Result<Duration, Ag9Error> {
    let Some(raw) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let seconds = raw.parse::<u64>().map_err(|_| {
        Ag9Error::Configuration(format!(
            "{name} must be a positive integer number of seconds"
        ))
    })?;
    if seconds == 0 {
        return Err(Ag9Error::Configuration(format!(
            "{name} must be greater than zero"
        )));
    }
    Ok(Duration::from_secs(seconds))
}

fn duration_env_millis(name: &str, default: Duration) -> Result<Duration, Ag9Error> {
    let Some(raw) = std::env::var(name).ok() else {
        return Ok(default);
    };
    let millis = raw.parse::<u64>().map_err(|_| {
        Ag9Error::Configuration(format!(
            "{name} must be a positive integer number of milliseconds"
        ))
    })?;
    if millis == 0 {
        return Err(Ag9Error::Configuration(format!(
            "{name} must be greater than zero"
        )));
    }
    Ok(Duration::from_millis(millis))
}

fn now_unix() -> Result<i64, Ag9Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .map_err(|e| Ag9Error::Protocol(format!("system clock is before Unix epoch: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn config() -> Ag9Config {
        Ag9Config {
            api_base_url: "https://api.ag9.ai".to_string(),
            jwks_url: "https://api.ag9.ai/.well-known/jwks.json".to_string(),
            issuer: DEFAULT_ISSUER.to_string(),
            audience: DEFAULT_AUDIENCE.to_string(),
            device_id: "device-1".to_string(),
            public_key: "public-key".to_string(),
            timeout: DEFAULT_TIMEOUT,
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_attestation_age: DEFAULT_MAX_AGE,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }

    fn authorization() -> SubscriptionAuthorization {
        SubscriptionAuthorization {
            version: 1,
            challenge_id: "challenge-1".to_string(),
            challenge_realm: "merchant.example".to_string(),
            challenge_expires: Some("2026-07-28T12:05:00Z".to_string()),
            challenge_digest: None,
            network: "mainnet".to_string(),
            plan_id: "plan".to_string(),
            plan_id_numeric: Some(42),
            plan_bump: Some(254),
            plan_created_at: Some(1_770_000_000),
            recipient: "recipient".to_string(),
            puller: "puller".to_string(),
            merchant: Some("merchant".to_string()),
            mint: "mint".to_string(),
            token_program: "token-program".to_string(),
            program_id: Some("subscription-program".to_string()),
            amount_base_units: "1000000".to_string(),
            decimals: 6,
            period_unit: "day".to_string(),
            period_count: 30,
            expected_period_hours: Some(720),
            subscription_expires: None,
            external_id: Some("customer-plan".to_string()),
            fee_payer: false,
            fee_payer_key: None,
            account: Some("primary".to_string()),
            subscriber: Some("subscriber".to_string()),
        }
    }

    fn intent(authorization: SubscriptionAuthorization) -> AuthIntent {
        AuthIntent::authorize_subscription(
            "$1.00",
            "Recurring subscription",
            "merchant.example",
            authorization,
        )
    }

    fn jwks(signing_key: &SigningKey) -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                kid: None,
                key_use: Some("sig".to_string()),
                alg: Some("EdDSA".to_string()),
            }],
        }
    }

    fn sign_jwt(signing_key: &SigningKey, claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let input = format!("{header}.{claims}");
        let signature = signing_key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn claims(now: i64, action_hash: &str) -> Value {
        serde_json::json!({
            "iss": DEFAULT_ISSUER,
            "sub": HUMAN_SUBJECT,
            "aud": DEFAULT_AUDIENCE,
            "human_id": "human-1",
            "device_id": "device-1",
            "action_hash": action_hash,
            "verification_method": PALM_METHOD,
            "iat": now,
            "exp": now + 300,
        })
    }

    #[test]
    fn action_hash_is_deterministic_and_sensitive_to_terms() {
        let config = config();
        let first = prepare_action(&intent(authorization()), &config, 100, "nonce".into()).unwrap();
        let second =
            prepare_action(&intent(authorization()), &config, 100, "nonce".into()).unwrap();
        assert_eq!(first.action_hash, second.action_hash);
        assert_eq!(first.authorization_expires_at, 400);

        let mut changed = authorization();
        changed.amount_base_units = "2000000".to_string();
        let changed = prepare_action(&intent(changed), &config, 100, "nonce".into()).unwrap();
        assert_ne!(first.action_hash, changed.action_hash);
    }

    #[test]
    fn action_hash_changes_for_each_authorization_nonce() {
        let config = config();
        let first =
            prepare_action(&intent(authorization()), &config, 100, "nonce-1".into()).unwrap();
        let second =
            prepare_action(&intent(authorization()), &config, 100, "nonce-2".into()).unwrap();
        assert_ne!(first.action_hash, second.action_hash);
    }

    #[test]
    fn non_subscription_intent_fails_closed() {
        let err = prepare_action(
            &AuthIntent::default_payment(),
            &config(),
            100,
            "nonce".into(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("restricted"));
    }

    #[test]
    fn verification_url_must_stay_on_the_configured_origin() {
        let accepted = validate_verification_url(
            "https://api.ag9.ai",
            "https://api.ag9.ai/v1/human/attestation/session/verify",
        )
        .unwrap();
        assert_eq!(accepted.host_str(), Some("api.ag9.ai"));

        let err = validate_verification_url(
            "https://api.ag9.ai",
            "https://example.com/pretend-palm-check",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("changed the configured API origin")
        );
    }

    #[test]
    fn status_url_encodes_the_session_as_one_path_segment() {
        let url = status_url("https://api.ag9.ai", "session/with?delimiters").unwrap();
        assert_eq!(
            url.as_str(),
            "https://api.ag9.ai/v1/human/attestation/session%2Fwith%3Fdelimiters/status"
        );
    }

    #[test]
    fn verifies_matching_fresh_palm_attestation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let now = 1_800_000_000;
        let hash = "action-hash";
        let jwt = sign_jwt(&signing_key, claims(now, hash));
        verify_attestation_jwt(&jwt, &jwks(&signing_key), &config(), hash, now).unwrap();
    }

    #[test]
    fn rejects_attestation_for_different_action() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let now = 1_800_000_000;
        let jwt = sign_jwt(&signing_key, claims(now, "other-action"));
        let err =
            verify_attestation_jwt(&jwt, &jwks(&signing_key), &config(), "expected-action", now)
                .unwrap_err();
        assert!(err.to_string().contains("action_hash mismatch"));
    }

    #[test]
    fn rejects_expired_or_wrong_device_attestation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let now = 1_800_000_000;
        let mut expired = claims(now - 400, "hash");
        expired["exp"] = serde_json::json!(now - 1);
        let jwt = sign_jwt(&signing_key, expired);
        assert!(
            verify_attestation_jwt(&jwt, &jwks(&signing_key), &config(), "hash", now)
                .unwrap_err()
                .to_string()
                .contains("expired")
        );

        let mut wrong_device = claims(now, "hash");
        wrong_device["device_id"] = serde_json::json!("other-device");
        let jwt = sign_jwt(&signing_key, wrong_device);
        assert!(
            verify_attestation_jwt(&jwt, &jwks(&signing_key), &config(), "hash", now)
                .unwrap_err()
                .to_string()
                .contains("device_id mismatch")
        );
    }

    #[test]
    fn rejects_wrong_audience_or_verification_method() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let now = 1_800_000_000;

        let mut wrong_audience = claims(now, "hash");
        wrong_audience["aud"] = serde_json::json!("other-service");
        let jwt = sign_jwt(&signing_key, wrong_audience);
        assert!(
            verify_attestation_jwt(&jwt, &jwks(&signing_key), &config(), "hash", now)
                .unwrap_err()
                .to_string()
                .contains("audience mismatch")
        );

        let mut wrong_method = claims(now, "hash");
        wrong_method["verification_method"] = serde_json::json!("password");
        let jwt = sign_jwt(&signing_key, wrong_method);
        assert!(
            verify_attestation_jwt(&jwt, &jwks(&signing_key), &config(), "hash", now)
                .unwrap_err()
                .to_string()
                .contains("not Palm")
        );
    }

    #[test]
    fn rejects_stale_or_future_attestation() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let now = 1_800_000_000;

        let mut stale_claims = claims(now - 301, "hash");
        stale_claims["exp"] = serde_json::json!(now + 300);
        let stale = sign_jwt(&signing_key, stale_claims);
        assert!(
            verify_attestation_jwt(&stale, &jwks(&signing_key), &config(), "hash", now)
                .unwrap_err()
                .to_string()
                .contains("too old")
        );

        let future = sign_jwt(&signing_key, claims(now + CLOCK_SKEW_SECONDS + 1, "hash"));
        assert!(
            verify_attestation_jwt(&future, &jwks(&signing_key), &config(), "hash", now)
                .unwrap_err()
                .to_string()
                .contains("in the future")
        );
    }

    #[test]
    fn rejects_forged_signature() {
        let signer = SigningKey::generate(&mut OsRng);
        let trusted = SigningKey::generate(&mut OsRng);
        let now = 1_800_000_000;
        let jwt = sign_jwt(&signer, claims(now, "hash"));
        let err =
            verify_attestation_jwt(&jwt, &jwks(&trusted), &config(), "hash", now).unwrap_err();
        assert!(err.to_string().contains("signature verification failed"));
    }
}
