//! Session intent client — open channels, sign vouchers, close.
//!
//! A session keeps a pre-funded on-chain payment channel open across many API
//! calls. Each call consumes a small voucher increment instead of a full
//! on-chain transaction, making high-frequency AI workloads cheap.
//!
//! # Lifecycle
//!
//! ```text
//! 1. Server returns 402 with session challenge (intent="session")
//! 2. Client builds a challenge-bound open transaction and sends the `open`
//!    action; the server verifies, broadcasts, and confirms it
//! 3. Client-signed channels send voucher_header(cost) per request;
//!    operator-signed channels send use_header() and the operator meters
//! 4. When done: close_header() triggers on-chain settlement
//! ```

use std::sync::Arc;

use pay_kit::mpp::client::session::ActiveSession;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::{
    ClosePayload, PaymentChallenge, PaymentCredential, SessionAction, SessionAuthentication,
    SessionAuthenticationType, SessionRequest, SessionVoucherSigner, SignedVoucher, UsePayload,
    VoucherData, VoucherSignatureType, format_authorization, parse_www_authenticate,
};
use solana_pubkey::Pubkey;
use tokio::sync::Mutex;

use crate::{Error, Result};

// Re-export so callers can construct their own sessions without depending on
// pay_kit::mpp directly.
pub use pay_kit::mpp::client::session::ActiveSession as RawSession;

/// A live session: wraps an [`ActiveSession`] and the original challenge so
/// authorization headers can be produced without re-parsing the challenge on
/// each call.
///
/// `SessionHandle` is `Clone` and `Send + Sync` — safe to share across async
/// tasks (e.g., a middleware that reuses the same channel for all in-flight
/// requests to the same server).
#[derive(Clone)]
pub struct SessionHandle {
    inner: Arc<Mutex<ActiveSession>>,
    /// Original challenge — echoed back in every `PaymentCredential`.
    challenge: PaymentChallenge,
    /// Reusable payer proof bound at open. Present for operator-signed
    /// channels, where it authenticates `use` and `close` actions.
    authentication: Option<SessionAuthentication>,
    /// Client-mode ephemeral voucher key. Kept so `close_header` can sign an
    /// equal-watermark voucher (close authentication without advancing
    /// settlement) — [`ActiveSession`] only signs strictly increasing ones.
    voucher_key: Option<ed25519_dalek::SigningKey>,
}

impl SessionHandle {
    /// Try to parse a session challenge from a `WWW-Authenticate` header value.
    ///
    /// Returns `None` if the header is absent, uses a different scheme, or
    /// carries a non-session intent.
    pub fn parse_challenge(header: &str) -> Option<(PaymentChallenge, SessionRequest)> {
        let challenge = parse_www_authenticate(header).ok()?;
        if challenge.intent.as_str() != "session" {
            return None;
        }
        let request: SessionRequest = challenge.request.decode().ok()?;
        Some((challenge, request))
    }

    /// Create a handle wrapping an already-opened channel.
    ///
    /// `channel_id` is the on-chain payment-channel public key — obtained after
    /// broadcasting and confirming the open transaction.
    /// `signer` is the session key whose public key was passed as
    /// `authorized_signer` in the open transaction.
    pub fn new(
        channel_id: Pubkey,
        signer: Box<dyn SolanaSigner>,
        challenge: PaymentChallenge,
    ) -> Self {
        Self::from_active(ActiveSession::new(channel_id, signer), challenge)
    }

    /// Wrap an existing [`ActiveSession`] (e.g. one produced by the PayKit
    /// session opener).
    pub fn from_active(session: ActiveSession, challenge: PaymentChallenge) -> Self {
        Self {
            inner: Arc::new(Mutex::new(session)),
            challenge,
            authentication: None,
            voucher_key: None,
        }
    }

    /// Attach the reusable payer proof bound at open (operator-signed mode).
    pub fn with_authentication(mut self, authentication: SessionAuthentication) -> Self {
        self.authentication = Some(authentication);
        self
    }

    /// Retain the client-mode ephemeral voucher key so `close_header` can
    /// authenticate a close without advancing settlement.
    pub fn with_voucher_key(mut self, key: ed25519_dalek::SigningKey) -> Self {
        self.voucher_key = Some(key);
        self
    }

    /// Build an `Authorization` header carrying a voucher for `amount` base units.
    ///
    /// Increments the cumulative watermark by `amount`. Call this before every
    /// metered API request on a client-signed channel.
    pub async fn voucher_header(&self, amount: u64) -> Result<String> {
        let mut session = self.inner.lock().await;
        let action = session
            .voucher_action(amount)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to sign voucher: {e}")))?;
        build_header(&self.challenge, &action)
    }

    /// Build an `Authorization` header for a metered request on an
    /// operator-signed channel, presenting the reusable payer proof.
    pub async fn use_header(&self) -> Result<String> {
        let authentication = self.authentication.clone().ok_or_else(|| {
            Error::Mpp("use requires the payer proof bound at open (operator mode)".to_string())
        })?;
        let session = self.inner.lock().await;
        let action = SessionAction::Use(UsePayload {
            channel_id: session.channel_id_str(),
            authentication,
        });
        build_header(&self.challenge, &action)
    }

    /// Build an `Authorization` header for cooperative channel close.
    ///
    /// Operator-signed channels authenticate with the bound payer proof and
    /// never carry a voucher. Client-signed channels must always authenticate
    /// with a final voucher: `final_increment` adds any outstanding balance,
    /// while `None` (or zero) re-signs the current watermark, which
    /// authenticates the close without advancing settlement.
    pub async fn close_header(&self, final_increment: Option<u64>) -> Result<String> {
        let mut session = self.inner.lock().await;
        if let Some(authentication) = self.authentication.clone() {
            let action = SessionAction::Close(ClosePayload {
                channel_id: session.channel_id_str(),
                authentication: Some(authentication),
                voucher: None,
            });
            return build_header(&self.challenge, &action);
        }
        let action = match final_increment {
            Some(increment) if increment > 0 => session
                .close_action(Some(increment))
                .await
                .map_err(|e| Error::Mpp(format!("Failed to build close action: {e}")))?,
            _ => SessionAction::Close(ClosePayload {
                channel_id: session.channel_id_str(),
                authentication: None,
                voucher: Some(self.watermark_voucher(&session)?),
            }),
        };
        build_header(&self.challenge, &action)
    }

    /// Sign a voucher at the session's current cumulative watermark.
    fn watermark_voucher(&self, session: &ActiveSession) -> Result<SignedVoucher> {
        use ed25519_dalek::Signer;

        let key = self.voucher_key.as_ref().ok_or_else(|| {
            Error::Mpp(
                "close without a final increment requires the session voucher key".to_string(),
            )
        })?;
        let data = VoucherData {
            channel_id: session.channel_id_str(),
            cumulative_amount: session.cumulative.to_string(),
            expires_at: Some(pay_kit::mpp::DEFAULT_SESSION_EXPIRES_AT),
        };
        let message = data
            .message_bytes()
            .map_err(|e| Error::Mpp(format!("Failed to encode close voucher: {e}")))?;
        let signature = crate::b58::encode_64(&key.sign(&message).to_bytes());
        Ok(SignedVoucher {
            data,
            signer: session.authorized_signer(),
            signature,
            signature_type: VoucherSignatureType::Ed25519,
        })
    }

    /// Build an `Authorization` header for a payment-channel `open` action.
    ///
    /// `open_slot` must come from the challenge's `recentSlot` and
    /// `transaction` must be the base64 open transaction built against the
    /// challenge's `recentBlockhash` — the server rejects anything else.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_payment_channel_header(
        &self,
        deposit: u64,
        payer: &str,
        payee: &str,
        mint: &str,
        salt: u64,
        grace_period: u32,
        open_slot: u64,
        transaction: String,
    ) -> Result<String> {
        let session = self.inner.lock().await;
        let SessionAction::Open(mut payload) = session.open_payment_channel_action(
            deposit,
            payer,
            payee,
            mint,
            salt,
            grace_period,
            open_slot,
            &transaction,
        ) else {
            unreachable!("open_payment_channel_action always returns SessionAction::Open")
        };
        payload.authentication = self.authentication.clone();
        build_header(&self.challenge, &SessionAction::Open(payload))
    }

    /// Build an `Authorization` header for a top-up after adding more funds
    /// on-chain.
    ///
    /// * `additional_amount` — amount added to the deposit (base units)
    /// * `transaction` — base64 signed top-up transaction
    pub async fn topup_header(&self, additional_amount: u64, transaction: &str) -> Result<String> {
        let session = self.inner.lock().await;
        let action = session.topup_action(additional_amount, transaction);
        build_header(&self.challenge, &action)
    }

    /// Current cumulative amount authorized so far (base units).
    pub async fn cumulative(&self) -> u64 {
        self.inner.lock().await.cumulative
    }

    /// Channel ID as base58 (matches what was registered with the server).
    pub async fn channel_id(&self) -> String {
        self.inner.lock().await.channel_id_str()
    }

    /// The original server challenge — useful for logging or re-use.
    pub fn challenge(&self) -> &PaymentChallenge {
        &self.challenge
    }
}

// ── Session open ─────────────────────────────────────────────────────────────

/// Open a payment-channel session from a 402 challenge.
///
/// Builds the open transaction against the challenge's `recentBlockhash` and
/// `recentSlot`, prompts for spend authorization, and returns the handle plus
/// the `Authorization` header for the retry. For operator-signed challenges
/// (`voucherSigner: "operator"`) the payer also signs the reusable session
/// proof bound to the opening challenge and derived channel.
#[allow(clippy::too_many_arguments)]
pub fn open_payment_channel_session_header(
    challenge: &PaymentChallenge,
    request: &SessionRequest,
    store: &dyn crate::accounts::AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    deposit: u64,
    resource_url: &str,
    sandbox: bool,
) -> Result<(SessionHandle, String)> {
    open_payment_channel_session_header_with_override(
        challenge,
        request,
        store,
        network_override,
        account_override,
        deposit,
        resource_url,
        sandbox,
        None,
    )
}

/// Variant of [`open_payment_channel_session_header`] that lets an MCP host
/// route the wallet approval through its own authenticated approval surface.
#[allow(clippy::too_many_arguments)]
pub fn open_payment_channel_session_header_with_override(
    challenge: &PaymentChallenge,
    request: &SessionRequest,
    store: &dyn crate::accounts::AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    deposit: u64,
    resource_url: &str,
    sandbox: bool,
    auth_override: crate::signer::AuthOverride,
) -> Result<(SessionHandle, String)> {
    use pay_kit::mpp::client::{
        DerivePaymentChannelOpenParams, PaymentChannelOpenOptions,
        PaymentChannelSessionOpenOptions, create_payment_channel_session_opener,
        derive_payment_channel_open,
    };
    use pay_kit::mpp::protocol::solana::default_rpc_url;
    use pay_kit::mpp::solana_keychain::MemorySigner;

    let details = &request.method_details;
    let network = network_override
        .map(str::to_string)
        .unwrap_or_else(|| details.network.clone());
    canonical_session_origin(resource_url)?;
    let prompt_context = crate::client::prompt::payment_prompt_context(None, &[Some(resource_url)]);
    let limit = session_spend_limit(deposit, request);
    let intent = crate::keystore::AuthIntent::authorize_spend_up_to(
        limit.usd_amount.as_deref(),
        &limit.display,
        &prompt_context.operator,
    );
    let (signer, ephemeral_notice) =
        crate::signer::load_signer_for_network_with_intent_and_override(
            &network,
            store,
            account_override,
            &intent,
            auth_override,
        )?;
    let payer = signer.pubkey();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create async runtime: {e}")))?;

    if sandbox && ephemeral_notice.is_some() {
        let pubkey = payer.to_string();
        let rpc =
            std::env::var("PAY_RPC_URL").unwrap_or_else(|_| default_rpc_url(&network).to_string());
        if let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(&rpc, &pubkey)) {
            tracing::warn!(error = %e, "Surfpool auto-fund failed — USDC balance may be 0");
        }
    }

    // Fresh ephemeral session keypair — the voucher signer for client-signed
    // channels; unused for signing in operator mode but still generated so the
    // handle can be constructed uniformly.
    let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let vk = sk.verifying_key();
    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(sk.as_bytes());
    kp_bytes[32..].copy_from_slice(vk.as_bytes());
    let session_signer: Box<dyn pay_kit::mpp::solana_keychain::SolanaSigner> =
        Box::new(MemorySigner::from_bytes(&kp_bytes).map_err(|e| Error::Mpp(e.to_string()))?);

    let voucher_signer = details
        .voucher_signer
        .unwrap_or(SessionVoucherSigner::Client);
    let authorized_signer = match voucher_signer {
        SessionVoucherSigner::Client => session_signer.pubkey(),
        SessionVoucherSigner::Operator => {
            let operator = details.operator.as_deref().ok_or_else(|| {
                Error::Mpp("operator-signed session challenge is missing operator".to_string())
            })?;
            std::str::FromStr::from_str(operator)
                .map_err(|_| Error::Mpp(format!("invalid session operator: {operator}")))?
        }
        _ => {
            return Err(Error::Mpp(
                "unsupported MPP session voucher signer".to_string(),
            ));
        }
    };

    let salt = rand::random::<u64>();
    let open_options = PaymentChannelOpenOptions {
        deposit: Some(deposit),
        salt: Some(salt),
        ..PaymentChannelOpenOptions::default()
    };

    // Derive the channel address up front: the operator-mode proof signs over
    // (challengeId, channelId) and must exist before the opener builds the
    // payload. The opener below re-derives the same channel from the same
    // salt/deposit/challenge inputs.
    let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request,
        payer,
        authorized_signer,
        options: open_options.clone(),
    })
    .map_err(|e| Error::Mpp(format!("derive_payment_channel_open: {e}")))?;

    let authentication = if voucher_signer == SessionVoucherSigner::Operator {
        let mut proof = SessionAuthentication {
            kind: SessionAuthenticationType::Proof,
            challenge_id: challenge.id.clone(),
            payer: payer.to_string(),
            signature: String::new(),
        };
        let message = proof
            .message_bytes(&open.channel_id.to_string())
            .map_err(|e| Error::Mpp(format!("failed to encode session proof: {e}")))?;
        let signature = rt
            .block_on(signer.sign_message(&message))
            .map_err(|e| Error::Mpp(format!("failed to sign session proof: {e}")))?;
        proof.signature = crate::b58::encode_64(&<[u8; 64]>::from(signature));
        Some(proof)
    } else {
        None
    };

    let opened = rt
        .block_on(create_payment_channel_session_opener(
            request,
            &signer,
            session_signer,
            None,
            PaymentChannelSessionOpenOptions {
                open: open_options,
                cumulative: None,
                expires_at: None,
                authentication: authentication.clone(),
                idle_timeout_seconds: None,
            },
        ))
        .map_err(|e| Error::Mpp(format!("create_payment_channel_session_opener: {e}")))?;
    debug_assert_eq!(opened.open.channel_id, open.channel_id);

    let auth_header = build_header(challenge, &opened.action)?;
    let mut handle = SessionHandle::from_active(opened.session, challenge.clone());
    handle = match authentication {
        Some(authentication) => handle.with_authentication(authentication),
        None => handle.with_voucher_key(sk),
    };

    tracing::debug!(
        payer = %payer,
        channel = %open.channel_id,
        deposit,
        voucher_signer = ?voucher_signer,
        "payment-channel session authorization header ready"
    );

    Ok((handle, auth_header))
}

/// Open an operator-metered MPP payment-channel session and return its first
/// `open` authorization plus the reusable `use` authorization.
///
/// Agent runtimes use this form because the operator, rather than the client,
/// meters each response. Client-voucher sessions require the caller to advance
/// a voucher by the delivered usage on every request.
pub fn open_operator_signed_session_authorizations(
    challenge: &PaymentChallenge,
    store: &dyn crate::accounts::AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: &str,
    auth_override: crate::signer::AuthOverride,
) -> Result<(String, String)> {
    let request: SessionRequest = challenge
        .request
        .decode()
        .map_err(|error| Error::Mpp(format!("invalid MPP session challenge: {error}")))?;
    if request.method_details.voucher_signer != Some(SessionVoucherSigner::Operator) {
        return Err(Error::Mpp(
            "agent payer requires an operator-signed MPP session".to_string(),
        ));
    }
    if let Some(forced) = network_override
        && forced != request.method_details.network
    {
        return Err(Error::Mpp(format!(
            "MPP session network mismatch: payer requires `{forced}`, gateway offered `{}`",
            request.method_details.network
        )));
    }

    let minimum = request
        .minimum_deposit
        .as_deref()
        .map(parse_session_deposit)
        .transpose()?
        .unwrap_or(0);
    let deposit = request
        .suggested_deposit
        .as_deref()
        .map(parse_session_deposit)
        .transpose()?
        .unwrap_or(1_000_000)
        .max(minimum)
        .max(1);
    let sandbox = network_override == Some("localnet");
    let (handle, open_authorization) = open_payment_channel_session_header_with_override(
        challenge,
        &request,
        store,
        network_override,
        account_override,
        deposit,
        resource_url,
        sandbox,
        auth_override,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Error::Mpp(format!("Failed to build runtime: {error}")))?;
    let use_authorization = runtime.block_on(handle.use_header())?;
    Ok((open_authorization, use_authorization))
}

fn parse_session_deposit(value: &str) -> Result<u64> {
    value.parse::<u64>().map_err(|_| {
        Error::Mpp(format!(
            "MPP session challenge advertised a non-numeric deposit: {value}"
        ))
    })
}

/// Build a voucher header for a subsequent call on an open session.
pub fn voucher_header_sync(handle: &SessionHandle, amount: u64) -> Result<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to build runtime: {e}")))?;
    rt.block_on(handle.voucher_header(amount))
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Normalize an HTTP(S) resource URL to the origin used to scope a session.
/// Credentials and paths are deliberately excluded so one session cannot be
/// keyed by an unsafe or overly-specific URL representation.
pub fn canonical_session_origin(resource_url: &str) -> Result<String> {
    let url = reqwest::Url::parse(resource_url)
        .map_err(|e| Error::Mpp(format!("invalid session authorization URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(Error::Mpp(
            "session authorization URL must be an absolute HTTP(S) URL".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Mpp(
            "session authorization URL must not contain credentials".to_string(),
        ));
    }
    Ok(url.origin().ascii_serialization())
}

struct SessionSpendLimit {
    display: String,
    usd_amount: Option<String>,
}

fn session_spend_limit(deposit: u64, request: &SessionRequest) -> SessionSpendLimit {
    let stablecoin = pay_types::Stablecoin::from_mint(&request.currency)
        .or_else(|| pay_types::Stablecoin::parse_symbol(&request.currency));

    if let Some(stablecoin) = stablecoin {
        let amount = crate::client::send::format_token_amount(deposit, stablecoin.decimals());
        let usd = if !amount.contains('.') {
            format!("{amount}.00")
        } else if amount
            .split_once('.')
            .is_some_and(|(_, fraction)| fraction.len() == 1)
        {
            format!("{amount}0")
        } else {
            amount.clone()
        };
        let usd_amount = format!("${usd}");
        SessionSpendLimit {
            display: usd_amount.clone(),
            usd_amount: Some(usd_amount),
        }
    } else {
        SessionSpendLimit {
            display: format!("{deposit} base units of {}", request.currency),
            usd_amount: None,
        }
    }
}

fn build_header(challenge: &PaymentChallenge, action: &SessionAction) -> Result<String> {
    let credential = PaymentCredential::new(challenge.to_echo(), action);
    format_authorization(&credential)
        .map_err(|e| Error::Mpp(format!("Failed to format authorization header: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_kit::mpp::{Base64UrlJson, SessionMethodDetails, SessionSplit, parse_authorization};

    fn test_request() -> SessionRequest {
        SessionRequest {
            amount: "25".to_string(),
            currency: solana_pubkey::Pubkey::new_unique().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            description: Some("test session".to_string()),
            external_id: Some("ext-123".to_string()),
            minimum_deposit: Some("100".to_string()),
            suggested_deposit: Some("1000000".to_string()),
            unit_type: Some("request".to_string()),
            method_details: SessionMethodDetails {
                network: "localnet".to_string(),
                channel_program: solana_pubkey::Pubkey::new_unique().to_string(),
                channel_id: None,
                recent_blockhash: Some(solana_hash::Hash::new_unique().to_string()),
                recent_slot: Some(314),
                decimals: Some(6),
                token_program: None,
                fee_payer: None,
                fee_payer_key: None,
                voucher_signer: Some(SessionVoucherSigner::Client),
                operator: None,
                min_voucher_delta: Some("25".to_string()),
                ttl_seconds: None,
                idle_timeout_options_seconds: None,
                idle_timeout_seconds: None,
                grace_period_seconds: Some(900),
                distribution_splits: vec![SessionSplit {
                    recipient: solana_pubkey::Pubkey::new_unique().to_string(),
                    share_bps: 100,
                }],
            },
        }
    }

    fn test_challenge(intent: &str) -> PaymentChallenge {
        let request = Base64UrlJson::from_typed(&test_request()).unwrap();
        PaymentChallenge::with_challenge_binding_secret(
            "test-secret",
            "test-realm",
            "solana",
            intent,
            request,
        )
    }

    fn test_keypair() -> (ed25519_dalek::SigningKey, Box<dyn SolanaSigner>) {
        use ed25519_dalek::SigningKey;
        use pay_kit::mpp::solana_keychain::MemorySigner;

        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        (sk.clone(), Box::new(MemorySigner::from_bytes(&kp).unwrap()))
    }

    fn test_signer() -> Box<dyn SolanaSigner> {
        test_keypair().1
    }

    fn parse_action(header: &str) -> SessionAction {
        let credential = parse_authorization(header).expect("parse authorization");
        serde_json::from_value(credential.payload).expect("decode session action")
    }

    #[test]
    fn parse_challenge_only_accepts_session_headers() {
        let challenge = test_challenge("session");
        let header = challenge.to_header().unwrap();

        let Some((parsed_challenge, request)) = SessionHandle::parse_challenge(&header) else {
            panic!("expected a session challenge");
        };
        assert_eq!(parsed_challenge.intent.as_str(), "session");
        assert_eq!(request.suggested_deposit.as_deref(), Some("1000000"));

        let non_session = test_challenge("charge").to_header().unwrap();
        assert!(SessionHandle::parse_challenge(&non_session).is_none());
        assert!(SessionHandle::parse_challenge("not a challenge").is_none());
    }

    #[test]
    fn canonical_origin_normalizes_paths_case_and_default_ports() {
        assert_eq!(
            canonical_session_origin("HTTPS://Example.COM:443/v1/chat?model=test").unwrap(),
            "https://example.com"
        );
        assert_eq!(
            canonical_session_origin("http://localhost:1402/v1/chat").unwrap(),
            "http://localhost:1402"
        );
    }

    #[test]
    fn canonical_origin_rejects_relative_non_http_and_credential_urls() {
        for invalid in [
            "/v1/chat",
            "file:///tmp/provider",
            "https://user:secret@example.com/v1/chat",
        ] {
            assert!(
                canonical_session_origin(invalid).is_err(),
                "accepted invalid session URL: {invalid}"
            );
        }
    }

    #[test]
    fn spend_limit_displays_usd_amount() {
        let mut request = test_request();
        request.currency = "USDC".to_string();
        let limit = session_spend_limit(1_000_000, &request);
        assert_eq!(limit.display, "$1.00");
        assert_eq!(limit.usd_amount.as_deref(), Some("$1.00"));
    }

    #[test]
    fn spend_limit_does_not_trust_unknown_asset_decimals() {
        let request = test_request();

        let limit = session_spend_limit(1_000_000, &request);

        assert_eq!(
            limit.display,
            format!("1000000 base units of {}", request.currency)
        );
        assert_eq!(limit.usd_amount, None);
    }

    #[tokio::test]
    async fn session_handle_builds_expected_headers() {
        let channel_id = Pubkey::new_unique();
        let channel_id_str = channel_id.to_string();
        let challenge = test_challenge("session");
        let (voucher_key, signer) = test_keypair();
        let handle =
            SessionHandle::new(channel_id, signer, challenge.clone()).with_voucher_key(voucher_key);

        let open = parse_action(
            &handle
                .open_payment_channel_header(
                    1_000_000,
                    &Pubkey::new_unique().to_string(),
                    &Pubkey::new_unique().to_string(),
                    &Pubkey::new_unique().to_string(),
                    7,
                    900,
                    314,
                    "AQAB".to_string(),
                )
                .await
                .unwrap(),
        );
        match open {
            SessionAction::Open(payload) => {
                assert_eq!(payload.channel_id, channel_id_str);
                assert_eq!(payload.deposit_amount, "1000000");
                assert_eq!(payload.open_slot, 314);
                assert_eq!(payload.transaction, "AQAB");
                assert!(payload.authentication.is_none());
            }
            _ => panic!("expected open action"),
        }

        let voucher = parse_action(&handle.voucher_header(125).await.unwrap());
        match voucher {
            SessionAction::Voucher(payload) => {
                assert_eq!(payload.voucher.data.channel_id, channel_id_str);
                assert_eq!(payload.voucher.data.cumulative_amount, "125");
            }
            _ => panic!("expected voucher action"),
        }
        assert_eq!(handle.cumulative().await, 125);
        assert_eq!(handle.channel_id().await, channel_id.to_string());
        assert_eq!(handle.challenge().intent, challenge.intent);

        let topup = parse_action(&handle.topup_header(2_000_000, "AQAB").await.unwrap());
        match topup {
            SessionAction::TopUp(payload) => {
                assert_eq!(payload.channel_id, channel_id.to_string());
                assert_eq!(payload.additional_amount, "2000000");
                assert_eq!(payload.transaction, "AQAB");
            }
            _ => panic!("expected topup action"),
        }

        let close = parse_action(&handle.close_header(Some(25)).await.unwrap());
        match close {
            SessionAction::Close(payload) => {
                let voucher = payload.voucher.expect("final voucher");
                assert_eq!(voucher.data.cumulative_amount, "150");
            }
            _ => panic!("expected close action"),
        }
    }

    #[tokio::test]
    async fn client_close_without_increment_signs_watermark_voucher() {
        let channel_id = Pubkey::new_unique();
        let challenge = test_challenge("session");
        let (voucher_key, signer) = test_keypair();
        let handle =
            SessionHandle::new(channel_id, signer, challenge).with_voucher_key(voucher_key);
        handle.voucher_header(100).await.unwrap();

        let close = parse_action(&handle.close_header(None).await.unwrap());
        let SessionAction::Close(payload) = close else {
            panic!("expected close action");
        };
        assert!(payload.authentication.is_none());
        let voucher = payload.voucher.expect("watermark voucher");
        assert_eq!(voucher.data.cumulative_amount, "100");
    }

    #[tokio::test]
    async fn operator_session_uses_bound_proof_for_use_and_close() {
        let channel_id = Pubkey::new_unique();
        let challenge = test_challenge("session");
        let payer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let proof =
            SessionAuthentication::sign(challenge.id.clone(), &channel_id.to_string(), &payer)
                .unwrap();
        let handle = SessionHandle::new(channel_id, test_signer(), challenge)
            .with_authentication(proof.clone());

        let SessionAction::Use(payload) = parse_action(&handle.use_header().await.unwrap()) else {
            panic!("expected use action");
        };
        assert_eq!(payload.channel_id, channel_id.to_string());
        assert_eq!(payload.authentication, proof);

        let SessionAction::Close(payload) = parse_action(&handle.close_header(None).await.unwrap())
        else {
            panic!("expected close action");
        };
        assert!(payload.voucher.is_none());
        assert_eq!(payload.authentication, Some(proof));
    }

    #[test]
    fn voucher_header_sync_matches_async_builder() {
        let handle = SessionHandle::new(
            Pubkey::new_unique(),
            test_signer(),
            test_challenge("session"),
        );
        let sync = voucher_header_sync(&handle, 42).unwrap();
        let action = parse_action(&sync);
        match action {
            SessionAction::Voucher(payload) => {
                assert_eq!(payload.voucher.data.cumulative_amount, "42");
            }
            _ => panic!("expected voucher action"),
        }
    }
}
