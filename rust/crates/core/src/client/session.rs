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
//! 2. Client creates a payment channel on-chain → gets channel_id + tx_sig
//! 3. Client calls SessionHandle::new() and sends open_header() on first request
//! 4. For each subsequent request: voucher_header(cost_per_request)
//! 5. When done: close_header() triggers on-chain settlement
//! ```

use std::sync::Arc;

use pay_kit::mpp::client::session::ActiveSession;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::{
    PaymentChallenge, PaymentCredential, SessionAction, SessionMode, SessionRequest,
    format_authorization, parse_www_authenticate,
};
use solana_pubkey::Pubkey;
use tokio::sync::Mutex;

use crate::{Error, Result};

// Re-export so callers can construct their own sessions without depending on
// pay_kit::mpp directly.
pub use pay_kit::mpp::client::session::ActiveSession as RawSession;

/// A live session: wraps an [`ActiveSession`] and the original challenge so
/// voucher authorization headers can be produced without re-parsing the
/// challenge on each call.
///
/// `SessionHandle` is `Clone` and `Send + Sync` — safe to share across async
/// tasks (e.g., a middleware that reuses the same channel for all in-flight
/// requests to the same server).
#[derive(Clone)]
pub struct SessionHandle {
    inner: Arc<Mutex<ActiveSession>>,
    /// Original challenge — echoed back in every `PaymentCredential`.
    challenge: PaymentChallenge,
    /// Delegated sessions bind the operator, rather than the local ephemeral
    /// voucher key, as the channel's on-chain authorized signer.
    authorized_signer_override: Option<Pubkey>,
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
        Self {
            inner: Arc::new(Mutex::new(ActiveSession::new(channel_id, signer))),
            challenge,
            authorized_signer_override: None,
        }
    }

    fn with_authorized_signer(mut self, authorized_signer: Pubkey) -> Self {
        self.authorized_signer_override = Some(authorized_signer);
        self
    }

    /// Build an `Authorization` header for the `open` action.
    ///
    /// Send this on the **first** request after the on-chain open transaction
    /// has been confirmed.
    ///
    /// * `deposit` — amount locked on-chain (base units, e.g. µUSDC)
    /// * `open_tx_signature` — base58 Solana transaction signature
    pub async fn open_header(&self, deposit: u64, open_tx_signature: &str) -> Result<String> {
        let session = self.inner.lock().await;
        let action = session.open_action(deposit, open_tx_signature);
        build_header(&self.challenge, &action)
    }

    /// Build an `Authorization` header carrying a voucher for `amount` base units.
    ///
    /// Increments the cumulative watermark by `amount`. Call this before every
    /// metered API request (after the initial open).
    pub async fn voucher_header(&self, amount: u64) -> Result<String> {
        let mut session = self.inner.lock().await;
        let action = session
            .voucher_action(amount)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to sign voucher: {e}")))?;
        build_header(&self.challenge, &action)
    }

    /// Build an `Authorization` header for cooperative channel close.
    ///
    /// `final_increment` optionally adds a last voucher for any outstanding
    /// balance before close. Pass `None` if the channel is already fully
    /// settled.
    pub async fn close_header(&self, final_increment: Option<u64>) -> Result<String> {
        let mut session = self.inner.lock().await;
        let action = session
            .close_action(final_increment)
            .await
            .map_err(|e| Error::Mpp(format!("Failed to build close action: {e}")))?;
        build_header(&self.challenge, &action)
    }

    /// Build an `Authorization` header for a payment-channel `open` action.
    ///
    /// `open_slot` is the channel's on-chain open slot — a channel-PDA seed
    /// since the epoch-addressed program update — and must match the slot the
    /// open transaction was built for (the challenge's `recentSlot`).
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
        self.open_payment_channel_header_with_mode(
            SessionMode::Push,
            deposit,
            payer,
            payee,
            mint,
            salt,
            grace_period,
            open_slot,
            transaction,
        )
        .await
    }

    /// Build an `Authorization` header for a payment-channel `open` action
    /// using an explicit submission mode.
    #[allow(clippy::too_many_arguments)]
    pub async fn open_payment_channel_header_with_mode(
        &self,
        mode: SessionMode,
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
        let SessionAction::Open(payload) = session.open_payment_channel_action_with_mode(
            mode,
            deposit,
            payer,
            payee,
            mint,
            salt,
            grace_period,
            open_slot,
            "pending",
        ) else {
            unreachable!("open_payment_channel_action always returns SessionAction::Open")
        };
        let mut payload = payload.with_transaction(transaction);
        if let Some(authorized_signer) = self.authorized_signer_override {
            payload.authorized_signer = authorized_signer.to_string();
        }
        build_header(&self.challenge, &SessionAction::Open(payload))
    }

    /// Build an `Authorization` header for a top-up after adding more funds
    /// on-chain.
    ///
    /// * `new_deposit` — new total deposit after the top-up (base units)
    /// * `topup_tx_signature` — base58 Solana transaction signature
    pub async fn topup_header(&self, new_deposit: u64, topup_tx_signature: &str) -> Result<String> {
        let session = self.inner.lock().await;
        let action = session.topup_action(new_deposit, topup_tx_signature);
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

// ── One-shot session pay ──────────────────────────────────────────────────────

/// Make a single API call through a session-gated endpoint.
///
/// Creates an ephemeral keypair, opens a session with the given `deposit`
/// (base units), sends the `open` action as the Authorization header, and
/// returns the `Authorization` header value to use for the retry.
///
/// The server currently trusts the deposit without on-chain verification,
/// so this works without a real payment channel for development/testing.
pub fn open_session_header(
    challenge: &PaymentChallenge,
    deposit: u64,
) -> Result<(SessionHandle, String)> {
    use ed25519_dalek::SigningKey;
    use pay_kit::mpp::solana_keychain::MemorySigner;
    use solana_pubkey::Pubkey;

    // Generate a fresh ephemeral session keypair.
    let sk = SigningKey::generate(&mut rand::thread_rng());
    let vk = sk.verifying_key();
    let mut kp = [0u8; 64];
    kp[..32].copy_from_slice(sk.as_bytes());
    kp[32..].copy_from_slice(vk.as_bytes());
    let signer: Box<dyn pay_kit::mpp::solana_keychain::SolanaSigner> =
        Box::new(MemorySigner::from_bytes(&kp).map_err(|e| Error::Mpp(e.to_string()))?);

    // Random channel ID — server stores it keyed by this string.
    let channel_id = Pubkey::new_unique();

    let handle = SessionHandle::new(channel_id, signer, challenge.clone());

    // Build the open header (fake tx sig — server trusts it for now).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to build runtime: {e}")))?;
    let auth_header = rt.block_on(handle.open_header(deposit, "demo_open_tx"))?;

    Ok((handle, auth_header))
}

/// Open a payment-channel push session with a payer-signed transaction.
///
/// The transaction is signed by the payer and fee-payer/cosigned by the server
/// when it processes the `open` action.
pub fn open_payment_channel_session_header(
    challenge: &PaymentChallenge,
    request: &pay_kit::mpp::SessionRequest,
    store: &dyn crate::accounts::AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    deposit: u64,
    sandbox: bool,
) -> Result<(SessionHandle, String)> {
    open_payment_channel_session_header_with_mode(
        challenge,
        request,
        store,
        network_override,
        account_override,
        deposit,
        pay_kit::mpp::SessionMode::Push,
        sandbox,
    )
}

/// Open a payment-channel session with an explicit submission mode.
#[allow(clippy::too_many_arguments)]
pub fn open_payment_channel_session_header_with_mode(
    challenge: &PaymentChallenge,
    request: &pay_kit::mpp::SessionRequest,
    store: &dyn crate::accounts::AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    deposit: u64,
    submission_mode: pay_kit::mpp::SessionMode,
    sandbox: bool,
) -> Result<(SessionHandle, String)> {
    use pay_kit::mpp::client::{
        BuildOpenPaymentChannelTransactionParams, DerivePaymentChannelOpenParams,
        PaymentChannelOpenOptions, build_open_payment_channel_transaction,
        derive_payment_channel_open,
    };
    use pay_kit::mpp::protocol::solana::default_rpc_url;
    use pay_kit::mpp::solana_keychain::MemorySigner;
    use solana_hash::Hash;
    use solana_pubkey::Pubkey;
    use std::str::FromStr;

    let network = network_override.map(str::to_string).unwrap_or_else(|| {
        request
            .network
            .clone()
            .unwrap_or_else(|| "mainnet".to_string())
    });
    let intent = crate::keystore::AuthIntent::open_session();
    let (signer, ephemeral_notice) = crate::signer::load_signer_for_network_with_intent(
        &network,
        store,
        account_override,
        &intent,
    )?;
    let payer = signer.pubkey();
    let rpc_url =
        std::env::var("PAY_RPC_URL").unwrap_or_else(|_| default_rpc_url(&network).to_string());

    let fee_payer = Pubkey::from_str(&request.operator)
        .map_err(|_| Error::Mpp(format!("invalid operator pubkey: {}", request.operator)))?;
    let salt = rand::random::<u64>();
    let grace_period = 900u32;
    let open_options = PaymentChannelOpenOptions {
        deposit: Some(deposit),
        grace_period: Some(grace_period),
        salt: Some(salt),
        ..PaymentChannelOpenOptions::default()
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create async runtime: {e}")))?;

    if sandbox && ephemeral_notice.is_some() {
        let pubkey = payer.to_string();
        let rpc = rpc_url.clone();
        if let Err(e) = rt.block_on(crate::client::sandbox::fund_via_surfpool(&rpc, &pubkey)) {
            tracing::warn!(error = %e, "Surfpool auto-fund failed — USDC balance may be 0");
        }
    }

    let recent_blockhash = if let Some(blockhash) = request.recent_blockhash.as_deref() {
        Hash::from_str(blockhash)
            .map_err(|e| Error::Mpp(format!("invalid recentBlockhash in challenge: {e}")))?
    } else {
        use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
        RpcClient::new(rpc_url.clone())
            .get_latest_blockhash()
            .map_err(|e| Error::Mpp(format!("failed to get recent blockhash: {e}")))?
    };

    let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let vk = sk.verifying_key();
    let mut kp_bytes = [0u8; 64];
    kp_bytes[..32].copy_from_slice(sk.as_bytes());
    kp_bytes[32..].copy_from_slice(vk.as_bytes());
    let session_signer: Box<dyn pay_kit::mpp::solana_keychain::SolanaSigner> =
        Box::new(MemorySigner::from_bytes(&kp_bytes).map_err(|e| Error::Mpp(e.to_string()))?);
    let authorized_signer = match request.settlement_authority {
        pay_kit::mpp::SessionSettlementAuthority::ClientVoucher => session_signer.pubkey(),
        pay_kit::mpp::SessionSettlementAuthority::Delegated => fee_payer,
        _ => {
            return Err(Error::Mpp(
                "unsupported MPP session settlement authority".to_string(),
            ));
        }
    };

    let open = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request,
        payer,
        authorized_signer,
        options: open_options.clone(),
    })
    .map_err(|e| Error::Mpp(format!("derive_payment_channel_open: {e}")))?;
    let payee = open.payee;
    let mint = open.mint;

    let open_tx = rt
        .block_on(build_open_payment_channel_transaction(
            BuildOpenPaymentChannelTransactionParams {
                request,
                signer: &signer,
                authorized_signer,
                fee_payer: Some(fee_payer),
                recent_blockhash,
                options: open_options,
            },
        ))
        .map_err(|e| Error::Mpp(format!("build_open_payment_channel_transaction: {e}")))?;

    let handle = SessionHandle::new(open_tx.channel_id, session_signer, challenge.clone())
        .with_authorized_signer(authorized_signer);
    let auth_header = rt.block_on(handle.open_payment_channel_header_with_mode(
        submission_mode.clone(),
        deposit,
        &payer.to_string(),
        &payee.to_string(),
        &mint.to_string(),
        salt,
        grace_period,
        // The open slot is a channel-PDA seed since the epoch-addressed
        // program update; use the same slot the open transaction was derived
        // for (challenge `recentSlot`, resolved inside
        // `derive_payment_channel_open`) so the server re-derives the same PDA.
        open.open_slot,
        open_tx.transaction,
    ))?;

    tracing::debug!(
        payer = %payer,
        channel = %open_tx.channel_id,
        deposit,
        mode = ?submission_mode,
        "payment-channel session authorization header ready"
    );

    Ok((handle, auth_header))
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

fn build_header(challenge: &PaymentChallenge, action: &SessionAction) -> Result<String> {
    let credential = PaymentCredential::new(challenge.to_echo(), action);
    format_authorization(&credential)
        .map_err(|e| Error::Mpp(format!("Failed to format authorization header: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_kit::mpp::{
        Base64UrlJson, SessionMode, SessionPullVoucherStrategy, SessionSplit, parse_authorization,
    };

    fn test_request() -> SessionRequest {
        SessionRequest {
            cap: "1000000".to_string(),
            currency: solana_pubkey::Pubkey::new_unique().to_string(),
            decimals: Some(6),
            network: Some("localnet".to_string()),
            operator: solana_pubkey::Pubkey::new_unique().to_string(),
            recipient: solana_pubkey::Pubkey::new_unique().to_string(),
            splits: vec![SessionSplit {
                recipient: solana_pubkey::Pubkey::new_unique().to_string(),
                bps: 100,
            }],
            program_id: Some(solana_pubkey::Pubkey::new_unique().to_string()),
            description: Some("test session".to_string()),
            external_id: Some("ext-123".to_string()),
            min_voucher_delta: Some("25".to_string()),
            settlement_authority: pay_kit::mpp::SessionSettlementAuthority::ClientVoucher,
            modes: vec![SessionMode::Push, SessionMode::Pull],
            pull_voucher_strategy: Some(SessionPullVoucherStrategy::ClientVoucher),
            recent_blockhash: None,
            recent_slot: None,
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

    fn test_signer() -> Box<dyn SolanaSigner> {
        use ed25519_dalek::SigningKey;
        use pay_kit::mpp::solana_keychain::MemorySigner;

        let sk = SigningKey::generate(&mut rand::thread_rng());
        let vk = sk.verifying_key();
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(sk.as_bytes());
        kp[32..].copy_from_slice(vk.as_bytes());
        Box::new(MemorySigner::from_bytes(&kp).unwrap())
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
        assert_eq!(request.cap, "1000000");

        let non_session = test_challenge("charge").to_header().unwrap();
        assert!(SessionHandle::parse_challenge(&non_session).is_none());
        assert!(SessionHandle::parse_challenge("not a challenge").is_none());
    }

    #[tokio::test]
    async fn session_handle_builds_expected_headers() {
        let channel_id = Pubkey::new_unique();
        let channel_id_str = channel_id.to_string();
        let challenge = test_challenge("session");
        let handle = SessionHandle::new(channel_id, test_signer(), challenge.clone());

        let open = parse_action(&handle.open_header(1_000_000, "open_sig").await.unwrap());
        match open {
            SessionAction::Open(payload) => {
                assert_eq!(payload.mode, SessionMode::Push);
                assert_eq!(payload.channel_id.as_deref(), Some(channel_id_str.as_str()));
                assert_eq!(payload.deposit.as_deref(), Some("1000000"));
                assert_eq!(payload.signature, "open_sig");
            }
            _ => panic!("expected open action"),
        }

        let voucher = parse_action(&handle.voucher_header(125).await.unwrap());
        match voucher {
            SessionAction::Voucher(payload) => {
                assert_eq!(payload.voucher.data.channel_id, channel_id_str);
                assert_eq!(payload.voucher.data.cumulative, "125");
            }
            _ => panic!("expected voucher action"),
        }
        assert_eq!(handle.cumulative().await, 125);
        assert_eq!(handle.channel_id().await, channel_id.to_string());
        assert_eq!(handle.challenge().intent, challenge.intent);

        let topup = parse_action(&handle.topup_header(2_000_000, "topup_sig").await.unwrap());
        match topup {
            SessionAction::TopUp(payload) => {
                assert_eq!(payload.channel_id, channel_id.to_string());
                assert_eq!(payload.new_deposit, "2000000");
                assert_eq!(payload.signature, "topup_sig");
            }
            _ => panic!("expected topup action"),
        }

        let close = parse_action(&handle.close_header(Some(25)).await.unwrap());
        match close {
            SessionAction::Close(payload) => {
                let voucher = payload.voucher.expect("final voucher");
                assert_eq!(voucher.data.cumulative, "150");
            }
            _ => panic!("expected close action"),
        }
    }

    #[tokio::test]
    async fn delegated_open_uses_operator_as_authorized_signer() {
        let operator = Pubkey::new_unique();
        let handle = SessionHandle::new(
            Pubkey::new_unique(),
            test_signer(),
            test_challenge("session"),
        )
        .with_authorized_signer(operator);
        let header = handle
            .open_payment_channel_header_with_mode(
                SessionMode::Push,
                1_000_000,
                &Pubkey::new_unique().to_string(),
                &Pubkey::new_unique().to_string(),
                &Pubkey::new_unique().to_string(),
                7,
                900,
                42,
                "transaction".to_string(),
            )
            .await
            .unwrap();

        let SessionAction::Open(payload) = parse_action(&header) else {
            panic!("expected open action");
        };
        assert_eq!(payload.authorized_signer, operator.to_string());
    }

    #[test]
    fn open_session_header_returns_parseable_header() {
        let challenge = test_challenge("session");
        let (handle, header) = open_session_header(&challenge, 1_000_000).unwrap();
        let action = parse_action(&header);
        match action {
            SessionAction::Open(payload) => {
                assert_eq!(payload.mode, SessionMode::Push);
                assert_eq!(payload.deposit.as_deref(), Some("1000000"));
            }
            _ => panic!("expected open action"),
        }
        let parsed = SessionHandle::parse_challenge(&challenge.to_header().unwrap()).unwrap();
        assert_eq!(parsed.0.intent, handle.challenge().intent);
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
                assert_eq!(payload.voucher.data.cumulative, "42");
            }
            _ => panic!("expected voucher action"),
        }
    }
}
