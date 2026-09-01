//! Server-side support for the MPP `subscription` intent.
//!
//! Bridges between pay's developer-facing endpoint config
//! (`pay_types::metering::SubscriptionEndpoint`) and the SDK's
//! `pay_kit::mpp::server::SubscriptionServer`.
//!
//! Covers challenge emission and activation-credential verification through
//! pay-kit's Rust subscription server.

use std::str::FromStr;

use pay_kit::mpp::SubscriptionPeriodUnit;
use pay_kit::mpp::server::{SubscriptionConfig as SdkSubscriptionConfig, SubscriptionServer};
#[allow(unused_imports)]
use solana_pubkey::Pubkey;

use crate::{Error, Result};
use pay_types::metering::{SubscriptionEndpoint, SubscriptionPeriodUnit as TypesPeriodUnit};

/// Server-side defaults pulled from the API spec's `operator` block. Each
/// subscription endpoint inherits these unless it overrides them.
///
/// Not `Debug` because `fee_payer_signer` is a trait object that doesn't
/// implement `Debug`. Callers that need to log the operator config
/// should print the individual fields.
#[derive(Clone)]
pub struct OperatorDefaults<'a> {
    /// Operator wallet pubkey (b58). Used as the puller and Plan owner.
    pub puller: &'a str,
    /// Default recipient if the endpoint doesn't specify one.
    pub recipient: &'a str,
    /// Network slug.
    pub network: &'a str,
    /// Resolved RPC URL the server uses for on-chain reads
    /// (`getLatestBlockhash`, `getAccountInfo`, `sendTransaction`).
    /// Threaded through to the SDK so its per-request blockhash
    /// pre-fetch hits the configured Helius / Surfnet endpoint rather
    /// than the SDK's fallback to `localhost:8899`.
    pub rpc_url: &'a str,
    /// HMAC secret shared by the subscription + authenticate handlers
    /// to bind each challenge to its server. Sourced from
    /// `operator.challenge_binding_secret` in the server YAML;
    /// required when subscription endpoints are present (`pay server
    /// start` rejects the config at boot otherwise).
    pub challenge_binding_secret: Option<&'a str>,
    /// Realm surfaced in `WWW-Authenticate: Payment realm="…"`. Sourced
    /// from `operator.realm` when set, else falls back to the server
    /// subdomain so the label is always deterministic and non-empty.
    pub realm: Option<&'a str>,
    /// If set, requests this server to sponsor activation fees.
    pub fee_payer: bool,
    /// Operator's fee-payer signer. Required when `fee_payer` is true
    /// — the SDK's verify path co-signs the activation transaction
    /// with it before broadcasting. The middleware threads it through
    /// from `PaymentState::fee_payer_signer`.
    pub fee_payer_signer: Option<std::sync::Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>>,
}

/// Resolve `(amount_base_units, decimals, mint_b58)` from the endpoint
/// config. Either `price_usd` (with a known stablecoin currency) or an
/// explicit `amount_base_units` must be present.
pub fn resolve_amount(spec: &SubscriptionEndpoint) -> Result<(String, u8, String)> {
    // Currency resolution: accept a known stablecoin symbol (USDC/USDT/…)
    // OR a raw mint address. Symbols resolve against `mainnet` decimals;
    // anything else needs an explicit `amount_base_units`.
    let (mint, decimals) = if let Some(stable) = pay_types::Stablecoin::parse_symbol(&spec.currency)
    {
        (stable.mint(None).to_string(), 6u8)
    } else {
        // Assume a raw mint and require an explicit base-unit amount: we
        // can't price arbitrary tokens against USD without an oracle.
        (spec.currency.clone(), 0)
    };

    let amount_base_units = if let Some(raw) = spec.amount_base_units.clone() {
        raw
    } else if let Some(price_usd) = spec.price_usd {
        if decimals == 0 {
            return Err(Error::Config(format!(
                "subscription endpoint uses currency `{}` but only provided a USD price; \
                 set `amount_base_units` explicitly when the currency is not a known \
                 stablecoin",
                spec.currency
            )));
        }
        let scaled = (price_usd * 10f64.powi(decimals as i32)).round() as u64;
        if scaled == 0 {
            return Err(Error::Config(format!(
                "subscription price_usd={price_usd} rounds to zero base units"
            )));
        }
        scaled.to_string()
    } else {
        return Err(Error::Config(
            "subscription endpoint requires either `price_usd` or `amount_base_units`".into(),
        ));
    };

    Ok((amount_base_units, decimals, mint))
}

/// Build a [`SubscriptionServer`] handler for the given endpoint, merging
/// the endpoint's `SubscriptionEndpoint` config with the operator-level
/// defaults. Fails fast at boot when the endpoint is missing fields the
/// SDK requires (`plan_id`, `puller`, etc.) so we don't emit unsignable
/// challenges later.
pub fn build_handler(
    spec: &SubscriptionEndpoint,
    defaults: OperatorDefaults<'_>,
    description: Option<&str>,
) -> Result<SubscriptionServer> {
    let plan_id = spec.plan_id.clone().ok_or_else(|| {
        Error::Config(
            "subscription endpoint is missing `plan_id`. Run `pay server plans publish` \
                 to publish the on-chain Plan and write its address back into pay-demo.yaml."
                .into(),
        )
    })?;

    let (_amount, decimals, mint) = resolve_amount(spec)?;

    let (period_unit, period_count) = spec.parse_period().map_err(Error::Config)?;
    let sdk_period_unit = match period_unit {
        TypesPeriodUnit::Day => SubscriptionPeriodUnit::Day,
        TypesPeriodUnit::Week => SubscriptionPeriodUnit::Week,
    };

    let puller = spec
        .puller
        .clone()
        .unwrap_or_else(|| defaults.puller.to_string());
    let recipient = spec
        .recipient
        .clone()
        .unwrap_or_else(|| defaults.recipient.to_string());

    let config = SdkSubscriptionConfig {
        plan_id,
        mint,
        decimals,
        token_program: pay_kit::mpp::protocol::solana::programs::TOKEN_PROGRAM.to_string(),
        puller: puller.clone(),
        recipient,
        period_unit: sdk_period_unit,
        period_count: period_count as u64,
        subscription_expires: spec.expires_at.clone(),
        network: defaults.network.to_string(),
        program_id: None,
        rpc_url: Some(defaults.rpc_url.to_string()),
        // `challenge_binding_secret` and `realm` are required on the SDK side — fall
        // back loudly when the operator config is incomplete instead
        // of inheriting a silent SDK default. Boot-time validation in
        // `pay gate api` is supposed to catch a missing secret
        // before any request lands; this guard is the runtime backstop.
        challenge_binding_secret: defaults
            .challenge_binding_secret
            .map(str::to_string)
            .ok_or_else(|| {
                Error::Config(
                    "subscription handler requires a challenge-binding secret — set \
                 `operator.challenge_binding_secret` in the server YAML"
                        .into(),
                )
            })?,
        realm: defaults
            .realm
            .map(str::to_string)
            .ok_or_else(|| Error::Config("subscription handler requires a realm".into()))?,
        fee_payer: defaults.fee_payer,
        fee_payer_signer: defaults.fee_payer_signer.clone(),
        // The signer is preferred when threaded through, but we also
        // expose the pubkey explicitly so a stateless middleware that
        // only carries the pubkey at challenge-emission time can still
        // emit `methodDetails.feePayerKey`. The SDK prefers the
        // explicit pubkey over the signer-derived one.
        fee_payer_pubkey: if defaults.fee_payer {
            // Prefer the actual signer's pubkey when an explicit
            // fee-payer signer was configured — the SDK serialises
            // this into `methodDetails.feePayerKey`, which the client
            // uses to allocate the payer slot in the activation tx.
            // Falling back to the puller is only safe when the
            // operator runs both roles from one wallet; the moment the
            // fee-payer wallet diverges, this mismatch would cause the
            // client tx to allocate the wrong payer account.
            let signer_derived = defaults
                .fee_payer_signer
                .as_ref()
                .map(|s| s.pubkey().to_string());
            signer_derived.or_else(|| Some(puller.clone()))
        } else {
            None
        },
        store: None,
        // The on-chain Plan terms (numeric id, bump, created_at) are
        // populated by pay-side spec/YAML plumbing before this handler is
        // built. The client validates that every field is present.
        plan_id_numeric: spec.plan_id_numeric,
        plan_bump: spec.plan_bump,
        plan_created_at: spec.plan_created_at,
        description: description.map(str::to_string),
    };

    SubscriptionServer::new(config)
        .map_err(|e| Error::Mpp(format!("Failed to initialise SubscriptionServer: {e}")))
}

/// Generate a 402 challenge for an endpoint's subscription.
pub fn build_challenge(
    spec: &SubscriptionEndpoint,
    defaults: OperatorDefaults<'_>,
    description: Option<&str>,
) -> Result<pay_kit::mpp::PaymentChallenge> {
    let server = build_handler(spec, defaults, description)?;
    let (amount_base_units, _decimals, _mint) = resolve_amount(spec)?;
    server
        .subscription_challenge(&amount_base_units)
        .map_err(|e| Error::Mpp(format!("Failed to build subscription challenge: {e}")))
}

/// Outcome of [`ensure_plan_published`] for a single subscription endpoint.
#[derive(Debug, Clone)]
pub struct PublishedPlan {
    /// Endpoint path the Plan was published for. Used as the YAML
    /// match-key when writing the new IDs back.
    pub endpoint_path: String,
    /// Deterministic `plan_id` u64 derived from `(operator, endpoint.path)`.
    pub plan_id_numeric: u64,
    /// On-chain `Plan` PDA (base58).
    pub plan_pda: String,
    /// PDA bump.
    pub plan_bump: u8,
    /// Plan's `created_at` unix timestamp (set by the program on creation,
    /// read back from the account).
    pub plan_created_at: i64,
    /// Settlement signature if we just broadcast the create_plan tx; `None`
    /// when the Plan already existed on-chain.
    pub broadcast_signature: Option<String>,
}

/// Status of the Plan PDA on-chain. Returned by [`check_plan_exists`] so
/// callers can decide whether to prompt the operator before broadcasting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStatus {
    /// Account exists at the derived PDA and is owned by the
    /// subscriptions program. The expected Plan is in place.
    Exists,
    /// Account does not exist (or is empty) — broadcasting create_plan
    /// is required.
    Missing,
    /// Account exists but is owned by a different program. Refuse to
    /// broadcast — the operator must close + republish or pick a
    /// different plan_id seed.
    WrongOwner { actual_owner: String },
}

/// Largest integer that RFC 8785/JCS can serialize without IEEE-754 rounding.
/// Subscription methodDetails travel through canonical JSON, so Plan IDs must
/// stay within this range or the client receives a different PDA seed.
pub const MAX_SAFE_JSON_PLAN_ID: u64 = (1_u64 << 53) - 1;

/// Deterministic numeric `plan_id` derived from `(operator, endpoint_path)`.
/// Stable across runs so the same YAML always points at the same on-chain
/// Plan. FNV-1a supplies the mixing; the result is constrained to the largest
/// integer that survives RFC 8785/JCS canonicalization exactly.
pub fn compute_plan_id_numeric(operator: &str, endpoint_path: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in operator.bytes().chain(*b"/").chain(endpoint_path.bytes()) {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    let hash = hash & MAX_SAFE_JSON_PLAN_ID;
    // Never return zero — the program treats plan_id=0 as a reserved sentinel.
    if hash == 0 { 1 } else { hash }
}

/// Check whether the expected Plan PDA exists on-chain.
///
/// Distinguishes "account genuinely missing" (returns
/// [`PlanStatus::Missing`]) from "RPC transport failure" (returns
/// `Err`). Conflating the two would let a transient network blip at
/// startup prompt the operator to broadcast a duplicate
/// `create_plan`, wasting SOL and failing on duplicate-PDA error.
pub async fn check_plan_exists(
    rpc_url: &str,
    plan_pda: &solana_pubkey::Pubkey,
) -> Result<PlanStatus> {
    use pay_kit::mpp::program::subscriptions::default_program_id;
    let url = rpc_url.to_string();
    let pda = *plan_pda;
    let outcome = tokio::task::spawn_blocking(move || -> Result<PlanStatus> {
        use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
        // `get_account_with_commitment` returns `Ok(Response { value:
        // None })` when the account doesn't exist, vs `Err(...)` for
        // any transport / parse / RPC-level failure. That's the
        // distinction we need; the legacy `get_account` collapses both
        // into `Err`, which is why the old impl conflated them.
        let rpc = RpcClient::new(url);
        let commitment = solana_commitment_config::CommitmentConfig::confirmed();
        match rpc.get_account_with_commitment(&pda, commitment) {
            Ok(response) => match response.value {
                Some(account) => {
                    let expected_owner = default_program_id();
                    if account.owner == expected_owner {
                        Ok(PlanStatus::Exists)
                    } else {
                        Ok(PlanStatus::WrongOwner {
                            actual_owner: account.owner.to_string(),
                        })
                    }
                }
                None => Ok(PlanStatus::Missing),
            },
            Err(e) => Err(Error::Mpp(format!(
                "Failed to fetch Plan PDA {pda} from {}: {e}. \
                 Retry once the RPC is reachable — refusing to assume the \
                 plan is missing on a transport error (would risk an \
                 accidental duplicate-create broadcast).",
                rpc.url()
            ))),
        }
    })
    .await
    .map_err(|e| Error::Mpp(format!("RPC task join: {e}")))??;
    Ok(outcome)
}

/// Broadcast a `create_plan` instruction and wait for confirmation, then
/// read the new Plan account to capture its `created_at` timestamp.
///
/// This function does **not** prompt — callers (e.g. `pay gate api`)
/// are expected to interactively confirm via dialoguer before invoking
/// it, since publishing costs real SOL on mainnet.
pub async fn publish_plan(
    spec: &SubscriptionEndpoint,
    operator: &solana_pubkey::Pubkey,
    operator_signer: std::sync::Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>,
    rpc_url: &str,
    plan_id_numeric: u64,
) -> Result<PublishedPlan> {
    use pay_kit::mpp::program::subscriptions::{
        CreatePlanAccounts, CreatePlanData, PlanTerms, build_create_plan_ix, default_program_id,
        find_plan_pda, plan_id_seed,
    };
    use solana_pubkey::Pubkey;

    // ── Resolve mint + decimals + per-period amount ───────────────────
    let (amount_base_units, decimals, mint_str) = resolve_amount(spec)?;
    let amount: u64 = amount_base_units
        .parse()
        .map_err(|e| Error::Config(format!("invalid amount: {e}")))?;
    let mint = Pubkey::from_str(&mint_str)
        .map_err(|e| Error::Config(format!("invalid mint pubkey: {e}")))?;

    // ── Period — must round-trip through the SDK's bounds check ───────
    let (period_unit, period_count) = spec.parse_period().map_err(Error::Config)?;
    let period_hours = match period_unit {
        pay_types::metering::SubscriptionPeriodUnit::Day => period_count as u64 * 24,
        pay_types::metering::SubscriptionPeriodUnit::Week => period_count as u64 * 168,
    };

    let program_id = default_program_id();
    let seed = plan_id_seed(plan_id_numeric);
    let (plan_pda, plan_bump) = find_plan_pda(operator, &seed, &program_id);

    // ── Build create_plan data + instruction ─────────────────────────
    let create_data = CreatePlanData::new(
        plan_id_numeric,
        mint,
        PlanTerms {
            amount,
            period_hours,
            created_at: 0, // set on-chain by the program
        },
        0,                      // no plan-level expiry; HTTP-layer subscription_expires governs
        [Pubkey::default(); 4], // open destinations whitelist for v0
        [Pubkey::default(); 4], // owner-only pullers for v0
        "",
    )
    .map_err(|e| Error::Config(format!("Failed to build CreatePlanData: {e}")))?;

    let token_program = Pubkey::from_str(pay_kit::mpp::protocol::solana::programs::TOKEN_PROGRAM)
        .map_err(|e| Error::Config(format!("invalid token program id: {e}")))?;
    let _ = decimals;

    let ix = build_create_plan_ix(
        program_id,
        CreatePlanAccounts {
            merchant: *operator,
            plan_pda,
            token_mint: mint,
            token_program,
        },
        &create_data,
    );
    let _ = decimals;

    // ── Sign + broadcast ─────────────────────────────────────────────
    let signature = sign_and_broadcast(operator_signer, vec![ix], rpc_url).await?;

    // ── Read the new Plan account back to capture created_at ─────────
    let plan_created_at = fetch_plan_created_at(rpc_url, &plan_pda).await?;

    Ok(PublishedPlan {
        endpoint_path: String::new(), // caller fills this in
        plan_id_numeric,
        plan_pda: plan_pda.to_string(),
        plan_bump,
        plan_created_at,
        broadcast_signature: Some(signature),
    })
}

/// Read just the `created_at` (i64 LE) out of an existing or freshly-published Plan
/// account at the canonical offset. Avoids vendoring the full Plan
/// account decoder for the one field `pay gate api` actually needs.
pub async fn fetch_plan_created_at(rpc_url: &str, plan_pda: &solana_pubkey::Pubkey) -> Result<i64> {
    let url = rpc_url.to_string();
    let pda = *plan_pda;
    tokio::task::spawn_blocking(move || -> Result<i64> {
        use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
        let rpc = RpcClient::new(url);
        let account = rpc
            .get_account(&pda)
            .map_err(|e| Error::Mpp(format!("Could not fetch Plan account {pda}: {e}")))?;
        decode_plan_created_at(&account.data)
    })
    .await
    .map_err(|e| Error::Mpp(format!("RPC task join: {e}")))?
}

fn decode_plan_created_at(data: &[u8]) -> Result<i64> {
    // Plan layout:
    //   0   discriminator (u8)
    //   1   owner (32B)
    //   33  bump (u8)
    //   34  status (u8)
    //   35  data.plan_id (u64)
    //   43  data.mint (32B)
    //   75  data.terms.amount (u64)
    //   83  data.terms.period_hours (u64)
    //   91  data.terms.created_at (i64)  ← our target
    const CREATED_AT_OFFSET: usize = 91;
    if data.len() < CREATED_AT_OFFSET + 8 {
        return Err(Error::Mpp(format!(
            "Plan account is too short ({} bytes)",
            data.len()
        )));
    }
    let bytes: [u8; 8] = data[CREATED_AT_OFFSET..CREATED_AT_OFFSET + 8]
        .try_into()
        .map_err(|_| Error::Mpp("Plan.created_at slice".into()))?;
    Ok(i64::from_le_bytes(bytes))
}

/// Sign a one-or-more-instruction transaction with the operator's signer
/// and broadcast through `send_and_confirm_transaction`. Returns the
/// settlement signature as base58.
async fn sign_and_broadcast(
    signer: std::sync::Arc<dyn pay_kit::mpp::solana_keychain::SolanaSigner>,
    instructions: Vec<solana_instruction::Instruction>,
    rpc_url: &str,
) -> Result<String> {
    use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
    use solana_message::Message;
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    let url = rpc_url.to_string();
    let signer_pubkey = signer.pubkey();

    // Fetch a recent blockhash on a blocking worker thread.
    let blockhash = tokio::task::spawn_blocking({
        let url = url.clone();
        move || {
            let rpc = RpcClient::new(url);
            rpc.get_latest_blockhash()
                .map_err(|e| Error::Mpp(format!("Failed to fetch blockhash: {e}")))
        }
    })
    .await
    .map_err(|e| Error::Mpp(format!("RPC task join: {e}")))??;

    let message = Message::new_with_blockhash(&instructions, Some(&signer_pubkey), &blockhash);
    let mut tx = Transaction::new_unsigned(message);

    let msg_bytes = tx.message_data();
    let sig_bytes = signer
        .sign_message(&msg_bytes)
        .await
        .map_err(|e| Error::Mpp(format!("Operator signing failed: {e}")))?;
    let signature = Signature::from(<[u8; 64]>::from(sig_bytes));

    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == signer_pubkey)
        .ok_or_else(|| Error::Mpp("Operator pubkey absent from account_keys".into()))?;
    if tx.signatures.len() <= signer_index {
        return Err(Error::Mpp(
            "Transaction signatures vec is shorter than account_keys".into(),
        ));
    }
    tx.signatures[signer_index] = signature;

    let serialised =
        bincode::serialize(&tx).map_err(|e| Error::Mpp(format!("Failed to serialise tx: {e}")))?;
    let confirmed_sig = tokio::task::spawn_blocking(move || {
        let rpc = RpcClient::new(url);
        let tx: Transaction = bincode::deserialize(&serialised)
            .map_err(|e| Error::Mpp(format!("tx round-trip: {e}")))?;
        rpc.send_and_confirm_transaction(&tx)
            .map_err(|e| Error::Mpp(format!("Broadcast failed: {e}")))
    })
    .await
    .map_err(|e| Error::Mpp(format!("RPC task join: {e}")))??;
    Ok(confirmed_sig.to_string())
}

/// Verify a subscription activation credential.
///
/// Thin wrapper around [`SubscriptionServer::verify_credential`] that
/// parses the `Authorization: Payment <…>` header into a credential first.
/// Returns a [`pay_kit::mpp::ReceiptKind::Subscription`] on success — the
/// activation transaction has been broadcast, confirmed, and the on-chain
/// `SubscriptionDelegation` has been validated against the challenge.
pub async fn verify_activation(
    server: &SubscriptionServer,
    auth_header: &str,
) -> Result<pay_kit::mpp::ReceiptKind> {
    let credential = pay_kit::mpp::parse_authorization(auth_header)
        .map_err(|e| Error::Mpp(format!("Failed to parse Authorization header: {e}")))?;
    server
        .verify_credential(&credential)
        .await
        .map_err(|e| Error::Mpp(format!("Subscription verify failed: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operator_defaults<'a>() -> OperatorDefaults<'a> {
        OperatorDefaults {
            puller: "5fKb5cF22cFybZB1H4hLDydFhwoQy9JzKzRWaSbMkB6h",
            recipient: "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin",
            network: "mainnet",
            rpc_url: "https://api.mainnet-beta.solana.com",
            challenge_binding_secret: Some("test-secret-key-do-not-use-32b-pad"),
            realm: Some("test-realm"),
            fee_payer: false,
            fee_payer_signer: None,
        }
    }

    fn make_spec() -> SubscriptionEndpoint {
        SubscriptionEndpoint {
            period: "30d".into(),
            price_usd: Some(9.99),
            amount_base_units: None,
            currency: "USDC".into(),
            expires_at: None,
            plan_id: Some("8tWbqLkUJoYy7zXc5h2EvCRoaQEv2xnQjUuYhc3rzCgT".into()),
            plan_id_numeric: None,
            plan_bump: None,
            plan_created_at: None,
            puller: None,
            recipient: None,
            free_trial_days: None,
        }
    }

    #[test]
    fn resolve_amount_scales_usd_to_usdc_base_units() {
        let spec = make_spec();
        let (amount, decimals, mint) = resolve_amount(&spec).unwrap();
        assert_eq!(decimals, 6);
        // 9.99 * 1_000_000 = 9_990_000
        assert_eq!(amount, "9990000");
        assert!(!mint.is_empty());
    }

    #[test]
    fn resolve_amount_uses_explicit_base_units_when_present() {
        let mut spec = make_spec();
        spec.price_usd = None;
        spec.amount_base_units = Some("42".to_string());
        let (amount, _, _) = resolve_amount(&spec).unwrap();
        assert_eq!(amount, "42");
    }

    #[test]
    fn resolve_amount_errors_on_missing_pricing() {
        let mut spec = make_spec();
        spec.price_usd = None;
        spec.amount_base_units = None;
        assert!(resolve_amount(&spec).is_err());
    }

    #[test]
    fn resolve_amount_errors_when_unknown_currency_and_only_usd() {
        let mut spec = make_spec();
        spec.currency = "Bonk1111111111111111111111111111111111111111".to_string();
        spec.amount_base_units = None;
        assert!(resolve_amount(&spec).is_err());
    }

    #[test]
    fn build_handler_errors_when_plan_id_missing() {
        let mut spec = make_spec();
        spec.plan_id = None;
        match build_handler(&spec, operator_defaults(), None) {
            Ok(_) => panic!("expected missing plan_id to error"),
            Err(e) => assert!(format!("{e}").to_lowercase().contains("plan")),
        }
    }

    #[test]
    fn build_challenge_emits_subscription_intent_header() {
        let challenge = build_challenge(&make_spec(), operator_defaults(), None).unwrap();
        let header = pay_kit::mpp::format_www_authenticate(&challenge).unwrap();
        assert!(header.contains("intent=\"subscription\""));
        assert!(header.contains("method=\"solana\""));
        assert!(header.contains("realm=\"test-realm\""));
    }

    #[test]
    fn build_challenge_rejects_month_period() {
        let mut spec = make_spec();
        spec.period = "1m".into();
        match build_challenge(&spec, operator_defaults(), None) {
            Ok(_) => panic!("expected month period to be rejected"),
            Err(e) => assert!(format!("{e}").to_lowercase().contains("month")),
        }
    }

    #[test]
    fn decode_plan_created_at_reads_the_on_chain_layout() {
        let expected = 1_770_000_123_i64;
        let mut data = vec![0_u8; 99];
        data[91..99].copy_from_slice(&expected.to_le_bytes());

        assert_eq!(decode_plan_created_at(&data).unwrap(), expected);
        assert!(decode_plan_created_at(&data[..98]).is_err());
    }

    #[test]
    fn generated_plan_id_survives_canonical_json_without_rounding() {
        let id = compute_plan_id_numeric("merchant", "api/v1/very-feed");
        assert!((1..=MAX_SAFE_JSON_PLAN_ID).contains(&id));
        let encoded =
            pay_kit::mpp::Base64UrlJson::from_typed(&serde_json::json!({ "planIdNumeric": id }))
                .expect("canonical JSON");
        assert_eq!(
            encoded.decode_value().unwrap()["planIdNumeric"].as_u64(),
            Some(id)
        );

        let unsafe_id = 18_360_896_155_494_901_300_u64;
        let rounded = pay_kit::mpp::Base64UrlJson::from_typed(
            &serde_json::json!({ "planIdNumeric": unsafe_id }),
        )
        .expect("canonical JSON")
        .decode_value()
        .unwrap();
        assert_ne!(rounded["planIdNumeric"].as_u64(), Some(unsafe_id));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_activation_rejects_garbage_authorization_header() {
        let server = build_handler(&make_spec(), operator_defaults(), None).unwrap();
        // Not a valid base64url Payment credential — must fail at the
        // header parse stage long before any RPC is touched.
        let err = verify_activation(&server, "Payment not!base64!!!")
            .await
            .unwrap_err();
        let msg = format!("{err}").to_lowercase();
        assert!(
            msg.contains("parse") || msg.contains("decode") || msg.contains("authorization"),
            "{err}"
        );
    }
}
