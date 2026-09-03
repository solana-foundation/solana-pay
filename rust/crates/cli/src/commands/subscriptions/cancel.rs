//! `pay subscriptions cancel <subscription-id>` — cancel an on-chain
//! subscription delegation.
//!
//! Two settlement paths:
//!
//! 1. **Direct on-chain** — subscriber wallet has enough SOL to pay
//!    network fees. Build the `cancel_subscription` instruction, sign
//!    as subscriber, broadcast through the configured RPC, await
//!    `confirmed` commitment.
//!
//! 2. **Via pay-api gateway** — subscriber wallet is low on SOL. The
//!    gateway sponsors the SOL fee in exchange for a USDC service
//!    charge (the gateway exposes `POST /v1/subscriptions/cancel`,
//!    which returns a 402 charge challenge first). Triggered
//!    automatically when SOL is below the per-tx threshold, or
//!    explicitly with `--via-gateway`.
//!
//! Cancellation has no MPP scheme of its own — the spec
//! (draft-solana-subscription-00 §Cancellation) treats it as a pure
//! on-chain operation. Both paths converge on flipping the local
//! accounts.yml entry to `cancelled` after settlement.

use std::sync::Arc;

use owo_colors::OwoColorize;
use pay_kit::mpp::client::build_credential_header;
use pay_kit::mpp::program::subscriptions::{
    CancelSubscriptionAccounts, build_cancel_subscription_ix, default_program_id,
    find_event_authority_pda, parse_pubkey,
};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
use pay_kit::mpp::{PaymentChallenge, parse_www_authenticate};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use pay_core::accounts::{AccountsFile, AccountsStore, FileAccountsStore, SubscriptionStatus};

/// Minimum SOL balance (lamports) the subscriber must hold for the
/// direct on-chain path. Below this the command auto-routes through the
/// pay-api gateway. 50_000 lamports = 0.00005 SOL — plenty of headroom
/// over the ~5_000-lamport base fee for one signature.
const DIRECT_PATH_MIN_LAMPORTS: u64 = 50_000;

#[derive(clap::Args)]
pub struct CancelCommand {
    /// Base58 `subscription_id` to cancel.
    pub subscription_id: String,

    /// Skip the on-chain cancel transaction and only flip the local
    /// entry to `cancelled`. Useful when the on-chain side was already
    /// cancelled out-of-band (e.g., by closing the SubscriptionAuthority).
    #[arg(long)]
    pub local_only: bool,

    /// Force routing through the pay-api gateway even when the
    /// subscriber has enough SOL for a direct broadcast. The argument
    /// is the gateway's base URL (e.g.
    /// `https://pay-api.gateway-402.com`).
    ///
    /// When unset, the command auto-routes through `$PAY_API_URL` if
    /// the subscriber's SOL balance is below the per-tx threshold.
    #[arg(long)]
    pub via_gateway: Option<String>,

    /// Gateway operator pubkey (base58) that signs as fee-payer.
    /// Required when routing via the gateway. Defaults to
    /// `$PAY_API_FEE_PAYER` when unset.
    #[arg(long)]
    pub gateway_fee_payer: Option<String>,

    /// RPC URL override. Defaults to `$PAY_RPC_URL` if set, otherwise
    /// the canonical public RPC for the subscription's network.
    #[arg(long)]
    pub rpc_url: Option<String>,
}

impl CancelCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let store = FileAccountsStore::default_path();
        let mut accounts: AccountsFile = store.load()?;

        // ── Locate the subscription ─────────────────────────────────────
        let owner = accounts
            .all_subscriptions()
            .find(|(_, _, sub)| sub.subscription_id == self.subscription_id)
            .map(|(net, name, sub)| (net.to_string(), name.to_string(), sub.clone()));

        let Some((network, account_name, subscription)) = owner else {
            return Err(pay_core::Error::Config(format!(
                "subscription `{}` is not tracked locally. \
                 Run `pay subscriptions list` to see known ids.",
                self.subscription_id
            )));
        };

        if self.local_only {
            accounts.set_subscription_status(
                &network,
                &account_name,
                &self.subscription_id,
                SubscriptionStatus::Cancelled,
            );
            store.save(&accounts)?;
            eprintln!(
                "Marked `{}` as {} in {network}/{account_name} (local only).",
                self.subscription_id,
                "cancelled".yellow()
            );
            return Ok(());
        }

        // ── Resolve on-chain accounts ───────────────────────────────────
        let program_id = match subscription.program_id.as_deref() {
            Some(p) => {
                parse_pubkey(p, "program_id").map_err(|e| pay_core::Error::Config(e.to_string()))?
            }
            None => default_program_id(),
        };
        let subscription_pda = parse_pubkey(&subscription.subscription_id, "subscription_id")
            .map_err(|e| pay_core::Error::Config(e.to_string()))?;
        let plan_pda = parse_pubkey(&subscription.plan_id, "plan_id")
            .map_err(|e| pay_core::Error::Config(e.to_string()))?;
        let (event_authority, _) = find_event_authority_pda(&program_id);

        // ── Resolve gateway URL + RPC URL ───────────────────────────────
        //
        // Precedence on gateway URL: `--via-gateway` > `PAY_API_URL` env >
        // built-in default. The default lets a fresh install route a
        // no-SOL cancel through the hosted pay-api without any env
        // wiring; power users override per-invocation or per-shell.
        // `--gateway-fee-payer` and `PAY_API_FEE_PAYER` remain as
        // advanced overrides but are NOT required anymore — the
        // gateway advertises its fee-payer pubkey in the 402 discovery
        // response, so the common path needs zero config.
        let gateway_url = self
            .via_gateway
            .clone()
            .unwrap_or_else(pay_core::client::balance::pay_api_url);
        let gateway_fee_payer_override = self
            .gateway_fee_payer
            .clone()
            .or_else(|| std::env::var("PAY_API_FEE_PAYER").ok());

        // Route `localnet`/`surfnet` to the pay sandbox cluster
        // (`https://402.surfnet.dev:8899`) rather than pay-kit's bare
        // `http://localhost:8899` default — local validators are the
        // exception, the surfpool-backed sandbox is the norm. Mainnet
        // and devnet keep pay-kit's defaults.
        let rpc_url = self
            .rpc_url
            .clone()
            .or_else(|| std::env::var("PAY_RPC_URL").ok())
            .unwrap_or_else(|| {
                pay_core::client::subscription::default_rpc_url_for_network(&network)
            });

        // ── Subscriber pubkey from accounts.yml (no keystore unlock) ────
        //
        // We need to know the subscriber pubkey BEFORE prompting Touch ID
        // so we can (a) probe SOL balance to decide direct-vs-gateway,
        // and (b) probe the gateway to learn the real USDC fee for the
        // prompt. The account's `pubkey` is stored plaintext in
        // `accounts.yml`, so we can read it without unlocking the
        // keystore.
        let subscriber_pubkey_str = accounts
            .accounts
            .get(&network)
            .and_then(|m| m.get(&account_name))
            .and_then(|a| a.pubkey.clone())
            .ok_or_else(|| {
                pay_core::Error::Config(format!(
                    "Account `{account_name}` on network `{network}` has no \
                     pubkey on file. Re-run `pay account ls` to confirm."
                ))
            })?;
        let subscriber_pubkey = parse_pubkey(&subscriber_pubkey_str, "subscriber")
            .map_err(|e| pay_core::Error::Config(e.to_string()))?;

        // ── Decide direct vs gateway ────────────────────────────────────
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| pay_core::Error::Config(format!("Failed to create runtime: {e}")))?;

        let force_gateway = self.via_gateway.is_some();
        let sol_lamports = rt
            .block_on(pay_core::balance::get_sol_balance(
                &rpc_url,
                &subscriber_pubkey.to_string(),
            ))
            .unwrap_or(0);

        let use_gateway = force_gateway || sol_lamports < DIRECT_PATH_MIN_LAMPORTS;

        // ── Probe gateway BEFORE prompting Touch ID ─────────────────────
        //
        // On the gateway path we POST without a tx to learn the
        // fee-payer pubkey + USDC service fee. That lets the Touch ID
        // prompt below carry the real price ("authorize $0.0015 USDC")
        // instead of "$0". Direct path skips this — there's no
        // gateway involved.
        let gateway_probe = if use_gateway {
            eprintln!("{} {}", "Routing via".dimmed(), gateway_url.dimmed());
            Some(rt.block_on(probe_gateway_challenge(
                &gateway_url,
                &subscription_pda.to_string(),
                &network,
            ))?)
        } else {
            None
        };

        // ── Touch ID prompt with the (now-known) real amount ────────────
        let (intent_amount_label, intent_reason) = match &gateway_probe {
            Some(probe) => (
                format!("${}", probe.fee_display.clone()),
                format!(
                    "Cancel subscription {} (gateway fee {} {})",
                    truncate(&subscription.subscription_id),
                    probe.fee_display,
                    probe.currency,
                ),
            ),
            None => (
                "0".to_string(),
                format!(
                    "Cancel subscription {} (plan {})",
                    truncate(&subscription.subscription_id),
                    truncate(&subscription.plan_id),
                ),
            ),
        };
        let intent = pay_core::keystore::AuthIntent::authorize_payment_details(
            &intent_amount_label,
            &intent_reason,
            &subscription
                .resource_url
                .clone()
                .unwrap_or_else(|| format!("subscription/{}", network)),
        );
        let (signer, _ephemeral_notice) =
            pay_core::signer::load_signer_for_network_payment_with_intent(
                &network,
                &store,
                Some(&account_name),
                &intent_amount_label,
                &intent,
            )?;
        // Defence-in-depth: the keystore unlocked the account we expected.
        if signer.pubkey() != subscriber_pubkey {
            return Err(pay_core::Error::Config(format!(
                "Keystore returned `{}` but accounts.yml has `{}` for {network}/{account_name}.",
                signer.pubkey(),
                subscriber_pubkey,
            )));
        }

        // ── Settle ──────────────────────────────────────────────────────
        let signature = if use_gateway {
            let probe = gateway_probe.expect("gateway_probe set when use_gateway");
            let gw_fee_payer = match gateway_fee_payer_override {
                Some(explicit) => parse_pubkey(&explicit, "gateway_fee_payer")
                    .map_err(|e| pay_core::Error::Config(e.to_string()))?,
                None => probe.fee_payer,
            };
            let ix = build_cancel_subscription_ix(
                program_id,
                CancelSubscriptionAccounts {
                    subscriber: subscriber_pubkey,
                    plan_pda,
                    subscription_pda,
                    event_authority,
                },
            );
            rt.block_on(broadcast_via_gateway(
                Arc::new(signer),
                ix,
                &gw_fee_payer,
                &gateway_url,
                &network,
                &rpc_url,
                &subscription_pda.to_string(),
                probe.challenge,
            ))?
        } else {
            let ix = build_cancel_subscription_ix(
                program_id,
                CancelSubscriptionAccounts {
                    subscriber: subscriber_pubkey,
                    plan_pda,
                    subscription_pda,
                    event_authority,
                },
            );
            rt.block_on(broadcast_direct(&signer, ix, &rpc_url))
                .map_err(|e| pay_core::Error::Mpp(format!("Direct cancel broadcast failed: {e}")))?
        };

        // ── Persist local state ─────────────────────────────────────────
        //
        // On-chain cancel doesn't void the current period — the
        // subscriber keeps access until `expires_at_ts` (the period
        // end the on-chain `cancel_subscription` ix pinned). We mark
        // the row Cancelled so `pay subscriptions ls` can render the
        // "active until X" hint, and compute the period end from
        // `activated_at + period` when the row didn't already capture
        // an `expires_at` (e.g. server YAML omitted `expires_at`). The
        // next `ls` invocation sweeps the row once that timestamp
        // elapses.
        if let Some(sub) = accounts
            .accounts
            .get(&network)
            .and_then(|m| m.get(&account_name))
            .and_then(|a| a.subscriptions.get(&self.subscription_id))
            && sub.expires_at.is_none()
            && let Some(period_end) = compute_period_end(sub)
        {
            let mut updated = sub.clone();
            updated.expires_at = Some(period_end);
            accounts.upsert_subscription(&network, &account_name, updated)?;
        }
        accounts.set_subscription_status(
            &network,
            &account_name,
            &self.subscription_id,
            SubscriptionStatus::Cancelled,
        );
        store.save(&accounts)?;

        eprintln!(
            "Cancelled subscription {} {} (tx {})",
            truncate(&self.subscription_id).bold(),
            format!("in {network}/{account_name}").dimmed(),
            signature
        );
        Ok(())
    }
}

// ── Direct on-chain path ────────────────────────────────────────────────────

async fn broadcast_direct(
    signer: &dyn SolanaSigner,
    instruction: solana_instruction::Instruction,
    rpc_url: &str,
) -> pay_core::Result<String> {
    let pubkey = signer.pubkey();
    let url = rpc_url.to_string();

    let blockhash = tokio::task::spawn_blocking({
        let url = url.clone();
        move || {
            let rpc = RpcClient::new(url);
            rpc.get_latest_blockhash()
                .map_err(|e| pay_core::Error::Mpp(format!("Failed to fetch blockhash: {e}")))
        }
    })
    .await
    .map_err(|e| pay_core::Error::Mpp(format!("RPC task join: {e}")))??;

    let message = Message::new_with_blockhash(&[instruction], Some(&pubkey), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let sig_bytes = signer
        .sign_message(&tx.message_data())
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Subscriber signing failed: {e}")))?;
    let signature = Signature::from(<[u8; 64]>::from(sig_bytes));
    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == pubkey)
        .ok_or_else(|| pay_core::Error::Mpp("Subscriber pubkey absent from account_keys".into()))?;
    tx.signatures[signer_index] = signature;

    let serialised = bincode::serialize(&tx)
        .map_err(|e| pay_core::Error::Mpp(format!("Failed to serialise tx: {e}")))?;
    let confirmed = tokio::task::spawn_blocking(move || {
        let rpc = RpcClient::new(url);
        let tx: Transaction = bincode::deserialize(&serialised)
            .map_err(|e| pay_core::Error::Mpp(format!("tx round-trip: {e}")))?;
        rpc.send_and_confirm_transaction(&tx)
            .map_err(|e| pay_core::Error::Mpp(format!("Broadcast failed: {e}")))
    })
    .await
    .map_err(|e| pay_core::Error::Mpp(format!("RPC task join: {e}")))??;
    Ok(confirmed.to_string())
}

// ── pay-api gateway path ────────────────────────────────────────────────────
//
// The gateway exposes `POST /v1/subscriptions/cancel` with a two-step
// flow: the first POST returns a 402 USDC charge challenge; the second
// POST (with `Authorization: Payment …` set) verifies the charge,
// co-signs the user-submitted cancel_subscription tx as fee-payer, and
// broadcasts.

#[allow(clippy::too_many_arguments)]
async fn broadcast_via_gateway(
    signer: Arc<dyn SolanaSigner>,
    instruction: solana_instruction::Instruction,
    gateway_fee_payer: &Pubkey,
    gateway_url: &str,
    network: &str,
    rpc_url: &str,
    subscription_pda: &str,
    challenge: PaymentChallenge,
) -> pay_core::Result<String> {
    let url = rpc_url.to_string();
    let cancel_url = format!(
        "{}/v1/subscriptions/cancel",
        gateway_url.trim_end_matches('/')
    );

    // ── Build the partial-signed cancel_subscription tx ────────────────
    //
    // Fee-payer slot at account_keys[0] is the gateway's pubkey
    // (learned during the discovery probe); the subscriber signs as
    // the second signer. The gateway's `parse_cancel_tx` enforces both
    // conditions.
    let blockhash = tokio::task::spawn_blocking({
        let url = url.clone();
        move || {
            let rpc = RpcClient::new(url);
            rpc.get_latest_blockhash()
                .map_err(|e| pay_core::Error::Mpp(format!("Failed to fetch blockhash: {e}")))
        }
    })
    .await
    .map_err(|e| pay_core::Error::Mpp(format!("RPC task join: {e}")))??;

    let message = Message::new_with_blockhash(&[instruction], Some(gateway_fee_payer), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let subscriber = signer.pubkey();
    let subscriber_index = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == subscriber)
        .ok_or_else(|| {
            pay_core::Error::Mpp(
                "Subscriber pubkey absent from cancel_subscription account_keys".into(),
            )
        })?;
    let sig_bytes = signer
        .sign_message(&tx.message_data())
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Subscriber signing failed: {e}")))?;
    tx.signatures[subscriber_index] = Signature::from(<[u8; 64]>::from(sig_bytes));

    let tx_bytes = bincode::serialize(&tx)
        .map_err(|e| pay_core::Error::Mpp(format!("Failed to serialise tx: {e}")))?;
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &tx_bytes);

    // ── Sign the USDC charge credential against the probed challenge ───
    let rpc = RpcClient::new(url.clone());
    let authorization = build_credential_header(signer.as_ref(), &rpc, &challenge)
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Failed to build charge credential: {e}")))?;

    // ── Authenticated POST → expect 200 with cancel signature ──────────
    let http = reqwest::Client::new();
    let body = serde_json::json!({
        "tx": tx_b64,
        "subscriptionPda": subscription_pda,
        "network": network,
        "currency": "USDC",
    });
    let second = http
        .post(&cancel_url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .json(&body)
        .send()
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Gateway retry failed: {e}")))?;

    let status = second.status();
    let resp_text = second.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(pay_core::Error::Mpp(format!(
            "Gateway cancel failed ({status}): {resp_text}"
        )));
    }

    // Body shape: `{ "signature": "...", "receipt": {...}, "subscriptionPda": "..." }`
    let resp_json: serde_json::Value = serde_json::from_str(&resp_text)
        .map_err(|e| pay_core::Error::Mpp(format!("Could not parse gateway response: {e}")))?;
    let signature = resp_json
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| pay_core::Error::Mpp("Gateway response missing `signature` field".into()))?
        .to_string();
    Ok(signature)
}

/// Discovery probe — POST the cancel endpoint with no `Authorization`
/// and no `tx`. The gateway returns 402 with a charge challenge
/// (`WWW-Authenticate`) plus a JSON body advertising the fee-payer
/// pubkey, the USDC fee, and the SOL/USD oracle price. We use the
/// fee-payer to build the cancel tx and the fee to populate the Touch
/// ID prompt with the real amount.
async fn probe_gateway_challenge(
    gateway_url: &str,
    subscription_pda: &str,
    network: &str,
) -> pay_core::Result<GatewayProbe> {
    let cancel_url = format!(
        "{}/v1/subscriptions/cancel",
        gateway_url.trim_end_matches('/')
    );
    let body = serde_json::json!({
        "subscriptionPda": subscription_pda,
        "network": network,
        "currency": "USDC",
    });
    let http = reqwest::Client::new();
    let resp = http
        .post(&cancel_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Gateway discovery probe failed: {e}")))?;
    if resp.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(pay_core::Error::Mpp(format!(
            "Expected 402 from gateway discovery, got {status}: {text}"
        )));
    }

    // Parse the JSON body first — it carries the structured fee /
    // pubkey fields. We also parse the WWW-Authenticate header so the
    // returned challenge can be fed straight into
    // `build_credential_header` later.
    let www_auth = resp
        .headers()
        .get(reqwest::header::WWW_AUTHENTICATE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            pay_core::Error::Mpp("Gateway 402 response missing WWW-Authenticate header".into())
        })?
        .to_string();
    let challenge: PaymentChallenge = parse_www_authenticate(&www_auth)
        .map_err(|e| pay_core::Error::Mpp(format!("Invalid challenge: {e}")))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Could not parse gateway 402 body: {e}")))?;
    let fee_payer_str = body
        .get("feePayer")
        .and_then(|v| v.as_str())
        .ok_or_else(|| pay_core::Error::Mpp("Gateway 402 missing `feePayer`".into()))?;
    let fee_payer =
        parse_pubkey(fee_payer_str, "feePayer").map_err(|e| pay_core::Error::Mpp(e.to_string()))?;
    let currency = body
        .get("currency")
        .and_then(|v| v.as_str())
        .unwrap_or("USDC")
        .to_string();
    // The amount the user is consenting to comes from the challenge's
    // request payload, not the convenience `feeRaw` field. We render
    // it via the standard token-amount formatter so the Touch ID
    // prompt shows "$0.0015" rather than "1500 base units".
    let charge_request: pay_kit::mpp::protocol::intents::ChargeRequest = challenge
        .request
        .decode()
        .map_err(|e| pay_core::Error::Mpp(format!("Gateway challenge request payload: {e}")))?;
    let amount_raw: u64 = charge_request.amount.parse().map_err(|e| {
        pay_core::Error::Mpp(format!("Gateway challenge amount is not numeric: {e}"))
    })?;
    let decimals = pay_types::Stablecoin::parse_symbol(&currency)
        .map(|c| c.decimals())
        .unwrap_or(6);
    let fee_display = pay_core::client::send::format_token_amount(amount_raw, decimals);

    Ok(GatewayProbe {
        challenge,
        fee_payer,
        currency,
        fee_display,
    })
}

struct GatewayProbe {
    challenge: PaymentChallenge,
    fee_payer: Pubkey,
    currency: String,
    /// Human-readable fee amount (`"0.0015"`), already decimal-shifted
    /// from base units. Embedded in the Touch ID prompt label.
    fee_display: String,
}

fn truncate(id: &str) -> String {
    if id.len() <= 12 {
        id.to_string()
    } else {
        format!("{}…{}", &id[..6], &id[id.len() - 4..])
    }
}

/// Compute the RFC 3339 timestamp at which the current paid period
/// ends, given a subscription's `activated_at` + period. Mirrors the
/// on-chain `expires_at_ts` the program pins when `cancel_subscription`
/// fires. Returns `None` if `activated_at` can't be parsed or the
/// period unit is unknown — caller treats that as "no estimate".
fn compute_period_end(sub: &pay_core::accounts::Subscription) -> Option<String> {
    let activated = chrono::DateTime::parse_from_rfc3339(&sub.activated_at)
        .ok()?
        .with_timezone(&chrono::Utc);
    let count = i64::from(sub.period_count);
    let delta = match sub.period_unit.as_str() {
        "day" => chrono::Duration::days(count),
        "week" => chrono::Duration::weeks(count),
        _ => return None,
    };
    Some((activated + delta).to_rfc3339())
}
