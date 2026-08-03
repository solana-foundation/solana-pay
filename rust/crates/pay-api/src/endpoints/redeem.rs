//! `POST /v1/redeem`
//!
//! Activation-campaign redemption. Takes a code + destination, looks up
//! the gateway hot wallet's recent transactions via Helius to make sure
//! the code hasn't been burned yet, then builds + signs + broadcasts a
//! transaction that pays the code's campaign amount of the configured token
//! to the destination and stamps `pay-redeem:<code>` as a memo so the
//! next request can detect this one.
//!
//! The fee payer / hot wallet is `state.send.fee_payer` — the same
//! GCP-KMS-backed signer the `/v1/send` endpoint uses. The redemption
//! endpoint only needs the mint, amount, decimals, network, and a
//! Helius API key on top of that.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::{Arc, LazyLock, Mutex};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use pay_api_core::Error;
use pay_api_core::ata::{ATA_PROGRAM_ID, associated_token_address};
use pay_api_core::receipt::MEMO_PROGRAM;
use pay_api_types::Network;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use serde::{Deserialize, Serialize};
use serde_json::json;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use spl_token_2022_interface::instruction as token_ix;
use tracing::{info, warn};

use crate::config::validate_redemption_code;
use crate::state::AppState;

// ── Constants ─────────────────────────────────────────────────────────────

/// SPL Memo v2 program ID, typed. String form lives in
/// `pay_api_core::receipt::MEMO_PROGRAM` (also used by the receipt
/// parser); we parse it once here for the instruction-builder path.
static MEMO_PROGRAM_ID: LazyLock<Pubkey> =
    LazyLock::new(|| Pubkey::from_str(MEMO_PROGRAM).expect("MEMO_PROGRAM is a valid pubkey"));

/// Memo prefix for every redemption Transfer. The burn check matches
/// the full string `"Redeem code <CODE>"` so a hand-written memo would
/// have to use this exact phrasing + a real code to collide.
const REDEEM_MEMO_PREFIX: &str = "Redeem code ";

/// Cap on Helius pages walked per request. Eight pages covers the
/// current campaigns with slack.
const DEFAULT_MAX_SCAN_PAGES: usize = 8;

/// Helius enhanced-transactions page limit.
const HELIUS_PAGE_LIMIT: usize = 100;

// ── HTTP shapes ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct RedeemRequest {
    pub code: String,
    pub destination: String,
}

#[derive(Debug, Serialize)]
struct RedeemResponse {
    signature: String,
    destination: String,
    campaign: String,
    /// USD-formatted activation amount (e.g. `"$0.10"`). Derived from
    /// the campaign amount + decimals so the CLI can
    /// surface it in the success notice without needing to know the
    /// atomic unit / stablecoin layout. Always `$`-prefixed since
    /// every supported `redemption.currency` is a USD stablecoin.
    amount: String,
}

// ── Handler ───────────────────────────────────────────────────────────────

pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RedeemRequest>,
) -> Response {
    let cfg = match &state.redemption {
        Some(cfg) if cfg.enabled => cfg,
        _ => return err_resp(StatusCode::SERVICE_UNAVAILABLE, "redemption disabled"),
    };

    if let Err(msg) = validate_redemption_code(&req.code) {
        return err_resp(StatusCode::BAD_REQUEST, &msg);
    }
    let grant = match cfg.grants.get(&req.code) {
        Some(grant) => grant,
        None => return err_resp(StatusCode::BAD_REQUEST, "unknown code"),
    };
    let destination_pk = match Pubkey::from_str(req.destination.trim()) {
        Ok(pk) => pk,
        Err(_) => return err_resp(StatusCode::BAD_REQUEST, "invalid destination pubkey"),
    };

    let signer = match fee_payer_signer(&state).await {
        Ok(s) => s,
        Err(_) => {
            return err_resp(
                StatusCode::INTERNAL_SERVER_ERROR,
                "fee-payer signer unavailable",
            );
        }
    };
    let hot_wallet = signer.pubkey();

    // Close the TOCTOU window between the Helius scan and broadcast by
    // marking the code as in-flight. A concurrent request carrying the
    // same code sees the lock and returns 409 immediately. Released on
    // every exit path via RAII (Drop on `_in_flight`). Single-instance
    // only — a multi-instance deployment would need an external lock.
    let _in_flight = match InFlightGuard::acquire(&cfg.in_flight, &req.code) {
        Ok(g) => g,
        Err(_) => {
            return err_resp(StatusCode::CONFLICT, "code redemption already in progress");
        }
    };

    // 1. Dedup scan.
    match find_prior_burn(&hot_wallet, &req.code, cfg).await {
        Ok(Some(sig)) => {
            return err_resp_with_extra(
                StatusCode::CONFLICT,
                "code already redeemed",
                json!({ "signature": sig }),
            );
        }
        Ok(None) => {}
        Err(e) => {
            // Strip the request URL before logging — it carries the
            // Helius `api-key=` query param and `reqwest::Error`'s
            // Display impl prints it verbatim.
            warn!(error = %e.without_url(), "Helius dedup scan failed");
            return err_resp(StatusCode::BAD_GATEWAY, "redemption dedup check failed");
        }
    }

    // 2. Build the unsigned tx.
    let rpc_url = match state.rpc_url_for(cfg.network) {
        Ok(url) => url.to_string(),
        Err(e) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    let blockhash_str = match state.rpc.get_latest_blockhash(&rpc_url).await {
        Ok(b) => b,
        Err(e) => return err_resp(StatusCode::BAD_GATEWAY, &e.to_string()),
    };
    let blockhash = match solana_hash::Hash::from_str(&blockhash_str) {
        Ok(b) => b,
        Err(_) => return err_resp(StatusCode::BAD_GATEWAY, "blockhash decode failed"),
    };

    let unsigned = match build_unsigned(
        &req.code,
        grant.amount,
        &destination_pk,
        &hot_wallet,
        cfg,
        blockhash,
    ) {
        Ok(tx) => tx,
        Err(msg) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &msg),
    };

    // 3. Sign + broadcast.
    let signature = match sign_and_broadcast(unsigned, signer, &state, &rpc_url).await {
        Ok(sig) => sig,
        Err(msg) => return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &msg),
    };

    info!(
        campaign = %grant.campaign_id,
        destination = %destination_pk,
        signature = %signature,
        "redeem succeeded"
    );

    let amount = format!(
        "${}",
        super::send::format_base_units(grant.amount, cfg.decimals)
    );

    (
        StatusCode::OK,
        Json(RedeemResponse {
            signature: signature.to_string(),
            destination: destination_pk.to_string(),
            campaign: grant.campaign_id.clone(),
            amount,
        }),
    )
        .into_response()
}

fn redeem_memo(code: &str) -> String {
    format!("{REDEEM_MEMO_PREFIX}{code}")
}

// ── Helius dedup scan ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct HeliusTx {
    signature: String,
    #[serde(default)]
    instructions: Vec<HeliusIx>,
}

#[derive(Debug, Deserialize)]
struct HeliusIx {
    #[serde(rename = "programId", default)]
    program_id: String,
    #[serde(default)]
    data: String,
}

/// Walk the hot wallet's Helius "transactions for address" history
/// looking for any prior tx whose memo program ix decodes to
/// `pay-redeem:<code>`. Returns the matching signature when found.
async fn find_prior_burn(
    hot_wallet: &Pubkey,
    code: &str,
    cfg: &RedemptionState,
) -> Result<Option<String>, reqwest::Error> {
    // Sandbox / local-testing escape hatch: when no Helius key is set
    // (Helius enhanced transactions is mainnet-only, so it can't see
    // forks like Surfnet), skip the burn scan and let the transfer
    // proceed. Production deployments always have a key configured;
    // this just unblocks end-to-end testing against `402.surfnet.dev`.
    if cfg.solana_rpc_api_key.is_empty() {
        warn!("redemption.solana_rpc_api_key is empty — skipping dedup scan (sandbox mode)");
        return Ok(None);
    }

    let http = &cfg.http_client;
    let needle = redeem_memo(code);
    let hot_wallet_str = hot_wallet.to_string();
    let mut cursor: Option<String> = None;

    for page in 0..cfg.max_scan_pages {
        let mut url = reqwest::Url::parse(&format!(
            "{}/v0/addresses/{}/transactions",
            cfg.helius_base.trim_end_matches('/'),
            hot_wallet_str
        ))
        .expect("static URL parses");
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("api-key", &cfg.solana_rpc_api_key);
            // No `type=` filter: Helius's heuristic classifier can mark a
            // multi-instruction tx (idempotent-ATA-create + TransferChecked
            // + memo) as something other than `TRANSFER`, which would
            // silently exclude prior burns from the scan. Match purely on
            // the memo content so reclassification can't cause a miss.
            q.append_pair("limit", &HELIUS_PAGE_LIMIT.to_string());
            if let Some(c) = cursor.as_deref() {
                q.append_pair("before-signature", c);
            }
        }
        let txs: Vec<HeliusTx> = http
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if txs.is_empty() {
            return Ok(None);
        }
        for tx in &txs {
            for ix in &tx.instructions {
                if ix.program_id == MEMO_PROGRAM
                    && let Some(decoded_bytes) = bs58::decode(&ix.data).into_vec().ok()
                    && let Ok(decoded) = std::str::from_utf8(&decoded_bytes)
                    && decoded == needle
                {
                    return Ok(Some(tx.signature.clone()));
                }
            }
        }
        // Underfull page → end of history.
        if txs.len() < HELIUS_PAGE_LIMIT {
            return Ok(None);
        }
        cursor = txs.last().map(|t| t.signature.clone());
        if page + 1 == cfg.max_scan_pages {
            warn!(
                code = code,
                max_scan_pages = cfg.max_scan_pages,
                "redeem scan hit page cap without exhausting hot-wallet history"
            );
        }
    }
    Ok(None)
}

// ── Transaction construction ──────────────────────────────────────────────

fn build_unsigned(
    code: &str,
    amount: u64,
    destination: &Pubkey,
    hot_wallet: &Pubkey,
    cfg: &RedemptionState,
    blockhash: solana_hash::Hash,
) -> Result<Transaction, String> {
    let hot_ata = associated_token_address(hot_wallet, &cfg.mint, &cfg.token_program);
    let dest_ata = associated_token_address(destination, &cfg.mint, &cfg.token_program);

    let mut ixs: Vec<Instruction> = Vec::with_capacity(3);

    // 1. Idempotent ATA creation for destination — no-op if it exists.
    ixs.push(create_associated_token_account_idempotent_ix(
        hot_wallet,
        destination,
        &cfg.mint,
        &cfg.token_program,
    ));

    // 2. TransferChecked (mint + decimals validated on-chain).
    ixs.push(
        token_ix::transfer_checked(
            &cfg.token_program,
            &hot_ata,
            &cfg.mint,
            &dest_ata,
            hot_wallet,
            &[],
            amount,
            cfg.decimals,
        )
        .map_err(|e| format!("transfer_checked: {e}"))?,
    );

    // 3. Memo.
    ixs.push(Instruction {
        program_id: *MEMO_PROGRAM_ID,
        accounts: Vec::<AccountMeta>::new(),
        data: redeem_memo(code).into_bytes(),
    });

    Ok(Transaction::new_unsigned(Message::new_with_blockhash(
        &ixs,
        Some(hot_wallet),
        &blockhash,
    )))
}

/// Sign the message-bytes with the SolanaSigner and broadcast via the
/// shared pay-api-core RPC client. Mirrors the pattern used in
/// `subscriptions::co_sign_and_broadcast`.
async fn sign_and_broadcast(
    mut tx: Transaction,
    signer: Arc<dyn SolanaSigner>,
    state: &AppState,
    rpc_url: &str,
) -> Result<Signature, String> {
    let fee_payer = signer.pubkey();
    let idx = tx
        .message
        .account_keys
        .iter()
        .position(|k| *k == fee_payer)
        .ok_or_else(|| "fee payer not in account keys".to_string())?;

    let msg_bytes = tx.message_data();
    let sig_bytes = signer
        .sign_message(&msg_bytes)
        .await
        .map_err(|e| format!("fee-payer sign failed: {e}"))?;
    let signature = Signature::from(<[u8; 64]>::from(sig_bytes));
    if tx.signatures.len() <= idx {
        return Err("tx.signatures slot missing for fee payer".into());
    }
    tx.signatures[idx] = signature;

    let serialised = bincode::serialize(&tx).map_err(|e| format!("bincode: {e}"))?;
    let tx_b64 = base64::engine::general_purpose::STANDARD.encode(&serialised);

    let sig_str = state
        .rpc
        .send_raw_transaction(rpc_url, &tx_b64)
        .await
        .map_err(|e: Error| e.to_string())?;
    Signature::from_str(&sig_str).map_err(|_| "rpc returned malformed signature".into())
}

async fn fee_payer_signer(state: &AppState) -> Result<Arc<dyn SolanaSigner>, Error> {
    crate::signer::build_fee_payer_signer(
        &state.send.fee_payer,
        "send.fee_payer.key_name is missing",
        "send.fee_payer.pubkey is missing",
    )
    .await
}

// ── State carried at boot ─────────────────────────────────────────────────

/// Cached redemption settings the api boots with. Held on AppState so
/// the handler is a pure dispatch.
#[derive(Clone, Debug)]
pub struct RedemptionState {
    pub enabled: bool,
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub decimals: u8,
    pub network: Network,
    pub solana_rpc_api_key: String,
    pub helius_base: String,
    pub max_scan_pages: usize,
    /// Active code → campaign grant, loaded from `REDEMPTION_CODES`
    /// (Doppler) at boot. Lookups in the handler are O(1).
    pub grants: HashMap<String, RedemptionGrant>,
    /// Pooled HTTP client for the Helius dedup scan. Shared across all
    /// `/v1/redeem` requests so connections / TLS handshakes are reused.
    pub http_client: reqwest::Client,
    /// Set of codes currently mid-redemption on this instance. The
    /// handler inserts before the Helius scan and removes on every
    /// exit path; a concurrent request finding the code present
    /// returns 409.
    pub in_flight: Arc<Mutex<HashSet<String>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedemptionGrant {
    pub campaign_id: String,
    pub amount: u64,
}

impl RedemptionState {
    /// Resolve mint / token program from `redemption.currency` via the
    /// same pay-kit helpers `/v1/send` uses, then fold in the rest of
    /// the static config.
    pub fn from_config(cfg: &crate::config::RedemptionConfig) -> Result<Self, Error> {
        use pay_kit::mpp::protocol::solana::{
            default_token_program_for_currency, resolve_stablecoin_mint,
        };

        let network_str = cfg.network.as_str();
        let mint_str =
            resolve_stablecoin_mint(&cfg.currency, Some(network_str)).ok_or_else(|| {
                Error::SendNotConfigured(format!(
                    "redemption.currency `{}` resolves to native SOL — pick a stablecoin",
                    cfg.currency
                ))
            })?;
        let token_program_str =
            default_token_program_for_currency(&cfg.currency, Some(network_str));

        let mint = Pubkey::from_str(mint_str).map_err(|_| {
            Error::SendNotConfigured(format!(
                "redemption.currency `{}` resolved to an unparseable mint",
                cfg.currency
            ))
        })?;
        let token_program =
            Pubkey::from_str(token_program_str).expect("pay-kit program ids are valid pubkeys");

        // Every stablecoin pay-kit knows about on Solana is 6-decimals.
        // Hardcoded so we don't have to pull `getMint` at boot.
        const STABLECOIN_DECIMALS: u8 = 6;

        let mut grants = HashMap::new();
        for code in &cfg.codes {
            grants.insert(
                code.clone(),
                RedemptionGrant {
                    campaign_id: "legacy".to_string(),
                    amount: cfg.amount,
                },
            );
        }
        for campaign in cfg.campaigns.iter().filter(|campaign| campaign.enabled) {
            for code in &campaign.codes {
                grants.insert(
                    code.clone(),
                    RedemptionGrant {
                        campaign_id: campaign.id.clone(),
                        amount: campaign.amount,
                    },
                );
            }
        }
        let http_client = reqwest::Client::builder()
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest::Client builds with default tls");

        Ok(Self {
            enabled: cfg.enabled,
            mint,
            token_program,
            decimals: STABLECOIN_DECIMALS,
            network: cfg.network,
            solana_rpc_api_key: cfg.solana_rpc_api_key.clone(),
            helius_base: cfg.helius_base.clone(),
            max_scan_pages: cfg.max_scan_pages.unwrap_or(DEFAULT_MAX_SCAN_PAGES),
            grants,
            http_client,
            in_flight: Arc::new(Mutex::new(HashSet::new())),
        })
    }
}

// ── In-flight guard ───────────────────────────────────────────────────────

/// RAII guard that releases the in-flight slot for a code on Drop.
/// `acquire` returns `Err(())` if the code is already in flight on this
/// instance, which the handler converts to 409.
struct InFlightGuard {
    set: Arc<Mutex<HashSet<String>>>,
    code: String,
}

impl InFlightGuard {
    fn acquire(set: &Arc<Mutex<HashSet<String>>>, code: &str) -> Result<Self, ()> {
        let mut guard = set.lock().expect("in_flight mutex poisoned");
        if !guard.insert(code.to_string()) {
            return Err(());
        }
        Ok(Self {
            set: set.clone(),
            code: code.to_string(),
        })
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.set.lock() {
            guard.remove(&self.code);
        }
    }
}

// ── ATA idempotent-create helper ──────────────────────────────────────────
//
// `pay_api_core::ata` exports the program id + address derivation; we
// only need the small instruction builder, which the rest of pay-api
// doesn't have a use for yet.

/// `CreateIdempotent` instruction (discriminator = 1, no payload).
fn create_associated_token_account_idempotent_ix(
    funding: &Pubkey,
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Instruction {
    let ata = associated_token_address(owner, mint, token_program);
    Instruction {
        program_id: ATA_PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(*funding, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(*owner, false),
            AccountMeta::new_readonly(*mint, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![1],
    }
}

// ── Response helpers ──────────────────────────────────────────────────────

fn err_resp(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "error": message }))).into_response()
}

fn err_resp_with_extra(status: StatusCode, message: &str, extra: serde_json::Value) -> Response {
    let mut body = json!({ "error": message });
    if let (Some(obj), Some(extra_obj)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::{RedemptionGrant, RedemptionState};
    use crate::config::{RedemptionCampaignConfig, RedemptionConfig};

    #[test]
    fn resolves_codes_to_campaign_specific_grants() {
        let cfg = RedemptionConfig {
            enabled: true,
            amount: 5_000_000,
            codes: vec!["LEGACY123".to_string()],
            campaigns: vec![
                RedemptionCampaignConfig {
                    id: "anthropic-tokyo-Q2-2026".to_string(),
                    enabled: true,
                    amount: 5_000_000,
                    codes: vec!["TOKYO123".to_string()],
                },
                RedemptionCampaignConfig {
                    id: "superteam-uk-Q3-2026".to_string(),
                    enabled: true,
                    amount: 50_000_000,
                    codes: vec!["SUPER123".to_string()],
                },
                RedemptionCampaignConfig {
                    id: "disabled-campaign".to_string(),
                    enabled: false,
                    amount: 100_000_000,
                    codes: vec!["OFFLINE1".to_string()],
                },
            ],
            ..RedemptionConfig::default()
        };

        let state = RedemptionState::from_config(&cfg).expect("redemption state should resolve");

        assert_eq!(
            state.grants.get("LEGACY123"),
            Some(&RedemptionGrant {
                campaign_id: "legacy".to_string(),
                amount: 5_000_000,
            })
        );
        assert_eq!(
            state.grants.get("TOKYO123"),
            Some(&RedemptionGrant {
                campaign_id: "anthropic-tokyo-Q2-2026".to_string(),
                amount: 5_000_000,
            })
        );
        assert_eq!(
            state.grants.get("SUPER123"),
            Some(&RedemptionGrant {
                campaign_id: "superteam-uk-Q3-2026".to_string(),
                amount: 50_000_000,
            })
        );
        assert!(!state.grants.contains_key("OFFLINE1"));
    }
}
