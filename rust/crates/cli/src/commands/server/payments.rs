//! Shared payment-stack machinery for the gateway commands.
//!
//! `pay server start` and `pay serve inference --price`/`--pricing` build the
//! same sandbox charge stack: an auto/ephemeral fee-payer signer, localnet RPC
//! resolution, Surfpool wallet funding + payout-recipient ATA preparation,
//! the shared recent-blockhash cache, the charge HMAC secret (mirrored into
//! `MPP_CHALLENGE_BINDING_SECRET`), and the per-currency [`Mpp`] servers.
//! Everything here is behavior moved verbatim out of `start.rs` so the two
//! commands can't drift.

use std::str::FromStr;
use std::sync::Arc;

use pay_kit::mpp::server::Mpp;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_types::Stablecoin;
use pay_types::metering::SignerConfig;

use crate::network::SolanaNetwork;

pub(crate) const AUTO_OPERATOR_ACCOUNT_NAME: &str = "gateway";

pub(crate) fn should_use_auto_fee_payer_signer(
    sandbox: bool,
    network: &SolanaNetwork,
    signer_cfg: Option<&SignerConfig>,
) -> bool {
    sandbox || (signer_cfg.is_none() && network.is_throwaway())
}

/// `(account_name, pubkey)` of a freshly generated gateway ephemeral.
pub(crate) type GeneratedGatewayAccount = (String, String);

/// Load the auto/ephemeral gateway fee-payer signer for `network`.
///
/// This is the `--sandbox` / throwaway-network smart-default path: a
/// dedicated per-network `gateway` ephemeral from accounts.yml (minted on
/// first use). Returns the signer plus `Some((account_name, pubkey))` when a
/// new account was generated, so the caller can surface it in its banner.
pub(crate) fn load_auto_fee_payer_signer(
    network: &SolanaNetwork,
) -> pay_core::Result<(Arc<dyn SolanaSigner>, Option<GeneratedGatewayAccount>)> {
    let auto_network = network.slug();
    let store = pay_core::accounts::FileAccountsStore::default_path();
    let _ = pay_core::accounts::load_or_create_exact_ephemeral_for_network_as(
        auto_network,
        pay_core::accounts::DEFAULT_ACCOUNT_NAME,
        &store,
    )?;
    let (signer, ephemeral_notice) = pay_core::signer::load_signer_for_network_with_reason(
        auto_network,
        &store,
        Some(AUTO_OPERATOR_ACCOUNT_NAME),
        "use your pay account as the gateway fee payer",
    )?;
    let generated = ephemeral_notice.map(|resolved| {
        (
            resolved.account_name,
            resolved.account.pubkey.unwrap_or_else(|| "?".to_string()),
        )
    });
    Ok((Arc::new(signer) as Arc<dyn SolanaSigner>, generated))
}

/// Sandbox RPC URL fallback chain.
///
/// In sandbox the spec's `operator.rpc_url` is deliberately dropped from the
/// chain — a devnet/mainnet URL in a YAML must not be able to pull the
/// pinned-localnet sandbox onto a real cluster. An explicit CLI `--rpc-url` /
/// `PAY_RPC_URL` is still honored so a local `solana-test-validator` works;
/// otherwise this resolves to the hosted Surfpool sandbox (where ephemeral
/// wallets can be auto-created and auto-funded).
pub(crate) fn resolve_sandbox_rpc_url(cli_rpc_url: Option<String>) -> String {
    cli_rpc_url
        .or_else(|| std::env::var("PAY_RPC_URL").ok())
        .unwrap_or_else(|| SolanaNetwork::Localnet.default_rpc_url(true))
}

pub(crate) fn resolve_currency(currency: &str, network: &str) -> (String, u8) {
    let currency = currency.trim();
    if currency.eq_ignore_ascii_case("SOL") {
        return ("sol".to_string(), 9);
    }
    if let Some(stablecoin) = Stablecoin::parse_symbol(currency) {
        return (stablecoin.mint(Some(network)).to_string(), 6);
    }
    (currency.to_string(), 6)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct StableTokenAccountRequirement {
    pub(crate) label: String,
    pub(crate) mint: String,
    pub(crate) token_program: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SurfpoolFundingTarget {
    pub(crate) label: &'static str,
    pub(crate) address: String,
    pub(crate) requires_sol: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PayoutRecipientTarget {
    pub(crate) label: String,
    pub(crate) pubkey: solana_pubkey::Pubkey,
}

pub(crate) fn surfpool_funding_targets(
    recipient: &str,
    operator_pubkey: Option<&str>,
) -> Vec<SurfpoolFundingTarget> {
    let mut targets = Vec::new();
    if let Some(operator_pubkey) = operator_pubkey {
        targets.push(SurfpoolFundingTarget {
            label: "operator signer",
            address: operator_pubkey.to_string(),
            requires_sol: true,
        });
    }
    if !targets.iter().any(|target| target.address == recipient) {
        targets.push(SurfpoolFundingTarget {
            label: "payment recipient",
            address: recipient.to_string(),
            requires_sol: false,
        });
    }
    targets
}

pub(crate) fn surfpool_prep_notice_body(
    rpc_url: &str,
    targets: &[SurfpoolFundingTarget],
    payout_recipients: &[PayoutRecipientTarget],
    stable_requirements: &[StableTokenAccountRequirement],
    auto_fund: bool,
) -> String {
    let mut lines = vec![format!("rpc: {rpc_url}")];
    for target in targets {
        let wallet_action = if auto_fund && target.requires_sol {
            "funding"
        } else {
            "checking"
        };
        let label = if target.requires_sol {
            target.label.to_string()
        } else {
            format!("{} (SOL optional)", target.label)
        };
        lines.push(format!("{wallet_action} {}: {}", label, target.address));
    }
    if !payout_recipients.is_empty() && !stable_requirements.is_empty() {
        let ata_action = if auto_fund {
            "creating missing"
        } else {
            "checking"
        };
        let tokens = stable_requirements
            .iter()
            .map(|requirement| requirement.label.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "{ata_action} ATAs for all configured stable tokens ({tokens}) across {} payout recipient(s):",
            payout_recipients.len()
        ));
        for recipient in payout_recipients {
            lines.push(format!("  {}: {}", recipient.label, recipient.pubkey));
        }
    }
    lines.join("\n")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FundingTargetBalance {
    pub(crate) address: String,
    pub(crate) lamports: u64,
}

/// Auto-fund local Surfpool wallets and validate the resulting balances.
///
/// Funding triggers when EITHER:
///   - the caller runs in `--sandbox` (explicit opt-in), or
///   - the resolved RPC URL points at Surfpool (the smart-default
///     `network: localnet` path lands here).
///
/// `fund_via_surfpool` deposits a fixed amount (100 SOL + 1000 USDC) so
/// calling it on every server start is idempotent and survives Surfpool
/// restarts (which would otherwise wipe the cheatcode-set balances).
///
/// When the RPC is a real cluster (mainnet/devnet/local validator), funding
/// is skipped silently — the operator is responsible for funding their own
/// wallet. Returns `(should_fund, balances)`; `should_fund` also gates
/// startup ATA creation downstream.
pub(crate) async fn prepare_funding_targets(
    sandbox: bool,
    network: &SolanaNetwork,
    rpc_url: &str,
    surfpool_targets: &[SurfpoolFundingTarget],
    payout_recipient_targets: &[PayoutRecipientTarget],
    stable_requirements: &[StableTokenAccountRequirement],
) -> pay_core::Result<(bool, Vec<FundingTargetBalance>)> {
    let looks_like_surfpool = rpc_url.contains("surfnet") || rpc_url.contains("surfpool");
    let should_fund = sandbox || looks_like_surfpool;
    if should_fund {
        crate::components::print_notice(
            crate::components::NoticeLevel::Info,
            "Preparing sandbox wallets",
            &surfpool_prep_notice_body(
                rpc_url,
                surfpool_targets,
                payout_recipient_targets,
                stable_requirements,
                true,
            ),
        );
        for target in surfpool_targets.iter().filter(|target| target.requires_sol) {
            if let Err(e) =
                pay_core::client::sandbox::fund_via_surfpool(rpc_url, &target.address).await
            {
                if looks_like_surfpool {
                    return Err(pay_core::Error::Config(format!(
                        "Sandbox funding failed\n{} {}\n{}\n\n\
                         Startup aborted before accepting traffic.",
                        target.label, target.address, e
                    )));
                }
                crate::components::print_notice(
                    crate::components::NoticeLevel::Warning,
                    "Sandbox funding unavailable",
                    &format!(
                        "{} {}\n{}\n\nValidating existing balances instead.",
                        target.label, target.address, e
                    ),
                );
            }
        }
    } else {
        crate::components::print_notice(
            crate::components::NoticeLevel::Info,
            "Validating payment configuration",
            &surfpool_prep_notice_body(
                rpc_url,
                surfpool_targets,
                payout_recipient_targets,
                stable_requirements,
                false,
            ),
        );
    }

    let balances = validate_funding_target_balances(rpc_url, network, surfpool_targets).await?;
    Ok((should_fund, balances))
}

pub(crate) async fn validate_funding_target_balances(
    rpc_url: &str,
    network: &SolanaNetwork,
    targets: &[SurfpoolFundingTarget],
) -> pay_core::Result<Vec<FundingTargetBalance>> {
    let client = reqwest::Client::new();
    let mut balances = Vec::with_capacity(targets.len());
    for target in targets {
        let lamports = fetch_lamports(&client, rpc_url, &target.address).await?;
        if lamports == 0 {
            if target.requires_sol {
                return Err(pay_core::Error::Config(format!(
                    "{} wallet has 0 SOL\n{}\non `{network}` via {rpc_url}\n\n\
                     Startup aborted because payment configuration is not usable \
                     until this wallet exists on chain. Fund this address and \
                     restart the server.",
                    target.label, target.address
                )));
            }
            crate::components::print_notice(
                crate::components::NoticeLevel::Warning,
                "Payment recipient has 0 SOL",
                &format!(
                    "{}\non `{network}` via {rpc_url}\n\n\
                     Startup will continue because recipients do not sign or pay \
                     rent for stable token account creation.",
                    target.address
                ),
            );
        }
        balances.push(FundingTargetBalance {
            address: target.address.clone(),
            lamports,
        });
    }
    Ok(balances)
}

pub(crate) fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

/// Fetch a wallet's lamport balance via JSON-RPC.
async fn fetch_lamports(
    client: &reqwest::Client,
    rpc_url: &str,
    pubkey: &str,
) -> pay_core::Result<u64> {
    let resp = client
        .post(rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [pubkey]
        }))
        .send()
        .await
        .map_err(|e| {
            pay_core::Error::Config(format!(
                "Failed to fetch SOL balance for `{pubkey}` via {rpc_url}: {e}"
            ))
        })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(pay_core::Error::Config(format!(
            "Failed to fetch SOL balance for `{pubkey}` via {rpc_url}: HTTP {status}"
        )));
    }
    let value = resp.json::<serde_json::Value>().await.map_err(|e| {
        pay_core::Error::Config(format!(
            "Invalid getBalance response for `{pubkey}` via {rpc_url}: {e}"
        ))
    })?;
    if let Some(err) = value.get("error") {
        return Err(pay_core::Error::Config(format!(
            "getBalance failed for `{pubkey}` via {rpc_url}: {err}"
        )));
    }
    value["result"]["value"].as_u64().ok_or_else(|| {
        pay_core::Error::Config(format!(
            "getBalance response for `{pubkey}` via {rpc_url} did not include result.value"
        ))
    })
}

pub(crate) fn stable_token_account_requirements(
    currency_configs: &[(String, String, u8)],
    network: &str,
) -> pay_core::Result<Vec<StableTokenAccountRequirement>> {
    let mut requirements = Vec::new();
    for (label, mint, _decimals) in currency_configs {
        if Stablecoin::parse_symbol(label).is_none() && Stablecoin::from_mint(mint).is_none() {
            continue;
        }

        solana_pubkey::Pubkey::from_str(mint).map_err(|e| {
            pay_core::Error::Config(format!(
                "stable currency `{label}` resolved to invalid mint `{mint}`: {e}"
            ))
        })?;
        let token_program = pay_kit::mpp::protocol::solana::default_token_program_for_currency(
            label,
            Some(network),
        )
        .to_string();
        let requirement = StableTokenAccountRequirement {
            label: label.clone(),
            mint: mint.clone(),
            token_program,
        };
        if !requirements.contains(&requirement) {
            requirements.push(requirement);
        }
    }
    Ok(requirements)
}

pub(crate) async fn ensure_payout_recipient_token_accounts(
    recipients: &[solana_pubkey::Pubkey],
    stable_requirements: &[StableTokenAccountRequirement],
    network: &str,
    rpc_url: &str,
    allow_startup_creation: bool,
    fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
) -> pay_core::Result<()> {
    if recipients.is_empty() || stable_requirements.is_empty() {
        return Ok(());
    }

    let signer = if allow_startup_creation {
        Some(fee_payer_signer.ok_or_else(|| {
            pay_core::Error::Config(
                "stable payout recipient ATA setup requires an operator signer".to_string(),
            )
        })?)
    } else {
        None
    };
    let payer = signer.as_ref().map(|signer| signer.pubkey());
    let rpc = pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient::new(rpc_url.to_string());
    for recipient in recipients {
        for requirement in stable_requirements {
            let mint = solana_pubkey::Pubkey::from_str(&requirement.mint).map_err(|e| {
                pay_core::Error::Config(format!(
                    "stable mint `{}` is not a valid Solana pubkey: {e}",
                    requirement.mint
                ))
            })?;
            let token_program = solana_pubkey::Pubkey::from_str(&requirement.token_program)
                .map_err(|e| {
                    pay_core::Error::Config(format!(
                        "token program `{}` is not a valid Solana pubkey: {e}",
                        requirement.token_program
                    ))
                })?;
            let (ata, _) = pay_kit::mpp::program::payment_channels::find_associated_token_address(
                recipient,
                &mint,
                &token_program,
            );
            if rpc.get_account(&ata).is_ok() {
                continue;
            }

            if !allow_startup_creation {
                // TODO(mainnet): add an operator-funded creation command for
                // production clusters. Startup still aborts so no traffic is
                // served before payment config is fully usable.
                return Err(pay_core::Error::Config(format!(
                    "Missing stable token account for payout recipient\n\
                     recipient: {recipient}\n\
                     mint: {}\n\
                     ata: {ata}\n\
                     network: {network}\n\
                     rpc: {rpc_url}\n\n\
                     Create this associated token account, or use the Surfpool \
                     localnet sandbox where pay can create it automatically.",
                    requirement.mint
                )));
            }

            let signer = signer
                .as_ref()
                .expect("signer is present when startup creation is enabled");
            let payer = payer.expect("payer is present when startup creation is enabled");
            let ix = create_associated_token_account_idempotent_ix(
                &payer,
                recipient,
                &mint,
                &token_program,
            );
            sign_and_broadcast_gateway(signer.clone(), vec![ix], rpc_url).await?;
        }
    }

    Ok(())
}

pub(crate) fn create_associated_token_account_idempotent_ix(
    payer: &solana_pubkey::Pubkey,
    owner: &solana_pubkey::Pubkey,
    mint: &solana_pubkey::Pubkey,
    token_program: &solana_pubkey::Pubkey,
) -> solana_instruction::Instruction {
    pay_kit::mpp::program::payment_channels::build_create_associated_token_account_instruction(
        payer,
        owner,
        mint,
        token_program,
    )
}

async fn sign_and_broadcast_gateway(
    signer: Arc<dyn SolanaSigner>,
    instructions: Vec<solana_instruction::Instruction>,
    rpc_url: &str,
) -> pay_core::Result<String> {
    use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
    use solana_message::Message;
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    let url = rpc_url.to_string();
    let signer_pubkey = signer.pubkey();
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

    let message = Message::new_with_blockhash(&instructions, Some(&signer_pubkey), &blockhash);
    let mut tx = Transaction::new_unsigned(message);
    let msg_bytes = tx.message_data();
    let sig_bytes = signer
        .sign_message(&msg_bytes)
        .await
        .map_err(|e| pay_core::Error::Mpp(format!("Operator signing failed: {e}")))?;
    let signature = Signature::from(<[u8; 64]>::from(sig_bytes));

    let signer_index = tx
        .message
        .account_keys
        .iter()
        .position(|key| *key == signer_pubkey)
        .ok_or_else(|| pay_core::Error::Mpp("Operator pubkey absent from account_keys".into()))?;
    if tx.signatures.len() <= signer_index {
        return Err(pay_core::Error::Mpp(
            "Transaction signatures vec is shorter than account_keys".into(),
        ));
    }
    tx.signatures[signer_index] = signature;

    let serialized = bincode::serialize(&tx)
        .map_err(|e| pay_core::Error::Mpp(format!("Failed to serialise tx: {e}")))?;
    let confirmed_sig = tokio::task::spawn_blocking(move || {
        let rpc = RpcClient::new(url);
        let tx: Transaction = bincode::deserialize(&serialized)
            .map_err(|e| pay_core::Error::Mpp(format!("tx round-trip: {e}")))?;
        rpc.send_and_confirm_transaction(&tx)
            .map_err(|e| pay_core::Error::Mpp(format!("Broadcast failed: {e}")))
    })
    .await
    .map_err(|e| pay_core::Error::Mpp(format!("RPC task join: {e}")))??;

    Ok(confirmed_sig.to_string())
}

/// Resolve the charge HMAC secret and mirror it into
/// `MPP_CHALLENGE_BINDING_SECRET`.
///
/// The mirror is what the subscription middleware (which lazy-builds a
/// SubscriptionServer per request, with `challenge_binding_secret: None`)
/// picks up via the SDK's env fallback. Without this, the per-request
/// `SubscriptionServer::new` errors with "Missing
/// MPP_CHALLENGE_BINDING_SECRET env var".
///
/// SAFETY: must be called before any request-handler threads read the
/// environment (both gateways call it during startup, before serving).
pub(crate) fn init_challenge_binding_secret() -> String {
    let challenge_binding_secret = std::env::var("PAY_MPP_CHALLENGE_SECRET")
        .unwrap_or_else(|_| bs58::encode(rand::random::<[u8; 32]>()).into_string());
    unsafe {
        std::env::set_var("MPP_CHALLENGE_BINDING_SECRET", &challenge_binding_secret);
    }
    challenge_binding_secret
}

/// Shared recent-blockhash cache, refreshed by a background thread.
///
/// Issuing a 402 embeds a `recentBlockhash` per advertised currency and
/// scheme; fetching it inline turned one 402 into N blocking RPC round-trips
/// (the dominant challenge latency). The handlers read this cache and only
/// fall back to a direct fetch when it's empty or stale, so it's purely a
/// latency optimization — the wire payload is unchanged.
pub(crate) fn spawn_blockhash_cache(rpc_url: &str) -> pay_kit::mpp::blockhash::BlockhashCache {
    use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;

    let blockhash_cache = pay_kit::mpp::blockhash::BlockhashCache::new();
    let cache = blockhash_cache.clone();
    let worker_rpc_url = rpc_url.to_string();
    let refresh = move || {
        let rpc = RpcClient::new(worker_rpc_url.clone());
        // Fetch blockhash + lastValidBlockHeight + slot in one RPC call:
        // getLatestBlockhash's response context carries the current slot, which
        // the epoch-addressed program needs as the challenge `recentSlot`
        // (channel `openSlot`) — no separate getSlot round-trip.
        match pay_kit::mpp::blockhash::fetch_blockhash_with_slot(&rpc, rpc.commitment()) {
            Ok(entry) => {
                cache.set(entry.blockhash, entry.last_valid_block_height, entry.slot);
            }
            Err(e) => {
                tracing::warn!(error = %e, "blockhash cache refresh failed");
            }
        }
    };
    // Prime once so the first 402 is already fast, then refresh on a
    // 10s interval — far inside the ~60-90s blockhash validity window
    // and the cache's 45s staleness cap.
    refresh();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(10));
            refresh();
        }
    });
    blockhash_cache
}

/// Build one MPP charge server per configured currency, all bound to the
/// same recipient/network/secret and sharing the blockhash cache.
#[allow(clippy::too_many_arguments)] // one call site per gateway command; a config struct would just rename the args
pub(crate) fn build_charge_mpps(
    currency_configs: &[(String, String, u8)],
    recipient: &str,
    network_slug: &str,
    rpc_url: &str,
    challenge_binding_secret: &str,
    fee_payer: bool,
    fee_payer_signer: Option<Arc<dyn SolanaSigner>>,
    blockhash_cache: &pay_kit::mpp::blockhash::BlockhashCache,
) -> pay_core::Result<Vec<Mpp>> {
    currency_configs
        .iter()
        .map(|(_, mpp_currency, decimals)| {
            Mpp::new(pay_kit::mpp::server::Config {
                recipient: recipient.to_string(),
                currency: mpp_currency.clone(),
                decimals: *decimals,
                network: network_slug.to_string(),
                rpc_url: Some(rpc_url.to_string()),
                challenge_binding_secret: Some(challenge_binding_secret.to_string()),
                fee_payer,
                fee_payer_signer: fee_payer_signer.clone(),
                html: true,
                ..Default::default()
            })
            .map(|m| m.with_blockhash_cache(blockhash_cache.clone()))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pay_core::Error::Config(format!("Failed to create MPP server: {e}")))
}

/// Build the x402 `upto` backend for the sandbox charge stack.
///
/// Mirrors `server start`'s upto wiring: an [`X402Upto`] built from the
/// operator (fee-payer) signer, the sandbox RPC, and the configured
/// currencies, sharing the same blockhash cache as the charge MPPs. In
/// sandbox inference the payout recipient IS the operator's own gateway
/// wallet, so the operator keeps the whole channel payout. Used by
/// `pay serve inference` per-token charging, where the settlement voucher is
/// signed post-response from the observed token usage.
pub(crate) fn build_sandbox_upto_backend(
    currency_configs: &[(String, String, u8)],
    recipient: &str,
    network_slug: &str,
    rpc_url: &str,
    resource: &str,
    fee_payer_signer: Arc<dyn SolanaSigner>,
    blockhash_cache: &pay_kit::mpp::blockhash::BlockhashCache,
) -> pay_core::Result<pay_kit::x402::server::X402Upto> {
    let receiver_authorizer = fee_payer_signer.pubkey().to_string();
    let payout = if recipient == receiver_authorizer {
        pay_kit::x402::server::UptoPayout::ReceiverKeepsAll
    } else {
        pay_kit::x402::server::UptoPayout::Beneficiary {
            address: recipient.to_string(),
        }
    };
    let currencies: Vec<pay_kit::x402::server::CurrencyConfig> = currency_configs
        .iter()
        .map(
            |(_symbol, mint, decimals)| pay_kit::x402::server::CurrencyConfig {
                currency: mint.clone(),
                decimals: *decimals,
                token_program: None,
            },
        )
        .collect();
    let cfg = pay_kit::x402::server::UptoConfig {
        payout,
        currencies,
        cluster: network_slug.to_string(),
        rpc_url: Some(rpc_url.to_string()),
        resource: resource.to_string(),
        description: None,
        max_timeout_seconds: 300,
        program_id: None,
        withdraw_delay: 0,
        fee_payer_signer,
        receiver_authorizer_signer: None,
    };
    pay_kit::x402::server::X402Upto::new(cfg)
        .map(|u| u.with_blockhash_cache(blockhash_cache.clone()))
        .map_err(|e| pay_core::Error::Config(format!("Failed to create x402 upto backend: {e}")))
}
