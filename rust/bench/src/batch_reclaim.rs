//! One-off recovery for x402 batch-settlement channels a bench run couldn't
//! close (e.g. the run was killed mid-flight, or `close_after_run` was off).
//! Scans the shared payment-channels program on-chain for this fixture's
//! channels and drives them through:
//!
//!   request_close -> wait (grace period) -> finalize_close (seal+distribute)
//!   -> wait (open-slot window) -> reclaim (rent back to the operator)
//!
//! No gateway/x402 protocol involved: these are plain on-chain instructions,
//! and we hold both the deterministic payer keys and the operator's fee-payer
//! key directly, so there's no need to go through the HTTP refund flow a live
//! bench run uses. `finalize_close`/`reclaim` reuse pay-kit's own server-side
//! implementations (`X402BatchSettlement`) against a throwaway, empty channel
//! store — its post-broadcast store bookkeeping will error (the store never
//! saw these channels), but that's after the on-chain transaction already
//! landed, so the error is logged and ignored; success is verified by
//! re-scanning on-chain status afterward, not by that bookkeeping call.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use pay_kit::core::payment_channels as pc;
use pay_kit::core::store::MemoryChannelStore;
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_kit::x402::server::batch_settlement::{BatchConfig, X402BatchSettlement};
use solana_pubkey::Pubkey;

use crate::channel_recovery::{
    CHANNEL_ACCOUNT_SIZE, CHANNEL_STATUS_OFFSET, decode_payer, signed_transaction,
    submit_transactions,
};
use crate::config::RunConfig;
use crate::fixture_rpc::{ExecutionConfig, FixtureRpc};
use crate::fixtures;
use crate::wallet::{self, Wallet};

const STATUS_OPEN: u8 = 0;
const STATUS_CLOSING: u8 = 2;
const STATUS_DISTRIBUTED: u8 = 3;

/// Seconds to wait after `request_close` before `finalize_close` is
/// permitted — a little over the program's `DEFAULT_GRACE_PERIOD_SECONDS`
/// (900s) to absorb clock skew against the validator.
const GRACE_WAIT_SECS: u64 = 960;
/// Seconds to wait after `finalize_close` before `reclaim` is permitted — a
/// little over `OPEN_SLOT_WINDOW` (1500 slots) at ~450ms/slot.
const SLOT_WAIT_SECS: u64 = 780;

struct OwnedChannel {
    address: Pubkey,
    payer: Pubkey,
}

pub async fn recover_batch(
    config_path: &str,
    fixture_id: &str,
    users: usize,
    receiver: &str,
    concurrency: usize,
    yes: bool,
) -> Result<()> {
    if !yes {
        bail!("batch-reclaim submits real on-chain transactions; pass --yes to confirm");
    }

    let cfg = RunConfig::from_yaml_path(config_path)?;
    let rpc_url = cfg
        .resolve_rpc_url()?
        .context("config has no resolvable RPC URL")?;
    let funder = wallet::load_funder(&cfg.run.funder, cfg.run.network)?;
    let mint = cfg
        .run
        .mint
        .clone()
        .context("config.run.mint is required (the channel token)")?;
    let program_id = pc::default_program_id();

    // The fixture's wallet-derivation namespace can differ from `fixture_id`
    // itself (`setup.wallet_set_id` in the journal) — the same resolution
    // `bench run` applies, or every derived key here is silently wrong and
    // the on-chain scan below matches nothing.
    let wallet_set_id = fixtures::validate_ready_fixture(fixture_id, &cfg, &funder)?;
    println!(
        "deriving {users} fixture wallets for `{fixture_id}` (wallet set `{wallet_set_id}`)..."
    );
    let mut wallets: HashMap<Pubkey, Wallet> = HashMap::with_capacity(users);
    for i in 0..users as u32 {
        let w = wallet::derive_user(&funder.seed(), &wallet_set_id, i);
        wallets.insert(w.pubkey, w);
    }

    let discovery = pay_api_core::RpcClient::new(Duration::from_secs(30))?;
    // The default rpc_requests_per_second (20) is tuned to keep a live load
    // run polite to devnet; left unset here it throttles this one-off,
    // human-supervised recovery run to `concurrency` in name only. Scale it
    // with `concurrency` so a large stranded-channel backlog actually drains
    // in a supervised session instead of hours regardless of --concurrency.
    let execution = ExecutionConfig {
        submit_concurrency: concurrency,
        rpc_requests_per_second: concurrency as u32,
        rpc_burst: concurrency.saturating_mul(2),
        ..ExecutionConfig::default()
    };
    let rpc = FixtureRpc::new(rpc_url.clone(), execution);

    // Phase 1: request_close on every OPEN channel we own.
    let opened = scan_owned(&discovery, &rpc_url, &program_id, STATUS_OPEN, &wallets).await?;
    println!("phase 1: {} open channels to close", opened.len());
    if !opened.is_empty() {
        request_close_all(&rpc, &program_id, &opened, &wallets, &funder, concurrency).await?;
    }

    println!("waiting {GRACE_WAIT_SECS}s for the close grace period...");
    tokio::time::sleep(Duration::from_secs(GRACE_WAIT_SECS)).await;

    // Phase 2: finalize_close (seal + distribute) on due CLOSING channels.
    let operator_signer: Arc<dyn SolanaSigner> =
        Arc::new(MemorySigner::from_bytes(&funder.keypair).context("operator signer")?);
    let mut batch_config = BatchConfig::new(receiver, "devnet", operator_signer);
    batch_config.currency = mint;
    batch_config.rpc_url = Some(rpc_url.clone());
    let batch = X402BatchSettlement::with_store(batch_config, Arc::new(MemoryChannelStore::new()))?;

    let closing = scan_owned(&discovery, &rpc_url, &program_id, STATUS_CLOSING, &wallets).await?;
    println!("phase 2: {} closing channels to finalize", closing.len());
    for chunk in closing.chunks(50) {
        let ids: Vec<String> = chunk.iter().map(|c| c.address.to_string()).collect();
        if let Err(e) = batch.finalize_close(&ids).await {
            eprintln!(
                "finalize_close chunk of {}: {e:#} (on-chain likely still landed; verified by re-scan)",
                ids.len()
            );
        }
    }

    println!("waiting {SLOT_WAIT_SECS}s for the open-slot window...");
    tokio::time::sleep(Duration::from_secs(SLOT_WAIT_SECS)).await;

    // Phase 3: reclaim rent on DISTRIBUTED channels past the window.
    let distributed = scan_owned(
        &discovery,
        &rpc_url,
        &program_id,
        STATUS_DISTRIBUTED,
        &wallets,
    )
    .await?;
    println!(
        "phase 3: {} distributed channels to reclaim",
        distributed.len()
    );
    for chunk in distributed.chunks(50) {
        let ids: Vec<String> = chunk.iter().map(|c| c.address.to_string()).collect();
        if let Err(e) = batch.reclaim(&ids).await {
            eprintln!(
                "reclaim chunk of {}: {e:#} (on-chain likely still landed; verify operator balance)",
                ids.len()
            );
        }
    }

    println!("done. Check the operator's SOL balance to confirm rent was returned.");
    Ok(())
}

/// Fetch every account of the shared payment-channels program at `status`,
/// and keep only the ones whose `payer` is one of ours.
async fn scan_owned(
    rpc: &pay_api_core::RpcClient,
    rpc_url: &str,
    program_id: &Pubkey,
    status: u8,
    wallets: &HashMap<Pubkey, Wallet>,
) -> Result<Vec<OwnedChannel>> {
    let accounts = rpc
        .get_program_accounts_filtered(
            rpc_url,
            &program_id.to_string(),
            CHANNEL_ACCOUNT_SIZE,
            CHANNEL_STATUS_OFFSET,
            &[status],
        )
        .await
        .with_context(|| format!("scanning channels at status {status}"))?;

    let mut owned = Vec::new();
    for account in accounts {
        let Some(payer) = decode_payer(&account.data) else {
            continue;
        };
        if wallets.contains_key(&payer) {
            let Ok(address) = Pubkey::from_str(&account.pubkey) else {
                continue;
            };
            owned.push(OwnedChannel { address, payer });
        }
    }
    Ok(owned)
}

async fn request_close_all(
    rpc: &FixtureRpc,
    program_id: &Pubkey,
    channels: &[OwnedChannel],
    wallets: &HashMap<Pubkey, Wallet>,
    funder: &Wallet,
    concurrency: usize,
) -> Result<()> {
    for batch in channels.chunks(concurrency) {
        let (blockhash, _) = rpc.latest_blockhash().await?;
        let mut transactions = Vec::with_capacity(batch.len());
        for owned in batch {
            let payer_wallet = wallets
                .get(&owned.payer)
                .expect("scan_owned only keeps channels we derived");
            let instruction =
                pc::build_request_close_instruction(&owned.payer, &owned.address, program_id);
            let transaction =
                signed_transaction(funder, &[payer_wallet], vec![instruction], blockhash).await?;
            transactions.push((format!("channel {}", owned.address), transaction));
        }
        submit_transactions(rpc, transactions, concurrency, "request_close batch").await?;
    }
    Ok(())
}
