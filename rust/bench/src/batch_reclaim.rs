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
//! bench run uses. `seal`/`distribute`/`reclaim` require no signature but the
//! operator's (they're permissionless lifecycle operations any holder of the
//! fee-payer key can always invoke), so finalize/reclaim submit through the
//! same bulk `FixtureRpc` pipeline as `request_close` — its `TxPipeline` runs
//! one shared confirmation tracker that batches `getSignatureStatuses` across
//! every in-flight transaction, decoupling submission rate from per-transaction
//! confirm-wait latency. `pay_kit`'s own `X402BatchSettlement::finalize_close`/
//! `reclaim` submit one transaction at a time instead (each a full blocking
//! send-and-confirm round trip), which doesn't scale to hundreds of thousands
//! of channels.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use pay_kit::core::payment_channels as pc;
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
    ensure!(concurrency > 0, "batch-reclaim concurrency must be > 0");
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
    let mint = Pubkey::from_str(&mint).context("config.run.mint is not a valid pubkey")?;
    let receiver = Pubkey::from_str(receiver).context("--receiver is not a valid pubkey")?;
    let program_id = pc::default_program_id();
    let treasury = pc::treasury_owner_for_cluster("devnet");

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
    let token_program = rpc
        .accounts(&[mint])
        .await?
        .into_iter()
        .next()
        .flatten()
        .context("channel mint account not found")?
        .owner;

    // Phase 1: request_close on every OPEN channel we own.
    let opened = scan_owned(&discovery, &rpc_url, &program_id, STATUS_OPEN, &wallets).await?;
    println!("phase 1: {} open channels to close", opened.len());
    if !opened.is_empty() {
        request_close_all(&rpc, &program_id, &opened, &wallets, &funder, concurrency).await?;
    }

    if opened.is_empty() {
        // Nothing here started a fresh grace period this run — any CLOSING
        // channels were already closed by an earlier invocation (crash
        // recovery, or a previous run of this tool). finalize_close skips
        // whatever isn't past its own on-chain due time yet, so there's
        // nothing this fixed wait would protect against.
        println!("phase 1 closed nothing new; skipping the grace-period wait");
    } else {
        println!("waiting {GRACE_WAIT_SECS}s for the close grace period...");
        tokio::time::sleep(Duration::from_secs(GRACE_WAIT_SECS)).await;
    }

    // Phase 2: finalize (seal + distribute) on CLOSING channels we own.
    // Channels not yet past their on-chain grace period simply fail that
    // instruction (no fund-safety issue) rather than being pre-filtered —
    // the wait above already covers the common case (this run's own closes).
    let closing = scan_owned(&discovery, &rpc_url, &program_id, STATUS_CLOSING, &wallets).await?;
    println!("phase 2: {} closing channels to finalize", closing.len());
    if !closing.is_empty() {
        finalize_close_all(
            &rpc,
            &program_id,
            &closing,
            &funder,
            &mint,
            &token_program,
            &treasury,
            &receiver,
            concurrency,
        )
        .await?;
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
    if !distributed.is_empty() {
        reclaim_all(&rpc, &program_id, &distributed, &funder, concurrency).await?;
    }

    println!("done. Check the operator's SOL balance to confirm rent was returned.");
    Ok(())
}

/// `pay_api_core::RpcClient` has no retry policy of its own (unlike
/// `FixtureRpc`), and a getProgramAccounts scan over ~500k channel accounts
/// is a large enough single response that a transient connection reset from
/// a public devnet RPC is routine, not exceptional. Retry a bounded number
/// of times with a short fixed delay rather than aborting the whole recovery
/// run over one dropped connection.
const SCAN_MAX_ATTEMPTS: usize = 5;
const SCAN_RETRY_DELAY: Duration = Duration::from_secs(5);

/// Fetch every account of the shared payment-channels program at `status`,
/// and keep only the ones whose `payer` is one of ours.
async fn scan_owned(
    rpc: &pay_api_core::RpcClient,
    rpc_url: &str,
    program_id: &Pubkey,
    status: u8,
    wallets: &HashMap<Pubkey, Wallet>,
) -> Result<Vec<OwnedChannel>> {
    let mut accounts = None;
    for attempt in 1..=SCAN_MAX_ATTEMPTS {
        match rpc
            .get_program_accounts_filtered(
                rpc_url,
                &program_id.to_string(),
                CHANNEL_ACCOUNT_SIZE,
                CHANNEL_STATUS_OFFSET,
                &[status],
            )
            .await
        {
            Ok(result) => {
                accounts = Some(result);
                break;
            }
            Err(error) if attempt < SCAN_MAX_ATTEMPTS => {
                eprintln!(
                    "scanning channels at status {status}: attempt {attempt}/{SCAN_MAX_ATTEMPTS} failed ({error:#}), retrying in {}s",
                    SCAN_RETRY_DELAY.as_secs()
                );
                tokio::time::sleep(SCAN_RETRY_DELAY).await;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("scanning channels at status {status} ({SCAN_MAX_ATTEMPTS} attempts)")
                });
            }
        }
    }
    let accounts = accounts.expect("loop only exits via break(Some) or early return");

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

/// `seal` + `distribute` per channel, funder-signed only: both are
/// permissionless lifecycle instructions the operator (fee payer) can always
/// invoke, so unlike `request_close_all` there's no per-channel payer
/// signature to gather.
#[allow(clippy::too_many_arguments)]
async fn finalize_close_all(
    rpc: &FixtureRpc,
    program_id: &Pubkey,
    channels: &[OwnedChannel],
    funder: &Wallet,
    mint: &Pubkey,
    token_program: &Pubkey,
    treasury: &Pubkey,
    receiver: &Pubkey,
    concurrency: usize,
) -> Result<()> {
    let recipients = pc::sole_recipient(receiver);
    for batch in channels.chunks(concurrency) {
        let (blockhash, _) = rpc.latest_blockhash().await?;
        let mut transactions = Vec::with_capacity(batch.len());
        for owned in batch {
            let instructions = vec![
                pc::build_seal_instruction(&owned.address, program_id),
                pc::build_distribute_instruction(
                    &owned.address,
                    &owned.payer,
                    &funder.pubkey,
                    &funder.pubkey,
                    treasury,
                    mint,
                    &recipients,
                    token_program,
                    program_id,
                ),
            ];
            let transaction = signed_transaction(funder, &[], instructions, blockhash).await?;
            transactions.push((format!("channel {}", owned.address), transaction));
        }
        // A channel here can permanently fail distribute (e.g. one opened
        // under an earlier, incompatible protocol revision whose committed
        // distribution_hash this build can never reproduce) — don't let a
        // batch containing one abort every other batch behind it in the
        // sweep; submit_transactions already logs the per-channel detail.
        if let Err(e) =
            submit_transactions(rpc, transactions, concurrency, "finalize_close batch").await
        {
            eprintln!("{e:#}");
        }
    }
    Ok(())
}

/// `reclaim` per channel, funder-signed only: permissionless, same as above.
async fn reclaim_all(
    rpc: &FixtureRpc,
    program_id: &Pubkey,
    channels: &[OwnedChannel],
    funder: &Wallet,
    concurrency: usize,
) -> Result<()> {
    for batch in channels.chunks(concurrency) {
        let (blockhash, _) = rpc.latest_blockhash().await?;
        let mut transactions = Vec::with_capacity(batch.len());
        for owned in batch {
            let instruction =
                pc::build_reclaim_instruction(&owned.address, &funder.pubkey, program_id);
            let transaction = signed_transaction(funder, &[], vec![instruction], blockhash).await?;
            transactions.push((format!("channel {}", owned.address), transaction));
        }
        if let Err(e) = submit_transactions(rpc, transactions, concurrency, "reclaim batch").await {
            eprintln!("{e:#}");
        }
    }
    Ok(())
}
