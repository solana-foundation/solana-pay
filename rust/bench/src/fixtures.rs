//! Reusable public-cluster fixture provisioning.
//!
//! A fixture derives every test wallet from one funder seed plus a stable
//! setup ID. `setup` is safe to resume because it reconciles each derived ATA
//! to its requested balance before transferring the difference; `teardown`
//! re-derives the same wallets, returns their tokens, and closes their ATAs so
//! the funder recovers rent.

use std::str::FromStr;
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use futures::{StreamExt, TryStreamExt};
use pay_kit::mpp::solana_keychain::{SolanaSigner, memory::MemorySigner};
use serde::Deserialize;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use spl_token_2022_interface::extension::StateWithExtensions;
use spl_token_2022_interface::instruction as token_instruction;
use spl_token_2022_interface::state::Account as TokenAccount;
use tokio_util::sync::CancellationToken;

use crate::config::{FunderCfg, Network, RunConfig};
use crate::fixture_rpc::{ExecutionConfig, FixtureRpc};
use crate::journal::{
    FixtureAsset, FixtureJournal, FixturePhase, FixtureState, PendingTransaction,
};
use crate::wallet::{Wallet, derive_user, load_funder};

/// A conservative public-cluster transaction-fee allowance for each setup
/// transaction. Actual fees are RPC-controlled, so this is a preflight floor,
/// not a fee quote.
const SETUP_FEE_ALLOWANCE_LAMPORTS: u64 = 10_000;

struct PreparedUser {
    index: usize,
    wallet: Wallet,
    instructions: Vec<Instruction>,
}

#[derive(Clone, Copy)]
struct SetupWindow<'a> {
    rpc: &'a FixtureRpc,
    funder: &'a Wallet,
    seed: &'a [u8; 32],
    wallet_set_id: &'a str,
    sol_lamports: u64,
    assets: &'a [FixtureAsset],
}

#[derive(Clone, Copy)]
struct TeardownWindow<'a> {
    rpc: &'a FixtureRpc,
    funder: &'a Wallet,
    seed: &'a [u8; 32],
    wallet_set_id: &'a str,
    assets: &'a [FixtureAsset],
}

/// A standalone YAML file purpose-built for setup/teardown. It is deliberately
/// separate from the request-load config: fixture allocation is an explicit,
/// reviewable spend plan rather than an incidental side effect of load shape.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupConfig {
    pub setup: SetupMeta,
    pub assets: Vec<AssetConfig>,
    #[serde(default)]
    pub execution: ExecutionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupMeta {
    pub name: String,
    /// Optional derivation namespace shared with another fixture. This lets a
    /// new asset reuse an existing deterministic wallet cohort while keeping
    /// its own independent setup/teardown journal.
    #[serde(default)]
    pub wallet_set_id: Option<String>,
    pub network: Network,
    #[serde(default)]
    pub rpc_url_env: Option<String>,
    #[serde(default)]
    pub rpc_url: Option<String>,
    #[serde(default)]
    pub funder: FunderCfg,
    pub users: usize,
    #[serde(default)]
    pub sol_lamports_per_user: u64,
    /// Hard ceiling for the SOL allocation plus estimated ATA rent. This is
    /// checked before the first transaction is submitted.
    pub max_total_sol: f64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetConfig {
    /// Human label shown in progress and stored in the fixture journal.
    pub label: String,
    /// Explicit mint; never silently substitute a mainnet mint on devnet.
    pub mint: String,
    /// SPL Token or Token-2022 program owning the mint.
    pub token_program: String,
    pub decimals: u8,
    /// Exact human amount allocated to each derived wallet, e.g. `"0.01"`.
    pub amount_per_user: String,
    /// Per-asset hard ceiling, expressed with the same decimal precision.
    pub max_total_amount: String,
}

impl SetupConfig {
    pub fn from_yaml_path(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
        let cfg: Self = serde_yml::from_str(&raw).with_context(|| format!("parsing {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.setup.users > 0, "setup.users must be > 0");
        if let Some(id) = &self.setup.wallet_set_id {
            validate_setup_id(id).context("invalid setup.wallet_set_id")?;
        }
        ensure!(
            self.setup.max_total_sol.is_finite() && self.setup.max_total_sol >= 0.0,
            "setup.max_total_sol must be a finite number >= 0"
        );
        ensure!(!self.assets.is_empty(), "at least one asset is required");
        self.execution.validate()?;
        ensure!(
            self.setup.network != Network::Fork,
            "fixture setup requires devnet or mainnet; use `bench rehearse` for a fork"
        );
        for asset in &self.assets {
            ensure!(
                !asset.label.trim().is_empty(),
                "asset.label cannot be empty"
            );
            Pubkey::from_str(&asset.mint)
                .with_context(|| format!("asset `{}` has an invalid mint", asset.label))?;
            Pubkey::from_str(&asset.token_program)
                .with_context(|| format!("asset `{}` has an invalid token_program", asset.label))?;
            let amount = decimal_to_base(&asset.amount_per_user, asset.decimals)?;
            let cap = decimal_to_base(&asset.max_total_amount, asset.decimals)?;
            let total = amount
                .checked_mul(self.setup.users as u64)
                .context("asset total overflow")?;
            ensure!(
                total <= cap,
                "asset `{}` needs {} base units, exceeding max_total_amount `{}`",
                asset.label,
                total,
                asset.max_total_amount
            );
        }
        Ok(())
    }

    fn resolve_rpc_url(&self) -> Result<String> {
        if let Some(url) = &self.setup.rpc_url {
            return Ok(url.clone());
        }
        let var = self
            .setup
            .rpc_url_env
            .as_ref()
            .context("setup needs rpc_url or rpc_url_env")?;
        std::env::var(var).with_context(|| format!("rpc_url_env `{var}` is not set"))
    }

    fn journal_assets(&self) -> Result<Vec<FixtureAsset>> {
        self.assets
            .iter()
            .map(|asset| {
                Ok(FixtureAsset {
                    label: asset.label.clone(),
                    mint: asset.mint.clone(),
                    token_program: asset.token_program.clone(),
                    decimals: asset.decimals,
                    amount_base: decimal_to_base(&asset.amount_per_user, asset.decimals)?,
                })
            })
            .collect()
    }
}

/// Create or resume a deterministic fixture set.
pub async fn setup(config_path: &str, id: Option<&str>, yes: bool) -> Result<()> {
    let config = SetupConfig::from_yaml_path(config_path)?;
    require_confirmation(yes, "setup")?;
    let rpc_url = config.resolve_rpc_url()?;
    let rpc = FixtureRpc::new(rpc_url.clone(), config.execution.clone());
    let funder = load_funder(&config.setup.funder, config.setup.network)?;
    let setup_id = id
        .map(str::to_owned)
        .unwrap_or_else(|| new_setup_id(&config.setup.name));
    validate_setup_id(&setup_id)?;
    let assets = config.journal_assets()?;

    let mut journal = if FixtureJournal::exists(&setup_id)? {
        let existing = FixtureJournal::load(&setup_id)?;
        ensure_same_fixture(existing.state(), &config, &funder, &assets)?;
        existing
    } else {
        let now = chrono::Utc::now().to_rfc3339();
        FixtureJournal::create(FixtureState {
            setup_id: setup_id.clone(),
            wallet_set_id: config.setup.wallet_set_id.clone(),
            name: config.setup.name.clone(),
            network: config.setup.network,
            funder_pubkey: funder.pubkey.to_string(),
            users: config.setup.users,
            sol_lamports_per_user: config.setup.sol_lamports_per_user,
            assets: assets.clone(),
            phase: FixturePhase::SettingUp,
            next_user: 0,
            pending: Vec::new(),
            created_at: now.clone(),
            updated_at: now,
        })?
    };

    ensure!(
        journal.state().phase != FixturePhase::TornDown,
        "fixture `{setup_id}` was torn down; choose a new --id to derive a fresh set"
    );
    ensure!(
        journal.state().phase != FixturePhase::TearingDown,
        "fixture `{setup_id}` is being torn down; finish teardown before setting it up again"
    );
    if journal.state().phase == FixturePhase::Ready {
        println!("fixture `{setup_id}` is already ready; use teardown when the load test is done");
        return Ok(());
    }

    resolve_pending(&rpc, &mut journal).await?;
    let ata_rent = rpc_minimum_ata_rent(&rpc).await?;
    let minimum_sol = enforce_sol_cap(&config, assets.len(), ata_rent)?;
    verify_funder_sol_balance(&rpc, &funder, minimum_sol).await?;
    ensure_funder_atas(&rpc, &funder, &assets, &mut journal, "setup", usize::MAX).await?;
    let seed = funder.seed();
    let wallet_set_id = config.setup.wallet_set_id.as_deref().unwrap_or(&setup_id);
    verify_funder_balances(
        &rpc,
        &funder,
        &assets,
        config.setup.users,
        &seed,
        wallet_set_id,
    )
    .await?;

    journal.set_phase(FixturePhase::SettingUp)?;
    let start = journal.state().next_user;
    let cancellation = CancellationToken::new();
    let signal_cancel = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.cancel();
        }
    });
    let mut window_start = start;
    let progress_started = Instant::now();
    while window_start < config.setup.users {
        let window_end = (window_start + config.execution.window_users).min(config.setup.users);
        let mut prepared = tokio::select! {
            _ = cancellation.cancelled() => {
                signal_task.abort();
                bail!("fixture setup cancelled before window {window_start}..{window_end}; rerun to resume")
            },
            result = prepare_setup_window(
                SetupWindow {
                    rpc: &rpc,
                    funder: &funder,
                    seed: &seed,
                    wallet_set_id,
                    sol_lamports: config.setup.sol_lamports_per_user,
                    assets: &assets,
                },
                window_start,
                window_end,
                config.execution.reconcile_concurrency,
            ) => match result {
                Ok(prepared) => prepared,
                Err(error) => {
                    signal_task.abort();
                    return Err(error);
                }
            },
        };
        prepared.sort_by_key(|item| item.index);
        for item in prepared {
            if cancellation.is_cancelled() {
                signal_task.abort();
                bail!(
                    "fixture setup cancelled before window submission; rerun to resume from user {window_start}"
                );
            }
            let result = send_transaction(
                &rpc,
                &funder,
                None,
                item.instructions,
                &mut journal,
                "setup",
                item.index,
            )
            .await
            .with_context(|| format!("setting up user {}", item.index));
            if let Err(error) = result {
                signal_task.abort();
                return Err(error);
            }
        }
        journal.checkpoint(window_end)?;
        if cancellation.is_cancelled() {
            signal_task.abort();
            bail!(
                "fixture setup cancelled after window {window_start}..{window_end} was persisted; rerun to resume"
            );
        }
        if window_end % 100 == 0 || window_end == config.setup.users {
            let completed = window_end.saturating_sub(start);
            let elapsed_seconds = progress_started.elapsed().as_secs_f64();
            let users_per_second = completed as f64 / elapsed_seconds.max(0.001);
            let remaining = config.setup.users.saturating_sub(window_end);
            let estimated_remaining_seconds = (remaining as f64 / users_per_second).ceil() as u64;
            tracing::info!(
                setup_id,
                completed = window_end,
                users = config.setup.users,
                elapsed_seconds,
                users_per_second,
                estimated_remaining_seconds,
                "fixture setup progress"
            );
        }
        window_start = window_end;
    }
    signal_task.abort();
    journal.set_phase(FixturePhase::Ready)?;
    println!(
        "fixture `{setup_id}` ready: {} deterministic wallets × {} token account(s)",
        config.setup.users,
        assets.len()
    );
    Ok(())
}

/// Reclaim every fixture balance and close every derived ATA to return rent to
/// the funder. The same `setup_id` makes the user signing keys recoverable.
pub async fn teardown(setup_id: &str, config_path: &str, yes: bool) -> Result<()> {
    require_confirmation(yes, "teardown")?;
    validate_setup_id(setup_id)?;
    let mut journal = FixtureJournal::load(setup_id)?;
    ensure!(
        journal.state().phase != FixturePhase::TornDown,
        "fixture `{setup_id}` is already torn down"
    );
    let config = SetupConfig::from_yaml_path(config_path)?;
    let rpc_url = config.resolve_rpc_url()?;
    let rpc = FixtureRpc::new(rpc_url.clone(), config.execution.clone());
    let funder = load_funder(&config.setup.funder, journal.state().network)
        .context("teardown must use the same funder configured for setup")?;
    ensure_same_fixture(journal.state(), &config, &funder, &config.journal_assets()?)?;
    ensure!(
        funder.pubkey.to_string() == journal.state().funder_pubkey,
        "BENCH_FUNDER_KEYPAIR does not match fixture `{setup_id}`'s funder"
    );

    resolve_pending(&rpc, &mut journal).await?;
    let teardown_assets = journal.state().assets.clone();
    ensure_funder_atas(
        &rpc,
        &funder,
        &teardown_assets,
        &mut journal,
        "teardown",
        usize::MAX,
    )
    .await?;
    if journal.state().phase != FixturePhase::TearingDown {
        journal.set_phase(FixturePhase::TearingDown)?;
        journal.checkpoint(0)?;
    }
    let seed = funder.seed();
    let wallet_set_id = journal
        .state()
        .wallet_set_id
        .clone()
        .unwrap_or_else(|| setup_id.to_string());
    let start = journal.state().next_user.min(journal.state().users);
    let cancellation = CancellationToken::new();
    let signal_cancel = cancellation.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.cancel();
        }
    });
    let mut window_start = start;
    let progress_started = Instant::now();
    while window_start < journal.state().users {
        let window_end = (window_start + config.execution.window_users).min(journal.state().users);
        let mut prepared = tokio::select! {
            _ = cancellation.cancelled() => {
                signal_task.abort();
                bail!("fixture teardown cancelled before window {window_start}..{window_end}; rerun to resume")
            },
            result = prepare_teardown_window(
                TeardownWindow {
                    rpc: &rpc,
                    funder: &funder,
                    seed: &seed,
                    wallet_set_id: &wallet_set_id,
                    assets: &teardown_assets,
                },
                window_start,
                window_end,
                config.execution.reconcile_concurrency,
            ) => match result {
                Ok(prepared) => prepared,
                Err(error) => {
                    signal_task.abort();
                    return Err(error);
                }
            },
        };
        prepared.sort_by_key(|item| item.index);
        for item in prepared {
            if cancellation.is_cancelled() {
                signal_task.abort();
                bail!(
                    "fixture teardown cancelled before window submission; rerun to resume from user {window_start}"
                );
            }
            let result = send_transaction(
                &rpc,
                &funder,
                Some(&item.wallet),
                item.instructions,
                &mut journal,
                "teardown",
                item.index,
            )
            .await
            .with_context(|| format!("tearing down user {}", item.index));
            if let Err(error) = result {
                signal_task.abort();
                return Err(error);
            }
        }
        journal.checkpoint(window_end)?;
        if cancellation.is_cancelled() {
            signal_task.abort();
            bail!(
                "fixture teardown cancelled after window {window_start}..{window_end} was persisted; rerun to resume"
            );
        }
        if window_end % 100 == 0 || window_end == journal.state().users {
            let completed = window_end.saturating_sub(start);
            let elapsed_seconds = progress_started.elapsed().as_secs_f64();
            let users_per_second = completed as f64 / elapsed_seconds.max(0.001);
            let remaining = journal.state().users.saturating_sub(window_end);
            let estimated_remaining_seconds = (remaining as f64 / users_per_second).ceil() as u64;
            tracing::info!(
                setup_id,
                completed = window_end,
                users = journal.state().users,
                elapsed_seconds,
                users_per_second,
                estimated_remaining_seconds,
                "fixture teardown progress"
            );
        }
        window_start = window_end;
    }
    signal_task.abort();
    journal.set_phase(FixturePhase::TornDown)?;
    println!("fixture `{setup_id}` torn down; token accounts closed and rent reclaimed");
    Ok(())
}

/// Ensure a load run points at a completed fixture made by the same funder and
/// network. The fixture amounts remain deliberately independent from the load
/// config: the session challenge determines the actual required deposit.
pub fn validate_ready_fixture(setup_id: &str, run: &RunConfig, funder: &Wallet) -> Result<String> {
    let fixture = FixtureJournal::load(setup_id)?;
    ensure!(
        fixture.state().phase == FixturePhase::Ready,
        "fixture `{setup_id}` is not ready; run `bench setup ... --id {setup_id} --yes` first"
    );
    ensure!(
        fixture.state().network == run.run.network,
        "fixture `{setup_id}` targets {:?}, but the load config targets {:?}",
        fixture.state().network,
        run.run.network
    );
    ensure!(
        fixture.state().funder_pubkey == funder.pubkey.to_string(),
        "fixture `{setup_id}` belongs to a different funder"
    );
    ensure!(
        fixture.state().users >= run.load.users,
        "fixture `{setup_id}` has {} wallets but the load requests {} users",
        fixture.state().users,
        run.load.users
    );
    Ok(fixture
        .state()
        .wallet_set_id
        .clone()
        .unwrap_or_else(|| setup_id.to_string()))
}

fn require_confirmation(yes: bool, operation: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    bail!(
        "fixture {operation} submits transactions; re-run with --yes after reviewing the YAML caps"
    )
}

fn validate_setup_id(id: &str) -> Result<()> {
    ensure!(!id.is_empty(), "setup ID cannot be empty");
    ensure!(
        id.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "setup ID may contain only letters, digits, `-`, and `_`"
    );
    Ok(())
}

fn new_setup_id(name: &str) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{slug}-{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"))
}

fn ensure_same_fixture(
    state: &FixtureState,
    config: &SetupConfig,
    funder: &Wallet,
    assets: &[FixtureAsset],
) -> Result<()> {
    ensure!(
        state.name == config.setup.name,
        "existing fixture name does not match config"
    );
    ensure!(
        state.wallet_set_id == config.setup.wallet_set_id,
        "existing fixture wallet set does not match config"
    );
    ensure!(
        state.network == config.setup.network,
        "existing fixture network does not match config"
    );
    ensure!(
        state.funder_pubkey == funder.pubkey.to_string(),
        "existing fixture uses another funder"
    );
    ensure!(
        state.users == config.setup.users,
        "existing fixture user count does not match config"
    );
    ensure!(
        state.sol_lamports_per_user == config.setup.sol_lamports_per_user,
        "existing fixture SOL allocation does not match config"
    );
    ensure!(
        state.assets == assets,
        "existing fixture assets do not match config"
    );
    Ok(())
}

fn enforce_sol_cap(config: &SetupConfig, asset_count: usize, ata_rent: u64) -> Result<u64> {
    let users = config.setup.users as u128;
    let per_user = u128::from(config.setup.sol_lamports_per_user)
        .checked_add(u128::from(ata_rent) * asset_count as u128)
        .and_then(|total| total.checked_add(u128::from(SETUP_FEE_ALLOWANCE_LAMPORTS)))
        .context("SOL allocation overflow")?;
    let estimated_lamports = per_user
        .checked_mul(users)
        .context("SOL allocation overflow")?;
    let estimated = estimated_lamports as f64 / 1_000_000_000.0;
    ensure!(
        estimated <= config.setup.max_total_sol,
        "fixture estimates {estimated:.4} SOL (allocation + ATA rent), exceeding setup.max_total_sol={:.4}",
        config.setup.max_total_sol
    );
    tracing::info!(
        estimated_sol = estimated,
        ata_rent_lamports = ata_rent,
        "fixture plan within SOL cap"
    );
    u64::try_from(estimated_lamports).context("fixture SOL allocation exceeds u64")
}

async fn verify_funder_sol_balance(rpc: &FixtureRpc, funder: &Wallet, minimum: u64) -> Result<()> {
    let available = rpc_balance(rpc, &funder.pubkey).await?;
    ensure!(
        available >= minimum,
        "funder has {available} lamports; fixture needs at least {minimum} for allocations, ATA rent, and fee allowance"
    );
    Ok(())
}

async fn ensure_funder_atas(
    rpc: &FixtureRpc,
    funder: &Wallet,
    assets: &[FixtureAsset],
    journal: &mut FixtureJournal,
    operation: &str,
    user_index: usize,
) -> Result<()> {
    let instructions = assets
        .iter()
        .map(|asset| create_ata_ix(&funder.pubkey, &funder.pubkey, asset))
        .collect::<Result<Vec<_>>>()?;
    send_transaction(
        rpc,
        funder,
        None,
        instructions,
        journal,
        operation,
        user_index,
    )
    .await?;
    Ok(())
}

async fn verify_funder_balances(
    rpc: &FixtureRpc,
    funder: &Wallet,
    assets: &[FixtureAsset],
    users: usize,
    seed: &[u8; 32],
    wallet_set_id: &str,
) -> Result<()> {
    for asset in assets {
        let ata = associated_token_address(&funder.pubkey, asset)?;
        let available = token_balance(rpc, &ata).await?.context(
            "funder ATA missing after idempotent creation; check the configured token program",
        )?;
        let addresses = (0..users)
            .map(|index| {
                let user = derive_user(seed, wallet_set_id, index as u32);
                associated_token_address(&user.pubkey, asset)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut needed = 0u64;
        for chunk in addresses.chunks(100) {
            let accounts = rpc
                .accounts(chunk)
                .await
                .with_context(|| format!("fetching existing {} fixture balances", asset.label))?;
            for account in accounts {
                let current = token_amount(account.as_ref())?;
                ensure!(
                    current <= asset.amount_base,
                    "derived wallet already has {current} {} base units (fixture target is {}); refuse to mix funds",
                    asset.label,
                    asset.amount_base
                );
                needed = needed
                    .checked_add(asset.amount_base - current)
                    .context("asset funding total overflow")?;
            }
        }
        ensure!(
            available >= needed,
            "funder {} ATA has {available} base units; fixture needs {needed} more. Fund it before setup.",
            asset.label
        );
    }
    Ok(())
}

async fn prepare_setup_window(
    window: SetupWindow<'_>,
    start: usize,
    end: usize,
    concurrency: usize,
) -> Result<Vec<PreparedUser>> {
    let prepared = futures::stream::iter(start..end)
        .map(move |index| {
            let user = derive_user(window.seed, window.wallet_set_id, index as u32);
            async move {
                let instructions = prepare_setup_user(
                    window.rpc,
                    window.funder,
                    &user,
                    window.sol_lamports,
                    window.assets,
                )
                .await?;
                Ok::<_, anyhow::Error>(PreparedUser {
                    index,
                    wallet: user,
                    instructions,
                })
            }
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await?;
    Ok(prepared)
}

async fn prepare_setup_user(
    rpc: &FixtureRpc,
    funder: &Wallet,
    user: &Wallet,
    sol_lamports: u64,
    assets: &[FixtureAsset],
) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let current_sol = rpc_balance(rpc, &user.pubkey).await?;
    if current_sol < sol_lamports {
        instructions.push(system_instruction::transfer(
            &funder.pubkey,
            &user.pubkey,
            sol_lamports - current_sol,
        ));
    }
    for asset in assets {
        let user_ata = associated_token_address(&user.pubkey, asset)?;
        let current = token_balance(rpc, &user_ata).await?;
        let current_amount = current.unwrap_or(0);
        ensure!(
            current_amount <= asset.amount_base,
            "derived wallet {} already has {} {} base units (fixture target is {}); refuse to mix funds",
            user.pubkey,
            current_amount,
            asset.label,
            asset.amount_base
        );
        if current.is_none() {
            instructions.push(create_ata_ix(&funder.pubkey, &user.pubkey, asset)?);
        }
        if current_amount < asset.amount_base {
            let funder_ata = associated_token_address(&funder.pubkey, asset)?;
            if current.is_some() {
                instructions.push(create_ata_ix(&funder.pubkey, &user.pubkey, asset)?);
            }
            instructions.push(
                token_instruction::transfer_checked(
                    &token_program(asset)?,
                    &funder_ata,
                    &mint(asset)?,
                    &user_ata,
                    &funder.pubkey,
                    &[],
                    asset.amount_base - current_amount,
                    asset.decimals,
                )
                .map_err(|error| anyhow::anyhow!("building {} transfer: {error}", asset.label))?,
            );
        }
    }
    Ok(instructions)
}

async fn prepare_teardown_window(
    window: TeardownWindow<'_>,
    start: usize,
    end: usize,
    concurrency: usize,
) -> Result<Vec<PreparedUser>> {
    futures::stream::iter(start..end)
        .map(move |index| {
            let user = derive_user(window.seed, window.wallet_set_id, index as u32);
            async move {
                let instructions =
                    prepare_teardown_user(window.rpc, window.funder, &user, window.assets).await?;
                Ok::<_, anyhow::Error>(PreparedUser {
                    index,
                    wallet: user,
                    instructions,
                })
            }
        })
        .buffer_unordered(concurrency)
        .try_collect()
        .await
}

async fn prepare_teardown_user(
    rpc: &FixtureRpc,
    funder: &Wallet,
    user: &Wallet,
    assets: &[FixtureAsset],
) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    for asset in assets {
        let user_ata = associated_token_address(&user.pubkey, asset)?;
        let Some(balance) = token_balance(rpc, &user_ata).await? else {
            continue;
        };
        let funder_ata = associated_token_address(&funder.pubkey, asset)?;
        if balance > 0 {
            instructions.push(
                token_instruction::transfer_checked(
                    &token_program(asset)?,
                    &user_ata,
                    &mint(asset)?,
                    &funder_ata,
                    &user.pubkey,
                    &[],
                    balance,
                    asset.decimals,
                )
                .map_err(|error| {
                    anyhow::anyhow!("building {} recovery transfer: {error}", asset.label)
                })?,
            );
        }
        instructions.push(
            token_instruction::close_account(
                &token_program(asset)?,
                &user_ata,
                &funder.pubkey,
                &user.pubkey,
                &[],
            )
            .map_err(|error| anyhow::anyhow!("building {} ATA close: {error}", asset.label))?,
        );
    }
    let sol = rpc_balance(rpc, &user.pubkey).await?;
    if sol > 0 {
        instructions.push(system_instruction::transfer(
            &user.pubkey,
            &funder.pubkey,
            sol,
        ));
    }
    Ok(instructions)
}

fn create_ata_ix(payer: &Pubkey, owner: &Pubkey, asset: &FixtureAsset) -> Result<Instruction> {
    Ok(
        pay_kit::mpp::program::payment_channels::build_create_associated_token_account_instruction(
            payer,
            owner,
            &mint(asset)?,
            &token_program(asset)?,
        ),
    )
}

fn associated_token_address(owner: &Pubkey, asset: &FixtureAsset) -> Result<Pubkey> {
    let (ata, _) = pay_kit::mpp::program::payment_channels::find_associated_token_address(
        owner,
        &mint(asset)?,
        &token_program(asset)?,
    );
    Ok(ata)
}

fn mint(asset: &FixtureAsset) -> Result<Pubkey> {
    asset
        .mint
        .parse()
        .with_context(|| format!("invalid {} mint in fixture journal", asset.label))
}

fn token_program(asset: &FixtureAsset) -> Result<Pubkey> {
    asset
        .token_program
        .parse()
        .with_context(|| format!("invalid {} token program in fixture journal", asset.label))
}

async fn rpc_minimum_ata_rent(rpc: &FixtureRpc) -> Result<u64> {
    rpc.minimum_balance_for_rent(TokenAccount::LEN)
        .await
        .context("fetching minimum ATA rent")
}

async fn rpc_balance(rpc: &FixtureRpc, address: &Pubkey) -> Result<u64> {
    rpc.balance(address).await.context("fetching SOL balance")
}

async fn token_balance(rpc: &FixtureRpc, address: &Pubkey) -> Result<Option<u64>> {
    let account = rpc
        .accounts(&[*address])
        .await
        .context("fetching token account")?
        .into_iter()
        .next()
        .flatten();
    match account.as_ref() {
        Some(account) => token_amount(Some(account)).map(Some),
        None => Ok(None),
    }
}

fn token_amount(account: Option<&solana_account::Account>) -> Result<u64> {
    match account {
        Some(account) => StateWithExtensions::<TokenAccount>::unpack(&account.data)
            .map(|account| account.base.amount)
            .context("decoding token account"),
        None => Ok(0),
    }
}

async fn send_transaction(
    rpc: &FixtureRpc,
    fee_payer: &Wallet,
    additional_signer: Option<&Wallet>,
    instructions: Vec<Instruction>,
    journal: &mut FixtureJournal,
    operation: &str,
    user_index: usize,
) -> Result<()> {
    if instructions.is_empty() {
        return Ok(());
    }
    let (blockhash, last_valid_block_height) = rpc
        .latest_blockhash()
        .await
        .context("fetching recent blockhash")?;
    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer.pubkey), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    sign_transaction(&mut transaction, fee_payer).await?;
    if let Some(signer) = additional_signer
        && signer.pubkey != fee_payer.pubkey
    {
        sign_transaction(&mut transaction, signer).await?;
    }
    let signature = transaction
        .signatures
        .first()
        .copied()
        .context("fixture transaction has no fee-payer signature")?;
    journal.add_pending(PendingTransaction {
        signature: signature.to_string(),
        operation: operation.to_owned(),
        user_index,
        last_valid_block_height,
    })?;
    rpc.submit_and_confirm(&transaction)
        .await
        .context("broadcasting fixture transaction")?;
    journal.clear_pending(&signature.to_string())?;
    Ok(())
}

async fn resolve_pending(rpc: &FixtureRpc, journal: &mut FixtureJournal) -> Result<()> {
    let pending = journal.state().pending.clone();
    for transaction in pending {
        let signature = Signature::from_str(&transaction.signature).with_context(|| {
            format!(
                "invalid pending transaction signature {}",
                transaction.signature
            )
        })?;
        if let Some(status) = rpc.signature_status(signature).await? {
            if let Some(error) = status.err {
                bail!(
                    "pending {} transaction {} failed: {error:?}",
                    transaction.operation,
                    transaction.signature
                );
            }
            journal.clear_pending(&transaction.signature)?;
            continue;
        }
        let current_height = rpc.block_height().await?;
        if current_height >= transaction.last_valid_block_height {
            tracing::warn!(
                signature = %transaction.signature,
                operation = %transaction.operation,
                user_index = transaction.user_index,
                "pending fixture transaction expired before confirmation; reconciliation will rebuild it"
            );
            journal.clear_pending(&transaction.signature)?;
            continue;
        }
        bail!(
            "pending {} transaction {} has not confirmed and its blockhash is still valid; refusing to rebuild it",
            transaction.operation,
            transaction.signature
        );
    }
    Ok(())
}

async fn sign_transaction(transaction: &mut Transaction, wallet: &Wallet) -> Result<()> {
    let signer =
        MemorySigner::from_bytes(&wallet.keypair).context("loading derived wallet signer")?;
    let signature = signer
        .sign_message(&transaction.message_data())
        .await
        .context("signing fixture transaction")?;
    let index = transaction
        .message
        .account_keys
        .iter()
        .position(|key| *key == wallet.pubkey)
        .context("fixture signer is absent from transaction")?;
    transaction.signatures[index] = Signature::from(<[u8; 64]>::from(signature));
    Ok(())
}

fn decimal_to_base(value: &str, decimals: u8) -> Result<u64> {
    let value = value.trim();
    ensure!(!value.is_empty(), "token amount cannot be empty");
    ensure!(!value.starts_with('-'), "token amount cannot be negative");
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    ensure!(
        whole.chars().all(|c| c.is_ascii_digit()) && fraction.chars().all(|c| c.is_ascii_digit()),
        "token amount `{value}` must be a decimal number"
    );
    ensure!(
        fraction.len() <= usize::from(decimals),
        "token amount `{value}` has more than {decimals} decimal places"
    );
    let whole = whole.parse::<u64>().context("token amount is too large")?;
    let scale = 10u64.pow(u32::from(decimals));
    let fraction = if fraction.is_empty() {
        0
    } else {
        let padded = format!("{fraction:0<width$}", width = usize::from(decimals));
        padded
            .parse::<u64>()
            .context("token fraction is too large")?
    };
    whole
        .checked_mul(scale)
        .and_then(|base| base.checked_add(fraction))
        .context("token amount overflows base units")
}

#[cfg(test)]
mod tests {
    use super::{RunConfig, SetupConfig, decimal_to_base};

    #[test]
    fn decimal_amounts_are_exact() {
        assert_eq!(decimal_to_base("0.000001", 6).unwrap(), 1);
        assert_eq!(decimal_to_base("1.25", 6).unwrap(), 1_250_000);
        assert_eq!(decimal_to_base("2", 6).unwrap(), 2_000_000);
        assert!(decimal_to_base("0.0000001", 6).is_err());
        assert!(decimal_to_base("-1", 6).is_err());
    }

    #[test]
    fn bundled_devnet_fixture_is_within_its_caps() {
        let config: SetupConfig =
            serde_yml::from_str(include_str!("../configs/devnet-fixture-100k.yml")).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn bundled_devnet_usdg_fixture_is_within_its_caps() {
        let config: SetupConfig =
            serde_yml::from_str(include_str!("../configs/devnet-fixture-100k-usdg.yml")).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn bundled_devnet_usdtest_fixture_reuses_retained_wallet_set() {
        for raw in [
            include_str!("../configs/devnet-fixture-100-usdtest.yml"),
            include_str!("../configs/devnet-fixture-100k-usdtest.yml"),
        ] {
            let config: SetupConfig = serde_yml::from_str(raw).unwrap();
            config.validate().unwrap();
            assert_eq!(
                config.setup.wallet_set_id.as_deref(),
                Some("devnet-100k-usdg")
            );
        }
    }

    #[test]
    fn bundled_devnet_usdtest_runs_close_every_channel() {
        for raw in [
            include_str!("../configs/session-devnet-smoke-10.yml"),
            include_str!("../configs/session-devnet.yml"),
        ] {
            let config: RunConfig = serde_yml::from_str(raw).unwrap();
            assert!(config.session.unwrap().close_after_run);
            assert!(config.run.safety.max_total_usdc <= 1.0);
            assert!(config.run.safety.max_total_sol <= 2.5);
        }
    }
}
