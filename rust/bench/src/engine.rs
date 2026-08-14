//! Pipeline orchestration: resolve → fund+provision → prepare → unleash →
//! settle+sweep, journalled at every transition. Scheme- and funder-agnostic;
//! the rehearsal (fork) and mainnet paths share this code.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures::stream::{self, StreamExt};
use solana_pubkey::Pubkey;
use tracing::Instrument;

use crate::config::RunConfig;
use crate::driver::{self, DriverConfig};
use crate::journal::{Journal, Status, UserRecord};
use crate::report::ReportJson;
use crate::scheme::{BenchScheme, UserCtx, UserSetup};
use crate::wallet::{self, Funder};

/// Concurrency for the on-chain provisioning + off-chain prepare phases.
/// (Deliberately modest for M1; M3 tunes this against RPC limits.)
const PROVISION_CONCURRENCY: usize = 16;
const PREPARE_CONCURRENCY: usize = 32;

pub struct PipelineParams<'a> {
    pub config: &'a RunConfig,
    pub scheme: &'a dyn BenchScheme,
    pub funder: &'a dyn Funder,
    pub funder_seed: [u8; 32],
    /// Wallet derivation namespace. Usually the run ID; a prepared fixture
    /// supplies its stable setup ID so load runs reuse pre-provisioned wallets.
    pub wallet_set_id: &'a str,
    pub rpc_url: String,
    /// Forced `Host` header (rehearsal proxy). `None` on mainnet.
    pub host_override: Option<String>,
    pub journal: &'a mut Journal,
}

#[tracing::instrument(
    name = "run_pipeline",
    skip_all,
    fields(scheme = p.scheme.name(), users = p.config.load.users)
)]
pub async fn run_pipeline(p: PipelineParams<'_>) -> Result<ReportJson> {
    let cfg = p.config;
    let load = &cfg.load;
    // M1: single endpoint. Multi-endpoint weighting is a later milestone.
    let endpoint = &cfg.endpoints[0];
    let scheme = p.scheme;
    let funder = p.funder;
    let run_id = p.journal.state().run_id.clone();

    // ── 1. Resolve price from a 402 probe ───────────────────────────────────
    let probe = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let price = scheme
        .resolve(&probe, endpoint, p.host_override.as_deref())
        .await
        .context("resolving price from 402 challenge")?;
    tracing::info!(
        amount_base = price.amount_base,
        currency = %price.currency,
        decimals = price.decimals,
        recipient = %price.recipient,
        "resolved price"
    );

    // ── 2. Funding plan + hard spend caps ───────────────────────────────────
    let per = scheme.funding_plan(load, &price);
    let users = load.users as u128;
    let total_sol = (per.sol_lamports as u128 * users) as f64 / 1e9;
    let total_token = (per.token_base as u128 * users) as f64 / 10f64.powi(price.decimals as i32);
    enforce_caps(cfg, total_sol, total_token)?;
    tracing::info!(
        per_user_sol = per.sol_lamports,
        per_user_token = per.token_base,
        total_sol,
        total_token,
        funder = funder.kind(),
        "funding plan within caps"
    );

    let mint_pk: Option<Pubkey> = match &price.mint {
        Some(m) => Some(m.parse().context("price.mint is not a valid pubkey")?),
        None => None,
    };

    // ── 3. Build per-user contexts (deterministic wallets) ──────────────────
    let prep_http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(64)
        .build()?;
    let ctxs: Vec<UserCtx> = (0..load.users as u32)
        .filter(|index| *index as usize % load.shard_count == load.shard_index)
        .map(|i| UserCtx {
            index: i,
            wallet: wallet::derive_user(&p.funder_seed, p.wallet_set_id, i),
            rpc_url: p.rpc_url.clone(),
            endpoint: endpoint.clone(),
            http: prep_http.clone(),
            host_override: p.host_override.clone(),
            mint: mint_pk,
        })
        .collect();

    // ── 4. Provision: fund each wallet, then scheme-specific on-chain setup ──
    p.journal.set_status(Status::Provisioning)?;
    let t_provision = Instant::now();
    let mut prov: Vec<(u32, Result<UserSetup>)> = stream::iter(ctxs.iter())
        .map(|ctx| {
            async move {
                let token = mint_pk.as_ref().map(|m| (m, per.token_base));
                let res = match funder
                    .fund(&ctx.wallet.pubkey, per.sol_lamports, token)
                    .await
                {
                    Ok(()) => scheme.provision_user(ctx).await,
                    Err(e) => Err(e),
                };
                (ctx.index, res)
            }
            .instrument(tracing::info_span!("provision", index = ctx.index))
        })
        .buffer_unordered(PROVISION_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;

    prov.sort_by_key(|(i, _)| *i);
    let ctx_by_index: HashMap<u32, &UserCtx> = ctxs.iter().map(|ctx| (ctx.index, ctx)).collect();
    let mut setups: Vec<UserSetup> = Vec::with_capacity(ctxs.len());
    for (idx, res) in prov {
        match res {
            Ok(setup) => {
                p.journal.upsert_user(UserRecord {
                    index: idx,
                    pubkey: ctx_by_index[&idx].wallet.pubkey.to_string(),
                    ata: setup.ata.clone(),
                    channel_id: setup.channel_id.clone(),
                    open_sig: setup.open_sig.clone(),
                    token_base: per.token_base,
                    sol_lamports: per.sol_lamports,
                    funded: true,
                    swept: false,
                })?;
                setups.push(setup);
            }
            Err(e) => {
                p.journal.set_status(Status::Failed)?;
                bail!("provisioning user {idx} failed: {e:#}");
            }
        }
    }
    p.journal.set_status(Status::Provisioned)?;
    tracing::info!(
        users = ctxs.len(),
        elapsed_ms = t_provision.elapsed().as_millis() as u64,
        "phase: provisioned"
    );

    // ── 5. Build bounded per-user request sources ──────────────────────────
    // Sources sign only when their worker dispatches a request. This keeps
    // memory independent of the measured-window length.
    let t_prepare = Instant::now();
    let prepared = stream::iter(ctxs.iter().zip(setups.iter()))
        .map(|(ctx, setup)| {
            scheme
                .request_source(ctx, setup)
                .instrument(tracing::info_span!("request_source", index = ctx.index))
        })
        .buffer_unordered(PREPARE_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    let mut sources = Vec::with_capacity(prepared.len());
    for r in prepared {
        sources.push(r.context("building request source")?);
    }
    p.journal.set_status(Status::Prepared)?;
    tracing::info!(
        sources = sources.len(),
        elapsed_ms = t_prepare.elapsed().as_millis() as u64,
        "phase: bounded request sources ready"
    );

    // ── 6. Unleash (measured) ───────────────────────────────────────────────
    p.journal.set_status(Status::Unleashing)?;
    let dcfg = DriverConfig {
        rps_per_user: load.requests_per_sec_per_user,
        max_concurrency: load.max_concurrency,
        deadline: Duration::from_secs(load.unleash_secs),
        // Pool ≥ concurrency so every in-flight request reuses a kept-alive
        // connection instead of churning loopback ephemeral ports (the prior
        // 256 vs 4096+ mismatch caused connect storms → backlog overflow).
        pool_per_host: load.max_concurrency.max(256),
        workers: load.workers,
    };
    let http = driver::build_http(&dcfg);
    let report = driver::run(sources, http, dcfg)
        .instrument(tracing::info_span!("unleash"))
        .await;
    tracing::info!(
        completed = report.completed,
        ok = report.ok,
        fail = report.fail,
        rps = report.rps_overall,
        elapsed_ms = report.wall.as_millis() as u64,
        "phase: unleash complete"
    );

    // ── 7. Settle + sweep ───────────────────────────────────────────────────
    p.journal.set_status(Status::Settling)?;
    let t_settle = Instant::now();
    for (ctx, setup) in ctxs.iter().zip(setups.iter()) {
        scheme
            .settle_and_close(ctx, setup)
            .await
            .with_context(|| format!("settling user {}", ctx.index))?;
    }
    for ctx in &ctxs {
        funder
            .sweep(&ctx.wallet, mint_pk.as_ref())
            .await
            .with_context(|| format!("sweeping user {}", ctx.index))?;
        if let Some(rec) = p
            .journal
            .state()
            .users
            .iter()
            .find(|u| u.index == ctx.index)
            .cloned()
        {
            p.journal.upsert_user(UserRecord { swept: true, ..rec })?;
        }
    }
    p.journal.set_status(Status::Swept)?;
    p.journal.set_status(Status::Complete)?;
    tracing::info!(
        elapsed_ms = t_settle.elapsed().as_millis() as u64,
        "phase: settled + swept"
    );

    Ok(ReportJson::from_driver(
        &run_id,
        scheme.name(),
        cfg.run.network.slug(),
        ctxs.len(),
        load.requests_per_sec_per_user,
        &report,
    ))
}

/// Reject a run whose estimated spend exceeds the configured hard caps.
fn enforce_caps(cfg: &RunConfig, total_sol: f64, total_token: f64) -> Result<()> {
    let s = &cfg.run.safety;
    if total_sol > s.max_total_sol {
        bail!(
            "estimated SOL {total_sol:.4} exceeds cap max_total_sol={:.4}",
            s.max_total_sol
        );
    }
    if total_token > s.max_total_usdc {
        bail!(
            "estimated token spend {total_token:.4} exceeds cap max_total_usdc={:.4}",
            s.max_total_usdc
        );
    }
    Ok(())
}
