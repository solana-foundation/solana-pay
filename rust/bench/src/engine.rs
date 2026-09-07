//! Pipeline orchestration: resolve → fund+provision → prepare → unleash →
//! settle+sweep, journalled at every transition. Scheme- and funder-agnostic;
//! the rehearsal (fork) and mainnet paths share this code.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures::stream::{self, StreamExt};
use serde_json::{Value, json};
use solana_pubkey::Pubkey;
use tracing::Instrument;

use crate::config::{RunConfig, Scheme};
use crate::driver::{self, DriverConfig};
use crate::journal::{Journal, Status, UserRecord};
use crate::report::ReportJson;
use crate::scheme::{BenchScheme, UserCtx, UserSetup};
use crate::wallet::{self, Funder};

/// Concurrency for the off-chain request-source preparation phase.
const PREPARE_CONCURRENCY: usize = 32;
/// Amortize the atomic full-state journal write for large fixture runs. A
/// crash can lose at most this many completion markers; session recovery is
/// idempotent and reconciles those users from chain state.
const JOURNAL_CHECKPOINT_USERS: usize = 1_024;

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
    let no_chain = cfg.run.scheme == Scheme::SelfTest
        || cfg.session.as_ref().is_some_and(|session| session.offline);

    // ── 1. Resolve price from a 402 probe ───────────────────────────────────
    let tls_ca_certificate = cfg.tls_ca_certificate()?;
    let mut probe_builder = reqwest::Client::builder().timeout(Duration::from_secs(20));
    if let Some(certificate) = tls_ca_certificate.clone() {
        probe_builder = probe_builder.add_root_certificate(certificate);
    }
    let probe = probe_builder.build()?;
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
    let mint_pk: Option<Pubkey> = match &price.mint {
        Some(m) => Some(m.parse().context("price.mint is not a valid pubkey")?),
        None => None,
    };
    let per = scheme.funding_plan(load, &price);
    // The 402 challenge is untrusted input. For SPL funding, use the mint's
    // on-chain decimals for cap arithmetic and reject a conflicting challenge
    // before any wallet receives funds.
    let token_decimals = if per.token_base == 0 || no_chain {
        price.decimals
    } else {
        let mint = mint_pk
            .as_ref()
            .context("SPL funding plan requires a mint in the payment challenge")?;
        verified_mint_decimals(&p.rpc_url, mint, price.decimals).await?
    };
    let users = load.users as u128;
    let total_sol = (per.sol_lamports as u128 * users) as f64 / 1e9;
    let total_token = (per.token_base as u128 * users) as f64 / 10f64.powi(token_decimals as i32);
    enforce_caps(cfg, total_sol, total_token)?;
    tracing::info!(
        per_user_sol = per.sol_lamports,
        per_user_token = per.token_base,
        total_sol,
        total_token,
        funder = funder.kind(),
        "funding plan within caps"
    );

    // ── 3. Build per-user contexts (deterministic wallets) ──────────────────
    // Provisioning opens a real payment channel per user, which broadcasts an
    // on-chain transaction and waits for the gateway to confirm it. Under a
    // large open burst devnet/RPC latency makes individual opens occasionally
    // stall for tens of seconds; a tight timeout aborts the whole run on the
    // first such stall (no per-open retry). Give opens generous headroom so
    // provisioning tens of thousands of channels rides through those spikes.
    let mut prep_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .pool_max_idle_per_host(64);
    if let Some(certificate) = tls_ca_certificate.clone() {
        prep_builder = prep_builder.add_root_certificate(certificate);
    }
    let prep_http = prep_builder.build()?;
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

    // ── 3b. Reuse: discover each wallet's existing open channel so provisioning
    //        drives it by address instead of opening a new one (no new rent). ──
    if cfg.session.as_ref().is_some_and(|s| s.reuse) && !no_chain {
        let expected: HashMap<Pubkey, (u32, wallet::Wallet, Pubkey)> = ctxs
            .iter()
            .map(|ctx| {
                let authorized_signer = match cfg.run.scheme {
                    Scheme::X402BatchSettlement => ctx.wallet.pubkey,
                    _ => wallet::subkey(&ctx.wallet.seed(), "session").pubkey,
                };
                (
                    ctx.wallet.pubkey,
                    (ctx.index, ctx.wallet.clone(), authorized_signer),
                )
            })
            .collect();
        let map = crate::session_recovery::discover_reuse_map(&p.rpc_url, &expected)
            .await
            .context("discovering reusable channels")?;
        tracing::info!(
            reusable = map.len(),
            users = ctxs.len(),
            "reuse: discovered existing channels (wallets without one will open)"
        );
        scheme.set_reuse_channels(map);
    }

    // ── 4. Provision: fund each wallet, then scheme-specific on-chain setup ──
    p.journal.set_status(Status::Provisioning)?;
    // Persist every wallet before the first funding RPC. A timeout can be
    // returned after a transfer lands, so even a failed funding result must be
    // recoverable and swept rather than silently disappearing from the run.
    if !no_chain {
        p.journal
            .upsert_users(ctxs.iter().map(|ctx| user_record(ctx, None, per, false)))?;
    }
    let t_provision = Instant::now();
    let mut provisioning = stream::iter(ctxs.iter())
        .map(|ctx| {
            async move {
                let token = mint_pk.as_ref().map(|m| (m, per.token_base));
                let outcome = match funder
                    .fund(&ctx.wallet.pubkey, per.sol_lamports, token)
                    .await
                {
                    Ok(()) => match scheme.provision_user(ctx).await {
                        Ok(setup) => ProvisionOutcome::Provisioned(setup),
                        Err(error) => ProvisionOutcome::ProvisionFailed(error),
                    },
                    Err(error) => ProvisionOutcome::FundingFailed(error),
                };
                (ctx.index, outcome)
            }
            .instrument(tracing::info_span!("provision", index = ctx.index))
        })
        .buffer_unordered(load.provision_concurrency);
    let ctx_by_index: HashMap<u32, &UserCtx> = ctxs.iter().map(|ctx| (ctx.index, ctx)).collect();
    // Best-effort provisioning: with `provision_min_success_fraction < 1.0` a
    // few transient open failures (devnet RPC drops when opening tens of
    // thousands of channels) are skipped rather than aborting the whole run.
    let tolerate_failures = load.provision_min_success_fraction < 1.0;
    let mut provision_failures = 0usize;
    let mut failure_sample: Option<String> = None;
    let mut provisioned: Vec<(u32, UserSetup)> = Vec::with_capacity(ctxs.len());
    // All funding attempts, including provision failures, must get a sweep.
    // A `None` setup means no protocol close can safely be attempted, but the
    // wallet itself still needs its residual SOL/SPL balance reclaimed.
    let mut cleanup: Vec<(u32, Option<UserSetup>)> = Vec::with_capacity(ctxs.len());
    let mut provision_checkpoint = Vec::with_capacity(JOURNAL_CHECKPOINT_USERS);
    while let Some((idx, outcome)) = provisioning.next().await {
        match outcome {
            ProvisionOutcome::Provisioned(setup) => {
                if !no_chain {
                    provision_checkpoint.push(user_record(
                        ctx_by_index[&idx],
                        Some(&setup),
                        per,
                        true,
                    ));
                    if provision_checkpoint.len() == JOURNAL_CHECKPOINT_USERS {
                        p.journal.upsert_users(provision_checkpoint.drain(..))?;
                    }
                }
                cleanup.push((idx, Some(setup.clone())));
                provisioned.push((idx, setup));
            }
            ProvisionOutcome::ProvisionFailed(error) => {
                if !provision_checkpoint.is_empty() {
                    p.journal.upsert_users(provision_checkpoint.drain(..))?;
                }
                let setup = scheme.take_ambiguous_setup(ctx_by_index[&idx]);
                if !no_chain {
                    p.journal.upsert_users([user_record(
                        ctx_by_index[&idx],
                        setup.as_ref(),
                        per,
                        true,
                    )])?;
                }
                // An MPP open can have been broadcast before its response
                // failed. Keep its deterministic channel ID and require a
                // successful close before the wallet is swept/marked clean.
                cleanup.push((idx, setup));
                if tolerate_failures {
                    // Skip this channel and keep going; the measured run uses
                    // whatever came up. Sample the first error for the summary.
                    provision_failures += 1;
                    if failure_sample.is_none() {
                        failure_sample = Some(format!("{error:#}"));
                    }
                    continue;
                }
                // Keep the journal outstanding: the open request may have
                // reached chain even when its HTTP response failed, and prior
                // users are definitely funded. Recovery must reconcile it.
                return Err(error).with_context(|| format!("provisioning user {idx} failed"));
            }
            ProvisionOutcome::FundingFailed(error) => {
                if !provision_checkpoint.is_empty() {
                    p.journal.upsert_users(provision_checkpoint.drain(..))?;
                }
                // The intent record is already durable; include it in cleanup
                // because the transfer may have landed despite the RPC error.
                cleanup.push((idx, None));
                if tolerate_failures {
                    provision_failures += 1;
                    if failure_sample.is_none() {
                        failure_sample = Some(format!("{error:#}"));
                    }
                    continue;
                }
                return Err(error).with_context(|| format!("funding user {idx} failed"));
            }
        }
    }
    if !provision_checkpoint.is_empty() {
        p.journal.upsert_users(provision_checkpoint.drain(..))?;
    }
    provisioned.sort_by_key(|(idx, _)| *idx);
    let succeeded = provisioned.len();
    if tolerate_failures {
        let attempted = ctxs.len();
        let fraction = succeeded as f64 / attempted.max(1) as f64;
        if fraction < load.provision_min_success_fraction {
            bail!(
                "provisioning succeeded for only {succeeded}/{attempted} channels \
                 ({fraction:.3} < required {:.3}); first failure: {}",
                load.provision_min_success_fraction,
                failure_sample.as_deref().unwrap_or("<none>")
            );
        }
        if provision_failures > 0 {
            tracing::warn!(
                succeeded,
                attempted,
                skipped = provision_failures,
                first_failure = failure_sample.as_deref().unwrap_or(""),
                "phase: provisioned best-effort (skipped transient open failures)"
            );
        }
    }
    p.journal.set_status(Status::Provisioned)?;
    tracing::info!(
        users = succeeded,
        elapsed_ms = t_provision.elapsed().as_millis() as u64,
        "phase: provisioned"
    );

    // ── 5. Build bounded per-user request sources ──────────────────────────
    // Sources normally sign only when their worker dispatches a request. An
    // explicit offline capacity-isolation config may instead pre-sign a fixed,
    // validated window so client signing does not compete with the proxy.
    let t_prepare = Instant::now();
    let prepared = stream::iter(provisioned.iter())
        .map(|(idx, setup)| {
            let ctx = ctx_by_index[idx];
            scheme
                .request_source(ctx, setup)
                .instrument(tracing::info_span!("request_source", index = *idx))
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
    // Optionally start the scheme's background hot-path pipeline (session signer
    // pool) now that channels + queues exist. The guard stops + joins the signer
    // threads when dropped, immediately after the measured window.
    let hot_path = scheme.spawn_hot_path();
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
        http2_prior_knowledge: load.http2_prior_knowledge,
        tls_ca_certificate,
        stable_connections: load.stable_connections,
        target_url: endpoint.url.clone(),
        ca_pem: cfg.tls_ca_pem()?,
        closed_loop: load.closed_loop,
    };
    let report = driver::run(sources, dcfg)
        .instrument(tracing::info_span!("unleash"))
        .await;
    // Stop the signer pool now the measured window is over (logs produced/stalls).
    drop(hot_path);
    tracing::info!(
        completed = report.completed,
        ok = report.ok,
        fail = report.fail,
        completed_rps = report.completed_rps,
        accepted_rps = report.accepted_rps,
        elapsed_ms = report.wall.as_millis() as u64,
        "phase: unleash complete"
    );

    // ── 7. Settle + sweep ───────────────────────────────────────────────────
    p.journal.set_status(Status::Settling)?;
    let t_settle = Instant::now();
    if !no_chain {
        let mut settlement = stream::iter(cleanup.iter())
            .map(|(idx, setup)| {
                let ctx = ctx_by_index[idx];
                async move {
                    let result: Result<()> = async {
                        if let Some(setup) = setup {
                            scheme
                                .settle_and_close(ctx, setup)
                                .await
                                .with_context(|| format!("settling user {}", ctx.index))?;
                        }
                        funder
                            .sweep(&ctx.wallet, mint_pk.as_ref())
                            .await
                            .with_context(|| format!("sweeping user {}", ctx.index))?;
                        Ok(())
                    }
                    .await;
                    (ctx.index, result)
                }
            })
            .buffer_unordered(load.settlement_concurrency);
        let mut swept_checkpoint = Vec::with_capacity(JOURNAL_CHECKPOINT_USERS);
        let mut failure_count = 0usize;
        let mut failure_samples = Vec::new();
        while let Some((index, result)) = settlement.next().await {
            match result {
                Ok(()) => {
                    swept_checkpoint.push(index);
                    if swept_checkpoint.len() == JOURNAL_CHECKPOINT_USERS {
                        p.journal.mark_users_swept(&swept_checkpoint)?;
                        swept_checkpoint.clear();
                    }
                }
                Err(error) => {
                    failure_count += 1;
                    if failure_samples.len() < 20 {
                        failure_samples.push(format!("user {index}: {error:#}"));
                    }
                }
            }
        }
        if !swept_checkpoint.is_empty() {
            p.journal.mark_users_swept(&swept_checkpoint)?;
        }
        if failure_count > 0 {
            bail!(
                "{failure_count} settlement/sweep operations failed; first failures:\n{}",
                failure_samples.join("\n")
            );
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
        cfg,
        succeeded,
        &report,
    ))
}

/// True only when `estimate` is definitively at or below `cap`. Any NaN makes
/// `partial_cmp` return `None`, which we treat as "not within cap" so callers
/// fail closed rather than comparing a non-finite value away.
fn within_cap(estimate: f64, cap: f64) -> bool {
    matches!(
        estimate.partial_cmp(&cap),
        Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
    )
}

/// Reject a run whose estimated spend exceeds the configured hard caps.
fn enforce_caps(cfg: &RunConfig, total_sol: f64, total_token: f64) -> Result<()> {
    let s = &cfg.run.safety;
    // Fail closed on non-finite values: `partial_cmp` returns `None` for any
    // NaN, which `within_cap` treats as "over budget" so a NaN cap or estimate
    // rejects the run instead of being compared away. Config validation already
    // rejects non-finite caps; this is defense in depth.
    if !within_cap(total_sol, s.max_total_sol) {
        bail!(
            "estimated SOL {total_sol:.4} exceeds cap max_total_sol={:.4}",
            s.max_total_sol
        );
    }
    if !within_cap(total_token, s.max_total_usdc) {
        bail!(
            "estimated token spend {total_token:.4} exceeds cap max_total_usdc={:.4}",
            s.max_total_usdc
        );
    }
    Ok(())
}

enum ProvisionOutcome {
    Provisioned(UserSetup),
    ProvisionFailed(anyhow::Error),
    FundingFailed(anyhow::Error),
}

fn user_record(
    ctx: &UserCtx,
    setup: Option<&UserSetup>,
    per: crate::scheme::PerUserFunding,
    funded: bool,
) -> UserRecord {
    UserRecord {
        index: ctx.index,
        pubkey: ctx.wallet.pubkey.to_string(),
        ata: setup.and_then(|value| value.ata.clone()),
        channel_id: setup.and_then(|value| value.channel_id.clone()),
        open_sig: setup.and_then(|value| value.open_sig.clone()),
        token_base: per.token_base,
        sol_lamports: per.sol_lamports,
        funding_started: true,
        funded,
        swept: false,
    }
}

async fn verified_mint_decimals(
    rpc_url: &str,
    mint: &Pubkey,
    challenge_decimals: u8,
) -> Result<u8> {
    let response: Value = reqwest::Client::new()
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [mint.to_string(), {"encoding": "jsonParsed", "commitment": "confirmed"}],
        }))
        .send()
        .await
        .context("fetching SPL mint decimals")?
        .error_for_status()
        .context("SPL mint decimals RPC returned an error status")?
        .json()
        .await
        .context("decoding SPL mint decimals RPC response")?;
    validate_challenge_decimals(mint, challenge_decimals, mint_decimals_from_rpc(&response)?)
}

fn mint_decimals_from_rpc(response: &Value) -> Result<u8> {
    if let Some(error) = response.get("error") {
        bail!("SPL mint decimals RPC error: {error}");
    }
    let account = response
        .pointer("/result/value")
        .filter(|value| !value.is_null())
        .context("SPL mint account does not exist")?;
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .context("SPL mint account owner is missing")?;
    anyhow::ensure!(
        matches!(
            owner,
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                | "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        ),
        "mint account is not owned by a recognized SPL token program"
    );
    account
        .pointer("/data/parsed/info/decimals")
        .and_then(Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .context("SPL mint decimals are missing or invalid")
}

fn validate_challenge_decimals(
    mint: &Pubkey,
    challenge_decimals: u8,
    mint_decimals: u8,
) -> Result<u8> {
    anyhow::ensure!(
        mint_decimals == challenge_decimals,
        "payment challenge decimals ({challenge_decimals}) do not match mint {mint} decimals ({mint_decimals})"
    );
    Ok(mint_decimals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_caps(sol: f64, usdc: f64) -> RunConfig {
        let mut cfg: RunConfig =
            serde_yml::from_str(include_str!("../configs/selftest-10k.yml")).unwrap();
        cfg.run.safety.max_total_sol = sol;
        cfg.run.safety.max_total_usdc = usdc;
        cfg
    }

    #[test]
    fn enforce_caps_accepts_within_budget() {
        let cfg = config_with_caps(1.0, 1.0);
        enforce_caps(&cfg, 0.5, 0.5).unwrap();
    }

    #[test]
    fn enforce_caps_rejects_over_budget() {
        let cfg = config_with_caps(1.0, 1.0);
        assert!(enforce_caps(&cfg, 2.0, 0.5).is_err());
        assert!(enforce_caps(&cfg, 0.5, 2.0).is_err());
    }

    #[test]
    fn enforce_caps_fails_closed_on_non_finite() {
        // A NaN cap must never wave a spend through, even if config validation
        // is bypassed. `!(x <= NaN)` is true, so the run is rejected.
        assert!(enforce_caps(&config_with_caps(f64::NAN, 1.0), 1.0, 0.5).is_err());
        assert!(enforce_caps(&config_with_caps(1.0, f64::NAN), 0.5, 1.0).is_err());
        // A NaN estimate is likewise rejected rather than compared away.
        assert!(enforce_caps(&config_with_caps(1.0, 1.0), f64::NAN, 0.5).is_err());
    }

    #[test]
    fn challenge_decimals_must_match_the_mint() {
        let mint = Pubkey::new_from_array([7; 32]);
        assert_eq!(validate_challenge_decimals(&mint, 6, 6).unwrap(), 6);
        assert!(validate_challenge_decimals(&mint, 6, 9).is_err());
    }

    #[test]
    fn mint_decimals_requires_a_token_program_owned_mint() {
        let response = json!({
            "result": {"value": {
                "owner": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                "data": {"parsed": {"info": {"decimals": 6}}}
            }}
        });
        assert_eq!(mint_decimals_from_rpc(&response).unwrap(), 6);

        let not_a_mint = json!({
            "result": {"value": {
                "owner": "11111111111111111111111111111111",
                "data": {"parsed": {"info": {"decimals": 6}}}
            }}
        });
        assert!(mint_decimals_from_rpc(&not_a_mint).is_err());
    }
}
