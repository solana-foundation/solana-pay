//! `bench` — Pay mainnet scaling harness.
//!
//! Subcommands:
//!   rehearse <cfg>   full pipeline on a local surfpool fork (no real funds)
//!   run <cfg>        real run (mainnet); --yes required on real-money networks
//!   list-runs        show recorded runs + outstanding-fund status
//!   recover <id>     resume settle+sweep for an interrupted run (or --all)
//!   estimate <cfg>   validate a config and print parsed settings
//!
//! See `bench/README.md` and the approved plan for the design.

mod batch_reclaim;
mod channel_recovery;
mod config;
mod driver;
mod engine;
mod fixture_rpc;
mod fixtures;
mod h2pool;
mod journal;
mod observability;
mod rehearsal;
mod report;
mod scheme;
mod seeded_session;
mod session_recovery;
mod wallet;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::config::{Network, RunConfig};
use crate::journal::Journal;

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;
    if parsed == 0 {
        return Err("value must be greater than zero".to_string());
    }
    Ok(parsed)
}

#[derive(Parser)]
#[command(name = "bench", about = "Pay mainnet scaling harness", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Export spans + metrics to this OTLP endpoint (host:port or URL). Falls
    /// back to OTEL_EXPORTER_OTLP_ENDPOINT. Console logs are always on.
    #[arg(long, global = true, value_name = "HOST:PORT|URL")]
    otlp: Option<String>,
    /// Push CPU profiles (flamegraphs) to a Pyroscope server. Bare `--pyroscope`
    /// uses the local LGTM (`http://localhost:4040`); explore in Grafana →
    /// Pyroscope, app `pay-bench`.
    #[arg(
        long,
        global = true,
        value_name = "URL",
        num_args = 0..=1,
        default_missing_value = "http://localhost:4040"
    )]
    pyroscope: Option<String>,
    /// Allow payment credentials over plaintext HTTP to non-loopback hosts.
    /// Benchmarking escape hatch ONLY — never point this at a gateway holding
    /// real funds. Also requires `PAY_BENCH_ALLOW_INSECURE_HTTP=1` in the
    /// environment so it can't be muscle-memory'd into a real run.
    #[arg(long, global = true)]
    allow_insecure_http: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Rehearse a config against a local surfpool fork (no real funds).
    Rehearse { config: String },
    /// Run a config for real. Requires --yes on real-money networks.
    Run {
        config: String,
        /// Reuse wallets prepared by `bench setup --id <ID>` instead of
        /// funding a fresh timestamp-scoped wallet set.
        #[arg(long)]
        fixture_id: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Provision deterministic wallets and token accounts for a reusable
    /// public-cluster benchmark fixture. Requires --yes.
    Setup {
        config: String,
        /// Stable fixture ID. Reusing an ID resumes the same derived wallets.
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        yes: bool,
    },
    /// Mint the setup config's first asset to the funder ATA (funder must be the
    /// mint authority). Tops up the distributor before `setup` when extending a
    /// fixture beyond the currently-funded supply. Devnet only.
    Mint {
        config: String,
        /// Human decimal amount to mint, e.g. "700000".
        #[arg(long)]
        amount: String,
        #[arg(long)]
        yes: bool,
    },
    /// Export deterministic fixture recipients as a `pay fanout` CSV without
    /// exposing any derived private keys.
    ExportFanout {
        config: String,
        /// Fixture ID used as the derivation namespace unless the config
        /// declares `setup.wallet_set_id`.
        #[arg(long)]
        id: String,
        /// First zero-based wallet index to include.
        #[arg(long, default_value_t = 0)]
        start: usize,
        /// Destination CSV. Refuses to overwrite an existing file.
        #[arg(long)]
        output: String,
    },
    /// Transfer fixture balances home and close all derived token accounts.
    Teardown {
        setup_id: String,
        /// The same setup YAML used to create the fixture. It supplies the
        /// RPC and funder reference without persisting either secret.
        #[arg(long)]
        config: String,
        #[arg(long)]
        yes: bool,
    },
    /// List recorded runs and their status.
    ListRuns,
    /// Recover (settle + sweep) an interrupted run, or all outstanding runs.
    Recover {
        #[arg(required_unless_present = "all")]
        run_id: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Discover and close live fixture sessions left by an interrupted run.
    RecoverSessions {
        config: String,
        /// Reusable fixture whose deterministic wallets opened the channels.
        #[arg(long)]
        fixture_id: String,
        /// Confirm that this command may submit channel-close transactions.
        #[arg(long)]
        yes: bool,
        /// Bypass a lost gateway store and settle channels with zero vouchers.
        /// Safe only when the measured load phase never started.
        #[arg(long)]
        assume_no_vouchers: bool,
        /// With --assume-no-vouchers, also close channels that already carry a
        /// non-zero settled amount: seal at the on-chain amount, pay the payee
        /// (== funder), refund the payer, and reclaim rent. Used to sweep stale
        /// channels from prior runs whose gateway voucher state is gone.
        #[arg(long)]
        allow_settled: bool,
    },
    /// Top up existing fixture channels' deposits to a target so a long reuse
    /// run does not hit the per-channel cap mid-run. Each top-up is signed and
    /// funded by the channel's own deterministic payer wallet. Devnet only.
    TopUp {
        config: String,
        /// Reusable fixture whose deterministic wallets own the channels.
        #[arg(long)]
        fixture_id: String,
        /// Target per-channel deposit in USDC; channels below it are topped up.
        #[arg(long)]
        target_usdc: f64,
        #[arg(long)]
        yes: bool,
    },
    /// Recover x402 batch-settlement channels a run left open: request_close
    /// -> wait for the grace period -> finalize_close -> wait for the
    /// open-slot window -> reclaim. Returns the operator's escrowed rent.
    /// Plain on-chain instructions — the gateway does not need to be running.
    BatchReclaim {
        config: String,
        /// Reusable fixture whose deterministic wallets opened the channels.
        #[arg(long)]
        fixture_id: String,
        /// Number of fixture wallets to scan (0..users).
        #[arg(long)]
        users: usize,
        /// The channels' distribution recipient (payTo), base58.
        #[arg(long)]
        receiver: String,
        #[arg(
            long,
            default_value_t = 100,
            value_parser = parse_positive_usize
        )]
        concurrency: usize,
        #[arg(long)]
        yes: bool,
    },
    /// Validate a config and print the parsed settings.
    Estimate { config: String },
    /// Spin only the proxy (+ fork) and block, so it can be profiled in
    /// isolation. Drive it from a separate `bench load` process.
    Serve { config: String },
    /// Drive load against an external proxy (started by `bench serve`).
    Load {
        config: String,
        #[arg(long)]
        proxy: String,
        #[arg(long)]
        rpc: String,
    },
}

/// Service/profiler identity per subcommand: the proxy-only `serve` process
/// reports as `pay-proxy` so its traces/metrics/flamegraph stay separate from
/// the load generator (`pay-bench`).
fn identity(cmd: &Cmd) -> &'static str {
    match cmd {
        Cmd::Serve { .. } => "pay-proxy",
        _ => "pay-bench",
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.allow_insecure_http {
        if std::env::var("PAY_BENCH_ALLOW_INSECURE_HTTP").as_deref() != Ok("1") {
            bail!(
                "--allow-insecure-http also requires PAY_BENCH_ALLOW_INSECURE_HTTP=1 in the \
                 environment — belt-and-suspenders so this can't be muscle-memory'd into a \
                 real run against real funds"
            );
        }
        eprintln!(
            "\u{26a0}\u{fe0f}  --allow-insecure-http: payment credentials will be sent over \
             PLAINTEXT HTTP to non-loopback hosts. Benchmarking only — never point this at a \
             gateway handling real funds."
        );
        scheme::ALLOW_INSECURE_HTTP.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    let otlp = cli
        .otlp
        .clone()
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());
    let service = identity(&cli.cmd);
    // Hold the guard for the whole process so OTLP batches flush on exit.
    let _guard = observability::init(service, otlp.as_deref());
    warn_incomplete();

    // Optional CPU profiling → Pyroscope (flamegraphs in Grafana).
    let profiler = match cli.pyroscope.as_deref() {
        Some(url) => {
            use pyroscope::PyroscopeAgent;
            use pyroscope_pprofrs::{PprofConfig, pprof_backend};
            let agent = PyroscopeAgent::builder(url, service)
                .backend(pprof_backend(PprofConfig::new().sample_rate(100)))
                .build()
                .context("pyroscope build")?;
            tracing::info!(url, app = service, "pyroscope profiling enabled");
            Some(agent.start().context("pyroscope start")?)
        }
        None => None,
    };

    let rt = observability::named_runtime("bench").context("build bench runtime")?;
    let result = rt.block_on(run(cli.cmd));

    // Stop + flush the profiler so the last samples reach Pyroscope.
    if let Some(running) = profiler
        && let Ok(ready) = running.stop()
    {
        ready.shutdown();
    }
    result
}

async fn run(cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Rehearse { config } => {
            let cfg = RunConfig::from_yaml_path(&config)?;
            let report = rehearsal::run(cfg).await?;
            finish(report)
        }
        Cmd::Run {
            config,
            fixture_id,
            yes,
        } => run_real(&config, fixture_id.as_deref(), yes).await,
        Cmd::Setup { config, id, yes } => fixtures::setup(&config, id.as_deref(), yes).await,
        Cmd::Mint {
            config,
            amount,
            yes,
        } => fixtures::mint_supply(&config, &amount, yes).await,
        Cmd::ExportFanout {
            config,
            id,
            start,
            output,
        } => fixtures::export_fanout(&config, &id, start, &output),
        Cmd::Teardown {
            setup_id,
            config,
            yes,
        } => fixtures::teardown(&setup_id, &config, yes).await,
        Cmd::ListRuns => list_runs(),
        Cmd::Recover { run_id, all } => recover(run_id, all).await,
        Cmd::RecoverSessions {
            config,
            fixture_id,
            yes,
            assume_no_vouchers,
            allow_settled,
        } => {
            session_recovery::recover(&config, &fixture_id, yes, assume_no_vouchers, allow_settled)
                .await
        }
        Cmd::TopUp {
            config,
            fixture_id,
            target_usdc,
            yes,
        } => session_recovery::top_up(&config, &fixture_id, target_usdc, yes).await,
        Cmd::BatchReclaim {
            config,
            fixture_id,
            users,
            receiver,
            concurrency,
            yes,
        } => {
            batch_reclaim::recover_batch(&config, &fixture_id, users, &receiver, concurrency, yes)
                .await
        }
        Cmd::Serve { config } => {
            let cfg = RunConfig::from_yaml_path(&config)?;
            rehearsal::serve_proxy(cfg).await
        }
        Cmd::Load { config, proxy, rpc } => {
            let cfg = RunConfig::from_yaml_path(&config)?;
            let report = rehearsal::load(cfg, proxy, rpc).await?;
            finish(report)
        }
        Cmd::Estimate { config } => {
            let cfg = RunConfig::from_yaml_path(&config)?;
            println!("{cfg:#?}");
            Ok(())
        }
    }
}

/// Print the summary and write a JSON artifact next to the cwd.
fn finish(report: report::ReportJson) -> Result<()> {
    println!("{}", report.summary());
    let path = std::path::PathBuf::from(format!("bench-report-{}.json", report.run_id));
    report.write_json(&path)?;
    println!("report written to {}", path.display());
    Ok(())
}

async fn run_real(config: &str, fixture_id: Option<&str>, yes: bool) -> Result<()> {
    let cfg = RunConfig::from_yaml_path(config)?;
    if cfg.run.network.is_real_money() && cfg.run.safety.require_confirmation && !yes {
        bail!(
            "network `{:?}` spends real funds — re-run with --yes to confirm",
            cfg.run.network
        );
    }
    let rpc_url = cfg
        .resolve_rpc_url()?
        .context("a real run needs an RPC URL (rpc_url or rpc_url_env)")?;
    let funder_wallet = wallet::load_funder(&cfg.run.funder, cfg.run.network)?;
    let mainnet_funder = wallet::MainnetFunder {
        rpc_url: rpc_url.clone(),
        funder: funder_wallet.clone(),
    };
    let fixture_funder = wallet::FixtureFunder;
    let wallet_set_id = fixture_id
        .map(|id| fixtures::validate_ready_fixture(id, &cfg, &funder_wallet))
        .transpose()?;
    let funder: &dyn wallet::Funder = if fixture_id.is_some() {
        &fixture_funder
    } else {
        &mainnet_funder
    };
    let scheme = scheme::build(&cfg);

    let run_id = journal::new_run_id(&cfg.run.name, &chrono::Utc::now());
    let mut jrnl = Journal::create(
        run_id.clone(),
        cfg.run.name.clone(),
        cfg.run.scheme,
        cfg.run.network,
        funder_wallet.pubkey.to_string(),
    )?;

    let report = engine::run_pipeline(engine::PipelineParams {
        config: &cfg,
        scheme: scheme.as_ref(),
        funder,
        funder_seed: funder_wallet.seed(),
        wallet_set_id: wallet_set_id.as_deref().unwrap_or(&run_id),
        rpc_url,
        host_override: None,
        journal: &mut jrnl,
    })
    .await?;
    finish(report)
}

fn list_runs() -> Result<()> {
    let runs = Journal::scan_all()?;
    if runs.is_empty() {
        println!("no recorded runs (looked in {})", Journal::dir()?.display());
        return Ok(());
    }
    println!(
        "{:<34} {:<13} {:<9} {:>6} {:>6}  STATUS",
        "RUN ID", "SCHEME", "NETWORK", "USERS", "UNSWPT"
    );
    for r in runs {
        let unswept = r
            .users
            .iter()
            .filter(|u| (u.funded || u.funding_started) && !u.swept)
            .count();
        println!(
            "{:<34} {:<13} {:<9} {:>6} {:>6}  {:?}",
            r.run_id,
            format!("{:?}", r.scheme),
            format!("{:?}", r.network),
            r.users.len(),
            unswept,
            r.status,
        );
    }
    Ok(())
}

async fn recover(run_id: Option<String>, all: bool) -> Result<()> {
    let targets: Vec<journal::RunState> = if all {
        Journal::scan_incomplete()?
    } else {
        vec![
            Journal::load(&run_id.expect("clap guarantees run_id when !all"))?
                .state()
                .clone(),
        ]
    };
    if targets.is_empty() {
        println!("nothing to recover — no outstanding runs");
        return Ok(());
    }
    for state in targets {
        let unswept = state
            .users
            .iter()
            .filter(|u| (u.funded || u.funding_started) && !u.swept)
            .count();
        println!(
            "recover {} ({:?}, {:?}): {} unswept of {} users",
            state.run_id,
            state.scheme,
            state.network,
            unswept,
            state.users.len()
        );
        match state.network {
            Network::Fork => {
                // Fork ledgers are ephemeral; once the validator is gone there
                // is nothing on-chain to sweep. Mark the journal terminal.
                let mut j = Journal::load(&state.run_id)?;
                j.set_status(journal::Status::Complete)?;
                println!("  fork run — ledger ephemeral, marked complete");
            }
            Network::Mainnet | Network::Devnet => {
                // Real sweep lands in M4 (MainnetFunder). The wallets are
                // re-derivable from the funder secret + run_id; surface that.
                bail!(
                    "  mainnet/devnet recovery not implemented yet (M4): \
                     re-derive users from funder + run_id `{}` and sweep",
                    state.run_id
                );
            }
        }
    }
    Ok(())
}

/// Warn loudly if any prior run still has outstanding funds.
fn warn_incomplete() {
    if let Ok(runs) = Journal::scan_incomplete() {
        let real: Vec<_> = runs.iter().filter(|r| r.network.is_real_money()).collect();
        if !real.is_empty() {
            tracing::warn!(
                count = real.len(),
                "outstanding real-money runs may hold funds — `bench list-runs` / `bench recover`"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::parse_positive_usize;

    #[test]
    fn positive_usize_parser_rejects_zero() {
        assert!(parse_positive_usize("0").is_err());
        assert_eq!(parse_positive_usize("1").unwrap(), 1);
    }
}
