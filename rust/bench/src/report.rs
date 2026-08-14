//! Run reporting — a human summary table and a machine-readable JSON artifact.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::RunConfig;
use crate::driver::DriverReport;

#[derive(Serialize)]
pub struct ReportJson {
    pub code: CodeFingerprint,
    pub host: HostFingerprint,
    pub config_sha256: String,
    pub run_id: String,
    pub scheme: String,
    pub network: String,
    pub users: usize,
    pub rps_per_user: f64,
    pub target_rps: f64,
    pub scheduled: u64,
    pub dispatched: u64,
    pub completed: u64,
    pub accepted: u64,
    pub ok: u64,
    pub fail: u64,
    pub dropped: u64,
    pub wall_secs: f64,
    pub drain_secs: f64,
    pub completed_rps: f64,
    pub accepted_rps: f64,
    pub target_achievement_pct: f64,
    pub signing_rps: f64,
    pub service_latency_ms: LatencyMs,
    pub signing_latency_ms: LatencyMs,
    pub schedule_delay_ms: LatencyMs,
    pub end_to_end_latency_ms: LatencyMs,
    pub max_in_flight: usize,
    pub status_counts: HashMap<String, u64>,
    pub error_counts: HashMap<String, u64>,
    pub rps_series: Vec<u64>,
    pub accepted_rps_series: Vec<u64>,
}

#[derive(Serialize)]
pub struct CodeFingerprint {
    pub pay_head: Option<String>,
    pub pay_dirty: Option<bool>,
    pub pay_kit_rev: Option<String>,
    pub build_profile: &'static str,
}

#[derive(Serialize)]
pub struct HostFingerprint {
    pub hostname: Option<String>,
    pub kernel: Option<String>,
    pub os: &'static str,
    pub arch: &'static str,
    pub logical_cpus: usize,
}

#[derive(Serialize)]
pub struct LatencyMs {
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
    pub mean: f64,
}

impl ReportJson {
    pub fn from_driver(
        run_id: &str,
        scheme: &str,
        cfg: &RunConfig,
        users: usize,
        r: &DriverReport,
    ) -> Self {
        ReportJson {
            code: code_fingerprint(),
            host: host_fingerprint(),
            config_sha256: config_sha256(cfg),
            run_id: run_id.to_string(),
            scheme: scheme.to_string(),
            network: cfg.run.network.slug().to_string(),
            users,
            rps_per_user: cfg.load.requests_per_sec_per_user,
            target_rps: r.target_rps,
            scheduled: r.scheduled,
            dispatched: r.dispatched,
            completed: r.completed,
            accepted: r.accepted,
            ok: r.ok,
            fail: r.fail,
            dropped: r.dropped,
            wall_secs: r.wall.as_secs_f64(),
            drain_secs: r.drain.as_secs_f64(),
            completed_rps: r.completed_rps,
            accepted_rps: r.accepted_rps,
            target_achievement_pct: if r.target_rps > 0.0 {
                100.0 * r.accepted_rps / r.target_rps
            } else {
                0.0
            },
            signing_rps: r.signing_rps,
            service_latency_ms: LatencyMs::from(r.service_latency_ms),
            signing_latency_ms: LatencyMs::from(r.signing_latency_ms),
            schedule_delay_ms: LatencyMs::from(r.schedule_delay_ms),
            end_to_end_latency_ms: LatencyMs::from(r.end_to_end_latency_ms),
            max_in_flight: r.max_in_flight,
            status_counts: r
                .status_counts
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            error_counts: r.error_counts.clone(),
            rps_series: r.rps_series.clone(),
            accepted_rps_series: r.accepted_rps_series.clone(),
        }
    }

    pub fn write_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("report path needs a UTF-8 file name")?;
        let temporary = path.with_file_name(format!(".{file_name}.tmp"));
        std::fs::write(&temporary, json)
            .with_context(|| format!("writing report staging file {}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("publishing report {}", path.display()))?;
        Ok(())
    }

    /// A compact, human-scannable summary.
    pub fn summary(&self) -> String {
        let ok_pct = if self.completed > 0 {
            100.0 * self.ok as f64 / self.completed as f64
        } else {
            0.0
        };
        let mut s = String::new();
        s.push_str("\n========== BENCH RESULT ==========\n");
        s.push_str(&format!("run        {}\n", self.run_id));
        s.push_str(&format!("scheme     {} ({})\n", self.scheme, self.network));
        s.push_str(&format!(
            "load       {} users × {:.1} rps/user\n",
            self.users, self.rps_per_user
        ));
        s.push_str(&format!(
            "requests   scheduled {}  dispatched {}  completed {}  accepted {}  ok {} ({:.1}%)  fail {}  dropped {}\n",
            self.scheduled, self.dispatched, self.completed, self.accepted, self.ok, ok_pct, self.fail, self.dropped
        ));
        s.push_str(&format!(
            "throughput {:.0} accepted/s ({:.1}% of {:.0} target)  {:.0} completed/s  {:.0} signed/s over {:.1}s (+{:.3}s drain)\n",
            self.accepted_rps,
            self.target_achievement_pct,
            self.target_rps,
            self.completed_rps,
            self.signing_rps,
            self.wall_secs,
            self.drain_secs,
        ));
        s.push_str(&format!(
            "service    p50 {:.2}ms  p90 {:.2}ms  p99 {:.2}ms  p99.9 {:.2}ms  max {:.2}ms  mean {:.2}ms\n",
            self.service_latency_ms.p50,
            self.service_latency_ms.p90,
            self.service_latency_ms.p99,
            self.service_latency_ms.p999,
            self.service_latency_ms.max,
            self.service_latency_ms.mean,
        ));
        s.push_str(&format!(
            "schedule   p99 {:.2}ms  end-to-end p99 {:.2}ms  signing p99 {:.2}ms  max in-flight {}\n",
            self.schedule_delay_ms.p99,
            self.end_to_end_latency_ms.p99,
            self.signing_latency_ms.p99,
            self.max_in_flight,
        ));
        let mut statuses: Vec<_> = self.status_counts.iter().collect();
        statuses.sort_by(|a, b| a.0.cmp(b.0));
        let status_line: Vec<String> = statuses.iter().map(|(k, v)| format!("{k}×{v}")).collect();
        s.push_str(&format!("status     {}\n", status_line.join("  ")));
        if !self.error_counts.is_empty() {
            let mut errs: Vec<_> = self.error_counts.iter().collect();
            errs.sort_by(|a, b| b.1.cmp(a.1));
            let err_line: Vec<String> = errs.iter().map(|(k, v)| format!("{k}×{v}")).collect();
            s.push_str(&format!("errors     {}\n", err_line.join("  ")));
        }
        s.push_str("==================================\n");
        s
    }
}

fn code_fingerprint() -> CodeFingerprint {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pay_head = command_output(
        Command::new("git")
            .arg("-C")
            .arg(&workspace)
            .args(["rev-parse", "HEAD"]),
    );
    let pay_dirty = command_output(Command::new("git").arg("-C").arg(&workspace).args([
        "status",
        "--porcelain",
        "--untracked-files=no",
    ]))
    .map(|status| !status.is_empty());
    let pay_kit_rev = std::fs::read_to_string(workspace.join("rust/Cargo.toml"))
        .ok()
        .and_then(|cargo| extract_pay_kit_rev(&cargo));
    CodeFingerprint {
        pay_head,
        pay_dirty,
        pay_kit_rev,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    }
}

fn host_fingerprint() -> HostFingerprint {
    HostFingerprint {
        hostname: command_output(&mut Command::new("hostname")),
        kernel: command_output(Command::new("uname").arg("-r")),
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        logical_cpus: std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1),
    }
}

fn command_output(command: &mut Command) -> Option<String> {
    let output = command.output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn config_sha256(cfg: &RunConfig) -> String {
    let bytes = serde_json::to_vec(cfg).expect("validated config serializes");
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn extract_pay_kit_rev(cargo: &str) -> Option<String> {
    let line = cargo
        .lines()
        .find(|line| line.trim_start().starts_with("pay-kit =") && line.contains("rev ="))?;
    let rest = line.split_once("rev =")?.1.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    Some(rest[1..].split_once(quote)?.0.to_string())
}

impl From<crate::driver::LatencySummary> for LatencyMs {
    fn from(value: crate::driver::LatencySummary) -> Self {
        Self {
            p50: value.p50,
            p90: value.p90,
            p99: value.p99,
            p999: value.p999,
            max: value.max,
            mean: value.mean,
        }
    }
}
