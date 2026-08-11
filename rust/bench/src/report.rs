//! Run reporting — a human summary table and a machine-readable JSON artifact.

use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::driver::DriverReport;

#[derive(Serialize)]
pub struct ReportJson {
    pub run_id: String,
    pub scheme: String,
    pub network: String,
    pub users: usize,
    pub rps_per_user: f64,
    pub dispatched: u64,
    pub completed: u64,
    pub ok: u64,
    pub fail: u64,
    pub wall_secs: f64,
    pub rps_overall: f64,
    pub latency_ms: LatencyMs,
    pub status_counts: HashMap<String, u64>,
    pub error_counts: HashMap<String, u64>,
    pub rps_series: Vec<u64>,
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
        network: &str,
        users: usize,
        rps_per_user: f64,
        r: &DriverReport,
    ) -> Self {
        ReportJson {
            run_id: run_id.to_string(),
            scheme: scheme.to_string(),
            network: network.to_string(),
            users,
            rps_per_user,
            dispatched: r.dispatched,
            completed: r.completed,
            ok: r.ok,
            fail: r.fail,
            wall_secs: r.wall.as_secs_f64(),
            rps_overall: r.rps_overall,
            latency_ms: LatencyMs {
                p50: r.p50_ms,
                p90: r.p90_ms,
                p99: r.p99_ms,
                p999: r.p999_ms,
                max: r.max_ms,
                mean: r.mean_ms,
            },
            status_counts: r
                .status_counts
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect(),
            error_counts: r.error_counts.clone(),
            rps_series: r.rps_series.clone(),
        }
    }

    pub fn write_json(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json).with_context(|| format!("writing report {}", path.display()))?;
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
            "requests   dispatched {}  completed {}  ok {} ({:.1}%)  fail {}\n",
            self.dispatched, self.completed, self.ok, ok_pct, self.fail
        ));
        s.push_str(&format!(
            "throughput {:.0} req/s over {:.1}s\n",
            self.rps_overall, self.wall_secs
        ));
        s.push_str(&format!(
            "latency    p50 {:.2}ms  p90 {:.2}ms  p99 {:.2}ms  p99.9 {:.2}ms  max {:.2}ms  mean {:.2}ms\n",
            self.latency_ms.p50,
            self.latency_ms.p90,
            self.latency_ms.p99,
            self.latency_ms.p999,
            self.latency_ms.max,
            self.latency_ms.mean,
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
