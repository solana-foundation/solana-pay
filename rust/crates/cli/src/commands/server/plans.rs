//! `pay server plans publish` — publish on-chain `Plan` PDAs for every
//! subscription endpoint declared in a pay-demo.yaml.
//!
//! v0 surface: derives the deterministic Plan PDA per endpoint from the
//! operator's wallet + a stable seed and writes the address back into the
//! YAML in place. The on-chain `create_plan` broadcast is a TODO — pay-kit
//! exposes `INSTRUCTION_CREATE_PLAN = 7` but the SDK does not yet ship a
//! typed account-meta builder for it. Running with `--dry-run` is the
//! safe default until that lands; users with a manual publish script can
//! still benefit from the PDA derivation + write-back today.

use std::path::PathBuf;
use std::str::FromStr;

use owo_colors::OwoColorize;
use pay_core::server::subscription::compute_plan_id_numeric;
use pay_kit::mpp::program::subscriptions::{default_program_id, find_plan_pda, plan_id_seed};
use solana_pubkey::Pubkey;

#[derive(clap::Args)]
pub struct PublishCommand {
    /// Path to the YAML spec containing `subscription:` endpoints.
    /// Defaults to `./pay-demo.yaml`.
    #[arg(long, default_value = "pay-demo.yaml")]
    pub spec: PathBuf,

    /// Explicit Plan owner pubkey (base58). When omitted, falls back to
    /// `operator.recipient` in the spec.
    #[arg(long)]
    pub owner: Option<String>,

    /// Print the derived Plan PDAs without modifying the YAML. The default
    /// for v0 because the on-chain broadcast path is not yet implemented.
    #[arg(long, default_value_t = true)]
    pub dry_run: bool,

    /// Write the derived Plan PDAs back into the YAML. Use this once the
    /// Plan accounts have been published on-chain through another tool —
    /// pay does not broadcast them in v0.
    #[arg(long)]
    pub write: bool,
}

impl PublishCommand {
    pub fn run(self) -> pay_core::Result<()> {
        let raw = std::fs::read_to_string(&self.spec).map_err(|e| {
            pay_core::Error::Config(format!("Failed to read {}: {e}", self.spec.display()))
        })?;
        let api: pay_types::metering::ApiSpec = serde_yml::from_str(&raw).map_err(|e| {
            pay_core::Error::Config(format!("Invalid YAML at {}: {e}", self.spec.display()))
        })?;

        let owner_str = if let Some(o) = self.owner.clone() {
            o
        } else {
            let operator = api.operator.as_ref().ok_or_else(|| {
                pay_core::Error::Config(
                    "spec has no `operator:` block; pass --owner <pubkey> instead".to_string(),
                )
            })?;
            operator.recipient.clone().ok_or_else(|| {
                pay_core::Error::Config(
                    "spec has no `operator.recipient`; pass --owner <pubkey> to specify the Plan owner".to_string(),
                )
            })?
        };
        let owner = Pubkey::from_str(&owner_str).map_err(|e| {
            pay_core::Error::Config(format!("Plan owner is not a valid pubkey: {e}"))
        })?;
        let program_id = default_program_id();

        let mut rows: Vec<PlanRow> = Vec::new();
        for endpoint in &api.endpoints {
            let Some(sub) = endpoint.subscription.as_ref() else {
                continue;
            };
            // Stable plan-id derivation: must match `pay gate api`
            // (see `pay_core::server::subscription::compute_plan_id_numeric`
            // + `pay_kit::mpp::program::subscriptions::plan_id_seed`) so the
            // PDA this command writes back to the YAML is the same one
            // the running server expects to find on-chain.
            //
            // Reuse a YAML-pinned `plan_id_numeric` when present so an
            // operator who hand-edited the value keeps a stable PDA.
            let plan_id_numeric = sub
                .plan_id_numeric
                .unwrap_or_else(|| compute_plan_id_numeric(&owner_str, &endpoint.path));
            let seed = plan_id_seed(plan_id_numeric);
            let (plan_pda, _) = find_plan_pda(&owner, &seed, &program_id);
            rows.push(PlanRow {
                method: format!("{:?}", endpoint.method).to_uppercase(),
                path: endpoint.path.clone(),
                period: sub.period.clone(),
                currency: sub.currency.clone(),
                derived_plan: plan_pda.to_string(),
                existing_plan: sub.plan_id.clone(),
            });
        }

        if rows.is_empty() {
            eprintln!(
                "{}",
                "No subscription endpoints found in spec — nothing to publish.".dimmed()
            );
            return Ok(());
        }

        eprintln!();
        eprintln!("Subscription endpoints:");
        for row in &rows {
            let status = match row.existing_plan.as_deref() {
                Some(existing) if existing == row.derived_plan => {
                    "already pinned".green().to_string()
                }
                Some(_) => "differs from spec".yellow().to_string(),
                None => "pending publish".dimmed().to_string(),
            };
            let label = format!("{} {}", row.method, row.path);
            let header = label.bold();
            eprintln!("  {header} [{status}]");
            eprintln!("    period   {}", row.period);
            eprintln!("    currency {}", row.currency);
            eprintln!("    plan     {}", row.derived_plan);
            if let Some(existing) = row.existing_plan.as_deref()
                && existing != row.derived_plan
            {
                eprintln!("    {} {}", "existing in YAML:".yellow(), existing);
            }
        }
        eprintln!();

        if self.write {
            let updated = write_back_plan_ids(&raw, &rows)?;
            std::fs::write(&self.spec, updated).map_err(|e| {
                pay_core::Error::Config(format!("Failed to write {}: {e}", self.spec.display()))
            })?;
            eprintln!(
                "{} {}",
                "Wrote plan_id values into".green(),
                self.spec.display().to_string().green()
            );
        } else if self.dry_run {
            eprintln!(
                "{}",
                "Dry run: no YAML changes. Pass --write to update plan_id in place once the \n\
                 Plan accounts have been published on-chain. The actual on-chain broadcast \n\
                 will land in a follow-up slice (pay-kit's INSTRUCTION_CREATE_PLAN=7 still \n\
                 needs an account-meta builder)."
                    .dimmed()
            );
        }

        Ok(())
    }
}

struct PlanRow {
    method: String,
    path: String,
    period: String,
    currency: String,
    derived_plan: String,
    existing_plan: Option<String>,
}

/// In-place rewrite of `plan_id:` lines under each `subscription:` block.
/// Operates on the YAML text directly so comments and key ordering are
/// preserved — `serde_yml::to_string` would strip both.
fn write_back_plan_ids(yaml: &str, rows: &[PlanRow]) -> pay_core::Result<String> {
    // Build a quick lookup keyed by endpoint path. The spec doesn't allow
    // duplicate `(method, path)` pairs so the path alone is unique enough
    // for the in-place rewrite.
    let by_path: std::collections::HashMap<&str, &str> = rows
        .iter()
        .map(|r| (r.path.as_str(), r.derived_plan.as_str()))
        .collect();

    let mut out = String::with_capacity(yaml.len() + 256);
    let mut current_path: Option<String> = None;
    let mut inside_subscription = false;
    let mut subscription_indent: Option<usize> = None;
    let mut wrote_plan_id_for_current = false;

    for line in yaml.lines() {
        let stripped = line.trim_start();
        let indent = line.len() - stripped.len();

        // Track the current endpoint via `path:` lines under the
        // `endpoints:` list.
        if let Some(rest) = stripped.strip_prefix("path:") {
            let path_value = rest.trim().trim_matches('"').trim_matches('\'').to_string();
            current_path = Some(path_value);
            inside_subscription = false;
            subscription_indent = None;
            wrote_plan_id_for_current = false;
        } else if stripped.starts_with("subscription:") {
            inside_subscription = true;
            subscription_indent = Some(indent);
        } else if inside_subscription
            && let Some(block_indent) = subscription_indent
            && stripped.starts_with("plan_id:")
            && indent > block_indent
        {
            wrote_plan_id_for_current = true;
            // Replace the existing line with the derived value, preserving
            // indent.
            if let Some(path) = current_path.as_deref()
                && let Some(plan) = by_path.get(path)
            {
                let prefix = &line[..indent];
                out.push_str(prefix);
                out.push_str("plan_id: ");
                out.push_str(plan);
                out.push('\n');
                continue;
            }
        } else if inside_subscription
            && let Some(block_indent) = subscription_indent
            && indent <= block_indent
            && !stripped.is_empty()
            && !stripped.starts_with('#')
        {
            // Leaving the subscription block — if we never saw a
            // `plan_id:` line for it, insert one before this line.
            if let Some(path) = current_path.as_deref()
                && !wrote_plan_id_for_current
                && let Some(plan) = by_path.get(path)
            {
                let field_indent = " ".repeat(block_indent + 2);
                out.push_str(&field_indent);
                out.push_str("plan_id: ");
                out.push_str(plan);
                out.push('\n');
            }
            inside_subscription = false;
            subscription_indent = None;
        }

        out.push_str(line);
        out.push('\n');
    }

    // Trailing subscription block at EOF — insert plan_id if it was missing.
    if inside_subscription
        && let Some(path) = current_path.as_deref()
        && !wrote_plan_id_for_current
        && let Some(plan) = by_path.get(path)
        && let Some(block_indent) = subscription_indent
    {
        let field_indent = " ".repeat(block_indent + 2);
        out.push_str(&field_indent);
        out.push_str("plan_id: ");
        out.push_str(plan);
        out.push('\n');
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_back_inserts_plan_id_when_absent() {
        let yaml = "endpoints:\n  - method: GET\n    path: api/v1/pro\n    subscription:\n      period: 30d\n      currency: USDC\n";
        let rows = vec![PlanRow {
            method: "GET".into(),
            path: "api/v1/pro".into(),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "PlanXYZ".into(),
            existing_plan: None,
        }];
        let out = write_back_plan_ids(yaml, &rows).unwrap();
        assert!(out.contains("plan_id: PlanXYZ"), "{out}");
    }

    #[test]
    fn write_back_replaces_existing_plan_id() {
        let yaml = "endpoints:\n  - method: GET\n    path: api/v1/pro\n    subscription:\n      period: 30d\n      currency: USDC\n      plan_id: OLD\n";
        let rows = vec![PlanRow {
            method: "GET".into(),
            path: "api/v1/pro".into(),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "NEW".into(),
            existing_plan: Some("OLD".into()),
        }];
        let out = write_back_plan_ids(yaml, &rows).unwrap();
        assert!(out.contains("plan_id: NEW"), "{out}");
        assert!(!out.contains("plan_id: OLD"), "{out}");
    }

    #[test]
    fn write_back_preserves_comments_and_other_endpoints() {
        let yaml = "endpoints:\n  # comment-1\n  - method: GET\n    path: api/v1/pro\n    # subscription block\n    subscription:\n      period: 30d\n      currency: USDC\n  - method: POST\n    path: api/v1/charge\n    metering:\n      dimensions:\n        - direction: usage\n          unit: requests\n          scale: 1\n          tiers:\n            - price_usd: 0.01\n";
        let rows = vec![PlanRow {
            method: "GET".into(),
            path: "api/v1/pro".into(),
            period: "30d".into(),
            currency: "USDC".into(),
            derived_plan: "PlanXYZ".into(),
            existing_plan: None,
        }];
        let out = write_back_plan_ids(yaml, &rows).unwrap();
        assert!(out.contains("# comment-1"), "comment preserved");
        assert!(out.contains("# subscription block"));
        assert!(out.contains("plan_id: PlanXYZ"));
        // Other endpoints stay intact.
        assert!(out.contains("metering:"));
    }
}
