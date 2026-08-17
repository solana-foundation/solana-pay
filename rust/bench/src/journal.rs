//! Durable, resumable run-state — the safety net for real-money runs.
//!
//! Every run writes a journal at `~/.config/pay/bench/<run-id>.json`, updated at
//! each phase transition and per-user during provision/sweep. If a run is
//! interrupted, the journal (plus deterministic key derivation — see
//! [`crate::wallet`]) is enough to re-derive every wallet and sweep funds back
//! to the funder. `scan_incomplete` surfaces any run that still holds funds.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{Network, Scheme};

/// Durable state for an independently reusable fixture set. Unlike a load-run
/// journal, this contains only public derivation metadata and progress; every
/// wallet key remains recoverable from the funder seed and `wallet_set_id` (or
/// the fixture's `setup_id` for legacy journals).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureState {
    pub setup_id: String,
    #[serde(default)]
    pub wallet_set_id: Option<String>,
    pub name: String,
    pub network: Network,
    pub funder_pubkey: String,
    pub users: usize,
    pub sol_lamports_per_user: u64,
    pub assets: Vec<FixtureAsset>,
    pub phase: FixturePhase,
    /// The first index that still needs processing in the current phase. A
    /// transaction is idempotently reconciled before this checkpoint moves.
    pub next_user: usize,
    #[serde(default)]
    pub pending: Vec<PendingTransaction>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub signature: String,
    pub operation: String,
    pub user_index: usize,
    pub last_valid_block_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureAsset {
    pub label: String,
    pub mint: String,
    pub token_program: String,
    pub decimals: u8,
    pub amount_base: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixturePhase {
    SettingUp,
    Ready,
    TearingDown,
    TornDown,
}

/// Owns one setup journal at `~/.config/pay/bench/setups/<setup-id>.json`.
pub struct FixtureJournal {
    path: PathBuf,
    state: FixtureState,
}

impl FixtureJournal {
    fn dir() -> Result<PathBuf> {
        Ok(Journal::dir()?.join("setups"))
    }

    fn path_for(setup_id: &str) -> Result<PathBuf> {
        Ok(Self::dir()?.join(format!("{setup_id}.json")))
    }

    pub fn exists(setup_id: &str) -> Result<bool> {
        Ok(Self::path_for(setup_id)?.exists())
    }

    pub fn create(state: FixtureState) -> Result<Self> {
        let journal = Self {
            path: Self::path_for(&state.setup_id)?,
            state,
        };
        journal.save()?;
        Ok(journal)
    }

    pub fn load(setup_id: &str) -> Result<Self> {
        let path = Self::path_for(setup_id)?;
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading fixture journal {}", path.display()))?;
        let state = serde_json::from_str(&raw)
            .with_context(|| format!("parsing fixture journal {}", path.display()))?;
        Ok(Self { path, state })
    }

    pub fn state(&self) -> &FixtureState {
        &self.state
    }

    pub fn set_phase(&mut self, phase: FixturePhase) -> Result<()> {
        self.state.phase = phase;
        self.save()
    }

    pub fn checkpoint(&mut self, next_user: usize) -> Result<()> {
        self.state.next_user = next_user;
        self.save()
    }

    pub fn add_pending(&mut self, pending: PendingTransaction) -> Result<()> {
        self.state
            .pending
            .retain(|item| item.signature != pending.signature);
        self.state.pending.push(pending);
        self.save()
    }

    pub fn clear_pending(&mut self, signature: &str) -> Result<()> {
        self.state
            .pending
            .retain(|item| item.signature != signature);
        self.save()
    }

    fn save(&self) -> Result<()> {
        let dir = self
            .path
            .parent()
            .context("fixture journal path has no parent")?;
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut state = self.state.clone();
        state.updated_at = chrono::Utc::now().to_rfc3339();
        let json = serde_json::to_string_pretty(&state)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming into {}", self.path.display()))?;
        Ok(())
    }
}

/// Lifecycle of a run. Anything other than `Complete`/`Failed` (terminal) means
/// funds may still be deployed and a recovery sweep is warranted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Planning,
    Provisioning,
    Provisioned,
    Prepared,
    Unleashing,
    Settling,
    Swept,
    Complete,
    Failed,
}

impl Status {
    /// True if the run may still hold funds across user wallets.
    pub fn is_outstanding(self) -> bool {
        !matches!(self, Status::Complete | Status::Failed)
    }
}

/// Per-user durable record. Secrets are NEVER stored — keys are re-derivable
/// from the funder secret + run_id + index (see [`crate::wallet::derive_user`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserRecord {
    pub index: u32,
    pub pubkey: String,
    #[serde(default)]
    pub ata: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub open_sig: Option<String>,
    /// Token base units deposited/funded into this wallet.
    #[serde(default)]
    pub token_base: u64,
    #[serde(default)]
    pub sol_lamports: u64,
    #[serde(default)]
    pub funded: bool,
    #[serde(default)]
    pub swept: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunState {
    pub run_id: String,
    pub name: String,
    pub scheme: Scheme,
    pub network: Network,
    pub funder_pubkey: String,
    pub status: Status,
    pub created_at: String,
    pub updated_at: String,
    pub users: Vec<UserRecord>,
}

/// Owns a [`RunState`] and persists every mutation atomically.
pub struct Journal {
    path: PathBuf,
    state: RunState,
}

impl Journal {
    /// Directory holding all run journals: `~/.config/pay/bench`.
    pub fn dir() -> Result<PathBuf> {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(PathBuf::from(home).join(".config/pay/bench"))
    }

    fn path_for(run_id: &str) -> Result<PathBuf> {
        Ok(Self::dir()?.join(format!("{run_id}.json")))
    }

    /// Create a fresh journal and persist it immediately (before any funds move).
    pub fn create(
        run_id: String,
        name: String,
        scheme: Scheme,
        network: Network,
        funder_pubkey: String,
    ) -> Result<Self> {
        let now = chrono::Utc::now().to_rfc3339();
        let state = RunState {
            run_id: run_id.clone(),
            name,
            scheme,
            network,
            funder_pubkey,
            status: Status::Planning,
            created_at: now.clone(),
            updated_at: now,
            users: Vec::new(),
        };
        let journal = Self {
            path: Self::path_for(&run_id)?,
            state,
        };
        journal.save()?;
        Ok(journal)
    }

    /// Load an existing journal by run id.
    pub fn load(run_id: &str) -> Result<Self> {
        let path = Self::path_for(run_id)?;
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading journal {}", path.display()))?;
        let state: RunState = serde_json::from_str(&raw)
            .with_context(|| format!("parsing journal {}", path.display()))?;
        Ok(Self { path, state })
    }

    pub fn state(&self) -> &RunState {
        &self.state
    }

    pub fn set_status(&mut self, status: Status) -> Result<()> {
        self.state.status = status;
        self.save()
    }

    /// Insert or replace a user record (keyed on `index`) and persist.
    pub fn upsert_user(&mut self, rec: UserRecord) -> Result<()> {
        match self.state.users.iter_mut().find(|u| u.index == rec.index) {
            Some(existing) => *existing = rec,
            None => self.state.users.push(rec),
        }
        self.save()
    }

    /// Persist the whole state atomically (write-temp + rename), perms 0600.
    pub fn save(&self) -> Result<()> {
        let dir = self.path.parent().context("journal path has no parent")?;
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let mut state = self.state.clone();
        state.updated_at = chrono::Utc::now().to_rfc3339();
        let json = serde_json::to_string_pretty(&state)?;

        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, json.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming into {}", self.path.display()))?;
        Ok(())
    }

    /// All run journals whose status still implies outstanding funds.
    pub fn scan_incomplete() -> Result<Vec<RunState>> {
        Ok(Self::scan_all()?
            .into_iter()
            .filter(|s| s.status.is_outstanding())
            .collect())
    }

    /// Every persisted run journal, newest first.
    pub fn scan_all() -> Result<Vec<RunState>> {
        let dir = Self::dir()?;
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if let Ok(raw) = std::fs::read_to_string(&path)
                && let Ok(state) = serde_json::from_str::<RunState>(&raw)
            {
                out.push(state);
            }
        }
        out.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(out)
    }
}

/// Generate a sortable, human-scannable run id: `<name>-<utc-compact>`.
pub fn new_run_id(name: &str, now: &chrono::DateTime<chrono::Utc>) -> String {
    let slug: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!("{slug}-{}", now.format("%Y%m%dT%H%M%SZ"))
}

#[allow(dead_code)]
fn _is_path(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::FixtureState;

    #[test]
    fn legacy_fixture_journal_defaults_pending_transactions() {
        let raw = r#"
        {
          "setup_id": "legacy",
          "name": "legacy",
          "network": "devnet",
          "funder_pubkey": "11111111111111111111111111111111",
          "users": 1,
          "sol_lamports_per_user": 0,
          "assets": [],
          "phase": "setting_up",
          "next_user": 0,
          "created_at": "2026-01-01T00:00:00Z",
          "updated_at": "2026-01-01T00:00:00Z"
        }
        "#;
        let state: FixtureState = serde_json::from_str(raw).unwrap();
        assert!(state.pending.is_empty());
        assert!(state.wallet_set_id.is_none());
    }
}
