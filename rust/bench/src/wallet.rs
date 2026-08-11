//! Keys and funds.
//!
//! User wallets are **deterministically derived** from the funder secret + run
//! id + index, so a run never needs to store user secret keys: given the funder
//! and the run id, every wallet (and thus every stranded balance) is
//! re-derivable for recovery. Funding/sweeping is abstracted behind [`Funder`]
//! so the fork rehearsal (surfpool cheatcodes) and mainnet (real SPL transfers)
//! share one pipeline.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use solana_pubkey::Pubkey;
use surfpool_sdk::Surfnet;

use crate::config::{FunderCfg, Network};

/// A funded actor's keys. `keypair` is the 64-byte `secret‖public` layout that
/// `MemorySigner::from_bytes` expects.
#[derive(Clone)]
pub struct Wallet {
    pub keypair: [u8; 64],
    pub pubkey: Pubkey,
}

impl Wallet {
    fn from_seed(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let public = signing.verifying_key().to_bytes();
        let mut keypair = [0u8; 64];
        keypair[..32].copy_from_slice(&seed);
        keypair[32..].copy_from_slice(&public);
        Wallet {
            keypair,
            pubkey: Pubkey::new_from_array(public),
        }
    }

    /// The 32-byte ed25519 seed (first half of the keypair).
    pub fn seed(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.keypair[..32]);
        s
    }
}

/// Derive a labelled sub-key from a parent seed (e.g. a user's session-signer
/// or channel key). Deterministic, so it's recoverable alongside the user.
pub fn subkey(parent_seed: &[u8; 32], label: &str) -> Wallet {
    let hk = Hkdf::<Sha256>::new(Some(label.as_bytes()), parent_seed);
    let mut okm = [0u8; 32];
    hk.expand(b"pay-bench/subkey", &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length");
    Wallet::from_seed(okm)
}

/// Derive user `index`'s wallet from the funder seed and run id.
///
/// `HKDF-SHA256(salt = run_id, ikm = funder_seed, info = "pay-bench/user/<index>")`.
/// Deterministic and collision-free across runs (run id is the salt) — the
/// backbone of crash recovery.
pub fn derive_user(funder_seed: &[u8; 32], run_id: &str, index: u32) -> Wallet {
    let hk = Hkdf::<Sha256>::new(Some(run_id.as_bytes()), funder_seed);
    let mut okm = [0u8; 32];
    let info = format!("pay-bench/user/{index}");
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 is a valid HKDF-SHA256 output length");
    Wallet::from_seed(okm)
}

/// Load the funder keypair from config (env or file), or — only on the fork —
/// generate an ephemeral one when none is configured.
pub fn load_funder(cfg: &FunderCfg, network: Network) -> Result<Wallet> {
    if let Some(var) = &cfg.keypair_env {
        let raw =
            std::env::var(var).with_context(|| format!("funder.keypair_env `{var}` not set"))?;
        return parse_keypair(&raw).with_context(|| format!("parsing funder from env `{var}`"));
    }
    if let Some(path) = &cfg.keypair_path {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading funder keypair {path}"))?;
        return parse_keypair(&raw).with_context(|| format!("parsing funder keypair {path}"));
    }
    if network == Network::Fork {
        // Rehearsal with no real funder: an ephemeral key is fine, the fork
        // mints funds via cheatcodes regardless of who the "funder" is.
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        return Ok(Wallet::from_seed(seed));
    }
    bail!("a funder keypair (funder.keypair_env or keypair_path) is required on {network:?}")
}

/// Parse a keypair from a solana-CLI JSON byte array, or a base58 string.
fn parse_keypair(raw: &str) -> Result<Wallet> {
    let trimmed = raw.trim();
    let bytes: Vec<u8> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed).context("keypair JSON must be a byte array")?
    } else {
        bs58::decode(trimmed)
            .into_vec()
            .context("keypair is neither JSON array nor valid base58")?
    };
    if bytes.len() != 64 {
        bail!(
            "keypair must be 64 bytes (secret‖public), got {}",
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[..32]);
    Ok(Wallet::from_seed(seed))
}

/// Result of reclaiming a wallet's funds back to the funder. (Populated by the
/// mainnet funder in M4; the fork funder returns the default.)
#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct SweepResult {
    pub sol_reclaimed: u64,
    pub token_reclaimed: u64,
}

/// Funds movement: disperse to user wallets, and sweep back to the funder.
#[async_trait]
pub trait Funder: Send + Sync {
    /// Fund a user wallet with `sol_lamports` and, if `token` is set,
    /// `(mint, base_units)` of an SPL token.
    async fn fund(
        &self,
        user: &Pubkey,
        sol_lamports: u64,
        token: Option<(&Pubkey, u64)>,
    ) -> Result<()>;

    /// Reclaim a user wallet's remaining funds back to the funder. May be a
    /// no-op where the underlying ledger is ephemeral (fork).
    async fn sweep(&self, user: &Wallet, mint: Option<&Pubkey>) -> Result<SweepResult>;

    /// Human label for logs.
    fn kind(&self) -> &'static str;
}

/// Fork funder — mints funds directly via surfpool cheatcodes. Sweeping is a
/// no-op because the fork ledger is discarded when the validator stops.
pub struct ForkFunder<'a> {
    pub surfnet: &'a Surfnet,
}

#[async_trait]
impl Funder for ForkFunder<'_> {
    async fn fund(
        &self,
        user: &Pubkey,
        sol_lamports: u64,
        token: Option<(&Pubkey, u64)>,
    ) -> Result<()> {
        let cc = self.surfnet.cheatcodes();
        // Cross the surfpool type boundary via string to stay version-agnostic.
        let user_sp = sp_pubkey(user)?;
        if sol_lamports > 0 {
            cc.fund_sol(&user_sp, sol_lamports)
                .map_err(|e| anyhow::anyhow!("fund_sol: {e}"))?;
        }
        if let Some((mint, amount)) = token {
            let mint_sp = sp_pubkey(mint)?;
            cc.fund_token(&user_sp, &mint_sp, amount, None)
                .map_err(|e| anyhow::anyhow!("fund_token: {e}"))?;
        }
        Ok(())
    }

    async fn sweep(&self, _user: &Wallet, _mint: Option<&Pubkey>) -> Result<SweepResult> {
        Ok(SweepResult::default())
    }

    fn kind(&self) -> &'static str {
        "fork"
    }
}

/// External fork funder — mints via surfpool cheatcodes over **RPC** (no
/// in-process `Surfnet` handle), so the load driver can fund users against a
/// proxy/surfpool running in a *separate* process. Reuses the shared
/// `settlement::testkit` cheatcode helpers. Sweep is a no-op (ephemeral fork).
pub struct ExternalForkFunder {
    pub rpc_url: String,
}

#[async_trait]
impl Funder for ExternalForkFunder {
    async fn fund(
        &self,
        user: &Pubkey,
        sol_lamports: u64,
        token: Option<(&Pubkey, u64)>,
    ) -> Result<()> {
        use pay_kit::mpp::settlement::testkit;
        const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        if sol_lamports > 0 {
            testkit::fund_sol(&self.rpc_url, user, sol_lamports).await;
        }
        if let Some((mint, amount)) = token
            && amount > 0
        {
            testkit::fund_token(
                &self.rpc_url,
                user,
                &mint.to_string(),
                amount,
                TOKEN_PROGRAM,
            )
            .await;
        }
        Ok(())
    }

    async fn sweep(&self, _user: &Wallet, _mint: Option<&Pubkey>) -> Result<SweepResult> {
        Ok(SweepResult::default())
    }

    fn kind(&self) -> &'static str {
        "external-fork"
    }
}

/// No-op funder for **offline** runs — no chain, nothing to fund or sweep.
pub struct NoopFunder;

#[async_trait]
impl Funder for NoopFunder {
    async fn fund(&self, _user: &Pubkey, _sol: u64, _token: Option<(&Pubkey, u64)>) -> Result<()> {
        Ok(())
    }
    async fn sweep(&self, _user: &Wallet, _mint: Option<&Pubkey>) -> Result<SweepResult> {
        Ok(SweepResult::default())
    }
    fn kind(&self) -> &'static str {
        "noop"
    }
}

/// Convert a canonical `solana_pubkey::Pubkey` into surfpool's `Pubkey` type via
/// its string form, so a version skew between the two crates can't bite us.
fn sp_pubkey(pk: &Pubkey) -> Result<surfpool_sdk::Pubkey> {
    pk.to_string()
        .parse::<surfpool_sdk::Pubkey>()
        .map_err(|e| anyhow::anyhow!("pubkey conversion: {e}"))
}

/// Mainnet funder — real SPL transfers + ATA management + sweep. Implemented in
/// milestone M4; on the fork path this is never constructed.
pub struct MainnetFunder {
    #[allow(dead_code)]
    pub rpc_url: String,
    #[allow(dead_code)]
    pub funder: Wallet,
}

#[async_trait]
impl Funder for MainnetFunder {
    async fn fund(
        &self,
        _user: &Pubkey,
        _sol_lamports: u64,
        _token: Option<(&Pubkey, u64)>,
    ) -> Result<()> {
        bail!("mainnet funding not implemented yet (M4): real SPL transfer + ATA creation")
    }

    async fn sweep(&self, _user: &Wallet, _mint: Option<&Pubkey>) -> Result<SweepResult> {
        bail!("mainnet sweep not implemented yet (M4)")
    }

    fn kind(&self) -> &'static str {
        "mainnet"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_index_unique() {
        let funder_seed = [7u8; 32];
        let a = derive_user(&funder_seed, "run-1", 0);
        let a2 = derive_user(&funder_seed, "run-1", 0);
        let b = derive_user(&funder_seed, "run-1", 1);
        let other_run = derive_user(&funder_seed, "run-2", 0);
        assert_eq!(a.pubkey, a2.pubkey, "same inputs ⇒ same key");
        assert_ne!(a.pubkey, b.pubkey, "different index ⇒ different key");
        assert_ne!(a.pubkey, other_run.pubkey, "different run ⇒ different key");
        // keypair layout: seed is the first half.
        assert_eq!(&a.keypair[..32], &a.seed());
    }
}
