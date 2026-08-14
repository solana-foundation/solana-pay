//! Deterministic, benchmark-only MPP-session channel fixtures.
//!
//! The fixture writes confirmed [`ChannelState`] records into the normal
//! [`MemoryChannelStore`] used by [`SessionMpp`]. It is deliberately confined
//! to `pay-bench`: the production CLI exposes no state-import endpoint.

use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use pay_core::client::session::SessionHandle;
use pay_core::server::session::{SessionMpp, test_channel_state};
use pay_kit::mpp::blockhash::BlockhashCache;
use pay_kit::mpp::server::session::{SessionConfig, VoucherSigner};
use pay_kit::mpp::solana_keychain::{SolanaSigner, memory::MemorySigner};
use pay_kit::mpp::store::{ChannelStore, MemoryChannelStore};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_pubkey::Pubkey;

const FIXTURE_SECRET: &str = "pay-bench-seeded-session-v1";
const FIXTURE_DEPOSIT: u64 = 1_000_000_000;

/// A normal server-side session manager seeded with deterministic confirmed
/// channels. The load driver derives its own client handles from the same
/// namespace and the challenge received over HTTP.
pub struct SeededSessionFixture {
    pub session: Arc<SessionMpp>,
}

/// Build an offline verifier fixture with `channels` independently-owned,
/// deterministic client session keys. `namespace` is part of every derivation;
/// the same namespace and index always produce the same channel and signer.
pub async fn build(
    mut config: SessionConfig,
    namespace: &str,
    channels: usize,
) -> Result<SeededSessionFixture> {
    anyhow::ensure!(
        channels > 0,
        "seeded session fixture needs at least one channel"
    );
    config.voucher_signer = VoucherSigner::Client;
    config.rpc_url = None;

    // Challenges still carry a syntactically valid recent blockhash, but the
    // fixture never processes an open transaction or calls an RPC endpoint.
    let cache = BlockhashCache::new();
    cache.set(Hash::new_unique().to_string(), u64::MAX, 42);
    let store = Arc::new(MemoryChannelStore::new());
    let session = Arc::new(
        SessionMpp::new_with_channel_store(config, FIXTURE_SECRET, store.clone())
            .with_blockhash_cache(cache),
    );
    let challenge = session
        .challenge(None)
        .context("build seeded session challenge")?;

    for index in 0..channels {
        let material = material(namespace, index as u32);
        let signer = signer(&material.signer_seed)?;
        let state = test_channel_state(
            material.channel.to_string(),
            FIXTURE_DEPOSIT,
            signer.pubkey().to_string(),
            "client",
            &challenge.id,
            material.payer.to_string(),
            None,
        );
        store
            .put_channel(&material.channel.to_string(), state)
            .await
            .map_err(|error| anyhow::anyhow!("seed channel {index}: {error}"))?;
    }

    Ok(SeededSessionFixture { session })
}

/// Construct a deterministic client handle from the challenge returned by the
/// fixture server. Keeping this separate from [`build`] lets the driver
/// preserve the exact challenge it received over HTTP.
pub fn handle_for_challenge(
    namespace: &str,
    index: u32,
    challenge: pay_kit::mpp::PaymentChallenge,
) -> Result<SessionHandle> {
    let material = material(namespace, index);
    let signer = signer(&material.signer_seed)?;
    let voucher_key = SigningKey::from_bytes(&material.signer_seed);
    Ok(
        SessionHandle::new(material.channel, Box::new(signer), challenge)
            .with_voucher_key(voucher_key),
    )
}

struct Material {
    channel: Pubkey,
    payer: Pubkey,
    signer_seed: [u8; 32],
}

fn material(namespace: &str, index: u32) -> Material {
    Material {
        channel: Pubkey::new_from_array(derive(namespace, index, "channel")),
        payer: Pubkey::new_from_array(derive(namespace, index, "payer")),
        signer_seed: derive(namespace, index, "signer"),
    }
}

fn derive(namespace: &str, index: u32, label: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"pay-bench/seeded-session/v1/");
    hash.update(namespace.as_bytes());
    hash.update(b"/");
    hash.update(index.to_le_bytes());
    hash.update(b"/");
    hash.update(label.as_bytes());
    hash.finalize().into()
}

fn signer(seed: &[u8; 32]) -> Result<MemorySigner> {
    let key = SigningKey::from_bytes(seed);
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(seed);
    bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
    MemorySigner::from_bytes(&bytes).map_err(|error| anyhow::anyhow!("seeded signer: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_core::server::session::SessionOutcome;

    fn config() -> SessionConfig {
        SessionConfig {
            operator: Pubkey::new_unique().to_string(),
            recipient: Pubkey::new_unique().to_string(),
            amount: 1,
            suggested_deposit: Some(FIXTURE_DEPOSIT),
            currency: pay_kit::mpp::resolve_stablecoin_mint("USDC", Some("localnet"))
                .unwrap()
                .to_string(),
            decimals: 6,
            network: "localnet".to_string(),
            voucher_signer: VoucherSigner::Client,
            ..Default::default()
        }
    }

    #[test]
    fn derivation_is_stable_and_channel_owned() {
        let first = material("fixture-a", 7);
        let repeat = material("fixture-a", 7);
        let other = material("fixture-a", 8);
        assert_eq!(first.channel, repeat.channel);
        assert_eq!(first.signer_seed, repeat.signer_seed);
        assert_ne!(first.channel, other.channel);
        assert_ne!(first.signer_seed, other.signer_seed);
    }

    #[tokio::test]
    async fn seeded_state_accepts_a_client_voucher_through_normal_process() {
        let fixture = build(config(), "equivalence", 2).await.unwrap();
        let handle =
            handle_for_challenge("equivalence", 1, fixture.session.challenge(None).unwrap())
                .unwrap();
        let header = handle.voucher_header(1).await.unwrap();

        let SessionOutcome::Voucher {
            channel_id,
            cumulative,
        } = fixture.session.process(&header).await.unwrap()
        else {
            panic!("expected voucher outcome");
        };
        assert_eq!(channel_id, material("equivalence", 1).channel.to_string());
        assert_eq!(cumulative, 1);
    }

    #[tokio::test]
    async fn reconstructed_handle_matches_the_seeded_channel() {
        let fixture = build(config(), "reconstructed", 1).await.unwrap();
        let handle =
            handle_for_challenge("reconstructed", 0, fixture.session.challenge(None).unwrap())
                .unwrap();
        let header = handle.voucher_header(2).await.unwrap();
        assert!(matches!(
            fixture.session.process(&header).await.unwrap(),
            SessionOutcome::Voucher { cumulative: 2, .. }
        ));
    }

    #[tokio::test]
    async fn seeds_the_100k_gate_fixture_without_a_production_import_path() {
        let fixture = build(config(), "100k-fixture", 100_000).await.unwrap();
        let first =
            handle_for_challenge("100k-fixture", 0, fixture.session.challenge(None).unwrap())
                .unwrap();
        let last = handle_for_challenge(
            "100k-fixture",
            99_999,
            fixture.session.challenge(None).unwrap(),
        )
        .unwrap();
        assert_ne!(first.channel_id().await, last.channel_id().await);
    }
}
