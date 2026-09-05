//! Recovery for live payment channels whose process-local handles were lost.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use futures::stream::{self, StreamExt};
use pay_core::client::session::SessionHandle;
use pay_kit::generated::payment_channels::generated::accounts::Channel;
use pay_kit::mpp::program::payment_channels::{default_program_id, from_address};
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use pay_worker::channel::STATUS_DISTRIBUTED;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

use crate::channel_recovery::{
    CHANNEL_ACCOUNT_SIZE, CHANNEL_STATUS_OFFSET, signed_transaction, submit_transactions,
};
use crate::config::{Network, RunConfig, Scheme};
use crate::fixture_rpc::{ExecutionConfig, FixtureRpc};
use crate::scheme::{build_request, validate_payment_transport, www_authenticate};
use crate::wallet::{self, Wallet};

const CHANNEL_STATUS_OPEN: u8 = 0;
const CHANNEL_STATUS_SEALED: u8 = 1;
const REUSE_DISCOVERY_MAX_ATTEMPTS: usize = 5;
const REUSE_DISCOVERY_RETRY_BASE_DELAY_MS: u64 = 250;

struct RecoverableChannel {
    address: Pubkey,
    index: u32,
    wallet: Wallet,
    payee: Pubkey,
    channel: Channel,
}

/// Discover open channels owned by a deterministic fixture and close them
/// through the live gateway. This repairs the process-local handle gap after
/// an interrupted provisioning phase without guessing channel salts.
pub async fn recover(
    config_path: &str,
    fixture_id: &str,
    yes: bool,
    assume_no_vouchers: bool,
    allow_settled: bool,
) -> Result<()> {
    ensure!(
        yes,
        "session recovery submits channel-close transactions; re-run with --yes"
    );
    let config = RunConfig::from_yaml_path(config_path)?;
    ensure!(
        config.run.scheme == Scheme::MppSession,
        "session recovery requires run.scheme: mpp_session"
    );
    let endpoint = config
        .endpoints
        .first()
        .context("session recovery requires one endpoint")?;
    validate_payment_transport(&endpoint.url)?;

    let rpc_url = config
        .resolve_rpc_url()?
        .context("session recovery requires an RPC URL")?;
    let funder = wallet::load_funder(&config.run.funder, config.run.network)?;
    let wallet_set_id = crate::fixtures::validate_ready_fixture(fixture_id, &config, &funder)?;

    let expected: HashMap<Pubkey, (u32, Wallet, Pubkey)> = (0..config.load.users as u32)
        .map(|index| {
            let wallet = wallet::derive_user(&funder.seed(), &wallet_set_id, index);
            let session = wallet::subkey(&wallet.seed(), "session");
            (wallet.pubkey, (index, wallet, session.pubkey))
        })
        .collect();

    if assume_no_vouchers {
        return recover_without_gateway_state(
            &config,
            &rpc_url,
            fixture_id,
            &funder,
            &expected,
            allow_settled,
        )
        .await;
    }
    ensure!(
        !allow_settled,
        "--allow-settled only applies to --assume-no-vouchers direct recovery"
    );

    let rpc = pay_api_core::RpcClient::new(Duration::from_secs(30))?;
    let channels =
        discover_fixture_channels(&rpc, &rpc_url, CHANNEL_STATUS_OPEN, &expected).await?;

    println!(
        "discovered {} recoverable open channels for fixture `{fixture_id}`",
        channels.len()
    );
    if channels.is_empty() {
        return Ok(());
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(config.load.provision_concurrency);
    if let Some(certificate) = config.tls_ca_certificate()? {
        builder = builder.add_root_certificate(certificate);
    }
    let http = builder.build()?;
    let concurrency = config.load.provision_concurrency.min(channels.len());
    let mut closing = stream::iter(channels.into_iter().map(|channel| {
        let http = http.clone();
        let endpoint = endpoint.clone();
        async move {
            let result = close_channel(
                &http,
                &endpoint,
                channel.address,
                &channel.wallet,
                channel.payee,
            )
            .await;
            (channel.index, channel.address, result)
        }
    }))
    .buffer_unordered(concurrency);

    let mut closed = 0usize;
    let mut failures = Vec::new();
    while let Some((index, address, result)) = closing.next().await {
        match result {
            Ok(()) => {
                closed += 1;
                tracing::info!(index, channel = %address, "recovered session closed");
            }
            Err(error) => failures.push(format!("user {index} channel {address}: {error:#}")),
        }
    }
    println!(
        "closed {closed} recovered channels; {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        bail!("session recovery failures:\n{}", failures.join("\n"));
    }
    Ok(())
}

/// Discover one reusable open channel per fixture wallet, including the PDA
/// salt/open slot needed to reconstruct an x402 batch channel config. When a
/// wallet owns several open channels the most-settled one is chosen so a reuse
/// run resumes from the furthest-progressed watermark. Used by `session.reuse`.
pub(crate) async fn discover_reuse_map(
    rpc_url: &str,
    expected: &HashMap<Pubkey, (u32, Wallet, Pubkey)>,
) -> Result<HashMap<u32, crate::scheme::ReusableChannel>> {
    let rpc = pay_api_core::RpcClient::new(Duration::from_secs(30))?;
    let mut attempt = 1usize;
    let channels = loop {
        match discover_fixture_channels(&rpc, rpc_url, CHANNEL_STATUS_OPEN, expected).await {
            Ok(channels) => break channels,
            Err(error) if attempt < REUSE_DISCOVERY_MAX_ATTEMPTS => {
                tracing::warn!(
                    attempt,
                    max_attempts = REUSE_DISCOVERY_MAX_ATTEMPTS,
                    %error,
                    "retrying reusable-channel discovery"
                );
                let delay = REUSE_DISCOVERY_RETRY_BASE_DELAY_MS << (attempt - 1);
                tokio::time::sleep(Duration::from_millis(delay)).await;
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    };
    let mut map: HashMap<u32, crate::scheme::ReusableChannel> = HashMap::new();
    for channel in channels {
        let settled = channel.channel.settlement.settled;
        let entry = map
            .entry(channel.index)
            .or_insert_with(|| crate::scheme::ReusableChannel {
                channel_id: channel.address.to_string(),
                settled,
                salt: channel.channel.salt,
                open_slot: channel.channel.open_slot,
            });
        if settled > entry.settled {
            *entry = crate::scheme::ReusableChannel {
                channel_id: channel.address.to_string(),
                settled,
                salt: channel.channel.salt,
                open_slot: channel.channel.open_slot,
            };
        }
    }
    Ok(map)
}

async fn discover_fixture_channels(
    rpc: &pay_api_core::RpcClient,
    rpc_url: &str,
    status: u8,
    expected: &HashMap<Pubkey, (u32, Wallet, Pubkey)>,
) -> Result<Vec<RecoverableChannel>> {
    let accounts = rpc
        .get_program_accounts_filtered(
            rpc_url,
            &default_program_id().to_string(),
            CHANNEL_ACCOUNT_SIZE,
            CHANNEL_STATUS_OFFSET,
            &[status],
        )
        .await
        .with_context(|| format!("discovering payment channels with status {status}"))?;

    let mut channels = Vec::new();
    let mut signer_mismatches = 0usize;
    for account in accounts {
        let channel = Channel::from_bytes(&account.data)
            .with_context(|| format!("decoding channel {}", account.pubkey))?;
        let payer = from_address(&channel.payer);
        let Some((index, wallet, expected_signer)) = expected.get(&payer) else {
            continue;
        };
        let actual_signer = from_address(&channel.authorized_signer);
        if actual_signer != *expected_signer {
            signer_mismatches += 1;
            continue;
        }
        channels.push(RecoverableChannel {
            address: Pubkey::from_str(&account.pubkey)
                .with_context(|| format!("invalid channel address {}", account.pubkey))?,
            index: *index,
            wallet: wallet.clone(),
            payee: from_address(&channel.payee),
            channel,
        });
    }
    if signer_mismatches > 0 {
        tracing::info!(
            signer_mismatches,
            "ignored fixture channels owned by a different authorization scheme"
        );
    }
    Ok(channels)
}

/// Recover channels after the gateway's process-local store has been lost.
/// This path is intentionally explicit: it settles with no voucher and is
/// valid only when provisioning was interrupted before load began.
async fn recover_without_gateway_state(
    config: &RunConfig,
    rpc_url: &str,
    fixture_id: &str,
    funder: &Wallet,
    expected: &HashMap<Pubkey, (u32, Wallet, Pubkey)>,
    allow_settled: bool,
) -> Result<()> {
    let discovery = pay_api_core::RpcClient::new(Duration::from_secs(30))?;
    let open =
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_OPEN, expected).await?;
    let already_sealed =
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_SEALED, expected).await?;
    println!(
        "direct zero-voucher recovery for fixture `{fixture_id}`: {} open, {} sealed",
        open.len(),
        already_sealed.len()
    );
    validate_zero_voucher_channels(
        open.iter().chain(already_sealed.iter()),
        funder,
        allow_settled,
    )?;

    let concurrency = config.load.provision_concurrency.clamp(1, 256);
    let execution = ExecutionConfig {
        window_users: concurrency,
        reconcile_concurrency: concurrency,
        submit_concurrency: concurrency,
        rpc_requests_per_second: 1_000,
        rpc_burst: concurrency.saturating_mul(2),
        request_timeout_seconds: 30,
        confirmation_timeout_seconds: 90,
        ..ExecutionConfig::default()
    };
    let rpc = FixtureRpc::new(rpc_url.to_string(), execution);

    if !open.is_empty() {
        // Sign only one concurrency window per blockhash. A full high-scale
        // recovery outlives Solana's blockhash validity window.
        for batch in open.chunks(concurrency) {
            let (blockhash, _) = rpc.latest_blockhash().await?;
            let mut transactions = Vec::with_capacity(batch.len());
            for channel in batch {
                let instruction =
                    pay_worker::channel::build_settle_and_seal_ix(&channel.address, &channel.payee);
                let transaction =
                    signed_transaction(funder, &[], vec![instruction], blockhash).await?;
                transactions.push((
                    format!("user {} channel {}", channel.index, channel.address),
                    transaction,
                ));
            }
            submit_transactions(
                &rpc,
                transactions,
                concurrency,
                "zero-voucher settle-and-seal batch",
            )
            .await?;
        }
        wait_until_absent(
            &discovery,
            rpc_url,
            CHANNEL_STATUS_OPEN,
            expected,
            Duration::from_secs(60),
        )
        .await?;
    }

    let sealed =
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_SEALED, expected).await?;
    validate_zero_voucher_channels(sealed.iter(), funder, allow_settled)?;
    if !sealed.is_empty() {
        let mint = from_address(&sealed[0].channel.mint);
        ensure!(
            sealed
                .iter()
                .all(|channel| from_address(&channel.channel.mint) == mint),
            "refusing recovery: fixture channels use multiple settlement mints"
        );
        let token_program =
            pay_worker::channel::resolve_token_program(&discovery, rpc_url, &mint).await?;
        let empty_preimage = pay_worker::channel::DistributionPreimage {
            preimage_bytes: 0u32.to_le_bytes().to_vec(),
            recipients: Vec::new(),
        };
        let treasury = recovery_treasury_owner(config.run.network)?;
        // Distribution can be just as large as settlement, so refresh here too.
        for batch in sealed.chunks(concurrency) {
            let (blockhash, _) = rpc.latest_blockhash().await?;
            let mut transactions = Vec::with_capacity(batch.len());
            for channel in batch {
                let decoded = pay_worker::channel::DecodedChannel {
                    address: channel.address,
                    channel: channel.channel.clone(),
                };
                let (instruction, _) = pay_worker::channel::build_distribute_ix(
                    &decoded,
                    &treasury,
                    &token_program,
                    &empty_preimage,
                );
                let transaction =
                    signed_transaction(funder, &[], vec![instruction], blockhash).await?;
                transactions.push((
                    format!("user {} channel {}", channel.index, channel.address),
                    transaction,
                ));
            }
            submit_transactions(
                &rpc,
                transactions,
                concurrency,
                "empty-plan distribute batch",
            )
            .await?;
        }
        wait_until_absent(
            &discovery,
            rpc_url,
            CHANNEL_STATUS_SEALED,
            expected,
            Duration::from_secs(60),
        )
        .await?;
    }

    let distributed =
        discover_fixture_channels(&discovery, rpc_url, STATUS_DISTRIBUTED, expected).await?;
    for channel in &distributed {
        validate_rent_reclaim_destination(
            channel.address,
            from_address(&channel.channel.rent_payer),
        )?;
    }
    if !distributed.is_empty() {
        let current_slot = discovery.get_slot(rpc_url).await?;
        let locked = distributed
            .iter()
            .filter(|channel| {
                current_slot
                    < channel
                        .channel
                        .open_slot
                        .saturating_add(pay_kit::core::payment_channels::OPEN_SLOT_WINDOW)
                        .saturating_add(1)
            })
            .count();
        ensure!(
            locked == 0,
            "direct recovery distributed deposits but rent reclaim is not unlocked for {locked} fixture channels yet; rerun after the open-slot window"
        );

        for batch in distributed.chunks(concurrency) {
            let (blockhash, _) = rpc.latest_blockhash().await?;
            let mut transactions = Vec::with_capacity(batch.len());
            for channel in batch {
                let rent_payer = from_address(&channel.channel.rent_payer);
                let instruction =
                    pay_worker::channel::build_reclaim_ix(&channel.address, &rent_payer);
                let transaction =
                    signed_transaction(funder, &[], vec![instruction], blockhash).await?;
                transactions.push((
                    format!("user {} channel {}", channel.index, channel.address),
                    transaction,
                ));
            }
            submit_transactions(
                &rpc,
                transactions,
                concurrency,
                "distributed rent-reclaim batch",
            )
            .await?;
        }
    }

    let remaining_open =
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_OPEN, expected).await?;
    let remaining_sealed =
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_SEALED, expected).await?;
    let remaining_distributed =
        discover_fixture_channels(&discovery, rpc_url, STATUS_DISTRIBUTED, expected).await?;
    ensure!(
        remaining_open.is_empty()
            && remaining_sealed.is_empty()
            && remaining_distributed.is_empty(),
        "direct recovery incomplete: {} open, {} sealed, and {} distributed fixture channels remain",
        remaining_open.len(),
        remaining_sealed.len(),
        remaining_distributed.len()
    );
    println!(
        "direct recovery complete: {} channels settled, {} deposits distributed, and {} channel rents reclaimed",
        open.len(),
        sealed.len(),
        distributed.len()
    );
    Ok(())
}

fn recovery_treasury_owner(network: Network) -> Result<Pubkey> {
    match network {
        Network::Mainnet => Ok(pay_kit::mpp::program::payment_channels::treasury_owner()),
        // The devnet program is compiled with its cluster-specific treasury;
        // PayKit's legacy no-argument helper returns the mainnet constant.
        Network::Devnet => Pubkey::from_str("4zTeC5mVqWLruDexgU2mV66p9t5vCA9JyiZqdGDUspap")
            .context("invalid built-in devnet treasury owner"),
        Network::Fork => bail!("direct public-cluster recovery does not support fork networks"),
    }
}

fn validate_zero_voucher_channels<'a>(
    channels: impl Iterator<Item = &'a RecoverableChannel>,
    funder: &Wallet,
    allow_settled: bool,
) -> Result<()> {
    let empty_hash = Sha256::digest(0u32.to_le_bytes());
    for channel in channels {
        ensure!(
            channel.payee == funder.pubkey,
            "refusing recovery: channel {} payee {} is not the configured funder {}",
            channel.address,
            channel.payee,
            funder.pubkey
        );
        // Sealing with `has_voucher = 0` finalizes the channel at whatever
        // amount is already settled on-chain, and `distribute` then pays that
        // to the payee (== funder) and refunds the remainder to the payer. This
        // is safe for channels that carried real vouchers, so `--allow-settled`
        // opts out of the stricter never-metered guard when cleaning up stale
        // channels whose gateway voucher state is gone.
        ensure!(
            allow_settled
                || (channel.channel.settlement.settled == 0
                    && channel.channel.settlement.payout_watermark == 0),
            "refusing zero-voucher recovery: channel {} has non-zero settlement watermarks (pass --allow-settled to seal at the on-chain amount)",
            channel.address
        );
        ensure!(
            channel.channel.distribution_hash.as_slice() == empty_hash.as_slice(),
            "refusing zero-voucher recovery: channel {} has a non-empty distribution plan",
            channel.address
        );
    }
    Ok(())
}

/// Reclaiming an already-distributed channel cannot alter its settlement or
/// payout. It only closes the terminal PDA and returns rent to the address
/// recorded on-chain, so non-zero voucher watermarks are valid here.
fn validate_rent_reclaim_destination(channel: Pubkey, rent_payer: Pubkey) -> Result<()> {
    // The program fixes this destination when `open` is signed and reclaim
    // cannot redirect it. Sponsored opens intentionally return rent to the
    // operator rather than the channel payer.
    ensure!(
        rent_payer != Pubkey::default(),
        "refusing rent reclaim: channel {channel} has an invalid zero rent payer"
    );
    Ok(())
}

async fn wait_until_absent(
    rpc: &pay_api_core::RpcClient,
    rpc_url: &str,
    status: u8,
    expected: &HashMap<Pubkey, (u32, Wallet, Pubkey)>,
    timeout: Duration,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = discover_fixture_channels(rpc, rpc_url, status, expected).await?;
        if remaining.is_empty() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "timed out waiting for {} fixture channels to leave status {status}",
                remaining.len()
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn close_channel(
    http: &reqwest::Client,
    endpoint: &crate::config::Endpoint,
    channel_id: Pubkey,
    wallet: &Wallet,
    expected_payee: Pubkey,
) -> Result<()> {
    let challenge_response = build_request(
        http,
        &endpoint.method,
        &endpoint.url,
        &endpoint.body,
        None,
        &[],
    )
    .send()
    .await
    .context("requesting recovery challenge")?;
    ensure!(
        challenge_response.status() == reqwest::StatusCode::PAYMENT_REQUIRED,
        "expected 402 recovery challenge, got {}",
        challenge_response.status()
    );
    let www = www_authenticate(&challenge_response).context("recovery challenge missing")?;
    let (challenge, request) =
        SessionHandle::parse_challenge(&www).context("invalid session recovery challenge")?;
    ensure!(
        request.recipient == expected_payee.to_string(),
        "challenge recipient {} does not match on-chain payee {expected_payee}",
        request.recipient
    );

    let session_key = wallet::subkey(&wallet.seed(), "session");
    let signer = Box::new(
        MemorySigner::from_bytes(&session_key.keypair)
            .map_err(|error| anyhow::anyhow!("session signer: {error}"))?,
    );
    let voucher_key = ed25519_dalek::SigningKey::from_bytes(&session_key.seed());
    let handle = SessionHandle::new(channel_id, signer, challenge).with_voucher_key(voucher_key);
    let authorization = handle
        .close_header(None)
        .await
        .map_err(|error| anyhow::anyhow!("close header: {error}"))?;
    let response = build_request(
        http,
        &endpoint.method,
        &endpoint.url,
        &endpoint.body,
        None,
        &[("authorization".to_string(), authorization)],
    )
    .send()
    .await
    .context("sending recovery close")?;
    let status = response.status();
    let body = response.bytes().await.context("reading recovery close")?;
    crate::scheme::mpp_session::validate_close_response(status, &body)
}

/// Top up existing fixture channels' deposit vaults to `target_usdc` so a long
/// reuse run does not exhaust a channel's cap mid-run. Each `top_up` is signed
/// by its channel's payer (the deterministic fixture wallet), which also pays
/// the fee and funds the transfer from its own token account. Best-effort:
/// channels already at/above the target are skipped and per-channel failures
/// (e.g. a payer short on tokens) are reported without aborting the sweep.
pub async fn top_up(
    config_path: &str,
    fixture_id: &str,
    target_usdc: f64,
    yes: bool,
) -> Result<()> {
    ensure!(
        yes,
        "top-up submits on-chain deposit transactions; re-run with --yes"
    );
    let config = RunConfig::from_yaml_path(config_path)?;
    ensure!(
        config.run.scheme == Scheme::MppSession,
        "top-up requires run.scheme: mpp_session"
    );
    let rpc_url = config
        .resolve_rpc_url()?
        .context("top-up requires an RPC URL")?;
    let funder = wallet::load_funder(&config.run.funder, config.run.network)?;
    let wallet_set_id = crate::fixtures::validate_ready_fixture(fixture_id, &config, &funder)?;

    // USDC-like 6-decimal base units, matching the mpp_session deposit math.
    let target_base = (target_usdc * 1e6) as u64;
    ensure!(target_base > 0, "--target-usdc must be positive");

    let expected: HashMap<Pubkey, (u32, Wallet, Pubkey)> = (0..config.load.users as u32)
        .map(|index| {
            let wallet = wallet::derive_user(&funder.seed(), &wallet_set_id, index);
            let session = wallet::subkey(&wallet.seed(), "session");
            (wallet.pubkey, (index, wallet, session.pubkey))
        })
        .collect();

    let discovery = pay_api_core::RpcClient::new(Duration::from_secs(30))?;
    let channels =
        discover_fixture_channels(&discovery, &rpc_url, CHANNEL_STATUS_OPEN, &expected).await?;
    println!(
        "discovered {} open channels for fixture `{fixture_id}`",
        channels.len()
    );
    if channels.is_empty() {
        return Ok(());
    }

    let mint = from_address(&channels[0].channel.mint);
    ensure!(
        channels
            .iter()
            .all(|channel| from_address(&channel.channel.mint) == mint),
        "refusing top-up: fixture channels use multiple settlement mints"
    );
    let token_program =
        pay_worker::channel::resolve_token_program(&discovery, &rpc_url, &mint).await?;

    let pending: Vec<(&RecoverableChannel, u64)> = channels
        .iter()
        .filter_map(|channel| {
            let delta = target_base.saturating_sub(channel.channel.deposit);
            (delta > 0).then_some((channel, delta))
        })
        .collect();
    println!(
        "{} channels below target {target_usdc} USDC ({} already funded); topping up",
        pending.len(),
        channels.len() - pending.len()
    );
    if pending.is_empty() {
        return Ok(());
    }

    let concurrency = config.load.provision_concurrency.clamp(1, 256);
    let execution = ExecutionConfig {
        window_users: concurrency,
        reconcile_concurrency: concurrency,
        submit_concurrency: concurrency,
        rpc_requests_per_second: 1_000,
        rpc_burst: concurrency.saturating_mul(2),
        request_timeout_seconds: 30,
        confirmation_timeout_seconds: 90,
        ..ExecutionConfig::default()
    };
    let rpc = FixtureRpc::new(rpc_url.clone(), execution);

    let mut topped = 0usize;
    let mut failures = Vec::new();
    // Sign only one concurrency window per blockhash — a full-scale top-up
    // outlives Solana's blockhash validity window.
    for batch in pending.chunks(concurrency) {
        let (blockhash, _) = rpc.latest_blockhash().await?;
        let mut transactions = Vec::with_capacity(batch.len());
        for &(channel, delta) in batch {
            let instruction = pay_worker::channel::build_top_up_ix(
                &channel.address,
                &channel.wallet.pubkey,
                &mint,
                &token_program,
                delta,
            );
            let transaction =
                signed_transaction(&channel.wallet, &[], vec![instruction], blockhash).await?;
            transactions.push((channel.index, channel.address, transaction));
        }
        let rpc_ref = &rpc;
        let mut submitting = stream::iter(transactions.into_iter().map(
            move |(index, channel, tx)| async move {
                (index, channel, rpc_ref.submit_and_confirm(&tx).await)
            },
        ))
        .buffer_unordered(concurrency);
        while let Some((index, channel, result)) = submitting.next().await {
            match result {
                Ok(_) => topped += 1,
                Err(error) => failures.push(format!("user {index} channel {channel}: {error:#}")),
            }
        }
        println!(
            "top-up progress: {topped} confirmed, {} failed",
            failures.len()
        );
    }
    println!(
        "top-up complete: {topped} channels funded toward {target_usdc} USDC; {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        let shown = failures.iter().take(20).cloned().collect::<Vec<_>>();
        eprintln!(
            "first {} top-up failures:\n{}",
            shown.len(),
            shown.join("\n")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rent_reclaim_accepts_sponsored_operator() {
        validate_rent_reclaim_destination(Pubkey::new_unique(), Pubkey::new_unique()).unwrap();
    }

    #[test]
    fn rent_reclaim_rejects_zero_destination() {
        let error =
            validate_rent_reclaim_destination(Pubkey::new_unique(), Pubkey::default()).unwrap_err();
        assert!(error.to_string().contains("zero rent payer"));
    }

    #[test]
    fn distributed_status_uses_the_shared_channel_contract() {
        assert_eq!(STATUS_DISTRIBUTED, 3);
    }
}
