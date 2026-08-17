//! Recovery for live payment channels whose process-local handles were lost.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use futures::stream::{self, StreamExt};
use pay_core::client::session::SessionHandle;
use pay_kit::generated::payment_channels::generated::accounts::Channel;
use pay_kit::mpp::program::payment_channels::{default_program_id, from_address};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_kit::mpp::solana_keychain::memory::MemorySigner;
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;

use crate::config::{Network, RunConfig, Scheme};
use crate::fixture_rpc::{ExecutionConfig, FixtureRpc};
use crate::scheme::{build_request, validate_payment_transport, www_authenticate};
use crate::wallet::{self, Wallet};

const CHANNEL_ACCOUNT_SIZE: usize = 256;
const CHANNEL_STATUS_OFFSET: usize = 3;
const CHANNEL_STATUS_OPEN: u8 = 0;
const CHANNEL_STATUS_SEALED: u8 = 1;
const CHANNEL_STATUS_DISTRIBUTED: u8 = 2;

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
        return recover_without_gateway_state(&config, &rpc_url, fixture_id, &funder, &expected)
            .await;
    }

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
    ensure!(
        signer_mismatches == 0,
        "refusing recovery: {signer_mismatches} fixture channels had an unexpected authorized signer"
    );
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
    validate_zero_voucher_channels(open.iter().chain(already_sealed.iter()), funder)?;

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
                let transaction = signed_transaction(funder, vec![instruction], blockhash).await?;
                transactions.push((channel.index, channel.address, transaction));
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
    validate_zero_voucher_channels(sealed.iter(), funder)?;
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
                let transaction = signed_transaction(funder, vec![instruction], blockhash).await?;
                transactions.push((channel.index, channel.address, transaction));
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
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_DISTRIBUTED, expected)
            .await?;
    validate_zero_voucher_channels(distributed.iter(), funder)?;
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
                let transaction = signed_transaction(funder, vec![instruction], blockhash).await?;
                transactions.push((channel.index, channel.address, transaction));
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
        discover_fixture_channels(&discovery, rpc_url, CHANNEL_STATUS_DISTRIBUTED, expected)
            .await?;
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
        ensure!(
            channel.channel.settlement.settled == 0
                && channel.channel.settlement.payout_watermark == 0,
            "refusing zero-voucher recovery: channel {} has non-zero settlement watermarks",
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

async fn signed_transaction(
    fee_payer: &Wallet,
    instructions: Vec<Instruction>,
    blockhash: Hash,
) -> Result<Transaction> {
    let message = Message::new_with_blockhash(&instructions, Some(&fee_payer.pubkey), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    let signer = MemorySigner::from_bytes(&fee_payer.keypair).context("loading recovery signer")?;
    let signature = signer
        .sign_message(&transaction.message_data())
        .await
        .context("signing recovery transaction")?;
    let index = transaction
        .message
        .account_keys
        .iter()
        .position(|key| *key == fee_payer.pubkey)
        .context("recovery signer is absent from transaction")?;
    transaction.signatures[index] = Signature::from(<[u8; 64]>::from(signature));
    Ok(transaction)
}

async fn submit_transactions(
    rpc: &FixtureRpc,
    transactions: Vec<(u32, Pubkey, Transaction)>,
    concurrency: usize,
    operation: &str,
) -> Result<()> {
    let mut submitting = stream::iter(transactions.into_iter().map(
        |(index, channel, tx)| async move { (index, channel, rpc.submit_and_confirm(&tx).await) },
    ))
    .buffer_unordered(concurrency);
    let mut confirmed = 0usize;
    let mut failures = Vec::new();
    while let Some((index, channel, result)) = submitting.next().await {
        match result {
            Ok(_) => confirmed += 1,
            Err(error) => failures.push(format!("user {index} channel {channel}: {error:#}")),
        }
    }
    println!(
        "{operation}: {confirmed} confirmed, {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        let shown = failures.iter().take(20).cloned().collect::<Vec<_>>();
        bail!(
            "{operation} failed for {} channels (first {}):\n{}",
            failures.len(),
            shown.len(),
            shown.join("\n")
        );
    }
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
