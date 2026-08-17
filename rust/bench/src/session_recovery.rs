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
use solana_pubkey::Pubkey;

use crate::config::{RunConfig, Scheme};
use crate::scheme::{build_request, validate_payment_transport, www_authenticate};
use crate::wallet::{self, Wallet};

const CHANNEL_ACCOUNT_SIZE: usize = 256;
const CHANNEL_STATUS_OFFSET: usize = 3;
const CHANNEL_STATUS_OPEN: u8 = 0;

struct RecoverableChannel {
    address: Pubkey,
    index: u32,
    wallet: Wallet,
    payee: Pubkey,
}

/// Discover open channels owned by a deterministic fixture and close them
/// through the live gateway. This repairs the process-local handle gap after
/// an interrupted provisioning phase without guessing channel salts.
pub async fn recover(config_path: &str, fixture_id: &str, yes: bool) -> Result<()> {
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

    let rpc = pay_api_core::RpcClient::new(Duration::from_secs(30))?;
    let accounts = rpc
        .get_program_accounts_filtered(
            &rpc_url,
            &default_program_id().to_string(),
            CHANNEL_ACCOUNT_SIZE,
            CHANNEL_STATUS_OFFSET,
            &[CHANNEL_STATUS_OPEN],
        )
        .await
        .context("discovering open payment channels")?;

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
        });
    }
    ensure!(
        signer_mismatches == 0,
        "refusing recovery: {signer_mismatches} fixture channels had an unexpected authorized signer"
    );

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
