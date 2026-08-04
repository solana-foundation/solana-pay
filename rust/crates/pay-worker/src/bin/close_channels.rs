//! `close-channels` — operator maintenance job.
//!
//! Given a list of payment-channel addresses, advance each toward closure via
//! the payment-channels program's adaptive state machine, signing with a
//! GCP-KMS-backed fee payer.
//!
//! SAFETY: `DRY_RUN` defaults to `true`. Nothing is signed or sent unless
//! `DRY_RUN=false` is explicitly set. See `README.md`.
//!
//! Env:
//!   CHANNEL_ADDRESSES   comma-separated base58 pubkeys (required)
//!   NETWORK             mainnet | sandbox (default: mainnet)
//!   RPC_URL             optional RPC override for the active network
//!   DRY_RUN             default true; set false to actually sign+send
//!   PAY_API_SEND__FEE_PAYER__KEY_NAME / __PUBKEY   GCP KMS fee payer
//!   LOCAL_FEE_PAYER_PRIVATE_KEY                    local signing escape hatch

use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pay_api_core::rpc::RpcClient;
use pay_kit::core::payment_channels::MAX_RECLAIMS_PER_TX;
use pay_kit::core::settlement::packing::{ChannelInstructionGroup, MAX_TX_BYTES, pack, tx_size};
use pay_kit::mpp::solana_keychain::SolanaSigner;
use pay_worker::channel::{
    self, DecodedChannel, STATUS_CLOSING, STATUS_DISTRIBUTED, STATUS_OPEN, STATUS_SEALED,
};
use pay_worker::config::Config;
use pay_worker::error::JobError;
use pay_worker::signer::build_fee_payer_signer;
use solana_instruction::Instruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_transaction::Transaction;
use tracing::{error, info, warn};

const RECLAIM_LEASE_TTL_SECONDS: u64 = 300;
const RECLAIM_LEASE_PREFIX: &str = "pay-worker:reclaim:";

struct ReclaimLease {
    connection: redis::aio::ConnectionManager,
    key: String,
    owner: String,
}

impl ReclaimLease {
    async fn acquire(redis_url: &str, address: &Pubkey) -> Result<Option<Self>, JobError> {
        let client = redis::Client::open(redis_url)
            .map_err(|error| JobError::Config(format!("Redis client: {error}")))?;
        let mut connection = client
            .get_connection_manager()
            .await
            .map_err(|error| JobError::Config(format!("Redis connect: {error}")))?;
        let key = format!("{RECLAIM_LEASE_PREFIX}{address}");
        let owner = format!("{}-{}", std::process::id(), unix_nanos());
        let acquired: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&owner)
            .arg("NX")
            .arg("EX")
            .arg(RECLAIM_LEASE_TTL_SECONDS)
            .query_async(&mut connection)
            .await
            .map_err(|error| JobError::Config(format!("Redis reclaim lease: {error}")))?;
        Ok(acquired.map(|_| Self {
            connection,
            key,
            owner,
        }))
    }

    async fn release(mut self) {
        const RELEASE: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
"#;
        if let Err(error) = redis::Script::new(RELEASE)
            .key(&self.key)
            .arg(&self.owner)
            .invoke_async::<i32>(&mut self.connection)
            .await
        {
            warn!(%error, key = %self.key, "failed to release reclaim lease; TTL will expire it");
        }
    }
}

/// A planned or executed on-chain step for one channel.
struct PlannedStep {
    kind: StepKind,
    instructions: Vec<Instruction>,
    /// Human-readable expected effect, for logs.
    effect: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepKind {
    RequestClose,
    Seal,
    Distribute,
    Reclaim,
}

impl StepKind {
    const fn label(self) -> &'static str {
        match self {
            Self::RequestClose => "request_close",
            Self::Seal => "seal",
            Self::Distribute => "distribute",
            Self::Reclaim => "reclaim",
        }
    }
}

#[tokio::main]
async fn main() {
    init_tracing();

    match run().await {
        Ok(hard_failures) if hard_failures > 0 => {
            error!(hard_failures, "close-channels finished with failures");
            std::process::exit(1);
        }
        Ok(_) => {
            info!("close-channels finished");
        }
        Err(err) => {
            error!(error = %err, "close-channels aborted");
            std::process::exit(1);
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,pay_worker=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

async fn run() -> Result<usize, JobError> {
    let dry_run = parse_dry_run();
    let redis_url = if dry_run {
        None
    } else {
        Some(std::env::var("PAY_SESSION_REDIS_URL").map_err(|_| {
            JobError::Config("PAY_SESSION_REDIS_URL is required when DRY_RUN=false".into())
        })?)
    };
    let network = std::env::var("NETWORK")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mainnet".to_string());

    let config = Config::load(&network)?;
    let rpc_url = config.rpc_url_for(&network)?.to_string();
    let treasury_owner = Pubkey::from_str(config.treasury_owner.trim()).map_err(|_| {
        JobError::Config(format!("invalid treasury_owner: {}", config.treasury_owner))
    })?;

    let rpc = RpcClient::new(Duration::from_millis(config.rpc_timeout_ms))?;
    let current_slot = rpc.get_slot(&rpc_url).await?;
    let addresses = match parse_channel_addresses()? {
        Some(addresses) => addresses,
        None => channel::discover_distributed_channels(&rpc, &rpc_url).await?,
    };

    let signer = build_fee_payer_signer(&config.send.fee_payer).await?;
    let me = signer.pubkey();

    warn!(
        dry_run,
        network = %network,
        rpc_url = %redact(&rpc_url),
        fee_payer = %me,
        channels = addresses.len(),
        current_slot,
        "close-channels starting (DRY_RUN default is true; set DRY_RUN=false to broadcast)"
    );

    let confirm_timeout = Duration::from_secs(config.confirm_timeout_seconds);
    let now = unix_now();

    let mut hard_failures = 0usize;
    let mut skipped = 0usize;
    let mut acted = 0usize;
    let mut reclaim_candidates = Vec::new();
    let mut reclaim_leases = Vec::new();

    for address in &addresses {
        let lease = if let Some(redis_url) = redis_url.as_deref() {
            match ReclaimLease::acquire(redis_url, address).await {
                Ok(Some(lease)) => Some(lease),
                Ok(None) => {
                    skipped += 1;
                    info!(channel = %address, "channel is already owned by another worker");
                    continue;
                }
                Err(err) => {
                    error!(channel = %address, error = %err, "failed to acquire channel lease");
                    hard_failures += 1;
                    continue;
                }
            }
        } else {
            None
        };
        match process_channel(
            &rpc,
            &rpc_url,
            &signer,
            me,
            *address,
            &treasury_owner,
            now,
            current_slot,
            dry_run,
            confirm_timeout,
        )
        .await
        {
            Ok(ChannelOutcome::Acted { steps }) => {
                if let Some(lease) = lease {
                    lease.release().await;
                }
                acted += 1;
                info!(channel = %address, steps, "channel advanced");
            }
            Ok(ChannelOutcome::Skipped { reason }) => {
                if let Some(lease) = lease {
                    lease.release().await;
                }
                skipped += 1;
                info!(channel = %address, reason = %reason, "channel skipped");
            }
            Ok(ChannelOutcome::Reclaim { instructions }) => {
                if let Some(lease) = lease {
                    reclaim_leases.push(lease);
                }
                reclaim_candidates.push(ChannelInstructionGroup {
                    channel_id: address.to_string(),
                    instructions,
                });
            }
            Err(err) => {
                if let Some(lease) = lease {
                    lease.release().await;
                }
                // Per-channel errors don't abort the batch; only count as a
                // hard failure when we were actually trying to broadcast.
                if dry_run {
                    warn!(channel = %address, error = %err, "channel error (dry-run)");
                } else {
                    error!(channel = %address, error = %err, "channel error");
                    hard_failures += 1;
                }
            }
        }
    }

    let reclaim_outcome = process_reclaim_batches(
        &rpc,
        &rpc_url,
        &signer,
        me,
        reclaim_candidates,
        dry_run,
        confirm_timeout,
    )
    .await;
    acted += reclaim_outcome.acted;
    hard_failures += reclaim_outcome.failures;
    for lease in reclaim_leases {
        lease.release().await;
    }

    info!(
        acted,
        skipped,
        hard_failures,
        total = addresses.len(),
        dry_run,
        "close-channels summary"
    );
    Ok(hard_failures)
}

enum ChannelOutcome {
    Acted { steps: usize },
    Skipped { reason: String },
    Reclaim { instructions: Vec<Instruction> },
}

#[allow(clippy::too_many_arguments)]
async fn process_channel(
    rpc: &RpcClient,
    rpc_url: &str,
    signer: &Arc<dyn SolanaSigner>,
    me: Pubkey,
    address: Pubkey,
    treasury_owner: &Pubkey,
    now: i64,
    current_slot: u64,
    dry_run: bool,
    confirm_timeout: Duration,
) -> Result<ChannelOutcome, JobError> {
    let Some(decoded) = channel::fetch_channel(rpc, rpc_url, &address).await? else {
        return Ok(ChannelOutcome::Skipped {
            reason: "not a live Channel account (wrong owner/discriminator/size, or tombstoned)"
                .into(),
        });
    };

    let status = decoded.channel.status;
    let payer = decoded.payer();
    let payee = decoded.payee();
    info!(
        channel = %address,
        status,
        payer = %payer,
        payee = %payee,
        mint = %decoded.mint(),
        deposit = decoded.channel.deposit,
        grace_period = decoded.channel.grace_period,
        closure_started_at = decoded.channel.closure_started_at,
        "decoded channel"
    );

    // Build the ordered list of steps to run this invocation.
    let steps = plan_steps(
        rpc,
        rpc_url,
        &decoded,
        me,
        treasury_owner,
        now,
        current_slot,
    )
    .await?;

    if steps.len() == 1 && steps[0].kind == StepKind::Reclaim {
        let step = steps
            .into_iter()
            .next()
            .expect("single reclaim step was checked");
        log_planned_step(&address, &step);
        return Ok(ChannelOutcome::Reclaim {
            instructions: step.instructions,
        });
    }

    let mut ran = 0usize;
    for step in &steps {
        log_planned_step(&address, step);
        if dry_run {
            continue;
        }
        let sig = build_sign_send(rpc, rpc_url, signer, me, &step.instructions).await?;
        rpc.confirm_signature(rpc_url, &sig.to_string(), confirm_timeout)
            .await?;
        info!(
            channel = %address,
            step = step.kind.label(),
            signature = %sig,
            "step confirmed"
        );
        ran += 1;
    }

    if steps.is_empty() {
        Ok(ChannelOutcome::Skipped {
            reason: "no advancing action available this run".into(),
        })
    } else {
        Ok(ChannelOutcome::Acted {
            steps: if dry_run { steps.len() } else { ran },
        })
    }
}

/// Run the adaptive state machine and return the ordered instruction steps.
///
/// A "step" is one transaction. We keep `seal` + `distribute` as separate
/// transactions so the second only applies to state the first produced — and
/// so a dry-run can log each with its own derived accounts.
async fn plan_steps(
    rpc: &RpcClient,
    rpc_url: &str,
    decoded: &DecodedChannel,
    me: Pubkey,
    treasury_owner: &Pubkey,
    now: i64,
    current_slot: u64,
) -> Result<Vec<PlannedStep>, JobError> {
    let address = decoded.address;
    let payer = decoded.payer();
    let payee = decoded.payee();
    let mint = decoded.mint();
    let token_program = channel::resolve_token_program(rpc, rpc_url, &mint).await?;

    let mut steps = Vec::new();

    match decoded.channel.status {
        STATUS_OPEN => {
            if me == payee {
                warn!(
                    channel = %address,
                    "refusing to seal an open payee channel without Redis voucher state; use settle-sessions"
                );
            } else if me == payer {
                steps.push(PlannedStep {
                    kind: StepKind::RequestClose,
                    instructions: vec![channel::build_request_close_ix(&address, &payer)],
                    effect: "start the close grace window (a later run seals after grace)".into(),
                });
            } else {
                info!(channel = %address, "cannot advance (not payer/payee)");
            }
        }
        STATUS_CLOSING => {
            let deadline = decoded.close_deadline();
            if now >= deadline {
                steps.push(PlannedStep {
                    kind: StepKind::Seal,
                    instructions: vec![channel::build_seal_ix(&address)],
                    effect: "permissionlessly seal the channel (grace elapsed)".into(),
                });
                let dist =
                    build_distribute_step(rpc, rpc_url, decoded, treasury_owner, &token_program)
                        .await?;
                steps.push(dist);
            } else {
                info!(
                    channel = %address,
                    deadline,
                    now,
                    "grace not elapsed, retry after deadline"
                );
            }
        }
        STATUS_SEALED => {
            let dist = build_distribute_step(rpc, rpc_url, decoded, treasury_owner, &token_program)
                .await?;
            steps.push(dist);
        }
        STATUS_DISTRIBUTED => {
            let reclaim_slot = decoded
                .open_slot()
                .saturating_add(pay_kit::core::payment_channels::OPEN_SLOT_WINDOW)
                .saturating_add(1);
            if current_slot >= reclaim_slot {
                steps.push(PlannedStep {
                    kind: StepKind::Reclaim,
                    instructions: vec![channel::build_reclaim_ix(&address, &decoded.rent_payer())],
                    effect: format!(
                        "deallocate the distributed channel PDA and return rent to {}",
                        decoded.rent_payer()
                    ),
                });
            } else {
                info!(
                    channel = %address,
                    current_slot,
                    reclaim_slot,
                    "channel rent reclaim is not unlocked yet"
                );
            }
        }
        other => {
            warn!(channel = %address, status = other, "unknown channel status; skipping");
        }
    }

    Ok(steps)
}

/// Build the `distribute` step, recovering + verifying the distribution
/// preimage from the channel's open transaction first.
async fn build_distribute_step(
    rpc: &RpcClient,
    rpc_url: &str,
    decoded: &DecodedChannel,
    treasury_owner: &Pubkey,
    token_program: &Pubkey,
) -> Result<PlannedStep, JobError> {
    let preimage = channel::recover_distribution_preimage(rpc, rpc_url, decoded).await?;
    let recipients = preimage.recipients.len();
    let (ix, accounts) =
        channel::build_distribute_ix(decoded, treasury_owner, token_program, &preimage);
    info!(
        channel = %decoded.address,
        recipients,
        channel_ata = %accounts.channel_ata,
        payer_ata = %accounts.payer_ata,
        payee_ata = %accounts.payee_ata,
        treasury_ata = %accounts.treasury_ata,
        recipient_atas = ?accounts.recipient_atas,
        "distribute accounts derived"
    );
    Ok(PlannedStep {
        kind: StepKind::Distribute,
        instructions: vec![ix],
        effect: format!("refund payer + pay {recipients} recipient(s) + tombstone channel"),
    })
}

#[derive(Default)]
struct ReclaimBatchOutcome {
    acted: usize,
    failures: usize,
}

fn pack_reclaim_candidates(
    candidates: Vec<ChannelInstructionGroup>,
    fee_payer: &Pubkey,
) -> Vec<Vec<ChannelInstructionGroup>> {
    pack(candidates, fee_payer, MAX_RECLAIMS_PER_TX)
}

#[allow(clippy::too_many_arguments)]
async fn process_reclaim_batches(
    rpc: &RpcClient,
    rpc_url: &str,
    signer: &Arc<dyn SolanaSigner>,
    fee_payer: Pubkey,
    candidates: Vec<ChannelInstructionGroup>,
    dry_run: bool,
    confirm_timeout: Duration,
) -> ReclaimBatchOutcome {
    let mut outcome = ReclaimBatchOutcome::default();

    for group in pack_reclaim_candidates(candidates, &fee_payer) {
        let channels: Vec<_> = group
            .iter()
            .map(|candidate| candidate.channel_id.clone())
            .collect();
        let channel_count = channels.len();
        let instructions: Vec<_> = group
            .into_iter()
            .flat_map(|candidate| candidate.instructions)
            .collect();
        let serialized_size = tx_size(&instructions, &fee_payer);

        if serialized_size > MAX_TX_BYTES {
            outcome.failures += channel_count;
            error!(
                channels = ?channels,
                channel_count,
                tx_bytes = serialized_size,
                max_tx_bytes = MAX_TX_BYTES,
                "reclaim batch exceeds Solana transaction size"
            );
            continue;
        }

        if dry_run {
            outcome.acted += channel_count;
            info!(
                channels = ?channels,
                channel_count,
                instructions = instructions.len(),
                tx_bytes = serialized_size,
                "planned reclaim batch"
            );
            continue;
        }

        let result = async {
            let signature = build_sign_send(rpc, rpc_url, signer, fee_payer, &instructions).await?;
            rpc.confirm_signature(rpc_url, &signature.to_string(), confirm_timeout)
                .await?;
            Ok::<_, JobError>(signature)
        }
        .await;

        match result {
            Ok(signature) => {
                outcome.acted += channel_count;
                info!(
                    channels = ?channels,
                    channel_count,
                    instructions = instructions.len(),
                    tx_bytes = serialized_size,
                    %signature,
                    "reclaim batch confirmed"
                );
            }
            Err(error) => {
                outcome.failures += channel_count;
                error!(
                    channels = ?channels,
                    channel_count,
                    instructions = instructions.len(),
                    tx_bytes = serialized_size,
                    %error,
                    "reclaim batch failed"
                );
            }
        }
    }

    outcome
}

/// Build a FRESH transaction (fee payer = KMS pubkey), sign the message with
/// the async KMS signer, serialize, and broadcast. Mirrors pay-api's
/// `co_sign_and_broadcast` but constructs the tx from scratch.
async fn build_sign_send(
    rpc: &RpcClient,
    rpc_url: &str,
    signer: &Arc<dyn SolanaSigner>,
    fee_payer: Pubkey,
    instructions: &[Instruction],
) -> Result<Signature, JobError> {
    let blockhash_b58 = rpc.get_latest_blockhash(rpc_url).await?;
    let blockhash_bytes = bs58::decode(&blockhash_b58)
        .into_vec()
        .map_err(|e| JobError::TxBuild(format!("blockhash decode: {e}")))?;
    let blockhash_arr: [u8; 32] = blockhash_bytes
        .try_into()
        .map_err(|_| JobError::TxBuild("blockhash is not 32 bytes".into()))?;

    let mut message = Message::new(instructions, Some(&fee_payer));
    message.recent_blockhash = solana_message::Hash::from(blockhash_arr);

    let mut tx = Transaction::new_unsigned(message);

    // Fee payer occupies signature slot 0. There may be additional required
    // signers (payer/payee) — but for KMS-operator flows the fee payer is the
    // only signer we hold, so any other required signer means the step isn't
    // one we can complete. Guard against silently sending a half-signed tx.
    let required = tx.message.header.num_required_signatures as usize;
    if required != 1 {
        return Err(JobError::TxBuild(format!(
            "transaction requires {required} signatures but only the fee payer (KMS) is available"
        )));
    }

    let msg_bytes = tx.message_data();
    let sig_bytes = signer
        .sign_message(&msg_bytes)
        .await
        .map_err(|_| JobError::Signing)?;
    let signature = Signature::from(<[u8; 64]>::from(sig_bytes));
    if tx.signatures.is_empty() {
        return Err(JobError::TxBuild(
            "transaction has no signature slots".into(),
        ));
    }
    tx.signatures[0] = signature;

    let serialized = bincode::serialize(&tx).map_err(|e| JobError::TxBuild(e.to_string()))?;
    let tx_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &serialized);
    let sig_str = rpc.send_raw_transaction(rpc_url, &tx_b64).await?;
    Signature::from_str(&sig_str).map_err(|_| JobError::TxBuild("malformed signature".into()))
}

fn log_planned_step(address: &Pubkey, step: &PlannedStep) {
    let programs: Vec<String> = step
        .instructions
        .iter()
        .map(|ix| ix.program_id.to_string())
        .collect();
    let account_count: usize = step.instructions.iter().map(|ix| ix.accounts.len()).sum();
    info!(
        channel = %address,
        step = step.kind.label(),
        instructions = step.instructions.len(),
        accounts = account_count,
        programs = ?programs,
        effect = %step.effect,
        "planned step"
    );
}

fn parse_dry_run() -> bool {
    match std::env::var("DRY_RUN") {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            // Only an explicit falsey value disables dry-run.
            !matches!(v.as_str(), "false" | "0" | "no" | "off")
        }
        // Unset → dry-run.
        Err(_) => true,
    }
}

fn parse_channel_addresses() -> Result<Option<Vec<Pubkey>>, JobError> {
    let raw = std::env::var("CHANNEL_ADDRESSES").unwrap_or_default();
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let pk = Pubkey::from_str(part).map_err(|_| JobError::InvalidAddress(part.to_string()))?;
        out.push(pk);
    }
    if out.is_empty() {
        return Ok(None);
    }
    Ok(Some(out))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

/// Redact any `api-key=` query param from an RPC URL before logging.
fn redact(url: &str) -> String {
    match url.split_once("api-key=") {
        Some((head, _)) => format!("{head}api-key=***"),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey(tag: u8, index: usize) -> Pubkey {
        let mut bytes = [0_u8; 32];
        bytes[0] = tag;
        bytes[1..9].copy_from_slice(&(index as u64).to_le_bytes());
        Pubkey::new_from_array(bytes)
    }

    fn reclaim_candidate(index: usize, rent_payer: &Pubkey) -> ChannelInstructionGroup {
        let channel_id = pubkey(1, index);
        ChannelInstructionGroup {
            channel_id: channel_id.to_string(),
            instructions: vec![channel::build_reclaim_ix(&channel_id, rent_payer)],
        }
    }

    #[test]
    fn two_reclaims_share_one_transaction() {
        let fee_payer = pubkey(2, 0);
        let candidates = (0..2)
            .map(|index| reclaim_candidate(index, &fee_payer))
            .collect();

        let groups = pack_reclaim_candidates(candidates, &fee_payer);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
    }

    #[test]
    fn reclaim_batches_use_the_operation_specific_cap() {
        let fee_payer = pubkey(2, 0);
        let candidates = (0..=MAX_RECLAIMS_PER_TX)
            .map(|index| reclaim_candidate(index, &fee_payer))
            .collect();

        let groups = pack_reclaim_candidates(candidates, &fee_payer);
        let group_sizes: Vec<_> = groups.iter().map(Vec::len).collect();

        assert_eq!(group_sizes, vec![MAX_RECLAIMS_PER_TX, 1]);
        for group in groups {
            let instructions: Vec<_> = group
                .into_iter()
                .flat_map(|candidate| candidate.instructions)
                .collect();
            assert!(tx_size(&instructions, &fee_payer) <= MAX_TX_BYTES);
        }
    }

    #[test]
    fn varying_rent_payers_are_still_byte_bounded() {
        let fee_payer = pubkey(2, 0);
        let candidates = (0..MAX_RECLAIMS_PER_TX)
            .map(|index| {
                let rent_payer = pubkey(3, index);
                reclaim_candidate(index, &rent_payer)
            })
            .collect();

        let groups = pack_reclaim_candidates(candidates, &fee_payer);

        assert!(groups.len() > 1);
        for group in groups {
            let instructions: Vec<_> = group
                .into_iter()
                .flat_map(|candidate| candidate.instructions)
                .collect();
            assert!(tx_size(&instructions, &fee_payer) <= MAX_TX_BYTES);
        }
    }
}
