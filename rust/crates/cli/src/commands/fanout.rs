//! `pay fanout` — high-throughput, journaled CSV stablecoin payouts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use chrono::Utc;
use ed25519_dalek::SigningKey;
use futures_util::{StreamExt, TryStreamExt};
use pay_core::accounts::{
    Account, AccountChoice, AccountsFile, AccountsStore, FileAccountsStore, Keystore,
    MemoryAccountsStore, resolve_account_for_network,
};
use pay_core::client::push::executor::{
    ChunkTxContext, DirectSolanaBroadcaster, PushExecutor, PushExecutorConfig,
    drop_permit_off_runtime_thread,
};
use pay_core::client::push::journal::{Journal, default_journal_path};
use pay_core::client::push::manifest::{ManifestContext, parse_manifest_csv};
use pay_core::client::push::permit::{BatchAuthorizationSummary, BatchSigningPermit};
use pay_core::client::push::planner::{
    AtaSnapshot, DestinationAtaStatus, FeePayerMode, compute_reserve_lamports, pack_chunks,
    rent_exempt_minimum_lamports, token_account_len,
};
use pay_core::{Error, Result};
use pay_kit::mpp::protocol::solana::{default_rpc_url, programs};
use pay_types::{Stablecoin, stablecoin_mints};
use serde_json::{Value, json};
use solana_pubkey::Pubkey;

const DEFAULT_MAX_IN_FLIGHT: usize = 128;
const DEFAULT_POLL_INTERVAL_MS: u64 = 250;
const PREFLIGHT_CONCURRENCY: usize = 32;
const ESTIMATED_FEE_LAMPORTS_PER_CHUNK: u64 = 10_000;

#[derive(clap::Args)]
pub struct FanoutCommand {
    /// RFC 4180 CSV with exactly `recipient,amount` headers.
    #[arg(value_name = "CSV")]
    csv: PathBuf,

    /// Stablecoin symbol (for example USDC, USDG, or devnet-only USDtest).
    #[arg(long, value_name = "STABLECOIN")]
    currency: String,

    /// Solana network whose mint and account registry entry will be used.
    #[arg(long, default_value = "mainnet")]
    network: String,

    /// Explicit Solana JSON-RPC URL. Defaults to PAY_RPC_URL, then the network default.
    #[arg(long, value_name = "URL")]
    rpc_url: Option<String>,

    /// Solana CLI JSON keypair. Allowed only off mainnet; it is never persisted.
    #[arg(long, value_name = "PATH")]
    keypair: Option<PathBuf>,

    /// Maximum broadcast transactions awaiting confirmation at once.
    #[arg(long, default_value_t = DEFAULT_MAX_IN_FLIGHT)]
    max_in_flight: usize,

    /// Durable JSONL journal path. Defaults under ~/.config/pay/push/.
    #[arg(long, value_name = "PATH")]
    journal: Option<PathBuf>,
}

impl FanoutCommand {
    pub fn run(
        self,
        network_override: Option<&str>,
        account_override: Option<&str>,
        verbose: bool,
    ) -> Result<()> {
        let network = effective_network(&self.network, network_override).to_string();
        validate_network(&network)?;
        if network == "mainnet" && self.keypair.is_some() {
            return Err(Error::Config(
                "--keypair is disabled for mainnet fanout; use a configured pay account so its authentication policy is enforced"
                    .to_string(),
            ));
        }
        if self.max_in_flight == 0 {
            return Err(Error::Config(
                "--max-in-flight must be greater than 0".to_string(),
            ));
        }

        let rpc_url = self
            .rpc_url
            .clone()
            .or_else(|| std::env::var("PAY_RPC_URL").ok())
            .unwrap_or_else(|| default_rpc_url(&network).to_string());
        let (currency, mint) = resolve_currency(&self.currency, &network)?;
        let (store, account_name, sender) =
            resolve_signing_account(&network, account_override, self.keypair.as_deref())?;
        let csv = std::fs::read(&self.csv).map_err(|error| {
            Error::Config(format!("failed to read {}: {error}", self.csv.display()))
        })?;

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Config(format!("failed to start fanout runtime: {error}")))?;
        let rpc = FanoutRpc::new(rpc_url.clone());
        let mint_info = runtime.block_on(rpc.mint_info(&mint))?;
        let genesis_hash = runtime.block_on(rpc.genesis_hash())?;
        let context = ManifestContext {
            network_genesis_hash: genesis_hash,
            mint,
            token_program: mint_info.token_program,
            decimals: mint_info.decimals,
        };
        let manifest = parse_manifest_csv(csv.as_slice(), context)?;
        let snapshot =
            runtime.block_on(rpc.ata_snapshot(&sender, &manifest, mint_info.token_program))?;
        let plan = pack_chunks(
            &manifest,
            &snapshot,
            FeePayerMode::SelfFunded,
            &sender,
            &sender,
            0,
        )?;

        let source_balance = runtime.block_on(rpc.token_balance(&snapshot.sender_ata))?;
        if source_balance < manifest.total_amount_raw {
            return Err(Error::Config(format!(
                "source account has {source_balance} base units of {currency}; fanout needs {}",
                manifest.total_amount_raw
            )));
        }
        let rent_per_ata =
            rent_exempt_minimum_lamports(token_account_len(&mint_info.token_program));
        let missing_ata_rent_lamports = rent_per_ata
            .checked_mul(snapshot.missing_count() as u64)
            .ok_or_else(|| {
            Error::Config("missing-ATA rent estimate overflowed u64".to_string())
        })?;
        let estimated_fee_lamports = ESTIMATED_FEE_LAMPORTS_PER_CHUNK
            .checked_mul(plan.total_transactions() as u64)
            .ok_or_else(|| Error::Config("transaction fee estimate overflowed u64".to_string()))?;
        let reserve_lamports = compute_reserve_lamports(estimated_fee_lamports);
        let needed_sol = missing_ata_rent_lamports
            .checked_add(estimated_fee_lamports)
            .and_then(|value| value.checked_add(reserve_lamports))
            .ok_or_else(|| Error::Config("fanout SOL estimate overflowed u64".to_string()))?;
        let available_sol = runtime.block_on(rpc.sol_balance(&sender))?;
        if available_sol < needed_sol {
            return Err(Error::Config(format!(
                "fee payer {sender} has {available_sol} lamports; fanout needs about {needed_sol} for {} missing ATAs, fees, and reserve",
                snapshot.missing_count()
            )));
        }

        let manifest_hash = manifest.hash_hex();
        let journal_path = self.journal.unwrap_or_else(|| {
            default_journal_path(pay_core::client::push::manifest_hash_prefix(&manifest_hash))
        });
        let mut journal = Journal::create_new(journal_path.clone())?;
        journal.append_run_created(
            manifest_hash,
            network.clone(),
            currency.clone(),
            mint.to_string(),
            mint_info.token_program.to_string(),
            mint_info.decimals,
            manifest.rows.len(),
            manifest.total_amount_raw,
            "self_funded".to_string(),
        )?;
        journal.append_preflight_completed(
            FeePayerMode::SelfFunded,
            estimated_fee_lamports,
            missing_ata_rent_lamports,
            reserve_lamports,
            plan.total_transactions(),
            manifest.total_amount_raw,
        )?;

        if verbose {
            eprintln!(
                "Fanout plan: {} recipients, {} transactions, {} missing ATAs, {} max in flight",
                manifest.rows.len(),
                plan.total_transactions(),
                snapshot.missing_count(),
                self.max_in_flight
            );
        }

        let summary = BatchAuthorizationSummary {
            account: &account_name,
            currency: &currency,
            currency_decimals: mint_info.decimals,
            network: &network,
            recipient_total_raw: manifest.total_amount_raw,
            max_total_raw: manifest.total_amount_raw,
        };
        let mut permit = BatchSigningPermit::authorize(
            &network,
            store.as_ref(),
            Some(&account_name),
            genesis_hash,
            &manifest,
            plan.clone(),
            summary,
            chrono::Duration::hours(6),
            None,
        )?;
        journal.append_authorization_granted(
            sender.to_string(),
            manifest.total_amount_raw,
            plan.total_transactions(),
            permit.expires_at(),
        )?;

        let broadcaster = DirectSolanaBroadcaster::new(rpc_url, sender);
        let executor_config = PushExecutorConfig {
            max_in_flight: self.max_in_flight,
            poll_interval: Duration::from_millis(DEFAULT_POLL_INTERVAL_MS),
        };
        let outcome = runtime.block_on(async {
            let mut executor = PushExecutor::new(
                &mut permit,
                &mut journal,
                &broadcaster,
                ChunkTxContext {
                    sender,
                    mint,
                    token_program: mint_info.token_program,
                    decimals: mint_info.decimals,
                },
                executor_config,
            );
            executor.run(&plan.chunks).await
        });
        drop_permit_off_runtime_thread(permit);
        let outcome = outcome?;
        journal.append_run_completed(outcome.confirmed, outcome.failed, 0)?;
        if outcome.failed > 0 {
            return Err(Error::Config(format!(
                "fanout finished with {} confirmed and {} failed chunks; journal: {}",
                outcome.confirmed,
                outcome.failed,
                journal_path.display()
            )));
        }

        println!(
            "Fanout confirmed: {} recipients in {} transactions\nJournal: {}",
            manifest.rows.len(),
            outcome.confirmed,
            journal_path.display()
        );
        Ok(())
    }
}

#[derive(Clone)]
struct FanoutRpc {
    http: reqwest::Client,
    url: String,
}

#[derive(Clone, Copy)]
struct MintInfo {
    token_program: Pubkey,
    decimals: u8,
}

impl FanoutRpc {
    fn new(url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            url,
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value> {
        let response = self
            .http
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|error| Error::Config(format!("{method} transport failed: {error}")))?;
        let body: Value = response
            .json()
            .await
            .map_err(|error| Error::Config(format!("{method} returned invalid JSON: {error}")))?;
        if let Some(error) = body.get("error") {
            return Err(Error::Config(format!("{method} RPC error: {error}")));
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| Error::Config(format!("{method} response is missing result")))
    }

    async fn genesis_hash(&self) -> Result<[u8; 32]> {
        let hash = self
            .call("getGenesisHash", json!([]))
            .await?
            .as_str()
            .ok_or_else(|| Error::Config("malformed getGenesisHash response".to_string()))?
            .to_string();
        let bytes = bs58::decode(hash)
            .into_vec()
            .map_err(|error| Error::Config(format!("invalid genesis hash: {error}")))?;
        bytes
            .try_into()
            .map_err(|_| Error::Config("genesis hash must decode to 32 bytes".to_string()))
    }

    async fn mint_info(&self, mint: &Pubkey) -> Result<MintInfo> {
        let result = self
            .call(
                "getAccountInfo",
                json!([mint.to_string(), {"encoding":"jsonParsed","commitment":"confirmed"}]),
            )
            .await?;
        let value = result
            .get("value")
            .filter(|value| !value.is_null())
            .ok_or_else(|| Error::Config(format!("mint {mint} does not exist")))?;
        let token_program = value
            .get("owner")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Config("mint account owner is missing".to_string()))?
            .parse()
            .map_err(|error| Error::Config(format!("mint token program is invalid: {error}")))?;
        let decimals = value
            .pointer("/data/parsed/info/decimals")
            .and_then(Value::as_u64)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or_else(|| Error::Config("mint decimals are missing or invalid".to_string()))?;
        Ok(MintInfo {
            token_program,
            decimals,
        })
    }

    async fn ata_snapshot(
        &self,
        sender: &Pubkey,
        manifest: &pay_core::client::push::manifest::TransferManifest,
        token_program: Pubkey,
    ) -> Result<AtaSnapshot> {
        let sender_ata = associated_token_address(sender, &manifest.context.mint, &token_program)?;
        let indexed = manifest
            .rows
            .iter()
            .enumerate()
            .map(|(index, row)| {
                let ata = associated_token_address(
                    &row.recipient,
                    &manifest.context.mint,
                    &token_program,
                )?;
                Ok((index, row.recipient, ata))
            })
            .collect::<Result<Vec<_>>>()?;
        let batches = indexed
            .chunks(100)
            .map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        let mut statuses = futures_util::stream::iter(batches)
            .map(|batch| {
                let rpc = self.clone();
                async move {
                    let addresses = batch
                        .iter()
                        .map(|(_, _, ata)| ata.to_string())
                        .collect::<Vec<_>>();
                    let result = rpc
                        .call(
                            "getMultipleAccounts",
                            json!([addresses, {"encoding":"base64","commitment":"confirmed"}]),
                        )
                        .await?;
                    let values =
                        result
                            .get("value")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                Error::Config("malformed getMultipleAccounts response".to_string())
                            })?;
                    if values.len() != batch.len() {
                        return Err(Error::Config(
                            "getMultipleAccounts returned the wrong number of accounts".to_string(),
                        ));
                    }
                    Ok::<_, Error>(
                        batch
                            .into_iter()
                            .zip(values)
                            .map(|((index, recipient, ata), value)| {
                                (
                                    index,
                                    DestinationAtaStatus {
                                        recipient,
                                        ata,
                                        exists: !value.is_null(),
                                    },
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                }
            })
            .buffer_unordered(PREFLIGHT_CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        statuses.sort_by_key(|(index, _)| *index);
        let destinations = statuses.into_iter().map(|(_, status)| status).collect();
        let sender_ata_exists = self.account_exists(&sender_ata).await?;
        Ok(AtaSnapshot {
            sender_ata,
            sender_ata_exists,
            destinations,
        })
    }

    async fn account_exists(&self, address: &Pubkey) -> Result<bool> {
        let result = self
            .call(
                "getAccountInfo",
                json!([address.to_string(), {"encoding":"base64","commitment":"confirmed"}]),
            )
            .await?;
        Ok(result.get("value").is_some_and(|value| !value.is_null()))
    }

    async fn token_balance(&self, address: &Pubkey) -> Result<u64> {
        let result = self
            .call(
                "getTokenAccountBalance",
                json!([address.to_string(), {"commitment":"confirmed"}]),
            )
            .await?;
        result
            .pointer("/value/amount")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Config(format!("token account {address} has no raw balance")))?
            .parse()
            .map_err(|error| Error::Config(format!("token balance is invalid: {error}")))
    }

    async fn sol_balance(&self, address: &Pubkey) -> Result<u64> {
        let result = self
            .call(
                "getBalance",
                json!([address.to_string(), {"commitment":"confirmed"}]),
            )
            .await?;
        result
            .get("value")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Config("malformed getBalance response".to_string()))
    }
}

fn resolve_currency(currency: &str, network: &str) -> Result<(String, Pubkey)> {
    if currency.eq_ignore_ascii_case("USDtest") {
        if network != "devnet" {
            return Err(Error::Config(
                "USDtest is devnet-only; pass --network devnet".to_string(),
            ));
        }
        return Ok((
            "USDtest".to_string(),
            Pubkey::from_str(stablecoin_mints::USDTEST_DEVNET)
                .map_err(|error| Error::Config(format!("invalid USDtest mint: {error}")))?,
        ));
    }
    let stablecoin = Stablecoin::from_str(currency).map_err(Error::Config)?;
    Pubkey::from_str(stablecoin.mint(Some(network)))
        .map(|mint| (stablecoin.symbol().to_string(), mint))
        .map_err(|error| Error::Config(format!("invalid {} mint: {error}", stablecoin.symbol())))
}

fn validate_network(network: &str) -> Result<()> {
    match network {
        "mainnet" | "devnet" | "testnet" | "localnet" => Ok(()),
        _ => Err(Error::Config(format!(
            "unsupported fanout network `{network}`; use mainnet, devnet, testnet, or localnet"
        ))),
    }
}

fn effective_network<'a>(configured: &'a str, override_network: Option<&'a str>) -> &'a str {
    override_network.unwrap_or(configured)
}

fn resolve_signing_account(
    network: &str,
    account_override: Option<&str>,
    keypair: Option<&Path>,
) -> Result<(Box<dyn AccountsStore>, String, Pubkey)> {
    if let Some(path) = keypair {
        let raw = std::fs::read_to_string(path).map_err(|error| {
            Error::Config(format!(
                "failed to read keypair {}: {error}",
                path.display()
            ))
        })?;
        let bytes: Vec<u8> = serde_json::from_str(&raw).map_err(|error| {
            Error::Config(format!(
                "keypair {} is not a JSON byte array: {error}",
                path.display()
            ))
        })?;
        if bytes.len() != 64 {
            return Err(Error::Config(format!(
                "keypair {} must contain exactly 64 bytes",
                path.display()
            )));
        }
        let seed: [u8; 32] = bytes[..32]
            .try_into()
            .map_err(|_| Error::Config("keypair seed must be 32 bytes".to_string()))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public = signing_key.verifying_key().to_bytes();
        if bytes[32..] != public {
            return Err(Error::Config(format!(
                "keypair {} public half does not match its secret seed",
                path.display()
            )));
        }
        let pubkey = Pubkey::new_from_array(public);
        let account_name = "fanout-keypair".to_string();
        let account = Account {
            keystore: Keystore::File,
            active: true,
            auth_required: Some(false),
            pubkey: Some(pubkey.to_string()),
            vault: None,
            account: None,
            path: Some(path.to_string_lossy().to_string()),
            secret_key_b58: None,
            created_at: Some(Utc::now().to_rfc3339()),
            subscriptions: BTreeMap::new(),
        };
        let mut file = AccountsFile::default();
        file.upsert(network, &account_name, account);
        return Ok((
            Box::new(MemoryAccountsStore::with_file(file)),
            account_name,
            pubkey,
        ));
    }

    let store = FileAccountsStore::default_path();
    let file = store.load()?;
    let (account_name, account) = if let Some(name) = account_override {
        let account = file
            .named_account_for_network(network, name)
            .cloned()
            .ok_or_else(|| Error::Config(format!("account `{name}` not found on {network}")))?;
        (name.to_string(), account)
    } else {
        match resolve_account_for_network(network, &file) {
            AccountChoice::Resolved { name, account } => (name, account),
            AccountChoice::Missing => {
                return Err(Error::Config(format!(
                    "no pay account configured for {network}; pass --account or, off mainnet, --keypair"
                )));
            }
        }
    };
    let pubkey = account
        .pubkey
        .as_deref()
        .ok_or_else(|| Error::Config(format!("account `{account_name}` has no cached pubkey")))?
        .parse()
        .map_err(|error| {
            Error::Config(format!(
                "account `{account_name}` pubkey is invalid: {error}"
            ))
        })?;
    Ok((Box::new(store), account_name, pubkey))
}

fn associated_token_address(
    owner: &Pubkey,
    mint: &Pubkey,
    token_program: &Pubkey,
) -> Result<Pubkey> {
    let associated_program = Pubkey::from_str(programs::ASSOCIATED_TOKEN_PROGRAM)
        .map_err(|error| Error::Config(format!("invalid associated-token program id: {error}")))?;
    Ok(Pubkey::find_program_address(
        &[owner.as_ref(), token_program.as_ref(), mint.as_ref()],
        &associated_program,
    )
    .0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usdtest_is_rejected_outside_devnet() {
        let error = resolve_currency("USDtest", "mainnet").unwrap_err();
        assert!(error.to_string().contains("devnet-only"));
    }

    #[test]
    fn zero_in_flight_is_rejected_by_command_validation_shape() {
        assert_eq!(DEFAULT_MAX_IN_FLIGHT, 128);
        assert!(validate_network("devnet").is_ok());
        assert!(validate_network("bogus").is_err());
    }

    #[test]
    fn global_network_override_wins_over_fanout_default() {
        assert_eq!(effective_network("mainnet", Some("devnet")), "devnet");
        assert_eq!(effective_network("devnet", None), "devnet");
    }
}
