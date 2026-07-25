//! On-chain registration phase shared by `pay serve` commands.
//!
//! PDA seeds provide deterministic identity, while category and protocol are
//! duplicated at stable account-data offsets for `getProgramAccounts` memcmp
//! discovery. PDA seed bytes themselves are hashed and cannot be filtered.

use std::str::FromStr;
use std::sync::Arc;

use pay_kit::mpp::solana_keychain::SolanaSigner;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

pub const DEFAULT_PROGRAM_ID: &str = "FJwLLb2G63XfXs43vQRYtXYXXM515d9UGt3paNLtm6j5";
pub const PROGRAM_ID_ENV: &str = "PAY_PROVIDER_PROGRAM_ID";
pub const RPC_URL_ENV: &str = "PAY_PROVIDER_RPC_URL";

const PROVIDER_SEED: &[u8] = b"provider";
const DISCRIMINATOR: &[u8; 8] = b"PAYPROV1";
const CATEGORY_MAX_LEN: usize = 16;
const PROTOCOL_MAX_LEN: usize = 16;
const NAME_MAX_LEN: usize = 32;
const DESCRIPTION_MAX_LEN: usize = 128;
const ENDPOINT_MAX_LEN: usize = 255;
const HEARTBEAT_INTERVAL_SECONDS: u64 = 24 * 60 * 60;
const PROVIDER_ACCOUNT_LEN: usize = 8
    + CATEGORY_MAX_LEN
    + PROTOCOL_MAX_LEN
    + 32
    + 8
    + 6
    + NAME_MAX_LEN
    + DESCRIPTION_MAX_LEN
    + ENDPOINT_MAX_LEN;
const RENT_SYSVAR: &str = "SysvarRent111111111111111111111111111111111";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRegistration {
    pub category: String,
    pub protocol: String,
    pub name: String,
    pub description: String,
    pub endpoint: String,
}

impl ServiceRegistration {
    pub fn new(
        category: impl Into<String>,
        protocol: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> pay_core::Result<Self> {
        let registration = Self {
            category: category.into(),
            protocol: protocol.into(),
            name: name.into(),
            description: description.into(),
            endpoint: endpoint.into(),
        };
        registration.validate()?;
        Ok(registration)
    }

    fn validate(&self) -> pay_core::Result<()> {
        validate_field("category", &self.category, CATEGORY_MAX_LEN, true)?;
        validate_field("protocol", &self.protocol, PROTOCOL_MAX_LEN, true)?;
        validate_field("name", &self.name, NAME_MAX_LEN, true)?;
        validate_field("description", &self.description, DESCRIPTION_MAX_LEN, false)?;
        validate_field("endpoint", &self.endpoint, ENDPOINT_MAX_LEN, true)?;
        if !(self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")) {
            return Err(pay_core::Error::Config(
                "provider registry endpoint must start with http:// or https://".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationOutcome {
    pub pda: Pubkey,
    pub signature: Option<String>,
}

/// Register a service if its authority/category/protocol PDA is absent.
/// Existing byte-identical entries are treated as success, making server boot
/// idempotent. A conflicting existing entry must be deregistered explicitly.
pub async fn register_service(
    registration: &ServiceRegistration,
    signer: Arc<dyn SolanaSigner>,
    rpc_url: &str,
) -> pay_core::Result<RegistrationOutcome> {
    let program_id = program_id()?;
    let authority = signer.pubkey();
    let (pda, instruction, expected_data) =
        build_register_instruction(registration, authority, program_id)?;
    let url = rpc_url.to_string();
    let existing_pda = pda;
    let (existing, rent_lamports) = tokio::task::spawn_blocking(move || {
        use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
        let rpc = RpcClient::new(url);
        let commitment = solana_commitment_config::CommitmentConfig::confirmed();
        let account = rpc
            .get_account_with_commitment(&existing_pda, commitment)
            .map_err(|error| {
                pay_core::Error::Mpp(format!(
                    "failed to query provider registry PDA {existing_pda}: {error}"
                ))
            })?
            .value
            .map(|account| (account.owner, account.data));
        let rent = rpc
            .get_minimum_balance_for_rent_exemption(PROVIDER_ACCOUNT_LEN)
            .map_err(|error| {
                pay_core::Error::Mpp(format!("failed to query provider registry rent: {error}"))
            })?;
        Ok::<_, pay_core::Error>((account, rent))
    })
    .await
    .map_err(|error| pay_core::Error::Mpp(format!("provider registry RPC task: {error}")))??;

    if let Some((owner, data)) = existing {
        if owner != program_id {
            return Err(pay_core::Error::Config(format!(
                "provider registry PDA {pda} is owned by {owner}, expected {program_id}"
            )));
        }
        if !provider_metadata_matches(&data, &expected_data) {
            return Err(pay_core::Error::Config(format!(
                "provider registry PDA {pda} already exists with different metadata; deregister it before changing the service"
            )));
        }
        eprintln!(
            "⏺ renewing {} / {} as {}\n  endpoint: {}\n  authority: {}\n  registry PDA: {}\n  RPC: {}",
            registration.category,
            registration.protocol,
            registration.name,
            registration.endpoint,
            authority,
            pda,
            rpc_url,
        );
        let instruction = build_renew_instruction(pda, authority, program_id);
        let signature = sign_simulate_and_broadcast(signer, instruction, rpc_url).await?;
        return Ok(RegistrationOutcome {
            pda,
            signature: Some(signature),
        });
    }

    eprintln!(
        "⏺ registering {} / {} as {}\n  endpoint: {}\n  authority: {}\n  registry PDA: {}\n  max rent: {} lamports\n  RPC: {}",
        registration.category,
        registration.protocol,
        registration.name,
        registration.endpoint,
        authority,
        pda,
        rent_lamports,
        rpc_url,
    );
    let signature = sign_simulate_and_broadcast(signer, instruction, rpc_url).await?;
    Ok(RegistrationOutcome {
        pda,
        signature: Some(signature),
    })
}

/// Submit one heartbeat per day. If heartbeats stop, the on-chain seven-day
/// grace period eventually makes the entry eligible for rewarded eviction.
pub fn spawn_renewal_task(
    registration: ServiceRegistration,
    signer: Arc<dyn SolanaSigner>,
    rpc_url: String,
) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(error) = register_service(&registration, signer.clone(), &rpc_url).await {
                tracing::warn!(%error, "failed to submit provider registry heartbeat");
            }
        }
    });
}

pub fn registry_rpc_url(sandbox: bool) -> String {
    std::env::var(RPC_URL_ENV)
        .ok()
        .or_else(|| std::env::var("PAY_RPC_URL").ok())
        .unwrap_or_else(|| {
            if sandbox {
                crate::network::SolanaNetwork::Localnet.default_rpc_url(true)
            } else {
                crate::network::SolanaNetwork::Mainnet.default_rpc_url(false)
            }
        })
}

pub fn registry_rpc_url_with_fallback(fallback: &str) -> String {
    std::env::var(RPC_URL_ENV).unwrap_or_else(|_| fallback.to_string())
}

pub fn profile_keys(profile: &pay_types::metering::ApiProfile) -> (String, String) {
    match profile {
        pay_types::metering::ApiProfile::OpenaiCompatible { version, .. } => {
            ("inference".to_string(), format!("openai-{version}"))
        }
        pay_types::metering::ApiProfile::XtreamCodes { version, .. } => {
            ("iptv".to_string(), format!("xtream-{version}"))
        }
    }
}

fn program_id() -> pay_core::Result<Pubkey> {
    let value = std::env::var(PROGRAM_ID_ENV).unwrap_or_else(|_| DEFAULT_PROGRAM_ID.to_string());
    Pubkey::from_str(&value).map_err(|error| {
        pay_core::Error::Config(format!("invalid {PROGRAM_ID_ENV} `{value}`: {error}"))
    })
}

fn build_register_instruction(
    registration: &ServiceRegistration,
    authority: Pubkey,
    program_id: Pubkey,
) -> pay_core::Result<(Pubkey, Instruction, Vec<u8>)> {
    registration.validate()?;
    let category = fixed_field::<CATEGORY_MAX_LEN>(&registration.category);
    let protocol = fixed_field::<PROTOCOL_MAX_LEN>(&registration.protocol);
    let name = fixed_field::<NAME_MAX_LEN>(&registration.name);
    let description = fixed_field::<DESCRIPTION_MAX_LEN>(&registration.description);
    let endpoint = fixed_field::<ENDPOINT_MAX_LEN>(&registration.endpoint);
    let (pda, bump) = Pubkey::find_program_address(
        &[PROVIDER_SEED, authority.as_ref(), &category, &protocol],
        &program_id,
    );

    let lengths = [
        registration.category.len() as u8,
        registration.protocol.len() as u8,
        registration.name.len() as u8,
        registration.description.len() as u8,
        registration.endpoint.len() as u8,
    ];
    let mut instruction_data = Vec::with_capacity(1 + 1 + lengths.len() + 447);
    instruction_data.push(0);
    instruction_data.push(bump);
    instruction_data.extend_from_slice(&lengths);
    instruction_data.extend_from_slice(&category);
    instruction_data.extend_from_slice(&protocol);
    instruction_data.extend_from_slice(&name);
    instruction_data.extend_from_slice(&description);
    instruction_data.extend_from_slice(&endpoint);

    let mut account_data = Vec::with_capacity(PROVIDER_ACCOUNT_LEN);
    account_data.extend_from_slice(DISCRIMINATOR);
    account_data.extend_from_slice(&category);
    account_data.extend_from_slice(&protocol);
    account_data.extend_from_slice(authority.as_ref());
    account_data.extend_from_slice(&0i64.to_le_bytes());
    account_data.push(bump);
    account_data.extend_from_slice(&lengths);
    account_data.extend_from_slice(&name);
    account_data.extend_from_slice(&description);
    account_data.extend_from_slice(&endpoint);
    debug_assert_eq!(account_data.len(), PROVIDER_ACCOUNT_LEN);

    let rent_sysvar = Pubkey::from_str(RENT_SYSVAR).expect("static rent sysvar address is valid");
    let instruction = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority, true),
            AccountMeta::new(pda, false),
            AccountMeta::new_readonly(rent_sysvar, false),
            AccountMeta::new_readonly(Pubkey::default(), false),
        ],
        data: instruction_data,
    };
    Ok((pda, instruction, account_data))
}

fn build_renew_instruction(pda: Pubkey, authority: Pubkey, program_id: Pubkey) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(authority, true),
            AccountMeta::new(pda, false),
        ],
        data: vec![1],
    }
}

fn provider_metadata_matches(actual: &[u8], expected: &[u8]) -> bool {
    const EVICT_AFTER_OFFSET: usize = 72;
    const EVICT_AFTER_END: usize = EVICT_AFTER_OFFSET + 8;
    actual.len() == PROVIDER_ACCOUNT_LEN
        && expected.len() == PROVIDER_ACCOUNT_LEN
        && actual[..EVICT_AFTER_OFFSET] == expected[..EVICT_AFTER_OFFSET]
        && actual[EVICT_AFTER_END..] == expected[EVICT_AFTER_END..]
}

fn fixed_field<const N: usize>(value: &str) -> [u8; N] {
    let mut field = [0; N];
    field[..value.len()].copy_from_slice(value.as_bytes());
    field
}

fn validate_field(name: &str, value: &str, max_len: usize, required: bool) -> pay_core::Result<()> {
    if required && value.is_empty() {
        return Err(pay_core::Error::Config(format!(
            "provider registry {name} cannot be empty"
        )));
    }
    if value.len() > max_len {
        return Err(pay_core::Error::Config(format!(
            "provider registry {name} is {} UTF-8 bytes; maximum is {max_len}",
            value.len()
        )));
    }
    Ok(())
}

async fn sign_simulate_and_broadcast(
    signer: Arc<dyn SolanaSigner>,
    instruction: Instruction,
    rpc_url: &str,
) -> pay_core::Result<String> {
    use pay_kit::mpp::solana_rpc_client::rpc_client::RpcClient;
    use solana_message::Message;
    use solana_signature::Signature;
    use solana_transaction::Transaction;

    let url = rpc_url.to_string();
    let signer_pubkey = signer.pubkey();
    let blockhash = tokio::task::spawn_blocking({
        let url = url.clone();
        move || {
            RpcClient::new(url).get_latest_blockhash().map_err(|error| {
                pay_core::Error::Mpp(format!(
                    "failed to fetch provider registration blockhash: {error}"
                ))
            })
        }
    })
    .await
    .map_err(|error| pay_core::Error::Mpp(format!("provider registry RPC task: {error}")))??;

    let message = Message::new_with_blockhash(&[instruction], Some(&signer_pubkey), &blockhash);
    let mut transaction = Transaction::new_unsigned(message);
    let signature = signer
        .sign_message(&transaction.message_data())
        .await
        .map_err(|error| {
            pay_core::Error::Mpp(format!("provider registration signing failed: {error}"))
        })?;
    let signer_index = transaction
        .message
        .account_keys
        .iter()
        .position(|key| *key == signer_pubkey)
        .ok_or_else(|| {
            pay_core::Error::Mpp("provider authority absent from transaction".to_string())
        })?;
    transaction.signatures[signer_index] = Signature::from(<[u8; 64]>::from(signature));
    let serialized = bincode::serialize(&transaction).map_err(|error| {
        pay_core::Error::Mpp(format!(
            "failed to serialize provider registration: {error}"
        ))
    })?;

    tokio::task::spawn_blocking(move || {
        let rpc = RpcClient::new(url);
        let transaction: Transaction = bincode::deserialize(&serialized).map_err(|error| {
            pay_core::Error::Mpp(format!(
                "provider registration transaction round-trip: {error}"
            ))
        })?;
        let simulation = rpc.simulate_transaction(&transaction).map_err(|error| {
            pay_core::Error::Mpp(format!("provider registration simulation failed: {error}"))
        })?;
        if let Some(error) = simulation.value.err {
            return Err(pay_core::Error::Mpp(format!(
                "provider registration simulation rejected: {error:?}"
            )));
        }
        rpc.send_and_confirm_transaction(&transaction)
            .map(|signature| signature.to_string())
            .map_err(|error| {
                pay_core::Error::Mpp(format!("provider registration broadcast failed: {error}"))
            })
    })
    .await
    .map_err(|error| pay_core::Error::Mpp(format!("provider registry RPC task: {error}")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_instruction_matches_program_layout_and_pda() {
        let registration = ServiceRegistration::new(
            "inference",
            "openai-v1",
            "local-ollama",
            "OpenAI-compatible local inference",
            "https://ai.example.com",
        )
        .unwrap();
        let authority = Pubkey::new_from_array([7; 32]);
        let program_id = Pubkey::from_str(DEFAULT_PROGRAM_ID).unwrap();
        let (pda, instruction, account_data) =
            build_register_instruction(&registration, authority, program_id).unwrap();

        let expected = Pubkey::find_program_address(
            &[
                PROVIDER_SEED,
                authority.as_ref(),
                &fixed_field::<CATEGORY_MAX_LEN>("inference"),
                &fixed_field::<PROTOCOL_MAX_LEN>("openai-v1"),
            ],
            &program_id,
        )
        .0;
        assert_eq!(pda, expected);
        assert_eq!(instruction.data[0], 0);
        assert_eq!(instruction.data.len(), 1 + 453);
        assert_eq!(account_data.len(), PROVIDER_ACCOUNT_LEN);
        assert_eq!(&account_data[..8], DISCRIMINATOR);
        assert_eq!(&account_data[8..17], b"inference");
        assert_eq!(&account_data[24..33], b"openai-v1");
        assert_eq!(&account_data[40..72], authority.as_ref());
        assert_eq!(&account_data[72..80], &0i64.to_le_bytes());
        assert!(provider_metadata_matches(&account_data, &account_data));
    }

    #[test]
    fn profile_keys_use_versioned_protocol_ids() {
        let openai = pay_types::metering::ApiProfile::OpenaiCompatible {
            version: "v1".to_string(),
            surfaces: Vec::new(),
        };
        let xtream = pay_types::metering::ApiProfile::XtreamCodes {
            version: "v1".to_string(),
            surfaces: Vec::new(),
        };
        assert_eq!(
            profile_keys(&openai),
            ("inference".into(), "openai-v1".into())
        );
        assert_eq!(profile_keys(&xtream), ("iptv".into(), "xtream-v1".into()));
    }

    #[test]
    fn field_limits_are_enforced_before_signing() {
        let error = ServiceRegistration::new(
            "inference-category-too-long",
            "openai-v1",
            "name",
            "description",
            "https://example.com",
        )
        .unwrap_err();
        assert!(error.to_string().contains("maximum is 16"));
    }
}
