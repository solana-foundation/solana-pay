//! `pay send` — send stablecoins to a recipient.

use std::str::FromStr;

use dialoguer::{Select, theme::ColorfulTheme};
use owo_colors::OwoColorize;
use pay_core::accounts::{
    AccountChoice, AccountsFile, FileAccountsStore, MAINNET_NETWORK,
    load_or_create_ephemeral_for_network, load_or_create_ephemeral_for_network_as,
    resolve_account_for_network,
};
use pay_core::balance::AccountBalances;
use pay_core::client::send::ResolvedCurrency;
use pay_core::send::{STABLECOIN_DECIMALS, format_token_amount, parse_token_amount};
use pay_types::Stablecoin;
use solana_pubkey::Pubkey;

use crate::{components, no_dna};

const DEFAULT_STABLECOIN: Stablecoin = Stablecoin::Usdc;

/// Send stablecoins to a recipient address.
///
/// Examples:
///   pay send 1 <address>                         Choose an eligible stablecoin
///   pay send 1 <address> --currency USDC         Send 1 USDC
///   pay send 5 <address> --currency USDT         Send 5 USDT
///   pay send max <address>                       Send an entire stablecoin balance
///   pay send 1 <address> --memo invoice-123      Attach memo metadata
///   pay send 1 <address> --memo-hex 48656c6c6f  Attach hex-encoded memo text
#[derive(clap::Args)]
pub struct SendCommand {
    /// Amount of stablecoin to send (e.g. "1.25"), or "max" to send the
    /// entire selected stablecoin balance.
    pub amount: String,

    /// Recipient public key (base-58) or account name.
    pub recipient: String,

    /// Stablecoin symbol. When omitted, pay selects an eligible balance or
    /// asks you to choose if more than one can pay.
    #[arg(long, value_name = "STABLECOIN")]
    pub currency: Option<String>,

    /// Optional memo metadata for the recipient split.
    #[arg(long, value_name = "MEMO")]
    pub memo: Option<String>,

    /// Hex-encoded UTF-8 memo metadata for the recipient split.
    #[arg(long, value_name = "HEX", conflicts_with = "memo")]
    pub memo_hex: Option<String>,

    /// Take the fee-payer refund out of AMOUNT instead of adding it on top.
    /// This is implied when AMOUNT is "max".
    #[arg(long)]
    pub fee_within: bool,

    /// Send as a confidential transfer (amount hidden on-chain). Requires a
    /// Token-2022 mint with the Confidential Transfer extension; the gateway
    /// issues a confidential challenge and the payment settles as a bundle.
    #[arg(long)]
    pub confidential: bool,
}

impl SendCommand {
    pub fn run(
        self,
        network_override: Option<&str>,
        account_override: Option<&str>,
        verbose: bool,
    ) -> pay_core::Result<()> {
        let amount = self.amount;
        let recipient_input = self.recipient;
        let config = pay_core::Config::load().unwrap_or_default();
        let network = network_override.unwrap_or(pay_core::accounts::MAINNET_NETWORK);
        let rpc_url = configured_rpc_url(&config);
        let fee_within = effective_fee_within(&amount, self.fee_within);
        let recipient = resolve_recipient_pubkey(&recipient_input, network)?;
        let memo = resolve_memo(self.memo.as_deref(), self.memo_hex.as_deref())?;

        let currency = resolve_send_currency(
            &amount,
            self.currency.as_deref(),
            network,
            account_override,
            rpc_url,
        )?;

        let amount_display = if sends_entire_balance(&amount) {
            format!("max {currency}")
        } else {
            format!("{amount} {currency}")
        };

        if verbose {
            eprintln!(
                "{}",
                format!("Sending {amount_display} to {recipient}...").dimmed()
            );
        }

        let result = pay_core::client::send::send_stablecoin(
            pay_core::client::send::StablecoinSendRequest {
                amount: &amount,
                recipient: &recipient,
                currency,
                network,
                account_override,
                memo: memo.as_deref(),
                fee_within,
                confidential: self.confidential,
                rpc_url,
            },
        )?;

        let title = send_success_title(&result);
        components::print_notice_with_machine_output(
            components::NoticeLevel::Success,
            &title,
            &send_success_body(&result),
            &result.signature,
        );

        Ok(())
    }
}

fn send_success_title(result: &pay_core::client::send::SendResult) -> String {
    let amount_sent = format_token_amount(result.amount_raw, result.decimals);
    let title = format!("Sent {amount_sent} {} to {}", result.currency, result.to);
    if result.total_amount_raw != result.amount_raw {
        let total = format_token_amount(result.total_amount_raw, result.decimals);
        let fee = if result.fee_refund_raw > 0 {
            result.fee_refund_raw
        } else {
            result.total_amount_raw.saturating_sub(result.amount_raw)
        };
        let fee = format_token_amount(fee, result.decimals);
        return format!(
            "{title} (total paid: {total} {}, fee: {fee} {})",
            result.currency, result.currency
        );
    }
    title
}

fn send_success_body(result: &pay_core::client::send::SendResult) -> String {
    format!(
        "{} {}",
        crate::components::solana_transaction_link(&result.signature, &result.network),
        result.signature
    )
}

fn effective_fee_within(amount: &str, fee_within: bool) -> bool {
    fee_within || sends_entire_balance(amount)
}

fn resolve_memo(memo: Option<&str>, memo_hex: Option<&str>) -> pay_core::Result<Option<String>> {
    match (memo, memo_hex) {
        (Some(_), Some(_)) => Err(pay_core::Error::Config(
            "Pass either --memo or --memo-hex, not both".to_string(),
        )),
        (Some(value), None) => normalize_memo_text(value),
        (None, Some(value)) => decode_memo_hex(value),
        (None, None) => Ok(None),
    }
}

fn normalize_memo_text(value: &str) -> pay_core::Result<Option<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    validate_memo_len(value)?;
    Ok(Some(value.to_string()))
}

fn decode_memo_hex(value: &str) -> pay_core::Result<Option<String>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if !hex.len().is_multiple_of(2) {
        return Err(pay_core::Error::Config(
            "Memo hex must contain an even number of digits".to_string(),
        ));
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let mut chars = hex.as_bytes().chunks_exact(2);
    for pair in &mut chars {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }

    let memo = String::from_utf8(bytes)
        .map_err(|_| pay_core::Error::Config("Memo hex must decode to UTF-8 text".to_string()))?;
    normalize_memo_text(&memo)
}

fn hex_digit(byte: u8) -> pay_core::Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(pay_core::Error::Config(
            "Memo hex must contain only hexadecimal digits".to_string(),
        )),
    }
}

fn validate_memo_len(value: &str) -> pay_core::Result<()> {
    if value.len() > 566 {
        return Err(pay_core::Error::Config(
            "Memo cannot exceed 566 bytes".to_string(),
        ));
    }
    Ok(())
}

fn sends_entire_balance(amount: &str) -> bool {
    amount == "*" || amount.eq_ignore_ascii_case("max")
}

fn configured_rpc_url(config: &pay_core::Config) -> Option<&str> {
    config
        .rpc_url
        .as_deref()
        .filter(|url| !url.trim().is_empty())
}

fn resolve_recipient_pubkey(recipient: &str, network: &str) -> pay_core::Result<String> {
    if Pubkey::from_str(recipient).is_ok() {
        return Ok(recipient.to_string());
    }

    let file = AccountsFile::load()?;
    resolve_recipient_pubkey_from_file(recipient, network, &file)
}

fn resolve_recipient_pubkey_from_file(
    recipient: &str,
    network: &str,
    file: &AccountsFile,
) -> pay_core::Result<String> {
    if Pubkey::from_str(recipient).is_ok() {
        return Ok(recipient.to_string());
    }

    if let Some(account) = file.named_account_for_network(network, recipient) {
        return account.pubkey.clone().ok_or_else(|| {
            pay_core::Error::Config(format!(
                "Account `{recipient}` exists on {network} but has no pubkey"
            ))
        });
    }

    Err(pay_core::Error::Config(format!(
        "Recipient `{recipient}` is neither a valid Solana pubkey nor a configured {network} account name"
    )))
}

fn resolve_send_currency(
    amount: &str,
    requested_currency: Option<&str>,
    network: &str,
    account_override: Option<&str>,
    rpc_url_override: Option<&str>,
) -> pay_core::Result<ResolvedCurrency> {
    let sender = sender_pubkey_for_network(network, account_override)?;

    if let Some(requested) = requested_currency {
        let requested = requested.trim();
        if requested.is_empty() {
            return Err(pay_core::Error::Config(
                "Currency must not be empty".to_string(),
            ));
        }
        // Prefer the remote supported set: resolve the symbol against the
        // sender's stablecoin balances (the mint comes straight from pay-api).
        if let Some(sender) = &sender {
            let rpc_url = balance_rpc_url(network, rpc_url_override);
            if let Ok(balances) = balances_for_sender(network, &rpc_url, sender)
                && !balances.tokens_unavailable
                && let Some(token) = balances.tokens.iter().find(|t| t.is_symbol(requested))
                && let Some(symbol) = token.symbol.clone()
            {
                return Ok(ResolvedCurrency {
                    symbol,
                    mint: token.mint.clone(),
                });
            }
        }
        // Offline / not held / unknown to the API for this wallet: fall back to
        // the local enum registry.
        return normalize_requested_currency(requested, network);
    }

    let Some(sender) = sender else {
        if sends_entire_balance(amount) {
            return Err(pay_core::Error::Config(format!(
                "Cannot choose a stablecoin for `pay send max` without a configured {network} account"
            )));
        }
        return Ok(ResolvedCurrency::from_stablecoin(
            DEFAULT_STABLECOIN,
            network,
        ));
    };

    let rpc_url = balance_rpc_url(network, rpc_url_override);
    let balances = balances_for_sender(network, &rpc_url, &sender)?;
    if balances.tokens_unavailable {
        if sends_entire_balance(amount) {
            return Err(pay_core::Error::Config(
                "Stablecoin balances are unavailable; pass --currency STABLECOIN once balances are reachable"
                    .to_string(),
            ));
        }
        return Ok(ResolvedCurrency::from_stablecoin(
            DEFAULT_STABLECOIN,
            network,
        ));
    }

    let eligible = eligible_stablecoins(&balances, amount)?;
    match eligible.as_slice() {
        [] => Err(pay_core::Error::Config(no_eligible_stablecoin_message(
            amount, &balances,
        ))),
        [only] => Ok(only.currency.clone()),
        many => {
            if !can_prompt() {
                return Err(pay_core::Error::Config(
                    multiple_eligible_stablecoins_message(amount, many),
                ));
            }
            prompt_for_stablecoin(many)
        }
    }
}

fn sender_pubkey_for_network(
    network: &str,
    account_override: Option<&str>,
) -> pay_core::Result<Option<String>> {
    let file = AccountsFile::load()?;
    if let Some(name) = account_override {
        if let Some(pubkey) = file
            .named_account_for_network(network, name)
            .and_then(|account| account.pubkey.clone())
        {
            return Ok(Some(pubkey));
        }

        if network != MAINNET_NETWORK {
            let store = FileAccountsStore::default_path();
            let resolved = load_or_create_ephemeral_for_network_as(network, name, &store)?;
            return Ok(resolved.account.pubkey);
        }

        return Ok(None);
    }

    match resolve_account_for_network(network, &file) {
        AccountChoice::Resolved { account, .. } => Ok(account.pubkey),
        AccountChoice::Missing => {
            if network != MAINNET_NETWORK {
                let store = FileAccountsStore::default_path();
                let resolved = load_or_create_ephemeral_for_network(network, &store)?;
                return Ok(resolved.account.pubkey);
            }
            Ok(None)
        }
    }
}

fn balance_rpc_url(network: &str, rpc_url_override: Option<&str>) -> String {
    rpc_url_override
        .map(str::to_string)
        .or_else(|| std::env::var("PAY_RPC_URL").ok())
        .unwrap_or_else(|| {
            if network == MAINNET_NETWORK {
                pay_core::balance::mainnet_rpc_url()
            } else {
                pay_core::config::SANDBOX_RPC_URL.to_string()
            }
        })
}

fn balances_for_sender(
    network: &str,
    rpc_url: &str,
    sender: &str,
) -> pay_core::Result<AccountBalances> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| pay_core::Error::Config(format!("Failed to create runtime: {e}")))?;

    if network != MAINNET_NETWORK {
        let _ = rt.block_on(pay_core::sandbox::fund_via_surfpool(rpc_url, sender));
    }

    rt.block_on(pay_core::balance::get_stablecoin_balances(rpc_url, sender))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EligibleStablecoin {
    currency: ResolvedCurrency,
    balance: String,
}

fn eligible_stablecoins(
    balances: &AccountBalances,
    amount: &str,
) -> pay_core::Result<Vec<EligibleStablecoin>> {
    let required_balance_raw = if sends_entire_balance(amount) {
        // One raw unit is 0.000001 for 6-decimal stablecoins. For `max`,
        // this only excludes empty token accounts from the picker.
        1
    } else {
        let raw = parse_token_amount(amount, STABLECOIN_DECIMALS)?;
        if raw == 0 {
            return Err(pay_core::Error::Config(
                "Amount must be greater than 0".to_string(),
            ));
        }
        raw
    };

    let mut eligible = balances
        .tokens
        .iter()
        .filter(|token| token.raw_amount >= required_balance_raw)
        .filter_map(|token| {
            let symbol = token.symbol.clone()?;
            Some(EligibleStablecoin {
                currency: ResolvedCurrency {
                    symbol,
                    mint: token.mint.clone(),
                },
                balance: format_token_amount(token.raw_amount, STABLECOIN_DECIMALS),
            })
        })
        .collect::<Vec<_>>();
    eligible.sort_by(|left, right| left.currency.symbol.cmp(&right.currency.symbol));
    Ok(eligible)
}

fn normalize_requested_currency(
    currency: &str,
    network: &str,
) -> pay_core::Result<ResolvedCurrency> {
    if currency.trim().is_empty() {
        return Err(pay_core::Error::Config(
            "Currency must not be empty".to_string(),
        ));
    }
    Stablecoin::from_str(currency)
        .map(|stablecoin| ResolvedCurrency::from_stablecoin(stablecoin, network))
        .map_err(pay_core::Error::Config)
}

fn can_prompt() -> bool {
    !no_dna::is_agent() && std::io::IsTerminal::is_terminal(&std::io::stderr())
}

fn prompt_for_stablecoin(eligible: &[EligibleStablecoin]) -> pay_core::Result<ResolvedCurrency> {
    let labels = eligible
        .iter()
        .map(|token| format!("{}  {} available", token.currency, token.balance))
        .collect::<Vec<_>>();
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Choose stablecoin")
        .items(&labels)
        .default(0)
        .interact()
        .map_err(|e| pay_core::Error::Config(format!("Prompt error: {e}")))?;
    Ok(eligible[selection].currency.clone())
}

fn eligible_summary(eligible: &[EligibleStablecoin]) -> String {
    eligible
        .iter()
        .map(|token| format!("{} {}", token.currency, token.balance))
        .collect::<Vec<_>>()
        .join(", ")
}

fn multiple_eligible_stablecoins_message(amount: &str, eligible: &[EligibleStablecoin]) -> String {
    format!(
        "Multiple stablecoin balances can cover {amount}.\n\
         Pass --currency STABLECOIN.\n\n\
         Eligible balances: {}",
        eligible_summary(eligible)
    )
}

fn no_eligible_stablecoin_message(amount: &str, balances: &AccountBalances) -> String {
    let balances = stablecoin_balance_summary(balances);
    if sends_entire_balance(amount) {
        return if balances.is_empty() {
            "No stablecoin balances available to send".to_string()
        } else {
            format!("No non-zero stablecoin balance available to send. Balances: {balances}")
        };
    }

    if balances.is_empty() {
        format!("No stablecoin balance can cover {amount}")
    } else {
        format!("No stablecoin balance can cover {amount}. Balances: {balances}")
    }
}

fn stablecoin_balance_summary(balances: &AccountBalances) -> String {
    balances
        .tokens
        .iter()
        .filter_map(|token| {
            let currency = token.currency()?;
            Some(format!(
                "{} {}",
                currency,
                format_token_amount(token.raw_amount, STABLECOIN_DECIMALS)
            ))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pay_core::accounts::{Account, Keystore};
    use pay_core::balance::TokenBalance;

    const VALID_PUBKEY: &str = "11111111111111111111111111111111";
    const NAMED_PUBKEY: &str = "4BuiY9QUUfPoAGNJBja3JapAuVWMc9c7in6UCgyC2zPR";

    fn test_account(pubkey: Option<&str>) -> Account {
        Account {
            keystore: Keystore::AppleKeychain,
            provider: None,
            active: false,
            auth_required: Some(false),
            pubkey: pubkey.map(str::to_string),
            vault: None,
            account: None,
            path: None,
            secret_key_b58: None,
            created_at: None,
            subscriptions: std::collections::BTreeMap::new(),
        }
    }

    fn balances(tokens: Vec<(&'static str, u64)>) -> AccountBalances {
        AccountBalances {
            sol_lamports: 0,
            tokens: tokens
                .into_iter()
                .map(|(symbol, raw_amount)| TokenBalance {
                    mint: format!("{symbol}_mint"),
                    raw_amount,
                    ui_amount: raw_amount as f64 / 1_000_000.0,
                    symbol: Some(symbol.to_string()),
                })
                .collect(),
            tokens_unavailable: false,
        }
    }

    #[test]
    fn resolve_recipient_pubkey_accepts_literal_pubkey_first() {
        let mut file = AccountsFile::default();
        file.upsert("mainnet", VALID_PUBKEY, test_account(Some(NAMED_PUBKEY)));

        let resolved = resolve_recipient_pubkey_from_file(VALID_PUBKEY, "mainnet", &file).unwrap();

        assert_eq!(resolved, VALID_PUBKEY);
    }

    #[test]
    fn resolve_recipient_pubkey_falls_back_to_account_name() {
        let mut file = AccountsFile::default();
        file.upsert("mainnet", "alice", test_account(Some(NAMED_PUBKEY)));

        let resolved = resolve_recipient_pubkey_from_file("alice", "mainnet", &file).unwrap();

        assert_eq!(resolved, NAMED_PUBKEY);
    }

    #[test]
    fn resolve_recipient_pubkey_errors_for_unknown_name() {
        let file = AccountsFile::default();

        let err = resolve_recipient_pubkey_from_file("alice", "mainnet", &file).unwrap_err();

        assert!(
            err.to_string().contains(
                "Recipient `alice` is neither a valid Solana pubkey nor a configured mainnet account name"
            )
        );
    }

    #[test]
    fn resolve_recipient_pubkey_errors_when_account_has_no_pubkey() {
        let mut file = AccountsFile::default();
        file.upsert("mainnet", "alice", test_account(None));

        let err = resolve_recipient_pubkey_from_file("alice", "mainnet", &file).unwrap_err();

        assert!(
            err.to_string()
                .contains("Account `alice` exists on mainnet but has no pubkey")
        );
    }

    #[test]
    fn eligible_stablecoins_filters_by_amount() {
        let b = balances(vec![
            ("USDC", 900_000),
            ("USDT", 1_000_000),
            ("PYUSD", 2_500_000),
        ]);

        let eligible = eligible_stablecoins(&b, "1").unwrap();

        assert_eq!(
            eligible,
            vec![
                EligibleStablecoin {
                    currency: ResolvedCurrency {
                        symbol: "PYUSD".to_string(),
                        mint: "PYUSD_mint".to_string(),
                    },
                    balance: "2.5".to_string(),
                },
                EligibleStablecoin {
                    currency: ResolvedCurrency {
                        symbol: "USDT".to_string(),
                        mint: "USDT_mint".to_string(),
                    },
                    balance: "1".to_string(),
                },
            ]
        );
    }

    #[test]
    fn eligible_stablecoins_accepts_fractional_amount() {
        let b = balances(vec![("USDC", 499_999), ("USDT", 500_000)]);

        let eligible = eligible_stablecoins(&b, "0.5").unwrap();

        assert_eq!(
            eligible,
            vec![EligibleStablecoin {
                currency: ResolvedCurrency {
                    symbol: "USDT".to_string(),
                    mint: "USDT_mint".to_string(),
                },
                balance: "0.5".to_string(),
            }]
        );
    }

    #[test]
    fn multiple_eligible_message_is_notice_friendly() {
        let b = balances(vec![("USDC", 1_000_000), ("USDT", 2_000_000)]);
        let eligible = eligible_stablecoins(&b, "1").unwrap();

        assert_eq!(
            multiple_eligible_stablecoins_message("1", &eligible),
            "Multiple stablecoin balances can cover 1.\n\
             Pass --currency STABLECOIN.\n\n\
             Eligible balances: USDC 1, USDT 2"
        );
    }

    #[test]
    fn eligible_stablecoins_max_uses_non_zero_balances() {
        let b = balances(vec![("USDC", 0), ("USDT", 1)]);

        let eligible = eligible_stablecoins(&b, "max").unwrap();

        assert_eq!(
            eligible,
            vec![EligibleStablecoin {
                currency: ResolvedCurrency {
                    symbol: "USDT".to_string(),
                    mint: "USDT_mint".to_string(),
                },
                balance: "0.000001".to_string(),
            }]
        );
    }

    #[test]
    fn no_eligible_message_lists_balances() {
        let b = balances(vec![("USDC", 500_000), ("USDT", 250_000)]);

        let message = no_eligible_stablecoin_message("1", &b);

        assert_eq!(
            message,
            "No stablecoin balance can cover 1. Balances: USDC 0.5, USDT 0.25"
        );
    }

    #[test]
    fn effective_fee_within_defaults_max_to_true() {
        assert!(effective_fee_within("max", false));
        assert!(effective_fee_within("MAX", false));
        assert!(effective_fee_within("*", false));
        assert!(effective_fee_within("1", true));
        assert!(!effective_fee_within("1", false));
    }

    #[test]
    fn resolve_memo_accepts_text() {
        assert_eq!(
            resolve_memo(Some("Hello world"), None).unwrap(),
            Some("Hello world".to_string())
        );
    }

    #[test]
    fn resolve_memo_decodes_hex_text() {
        assert_eq!(
            resolve_memo(None, Some("48656c6c6f20776f726c64")).unwrap(),
            Some("Hello world".to_string())
        );
        assert_eq!(
            resolve_memo(None, Some("0x48656c6c6f")).unwrap(),
            Some("Hello".to_string())
        );
    }

    #[test]
    fn resolve_memo_rejects_both_forms() {
        let err = resolve_memo(Some("hello"), Some("68656c6c6f")).unwrap_err();

        assert!(err.to_string().contains("Pass either --memo or --memo-hex"));
    }

    #[test]
    fn resolve_memo_rejects_invalid_hex() {
        let odd = resolve_memo(None, Some("abc")).unwrap_err();
        assert!(
            odd.to_string()
                .contains("Memo hex must contain an even number of digits")
        );

        let invalid = resolve_memo(None, Some("zz")).unwrap_err();
        assert!(
            invalid
                .to_string()
                .contains("Memo hex must contain only hexadecimal digits")
        );
    }

    #[test]
    fn resolve_memo_rejects_non_utf8_hex() {
        let err = resolve_memo(None, Some("ff")).unwrap_err();

        assert!(err.to_string().contains("Memo hex must decode to UTF-8"));
    }

    #[test]
    fn resolve_memo_treats_empty_values_as_absent() {
        assert_eq!(resolve_memo(Some(""), None).unwrap(), None);
        assert_eq!(resolve_memo(None, Some("")).unwrap(), None);
    }

    #[test]
    fn send_success_title_includes_total_paid_when_fee_is_added() {
        let result = pay_core::client::send::SendResult {
            signature: "sig123".to_string(),
            amount_raw: 1_000_000,
            total_amount_raw: 1_001_500,
            fee_refund_raw: 1_500,
            decimals: 6,
            currency: "USDC".to_string(),
            mint: "mint".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            network: "mainnet".to_string(),
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
        };

        assert_eq!(
            send_success_title(&result),
            "Sent 1 USDC to to (total paid: 1.0015 USDC, fee: 0.0015 USDC)"
        );
    }

    #[test]
    fn send_success_title_omits_total_when_no_fee_is_added() {
        let result = pay_core::client::send::SendResult {
            signature: "sig123".to_string(),
            amount_raw: 1_000_000,
            total_amount_raw: 1_000_000,
            fee_refund_raw: 0,
            decimals: 6,
            currency: "USDC".to_string(),
            mint: "mint".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            network: "mainnet".to_string(),
            rpc_url: "https://api.mainnet-beta.solana.com".to_string(),
        };

        assert_eq!(send_success_title(&result), "Sent 1 USDC to to");
    }

    #[test]
    fn send_success_body_links_transaction() {
        let result = pay_core::client::send::SendResult {
            signature: "sig123".to_string(),
            amount_raw: 1_000_000,
            total_amount_raw: 1_000_000,
            fee_refund_raw: 0,
            decimals: 6,
            currency: "USDC".to_string(),
            mint: "mint".to_string(),
            from: "from".to_string(),
            to: "to".to_string(),
            network: "localnet".to_string(),
            rpc_url: "http://localhost:8899".to_string(),
        };
        let body = send_success_body(&result);

        assert!(body.contains("Link to receipt"));
        assert!(body.contains("sig123"));
        // `solana_transaction_link` now routes receipts through pay.sh
        // (see `components::link::solana_transaction_link`); localnet
        // maps to the `?network=sandbox` query.
        assert!(body.contains("https://pay.sh/receipt/sig123?network=sandbox"));
    }
}
