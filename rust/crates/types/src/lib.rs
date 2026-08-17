use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub mod metering;
pub mod registry;
pub mod splits;

/// Well-known mint addresses for supported Solana stablecoins.
///
/// Re-exported from pay-kit's shared core module (`pay_kit::core::mints`) so
/// there is a single source of truth for mint addresses across the client and
/// both protocol SDKs. Do not hard-code addresses here — add them upstream in
/// pay-kit's core module instead.
pub mod stablecoin_mints {
    pub use pay_kit::core::mints::{
        CASH_MAINNET, PYUSD_DEVNET, PYUSD_MAINNET, PYUSD_TESTNET, USDC_DEVNET, USDC_MAINNET,
        USDC_TESTNET, USDG_DEVNET, USDG_MAINNET, USDG_TESTNET, USDPT_MAINNET, USDT_MAINNET,
        USDTEST_DEVNET,
    };
}

/// Stablecoins supported by `pay send`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stablecoin {
    Usdc,
    Usdt,
    Pyusd,
    Cash,
    Usdg,
    /// USDPT (Anchorage) — Token-2022 confidential-capable stablecoin.
    Usdpt,
}

impl Stablecoin {
    pub const ALL: [Self; 6] = [
        Self::Usdc,
        Self::Usdt,
        Self::Pyusd,
        Self::Cash,
        Self::Usdg,
        Self::Usdpt,
    ];
    pub const SYMBOL_LIST: &'static str = "USDC, USDT, PYUSD, CASH, USDG, or USDPT";

    pub fn symbol(self) -> &'static str {
        match self {
            Self::Usdc => "USDC",
            Self::Usdt => "USDT",
            Self::Pyusd => "PYUSD",
            Self::Cash => "CASH",
            Self::Usdg => "USDG",
            Self::Usdpt => "USDPT",
        }
    }

    /// SPL mint decimals. All supported stablecoins are 6 today; keep
    /// per-variant for forward-compat when a non-6 stablecoin lands.
    pub fn decimals(self) -> u8 {
        match self {
            Self::Usdc | Self::Usdt | Self::Pyusd | Self::Cash | Self::Usdg | Self::Usdpt => 6,
        }
    }

    /// Look up the decimals for a mint by its base58 address. Returns
    /// `None` when the mint is not a recognised stablecoin — callers can
    /// fall back to 6 (the de-facto default) or render base units.
    pub fn decimals_for_mint(mint: &str) -> Option<u8> {
        Self::from_mint(mint).map(Self::decimals)
    }

    pub fn mint(self, network: Option<&str>) -> &'static str {
        match self {
            Self::Usdc => match network {
                Some("devnet") => stablecoin_mints::USDC_DEVNET,
                Some("testnet") => stablecoin_mints::USDC_TESTNET,
                _ => stablecoin_mints::USDC_MAINNET,
            },
            Self::Usdt => stablecoin_mints::USDT_MAINNET,
            Self::Pyusd => match network {
                Some("devnet") => stablecoin_mints::PYUSD_DEVNET,
                Some("testnet") => stablecoin_mints::PYUSD_TESTNET,
                _ => stablecoin_mints::PYUSD_MAINNET,
            },
            Self::Cash => stablecoin_mints::CASH_MAINNET,
            Self::Usdg => match network {
                Some("devnet") => stablecoin_mints::USDG_DEVNET,
                Some("testnet") => stablecoin_mints::USDG_TESTNET,
                _ => stablecoin_mints::USDG_MAINNET,
            },
            Self::Usdpt => stablecoin_mints::USDPT_MAINNET,
        }
    }

    pub fn symbol_for_mint(mint: &str) -> Option<&'static str> {
        Self::from_mint(mint).map(Self::symbol)
    }

    pub fn from_mint(mint: &str) -> Option<Self> {
        match mint {
            stablecoin_mints::USDC_MAINNET | stablecoin_mints::USDC_DEVNET => Some(Self::Usdc),
            stablecoin_mints::USDT_MAINNET => Some(Self::Usdt),
            stablecoin_mints::PYUSD_MAINNET | stablecoin_mints::PYUSD_DEVNET => Some(Self::Pyusd),
            stablecoin_mints::CASH_MAINNET => Some(Self::Cash),
            stablecoin_mints::USDG_MAINNET | stablecoin_mints::USDG_DEVNET => Some(Self::Usdg),
            stablecoin_mints::USDPT_MAINNET => Some(Self::Usdpt),
            _ => None,
        }
    }

    pub fn parse_symbol(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "USDC" => Some(Self::Usdc),
            "USDT" => Some(Self::Usdt),
            "PYUSD" => Some(Self::Pyusd),
            "CASH" => Some(Self::Cash),
            "USDG" => Some(Self::Usdg),
            "USDPT" => Some(Self::Usdpt),
            _ => None,
        }
    }
}

impl std::fmt::Display for Stablecoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.symbol())
    }
}

impl FromStr for Stablecoin {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_symbol(value).ok_or_else(|| {
            format!(
                "`pay send` sends stablecoins only; choose {}",
                Self::SYMBOL_LIST
            )
        })
    }
}

/// Represents an HTTP 402 payment challenge returned by a server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentChallenge {
    /// The URL that requires payment.
    pub resource_url: String,
    /// The payment endpoint to submit payment to.
    pub payment_url: String,
    /// Amount required in the smallest unit (e.g., satoshis, lamports).
    pub amount: u64,
    /// Currency or token identifier (e.g., "USD", "SOL", "BTC").
    pub currency: String,
    /// Human-readable description of what is being purchased.
    #[serde(default)]
    pub description: Option<String>,
}

/// The result of a successful payment, containing a receipt token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Opaque token proving payment was made.
    pub token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_challenge_serde_roundtrip() {
        let challenge = PaymentChallenge {
            resource_url: "https://api.example.com/data".to_string(),
            payment_url: "https://pay.example.com".to_string(),
            amount: 1000,
            currency: "USDC".to_string(),
            description: Some("API access".to_string()),
        };
        let json = serde_json::to_string(&challenge).unwrap();
        let back: PaymentChallenge = serde_json::from_str(&json).unwrap();
        assert_eq!(back.resource_url, challenge.resource_url);
        assert_eq!(back.payment_url, challenge.payment_url);
        assert_eq!(back.amount, challenge.amount);
        assert_eq!(back.currency, challenge.currency);
        assert_eq!(back.description, challenge.description);
    }

    #[test]
    fn payment_challenge_without_description() {
        let json = r#"{"resource_url":"https://a.com","payment_url":"https://b.com","amount":500,"currency":"SOL"}"#;
        let challenge: PaymentChallenge = serde_json::from_str(json).unwrap();
        assert_eq!(challenge.amount, 500);
        assert!(challenge.description.is_none());
    }

    #[test]
    fn payment_receipt_serde_roundtrip() {
        let receipt = PaymentReceipt {
            token: "receipt_token_123".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: PaymentReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token, receipt.token);
    }

    #[test]
    fn stablecoin_parses_supported_symbols() {
        assert_eq!("usdc".parse::<Stablecoin>().unwrap(), Stablecoin::Usdc);
        assert_eq!("USDG".parse::<Stablecoin>().unwrap(), Stablecoin::Usdg);
    }

    #[test]
    fn stablecoin_resolves_known_mints() {
        assert_eq!(
            Stablecoin::Usdg.mint(Some("mainnet")),
            stablecoin_mints::USDG_MAINNET
        );
        assert_eq!(
            Stablecoin::from_mint(stablecoin_mints::USDG_MAINNET),
            Some(Stablecoin::Usdg)
        );
        assert_eq!(
            Stablecoin::Usdg.mint(Some("devnet")),
            stablecoin_mints::USDG_DEVNET
        );
        assert_eq!(
            Stablecoin::from_mint(stablecoin_mints::USDG_DEVNET),
            Some(Stablecoin::Usdg)
        );
    }

    #[test]
    fn usdpt_round_trips_via_paykit_registry() {
        assert_eq!(Stablecoin::parse_symbol("usdpt"), Some(Stablecoin::Usdpt));
        assert_eq!(Stablecoin::Usdpt.symbol(), "USDPT");
        assert_eq!(Stablecoin::Usdpt.decimals(), 6);
        assert_eq!(
            Stablecoin::Usdpt.mint(Some("mainnet")),
            stablecoin_mints::USDPT_MAINNET
        );
        assert_eq!(
            Stablecoin::from_mint(stablecoin_mints::USDPT_MAINNET),
            Some(Stablecoin::Usdpt)
        );
        assert!(Stablecoin::ALL.contains(&Stablecoin::Usdpt));
    }
}
