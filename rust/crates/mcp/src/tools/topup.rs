use std::io::Write;

use base64::{Engine as _, engine::general_purpose};
use flate2::{Compression, write::ZlibEncoder};
use qrcode::{Color as QrColor, QrCode};
use rmcp::model::CallToolResult;
use rmcp::schemars;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const DEFAULT_AMOUNT_USDC: f64 = 5.0;
const DEFAULT_PIXELS_PER_MODULE: u32 = 8;
const QUIET_ZONE_MODULES: u32 = 4;

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TopupMethod {
    MobileWallet,
    Onramp,
}

impl TopupMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::MobileWallet => "mobile_wallet",
            Self::Onramp => "onramp",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OnrampProvider {
    Coinbase,
    Paypal,
    Venmo,
}

impl OnrampProvider {
    fn as_str(self) -> &'static str {
        match self {
            Self::Coinbase => "coinbase",
            Self::Paypal => "paypal",
            Self::Venmo => "venmo",
        }
    }

    fn url(self) -> &'static str {
        match self {
            Self::Coinbase => "https://www.coinbase.com/",
            Self::Paypal => "https://www.paypal.com/",
            Self::Venmo => "https://venmo.com/",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Params {
    /// Top-up flow to render. Use mobile_wallet for a Solana Pay USDC request, or onramp for a provider URL.
    pub method: TopupMethod,
    /// Required when method is onramp. Supported values: coinbase, paypal, venmo.
    #[serde(default)]
    pub onramp: Option<OnrampProvider>,
    /// Account name or Solana address to fund. Defaults to the active/default mainnet Pay account.
    #[serde(default)]
    pub account: Option<String>,
    /// USDC amount for mobile_wallet. Defaults to 5. Use 0 to omit the amount.
    #[serde(default)]
    pub amount_usdc: Option<f64>,
    /// QR PNG scale. Defaults to 8 pixels per QR module; valid range is 1..=32.
    #[serde(default)]
    pub pixels_per_module: Option<u32>,
}

#[derive(Debug, Serialize)]
struct TopupResponse {
    method: &'static str,
    provider: Option<&'static str>,
    account: String,
    funding_address: String,
    target_url: String,
    png_path: String,
    mime_type: &'static str,
    amount_usdc: Option<f64>,
    instructions: &'static str,
}

struct ResolvedAccount {
    label: String,
    address: String,
}

pub async fn run(params: Params) -> Result<CallToolResult, rmcp::ErrorData> {
    let account = match resolve_account(params.account.as_deref()) {
        Ok(account) => account,
        Err(message) => return Ok(super::tool_error(message)),
    };
    let pixels_per_module = params
        .pixels_per_module
        .unwrap_or(DEFAULT_PIXELS_PER_MODULE);
    if !(1..=32).contains(&pixels_per_module) {
        return Ok(super::tool_error(
            "`pixels_per_module` must be between 1 and 32",
        ));
    }

    let amount_usdc = match validate_amount(params.amount_usdc) {
        Ok(amount_usdc) => amount_usdc,
        Err(message) => return Ok(super::tool_error(message)),
    };
    let (provider, target_url, response_amount, instructions) = match params.method {
        TopupMethod::MobileWallet => (
            None,
            solana_pay_url(&account.address, amount_usdc),
            (amount_usdc > 0.0).then_some(amount_usdc),
            "Scan with a Solana mobile wallet and send USDC to this Pay account.",
        ),
        TopupMethod::Onramp => {
            let Some(provider) = params.onramp else {
                return Ok(super::tool_error(
                    "`onramp` is required when `method` is `onramp`",
                ));
            };
            (
                Some(provider),
                provider.url().to_string(),
                None,
                "Open the onramp provider, buy USDC or another supported stablecoin, then withdraw/send to the funding address.",
            )
        }
    };

    let png = match encode_qr_png(&target_url, pixels_per_module) {
        Ok(png) => png,
        Err(err) => return Ok(super::tool_error(format!("Failed to encode QR PNG: {err}"))),
    };
    let path = match write_qr_png(params.method, &account.address, &png) {
        Ok(path) => path,
        Err(err) => return Ok(super::tool_error(format!("Failed to write QR PNG: {err}"))),
    };

    let response = TopupResponse {
        method: params.method.as_str(),
        provider: provider.map(OnrampProvider::as_str),
        account: account.label,
        funding_address: account.address,
        target_url,
        png_path: path.to_string_lossy().to_string(),
        mime_type: "image/png",
        amount_usdc: response_amount,
        instructions,
    };
    let json = match serde_json::to_string_pretty(&response) {
        Ok(json) => json,
        Err(err) => {
            return Ok(super::tool_error(format!(
                "Failed to serialize response: {err}"
            )));
        }
    };
    let image = general_purpose::STANDARD.encode(&png);

    Ok(CallToolResult::success(vec![
        rmcp::model::ContentBlock::text(json),
        rmcp::model::ContentBlock::image(image, "image/png"),
    ]))
}

fn resolve_account(account: Option<&str>) -> Result<ResolvedAccount, String> {
    let accounts = pay_core::accounts::AccountsFile::load()
        .map_err(|e| format!("Failed to load Pay accounts: {e}"))?;
    let mainnet = pay_core::accounts::MAINNET_NETWORK;

    if let Some(account) = account.map(str::trim).filter(|account| !account.is_empty()) {
        if let Some(network_accounts) = accounts.accounts.get(mainnet)
            && let Some(named) = network_accounts.get(account)
        {
            let address = named.pubkey.clone().ok_or_else(|| {
                format!("Account `{account}` has no pubkey. Run `pay setup` again.")
            })?;
            return Ok(ResolvedAccount {
                label: account.to_string(),
                address,
            });
        }

        return Ok(ResolvedAccount {
            label: account.to_string(),
            address: account.to_string(),
        });
    }

    let (name, account) = accounts
        .account_for_network(mainnet)
        .ok_or_else(|| "No mainnet account found. Run `pay setup` first.".to_string())?;
    let address = account
        .pubkey
        .clone()
        .ok_or_else(|| format!("Account `{name}` has no pubkey. Run `pay setup` again."))?;

    Ok(ResolvedAccount {
        label: name.to_string(),
        address,
    })
}

fn validate_amount(amount: Option<f64>) -> Result<f64, String> {
    let amount = amount.unwrap_or(DEFAULT_AMOUNT_USDC);
    if !amount.is_finite() || amount < 0.0 {
        return Err("`amount_usdc` must be a finite non-negative number".to_string());
    }
    Ok(amount)
}

fn solana_pay_url(pubkey: &str, amount_usdc: f64) -> String {
    if amount_usdc > 0.0 {
        let amount = format_usdc_amount(amount_usdc);
        format!("solana:{pubkey}?amount={amount}&spl-token={USDC_MINT}")
    } else {
        format!("solana:{pubkey}?spl-token={USDC_MINT}")
    }
}

fn format_usdc_amount(amount: f64) -> String {
    let formatted = format!("{amount:.6}");
    formatted
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

fn write_qr_png(
    method: TopupMethod,
    account: &str,
    png: &[u8],
) -> Result<std::path::PathBuf, std::io::Error> {
    let prefix: String = account
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(12)
        .collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let path =
        std::env::temp_dir().join(format!("pay-topup-{}-{}-{ts}.png", method.as_str(), prefix));
    std::fs::write(&path, png)?;
    Ok(path)
}

fn encode_qr_png(data: &str, pixels_per_module: u32) -> Result<Vec<u8>, String> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
        .map_err(|e| e.to_string())?;
    let modules = code.width() as u32;
    let size = (modules + QUIET_ZONE_MODULES * 2) * pixels_per_module;
    let raw = qr_scanlines(&code, size, pixels_per_module);

    let mut zlib = ZlibEncoder::new(Vec::new(), Compression::default());
    zlib.write_all(&raw).map_err(|e| e.to_string())?;
    let compressed = zlib.finish().map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&size.to_be_bytes());
    ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // 8-bit grayscale, deflate, no filter, no interlace.
    write_png_chunk(&mut out, b"IHDR", &ihdr);
    write_png_chunk(&mut out, b"IDAT", &compressed);
    write_png_chunk(&mut out, b"IEND", &[]);

    Ok(out)
}

fn qr_scanlines(code: &QrCode, size: u32, pixels_per_module: u32) -> Vec<u8> {
    let modules = code.width() as i32;
    let quiet = QUIET_ZONE_MODULES as i32;
    let mut raw = Vec::with_capacity(((size + 1) * size) as usize);

    for y in 0..size {
        raw.push(0); // PNG filter type: none.
        let module_y = (y / pixels_per_module) as i32 - quiet;
        for x in 0..size {
            let module_x = (x / pixels_per_module) as i32 - quiet;
            let dark = module_x >= 0
                && module_x < modules
                && module_y >= 0
                && module_y < modules
                && code[(module_x as usize, module_y as usize)] != QrColor::Light;
            raw.push(if dark { 0 } else { 255 });
        }
    }

    raw
}

fn write_png_chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);

    let mut hasher = crc32fast::Hasher::new();
    hasher.update(kind);
    hasher.update(data);
    out.extend_from_slice(&hasher.finalize().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_wallet_url_matches_tui_topup_shape() {
        let url = solana_pay_url("11111111111111111111111111111111", 5.0);

        assert_eq!(
            url,
            "solana:11111111111111111111111111111111?amount=5&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        );
    }

    #[test]
    fn mobile_wallet_url_can_omit_amount() {
        let url = solana_pay_url("11111111111111111111111111111111", 0.0);

        assert_eq!(
            url,
            "solana:11111111111111111111111111111111?spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
        );
    }

    #[test]
    fn qr_png_has_png_signature_and_chunks() {
        let png = encode_qr_png("https://www.coinbase.com/", 4).expect("encode qr png");

        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(png.windows(4).any(|window| window == b"IHDR"));
        assert!(png.windows(4).any(|window| window == b"IDAT"));
        assert!(png.windows(4).any(|window| window == b"IEND"));
    }

    #[test]
    fn default_qr_png_stays_host_friendly_size() {
        let png = encode_qr_png(
            "solana:11111111111111111111111111111111?amount=5&spl-token=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            DEFAULT_PIXELS_PER_MODULE,
        )
        .expect("encode qr png");
        let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
        let height = u32::from_be_bytes(png[20..24].try_into().unwrap());

        assert_eq!(width, height);
        assert!(width <= 512, "default QR width {width}px is too large");
    }

    #[test]
    fn standard_image_content_shape_stays_host_compatible() {
        let content = rmcp::model::ContentBlock::image("abc123", "image/png");
        let value = serde_json::to_value(&content).expect("serialize content");

        assert_eq!(value["type"], "image");
        assert_eq!(value["data"], "abc123");
        assert_eq!(value["mimeType"], "image/png");
        assert!(value.get("_meta").is_none());
    }
}
