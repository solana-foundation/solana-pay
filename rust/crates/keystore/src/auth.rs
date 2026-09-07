//! Authentication gates — biometric or password prompts before secret access.

use crate::Result;

pub(crate) const DEFAULT_AUTH_REASON: &str = "authorize pay to use your payment account";

/// Why the keystore is asking the user to authenticate.
///
/// Platforms render this differently: Windows Hello and Touch ID display the
/// full message, while Linux Polkit maps the variant to a static action
/// message installed in the policy file. Payment limits are only used by the
/// Linux Polkit mapper; other platforms keep showing the exact amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthIntent {
    AuthorizePayment {
        message: String,
        limit: Option<PaymentLimit>,
    },
    CreateAccount(String),
    ImportAccount(String),
    ExportAccount(String),
    DeleteAccount(String),
    OpenSession(String),
    UseGatewayFeePayer(String),
    UseAccount(String),
    /// One-approval authorization for a `pay push` CSV batch. Shown once
    /// after read-only preflight, naming the exact recipient count, token
    /// total, and worst-case ceiling (including gasless reimbursement) the
    /// resulting signing permit may sign — never a generic "N payments"
    /// allowance. See `pay_core::client::push::permit`.
    AuthorizeBatch {
        message: String,
        limit: Option<PaymentLimit>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentLimit {
    Usd00001,
    Usd0001,
    Usd0005,
    Usd001,
    Usd005,
    Usd01,
    Usd05,
    Usd1,
    Usd2,
    Usd5,
    Usd10,
    Usd15,
    Usd20,
    Usd25,
    Usd50,
    AboveUsd50,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PaymentAmountKind {
    Exact,
    Maximum,
    Escrow,
}

impl PaymentAmountKind {
    const fn headline(self) -> &'static str {
        match self {
            Self::Exact => "authorize a payment.",
            Self::Maximum => "authorize a series of payments.",
            Self::Escrow => "authorize a channel escrow deposit.",
        }
    }

    const fn field_label(self) -> &'static str {
        match self {
            Self::Exact => "amount",
            Self::Maximum => "total allowance",
            Self::Escrow => "escrow deposit",
        }
    }
}

impl PaymentLimit {
    const BUCKETS: &[(u64, Self)] = &[
        (1, Self::Usd00001),
        (10, Self::Usd0001),
        (50, Self::Usd0005),
        (100, Self::Usd001),
        (500, Self::Usd005),
        (1_000, Self::Usd01),
        (5_000, Self::Usd05),
        (10_000, Self::Usd1),
        (20_000, Self::Usd2),
        (50_000, Self::Usd5),
        (100_000, Self::Usd10),
        (150_000, Self::Usd15),
        (200_000, Self::Usd20),
        (250_000, Self::Usd25),
        (500_000, Self::Usd50),
    ];

    pub fn from_amount(amount: &str) -> Option<Self> {
        parse_usd_minor_units(amount).map(Self::from_minor_units)
    }

    fn from_minor_units(units: u64) -> Self {
        Self::BUCKETS
            .iter()
            .find_map(|(ceiling, limit)| (units <= *ceiling).then_some(*limit))
            .unwrap_or(Self::AboveUsd50)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Usd00001 => "$0.0001",
            Self::Usd0001 => "$0.001",
            Self::Usd0005 => "$0.005",
            Self::Usd001 => "$0.01",
            Self::Usd005 => "$0.05",
            Self::Usd01 => "$0.10",
            Self::Usd05 => "$0.50",
            Self::Usd1 => "$1",
            Self::Usd2 => "$2",
            Self::Usd5 => "$5",
            Self::Usd10 => "$10",
            Self::Usd15 => "$15",
            Self::Usd20 => "$20",
            Self::Usd25 => "$25",
            Self::Usd50 => "$50",
            Self::AboveUsd50 => "more than $50",
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::Usd00001 => "00001",
            Self::Usd0001 => "0001",
            Self::Usd0005 => "0005",
            Self::Usd001 => "001",
            Self::Usd005 => "005",
            Self::Usd01 => "01",
            Self::Usd05 => "05",
            Self::Usd1 => "1",
            Self::Usd2 => "2",
            Self::Usd5 => "5",
            Self::Usd10 => "10",
            Self::Usd15 => "15",
            Self::Usd20 => "20",
            Self::Usd25 => "25",
            Self::Usd50 => "50",
            Self::AboveUsd50 => "above-50",
        }
    }
}

impl AuthIntent {
    pub fn authorize_payment(amount: &str, description: &str) -> Self {
        Self::AuthorizePayment {
            message: format!("authorize payment of {amount} for {description}"),
            limit: PaymentLimit::from_amount(amount),
        }
    }

    pub fn authorize_payment_details(amount: &str, reason: &str, operator: &str) -> Self {
        Self::AuthorizePayment {
            message: payment_authorization_message(
                PaymentAmountKind::Exact,
                amount,
                Some(reason),
                operator,
            ),
            limit: PaymentLimit::from_amount(amount),
        }
    }

    /// Authorize a payment-channel escrow deposit.
    ///
    /// `amount` is the canonical monetary value of the deposit (e.g. `$25.00`),
    /// used both to derive the amount-specific spend limit and to display the
    /// deposit being signed. It must stay a bare amount — the "escrow" framing
    /// comes from the headline, not from a prefix on `amount`, so that
    /// [`PaymentLimit::from_amount`] can still parse it and select an
    /// amount-specific authorization action instead of the generic fallback.
    pub fn authorize_channel_escrow(amount: &str, reason: &str, operator: &str) -> Self {
        Self::AuthorizePayment {
            message: payment_authorization_message(
                PaymentAmountKind::Escrow,
                amount,
                Some(reason),
                operator,
            ),
            limit: PaymentLimit::from_amount(amount),
        }
    }

    pub fn with_account_context(&self, account: &str) -> Self {
        let account = prompt_detail(account);
        match self {
            Self::AuthorizePayment { message, limit } => Self::AuthorizePayment {
                message: payment_message_with_account(message, &account),
                limit: *limit,
            },
            other => other.clone(),
        }
    }

    pub fn default_payment() -> Self {
        Self::AuthorizePayment {
            message: "authorize a payment with pay".to_string(),
            limit: None,
        }
    }

    pub fn send_sol(recipient: &str) -> Self {
        Self::AuthorizePayment {
            message: format!("authorize sending SOL to {recipient}"),
            limit: None,
        }
    }

    pub fn create_account(account: &str) -> Self {
        Self::CreateAccount(format!("set up the \"{account}\" payment account"))
    }

    pub fn import_account(account: &str) -> Self {
        Self::ImportAccount(format!("import the \"{account}\" payment account"))
    }

    pub fn export_account(account: &str) -> Self {
        Self::ExportAccount(format!("export the \"{account}\" payment account"))
    }

    pub fn delete_account(account: &str) -> Self {
        Self::DeleteAccount(format!("delete the \"{account}\" payment account"))
    }

    pub fn open_session() -> Self {
        Self::OpenSession("authorize opening a pay session".to_string())
    }

    pub fn authorize_spend_up_to(amount: Option<&str>, limit: &str, operator: &str) -> Self {
        Self::AuthorizePayment {
            message: payment_authorization_message(
                PaymentAmountKind::Maximum,
                limit,
                None,
                operator,
            ),
            limit: amount.and_then(PaymentLimit::from_amount),
        }
    }

    pub fn use_gateway_fee_payer() -> Self {
        Self::UseGatewayFeePayer("use your pay account as the gateway fee payer".to_string())
    }

    /// Build the one-approval `pay push` batch authorization prompt.
    ///
    /// `recipient_total_display` and `max_total_display` are pre-formatted
    /// decimal amounts (e.g. `"1234.56 USDG"`); `max_total_usd` is the same
    /// maximum expressed as a `"$..."` string used only to pick the Linux
    /// Polkit action bucket (stablecoins are USD-pegged 1:1, so the raw
    /// batch ceiling doubles as its own USD estimate).
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_batch(
        account: &str,
        recipient_count: usize,
        recipient_total_display: &str,
        max_total_display: &str,
        max_total_usd: &str,
        currency: &str,
        network: &str,
        manifest_hash_prefix: &str,
    ) -> Self {
        let message = batch_authorization_message(
            account,
            recipient_count,
            recipient_total_display,
            max_total_display,
            currency,
            network,
            manifest_hash_prefix,
        );
        Self::AuthorizeBatch {
            message,
            limit: PaymentLimit::from_amount(max_total_usd),
        }
    }

    pub fn use_account(message: impl Into<String>) -> Self {
        Self::UseAccount(message.into())
    }

    pub fn from_reason(reason: &str) -> Self {
        let message = normalize_message(reason);
        let lower = message.to_ascii_lowercase();

        if lower.starts_with("authorize payment")
            || lower.starts_with("authorize a payment")
            || lower.starts_with("authorize sending")
        {
            let limit = payment_limit_from_message(&message);
            Self::AuthorizePayment { message, limit }
        } else if lower.starts_with("set up") || lower.starts_with("store keypair") {
            Self::CreateAccount(message)
        } else if lower.starts_with("import") {
            Self::ImportAccount(message)
        } else if lower.starts_with("export") {
            Self::ExportAccount(message)
        } else if lower.starts_with("delete") {
            Self::DeleteAccount(message)
        } else if lower.starts_with("authorize opening a pay session") {
            Self::OpenSession(message)
        } else if lower.contains("gateway fee payer") {
            Self::UseGatewayFeePayer(message)
        } else {
            Self::UseAccount(message)
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::AuthorizePayment { message, .. }
            | Self::AuthorizeBatch { message, .. }
            | Self::CreateAccount(message)
            | Self::ImportAccount(message)
            | Self::ExportAccount(message)
            | Self::DeleteAccount(message)
            | Self::OpenSession(message)
            | Self::UseGatewayFeePayer(message)
            | Self::UseAccount(message) => message,
        }
    }

    pub fn payment_limit(&self) -> Option<PaymentLimit> {
        match self {
            Self::AuthorizePayment { limit, .. } | Self::AuthorizeBatch { limit, .. } => *limit,
            _ => None,
        }
    }

    #[cfg(any(test, target_os = "macos", target_os = "windows"))]
    pub(crate) fn prompt_message(&self) -> String {
        truncate_for_prompt(self.message(), 220)
    }
}

fn payment_limit_from_message(message: &str) -> Option<PaymentLimit> {
    let start = message.find('$')?;
    let mut amount = message[start..]
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '$' || *ch == '.')
        .collect::<String>();
    while amount.ends_with('.') {
        amount.pop();
    }
    PaymentLimit::from_amount(&amount)
}

fn prompt_detail(value: &str) -> String {
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let value = value.trim();
    if value.is_empty() {
        "unknown".to_string()
    } else {
        value.to_string()
    }
}

/// Normalise an operator label for the Touch ID prompt, returning `None`
/// when the value is missing, blank, the prompt placeholder `"unknown"`,
/// or a loopback hostname (`localhost`, `127.0.0.1`, `::1`). Loopback
/// labels are noise on the prompt — the user already knows they invoked
/// pay against their own server.
fn meaningful_operator(value: &str) -> Option<String> {
    let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "unknown" | "localhost" | "127.0.0.1" | "::1" | "[::1]"
    ) {
        return None;
    }
    Some(truncate_detail(value, 64))
}

fn truncate_detail(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_none() {
        return truncated;
    }

    if max_chars <= 3 {
        ".".repeat(max_chars)
    } else {
        let prefix = value.chars().take(max_chars - 3).collect::<String>();
        format!("{prefix}...")
    }
}

fn payment_authorization_message(
    amount_kind: PaymentAmountKind,
    amount: &str,
    reason: Option<&str>,
    operator: &str,
) -> String {
    let mut message = amount_kind.headline().to_string();
    message.push_str("\n\n");
    message.push_str(amount_kind.field_label());
    message.push_str(": ");
    message.push_str(&truncate_detail(&prompt_detail(amount), 48));

    if let Some(reason) = reason {
        message.push_str("\n\nreason: ");
        message.push_str(&truncate_detail(&prompt_detail(reason), 64));
    }

    if let Some(label) = meaningful_operator(operator) {
        message.push_str("\n\noperator: ");
        message.push_str(&label);
    }

    message
}

#[allow(clippy::too_many_arguments)]
fn batch_authorization_message(
    account: &str,
    recipient_count: usize,
    recipient_total_display: &str,
    max_total_display: &str,
    currency: &str,
    network: &str,
    manifest_hash_prefix: &str,
) -> String {
    let account = truncate_detail(&prompt_detail(account), 64);
    let currency = truncate_detail(&prompt_detail(currency), 24);
    let network = truncate_detail(&prompt_detail(network), 24);
    let manifest_hash_prefix = truncate_detail(&prompt_detail(manifest_hash_prefix), 24);

    format!(
        "authorize a batch payout from {account}.\n\n\
         recipients: {recipient_count}\n\n\
         recipient total: {recipient_total} {currency}\n\n\
         maximum total: {max_total} {currency}\n\n\
         network: {network}\n\n\
         manifest: {manifest_hash_prefix}",
        recipient_total = truncate_detail(&prompt_detail(recipient_total_display), 32),
        max_total = truncate_detail(&prompt_detail(max_total_display), 32),
    )
}

fn payment_message_with_account(message: &str, account: &str) -> String {
    let trimmed = message.trim_start();
    // Recognizes every current `PaymentAmountKind` headline plus one older,
    // no-longer-produced phrasing kept for defensiveness. A headline added
    // here without a matching arm silently drops the funding account from
    // the approval prompt — as `Escrow`'s did until this fix — so match
    // against the enum's own headline constants rather than duplicating the
    // wording as an independent literal.
    if !trimmed.starts_with("authorize a payment of ")
        && !trimmed.starts_with(PaymentAmountKind::Exact.headline())
        && !trimmed.starts_with(PaymentAmountKind::Maximum.headline())
        && !trimmed.starts_with(PaymentAmountKind::Escrow.headline())
    {
        return message.to_string();
    }

    let account = truncate_detail(&prompt_detail(account), 64);
    let (headline, details) = message
        .split_once("\n\n")
        .map_or((message, None), |(headline, details)| {
            (headline, Some(details))
        });
    let headline = headline.trim_end_matches('.').trim();
    if headline.is_empty() || headline.ends_with(&format!(" from {account}")) {
        return message.to_string();
    }

    let headline = format!("{headline} from {account}.");
    match details {
        Some(details) => format!("{headline}\n\n{details}"),
        None => headline,
    }
}

fn parse_usd_minor_units(amount: &str) -> Option<u64> {
    let amount = amount.trim().strip_prefix('$').unwrap_or(amount.trim());
    if amount.is_empty() {
        return None;
    }

    let mut parts = amount.split('.');
    let whole = parts.next()?;
    let frac = parts.next().unwrap_or("");
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }

    let whole_units = whole.parse::<u64>().ok()?.checked_mul(10_000)?;
    let frac_units = fractional_units(frac)?;
    whole_units.checked_add(frac_units)
}

fn fractional_units(frac: &str) -> Option<u64> {
    let mut units = 0u64;
    let mut multiplier = 1_000u64;
    for b in frac.bytes().take(4) {
        units = units.checked_add((b - b'0') as u64 * multiplier)?;
        multiplier /= 10;
    }
    if frac.bytes().skip(4).any(|b| b != b'0') {
        units = units.checked_add(1)?;
    }
    Some(units)
}

/// How the user proves identity before accessing secrets.
pub trait AuthGate: Send + Sync {
    /// Prompt the user to authenticate. Backends should present `intent`
    /// when the platform auth API allows it. Returns `Ok(())` on success.
    fn authenticate(&self, intent: &AuthIntent) -> Result<()>;

    /// Check if this auth mechanism is available on the current device.
    fn is_available(&self) -> bool;
}

/// No authentication — always succeeds. Used for testing and backends
/// where auth is handled externally (e.g. 1Password's `op` CLI).
pub struct NoAuth;

impl AuthGate for NoAuth {
    fn authenticate(&self, _intent: &AuthIntent) -> Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }
}

fn normalize_message(reason: &str) -> String {
    let normalized = reason.split_whitespace().collect::<Vec<_>>().join(" ");
    let normalized = normalized.trim();
    if normalized.is_empty() {
        DEFAULT_AUTH_REASON
    } else {
        normalized
    }
    .to_string()
}

#[cfg(any(test, target_os = "macos", target_os = "windows"))]
fn truncate_for_prompt(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_message_preserves_user_facing_reason() {
        assert_eq!(
            AuthIntent::from_reason("authorize a payment with pay").prompt_message(),
            "authorize a payment with pay"
        );
    }

    #[test]
    fn prompt_message_preserves_specific_payment_reason() {
        assert_eq!(
            AuthIntent::authorize_payment("$0.05", "accessing API api.example.com")
                .prompt_message(),
            "authorize payment of $0.05 for accessing API api.example.com"
        );
    }

    #[test]
    fn session_prompt_names_spending_limit_and_operator() {
        assert_eq!(
            AuthIntent::authorize_spend_up_to(
                Some("$1.00"),
                "$1.00",
                "modelstudio.alibaba.gateway-402.com",
            )
            .prompt_message(),
            "authorize a series of payments.\n\ntotal allowance: $1.00\n\noperator: modelstudio.alibaba.gateway-402.com"
        );
    }

    #[test]
    fn session_prompt_includes_account_on_first_sentence() {
        assert_eq!(
            AuthIntent::authorize_spend_up_to(
                Some("$1.00"),
                "$1.00",
                "modelstudio.alibaba.gateway-402.com",
            )
            .with_account_context("default")
            .prompt_message(),
            "authorize a series of payments from default.\n\ntotal allowance: $1.00\n\noperator: modelstudio.alibaba.gateway-402.com"
        );
    }

    #[test]
    fn payment_details_render_touch_id_context() {
        assert_eq!(
            AuthIntent::authorize_payment_details("$1.00", "Run a SQL query", "gateway-402.com")
                .prompt_message(),
            "authorize a payment.\n\namount: $1.00\n\nreason: Run a SQL query\n\noperator: gateway-402.com"
        );
    }

    #[test]
    fn payment_details_include_account_on_first_sentence() {
        assert_eq!(
            AuthIntent::authorize_payment_details("$0.30", "Send USDC", "gateway-402.com")
                .with_account_context("test")
                .prompt_message(),
            "authorize a payment from test.\n\namount: $0.30\n\nreason: Send USDC\n\noperator: gateway-402.com"
        );
    }

    #[test]
    fn payment_details_truncate_account_name() {
        let account = "a".repeat(65);
        let message =
            AuthIntent::authorize_payment_details("$0.30", "Send USDC", "gateway-402.com")
                .with_account_context(&account)
                .prompt_message();

        assert!(message.starts_with(
            "authorize a payment from aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..."
        ));
    }

    #[test]
    fn account_context_leaves_legacy_payment_prompt_unchanged() {
        assert_eq!(
            AuthIntent::authorize_payment("$0.30", "accessing API")
                .with_account_context("test")
                .prompt_message(),
            "authorize payment of $0.30 for accessing API"
        );
    }

    #[test]
    fn payment_details_truncate_reason_to_64_chars() {
        let reason = "a".repeat(65);
        let message = AuthIntent::authorize_payment_details("$1.00", &reason, "gateway-402.com")
            .prompt_message();

        assert_eq!(
            message,
            "authorize a payment.\n\namount: $1.00\n\nreason: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...\n\noperator: gateway-402.com"
        );
        assert_eq!(
            message
                .lines()
                .find_map(|line| line.strip_prefix("reason: "))
                .unwrap()
                .chars()
                .count(),
            64
        );
    }

    #[test]
    fn authorize_batch_names_every_required_field() {
        let intent = AuthIntent::authorize_batch(
            "default", 1_000, "1234.56", "1250.00", "$1250.00", "USDG", "mainnet", "a42f82c1",
        );
        let message = intent.prompt_message();
        assert!(message.starts_with("authorize a batch payout from default."));
        assert!(message.contains("recipients: 1000"));
        assert!(message.contains("recipient total: 1234.56 USDG"));
        assert!(message.contains("maximum total: 1250.00 USDG"));
        assert!(message.contains("network: mainnet"));
        assert!(message.contains("manifest: a42f82c1"));
        assert_eq!(intent.payment_limit(), Some(PaymentLimit::AboveUsd50));
    }

    #[test]
    fn prompt_message_trims_whitespace_and_punctuation() {
        assert_eq!(
            AuthIntent::from_reason("  delete default account  ").prompt_message(),
            "delete default account"
        );
    }

    #[test]
    fn prompt_message_falls_back_for_empty_reason() {
        assert_eq!(
            AuthIntent::from_reason("   ").prompt_message(),
            DEFAULT_AUTH_REASON
        );
    }

    #[test]
    fn prompt_message_bounds_long_reasons() {
        let long = "a".repeat(221);
        let message = AuthIntent::from_reason(&long).prompt_message();

        assert!(message.ends_with("..."));
        assert!(message.len() < 230);
    }

    #[test]
    fn from_reason_maps_known_reason_shapes_to_variants() {
        assert!(matches!(
            AuthIntent::from_reason("authorize sending SOL to recipient"),
            AuthIntent::AuthorizePayment { .. }
        ));
        assert!(matches!(
            AuthIntent::from_reason("set up the \"default\" payment account"),
            AuthIntent::CreateAccount(_)
        ));
        assert!(matches!(
            AuthIntent::from_reason("import the \"default\" payment account"),
            AuthIntent::ImportAccount(_)
        ));
        assert!(matches!(
            AuthIntent::from_reason("export the \"default\" payment account"),
            AuthIntent::ExportAccount(_)
        ));
        assert!(matches!(
            AuthIntent::from_reason("delete the \"default\" payment account"),
            AuthIntent::DeleteAccount(_)
        ));
        assert!(matches!(
            AuthIntent::from_reason("authorize opening a pay session"),
            AuthIntent::OpenSession(_)
        ));
        assert!(matches!(
            AuthIntent::from_reason("use your pay account as the gateway fee payer"),
            AuthIntent::UseGatewayFeePayer(_)
        ));
    }

    #[test]
    fn payment_limits_round_up_to_static_buckets() {
        assert_eq!(
            PaymentLimit::from_amount("$0"),
            Some(PaymentLimit::Usd00001)
        );
        assert_eq!(
            PaymentLimit::from_amount("$0.0001"),
            Some(PaymentLimit::Usd00001)
        );
        assert_eq!(
            PaymentLimit::from_amount("$0.00011"),
            Some(PaymentLimit::Usd0001)
        );
        assert_eq!(
            PaymentLimit::from_amount("$0.049"),
            Some(PaymentLimit::Usd005)
        );
        assert_eq!(
            PaymentLimit::from_amount("$0.0501"),
            Some(PaymentLimit::Usd01)
        );
        assert_eq!(PaymentLimit::from_amount("$50"), Some(PaymentLimit::Usd50));
        assert_eq!(
            PaymentLimit::from_amount("$50.01"),
            Some(PaymentLimit::AboveUsd50)
        );
    }

    #[test]
    fn authorize_payment_captures_limit() {
        assert_eq!(
            AuthIntent::authorize_payment("$0.05", "accessing API api.example.com").payment_limit(),
            Some(PaymentLimit::Usd005)
        );
        assert_eq!(
            AuthIntent::authorize_payment_details("$1.00", "API access", "gateway-402.com")
                .payment_limit(),
            Some(PaymentLimit::Usd1)
        );
        assert_eq!(
            AuthIntent::from_reason("authorize payment of $0.0501 for accessing API")
                .payment_limit(),
            Some(PaymentLimit::Usd01)
        );
    }

    #[test]
    fn session_budget_uses_existing_payment_limit_bucket() {
        assert_eq!(
            AuthIntent::authorize_spend_up_to(Some("$1.00"), "$1.00", "api.example.com",)
                .payment_limit(),
            Some(PaymentLimit::Usd1)
        );
    }

    #[test]
    fn authorize_payment_details_omits_operator_line_for_loopback() {
        let intent = AuthIntent::authorize_payment_details("$1.00", "API access", "localhost");
        let AuthIntent::AuthorizePayment { message, .. } = intent else {
            panic!("expected AuthorizePayment");
        };
        assert!(message.contains("reason: API access"));
        assert!(
            !message.contains("operator:"),
            "loopback operator should be omitted; got: {message:?}"
        );
    }

    #[test]
    fn authorize_payment_details_omits_operator_line_when_unknown() {
        let intent = AuthIntent::authorize_payment_details("$1.00", "API access", "");
        let AuthIntent::AuthorizePayment { message, .. } = intent else {
            panic!("expected AuthorizePayment");
        };
        assert!(!message.contains("operator:"));
    }

    #[test]
    fn authorize_payment_details_keeps_operator_line_for_real_domain() {
        let intent =
            AuthIntent::authorize_payment_details("$1.00", "API access", "api.example.com");
        let AuthIntent::AuthorizePayment { message, .. } = intent else {
            panic!("expected AuthorizePayment");
        };
        assert!(message.contains("operator: api.example.com"));
    }

    #[test]
    fn authorize_channel_escrow_keeps_amount_specific_limit() {
        // Regression: the escrow framing must not be folded into the amount, or
        // `PaymentLimit::from_amount` fails to parse it and the authorization
        // silently drops to the generic (no-limit) action. A bare "$25.00" must
        // still resolve to the Usd25 bucket.
        let intent = AuthIntent::authorize_channel_escrow("$25.00", "channel", "api.example.com");
        assert_eq!(intent.payment_limit(), Some(PaymentLimit::Usd25));
        let AuthIntent::AuthorizePayment { message, .. } = intent else {
            panic!("expected AuthorizePayment");
        };
        assert!(
            message.contains("escrow deposit: $25.00"),
            "escrow context should be in the headline/field, not the amount; got: {message:?}"
        );
    }

    #[test]
    fn authorize_channel_escrow_identifies_the_funding_account() {
        // Regression: payment_message_with_account's headline allowlist did
        // not include Escrow's, so with_account_context silently dropped the
        // funding account from every channel-escrow approval prompt — a
        // payer could not see which account was being drained before
        // approving.
        let intent = AuthIntent::authorize_channel_escrow("$25.00", "channel", "api.example.com")
            .with_account_context("trading");
        let AuthIntent::AuthorizePayment { message, .. } = intent else {
            panic!("expected AuthorizePayment");
        };
        assert!(
            message.contains("from trading"),
            "escrow approval should name the funding account; got: {message:?}"
        );
    }
}
