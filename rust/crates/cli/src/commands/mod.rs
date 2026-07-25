pub mod account;
pub(crate) mod agent_args;
pub mod catalog;
pub mod claude;
pub mod codex;
pub mod curl;
pub mod docs;
pub mod fetch;
pub mod goose;
pub mod help;
pub mod http;
pub(crate) mod payer_proxy;
pub mod qodercli;
pub mod send;
pub mod server;
pub mod setup;
pub mod skills;
pub mod subscriptions;
pub mod topup;
pub mod wget;
pub mod whoami;

use clap::Subcommand;
use owo_colors::OwoColorize;
use pay_core::client::receipt;
use pay_core::client::subscription as sub_client;
use pay_core::mpp;
use pay_core::runner::{DecodedPaymentChallenges, RunOutcome};
use pay_core::x402;
use pay_core::x402::Challenge as X402Challenge;
use pay_core::{run_curl_with_headers, run_httpie_with_headers, run_wget_with_headers};
use pay_kit::mpp::{ChargeRequest, SessionRequest};
use pay_types::Stablecoin;

use crate::components::ascii_table;
use crate::no_dna;
use crate::output::{self, OutputFormat};

#[derive(Subcommand)]
pub enum Command {
    /// Make an HTTP request via curl, handling 402 Payment Required flows.
    Curl(curl::CurlCommand),
    /// Download a resource via wget, handling 402 Payment Required flows.
    Wget(wget::WgetCommand),
    /// Make an HTTP request via HTTPie, handling 402 Payment Required flows.
    Http(http::HttpCommand),
    /// Fetch a URL using the built-in HTTP client (no external tool required).
    Fetch(fetch::FetchCommand),
    /// Run Claude Code with 402 payment support.
    Claude(claude::ClaudeCommand),
    /// Run Codex with 402 payment support.
    Codex(codex::CodexCommand),
    /// Run Goose with 402 payment support.
    Goose(goose::GooseCommand),
    /// Run Qoder CLI (qodercli) with 402 payment support.
    #[command(alias = "qoder")]
    Qodercli(qodercli::QodercliCommand),
    /// Manage accounts (new, import, list, default, remove, export).
    /// With no subcommand, lists accounts and prints the available subcommands.
    #[command(alias = "accounts")]
    Account {
        #[command(subcommand)]
        command: Option<account::AccountCommand>,
    },
    /// Show the system user, the active mainnet account, and its stablecoin
    /// balances.
    Whoami(whoami::WhoamiCommand),
    /// Send stablecoins to a recipient address.
    #[command(alias = "push")]
    Send(send::SendCommand),
    /// Generate a keypair, store it, and fund your account.
    Setup(setup::SetupCommand),
    /// Import funds from Venmo, PayPal, or a mobile wallet.
    Topup(topup::TopupCommand),
    /// Gate your API with stablecoin payments.
    #[command(alias = "serve")]
    Server {
        #[command(subcommand)]
        command: server::ServerCommand,
    },
    /// Browse, search, and inspect API providers from the skills catalog.
    Skills {
        #[command(subcommand)]
        command: skills::SkillsCommand,
    },
    /// Manage MPP `subscription`-intent delegations (list, new, cancel,
    /// status). With no subcommand, lists all subscriptions and prints the
    /// available verbs so the user discovers them.
    #[command(alias = "subscription", alias = "subs")]
    Subscriptions {
        #[command(subcommand)]
        command: Option<subscriptions::SubscriptionCommand>,
    },
    /// Make your API discoverable in pay's public catalog.
    Catalog {
        #[command(subcommand)]
        command: catalog::CatalogCommand,
    },
    /// Add a provider source (shorthand for `skills add`).
    #[command(alias = "add", short_flag = 'i')]
    Install(skills::install::InstallCommand),
    /// Start the MCP server (for Claude Code, Cursor, etc.)
    Mcp,
    /// Generate documentation artifacts (e.g. the provider-spec JSON Schema).
    Docs {
        #[command(subcommand)]
        command: docs::DocsCommand,
    },
}

/// Identifies which tool is being wrapped.
#[derive(Debug, Clone, Copy)]
pub enum ToolKind {
    Curl,
    Wget,
    Http,
    Fetch,
    Claude,
    Codex,
    Goose,
    Qodercli,
    Mcp,
}

impl Command {
    pub fn otlp_sidecar(&self) -> Option<&str> {
        match self {
            Command::Server { command } => command.otlp_sidecar(),
            _ => None,
        }
    }

    /// Whether this command needs a configured pay account before it can
    /// run usefully. Used by `main` to auto-run `pay setup` on a fresh
    /// install when the user invokes a payment-bearing command directly
    /// (e.g. `npx @solana/pay claude "buy me some flowers"`).
    ///
    /// Setup itself, account-management subcommands, and informational
    /// commands (whoami, skills, mcp, server) are excluded — they either
    /// don't need an account or handle the missing-account case
    /// gracefully on their own.
    pub fn requires_account(&self) -> bool {
        match self {
            Command::Curl(_)
            | Command::Wget(_)
            | Command::Http(_)
            | Command::Fetch(_)
            | Command::Claude(_)
            | Command::Codex(_)
            | Command::Goose(_)
            | Command::Qodercli(_)
            | Command::Send(_)
            | Command::Topup(_) => true,
            Command::Setup(_)
            | Command::Account { .. }
            | Command::Whoami(_)
            | Command::Skills { .. }
            | Command::Subscriptions { .. }
            | Command::Catalog { .. }
            | Command::Install(_)
            | Command::Server { .. }
            | Command::Docs { .. }
            | Command::Mcp => false,
        }
    }

    /// Which tool this command wraps.
    #[allow(dead_code)] // used by session budget TUI (currently disabled)
    pub fn tool_kind(&self) -> ToolKind {
        match self {
            Command::Curl(_) => ToolKind::Curl,
            Command::Wget(_) => ToolKind::Wget,
            Command::Http(_) => ToolKind::Http,
            Command::Fetch(_) => ToolKind::Fetch,
            Command::Claude(_) => ToolKind::Claude,
            Command::Codex(_) => ToolKind::Codex,
            Command::Goose(_) => ToolKind::Goose,
            Command::Qodercli(_) => ToolKind::Qodercli,
            Command::Account { .. }
            | Command::Whoami(_)
            | Command::Skills { .. }
            | Command::Subscriptions { .. }
            | Command::Catalog { .. }
            | Command::Install(_)
            | Command::Send(_)
            | Command::Setup(_)
            | Command::Topup(_)
            | Command::Server { .. }
            | Command::Docs { .. } => ToolKind::Mcp,
            Command::Mcp => ToolKind::Mcp,
        }
    }
}

/// Which underlying tool to use for retry.
enum Tool<'a> {
    Curl(&'a [String]),
    Wget(&'a [String]),
    Http(&'a [String]),
    Fetch {
        method: &'a str,
        url: &'a str,
        body: Option<&'a pay_core::fetch::RequestBody>,
        redirect_policy: pay_core::fetch::RedirectPolicy,
        validation_body: Option<&'a str>,
        content_type: Option<&'a str>,
    },
}

impl Command {
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        self,
        auto_pay: bool,
        output_fmt: Option<OutputFormat>,
        payment_cap: Option<u64>,
        keypair_override: Option<&str>,
        network_override: Option<&str>,
        account_override: Option<&str>,
        verbose: bool,
        sandbox: bool,
        alternate_provider: bool,
    ) -> pay_core::Result<()> {
        let pay_bin = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "pay".to_string());

        match self {
            Command::Account { command } => match command {
                Some(cmd) => return cmd.run(),
                None => return account::run_default(),
            },
            Command::Whoami(cmd) => return cmd.run(network_override, account_override),
            Command::Skills { command } => return command.run(),
            Command::Subscriptions { command } => match command {
                Some(cmd) => return cmd.run(),
                None => return subscriptions::run_default(),
            },
            Command::Catalog { command } => return command.run(),
            Command::Install(cmd) => return cmd.run(),
            Command::Send(cmd) => {
                return cmd.run(network_override, account_override, verbose);
            }
            Command::Setup(cmd) => return cmd.run(),
            Command::Topup(cmd) => return cmd.run(),
            Command::Server { command } => return command.run(keypair_override, sandbox),
            Command::Mcp => {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| {
                        pay_core::Error::Config(format!("Failed to create runtime: {e}"))
                    })?;
                return rt
                    .block_on(pay_mcp::run_server(&pay_mcp::McpOptions::default()))
                    .map_err(pay_core::Error::Config);
            }
            Command::Claude(cmd) => std::process::exit(cmd.run(
                &pay_bin,
                account_override,
                network_override,
                alternate_provider,
            )?),
            Command::Codex(cmd) => std::process::exit(cmd.run(
                &pay_bin,
                account_override,
                network_override,
                alternate_provider,
            )?),
            Command::Goose(cmd) => std::process::exit(cmd.run(
                &pay_bin,
                account_override,
                network_override,
                alternate_provider,
            )?),
            Command::Qodercli(cmd) => std::process::exit(cmd.run(
                &pay_bin,
                account_override,
                network_override,
                alternate_provider,
            )?),
            Command::Docs { command } => return command.run(),
            _ => {}
        }

        let (outcome, tool) = match &self {
            Command::Curl(cmd) => (pay_core::run_curl(&cmd.args)?, Tool::Curl(&cmd.args)),
            Command::Wget(cmd) => (pay_core::run_wget(&cmd.args)?, Tool::Wget(&cmd.args)),
            Command::Http(cmd) => (pay_core::run_httpie(&cmd.args)?, Tool::Http(&cmd.args)),
            Command::Fetch(cmd) => {
                let prepared = cmd.prepare()?;
                if prepared.body.is_some() && prepared.validation_body.is_none() {
                    pay_core::skills::validate_cached_catalog_opaque_request(
                        &prepared.method,
                        &cmd.url,
                        prepared
                            .content_type
                            .as_deref()
                            .unwrap_or("application/octet-stream"),
                    )?;
                } else {
                    pay_core::skills::validate_cached_catalog_request(
                        &prepared.method,
                        &cmd.url,
                        prepared.validation_body.as_deref(),
                    )?;
                }
                let outcome = pay_core::fetch::fetch_request_with_body_for(
                    pay_core::ClientApp::Cli,
                    &prepared.method,
                    &cmd.url,
                    &prepared.headers,
                    prepared.body.as_ref(),
                    prepared.redirect_policy,
                )?;
                let tool = Tool::Fetch {
                    method: &prepared.method,
                    url: &cmd.url,
                    body: prepared.body.as_ref(),
                    redirect_policy: prepared.redirect_policy,
                    validation_body: prepared.validation_body.as_deref(),
                    content_type: prepared.content_type.as_deref(),
                };
                return handle_outcome(
                    outcome,
                    &tool,
                    auto_pay,
                    output_fmt,
                    payment_cap,
                    Some(prepared.headers.clone()),
                    network_override,
                    account_override,
                    sandbox,
                    verbose,
                );
            }
            _ => unreachable!("handled above"),
        };

        handle_outcome(
            outcome,
            &tool,
            auto_pay,
            output_fmt,
            payment_cap,
            None,
            network_override,
            account_override,
            sandbox,
            verbose,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_outcome(
    outcome: RunOutcome,
    tool: &Tool,
    auto_pay: bool,
    output_fmt: Option<OutputFormat>,
    payment_cap: Option<u64>,
    fetch_headers: Option<Vec<(String, String)>>,
    network_override: Option<&str>,
    account_override: Option<&str>,
    sandbox: bool,
    verbose: bool,
) -> pay_core::Result<()> {
    let is_json = no_dna::should_json(output_fmt);

    match outcome {
        RunOutcome::MppChallenge {
            challenge,
            alternatives,
            advertised_challenges,
            resource_url,
            // TODO(step2): route `x402_alternative` through
            // `mpp::choose_payment` so CLI auto-pay also falls back to a
            // fundable x402 offer. The MCP `curl` path already does this.
            ..
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            let req: ChargeRequest = challenge.request.decode().unwrap_or_default();
            let mut challenges = Vec::with_capacity(1 + alternatives.len());
            challenges.push((*challenge).clone());
            challenges.extend(alternatives);
            if auto_pay {
                let capped_challenges;
                let challenges_to_pay = if let Some(cap) = payment_cap {
                    capped_challenges = mpp_challenges_within_cap(&challenges, cap)?;
                    capped_challenges.as_slice()
                } else {
                    challenges.as_slice()
                };
                if verbose && !is_json {
                    let currencies = mpp_challenge_currencies(&challenges).join(", ");
                    eprintln!(
                        "{}",
                        format!(
                            "402 Payment Required (MPP) — {} {}",
                            req.amount,
                            if currencies.is_empty() {
                                req.currency.clone()
                            } else {
                                currencies
                            }
                        )
                        .dimmed()
                    );
                }
                return pay_mpp_and_retry(
                    challenges_to_pay,
                    &resource_url,
                    PaymentRetryContext {
                        tool,
                        output_fmt,
                        fetch_headers,
                        network_override,
                        account_override,
                        verbose,
                    },
                );
            }

            if is_json {
                let network = req
                    .method_details
                    .as_ref()
                    .and_then(|v| v.get("network"))
                    .and_then(|v| v.as_str());
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "mpp",
                    "challenges": mpp_challenges_json(&challenges),
                    "challenge": {
                        "amount": req.amount,
                        "currency": req.currency,
                        "recipient": req.recipient,
                        "description": req.description,
                        "network": network,
                    },
                    "resource": resource_url,
                }))?;
            } else {
                eprintln!(
                    "{}",
                    format!(
                        "402 Payment Required (MPP) — {} {}",
                        req.amount, req.currency
                    )
                    .dimmed()
                );
            }
        }

        RunOutcome::SubscriptionChallenge {
            challenge,
            authenticate,
            advertised_challenges,
            resource_url,
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            let decoded = match sub_client::decode(&challenge) {
                Ok(d) => d,
                Err(e) => {
                    if is_json {
                        output::print_json(&serde_json::json!({
                            "status": 402,
                            "error": "subscription_decode_failed",
                            "message": e.to_string(),
                        }))?;
                    } else {
                        eprintln!(
                            "{} {}",
                            "Subscription challenge could not be decoded:".red(),
                            e
                        );
                    }
                    std::process::exit(1);
                }
            };

            if auto_pay {
                if let Some(cap) = payment_cap {
                    enforce_subscription_cap(&decoded, cap)?;
                }
                if verbose && !is_json {
                    eprintln!(
                        "{}",
                        format!(
                            "402 Payment Required (MPP subscription) — {} {} every {} {}{}",
                            decoded.amount_base_units,
                            decoded.currency_label,
                            decoded.period_count,
                            match decoded.period_unit {
                                pay_kit::mpp::SubscriptionPeriodUnit::Day => "day",
                                pay_kit::mpp::SubscriptionPeriodUnit::Week => "week",
                            },
                            if decoded.period_count == 1 { "" } else { "s" }
                        )
                        .dimmed()
                    );
                }
                return pay_subscription_and_retry(
                    &challenge,
                    authenticate.as_deref(),
                    &resource_url,
                    PaymentRetryContext {
                        tool,
                        output_fmt,
                        fetch_headers,
                        network_override,
                        account_override,
                        verbose,
                    },
                );
            }

            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "mpp-subscription",
                    "challenge": {
                        "amount_base_units": decoded.amount_base_units,
                        "currency": decoded.currency_label,
                        "mint": decoded.method_details.mint,
                        "plan": decoded.method_details.plan_id,
                        "puller": decoded.method_details.puller,
                        "recipient": decoded.request.recipient,
                        "period_unit": match decoded.period_unit {
                            pay_kit::mpp::SubscriptionPeriodUnit::Day => "day",
                            pay_kit::mpp::SubscriptionPeriodUnit::Week => "week",
                        },
                        "period_count": decoded.period_count,
                        "network": decoded.network,
                        "expires_at": decoded.request.subscription_expires,
                    },
                    "resource": resource_url,
                }))?;
            } else {
                eprintln!(
                    "{}",
                    format!(
                        "402 Payment Required (MPP subscription) — {} {} every {} {}{}",
                        decoded.amount_base_units,
                        decoded.currency_label,
                        decoded.period_count,
                        match decoded.period_unit {
                            pay_kit::mpp::SubscriptionPeriodUnit::Day => "day",
                            pay_kit::mpp::SubscriptionPeriodUnit::Week => "week",
                        },
                        if decoded.period_count == 1 { "" } else { "s" }
                    )
                    .dimmed()
                );
            }
        }

        RunOutcome::SessionChallenge {
            challenge,
            advertised_challenges,
            resource_url,
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            let req: Option<SessionRequest> = challenge.request.decode().ok();
            let cap_display = req
                .as_ref()
                .map(|request| display_token_amount(&request.cap, &request.currency))
                .unwrap_or_else(|| "unknown".to_string());

            if auto_pay {
                enforce_session_cap(req.as_ref(), payment_cap)?;
                return pay_session_and_retry(
                    &challenge,
                    req.as_ref(),
                    tool,
                    output_fmt,
                    fetch_headers,
                    network_override,
                    account_override,
                    sandbox,
                    verbose,
                );
            }

            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "mpp-session",
                    "challenge": {
                        "cap": req.as_ref().map(|r| &r.cap),
                        "cap_display": cap_display,
                        "currency": req.as_ref().map(|r| &r.currency),
                        "network": req.as_ref().and_then(|r| r.network.as_deref()),
                        "min_voucher_delta": req.as_ref().and_then(|r| r.min_voucher_delta.as_deref()),
                        "recipient": req.as_ref().map(|r| &r.recipient),
                    },
                    "resource": resource_url,
                }))?;
            } else {
                crate::components::print_notice(
                    crate::components::NoticeLevel::Info,
                    "MPP payment channel required",
                    &format!("Spending limit: {cap_display}"),
                );
            }
        }

        RunOutcome::X402Challenge {
            challenge,
            advertised_challenges,
            resource_url,
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            if auto_pay {
                enforce_payment_cap(
                    &challenge.requirements.amount,
                    &challenge.requirements.currency,
                    payment_cap,
                    "x402",
                )?;
                if verbose && !is_json {
                    eprintln!(
                        "{}",
                        format!(
                            "402 Payment Required (x402) — {} {}",
                            challenge.requirements.amount, challenge.requirements.currency
                        )
                        .dimmed()
                    );
                }
                return pay_x402_and_retry(
                    &challenge,
                    &resource_url,
                    PaymentRetryContext {
                        tool,
                        output_fmt,
                        fetch_headers,
                        network_override,
                        account_override,
                        verbose,
                    },
                );
            }

            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "x402",
                    "challenge": {
                        "amount": challenge.requirements.amount,
                        "currency": challenge.requirements.currency,
                        "recipient": challenge.requirements.recipient,
                        "description": challenge.requirements.description,
                        "cluster": challenge.requirements.cluster,
                    },
                    "resource": resource_url,
                }))?;
            } else {
                eprintln!(
                    "{}",
                    format!(
                        "402 Payment Required (x402) — {} {}",
                        challenge.requirements.amount, challenge.requirements.currency
                    )
                    .dimmed()
                );
            }
        }

        RunOutcome::X402UptoChallenge {
            challenge,
            advertised_challenges,
            resource_url,
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            if auto_pay {
                // The cap is the authorized ceiling (the channel deposit).
                enforce_payment_cap(
                    &challenge.requirements.amount,
                    &challenge.requirements.asset,
                    payment_cap,
                    "x402",
                )?;
                return pay_upto_and_retry(
                    &challenge,
                    &resource_url,
                    PaymentRetryContext {
                        tool,
                        output_fmt,
                        fetch_headers,
                        network_override,
                        account_override,
                        verbose,
                    },
                );
            }

            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "x402-upto",
                    "challenge": {
                        "amount": challenge.requirements.amount,
                        "currency": challenge.requirements.asset,
                        "recipient": challenge.requirements.pay_to,
                    },
                    "resource": resource_url,
                }))?;
            } else {
                eprintln!(
                    "{}",
                    format!(
                        "402 Payment Required (x402 upto) — up to {} {}",
                        challenge.requirements.amount, challenge.requirements.asset
                    )
                    .dimmed()
                );
            }
        }

        RunOutcome::X402SignInChallenge {
            challenge,
            advertised_challenges,
            resource_url,
            ..
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            if auto_pay {
                if verbose && !is_json {
                    eprintln!("{}", "402 Sign-In Required (x402)".dimmed());
                }
                return pay_x402_siwx_and_retry(
                    &challenge,
                    &resource_url,
                    PaymentRetryContext {
                        tool,
                        output_fmt,
                        fetch_headers,
                        network_override,
                        account_override,
                        verbose,
                    },
                );
            }

            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "x402-siwx",
                    "resource": resource_url,
                }))?;
            } else {
                eprintln!("{}", "402 Sign-In Required (x402)".dimmed());
            }
        }

        RunOutcome::UnknownPaymentRequired {
            headers: _,
            advertised_challenges,
            resource_url,
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "protocol": "unknown",
                    "resource": resource_url,
                }))?;
            } else {
                eprintln!();
                eprintln!(
                    "{}",
                    "402 Payment Required (no recognized payment protocol)".dimmed()
                );
                eprintln!("{}", format!("  Resource: {resource_url}").dimmed());
            }
        }

        RunOutcome::PaymentRejected {
            reason,
            retryable,
            advertised_challenges,
            ..
        } => {
            print_verbose_challenges(&advertised_challenges, verbose, is_json);
            // First-call rejection: the request already carried an Authorization
            // header (e.g. cached from a previous run) and the server rejected
            // it. There's no point retrying with the same header — surface the
            // reason and exit.
            if is_json {
                output::print_json(&serde_json::json!({
                    "status": 402,
                    "error": "payment_rejected",
                    "reason": reason,
                    "retryable": retryable,
                }))?;
            } else {
                let body = if retryable {
                    format!("{reason}\n(retryable — try again)")
                } else {
                    reason
                };
                crate::components::print_notice(
                    crate::components::NoticeLevel::Error,
                    "Payment rejected by verifier",
                    &body,
                );
            }
            std::process::exit(1);
        }

        RunOutcome::Completed {
            exit_code,
            body,
            response_headers,
            ..
        } => {
            print_verbose_receipt(
                &response_headers,
                network_override,
                ReceiptProvenance::InitialRequest,
                verbose,
                is_json,
            );
            if let Some(body) = body {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&body);
            }
            std::process::exit(exit_code);
        }
    }

    Ok(())
}

fn print_verbose_challenges(challenges: &DecodedPaymentChallenges, verbose: bool, is_json: bool) {
    if !verbose || is_json {
        return;
    }
    if let Some(rendered) = render_verbose_challenges(challenges) {
        eprint!(
            "{}",
            crate::components::notice_body(crate::components::NoticeLevel::Info, &rendered)
        );
    }
}

fn render_verbose_challenges(challenges: &DecodedPaymentChallenges) -> Option<String> {
    if challenges.is_empty() {
        return None;
    }
    let mut rows = Vec::with_capacity(challenges.x402.len() + challenges.mpp.len());
    for (protocol, challenges) in [("x402", &challenges.x402), ("mpp", &challenges.mpp)] {
        for challenge in challenges {
            rows.push(challenge_summary_row(protocol, challenge));
        }
    }
    Some(ascii_table::render_table(
        &["Protocol", "Terms", "Network"],
        &rows,
    ))
}

fn print_verbose_receipt(
    headers: &[(String, String)],
    fallback_network: Option<&str>,
    provenance: ReceiptProvenance<'_>,
    verbose: bool,
    is_json: bool,
) {
    if !verbose || is_json {
        return;
    }
    if let Some(rendered) = render_receipt_for_completion(headers, fallback_network, provenance) {
        crate::components::print_notice(
            crate::components::NoticeLevel::Success,
            &rendered.title,
            &rendered.body,
        );
    }
}

struct ReceiptNotice {
    title: String,
    body: String,
}

#[derive(Clone, Copy)]
struct ReceiptDisplayContext<'a> {
    asset: Option<&'a str>,
    scheme: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum ReceiptProvenance<'a> {
    InitialRequest,
    NonPaymentRetry,
    PaidRetry(Option<ReceiptDisplayContext<'a>>),
}

fn render_receipt_for_completion(
    headers: &[(String, String)],
    fallback_network: Option<&str>,
    provenance: ReceiptProvenance<'_>,
) -> Option<ReceiptNotice> {
    match provenance {
        ReceiptProvenance::InitialRequest => None,
        ReceiptProvenance::NonPaymentRetry => None,
        ReceiptProvenance::PaidRetry(payment) => {
            render_verbose_receipt(headers, fallback_network, payment)
        }
    }
}

fn render_verbose_receipt(
    headers: &[(String, String)],
    fallback_network: Option<&str>,
    payment: Option<ReceiptDisplayContext<'_>>,
) -> Option<ReceiptNotice> {
    let direct_url = response_header(headers, "payment-receipt-url")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let Some(decoded) = receipt::decode_response_receipt(headers) else {
        return direct_url.map(|url| ReceiptNotice {
            title: "Payment completed".to_string(),
            body: crate::components::link_with_arrow("Link to receipt", &url),
        });
    };
    let amount = receipt_amount(&decoded.decoded, payment.and_then(|payment| payment.asset))
        .unwrap_or_else(|| "Payment".to_string());
    let title = format!(
        "{amount} paid via {}",
        receipt_protocol_label(
            decoded.protocol,
            &decoded.decoded,
            payment.and_then(|payment| payment.scheme),
        )
    );
    let title = crate::components::terminal::sanitize_terminal_text(&title);
    let body = if let Some(url) = direct_url {
        crate::components::link_with_arrow("Link to receipt", &url)
    } else if let Some(signature) = decoded.signature.as_deref() {
        let network = fallback_network
            .or(decoded.network.as_deref())
            .unwrap_or("mainnet");
        crate::components::solana_transaction_link(signature, network)
    } else {
        "Payment receipt received".to_string()
    };
    Some(ReceiptNotice { title, body })
}

fn challenge_summary_row(protocol: &str, value: &serde_json::Value) -> Vec<String> {
    let kind = match protocol {
        "x402" => json_string(value, &[&["scheme"]]).unwrap_or_else(|| "payment".to_string()),
        "mpp" => json_string(value, &[&["intent"]]).unwrap_or_else(|| "charge".to_string()),
        _ => "-".to_string(),
    };
    let amount = format_amount(value);
    let network = json_string(
        value,
        &[&["network"], &["cluster"], &["request", "network"]],
    )
    .map(|network| format_challenge_network(value, &network))
    .unwrap_or_else(|| "-".to_string());
    let terms = match (kind.as_str(), amount.as_str()) {
        (_, "-") => "-".to_string(),
        ("upto" | "session", amount) => format!("up to {amount}"),
        (_, amount) => amount.to_string(),
    };

    vec![format!("{protocol}/{kind}"), terms, network]
}

fn format_challenge_network(value: &serde_json::Value, network: &str) -> String {
    use pay_kit::x402::exact::{SOLANA_DEVNET, SOLANA_MAINNET, SOLANA_TESTNET};

    let cluster = match network {
        SOLANA_MAINNET | "solana:mainnet" | "mainnet" | "mainnet-beta" => "mainnet",
        SOLANA_DEVNET | "solana:devnet" | "solana-devnet" | "devnet" => "devnet",
        SOLANA_TESTNET | "solana:testnet" | "solana-testnet" | "testnet" => "testnet",
        "localnet" | "sandbox" => "localnet",
        _ => return network.to_string(),
    };
    let is_solana = network.starts_with("solana:")
        || json_string(value, &[&["method"]]).is_some_and(|method| method == "solana");

    if is_solana {
        format!("Solana {cluster}")
    } else {
        cluster.to_string()
    }
}

fn receipt_amount(value: &serde_json::Value, fallback_asset: Option<&str>) -> Option<String> {
    let amount = json_string(value, &[&["amount"], &["settlement", "amount"]])?;
    let currency = json_string(
        value,
        &[&["asset"], &["currency"], &["settlement", "asset"]],
    )
    .or_else(|| fallback_asset.map(str::to_string));
    Some(currency.map_or(amount.clone(), |currency| {
        display_token_amount(&amount, &currency)
    }))
}

fn receipt_protocol_label(
    protocol: receipt::ReceiptProtocol,
    value: &serde_json::Value,
    fallback_scheme: Option<&str>,
) -> String {
    let scheme = match protocol {
        receipt::ReceiptProtocol::X402 => {
            json_string(value, &[&["accepted", "scheme"], &["scheme"]])
        }
        receipt::ReceiptProtocol::Mpp => json_string(value, &[&["intent"], &["receipt", "intent"]]),
    };
    scheme
        .or_else(|| fallback_scheme.map(str::to_string))
        .map_or_else(
            || protocol.to_string(),
            |scheme| format!("{protocol} / {scheme}"),
        )
}

fn format_amount(value: &serde_json::Value) -> String {
    let amount = json_string(
        value,
        &[
            &["amount"],
            &["maxAmountRequired"],
            &["request", "amount"],
            &["request", "cap"],
        ],
    );
    let currency = json_string(
        value,
        &[&["asset"], &["currency"], &["request", "currency"]],
    );
    match (amount, currency) {
        (Some(amount), Some(currency)) => display_token_amount(&amount, &currency),
        (Some(amount), None) => amount,
        _ => "-".to_string(),
    }
}

fn json_string(value: &serde_json::Value, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| {
        path.iter()
            .try_fold(value, |current, key| current.get(*key))
            .and_then(|value| match value {
                serde_json::Value::String(value) => Some(value.clone()),
                serde_json::Value::Number(_) | serde_json::Value::Bool(_) => {
                    Some(value.to_string())
                }
                _ => None,
            })
    })
}

fn compact_identifier(value: &str) -> String {
    const PREFIX: usize = 10;
    const SUFFIX: usize = 8;
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= PREFIX + SUFFIX + 3 {
        return value.to_string();
    }
    format!(
        "{}...{}",
        chars[..PREFIX].iter().collect::<String>(),
        chars[chars.len() - SUFFIX..].iter().collect::<String>()
    )
}

fn response_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn mpp_challenges_within_cap(
    challenges: &[mpp::Challenge],
    payment_cap: u64,
) -> pay_core::Result<Vec<mpp::Challenge>> {
    let mut allowed = Vec::new();
    let mut lowest_required: Option<(u64, String, String)> = None;
    let mut unsupported_currencies = Vec::new();

    for challenge in challenges {
        let request: ChargeRequest = challenge.request.decode().map_err(|e| {
            pay_core::Error::Mpp(format!("Failed to decode challenge request: {e}"))
        })?;
        let amount_micro = match amount_as_stablecoin_micro(&request.amount, &request.currency) {
            Ok(amount_micro) => amount_micro,
            Err(pay_core::Error::PaymentRejected(_)) => {
                unsupported_currencies.push(request.currency);
                continue;
            }
            Err(err) => return Err(err),
        };

        if amount_micro <= payment_cap {
            allowed.push(challenge.clone());
        }

        if lowest_required
            .as_ref()
            .is_none_or(|(lowest, _, _)| amount_micro < *lowest)
        {
            lowest_required = Some((amount_micro, request.amount, request.currency));
        }
    }

    if !allowed.is_empty() {
        return Ok(allowed);
    }

    if let Some((required_micro, _amount, currency)) = lowest_required {
        return Err(payment_cap_error(
            "MPP",
            &currency,
            required_micro,
            payment_cap,
        ));
    }

    unsupported_currencies.sort();
    unsupported_currencies.dedup();
    if !unsupported_currencies.is_empty() {
        return Err(pay_core::Error::PaymentRejected(format!(
            "The automatic payment cap is stablecoin-denominated and cannot price advertised MPP currencies automatically: {}",
            unsupported_currencies.join(", ")
        )));
    }

    Err(pay_core::Error::PaymentRejected(
        "no MPP payment challenge was available".to_string(),
    ))
}

fn enforce_session_cap(
    request: Option<&SessionRequest>,
    payment_cap: Option<u64>,
) -> pay_core::Result<()> {
    let Some(payment_cap) = payment_cap else {
        return Ok(());
    };
    let Some(request) = request else {
        return Err(pay_core::Error::Mpp(
            "session payment cap requires a decoded SessionRequest".to_string(),
        ));
    };
    let required_micro = amount_as_stablecoin_micro(&request.cap, &request.currency)?;

    if required_micro <= payment_cap {
        return Ok(());
    }

    Err(payment_cap_error(
        "MPP session",
        Stablecoin::from_mint(&request.currency)
            .map(Stablecoin::symbol)
            .unwrap_or(&request.currency),
        required_micro,
        payment_cap,
    ))
}

fn enforce_payment_cap(
    amount: &str,
    currency: &str,
    payment_cap: Option<u64>,
    protocol: &str,
) -> pay_core::Result<()> {
    let Some(payment_cap) = payment_cap else {
        return Ok(());
    };
    let required_micro = amount_as_stablecoin_micro(amount, currency)?;
    if required_micro <= payment_cap {
        return Ok(());
    }
    Err(payment_cap_error(
        protocol,
        currency,
        required_micro,
        payment_cap,
    ))
}

fn payment_cap_error(
    protocol: &str,
    currency: &str,
    required_micro: u64,
    payment_cap: u64,
) -> pay_core::Error {
    pay_core::Error::PaymentRejected(format!(
        "{protocol} payment requires {} {currency}, above the automatic payment cap of {} stablecoins",
        format_stablecoin_amount(required_micro),
        format_stablecoin_amount(payment_cap),
    ))
}

fn amount_as_stablecoin_micro(amount: &str, currency: &str) -> pay_core::Result<u64> {
    let raw = amount
        .parse::<u64>()
        .map_err(|e| pay_core::Error::Mpp(format!("Invalid payment amount `{amount}`: {e}")))?;

    if is_known_stablecoin(currency) {
        return Ok(raw);
    }

    Err(pay_core::Error::PaymentRejected(format!(
        "The automatic payment cap is stablecoin-denominated and cannot price `{currency}` payments automatically"
    )))
}

fn is_known_stablecoin(currency: &str) -> bool {
    Stablecoin::parse_symbol(currency).is_some() || Stablecoin::from_mint(currency).is_some()
}

fn format_stablecoin_amount(amount: u64) -> String {
    let whole = amount / 1_000_000;
    let fraction = amount % 1_000_000;
    if fraction == 0 {
        return whole.to_string();
    }
    let mut fraction = format!("{fraction:06}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{whole}.{fraction}")
}

struct PaymentRetryContext<'a, 'tool> {
    tool: &'a Tool<'tool>,
    output_fmt: Option<OutputFormat>,
    fetch_headers: Option<Vec<(String, String)>>,
    network_override: Option<&'a str>,
    account_override: Option<&'a str>,
    verbose: bool,
}

fn pay_mpp_and_retry(
    challenges: &[mpp::Challenge],
    resource_url: &str,
    ctx: PaymentRetryContext<'_, '_>,
) -> pay_core::Result<()> {
    let is_json = no_dna::should_json(ctx.output_fmt);
    validate_tool_request_before_signing(ctx.tool)?;

    if ctx.verbose && !is_json {
        eprintln!("{}", "Paying...".dimmed());
    }

    let store = pay_core::accounts::FileAccountsStore::default_path();
    let challenge = mpp::select_challenge_by_balance(
        challenges,
        &store,
        ctx.network_override,
        ctx.account_override,
    )?
    .ok_or_else(|| {
        let networks = mpp_challenge_networks(challenges);
        let offered = if networks.is_empty() {
            "(none)".to_string()
        } else {
            networks.join(", ")
        };
        let active = ctx.network_override.unwrap_or("auto");
        pay_core::Error::Mpp(format!(
            "No MPP challenge matched the active network filter (active: {active}, offered: {offered}). \
             Drop `--network` or check `pay account list` for accounts on the offered networks."
        ))
    })?;
    let (auth_header, ephemeral_notice) = mpp::build_credential(
        challenge,
        &store,
        ctx.network_override,
        ctx.account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = ephemeral_notice {
        render_generated_wallet_notice(&resolved, is_json)?;
    }

    if ctx.verbose && !is_json {
        eprintln!("{}", "Payment signed, retrying...\n".dimmed());
    }

    let receipt_network = ctx
        .network_override
        .map(str::to_string)
        .or_else(|| mpp_challenge_network(challenge));
    let verbose = ctx.verbose;
    let retry_outcome =
        retry_with_header(ctx.tool, "Authorization", &auth_header, ctx.fetch_headers)?;
    handle_retry_outcome(
        retry_outcome,
        is_json,
        verbose,
        receipt_network.as_deref(),
        ReceiptProvenance::PaidRetry(None),
    )
}

fn pay_subscription_and_retry(
    challenge: &mpp::Challenge,
    authenticate_challenge: Option<&mpp::Challenge>,
    resource_url: &str,
    ctx: PaymentRetryContext<'_, '_>,
) -> pay_core::Result<()> {
    let is_json = no_dna::should_json(ctx.output_fmt);
    validate_tool_request_before_signing(ctx.tool)?;

    if ctx.verbose && !is_json {
        eprintln!("{}", "Activating subscription...".dimmed());
    }

    let store = pay_core::accounts::FileAccountsStore::default_path();
    let built = sub_client::build_credential_with_authenticate(
        challenge,
        authenticate_challenge,
        &store,
        ctx.network_override,
        ctx.account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = built.ephemeral_notice.clone() {
        render_generated_wallet_notice(&resolved, is_json)?;
    }

    if ctx.verbose && !is_json {
        eprintln!("{}", "Activation signed, retrying...\n".dimmed());
    }

    let retry_outcome = retry_with_header(
        ctx.tool,
        "Authorization",
        &built.authorization,
        ctx.fetch_headers,
    )?;
    let receipt_network = ctx
        .network_override
        .map(str::to_string)
        .or_else(|| mpp_challenge_network(challenge));

    // On any 2xx outcome, persist a best-effort local record. The
    // `subscription_id` is the deterministic SubscriptionDelegation PDA
    // (per spec §"Subscription Identifier"), so we can derive it without
    // round-tripping the Payment-Receipt header — which the curl/wget/httpie
    // wrappers don't preserve today.
    if let RunOutcome::Completed { exit_code, .. } = &retry_outcome
        && *exit_code == 0
    {
        if let Err(e) = persist_local_subscription_after_activation(&built, &store) {
            tracing::warn!(error = %e, "Activation succeeded but could not persist local record");
            if !is_json {
                eprintln!(
                    "{} Activation succeeded but the local registry could not be \
                     updated: {}. Run `pay subscriptions refresh` later to reconcile.",
                    "Warning:".yellow(),
                    e
                );
            }
        } else if ctx.verbose && !is_json {
            eprintln!("{}", "Subscription recorded locally.".dimmed());
        }
    }

    handle_retry_outcome(
        retry_outcome,
        is_json,
        ctx.verbose,
        receipt_network.as_deref(),
        ReceiptProvenance::PaidRetry(None),
    )
}

// `persist_local_subscription_after_activation` lives in
// `pay_core::client::subscription` so the MCP curl tool can reuse the
// same flow without duplicating the pubkey-derivation + RPC-backfill
// boilerplate. CLI calls it through the qualified path below.
use pay_core::client::subscription::persist_local_subscription_after_activation;

fn enforce_subscription_cap(
    decoded: &sub_client::DecodedSubscriptionChallenge,
    payment_cap: u64,
) -> pay_core::Result<()> {
    // Currency is the mint b58 in the wire form; the symbolic label gates
    // whether we can price it against a stablecoin cap. If the label is a
    // known stablecoin symbol we can compare base-units directly.
    if Stablecoin::parse_symbol(&decoded.currency_label).is_some() {
        let required = decoded.amount_base_units.parse::<u64>().map_err(|e| {
            pay_core::Error::Mpp(format!("Invalid amount in subscription challenge: {e}"))
        })?;
        if required <= payment_cap {
            return Ok(());
        }
        return Err(payment_cap_error(
            "MPP subscription",
            &decoded.currency_label,
            required,
            payment_cap,
        ));
    }
    Err(pay_core::Error::PaymentRejected(format!(
        "The automatic payment cap is stablecoin-denominated and cannot price \
         subscription currency `{}` automatically. Re-run without --yolo-upto \
         and approve interactively, or restrict to stablecoin-denominated plans.",
        decoded.currency_label
    )))
}

fn mpp_challenge_currencies(challenges: &[mpp::Challenge]) -> Vec<String> {
    challenges
        .iter()
        .filter_map(|challenge| {
            let request: ChargeRequest = challenge.request.decode().ok()?;
            Some(request.currency)
        })
        .collect()
}

fn mpp_challenge_network(challenge: &mpp::Challenge) -> Option<String> {
    let request = challenge.request.decode_value().ok()?;
    request
        .get("methodDetails")
        .and_then(|details| details.get("network"))
        .or_else(|| request.get("network"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn x402_receipt_network(
    network_override: Option<&str>,
    challenge_network: &str,
    challenge_cluster: Option<&str>,
    recent_blockhash: Option<&str>,
) -> String {
    if let Some(network) = network_override {
        return network.to_string();
    }
    if recent_blockhash.is_some_and(|hash| hash.starts_with(mpp::SURFPOOL_BLOCKHASH_PREFIX)) {
        return "localnet".to_string();
    }
    challenge_cluster.unwrap_or(challenge_network).to_string()
}

/// Distinct networks advertised across MPP challenges, used by error messages
/// to tell the user which networks the server offered.
fn mpp_challenge_networks(challenges: &[mpp::Challenge]) -> Vec<String> {
    let mut out: Vec<String> = challenges
        .iter()
        .filter_map(|challenge| {
            let request: ChargeRequest = challenge.request.decode().ok()?;
            request
                .method_details
                .as_ref()
                .and_then(|v| v.get("network"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn mpp_challenges_json(challenges: &[mpp::Challenge]) -> serde_json::Value {
    let values: Vec<serde_json::Value> = challenges
        .iter()
        .filter_map(|challenge| {
            let request: ChargeRequest = challenge.request.decode().ok()?;
            let network = request
                .method_details
                .as_ref()
                .and_then(|v| v.get("network"))
                .and_then(|v| v.as_str())
                .map(str::to_string);
            Some(serde_json::json!({
                "amount": request.amount,
                "currency": request.currency,
                "recipient": request.recipient,
                "description": request.description,
                "network": network,
            }))
        })
        .collect();
    serde_json::Value::Array(values)
}

fn pay_x402_and_retry(
    challenge: &X402Challenge,
    resource_url: &str,
    ctx: PaymentRetryContext<'_, '_>,
) -> pay_core::Result<()> {
    let is_json = no_dna::should_json(ctx.output_fmt);
    validate_tool_request_before_signing(ctx.tool)?;

    if ctx.verbose && !is_json {
        eprintln!("{}", "Paying...".dimmed());
    }

    let store = pay_core::accounts::FileAccountsStore::default_path();
    let built_payment = x402::build_payment(
        challenge,
        &store,
        ctx.network_override,
        ctx.account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = built_payment.ephemeral_notice {
        render_generated_wallet_notice(&resolved, is_json)?;
    }

    if ctx.verbose && !is_json {
        eprintln!("{}", "Payment signed, retrying...\n".dimmed());
    }

    let receipt_network = x402_receipt_network(
        ctx.network_override,
        &challenge.requirements.network,
        challenge.requirements.cluster.as_deref(),
        challenge.requirements.recent_blockhash.as_deref(),
    );
    let verbose = ctx.verbose;
    let retry_outcome = retry_with_headers(ctx.tool, &built_payment.headers, ctx.fetch_headers)?;
    handle_retry_outcome(
        retry_outcome,
        is_json,
        verbose,
        Some(&receipt_network),
        ReceiptProvenance::PaidRetry(Some(ReceiptDisplayContext {
            asset: Some(&challenge.requirements.currency),
            scheme: Some("exact"),
        })),
    )
}

fn pay_upto_and_retry(
    challenge: &x402::UptoChallenge,
    resource_url: &str,
    ctx: PaymentRetryContext<'_, '_>,
) -> pay_core::Result<()> {
    let is_json = no_dna::should_json(ctx.output_fmt);
    validate_tool_request_before_signing(ctx.tool)?;

    if ctx.verbose && !is_json {
        crate::components::print_notice(
            crate::components::NoticeLevel::Success,
            "Authorizing x402 payment",
            &payment_authorization_notice_body(
                &display_x402_upto_amount(
                    &challenge.requirements.amount,
                    &challenge.requirements.asset,
                ),
                None,
            ),
        );
    }

    let store = pay_core::accounts::FileAccountsStore::default_path();
    let built_payment = x402::build_upto_payment(
        challenge,
        &store,
        ctx.network_override,
        ctx.account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = built_payment.ephemeral_notice {
        render_generated_wallet_notice(&resolved, is_json)?;
    }

    let receipt_network = x402_receipt_network(
        ctx.network_override,
        &challenge.requirements.network,
        None,
        challenge.requirements.extra.recent_blockhash.as_deref(),
    );
    let verbose = ctx.verbose;
    let retry_outcome = retry_with_headers(ctx.tool, &built_payment.headers, ctx.fetch_headers)?;
    handle_retry_outcome(
        retry_outcome,
        is_json,
        verbose,
        Some(&receipt_network),
        ReceiptProvenance::PaidRetry(Some(ReceiptDisplayContext {
            asset: Some(&challenge.requirements.asset),
            scheme: Some("upto"),
        })),
    )
}

fn display_x402_upto_amount(amount: &str, asset: &str) -> String {
    display_token_amount(amount, asset)
}

fn display_token_amount(amount: &str, asset: &str) -> String {
    let Some(stablecoin) = Stablecoin::from_mint(asset).or_else(|| Stablecoin::parse_symbol(asset))
    else {
        return format!("{amount} {}", compact_identifier(asset));
    };
    let display_amount = amount
        .parse::<u64>()
        .map(|amount| format_token_amount(amount, stablecoin.decimals()))
        .unwrap_or_else(|_| amount.to_string());
    format!("{display_amount} {}", stablecoin.symbol())
}

fn format_token_amount(amount: u64, decimals: u8) -> String {
    let divisor = 10_u64.pow(u32::from(decimals));
    let whole = amount / divisor;
    let fraction = amount % divisor;
    if fraction == 0 {
        return whole.to_string();
    }
    let mut fraction = format!("{fraction:0width$}", width = usize::from(decimals));
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{whole}.{fraction}")
}

fn pay_x402_siwx_and_retry(
    challenge: &x402::SiwxAuthChallenge,
    resource_url: &str,
    ctx: PaymentRetryContext<'_, '_>,
) -> pay_core::Result<()> {
    let is_json = no_dna::should_json(ctx.output_fmt);
    validate_tool_request_before_signing(ctx.tool)?;

    if ctx.verbose && !is_json {
        eprintln!("{}", "Signing in...".dimmed());
    }

    let store = pay_core::accounts::FileAccountsStore::default_path();
    let built_payment = x402::build_siwx_auth_header(
        challenge,
        &store,
        ctx.network_override,
        ctx.account_override,
        Some(resource_url),
    )?;

    if let Some(resolved) = built_payment.ephemeral_notice {
        render_generated_wallet_notice(&resolved, is_json)?;
    }

    if ctx.verbose && !is_json {
        eprintln!("{}", "Sign-in signed, retrying...\n".dimmed());
    }

    let receipt_network = ctx.network_override.map(str::to_string);
    let verbose = ctx.verbose;
    let retry_outcome = retry_with_headers(ctx.tool, &built_payment.headers, ctx.fetch_headers)?;
    handle_retry_outcome(
        retry_outcome,
        is_json,
        verbose,
        receipt_network.as_deref(),
        ReceiptProvenance::NonPaymentRetry,
    )
}

#[allow(clippy::too_many_arguments)]
fn pay_session_and_retry(
    challenge: &mpp::Challenge,
    req: Option<&SessionRequest>,
    tool: &Tool,
    output_fmt: Option<OutputFormat>,
    fetch_headers: Option<Vec<(String, String)>>,
    network_override: Option<&str>,
    account_override: Option<&str>,
    sandbox: bool,
    verbose: bool,
) -> pay_core::Result<()> {
    use pay_kit::mpp::{SessionMode, SessionPullVoucherStrategy};

    let is_json = no_dna::should_json(output_fmt);
    validate_tool_request_before_signing(tool)?;

    // Deposit = min_voucher_delta * 1000, clamped to [1 USDC, cap].
    let min_delta = req
        .and_then(|r| r.min_voucher_delta.as_deref())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1_000);
    let cap = req
        .and_then(|r| r.cap.parse::<u64>().ok())
        .unwrap_or(1_000_000);
    let deposit = (min_delta * 1_000).max(1_000_000).min(cap);
    let cap_display = req
        .map(|request| display_token_amount(&request.cap, &request.currency))
        .unwrap_or_else(|| format!("{cap} base units"));
    let deposit_display = req
        .map(|request| display_token_amount(&deposit.to_string(), &request.currency))
        .unwrap_or_else(|| format!("{deposit} base units"));

    if verbose && !is_json {
        crate::components::print_notice(
            crate::components::NoticeLevel::Success,
            "Authorizing MPP session",
            &payment_authorization_notice_body(&cap_display, Some(&deposit_display)),
        );
    }

    let supports_push = req
        .map(|r| r.modes.is_empty() || r.modes.contains(&SessionMode::Push))
        .unwrap_or(true);
    let use_pull = req
        .map(|r| {
            r.modes.contains(&SessionMode::Pull)
                && (!supports_push
                    || matches!(
                        r.pull_voucher_strategy.as_ref(),
                        Some(SessionPullVoucherStrategy::ClientVoucher)
                    ))
        })
        .unwrap_or(false);

    let auth_header = if use_pull {
        let Some(request) = req else {
            return Err(pay_core::Error::Mpp(
                "pull-mode session requires a decoded SessionRequest".to_string(),
            ));
        };

        let store = pay_core::accounts::FileAccountsStore::default_path();
        match request.pull_voucher_strategy.as_ref() {
            Some(SessionPullVoucherStrategy::ClientVoucher) => {
                let (_handle, header) =
                    pay_core::session::open_payment_channel_session_header_with_mode(
                        challenge,
                        request,
                        &store,
                        network_override,
                        account_override,
                        deposit,
                        SessionMode::Pull,
                        sandbox,
                    )?;
                header
            }
            Some(SessionPullVoucherStrategy::OperatedVoucher) => {
                return Err(pay_core::Error::Mpp(
                    "operated-voucher pull sessions are no longer supported; \
                     use a client-voucher payment-channel session instead"
                        .to_string(),
                ));
            }
            None => {
                return Err(pay_core::Error::Mpp(
                    "pull-mode session challenge missing pullVoucherStrategy".to_string(),
                ));
            }
        }
    } else {
        if let Some(request) = req {
            let store = pay_core::accounts::FileAccountsStore::default_path();
            let (_handle, header) = pay_core::session::open_payment_channel_session_header(
                challenge,
                request,
                &store,
                network_override,
                account_override,
                deposit,
                sandbox,
            )?;
            header
        } else {
            let (_handle, header) = pay_core::session::open_session_header(challenge, deposit)?;
            header
        }
    };

    let receipt_network = network_override
        .map(str::to_string)
        .or_else(|| mpp_challenge_network(challenge));
    let retry_outcome = retry_with_header(tool, "Authorization", &auth_header, fetch_headers)?;
    handle_retry_outcome(
        retry_outcome,
        is_json,
        verbose,
        receipt_network.as_deref(),
        ReceiptProvenance::PaidRetry(None),
    )
}

fn payment_authorization_notice_body(limit: &str, deposit: Option<&str>) -> String {
    let mut body = format!("Spending limit: {limit}\n");
    if let Some(deposit) = deposit {
        body.push_str(&format!("Channel deposit: {deposit}\n"));
    }
    body.push_str("Approve in your wallet to retry the request.");
    body
}

fn validate_tool_request_before_signing(tool: &Tool) -> pay_core::Result<()> {
    match tool {
        Tool::Curl(args) => pay_core::runner::validate_curl_args_against_catalog(args),
        Tool::Fetch {
            method,
            url,
            body,
            validation_body,
            content_type,
            ..
        } if body.is_some() && validation_body.is_none() => {
            pay_core::skills::validate_cached_catalog_opaque_request(
                method,
                url,
                content_type.unwrap_or("application/octet-stream"),
            )
        }
        Tool::Fetch {
            method,
            url,
            validation_body,
            ..
        } => pay_core::skills::validate_cached_catalog_request(method, url, *validation_body),
        Tool::Wget(args) => pay_core::runner::validate_wget_args_against_catalog(args),
        // TODO: catalog validation for HTTPie request-item syntax
        // (`Header:Value`, `field=value`, `field:=raw`, …).
        Tool::Http(_) => Ok(()),
    }
}

/// Render the "Generated <network> wallet" notice when an ephemeral
/// wallet was just lazy-created. Visible only in text mode — JSON output
/// gets the same info as a structured side-channel field via stderr so
/// pipelines don't break.
fn render_generated_wallet_notice(
    resolved: &pay_core::accounts::ResolvedEphemeral,
    is_json: bool,
) -> pay_core::Result<()> {
    if is_json {
        // Print to stderr so the program's primary stdout (the API
        // response body) stays clean for piping.
        let payload = serde_json::json!({
            "event": "ephemeral_wallet_created",
            "network": resolved.network,
            "account": resolved.account_name,
            "pubkey": resolved.account.pubkey,
        });
        eprintln!("{payload}");
        return Ok(());
    }
    let pubkey = resolved.account.pubkey.as_deref().unwrap_or("(unknown)");
    let body = format!(
        "{}\nStored at ~/.config/pay/accounts.yml — reused on subsequent runs.",
        pubkey
    );
    crate::components::print_notice(
        crate::components::NoticeLevel::Info,
        &format!("Generated {} wallet", resolved.network),
        &body,
    );
    Ok(())
}

fn retry_with_header(
    tool: &Tool,
    header_name: &str,
    header_value: &str,
    fetch_headers: Option<Vec<(String, String)>>,
) -> pay_core::Result<RunOutcome> {
    retry_with_headers(
        tool,
        &[(header_name, header_value.to_string())],
        fetch_headers,
    )
}

fn retry_with_headers(
    tool: &Tool,
    headers_to_add: &[(&str, String)],
    fetch_headers: Option<Vec<(String, String)>>,
) -> pay_core::Result<RunOutcome> {
    match tool {
        Tool::Curl(args) => {
            let extra = retry_header_args(headers_to_add);
            run_curl_with_headers(args, &extra)
        }
        Tool::Wget(args) => {
            let extra = retry_header_args(headers_to_add);
            run_wget_with_headers(args, &extra)
        }
        Tool::Http(args) => {
            let extra = retry_header_args_httpie(headers_to_add);
            run_httpie_with_headers(args, &extra)
        }
        Tool::Fetch {
            method,
            url,
            body,
            redirect_policy,
            ..
        } => {
            let mut headers = fetch_headers.unwrap_or_default();
            headers.extend(
                headers_to_add
                    .iter()
                    .map(|(name, value)| (name.to_string(), value.clone())),
            );
            pay_core::fetch::fetch_request_with_body_for(
                pay_core::ClientApp::Cli,
                method,
                url,
                &headers,
                *body,
                *redirect_policy,
            )
        }
    }
}

fn retry_header_args(headers_to_add: &[(&str, String)]) -> Vec<String> {
    headers_to_add
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect()
}

/// Format headers as HTTPie request items: `Name:value` (no space after colon).
fn retry_header_args_httpie(headers_to_add: &[(&str, String)]) -> Vec<String> {
    headers_to_add
        .iter()
        .map(|(name, value)| format!("{name}:{value}"))
        .collect()
}

fn handle_retry_outcome(
    outcome: RunOutcome,
    is_json: bool,
    verbose: bool,
    receipt_network: Option<&str>,
    provenance: ReceiptProvenance<'_>,
) -> pay_core::Result<()> {
    match outcome {
        RunOutcome::Completed {
            exit_code,
            body,
            response_headers,
            ..
        } => {
            print_verbose_receipt(
                &response_headers,
                receipt_network,
                provenance,
                verbose,
                is_json,
            );
            if let Some(body) = body {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&body);
            }
            std::process::exit(exit_code);
        }
        RunOutcome::PaymentRejected {
            reason, retryable, ..
        } => {
            if is_json {
                output::error_json(&format!("Payment rejected by verifier: {reason}"));
            } else {
                let body = if retryable {
                    format!("{reason}\n(retryable — try again)")
                } else {
                    reason
                };
                crate::components::print_notice(
                    crate::components::NoticeLevel::Error,
                    "Payment rejected by verifier",
                    &body,
                );
            }
            std::process::exit(1);
        }
        _ => {
            if is_json {
                output::error_json("Server returned 402 again after payment");
            } else {
                eprintln!(
                    "{}",
                    "Error: Server returned 402 again after payment.".dimmed()
                );
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbose_challenge_rendering_groups_decoded_protocols() {
        let challenges = DecodedPaymentChallenges {
            x402: vec![serde_json::json!({
                "scheme": "upto",
                "amount": "250000",
                "asset": "USDC",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "payTo": "x402-recipient"
            })],
            mpp: vec![serde_json::json!({
                "intent": "charge",
                "method": "solana",
                "realm": "Example provider",
                "request": {
                    "amount": "10",
                    "currency": "USDC",
                    "network": "mainnet"
                }
            })],
        };

        let rendered = render_verbose_challenges(&challenges).unwrap();
        assert!(rendered.starts_with('+'));
        assert!(!rendered.contains("402 payment offers"));
        assert!(rendered.contains("| Protocol"));
        assert!(rendered.contains("Terms"));
        assert!(!rendered.contains("Recipient / Realm"));
        assert!(!rendered.contains("x402-recipient"));
        assert!(!rendered.contains("Example provider"));
        assert!(rendered.contains("x402/upto"));
        assert!(rendered.contains("mpp/charge"));
        assert!(rendered.contains("up to 0.25 USDC"));
        assert!(rendered.contains("0.00001 USDC"));
        assert_eq!(rendered.matches("Solana mainnet").count(), 2);
        assert_eq!(
            rendered
                .lines()
                .filter(|line| line.starts_with('+'))
                .count(),
            3
        );
        assert!(rendered.lines().all(|line| line.chars().count() <= 80));
    }

    #[test]
    fn verbose_session_challenge_reports_cap_and_currency() {
        let row = challenge_summary_row(
            "mpp",
            &serde_json::json!({
                "intent": "session",
                "method": "solana",
                "realm": "Alibaba Cloud Model Studio",
                "request": {
                    "cap": "100000",
                    "currency": pay_types::stablecoin_mints::USDG_MAINNET,
                    "network": "mainnet"
                }
            }),
        );

        assert_eq!(row, ["mpp/session", "up to 0.1 USDG", "Solana mainnet"]);
    }

    #[test]
    fn verbose_challenge_rendering_skips_empty_responses() {
        assert!(render_verbose_challenges(&DecodedPaymentChallenges::default()).is_none());
    }

    #[test]
    fn verbose_receipt_rendering_decodes_x402_and_links_advanced_view() {
        let headers = vec![(
            "payment-response".to_string(),
            "eyJzdWNjZXNzIjp0cnVlLCJwYXllciI6IkNIUEVnRjdYMWhZSmY2NG9SeDUzQUJVTDQzRFhwRWpUSkJ6QVltWldOdUtSIiwidHJhbnNhY3Rpb24iOiIzMkVUZU1aRDd3cjVnNTlqWlZFNHljVzZlTndWaTVSaHY5a1dBSFlWWlFBTWdMclJqeHNXWVFjc2ZaSEJGQkRGUWdFOHhEZzR0VDR1VENQcTdYNkpWWmlmIiwibmV0d29yayI6InNvbGFuYTo1ZXlrdDRVc0Z2OFA4TkpkVFJFcFkxdnpxS3FaS3ZkcCIsImFtb3VudCI6IjExIn0=".to_string(),
        )];

        let rendered = render_verbose_receipt(&headers, Some("sandbox"), None).unwrap();
        assert_eq!(rendered.title, "11 paid via x402");
        assert!(rendered.body.contains("Link to receipt"));
        assert!(rendered.body.contains("32ETeMZD7wr5g59j"));
    }

    #[test]
    fn verbose_receipt_rendering_prefers_server_receipt_url() {
        let headers = vec![
            (
                "payment-response".to_string(),
                "direct-settlement-signature".to_string(),
            ),
            (
                "Payment-Receipt-Url".to_string(),
                "https://receipts.example/authoritative".to_string(),
            ),
        ];

        let rendered = render_verbose_receipt(&headers, Some("sandbox"), None).unwrap();
        assert_eq!(rendered.title, "Payment paid via x402");
        assert!(
            rendered
                .body
                .contains("https://receipts.example/authoritative")
        );
        assert!(!rendered.body.contains("pay.sh/receipt"));
    }

    #[test]
    fn verbose_receipt_rendering_supports_url_only_response() {
        let headers = vec![(
            "payment-receipt-url".to_string(),
            "https://receipts.example/url-only".to_string(),
        )];

        let rendered = render_verbose_receipt(&headers, None, None).unwrap();
        assert_eq!(rendered.title, "Payment completed");
        assert!(rendered.body.contains("Link to receipt"));
        assert!(rendered.body.contains("https://receipts.example/url-only"));
    }

    #[test]
    fn verbose_receipt_rendering_decodes_mpp_receipt() {
        let receipt = pay_kit::mpp::ReceiptKind::Charge(pay_kit::mpp::Receipt::success(
            "solana",
            "mpp-settlement-signature",
            "challenge-1",
        ));
        let header = pay_kit::mpp::format_receipt(&receipt).unwrap();
        let headers = vec![("payment-receipt".to_string(), header)];

        let rendered = render_verbose_receipt(&headers, Some("localnet"), None).unwrap();
        assert_eq!(rendered.title, "Payment paid via mpp");
        assert!(rendered.body.contains("Link to receipt"));
        assert!(rendered.body.contains("mpp-settlement-signature"));
    }

    #[test]
    fn x402_receipt_network_distinguishes_devnet_from_surfpool() {
        let devnet = pay_kit::x402::exact::SOLANA_DEVNET;
        assert_eq!(x402_receipt_network(None, devnet, None, None), devnet);
        assert_eq!(
            x402_receipt_network(
                None,
                devnet,
                None,
                Some("SURFNETxSAFEHASHxxxxxxxxxxxxxxxxxxx18b8dc98"),
            ),
            "localnet"
        );
        assert_eq!(
            x402_receipt_network(Some("mainnet"), devnet, None, None),
            "mainnet"
        );
    }

    #[test]
    fn amount_as_stablecoin_micro_treats_known_stablecoins_as_six_decimals() {
        assert_eq!(
            amount_as_stablecoin_micro("1250000", "USDC").unwrap(),
            1_250_000
        );
        assert_eq!(amount_as_stablecoin_micro("5000", "CASH").unwrap(), 5_000);
        assert_eq!(amount_as_stablecoin_micro("5000", "USDG").unwrap(), 5_000);
        assert_eq!(
            amount_as_stablecoin_micro("1000000", pay_types::stablecoin_mints::USDC_MAINNET,)
                .unwrap(),
            1_000_000
        );
        assert_eq!(
            amount_as_stablecoin_micro("1000000", pay_types::stablecoin_mints::USDG_MAINNET)
                .unwrap(),
            1_000_000
        );
    }

    #[test]
    fn amount_as_stablecoin_micro_rejects_sol_under_stablecoin_cap() {
        assert!(amount_as_stablecoin_micro("1000000000", "SOL").is_err());
    }

    #[test]
    fn mpp_cap_filter_skips_unpriced_assets_when_stablecoin_fits() {
        let challenges = vec![
            mpp_challenge("SOL", "1000000000"),
            mpp_challenge("USDC", "500000"),
        ];
        let allowed = mpp_challenges_within_cap(&challenges, 1_000_000).unwrap();
        assert_eq!(allowed.len(), 1);
        let request: ChargeRequest = allowed[0].request.decode().unwrap();
        assert_eq!(request.currency, "USDC");
    }

    #[test]
    fn mpp_cap_filter_rejects_when_only_unpriced_assets_are_available() {
        let challenges = vec![mpp_challenge("SOL", "1000000000")];
        let err = mpp_challenges_within_cap(&challenges, 1_000_000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot price advertised MPP currencies"));
    }

    fn mpp_challenge(currency: &str, amount: &str) -> mpp::Challenge {
        let request = serde_json::json!({
            "amount": amount,
            "currency": currency,
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": { "network": "mainnet" }
        });
        mpp::Challenge::new(
            currency,
            "test",
            "solana",
            "charge",
            pay_kit::mpp::Base64UrlJson::from_value(&request).unwrap(),
        )
    }

    #[test]
    fn format_stablecoin_amount_trims_fraction() {
        assert_eq!(format_stablecoin_amount(1_000_000), "1");
        assert_eq!(format_stablecoin_amount(1_250_000), "1.25");
        assert_eq!(format_stablecoin_amount(1), "0.000001");
    }

    #[test]
    fn display_amount_resolves_mint_and_decimals() {
        let amount = serde_json::json!({
            "amount": "250000",
            "asset": pay_types::stablecoin_mints::USDC_MAINNET,
        });
        assert_eq!(format_amount(&amount), "0.25 USDC");
    }

    #[test]
    fn receipt_protocol_label_includes_the_payment_scheme() {
        assert_eq!(
            receipt_protocol_label(
                receipt::ReceiptProtocol::X402,
                &serde_json::json!({ "accepted": { "scheme": "upto" } }),
                None,
            ),
            "x402 / upto"
        );
        assert_eq!(
            receipt_protocol_label(
                receipt::ReceiptProtocol::Mpp,
                &serde_json::json!({ "intent": "charge" }),
                None,
            ),
            "mpp / charge"
        );
    }

    #[test]
    fn receipt_uses_selected_payment_metadata_when_server_omits_it() {
        let headers = vec![(
            "payment-response".to_string(),
            r#"{"amount":"11"}"#.to_string(),
        )];
        let rendered = render_verbose_receipt(
            &headers,
            None,
            Some(ReceiptDisplayContext {
                asset: Some(pay_types::stablecoin_mints::USDC_MAINNET),
                scheme: Some("exact"),
            }),
        )
        .unwrap();
        assert_eq!(rendered.title, "0.000011 USDC paid via x402 / exact");
    }

    #[test]
    fn receipt_title_strips_server_supplied_terminal_controls() {
        let headers = vec![(
            "payment-response".to_string(),
            r#"{"amount":"11","asset":"USDC\u001b","scheme":"exact\u0007"}"#.to_string(),
        )];

        let rendered = render_verbose_receipt(&headers, None, None).unwrap();

        assert!(!rendered.title.contains('\u{1b}'));
        assert!(!rendered.title.contains('\u{7}'));
        assert_eq!(rendered.title, "11 USDC paid via x402 / exact");
    }

    #[test]
    fn initial_response_never_renders_a_payment_receipt() {
        let headers = vec![(
            "payment-receipt-url".to_string(),
            "https://receipts.example/unpaid".to_string(),
        )];

        assert!(
            render_receipt_for_completion(&headers, None, ReceiptProvenance::InitialRequest,)
                .is_none()
        );
    }

    #[test]
    fn sign_in_retry_never_renders_a_payment_receipt() {
        let headers = vec![(
            "payment-receipt-url".to_string(),
            "https://receipts.example/sign-in".to_string(),
        )];

        assert!(
            render_receipt_for_completion(&headers, None, ReceiptProvenance::NonPaymentRetry,)
                .is_none()
        );
    }

    #[test]
    fn x402_upto_notice_uses_a_human_stablecoin_amount() {
        assert_eq!(
            display_x402_upto_amount("250000", pay_types::stablecoin_mints::USDC_MAINNET),
            "0.25 USDC"
        );
    }

    #[test]
    fn x402_upto_notice_uses_shared_authorization_copy() {
        let body = payment_authorization_notice_body("0.25 USDC", None);
        assert_eq!(
            body,
            "Spending limit: 0.25 USDC\nApprove in your wallet to retry the request."
        );
    }

    #[test]
    fn mpp_session_notice_adds_deposit_to_shared_authorization_copy() {
        let body = payment_authorization_notice_body("0.1 USDG", Some("0.1 USDG"));

        assert_eq!(
            body,
            "Spending limit: 0.1 USDG\n\
             Channel deposit: 0.1 USDG\n\
             Approve in your wallet to retry the request."
        );
        assert!(!body.to_ascii_lowercase().contains("push"));
        assert!(!body.to_ascii_lowercase().contains("pull"));
    }

    #[test]
    fn tool_kind_curl() {
        let cmd = Command::Curl(curl::CurlCommand {
            args: vec!["https://example.com".to_string()],
        });
        assert!(matches!(cmd.tool_kind(), ToolKind::Curl));
    }

    #[test]
    fn tool_kind_wget() {
        let cmd = Command::Wget(wget::WgetCommand {
            args: vec!["https://example.com".to_string()],
        });
        assert!(matches!(cmd.tool_kind(), ToolKind::Wget));
    }

    #[test]
    fn tool_kind_mcp() {
        assert!(matches!(Command::Mcp.tool_kind(), ToolKind::Mcp));
    }

    #[test]
    fn x402_retry_supports_v1_and_v2_header_names() {
        assert_eq!(pay_core::x402::X402_V1_PAYMENT_HEADER, "X-PAYMENT");
        assert_eq!(pay_core::x402::X402_V2_PAYMENT_HEADER, "PAYMENT-SIGNATURE");
        assert_eq!(pay_core::x402::SIGN_IN_WITH_X_HEADER, "SIGN-IN-WITH-X");
    }

    #[test]
    fn retry_header_args_preserves_multiple_x402_headers() {
        let headers = retry_header_args(&[
            (
                pay_core::x402::X402_V2_PAYMENT_HEADER,
                "payment".to_string(),
            ),
            (pay_core::x402::SIGN_IN_WITH_X_HEADER, "sign-in".to_string()),
        ]);

        assert_eq!(
            headers,
            vec![
                "PAYMENT-SIGNATURE: payment".to_string(),
                "SIGN-IN-WITH-X: sign-in".to_string()
            ]
        );
    }
}
