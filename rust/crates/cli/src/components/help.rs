//! Shared help text blocks for the CLI.

pub const ROOT_HELP_TEMPLATE: &str = "\
{before-help}{about-section}{usage-heading} {usage}{after-help}

Options:
{options}";

pub const SUPPORTED_PASS_THROUGH_COMMANDS: &[&str] = &[
    "curl", "wget", "http", "claude", "codex", "goose", "qodercli", "whoami",
];
pub const DEVELOPER_COMMANDS: &[&str] = &["server", "catalog"];
pub const AGENT_COMMANDS: &[&str] = &["mcp", "skills"];
pub const ACCOUNT_MANAGEMENT_COMMANDS: &[&str] =
    &["topup", "account", "setup", "send", "subscriptions"];
pub const OTHER_COMMANDS: &[&str] = &["fetch", "install"];

pub const ROOT_COMMAND_SUMMARY: &str = "\
Supported pass-through:
  \x1b[1mcurl\x1b[0m, \x1b[1mwget\x1b[0m, \x1b[1mhttp\x1b[0m, \x1b[1mclaude\x1b[0m, \x1b[1mcodex\x1b[0m, \x1b[1mgoose\x1b[0m, \x1b[1mqodercli\x1b[0m, \x1b[1mwhoami\x1b[0m

Developers:
  \x1b[1mserver\x1b[0m:  Gate your API with stablecoin payments
  \x1b[1mcatalog\x1b[0m: Make your API discoverable in pay's public catalog

Agents:
  \x1b[1mmcp\x1b[0m:    Start the MCP server for agent clients
  \x1b[1mskills\x1b[0m: Browse, search, and inspect API providers from the skills catalog

Account management:
  \x1b[1mtopup\x1b[0m:         Import funds from Venmo, PayPal, or a mobile wallet.
  \x1b[1maccount\x1b[0m:       Manage accounts (new, import, list, default, remove, export)
  \x1b[1msetup\x1b[0m:         Generate a keypair, store it, and fund your account
  \x1b[1msend\x1b[0m:          Send stablecoins to a recipient address
  \x1b[1msubscriptions\x1b[0m: Manage MPP subscription delegations (list, new, cancel, status)

Other:
  \x1b[1mfetch\x1b[0m:   Fetch a URL using the built-in HTTP client (no external tool required)
  \x1b[1minstall\x1b[0m: Add a provider source (shorthand for `skills add`)
";
