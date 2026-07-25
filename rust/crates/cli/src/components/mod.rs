//! Reusable display components for CLI output (links, notices, etc.).

pub mod account;
pub(crate) mod ascii_table;
pub mod banner;
pub mod help;
pub mod link;
pub mod log_format;
pub mod notice;
pub(crate) mod terminal;

pub use account::{
    explorer_link, format_account_header, print_balance_unavailable, print_balances,
    print_topup_note,
};
pub use banner::{
    PAY_SH_BANNER, PAY_SH_TAGLINE, gradient_line as gradient_banner_line,
    help_banner as pay_help_banner, render_banner as render_pay_banner,
};
pub use help::{
    ACCOUNT_MANAGEMENT_COMMANDS, AGENT_COMMANDS, DEVELOPER_COMMANDS, OTHER_COMMANDS,
    ROOT_COMMAND_SUMMARY, ROOT_HELP_TEMPLATE, SUPPORTED_PASS_THROUGH_COMMANDS,
};
pub use link::{link, link_with_arrow, solana_explorer_cluster_query, solana_transaction_link};
pub use notice::{
    NoticeLevel, notice, notice_body, print_notice, print_notice_with_machine_output,
};
