//! Styled notice box for CLI output.
//!
//! Renders a colored rail followed by a bold title and dimmed body:
//!
//! ```text
//! │ Title of the notice
//! │ First line of the body.
//! │ Second line of the body.
//! ```

use owo_colors::OwoColorize;

/// Severity of a notice — determines the rail color.
#[derive(Debug, Clone, Copy)]
pub enum NoticeLevel {
    Info,
    Success,
    Warning,
    Error,
}

impl NoticeLevel {
    fn rail(&self) -> String {
        match self {
            Self::Info => "│".blue().bold().to_string(),
            Self::Success => "│".green().bold().to_string(),
            Self::Warning => "│".yellow().bold().to_string(),
            Self::Error => "│".red().bold().to_string(),
        }
    }
}

/// Render a notice with a title and multi-line body.
///
/// The title is bold; body lines are dimmed and carry the same colored rail.
pub fn notice(level: NoticeLevel, title: &str, body: &str) -> String {
    let rail = level.rail();
    let title = title.bold();
    let mut out = format!("{rail} {title}\n");
    for line in body.lines() {
        out.push_str(&format!("{rail} {}\n", line.dimmed()));
    }
    out
}

/// Render body lines inside a colored notice rail without adding a title.
///
/// Useful when a preceding log line already supplies the title and the next
/// content (such as an ASCII table) should remain visually connected to it.
pub fn notice_body(level: NoticeLevel, body: &str) -> String {
    let rail = level.rail();
    let mut out = String::new();
    for line in body.lines() {
        out.push_str(&format!("{rail} {}\n", line.dimmed()));
    }
    out
}

/// Print a notice to stderr, using compact text when NO_DNA is active.
pub fn print_notice(level: NoticeLevel, title: &str, body: &str) {
    if crate::no_dna::is_agent() {
        eprint!("{}", agent_notice(title, body));
    } else {
        eprint!("{}", notice(level, title, body));
    }
}

/// Print a notice, or in NO_DNA mode print a compact title to stderr and
/// machine-readable output to stdout.
pub fn print_notice_with_machine_output(
    level: NoticeLevel,
    title: &str,
    body: &str,
    machine_output: &str,
) {
    if crate::no_dna::is_agent() {
        eprintln!("{}", title.dimmed());
        println!("{machine_output}");
    } else {
        print_notice(level, title, body);
    }
}

fn agent_notice(title: &str, body: &str) -> String {
    let mut out = format!("{}\n", title.dimmed());
    for line in body.lines() {
        out.push_str(&format!("{}\n", line.dimmed()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(input: &str) -> String {
        let mut out = String::new();
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\x1b' && chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn warning_notice_uses_colored_rail_without_outer_indent() {
        let rendered = notice(NoticeLevel::Warning, "Payment rejected", "declined");

        assert!(!rendered.contains("\x1b[43m"));
        assert!(!rendered.contains('⚠'));
        assert_eq!(strip_ansi(&rendered), "│ Payment rejected\n│ declined\n");
    }

    #[test]
    fn non_warning_notice_uses_rail_without_outer_indent() {
        let rendered = notice(NoticeLevel::Info, "Wallet generated", "ready");

        assert_eq!(strip_ansi(&rendered), "│ Wallet generated\n│ ready\n");
    }

    #[test]
    fn notice_body_keeps_every_table_line_on_the_same_rail() {
        let rendered = notice_body(NoticeLevel::Info, "+--+\n|x |\n+--+");

        assert_eq!(strip_ansi(&rendered), "│ +--+\n│ |x |\n│ +--+\n");
    }

    #[test]
    fn agent_notice_omits_rail() {
        let rendered = agent_notice("Payment rejected", "declined\ntry again");

        assert_eq!(
            strip_ansi(&rendered),
            "Payment rejected\ndeclined\ntry again\n"
        );
    }
}
