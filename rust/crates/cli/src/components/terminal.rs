//! Helpers for safely rendering untrusted values in a terminal.

/// Remove C0, DEL, and C1 controls from untrusted terminal text.
///
/// ANSI, OSC, and other terminal escape sequences are composed from these
/// controls. Keep generated formatting separate and sanitize remote values
/// before including them in display text or hyperlink targets.
pub(crate) fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_c0_del_and_c1_controls() {
        assert_eq!(sanitize_terminal_text("ok\u{1b}[2J\u{7f}\u{9b}x"), "ok[2Jx");
    }
}
