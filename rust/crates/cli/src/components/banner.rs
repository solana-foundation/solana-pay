//! Shared Pay banner rendering for human CLI output.

pub const PAY_SH_BANNER: &[&str] = &[
    "██████╗  █████╗ ██╗   ██╗   ███████╗██╗  ██╗",
    "██╔══██╗██╔══██╗╚██╗ ██╔╝   ██╔════╝██║  ██║",
    "██████╔╝███████║ ╚████╔╝    ███████╗███████║",
    "██╔═══╝ ██╔══██║  ╚██╔╝     ╚════██║██╔══██║",
    "██║     ██║  ██║   ██║   ██╗███████║██║  ██║",
    "╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝╚═╝  ╚═╝",
];
pub const PAY_SH_TAGLINE: &str = "Toolchain for agentic payments";

/// Render the banner used at the top of human help output.
pub fn help_banner() -> String {
    render_banner(PAY_SH_TAGLINE)
}

/// Render the Pay banner with a leading blank line.
pub fn render_banner(tagline: impl std::fmt::Display) -> String {
    if crate::no_dna::is_agent() {
        return String::new();
    }

    render_banner_art(tagline)
}

fn render_banner_art(tagline: impl std::fmt::Display) -> String {
    let mut output = String::from("\n");
    output.push_str(
        &PAY_SH_BANNER
            .iter()
            .enumerate()
            .map(|(row, line)| gradient_line(line, row, PAY_SH_BANNER.len()))
            .collect::<Vec<_>>()
            .join("\n"),
    );
    output.push_str(&format!("\n{tagline}"));
    output
}

/// Render one banner row with the vertical white-to-gray gradient used by
/// `pay gate api`.
pub fn gradient_line(line: &str, row: usize, row_count: usize) -> String {
    let mut rendered = String::new();
    let vertical_position = if row_count <= 1 {
        1.0
    } else {
        1.0 - row as f32 / (row_count - 1) as f32
    };
    let (r, g, b) = banner_gradient_color(vertical_position);

    for ch in line.chars() {
        if ch == ' ' {
            rendered.push(ch);
            continue;
        }

        rendered.push_str(&format!("\x1b[1;38;2;{r};{g};{b}m{ch}\x1b[0m"));
    }

    rendered
}

fn banner_gradient_color(position: f32) -> (u8, u8, u8) {
    lerp_rgb((86, 86, 86), (255, 255, 255), position)
}

fn lerp_rgb(from: (u8, u8, u8), to: (u8, u8, u8), t: f32) -> (u8, u8, u8) {
    (
        lerp_channel(from.0, to.0, t),
        lerp_channel(from.1, to.1, t),
        lerp_channel(from.2, to.2, t),
    )
}

fn lerp_channel(from: u8, to: u8, t: f32) -> u8 {
    (from as f32 + (to as f32 - from as f32) * t).round() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_art_starts_at_column_zero_after_blank_line() {
        let banner = render_banner_art(PAY_SH_TAGLINE);

        assert!(banner.starts_with("\n\x1b["));
        assert!(!banner.starts_with("\n "));
        assert!(banner.ends_with(&format!("\n{PAY_SH_TAGLINE}")));
        assert!(!banner.ends_with(&format!("\n  {PAY_SH_TAGLINE}")));
    }
}
