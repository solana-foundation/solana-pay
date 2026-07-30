//! Terminal plumbing: raw-mode/alternate-screen lifecycle and a backend
//! wrapper that degrades 24-bit RGB colors on terminals without truecolor.

use std::io;

use crossterm::event::{
    DisableBracketedPaste, DisableFocusChange, EnableBracketedPaste, EnableFocusChange,
};
use crossterm::execute;
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::Terminal;
use ratatui::backend::{Backend, CrosstermBackend, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Position, Size};
use ratatui::style::Color;

/// Braille spinner frames shared by the TUI status lines (ticks every ~80ms).
pub(crate) const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// Concrete backend used by every render function: a [`CrosstermBackend`]
/// wrapped so 24-bit RGB colors degrade gracefully on terminals that can't
/// render them.
pub(crate) type TuiBackend = DowngradeBackend<io::Stderr>;

/// True when the terminal advertises 24-bit ("truecolor") support via the
/// `COLORTERM` environment variable. macOS Terminal.app does NOT set this and
/// does not support truecolor: it mis-parses `\x1b[48;2;r;g;b` sequences, and
/// values like `Rgb(39, 39, 42)` leak their trailing `42` as ANSI SGR 42
/// ("green background"), which then sticks and floods the screen. Defaulting
/// to `false` when unset is intentional — downgrading to 256-color is always
/// safe, whereas emitting truecolor to a terminal that can't parse it is not.
fn supports_truecolor() -> bool {
    matches!(
        std::env::var("COLORTERM").as_deref(),
        Ok("truecolor") | Ok("24bit")
    )
}

/// Map an 8-bit color component to the nearest level of the xterm 6×6×6 color
/// cube, returning `(cube_index, level_value)`.
fn cube_level(v: u8) -> (u8, u8) {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let mut best = 0usize;
    let mut best_dist = i32::MAX;
    for (i, &level) in LEVELS.iter().enumerate() {
        let dist = (level as i32 - v as i32).abs();
        if dist < best_dist {
            best_dist = dist;
            best = i;
        }
    }
    (best as u8, LEVELS[best])
}

/// Nearest xterm-256 palette index for an RGB triple, picking whichever of the
/// 6×6×6 color cube (16..=231) or the 24-step grayscale ramp (232..=255) is
/// closest in squared-distance.
fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    let sq = |a: u8, b: u8| {
        let d = a as i32 - b as i32;
        d * d
    };
    let (ri, rv) = cube_level(r);
    let (gi, gv) = cube_level(g);
    let (bi, bv) = cube_level(b);
    let cube_idx = 16 + 36 * ri + 6 * gi + bi;
    let cube_dist = sq(rv, r) + sq(gv, g) + sq(bv, b);

    // Grayscale ramp: 24 shades at values 8, 18, … 238.
    let avg = (r as i32 + g as i32 + b as i32) / 3;
    let gray_i = ((avg - 8).max(0) / 10).min(23) as u8;
    let gray_v = 8 + 10 * gray_i;
    let gray_idx = 232 + gray_i;
    let gray_dist = sq(gray_v, r) + sq(gray_v, g) + sq(gray_v, b);

    if gray_dist < cube_dist {
        gray_idx
    } else {
        cube_idx
    }
}

/// Rewrite a 24-bit RGB color to the nearest 256-palette entry; pass every
/// other color (named, indexed, reset) through untouched.
fn downgrade_color(color: Color) -> Color {
    match color {
        Color::Rgb(r, g, b) => Color::Indexed(rgb_to_ansi256(r, g, b)),
        other => other,
    }
}

/// Backend wrapper that rewrites 24-bit RGB colors to the nearest 256-color
/// palette entry before they reach the terminal. Only active when `downgrade`
/// is set (terminal lacks truecolor); otherwise every call forwards unchanged.
pub(crate) struct DowngradeBackend<W: io::Write> {
    inner: CrosstermBackend<W>,
    downgrade: bool,
}

impl<W: io::Write> DowngradeBackend<W> {
    fn new(inner: CrosstermBackend<W>, downgrade: bool) -> Self {
        Self { inner, downgrade }
    }
}

// `Terminal` leaves the alternate screen via `execute!(backend_mut(), …)`,
// which needs the backend to be a `Write`; forward to the inner backend.
impl<W: io::Write> io::Write for DowngradeBackend<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::Write::flush(&mut self.inner)
    }
}

impl<W: io::Write> Backend for DowngradeBackend<W> {
    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        if !self.downgrade {
            return self.inner.draw(content);
        }
        // Clone each cell, downgrade its colors, then forward owned copies.
        let cells: Vec<(u16, u16, Cell)> = content
            .map(|(x, y, cell)| {
                let mut cell = cell.clone();
                cell.fg = downgrade_color(cell.fg);
                cell.bg = downgrade_color(cell.bg);
                (x, y, cell)
            })
            .collect();
        self.inner
            .draw(cells.iter().map(|(x, y, cell)| (*x, *y, cell)))
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.inner.hide_cursor()
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        self.inner.show_cursor()
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        self.inner.get_cursor_position()
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        self.inner.set_cursor_position(position)
    }

    fn clear(&mut self) -> io::Result<()> {
        self.inner.clear()
    }

    fn clear_region(&mut self, clear_type: ratatui::backend::ClearType) -> io::Result<()> {
        self.inner.clear_region(clear_type)
    }

    fn append_lines(&mut self, n: u16) -> io::Result<()> {
        self.inner.append_lines(n)
    }

    fn size(&self) -> io::Result<Size> {
        self.inner.size()
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        self.inner.window_size()
    }

    fn flush(&mut self) -> io::Result<()> {
        Backend::flush(&mut self.inner)
    }
}

/// Run a closure with a full-screen terminal, restoring state on exit.
pub(crate) fn with_terminal<T>(
    f: impl FnOnce(&mut Terminal<TuiBackend>) -> io::Result<T>,
) -> io::Result<T> {
    with_terminal_mode(false, f)
}

/// Picker variant that asks the terminal emulator to deliver a pasted URL as
/// one [`crossterm::event::Event::Paste`] instead of simulated key presses.
pub(crate) fn with_terminal_paste<T>(
    f: impl FnOnce(&mut Terminal<TuiBackend>) -> io::Result<T>,
) -> io::Result<T> {
    with_terminal_mode(true, f)
}

fn with_terminal_mode<T>(
    bracketed_paste: bool,
    f: impl FnOnce(&mut Terminal<TuiBackend>) -> io::Result<T>,
) -> io::Result<T> {
    terminal::enable_raw_mode()?;
    let mut stderr = io::stderr();
    // Focus events let the event loops force a full repaint when the user
    // switches back to this tab — the emulator may have disturbed the
    // alternate screen while it was hidden, and ratatui only diffs against
    // its own back-buffer.
    execute!(stderr, EnterAlternateScreen, EnableFocusChange)?;
    if bracketed_paste {
        execute!(stderr, EnableBracketedPaste)?;
    }
    let backend = DowngradeBackend::new(CrosstermBackend::new(stderr), !supports_truecolor());
    let mut terminal = Terminal::new(backend)?;

    let result = f(&mut terminal);

    let _ = terminal::disable_raw_mode();
    if bracketed_paste {
        let _ = execute!(terminal.backend_mut(), DisableBracketedPaste);
    }
    let _ = execute!(
        terminal.backend_mut(),
        DisableFocusChange,
        LeaveAlternateScreen
    );
    let _ = terminal.show_cursor();

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::{SOLANA_GREEN, SOLANA_PURPLE, TOPUP_CARD_BG};

    // ── Truecolor downgrade ─────────────────────────────────────────────

    #[test]
    fn downgrade_maps_rgb_to_256_palette_and_leaves_others_alone() {
        // RGB collapses to a 256-palette index in the valid 16..=255 range.
        match downgrade_color(TOPUP_CARD_BG) {
            Color::Indexed(i) => assert!((16..=255).contains(&i)),
            other => panic!("expected Indexed, got {other:?}"),
        }
        // Named / reset colors pass through untouched — no spurious remap.
        assert_eq!(downgrade_color(Color::Reset), Color::Reset);
        assert_eq!(downgrade_color(Color::Yellow), Color::Yellow);
    }

    #[test]
    fn dark_card_bg_does_not_downgrade_to_green() {
        // The original bug: Rgb(39,39,42)'s truecolor SGR leaked a green
        // background on non-truecolor terminals. The downgraded index must
        // land in the dark grayscale ramp, never a green cube cell.
        let idx = match downgrade_color(TOPUP_CARD_BG) {
            Color::Indexed(i) => i,
            other => panic!("expected Indexed, got {other:?}"),
        };
        // 232..=235 are the darkest grays — where a near-black belongs.
        assert!(
            (232..=235).contains(&idx),
            "near-black card bg downgraded to unexpected palette index {idx}"
        );
    }

    #[test]
    fn solana_green_stays_green_ish_after_downgrade() {
        // A genuinely green RGB should map into the green region of the
        // color cube (cube index where the green axis dominates).
        let idx = match downgrade_color(SOLANA_GREEN) {
            Color::Indexed(i) => i,
            other => panic!("expected Indexed, got {other:?}"),
        };
        assert!(
            (16..=231).contains(&idx),
            "expected a cube color, got {idx}"
        );
        let c = idx - 16;
        let (r, g, b) = (c / 36, (c / 6) % 6, c % 6);
        assert!(
            g > r && g > b,
            "expected green-dominant cube cell, got ({r},{g},{b})"
        );
    }

    #[test]
    fn downgrade_maps_known_rgb_triples_to_expected_indices() {
        // Exact-value pins derived from the cube/grayscale algorithm above:
        //
        // Rgb(39,39,42) — grayscale wins: avg=40 → gray_i=3 → index 235.
        assert_eq!(downgrade_color(TOPUP_CARD_BG), Color::Indexed(235));
        // Rgb(153,69,255) — cube wins: levels (135,95,255) → (2,1,5) → 99.
        assert_eq!(downgrade_color(SOLANA_PURPLE), Color::Indexed(99));
        // Rgb(20,241,149) — cube wins: levels (0,255,135) → (0,5,2) → 48.
        assert_eq!(downgrade_color(SOLANA_GREEN), Color::Indexed(48));
        // Pure white/black land on the cube corners (exact matches).
        assert_eq!(
            downgrade_color(Color::Rgb(255, 255, 255)),
            Color::Indexed(231)
        );
        assert_eq!(downgrade_color(Color::Rgb(0, 0, 0)), Color::Indexed(16));
    }
}
