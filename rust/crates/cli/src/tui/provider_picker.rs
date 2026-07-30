//! Harness-agnostic provider picker TUI: choose the inference provider (and
//! model) a coding harness should talk to through the Pay gateway.
//!
//! Built to scale past local discovery — providers will eventually come from
//! the p2p registry with many entries — so the layout is a full-width plain
//! table (no sidebar, no borders): a 🔍 type-to-search field and a rail-styled
//! provider list in the notice-component style (`components/notice.rs`:
//! colored `│` rail + bold title + dimmed body). `←`/`→` cycle the selected
//! provider's models; the picked model renders as an accent-colored chip with
//! its price.

use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::Terminal;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::commands::server::inference::discovery::DiscoveredProvider;

use super::term::{SPINNER, TuiBackend, with_terminal};
use super::theme::TOPUP_MAIN_BG;
use super::widgets::controls_bar;

/// Rows per provider entry: title, model list, price/description.
const ENTRY_HEIGHT: u16 = 3;

/// The provider (and model) the user picked.
pub struct ProviderChoice {
    pub provider: DiscoveredProvider,
    pub model: String,
}

// One short-lived value per TUI invocation — boxing the payload buys nothing.
#[allow(clippy::large_enum_variant)]
pub enum ProviderSelection {
    Selected(ProviderChoice),
    Cancelled,
}

/// Run the picker for `harness` (display-only label, e.g. the harness
/// command name). `requested_model` locks the model choice when set.
pub fn select_provider(
    harness: &str,
    providers: Vec<DiscoveredProvider>,
    requested_model: Option<&str>,
) -> io::Result<ProviderSelection> {
    if !std::io::IsTerminal::is_terminal(&std::io::stderr()) || providers.is_empty() {
        return Ok(ProviderSelection::Cancelled);
    }

    let harness = harness.to_string();
    let requested_model = requested_model.map(str::to_string);
    with_terminal(|terminal| run(terminal, harness, providers, requested_model))
}

fn run(
    terminal: &mut Terminal<TuiBackend>,
    harness: String,
    providers: Vec<DiscoveredProvider>,
    requested_model: Option<String>,
) -> io::Result<ProviderSelection> {
    let mut app = ProviderPickerApp::new(harness, providers, requested_model);

    loop {
        app.tick = app.tick.wrapping_add(1);
        terminal.draw(|frame| render(frame, &app))?;

        if event::poll(std::time::Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match key.code {
                KeyCode::Esc => return Ok(ProviderSelection::Cancelled),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Ok(ProviderSelection::Cancelled);
                }
                KeyCode::Up => app.move_selection(-1),
                KeyCode::Down => app.move_selection(1),
                KeyCode::Tab | KeyCode::Right => app.cycle_model(1),
                KeyCode::BackTab | KeyCode::Left => app.cycle_model(-1),
                KeyCode::Enter => {
                    if let Some(choice) = app.choice() {
                        return Ok(ProviderSelection::Selected(choice));
                    }
                }
                KeyCode::Backspace => app.pop_search(),
                KeyCode::Char(ch)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    app.push_search(ch);
                }
                _ => {}
            }
        }
    }
}

// ── App state ─────────────────────────────────────────────────────────────

struct ProviderPickerApp {
    /// Display-only harness label for the status line.
    harness: String,
    providers: Vec<DiscoveredProvider>,
    /// Live type-to-search query (case-insensitive substring).
    search: String,
    /// Index into [`Self::filtered`].
    selected: usize,
    /// `←`/`→` cursor into the selected provider's model list.
    model_idx: usize,
    /// `--model` lock: overrides the per-provider model choice.
    requested_model: Option<String>,
    tick: usize,
}

impl ProviderPickerApp {
    fn new(
        harness: String,
        mut providers: Vec<DiscoveredProvider>,
        requested_model: Option<String>,
    ) -> Self {
        // Keep hosted providers first while preserving discovery order within
        // the hosted and self-hosted groups.
        providers.sort_by_key(|provider| !provider.hosted());
        Self {
            harness,
            providers,
            search: String::new(),
            selected: 0,
            model_idx: 0,
            requested_model,
            tick: 0,
        }
    }

    fn model_locked(&self) -> bool {
        self.requested_model.is_some()
    }

    /// Case-insensitive substring match over title, slug, and model names.
    fn matches(&self, provider: &DiscoveredProvider) -> bool {
        if self.search.is_empty() {
            return true;
        }
        let query = self.search.to_lowercase();
        provider.title().to_lowercase().contains(&query)
            || provider.slug().to_lowercase().contains(&query)
            || provider
                .models
                .iter()
                .any(|m| m.to_lowercase().contains(&query))
    }

    /// The provider's models narrowed by the search query. Falls back to
    /// the full list when no model matches (the provider matched on
    /// title/slug instead) so the row never goes blank.
    fn visible_models<'a>(&self, provider: &'a DiscoveredProvider) -> Vec<&'a String> {
        if !self.search.is_empty() {
            let query = self.search.to_lowercase();
            let matching: Vec<&String> = provider
                .models
                .iter()
                .filter(|m| m.to_lowercase().contains(&query))
                .collect();
            if !matching.is_empty() {
                return matching;
            }
        }
        provider.models.iter().collect()
    }

    /// Providers passing the search filter, input order.
    fn filtered(&self) -> Vec<&DiscoveredProvider> {
        self.providers.iter().filter(|p| self.matches(p)).collect()
    }

    fn selected_provider(&self) -> Option<&DiscoveredProvider> {
        self.filtered().get(self.selected).copied()
    }

    fn clamp_selection(&mut self) {
        let clamped = self.selected.min(self.filtered().len().saturating_sub(1));
        if clamped != self.selected {
            self.selected = clamped;
            self.model_idx = 0;
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.filtered().len();
        if len == 0 {
            return;
        }
        let next = (self.selected as isize + delta).clamp(0, len as isize - 1) as usize;
        if next != self.selected {
            self.selected = next;
            self.model_idx = 0;
        }
    }

    /// Move the model cursor across the selected provider's (search-
    /// narrowed) models — clamped at both ends, no wrap. No-op while the
    /// model is locked by `--model` or the provider reports no models.
    fn cycle_model(&mut self, delta: isize) {
        if self.model_locked() {
            return;
        }
        let len = match self.selected_provider() {
            Some(provider) => self.visible_models(provider).len(),
            None => return,
        };
        if len == 0 {
            return;
        }
        self.model_idx = (self.model_idx as isize + delta).clamp(0, len as isize - 1) as usize;
    }

    fn push_search(&mut self, ch: char) {
        self.search.push(ch);
        self.model_idx = 0;
        self.clamp_selection();
    }

    fn pop_search(&mut self) {
        self.search.pop();
        self.model_idx = 0;
        self.clamp_selection();
    }

    /// Model that Enter would launch for `provider`: `--model` lock > the
    /// `←`/`→` model cursor over the search-narrowed models (selected
    /// provider only) > the provider's first model. `None` when the
    /// provider reports no models and nothing else decides.
    fn chosen_model(&self, provider: &DiscoveredProvider) -> Option<String> {
        if let Some(model) = &self.requested_model {
            return Some(model.clone());
        }
        let models = self.visible_models(provider);
        models
            .get(self.model_idx)
            .or_else(|| models.first())
            .map(|m| (*m).clone())
    }

    fn choice(&self) -> Option<ProviderChoice> {
        let provider = self.selected_provider()?.clone();
        let model = self.chosen_model(&provider)?;
        Some(ProviderChoice { provider, model })
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────

fn render(frame: &mut ratatui::Frame, app: &ProviderPickerApp) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(TOPUP_MAIN_BG)),
        area,
    );

    let rows = Layout::vertical([
        Constraint::Length(1), // search
        Constraint::Length(1), // gap
        Constraint::Min(0),    // provider list
        Constraint::Length(1), // controls
    ])
    .split(area);

    render_search(frame, inset_x(rows[0], 2), app);
    render_provider_list(frame, inset_x(rows[2], 2), app);
    render_controls(frame, rows[3], app);
}

/// 🔍 type-to-search field: the live query (with a trailing cursor), or a
/// dim placeholder while empty.
fn render_search(frame: &mut ratatui::Frame, area: Rect, app: &ProviderPickerApp) {
    let mut spans = vec![Span::raw("🔍 ")];
    if app.search.is_empty() {
        spans.push(Span::styled(
            "looking for models…",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        spans.push(Span::styled(
            app.search.clone(),
            Style::default().fg(Color::White).bold(),
        ));
        spans.push(Span::styled("▌", Style::default().fg(Color::Gray)));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// One display row of the provider list.
enum ListRow<'a> {
    /// Blank line between providers.
    Gap,
    /// `usize` is the index into [`ProviderPickerApp::filtered`].
    Entry(usize, &'a DiscoveredProvider),
}

impl ListRow<'_> {
    fn height(&self) -> u16 {
        match self {
            ListRow::Entry(..) => ENTRY_HEIGHT,
            _ => 1,
        }
    }
}

fn render_provider_list(frame: &mut ratatui::Frame, area: Rect, app: &ProviderPickerApp) {
    let providers = app.filtered();

    // Keep one empty row between provider options. Entry indices stay in sync
    // with the selection cursor because gaps do not participate in selection.
    let mut rows: Vec<ListRow> = Vec::new();
    for (idx, provider) in providers.iter().enumerate() {
        if idx > 0 {
            rows.push(ListRow::Gap);
        }
        rows.push(ListRow::Entry(idx, provider));
    }

    // Scroll (in lines) so the selected entry is fully visible.
    let mut sel_end: u16 = 0;
    let mut total: u16 = 0;
    for row in &rows {
        let h = row.height();
        if let ListRow::Entry(idx, _) = row
            && *idx == app.selected
        {
            sel_end = total + h;
        }
        total += h;
    }
    let offset = sel_end.saturating_sub(area.height);

    let mut line: u16 = 0;
    for row in &rows {
        let h = row.height();
        let start = line;
        line += h;
        if start < offset {
            continue; // clipped above
        }
        let y = area.y + (start - offset);
        if y + h > area.y + area.height {
            break; // clipped below
        }
        let row_area = Rect {
            x: area.x,
            y,
            width: area.width,
            height: h,
        };
        match row {
            ListRow::Gap => {}
            ListRow::Entry(idx, provider) => {
                let selected = *idx == app.selected;
                let chosen = selected.then(|| app.chosen_model(provider)).flatten();
                render_provider_entry(
                    frame,
                    row_area,
                    provider,
                    &app.visible_models(provider),
                    selected,
                    chosen.as_deref(),
                );
            }
        }
    }
}

/// One three-line entry in the notice style: a `│` rail spanning the row
/// (brand-colored when selected, gray otherwise), bold title + dim origin
/// on line 1, the model choice on line 2, and price on line 3.
/// Selection thickens the rail (`┃`), brightens the title, and highlights
/// the `←`/`→`-picked model as a white-on-accent chip (the list windows so
/// it stays visible). Inactive rows collapse to one priced model plus a count
/// so providers remain directly comparable.
fn render_provider_entry(
    frame: &mut ratatui::Frame,
    area: Rect,
    provider: &DiscoveredProvider,
    models: &[&String],
    selected: bool,
    chosen_model: Option<&str>,
) {
    // Brand color marks the active row only; inactive rails stay gray.
    let accent = if selected {
        provider
            .color()
            .and_then(hex_color)
            .unwrap_or(Color::DarkGray)
    } else {
        Color::DarkGray
    };
    let rail_glyph = if selected { "┃" } else { "│" };
    let rail = Span::styled(format!("{rail_glyph} "), Style::default().fg(accent).bold());
    let title_style = if selected {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::Gray).bold()
    };
    let dim = Style::default().fg(Color::DarkGray);

    let mut top = vec![
        rail.clone(),
        Span::styled(provider.title().to_string(), title_style),
        Span::styled(format!("  {}", provider.base_url), dim),
    ];
    if let Some(version) = provider.version.as_deref() {
        top.push(Span::styled(format!(" · v{version}"), dim));
    }

    let summary_model = chosen_model.or_else(|| first_priced_model(provider, models));
    let mut models_line = vec![rail.clone()];
    let avail = (area.width as usize).saturating_sub(2);
    if models.is_empty() {
        models_line.push(Span::styled("no models reported", dim));
    } else if let Some(chosen) = chosen_model {
        models_line.extend(model_chip_spans(models, chosen, accent, dim, avail));
    } else if let Some(model) = summary_model {
        let remaining = models.len().saturating_sub(1);
        let suffix = if remaining == 0 {
            String::new()
        } else {
            format!(" · {remaining} more")
        };
        models_line.push(Span::styled(
            truncate_str(&format!("{model}{suffix}"), avail),
            dim,
        ));
    }

    let pricing_hint = provider.pricing_hint_for_model(summary_model);
    let detail = pricing_detail_line(pricing_hint, rail);

    frame.render_widget(
        Paragraph::new(vec![Line::from(top), Line::from(models_line), detail]),
        area,
    );
}

fn first_priced_model<'a>(provider: &DiscoveredProvider, models: &[&'a String]) -> Option<&'a str> {
    models
        .iter()
        .copied()
        .find(|model| {
            provider
                .pricing_hint_for_model(Some(model))
                .is_some_and(|hint| hint.variant.is_some() || hint.io.is_some())
        })
        .or_else(|| models.first().copied())
        .map(String::as_str)
}

fn pricing_detail_line(
    hint: Option<crate::commands::server::inference::providers::PricingHint>,
    rail: Span<'static>,
) -> Line<'static> {
    let dim = Style::default().fg(Color::DarkGray);
    let mut detail = vec![rail];
    let Some(hint) = hint else {
        detail.push(Span::styled("unpriced", dim));
        return Line::from(detail);
    };

    let price = hint.to_string();
    detail.push(Span::styled(price, Style::default().fg(Color::Yellow)));
    Line::from(detail)
}

/// The selected row's model line: every model on one line, the chosen one
/// highlighted as a white-on-accent chip. Windows from the left so the
/// chip stays visible when the list overflows.
fn model_chip_spans<'a>(
    models: &[&'a String],
    chosen: &str,
    accent: Color,
    dim: Style,
    avail: usize,
) -> Vec<Span<'a>> {
    let chosen_idx = models
        .iter()
        .position(|m| m.as_str() == chosen)
        .unwrap_or(0);
    let chip_width = |name: &str| name.chars().count() + 3; // " name " + gap

    // Drop leading models until the chosen one fits in the row.
    let mut start = 0;
    while start < chosen_idx
        && models[start..=chosen_idx]
            .iter()
            .map(|m| chip_width(m))
            .sum::<usize>()
            > avail.saturating_sub(2)
    {
        start += 1;
    }

    let mut spans = Vec::new();
    if start > 0 {
        spans.push(Span::styled("… ", dim));
    }
    // A `--model` override may not be in the provider's list — show it as
    // the chip up front so the launch target is always visible.
    if !models.iter().any(|m| m.as_str() == chosen) {
        spans.push(Span::styled(
            format!(" {chosen} "),
            Style::default().fg(Color::White).bg(accent).bold(),
        ));
        spans.push(Span::raw(" "));
    }
    for (idx, model) in models.iter().enumerate().skip(start) {
        if idx == chosen_idx && models[chosen_idx].as_str() == chosen {
            spans.push(Span::styled(
                format!(" {model} "),
                Style::default().fg(Color::White).bg(accent).bold(),
            ));
        } else {
            spans.push(Span::styled(format!(" {model} "), dim));
        }
        spans.push(Span::raw(" "));
    }
    spans
}

fn render_controls(frame: &mut ratatui::Frame, area: Rect, app: &ProviderPickerApp) {
    let entries: Vec<(&str, &str)> = vec![
        ("↑ ↓", "provider"),
        ("← →", "model"),
        ("a-z", "search"),
        ("⏎", "launch"),
        ("Esc", "cancel"),
    ];

    let spinner = SPINNER[app.tick % SPINNER.len()];
    let status = match app.selected_provider() {
        Some(provider) => match app.chosen_model(provider) {
            Some(model) => Line::from(vec![
                Span::styled(spinner, Style::default().fg(Color::Green).bold()),
                Span::styled(
                    format!(" {} → {}/{} ", app.harness, provider.slug(), model),
                    Style::default().fg(Color::DarkGray),
                ),
            ]),
            None => Line::from(Span::styled(
                "pass --model to launch this provider ",
                Style::default().fg(Color::Yellow),
            )),
        },
        None => Line::from(Span::styled(
            "no providers match ",
            Style::default().fg(Color::DarkGray),
        )),
    };
    controls_bar(frame, area, &entries, Some(status));
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn inset_x(area: Rect, x: u16) -> Rect {
    Rect {
        x: area.x.saturating_add(x),
        width: area.width.saturating_sub(x.saturating_mul(2)),
        ..area
    }
}

/// `#rrggbb` → `Color::Rgb`.
fn hex_color(hex: &str) -> Option<Color> {
    let hex = hex.strip_prefix('#')?;
    if hex.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
    Some(Color::Rgb(r, g, b))
}

/// Truncate to at most `max` characters, ellipsizing when clipped.
fn truncate_str(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::commands::server::inference::providers::lm_studio::LmStudio;
    use crate::commands::server::inference::providers::ollama::Ollama;

    fn ollama(models: &[&str]) -> DiscoveredProvider {
        DiscoveredProvider {
            provider: Arc::new(Ollama),
            base_url: "http://127.0.0.1:11434".into(),
            models: models.iter().map(|m| (*m).to_string()).collect(),
            version: Some("0.9.1".into()),
            pricing: None,
            model_pricing: Vec::new(),
        }
    }

    fn lm_studio(models: &[&str]) -> DiscoveredProvider {
        DiscoveredProvider {
            provider: Arc::new(LmStudio),
            base_url: "http://127.0.0.1:1234".into(),
            models: models.iter().map(|m| (*m).to_string()).collect(),
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        }
    }

    fn proxied_ollama_with_gateway_pricing() -> DiscoveredProvider {
        DiscoveredProvider {
            provider: Arc::new(Ollama),
            base_url: "http://127.0.0.1:1402".into(),
            models: vec!["gemma4:latest".into()],
            version: Some("0.31.1".into()),
            pricing: None,
            model_pricing: vec![pay_pdb::types::ModelPricingSummary {
                model: "gemma4:latest".into(),
                variant: Some("gemma4".into()),
                price: Some("input $1.00 · output $3.00 / 1M tokens".into()),
                description: None,
            }],
        }
    }

    fn app(providers: Vec<DiscoveredProvider>) -> ProviderPickerApp {
        ProviderPickerApp::new("codex".into(), providers, None)
    }

    fn filtered_slugs(app: &ProviderPickerApp) -> Vec<&str> {
        app.filtered().iter().map(|p| p.slug()).collect()
    }

    // ── Filtering ──

    #[test]
    fn search_matches_title_slug_and_models_case_insensitively() {
        let mut app = app(vec![ollama(&["llama3.2:3b"]), lm_studio(&["qwen2.5-7b"])]);
        assert_eq!(filtered_slugs(&app), vec!["ollama", "lm-studio"]);

        // Title match, case-insensitive.
        app.search = "OLLAMA".into();
        assert_eq!(filtered_slugs(&app), vec!["ollama"]);

        // Slug match.
        app.search = "lm-stu".into();
        assert_eq!(filtered_slugs(&app), vec!["lm-studio"]);

        // Model-name match.
        app.search = "QWEN".into();
        assert_eq!(filtered_slugs(&app), vec!["lm-studio"]);

        // No match.
        app.search = "nope".into();
        assert!(app.filtered().is_empty());
        assert!(app.selected_provider().is_none());
    }

    #[test]
    fn left_right_moves_the_model_cursor_without_wrapping() {
        let mut app = app(vec![
            ollama(&["llama3.2:3b", "nomic-embed"]),
            lm_studio(&["qwen2.5-7b"]),
        ]);
        assert_eq!(app.choice().unwrap().model, "llama3.2:3b");

        // → moves forward and clamps at the end (no wrap).
        app.cycle_model(1);
        assert_eq!(app.choice().unwrap().model, "nomic-embed");
        app.cycle_model(1);
        assert_eq!(app.choice().unwrap().model, "nomic-embed");

        // ← moves back and clamps at the start (no wrap).
        app.cycle_model(-1);
        assert_eq!(app.choice().unwrap().model, "llama3.2:3b");
        app.cycle_model(-1);
        assert_eq!(app.choice().unwrap().model, "llama3.2:3b");

        // Moving the provider selection resets the model cursor.
        app.cycle_model(1);
        app.move_selection(1);
        assert_eq!(app.choice().unwrap().model, "qwen2.5-7b");
        app.move_selection(-1);
        assert_eq!(app.choice().unwrap().model, "llama3.2:3b");
    }

    #[test]
    fn search_narrows_the_model_choice() {
        let mut app = app(vec![ollama(&["llama3.2:3b", "nomic-embed", "qwen3:8b"])]);

        // Typing a model query narrows what ←/→ walks and what Enter picks.
        for ch in "nomic".chars() {
            app.push_search(ch);
        }
        assert_eq!(filtered_slugs(&app), vec!["ollama"]);
        assert_eq!(app.choice().unwrap().model, "nomic-embed");
        // Only one match — the cursor clamps inside the narrowed list.
        app.cycle_model(1);
        assert_eq!(app.choice().unwrap().model, "nomic-embed");

        // A title/slug match keeps the full model list.
        app.search = "ollama".into();
        app.model_idx = 0;
        assert_eq!(app.choice().unwrap().model, "llama3.2:3b");
        app.cycle_model(2);
        assert_eq!(app.choice().unwrap().model, "qwen3:8b");
    }

    #[test]
    fn cycle_model_is_a_noop_without_models() {
        let mut app = app(vec![ollama(&[])]);
        app.cycle_model(1);
        assert_eq!(app.model_idx, 0);
        assert!(app.choice().is_none());
    }

    #[test]
    fn selection_clamps_as_filters_narrow() {
        let mut app = app(vec![ollama(&["llama3.2:3b"]), lm_studio(&["qwen2.5-7b"])]);
        app.move_selection(1);
        assert_eq!(app.selected, 1);
        assert_eq!(app.selected_provider().unwrap().slug(), "lm-studio");

        // Typing narrows the list to one entry — selection clamps to it.
        for ch in "ollama".chars() {
            app.push_search(ch);
        }
        assert_eq!(app.selected, 0);
        assert_eq!(app.selected_provider().unwrap().slug(), "ollama");

        // Deleting the query restores the full list; selection stays valid.
        while !app.search.is_empty() {
            app.pop_search();
        }
        assert_eq!(filtered_slugs(&app).len(), 2);
        assert_eq!(app.selected, 0);
    }

    // ── Enter → choice ──

    #[test]
    fn enter_defaults_to_the_selected_providers_first_model() {
        let app = app(vec![ollama(&["llama3.2:3b", "nomic-embed"])]);
        let choice = app.choice().unwrap();
        assert_eq!(choice.provider.slug(), "ollama");
        assert_eq!(choice.model, "llama3.2:3b");
    }

    #[test]
    fn requested_model_locks_the_choice_and_the_cursor() {
        let mut app = ProviderPickerApp::new(
            "codex".into(),
            vec![ollama(&["llama3.2:3b", "nomic-embed"])],
            Some("custom-model".into()),
        );
        assert!(app.model_locked());
        assert_eq!(app.choice().unwrap().model, "custom-model");

        // Cycling models is a no-op while locked.
        app.cycle_model(1);
        assert_eq!(app.model_idx, 0);
        assert_eq!(app.choice().unwrap().model, "custom-model");
    }

    #[test]
    fn provider_without_models_yields_no_choice_unless_locked() {
        let app = app(vec![ollama(&[])]);
        assert!(app.choice().is_none());

        let locked =
            ProviderPickerApp::new("codex".into(), vec![ollama(&[])], Some("custom".into()));
        assert_eq!(locked.choice().unwrap().model, "custom");
    }

    // ── Helpers ──

    #[test]
    fn display_helpers_are_stable() {
        assert_eq!(hex_color("#22c55e"), Some(Color::Rgb(0x22, 0xc5, 0x5e)));
        assert_eq!(hex_color("22c55e"), None);
        assert_eq!(hex_color("#22c5"), None);
        assert_eq!(truncate_str("abcdef", 4), "abc…");
        assert_eq!(truncate_str("abc", 4), "abc");
    }

    // ── Hosted (catalog) rows ──

    fn hosted_gemini() -> DiscoveredProvider {
        let svc: pay_core::skills::Service = serde_json::from_value(serde_json::json!({
            "fqn": "solana-foundation/google/generativelanguage",
            "title": "Generative Language API (Gemini)",
            "service_url": "https://generativelanguage.google.gateway-402.com",
            "endpoints": [{
                "method": "POST",
                "path": "v1beta/models/{modelsId}:generateContent",
                "pricing": {
                    "dimensions": [
                        { "unit": "requests", "tiers": [{ "price_usd": 0.01 }] }
                    ]
                }
            }]
        }))
        .unwrap();
        let provider =
            crate::commands::server::inference::providers::catalog::CatalogProvider::from_service(
                &svc,
            );
        DiscoveredProvider {
            base_url: provider.service_url().to_string(),
            provider: Arc::new(provider),
            models: vec!["gemini-2.5-flash".into()],
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        }
    }

    /// A Gemini row priced per model via `variants[]` — the selected row's
    /// price must track the ←/→-picked model.
    fn hosted_gemini_variant_priced() -> DiscoveredProvider {
        let variant = |value: &str, inp: f64, out: f64, description: &str| {
            serde_json::json!({
                "param": "model", "value": value,
                "description": description,
                "dimensions": [
                    { "direction": "input", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": inp }] },
                    { "direction": "output", "unit": "tokens", "scale": 1000000, "tiers": [{ "price_usd": out }] }
                ]
            })
        };
        let svc: pay_core::skills::Service = serde_json::from_value(serde_json::json!({
            "fqn": "solana-foundation/google/generativelanguage",
            "service_url": "https://generativelanguage.google.gateway-402.com",
            "endpoints": [{
                "method": "POST",
                "path": "v1beta/models/{modelsId}:generateContent",
                "pricing": { "variants": [
                    variant(
                        "gemini-2.5-flash",
                        0.345,
                        2.875,
                        "Balanced Gemini 2.5 model for low-latency chat, coding, and multimodal tasks."
                    ),
                    variant(
                        "gemini-2.5-pro",
                        1.4375,
                        11.5,
                        "Gemini 2.5 Pro for complex reasoning, coding, and multimodal analysis."
                    ),
                ] }
            }]
        }))
        .unwrap();
        let provider =
            crate::commands::server::inference::providers::catalog::CatalogProvider::from_service(
                &svc,
            );
        DiscoveredProvider {
            base_url: provider.service_url().to_string(),
            provider: Arc::new(provider),
            models: vec!["gemini-2.5-flash".into(), "gemini-2.5-pro".into()],
            version: None,
            pricing: None,
            model_pricing: Vec::new(),
        }
    }

    /// Render `app` into a `w`×`h` test buffer.
    fn draw(app: &ProviderPickerApp, w: u16, h: u16) -> ratatui::buffer::Buffer {
        let backend = ratatui::backend::TestBackend::new(w, h);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    #[test]
    fn hosted_row_shows_pricing_hint_and_gateway_host() {
        // Passed peer-first on purpose: hosted entries still sort first in the
        // flat list.
        let mut app = app(vec![ollama(&["llama3.2:3b"]), hosted_gemini()]);
        assert_eq!(
            filtered_slugs(&app),
            vec!["google", "ollama"],
            "gateway providers must sort before p2p ones"
        );
        // Select ollama so the gemini row renders unselected (the selected
        // row swaps its pricing line for the model chip).
        app.move_selection(1);

        let text = buffer_text(&draw(&app, 120, 30));
        assert!(
            text.contains("Google Gemini"),
            "missing hosted brand title:\n{text}"
        );
        assert!(
            text.contains("gemini-2.5-flash"),
            "hosted model list missing model:\n{text}"
        );
        assert!(
            text.contains("$0.0100/req"),
            "hosted detail line must include pricing:\n{text}"
        );
        // The selected peer entry shows its model chip.
        assert!(
            text.contains(" llama3.2:3b "),
            "missing selected model chip:\n{text}"
        );
        // The `· N models` count noise is gone from line 2.
        assert!(
            !text.contains("· 1 model"),
            "model-count noise should be gone from line 2:\n{text}"
        );
    }

    #[test]
    fn inactive_row_uses_first_model_price_when_no_aggregate_exists() {
        let mut app = app(vec![
            proxied_ollama_with_gateway_pricing(),
            lm_studio(&["qwen2.5-7b"]),
        ]);
        app.move_selection(1);

        let text = buffer_text(&draw(&app, 120, 30));
        assert!(
            text.contains("input $1.00 · output $3.00 / 1M tokens"),
            "inactive row must fall back to its first model's live price:\n{text}"
        );
    }

    #[test]
    fn selected_row_price_tracks_the_picked_model_for_variant_pricing() {
        // Gemini-only so it's the selected row; flash is picked first.
        let mut app = app(vec![hosted_gemini_variant_priced()]);
        let flash = buffer_text(&draw(&app, 120, 30));
        assert!(
            flash.contains("input $0.34 · output $2.88 / 1M tokens"),
            "flash price must reflect its per-model variant:\n{flash}"
        );
        assert!(
            !flash.contains("Balanced Gemini 2.5 model"),
            "model prose should not compete with the price:\n{flash}"
        );
        assert!(
            !flash.contains("tok  gemini-2.5-flash"),
            "flash variant label must not render on the detail line:\n{flash}"
        );

        // →: pro's price replaces flash's.
        app.cycle_model(1);
        assert_eq!(app.choice().unwrap().model, "gemini-2.5-pro");
        let pro = buffer_text(&draw(&app, 120, 30));
        assert!(
            pro.contains("input $1.44 · output $11.50 / 1M tokens"),
            "pro price must track the ←/→ selection:\n{pro}"
        );
        assert!(
            !pro.contains("Gemini 2.5 Pro for complex reasoning"),
            "model prose should not compete with the price:\n{pro}"
        );
        assert!(
            !pro.contains("tok  gemini-2.5-pro"),
            "pro variant label must not render on the detail line:\n{pro}"
        );
        assert!(
            !pro.contains("$0.34"),
            "flash price must not linger after switching model:\n{pro}"
        );
    }

    #[test]
    fn inactive_row_collapses_models_to_one_choice_and_count() {
        let mut app = app(vec![
            hosted_gemini_variant_priced(),
            ollama(&["llama3.2:3b"]),
        ]);
        app.move_selection(1);

        let text = buffer_text(&draw(&app, 120, 30));
        assert!(
            text.contains("gemini-2.5-flash · 1 more"),
            "inactive model list should collapse to one comparable choice:\n{text}"
        );
        assert!(
            !text.contains("gemini-2.5-flash, gemini-2.5-pro"),
            "inactive row should not dump every model:\n{text}"
        );
    }

    #[test]
    fn proxied_local_row_hides_bare_variant_without_description() {
        let app = app(vec![proxied_ollama_with_gateway_pricing()]);
        let text = buffer_text(&draw(&app, 120, 30));

        assert!(
            text.contains("http://127.0.0.1:1402"),
            "local gateway row should display the proxy URL:\n{text}"
        );
        assert!(
            text.contains("gemma4:latest"),
            "model line should still show the full served model:\n{text}"
        );
        assert!(
            text.contains("input $1.00 · output $3.00 / 1M tokens"),
            "gateway-supplied price should render:\n{text}"
        );
        assert!(
            !text.contains("tok  gemma4"),
            "bare local pricing key should not render without a description:\n{text}"
        );
    }

    #[test]
    fn provider_list_is_flat_without_section_headers_or_placeholders() {
        let app = app(vec![ollama(&["llama3.2:3b"]), hosted_gemini()]);

        let text = buffer_text(&draw(&app, 120, 30));
        let ollama_at = text.find("Ollama").expect("ollama entry");
        let gemini_at = text.find("Google Gemini").expect("gemini entry");
        assert!(
            gemini_at < ollama_at,
            "hosted entries should remain first:\n{text}"
        );
        assert!(!text.contains("LOCAL"), "unexpected LOCAL header:\n{text}");
        assert!(
            !text.contains("SOLANA AGENT GATEWAY"),
            "unexpected gateway header:\n{text}"
        );
        assert!(!text.contains("P2P"), "unexpected P2P header:\n{text}");
        assert!(
            !text.contains("  none"),
            "unexpected empty-section placeholder:\n{text}"
        );
    }

    #[test]
    fn provider_options_have_one_blank_line_between_them() {
        let app = app(vec![ollama(&["llama3.2:3b"]), lm_studio(&["qwen2.5-7b"])]);

        let text = buffer_text(&draw(&app, 120, 30));
        let lines: Vec<_> = text.lines().collect();
        let ollama_line = lines
            .iter()
            .position(|line| line.contains("Ollama"))
            .expect("Ollama row");
        let lm_studio_line = lines
            .iter()
            .position(|line| line.contains("LM Studio"))
            .expect("LM Studio row");

        assert_eq!(
            lm_studio_line - ollama_line,
            usize::from(ENTRY_HEIGHT) + 1,
            "provider rows should be separated by exactly one line:\n{text}"
        );
        assert!(
            lines[lm_studio_line - 1].trim().is_empty(),
            "provider separator should be blank:\n{text}"
        );
    }

    #[test]
    fn selected_row_carries_brand_color_rail_and_model_chip() {
        // Gemini selected (hosted entries sort first), ollama inactive.
        let app = app(vec![ollama(&["llama3.2:3b"]), hosted_gemini()]);
        assert_eq!(app.selected_provider().unwrap().slug(), "google");

        let buffer = draw(&app, 120, 30);
        let text = buffer_text(&buffer);

        // The picked model renders as a chip; the price renders on detail line.
        assert!(
            text.contains(" gemini-2.5-flash "),
            "missing model chip:\n{text}"
        );
        assert!(
            text.contains("$0.0100/req"),
            "missing price on the selected row:\n{text}"
        );

        // Rails live in the list's first column (x = 2); the controls bar
        // (last row) is excluded — its separators aren't rails.
        let gemini_blue = Color::Rgb(0x42, 0x85, 0xf4);
        let mut selected_rail_color = None;
        let mut inactive_rail_color = None;
        let mut chip_style = None;
        for y in 0..buffer.area.height.saturating_sub(1) {
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                if x == 2 {
                    match cell.symbol() {
                        "┃" => selected_rail_color = Some(cell.fg),
                        "│" => inactive_rail_color = Some(cell.fg),
                        _ => {}
                    }
                }
                if cell.bg == gemini_blue {
                    chip_style = Some(cell.fg);
                }
            }
        }
        assert_eq!(
            selected_rail_color,
            Some(gemini_blue),
            "selected rail carries the brand color"
        );
        assert_eq!(
            inactive_rail_color,
            Some(Color::DarkGray),
            "inactive rails are gray, not brand-colored"
        );
        // Chip: same color as the rail, highlighted text in white.
        assert_eq!(
            chip_style,
            Some(Color::White),
            "model chip must be white-on-accent"
        );
    }

    // ── Render smoke test ──

    #[test]
    fn render_smoke_test_plain_table_layout() {
        let app = app(vec![
            ollama(&["llama3.2:3b", "nomic-embed"]),
            lm_studio(&["qwen2.5-7b"]),
        ]);

        let text = buffer_text(&draw(&app, 100, 30));

        // 🔍 search header only — no heading, no model-filter chips, no
        // cursor glyph after the emoji while empty.
        assert!(text.contains("🔍"), "missing search glass:\n{text}");
        assert!(
            text.contains("looking for models…"),
            "missing search placeholder:\n{text}"
        );
        assert!(
            !text.contains('▌'),
            "no cursor glyph while the search is empty:\n{text}"
        );
        assert!(
            !text.contains("PROVIDER FOR"),
            "heading row should be gone:\n{text}"
        );
        assert!(
            !text.contains(" all "),
            "model-filter chips should be gone:\n{text}"
        );

        // Flat provider list — no grouping headers or empty placeholders.
        assert!(!text.contains("LOCAL"), "unexpected LOCAL header:\n{text}");
        assert!(
            !text.contains("SOLANA AGENT GATEWAY"),
            "unexpected gateway header:\n{text}"
        );
        assert!(!text.contains("P2P"), "unexpected P2P header:\n{text}");
        assert!(
            !text.contains("  none"),
            "unexpected empty-section placeholder:\n{text}"
        );

        // Three-line rail entries: selected rail + plain rail, titles, the
        // selected row's model chip, and per-entry detail lines.
        assert!(text.contains('┃'), "missing selected rail:\n{text}");
        assert!(text.contains('│'), "missing entry rail:\n{text}");
        assert!(text.contains("Ollama"), "missing provider title:\n{text}");
        assert!(
            text.contains("http://127.0.0.1:11434"),
            "missing provider origin:\n{text}"
        );
        assert!(
            text.contains(" llama3.2:3b "),
            "missing selected model chip:\n{text}"
        );
        // All models render on one line next to the chip.
        assert!(
            text.contains("nomic-embed"),
            "missing sibling model on the selected line:\n{text}"
        );
        assert!(text.contains("LM Studio"), "missing second entry:\n{text}");
        assert!(
            text.contains("qwen2.5-7b"),
            "missing unselected model list:\n{text}"
        );

        // No borders and no sidebar anywhere in the new layout.
        assert!(
            !text.contains('╭') && !text.contains('┌'),
            "no border glyphs should render:\n{text}"
        );
        assert!(
            !text.contains("LOCAL PROVIDERS"),
            "sidebar should be gone:\n{text}"
        );
    }
}
