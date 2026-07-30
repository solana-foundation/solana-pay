//! Live TUI for `pay gate inference`: provider sidebar and per-connection
//! activity table, fed by the PDB event stream (bridged from
//! `broadcast::Sender<SseMessage>` to a `std::sync::mpsc` channel by the
//! caller).
//!
//! Mirrors the topup TUI's visual language — 45-col dark sidebar, content
//! window, 1-row controls bar, rounded borders — and its event-loop shape:
//! 50ms `event::poll` tick, non-blocking channel drain, render, key handling.

use std::collections::VecDeque;
use std::io;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use pay_pdb::types::{ConnectionSummary, FlowStatus, PaymentFlow, ProviderSummary, SseMessage};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};

use super::term::{SPINNER, with_terminal};
use super::theme::{CARD_BG, SOLANA_GREEN, TOPUP_MAIN_BG, TOPUP_SIDEBAR_BG};
use super::widgets::{controls_bar, solana_logo};

/// Local flow ring-buffer cap — mirrors PDB's 200-flow ring buffer.
const FLOW_CAP: usize = 200;

// ── Public API ────────────────────────────────────────────────────────────

/// Everything `run_inference_tui` needs; wired by the `gate inference`
/// command.
pub struct InferenceTuiArgs {
    /// Public gateway URL, e.g. `http://127.0.0.1:1402`.
    pub gateway_url: String,
    /// Web UI URL; `Some` enables the `w` key (opened via `webbrowser`).
    pub web_url: Option<String>,
    /// Public address the gateway is reachable at (identity card).
    pub public_url: String,
    /// Providers discovered before the TUI opened.
    pub initial_providers: Vec<ProviderSummary>,
    /// Flows recorded before the TUI opened.
    pub initial_flows: Vec<PaymentFlow>,
    /// Connection aggregates recorded before the TUI opened
    /// (`pdb.connections()`).
    pub initial_connections: Vec<ConnectionSummary>,
    /// Bridged PDB event stream, drained non-blockingly each 50ms tick.
    pub events: Receiver<SseMessage>,
}

/// Runs the TUI on the calling thread; returns when the user quits
/// (q / Ctrl-C / Esc).
pub fn run_inference_tui(args: InferenceTuiArgs) -> io::Result<()> {
    let InferenceTuiArgs {
        gateway_url,
        web_url,
        public_url,
        initial_providers,
        initial_flows,
        initial_connections,
        events,
    } = args;

    let mut app = InferenceApp::new(
        initial_providers,
        initial_flows,
        initial_connections,
        public_url,
    );

    with_terminal(|terminal| {
        loop {
            while let Ok(msg) = events.try_recv() {
                app.apply_event(msg);
            }
            app.tick = app.tick.wrapping_add(1);

            terminal.draw(|frame| render(frame, &app, &gateway_url, web_url.is_some()))?;

            if event::poll(Duration::from_millis(50))? {
                match event::read()? {
                    Event::Key(key) if key.kind == KeyEventKind::Press => {
                        match app.handle_key(key.code, key.modifiers) {
                            Action::Quit => return Ok(()),
                            Action::OpenWeb => {
                                if let Some(url) = web_url.as_deref() {
                                    let _ = webbrowser::open(url);
                                }
                            }
                            Action::None => {}
                        }
                    }
                    // Coming back to the tab (or a resize while hidden) can
                    // leave the emulator's copy of the alternate screen out
                    // of sync with ratatui's back-buffer diff — drop the
                    // buffer and repaint everything on the next draw.
                    Event::Resize(_, _) | Event::FocusGained => terminal.clear()?,
                    _ => {}
                }
            }
        }
    })
}

// ── App state ─────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pane {
    Providers,
    Requests,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Filter {
    All,
    Errors,
    Provider(String),
}

/// What a key press asks the event loop to do beyond mutating state.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    None,
    Quit,
    OpenWeb,
}

struct InferenceApp {
    providers: Vec<ProviderSummary>,
    /// Public address the gateway is reachable at, shown on the
    /// inference-server identity card (e.g. `http://203.0.113.4:1402`).
    public_url: String,
    /// Flows, newest first, capped at [`FLOW_CAP`] — kept only for the
    /// in-flight indicator (not rendered as rows).
    flows: VecDeque<PaymentFlow>,
    /// Aggregated per-connection activity, newest activity first.
    connections: Vec<ConnectionSummary>,
    pane: Pane,
    /// Index into [`Self::up_providers`] — only up providers are rendered
    /// and selectable.
    selected_provider: usize,
    /// Pinned connection id when the user moved the selection; `None`
    /// while following the newest activity.
    selected_id: Option<String>,
    /// True while the newest-activity connection is auto-selected.
    follow: bool,
    filter: Filter,
    /// Render-loop tick (~50ms) driving the spinner glyphs.
    tick: usize,
}

impl InferenceApp {
    fn new(
        providers: Vec<ProviderSummary>,
        initial_flows: Vec<PaymentFlow>,
        initial_connections: Vec<ConnectionSummary>,
        public_url: String,
    ) -> Self {
        let mut app = Self {
            providers,
            public_url,
            flows: VecDeque::new(),
            connections: initial_connections,
            pane: Pane::Requests,
            selected_provider: 0,
            selected_id: None,
            follow: true,
            filter: Filter::All,
            tick: 0,
        };
        app.sort_connections();
        // Initial flows arrive oldest-first (PDB snapshot order); pushing
        // each to the front leaves the newest at the front.
        for flow in initial_flows {
            app.push_flow(flow);
        }
        app
    }

    // ── Events ──

    fn apply_event(&mut self, msg: SseMessage) {
        match msg {
            SseMessage::Init { .. } => {}
            // Flows are tracked only to drive the in-flight indicator.
            SseMessage::Snapshot { flows } => {
                self.flows.clear();
                for flow in flows {
                    self.push_flow(flow);
                }
            }
            SseMessage::FlowCreated { flow } => self.push_flow(flow),
            SseMessage::FlowUpdated { flow } => {
                match self.flows.iter_mut().find(|f| f.id == flow.id) {
                    Some(existing) => *existing = flow,
                    // Update for a flow we never saw created (e.g. evicted,
                    // or the TUI attached mid-stream) — treat as new.
                    None => self.push_flow(flow),
                }
            }
            SseMessage::ProviderStatus { providers } => {
                self.providers = providers;
                let up_count = self.up_providers().len();
                self.selected_provider = self.selected_provider.min(up_count.saturating_sub(1));
            }
            SseMessage::ConnectionsSnapshot { connections } => {
                self.connections = connections;
                self.sort_connections();
            }
            SseMessage::ConnectionUpdated { connection } => {
                match self.connections.iter_mut().find(|c| c.id == connection.id) {
                    Some(existing) => *existing = connection,
                    None => self.connections.push(connection),
                }
                self.sort_connections();
            }
        }
    }

    /// Newest activity first (`updated_at` is RFC3339, so lexicographic
    /// order is chronological). Stable: ties keep their relative order.
    fn sort_connections(&mut self) {
        self.connections
            .sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    }

    fn push_flow(&mut self, flow: PaymentFlow) {
        self.flows.push_front(flow);
        while self.flows.len() > FLOW_CAP {
            self.flows.pop_back();
        }
    }

    // ── Selection & filtering ──

    /// Providers currently up — the only ones rendered and selectable.
    fn up_providers(&self) -> Vec<&ProviderSummary> {
        self.providers.iter().filter(|p| p.up).collect()
    }

    fn matches_filter(&self, conn: &ConnectionSummary) -> bool {
        match &self.filter {
            Filter::All => true,
            Filter::Errors => conn.failed > 0,
            Filter::Provider(slug) => conn.provider.as_deref() == Some(slug.as_str()),
        }
    }

    /// Connections passing the active filter, newest activity first.
    fn filtered_connections(&self) -> Vec<&ConnectionSummary> {
        self.connections
            .iter()
            .filter(|conn| self.matches_filter(conn))
            .collect()
    }

    /// Index of the selected connection within
    /// [`Self::filtered_connections`].
    fn selected_index(&self) -> Option<usize> {
        let connections = self.filtered_connections();
        if connections.is_empty() {
            return None;
        }
        if self.follow {
            return Some(0);
        }
        self.selected_id
            .as_ref()
            .and_then(|id| connections.iter().position(|conn| conn.id == *id))
            .or(Some(0))
    }

    /// The selected connection (kept for selection tests and future detail
    /// views — the table highlights via [`Self::selected_index`]).
    #[cfg_attr(not(test), allow(dead_code))]
    fn selected_connection(&self) -> Option<&ConnectionSummary> {
        let connections = self.filtered_connections();
        self.selected_index()
            .and_then(|idx| connections.get(idx).copied())
    }

    /// Best-effort in-flight indicator: any in-progress flow that plausibly
    /// belongs to this connection (same client ip, or same provider as a
    /// fallback). Cosmetic only.
    fn connection_in_flight(&self, conn: &ConnectionSummary) -> bool {
        self.flows.iter().any(|flow| {
            flow.status == FlowStatus::InProgress
                && (flow.client_ip == conn.client_ip
                    || (conn.provider.is_some()
                        && flow.inference.as_ref().map(|i| i.provider.as_str())
                            == conn.provider.as_deref()))
        })
    }

    /// Move the connection selection by `delta` rows (positive = older
    /// activity). Any manual move pins the selection and stops following.
    fn move_selection(&mut self, delta: isize) {
        let pinned_id = {
            let connections = self.filtered_connections();
            if connections.is_empty() {
                return;
            }
            let current = self.selected_index().unwrap_or(0) as isize;
            let next = (current + delta).clamp(0, connections.len() as isize - 1) as usize;
            connections[next].id.clone()
        };
        self.selected_id = Some(pinned_id);
        self.follow = false;
    }

    fn toggle_follow(&mut self) {
        if self.follow {
            // Pin whatever currently has the newest activity.
            let pinned = self
                .filtered_connections()
                .first()
                .map(|conn| conn.id.clone());
            self.follow = false;
            self.selected_id = pinned;
        } else {
            self.follow = true;
            self.selected_id = None;
        }
    }

    /// Cycle All → Errors → each up provider in sidebar order → All.
    fn cycle_filter(&mut self) {
        self.filter = match &self.filter {
            Filter::All => Filter::Errors,
            Filter::Errors => match self.up_providers().first() {
                Some(p) => Filter::Provider(p.slug.clone()),
                None => Filter::All,
            },
            Filter::Provider(slug) => {
                let ups = self.up_providers();
                let next = ups
                    .iter()
                    .position(|p| p.slug == *slug)
                    .and_then(|idx| ups.get(idx + 1));
                match next {
                    Some(p) => Filter::Provider(p.slug.clone()),
                    None => Filter::All,
                }
            }
        };
        // If the pinned connection got filtered out, fall back to following.
        let pinned_visible = self.selected_id.as_ref().is_some_and(|id| {
            self.filtered_connections()
                .iter()
                .any(|conn| conn.id == *id)
        });
        if !pinned_visible {
            self.selected_id = None;
            self.follow = true;
        }
    }

    fn filter_label(&self) -> String {
        match &self.filter {
            Filter::All => "all".to_string(),
            Filter::Errors => "errors".to_string(),
            Filter::Provider(slug) => slug.clone(),
        }
    }

    /// Clear the local connection + flow lists (display only — PDB history
    /// is untouched).
    fn clear_activity(&mut self) {
        self.connections.clear();
        self.flows.clear();
        self.selected_id = None;
        self.follow = true;
    }

    // ── Keys ──

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Action {
        match code {
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Action::Quit;
            }
            KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => return Action::Quit,
            KeyCode::Tab | KeyCode::BackTab => {
                self.pane = match self.pane {
                    Pane::Providers => Pane::Requests,
                    Pane::Requests => Pane::Providers,
                };
            }
            KeyCode::Up => match self.pane {
                Pane::Providers => {
                    self.selected_provider = self.selected_provider.saturating_sub(1);
                }
                Pane::Requests => self.move_selection(-1),
            },
            KeyCode::Down => match self.pane {
                Pane::Providers => {
                    if self.selected_provider + 1 < self.up_providers().len() {
                        self.selected_provider += 1;
                    }
                }
                Pane::Requests => self.move_selection(1),
            },
            KeyCode::Enter => self.toggle_follow(),
            KeyCode::Char('f') | KeyCode::Char('F') => self.cycle_filter(),
            KeyCode::Char('c') | KeyCode::Char('C') => self.clear_activity(),
            KeyCode::Char('w') | KeyCode::Char('W') => return Action::OpenWeb,
            _ => {}
        }
        Action::None
    }
}

// ── Rendering ─────────────────────────────────────────────────────────────

fn render(frame: &mut Frame, app: &InferenceApp, gateway_url: &str, has_web: bool) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    frame.render_widget(
        Block::default().style(Style::default().bg(TOPUP_MAIN_BG)),
        area,
    );

    let rows = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(area);

    let columns = Layout::horizontal([Constraint::Length(45), Constraint::Min(32)]).split(rows[0]);
    render_inference_server(frame, columns[0], app);
    render_connections(frame, columns[1], app);

    render_controls(frame, rows[1], app, gateway_url, has_web);
}

/// Left pane: Solana logo, then an "INFERENCE SERVER" identity card for
/// each **up** server (typically one — Ollama), showing its name, version,
/// public address, and served models. Down servers are not rendered.
fn render_inference_server(frame: &mut Frame, area: Rect, app: &InferenceApp) {
    frame.render_widget(
        Block::default().style(Style::default().bg(TOPUP_SIDEBAR_BG)),
        area,
    );

    let inner = Rect {
        x: area.x + 2,
        y: area.y + 1,
        width: area.width.saturating_sub(4),
        height: area.height.saturating_sub(2),
    };
    if inner.width == 0 || inner.height == 0 {
        return;
    }
    let bottom = inner.y + inner.height;
    let mut y = inner.y;

    // Solana logo at the top of the sidebar, like the topup TUI.
    let logo = solana_logo("");
    let logo_height = logo.len() as u16;
    if y + logo_height <= bottom {
        frame.render_widget(
            Paragraph::new(logo).centered(),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: logo_height,
            },
        );
    }
    y += logo_height + 1;

    let servers = app.up_providers();
    let heading = if servers.len() > 1 {
        "INFERENCE SERVERS"
    } else {
        "INFERENCE SERVER"
    };
    if y < bottom {
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                heading,
                Style::default().fg(Color::DarkGray).bold(),
            ))),
            Rect {
                x: inner.x,
                y,
                width: inner.width,
                height: 1,
            },
        );
    }
    y += 2;

    if servers.is_empty() {
        if y < bottom {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "no inference server detected",
                    Style::default().fg(Color::DarkGray),
                ))),
                Rect {
                    x: inner.x,
                    y,
                    width: inner.width,
                    height: 1,
                },
            );
        }
        return;
    }

    for (idx, server) in servers.iter().enumerate() {
        let selected = app.pane == Pane::Providers && idx == app.selected_provider;
        y = render_server_card(frame, inner, y, bottom, server, selected, &app.public_url);
        if y >= bottom {
            break;
        }
        y += 1; // gap between cards
    }
}

/// Render one inference-server identity card starting at row `y`; returns
/// the next free row. The card is a bordered block: brand-dot + name +
/// version on the header, a dim `address` and `models` field list inside,
/// each model on its own `▸` line with pricing when available.
fn render_server_card(
    frame: &mut Frame,
    inner: Rect,
    y: u16,
    bottom: u16,
    server: &ProviderSummary,
    selected: bool,
    public_url: &str,
) -> u16 {
    let accent = server
        .color
        .as_deref()
        .and_then(hex_color)
        .unwrap_or(SOLANA_GREEN);

    // Field lines: address, then one line per model (indented `▸`).
    let mut lines: Vec<Line> = Vec::new();
    let label = Style::default().fg(Color::DarkGray);
    let value = Style::default().fg(Color::Gray);

    lines.push(Line::from(vec![
        Span::styled("address  ", label),
        Span::styled(
            truncate_str(public_url, inner.width.saturating_sub(11).into()),
            value,
        ),
    ]));

    let model_count = server.models.len();
    let noun = if model_count == 1 { "model" } else { "models" };
    lines.push(Line::from(Span::styled(
        format!("{model_count} {noun}"),
        label,
    )));
    for model in &server.models {
        lines.extend(model_price_lines(server, model, inner.width.into()));
    }

    // Header: brand dot + name + version. Selection brightens the border
    // and name; otherwise the border is dim and the dot carries the brand.
    let border_style = if selected {
        Style::default().fg(accent)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let name_style = if selected {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::Gray).bold()
    };
    let version = server
        .version
        .as_deref()
        .map(|v| format!(" v{v}"))
        .unwrap_or_default();
    let title = Line::from(vec![
        Span::raw(" "),
        Span::styled("● ", Style::default().fg(accent)),
        Span::styled(server.title.clone(), name_style),
        Span::styled(version, Style::default().fg(Color::DarkGray)),
        Span::raw(" "),
    ]);

    // +2 for the top/bottom border rows.
    let card_height = (lines.len() as u16 + 2).min(bottom.saturating_sub(y));
    if card_height < 3 {
        return bottom;
    }
    let card_area = Rect {
        x: inner.x,
        y,
        width: inner.width,
        height: card_height,
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style)
        .title(title)
        // Card shares the sidebar background — only its border sets it apart.
        .style(Style::default().bg(TOPUP_SIDEBAR_BG));
    frame.render_widget(Paragraph::new(lines).block(block), card_area);

    y + card_height
}

fn model_price_lines<'a>(
    server: &'a ProviderSummary,
    model: &'a str,
    width: usize,
) -> Vec<Line<'a>> {
    let pricing = server
        .model_pricing
        .iter()
        .find(|summary| summary.model == model);
    let price = pricing.and_then(|summary| summary.price.as_deref());
    let price_label = price.unwrap_or("unpriced");
    let price_style = if price.is_some() {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let mut detail = vec![
        Span::styled("   ", Style::default().fg(Color::DarkGray)),
        Span::styled(price_label, price_style),
    ];
    let mut used = 3 + price_label.chars().count();
    let description = pricing
        .and_then(|summary| summary.description.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(description) = description {
        detail.push(Span::styled(" · ", Style::default().fg(Color::DarkGray)));
        used += 3;
        detail.push(Span::styled(
            truncate_str(description, width.saturating_sub(used)),
            Style::default().fg(Color::DarkGray),
        ));
    }

    vec![
        Line::from(vec![
            Span::styled(" ▸ ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                truncate_str(model, width.saturating_sub(3)),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(detail),
    ]
}

// Connections-table column widths (characters). `models` takes whatever
// width remains.
/// Selection marker / in-flight spinner column ("▸ " / "⠹ ").
const COL_MARKER: usize = 2;
const COL_WHO: usize = 12;
const COL_PROV: usize = 7;
const COL_REQS: usize = 7;
const COL_TOK_IN: usize = 8;
const COL_TOK_OUT: usize = 8;
const COL_PAID: usize = 10;
const COL_LAST: usize = 9;
/// Minimum width of the flexible models column.
const COL_MODELS_MIN: usize = 6;

fn render_connections(frame: &mut Frame, area: Rect, app: &InferenceApp) {
    let connections = app.filtered_connections();
    frame.render_widget(
        Block::default().style(Style::default().bg(TOPUP_MAIN_BG)),
        area,
    );
    // Plain text — no border. One column of horizontal breathing room.
    let inner = Rect {
        x: area.x + 1,
        y: area.y,
        width: area.width.saturating_sub(2),
        height: area.height,
    };
    if inner.width == 0 || inner.height < 3 {
        return;
    }

    let mut title = format!("CONNECTIONS · {}", app.connections.len());
    if app.filter != Filter::All {
        title = format!(
            "CONNECTIONS · {} · filter {}",
            app.connections.len(),
            app.filter_label()
        );
    }
    // Focus cue without a border: bright title when the pane is focused.
    let title_color = if app.pane == Pane::Requests {
        Color::White
    } else {
        Color::Gray
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            title,
            Style::default().fg(title_color).bold(),
        ))),
        Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width,
            height: 1,
        },
    );

    let fixed =
        COL_MARKER + COL_WHO + COL_PROV + COL_REQS + COL_TOK_IN + COL_TOK_OUT + COL_PAID + COL_LAST;
    let models_width = (inner.width as usize)
        .saturating_sub(fixed)
        .max(COL_MODELS_MIN);

    // Header row.
    let header = format!(
        "{marker}{who:<ww$}{prov:<pw$}{models:<mw$}{req:>rw$}{tin:>iw$}{tout:>ow$}{paid:>dw$}{last:>lw$}",
        marker = " ".repeat(COL_MARKER),
        who = "who",
        prov = "prov",
        models = "models",
        req = "req",
        // ↓ tokens in (prompt), ↑ tokens out (completion) — matches the
        // web UI's arrow convention.
        tin = "↓",
        tout = "↑",
        paid = "$ paid",
        last = "last",
        ww = COL_WHO,
        pw = COL_PROV,
        mw = models_width,
        rw = COL_REQS,
        iw = COL_TOK_IN,
        ow = COL_TOK_OUT,
        dw = COL_PAID,
        lw = COL_LAST,
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            header,
            Style::default().fg(Color::DarkGray),
        ))),
        Rect {
            x: inner.x,
            y: inner.y + 1,
            width: inner.width,
            height: 1,
        },
    );

    if connections.is_empty() {
        frame.render_widget(
            Paragraph::new(
                Line::from(Span::styled(
                    "waiting for connections…",
                    Style::default().fg(Color::DarkGray),
                ))
                .centered(),
            ),
            Rect {
                x: inner.x,
                y: inner.y + inner.height / 2,
                width: inner.width,
                height: 1,
            },
        );
        return;
    }

    // Scroll the window so the selected row stays visible. Two header
    // rows: the pane title and the column labels.
    let visible = inner.height.saturating_sub(2) as usize;
    if visible == 0 {
        return;
    }
    let selected = app.selected_index().unwrap_or(0);
    let offset = selected.saturating_sub(visible.saturating_sub(1));

    for (row, (idx, conn)) in connections
        .iter()
        .enumerate()
        .skip(offset)
        .take(visible)
        .enumerate()
    {
        let line = connection_row(app, conn, models_width, idx == selected);
        frame.render_widget(
            Paragraph::new(line),
            Rect {
                x: inner.x,
                y: inner.y + 2 + row as u16,
                width: inner.width,
                height: 1,
            },
        );
    }
}

/// One connections-table row: who (payer/ip), provider, models, ok/total
/// requests, prompt/completion token totals, $ paid, last activity.
fn connection_row(
    app: &InferenceApp,
    conn: &ConnectionSummary,
    models_width: usize,
    selected: bool,
) -> Line<'static> {
    // Selection marker wins the first column; otherwise a spinner marks
    // best-effort in-flight activity on this connection.
    let marker = if selected {
        Span::styled("▸ ", Style::default().fg(SOLANA_GREEN).bold())
    } else if app.connection_in_flight(conn) {
        Span::styled(
            format!("{} ", SPINNER[app.tick % SPINNER.len()]),
            Style::default().fg(Color::Yellow),
        )
    } else {
        Span::raw("  ")
    };

    let who = who_label(conn);
    let who_color = if conn.payer.is_some() {
        Color::Cyan
    } else {
        Color::Gray
    };
    let reqs_color = if conn.failed > 0 {
        Color::Red
    } else {
        Color::Gray
    };

    let mut spans = vec![
        marker,
        Span::styled(
            pad(&truncate_str(&who, COL_WHO - 1), COL_WHO),
            Style::default().fg(who_color),
        ),
        Span::styled(
            pad(
                &truncate_str(conn.provider.as_deref().unwrap_or("—"), COL_PROV - 1),
                COL_PROV,
            ),
            Style::default().fg(Color::Cyan),
        ),
        Span::styled(
            pad(
                &truncate_str(&models_label(&conn.models), models_width.saturating_sub(1)),
                models_width,
            ),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            format!("{:>width$}", reqs_label(conn), width = COL_REQS),
            Style::default().fg(reqs_color),
        ),
        Span::styled(
            format!("{:>width$}", conn.tokens_prompt, width = COL_TOK_IN),
            Style::default().fg(Color::Gray),
        ),
        Span::styled(
            format!("{:>width$}", conn.tokens_completion, width = COL_TOK_OUT),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!("{:>width$}", paid_label(conn.paid_usd), width = COL_PAID),
            Style::default().fg(SOLANA_GREEN),
        ),
        Span::styled(
            format!("{:>width$}", short_time(&conn.updated_at), width = COL_LAST),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    if selected {
        spans = spans
            .into_iter()
            .map(|span| {
                let style = span.style.bg(CARD_BG);
                span.style(style)
            })
            .collect();
    }
    Line::from(spans)
}

fn render_controls(
    frame: &mut Frame,
    area: Rect,
    app: &InferenceApp,
    gateway_url: &str,
    has_web: bool,
) {
    let follow_label = if app.follow {
        "following"
    } else {
        "follow latest"
    };
    let filter_label = format!("filter: {}", app.filter_label());
    let mut entries: Vec<(&str, &str)> = vec![
        ("↑ ↓", "select"),
        ("⇥", "pane"),
        ("⏎", follow_label),
        ("f", &filter_label),
        ("c", "clear"),
    ];
    if has_web {
        entries.push(("w", "web ui"));
    }
    entries.push(("q", "quit"));

    let status = Line::from(vec![
        Span::styled(
            SPINNER[app.tick % SPINNER.len()].to_string(),
            Style::default().fg(SOLANA_GREEN).bold(),
        ),
        Span::styled(" live", Style::default().fg(SOLANA_GREEN)),
        Span::styled("  ·  ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{gateway_url} "), Style::default().fg(Color::Cyan)),
    ]);
    controls_bar(frame, area, &entries, Some(status));
}

// ── Display helpers ───────────────────────────────────────────────────────

/// Who a connection belongs to: shortened payer pubkey for paid traffic,
/// client ip/host otherwise.
fn who_label(conn: &ConnectionSummary) -> String {
    conn.payer
        .as_deref()
        .map(short_pubkey)
        .unwrap_or_else(|| conn.client_ip.clone())
}

/// `F82JLphK…og` style pubkey shortening: first 4 + `…` + last 4 chars.
fn short_pubkey(pubkey: &str) -> String {
    let chars: Vec<char> = pubkey.chars().collect();
    if chars.len() <= 9 {
        return pubkey.to_string();
    }
    let head: String = chars[..4].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

/// `$0.0120` — settled stablecoin total (USD, 4 decimals).
fn paid_label(paid_usd: f64) -> String {
    format!("${paid_usd:.4}")
}

/// `ok/total` request counts.
fn reqs_label(conn: &ConnectionSummary) -> String {
    format!("{}/{}", conn.ok, conn.requests)
}

/// First model plus a `+N` overflow marker (`llama3.2:3b +2`).
fn models_label(models: &[String]) -> String {
    match models.split_first() {
        None => "—".to_string(),
        Some((first, [])) => first.clone(),
        Some((first, rest)) => format!("{first} +{}", rest.len()),
    }
}

/// RFC3339 timestamp → local `HH:MM:SS`.
fn short_time(ts: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| {
            dt.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|_| ts.get(11..19).unwrap_or(ts).to_string())
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

/// Left-pad/pad `s` to exactly `width` characters.
fn pad(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pay_pdb::types::{FlowEvent, InferenceInfo, ModelPricingSummary, Protocol};

    fn provider(slug: &str, title: &str, up: bool, models: &[&str]) -> ProviderSummary {
        ProviderSummary {
            slug: slug.to_string(),
            title: title.to_string(),
            base_url: "http://127.0.0.1:11434".to_string(),
            up,
            models: models.iter().map(|m| m.to_string()).collect(),
            version: None,
            color: Some("#22c55e".to_string()),
            model_pricing: models
                .iter()
                .map(|model| ModelPricingSummary {
                    model: (*model).to_string(),
                    variant: Some((*model).to_string()),
                    price: Some("input $0.10 · output $0.20 / 1M tokens".to_string()),
                    description: None,
                })
                .collect(),
        }
    }

    fn flow(id: &str, status: FlowStatus, provider: Option<&str>) -> PaymentFlow {
        PaymentFlow {
            id: id.to_string(),
            protocol: Protocol::Http,
            scheme: None,
            resource: "/v1/chat/completions".to_string(),
            status,
            client_ip: "::1".to_string(),
            started_at: "2026-07-01T12:01:22.101Z".to_string(),
            updated_at: "2026-07-01T12:01:24.020Z".to_string(),
            duration_ms: 1919,
            amount: None,
            steps: vec![],
            events: vec![
                FlowEvent {
                    ts: "2026-07-01T12:01:22.101Z".to_string(),
                    message: "POST /v1/chat/completions".to_string(),
                    detail: Some("Request forwarded upstream".to_string()),
                },
                FlowEvent {
                    ts: "2026-07-01T12:01:24.020Z".to_string(),
                    message: "200 — completed in 1919ms".to_string(),
                    detail: None,
                },
            ],
            challenge_headers: None,
            payer: None,
            session: None,
            payment_headers: None,
            response_headers: None,
            response_body: None,
            inference: provider.map(|slug| InferenceInfo {
                provider: slug.to_string(),
                model: Some("llama3.2:3b".to_string()),
                endpoint_kind: Some("chat".to_string()),
                streamed: true,
                tokens_prompt: Some(12),
                tokens_completion: Some(214),
                ttft_ms: Some(182),
                tokens_per_sec: Some(41.2),
            }),
        }
    }

    /// Connection aggregate with the given identity/provider and activity
    /// timestamp (drives newest-first ordering).
    fn conn(
        id: &str,
        payer: Option<&str>,
        provider: Option<&str>,
        updated_at: &str,
    ) -> ConnectionSummary {
        ConnectionSummary {
            id: id.to_string(),
            payer: payer.map(str::to_string),
            client_ip: "127.0.0.1".to_string(),
            provider: provider.map(str::to_string),
            models: vec!["llama3.2:3b".to_string()],
            requests: 3,
            ok: 3,
            failed: 0,
            tokens_prompt: 120,
            tokens_completion: 450,
            paid_usd: 0.012,
            started_at: "2026-07-01T12:00:00.000Z".to_string(),
            updated_at: updated_at.to_string(),
        }
    }

    fn app_with(providers: Vec<ProviderSummary>, flows: Vec<PaymentFlow>) -> InferenceApp {
        InferenceApp::new(providers, flows, vec![], TEST_PUBLIC_URL.to_string())
    }

    fn app_with_conns(connections: Vec<ConnectionSummary>) -> InferenceApp {
        InferenceApp::new(vec![], vec![], connections, TEST_PUBLIC_URL.to_string())
    }

    const TEST_PUBLIC_URL: &str = "http://203.0.113.4:1402";

    // ── Event application ──

    #[test]
    fn snapshot_replaces_flows() {
        let mut app = app_with(
            vec![],
            vec![flow("old", FlowStatus::ResourceDelivered, None)],
        );
        app.apply_event(SseMessage::Snapshot {
            flows: vec![
                flow("a", FlowStatus::ResourceDelivered, None),
                flow("b", FlowStatus::InProgress, None),
            ],
        });
        // Snapshot arrives oldest-first; newest ("b") ends up at the front.
        let ids: Vec<&str> = app.flows.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "a"]);
    }

    #[test]
    fn flow_created_pushes_newest_first_and_ring_buffer_caps_at_200() {
        let mut app = app_with(vec![], vec![]);
        for i in 0..205 {
            app.apply_event(SseMessage::FlowCreated {
                flow: flow(&format!("flow-{i}"), FlowStatus::InProgress, None),
            });
        }
        assert_eq!(app.flows.len(), FLOW_CAP);
        assert_eq!(app.flows.front().unwrap().id, "flow-204");
        assert_eq!(app.flows.back().unwrap().id, "flow-5");
    }

    #[test]
    fn flow_updated_replaces_by_id_and_falls_back_to_push() {
        let mut app = app_with(vec![], vec![flow("a", FlowStatus::InProgress, None)]);
        app.apply_event(SseMessage::FlowUpdated {
            flow: flow("a", FlowStatus::ResourceDelivered, Some("ollama")),
        });
        assert_eq!(app.flows.len(), 1);
        assert_eq!(app.flows[0].status, FlowStatus::ResourceDelivered);
        assert!(app.flows[0].inference.is_some());

        // Unknown id (evicted or missed create) is treated as a new flow.
        app.apply_event(SseMessage::FlowUpdated {
            flow: flow("never-seen", FlowStatus::Failed, None),
        });
        assert_eq!(app.flows.len(), 2);
        assert_eq!(app.flows.front().unwrap().id, "never-seen");
    }

    #[test]
    fn provider_status_replaces_providers_and_clamps_selection_to_up_providers() {
        let mut app = app_with(
            vec![
                provider("ollama", "Ollama", true, &[]),
                provider("vllm", "vLLM", true, &[]),
            ],
            vec![],
        );
        assert_eq!(app.up_providers().len(), 2);
        app.selected_provider = 1;

        // ollama goes down: only vllm remains selectable, selection clamps.
        app.apply_event(SseMessage::ProviderStatus {
            providers: vec![
                provider("ollama", "Ollama", false, &[]),
                provider("vllm", "vLLM", true, &[]),
            ],
        });
        assert_eq!(app.providers.len(), 2);
        let ups: Vec<&str> = app.up_providers().iter().map(|p| p.slug.as_str()).collect();
        assert_eq!(ups, vec!["vllm"]);
        assert_eq!(app.selected_provider, 0);

        // Everything down: selection clamps to 0, up list is empty.
        app.apply_event(SseMessage::ProviderStatus {
            providers: vec![provider("ollama", "Ollama", false, &[])],
        });
        assert!(app.up_providers().is_empty());
        assert_eq!(app.selected_provider, 0);
    }

    #[test]
    fn init_message_is_ignored() {
        let mut app = app_with(vec![], vec![flow("a", FlowStatus::InProgress, None)]);
        app.apply_event(SseMessage::Init {
            viewer_ip: "::1".into(),
        });
        assert_eq!(app.flows.len(), 1);
        assert!(app.providers.is_empty());
    }

    // ── Connection events ──

    #[test]
    fn connections_snapshot_replaces_list_sorted_newest_first() {
        let mut app = app_with_conns(vec![conn("old", None, None, "2026-07-01T11:00:00.000Z")]);
        app.apply_event(SseMessage::ConnectionsSnapshot {
            connections: vec![
                conn("a", None, None, "2026-07-01T12:00:01.000Z"),
                conn("b", None, None, "2026-07-01T12:00:05.000Z"),
            ],
        });
        let ids: Vec<&str> = app.connections.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "a"]);
    }

    #[test]
    fn connection_updated_upserts_and_resorts_newest_first() {
        let mut app = app_with_conns(vec![
            conn("a", None, None, "2026-07-01T12:00:05.000Z"),
            conn("b", None, None, "2026-07-01T12:00:01.000Z"),
        ]);
        // Fresh activity on the older connection moves it to the front and
        // replaces its aggregates.
        let mut b = conn("b", None, Some("ollama"), "2026-07-01T12:00:10.000Z");
        b.requests = 4;
        b.ok = 4;
        app.apply_event(SseMessage::ConnectionUpdated { connection: b });
        let ids: Vec<&str> = app.connections.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["b", "a"]);
        assert_eq!(app.connections[0].requests, 4);
        assert_eq!(app.connections[0].provider.as_deref(), Some("ollama"));

        // An unseen id is inserted.
        app.apply_event(SseMessage::ConnectionUpdated {
            connection: conn("c", None, None, "2026-07-01T12:00:20.000Z"),
        });
        let ids: Vec<&str> = app.connections.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "b", "a"]);
    }

    // ── Follow-latest ──

    #[test]
    fn follow_latest_tracks_connection_activity_until_user_moves_selection() {
        let mut app = app_with_conns(vec![
            conn("a", None, None, "2026-07-01T12:00:05.000Z"),
            conn("b", None, None, "2026-07-01T12:00:01.000Z"),
        ]);
        assert!(app.follow);
        assert_eq!(app.selected_connection().unwrap().id, "a");

        // While following, fresh activity moves the selection.
        app.apply_event(SseMessage::ConnectionUpdated {
            connection: conn("b", None, None, "2026-07-01T12:00:10.000Z"),
        });
        assert_eq!(app.selected_connection().unwrap().id, "b");

        // Moving the selection pins it…
        app.handle_key(KeyCode::Down, KeyModifiers::NONE);
        assert!(!app.follow);
        assert_eq!(app.selected_connection().unwrap().id, "a");

        // …so fresh activity no longer steals it.
        app.apply_event(SseMessage::ConnectionUpdated {
            connection: conn("c", None, None, "2026-07-01T12:00:20.000Z"),
        });
        assert_eq!(app.selected_connection().unwrap().id, "a");
    }

    #[test]
    fn enter_toggles_follow_latest() {
        let mut app = app_with_conns(vec![
            conn("newest", None, None, "2026-07-01T12:00:05.000Z"),
            conn("older", None, None, "2026-07-01T12:00:01.000Z"),
        ]);
        // Pin, then re-follow via Enter.
        app.handle_key(KeyCode::Down, KeyModifiers::NONE);
        assert!(!app.follow);
        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(app.follow);
        assert_eq!(app.selected_connection().unwrap().id, "newest");

        // Enter while following pins the current newest.
        app.handle_key(KeyCode::Enter, KeyModifiers::NONE);
        assert!(!app.follow);
        assert_eq!(app.selected_id.as_deref(), Some("newest"));
    }

    // ── Filtering ──

    #[test]
    fn filter_cycles_all_errors_then_up_providers_only() {
        let mut app = app_with(
            vec![
                provider("ollama", "Ollama", true, &[]),
                provider("llama-cpp", "llama.cpp", false, &[]),
                provider("lm-studio", "LM Studio", true, &[]),
            ],
            vec![],
        );
        assert_eq!(app.filter, Filter::All);
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Errors);
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Provider("ollama".into()));
        // llama-cpp is down — skipped.
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Provider("lm-studio".into()));
        app.cycle_filter();
        assert_eq!(app.filter, Filter::All);
    }

    #[test]
    fn filter_cycle_without_up_providers_skips_provider_stage() {
        let mut app = app_with(vec![provider("ollama", "Ollama", false, &[])], vec![]);
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Errors);
        app.cycle_filter();
        assert_eq!(app.filter, Filter::All);
    }

    #[test]
    fn errors_and_provider_filters_narrow_the_connection_list() {
        let mut app = app_with_conns(vec![
            conn("ok", None, Some("ollama"), "2026-07-01T12:00:05.000Z"),
            conn("bad", None, Some("lm-studio"), "2026-07-01T12:00:01.000Z"),
        ]);
        app.connections[1].failed = 2;
        assert_eq!(app.filtered_connections().len(), 2);

        app.filter = Filter::Errors;
        let ids: Vec<&str> = app
            .filtered_connections()
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids, vec!["bad"]);

        app.filter = Filter::Provider("ollama".into());
        let ids: Vec<&str> = app
            .filtered_connections()
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids, vec!["ok"]);
    }

    #[test]
    fn cycling_filter_releases_pinned_connection_that_gets_filtered_out() {
        let mut app = app_with_conns(vec![
            conn("bad", None, None, "2026-07-01T12:00:05.000Z"),
            conn("ok", None, None, "2026-07-01T12:00:01.000Z"),
        ]);
        app.connections[0].failed = 1;
        // Pin the healthy (older) connection, then switch to errors.
        app.handle_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(app.selected_id.as_deref(), Some("ok"));
        app.cycle_filter();
        assert_eq!(app.filter, Filter::Errors);
        assert!(app.follow);
        assert_eq!(app.selected_connection().unwrap().id, "bad");
    }

    // ── Keys ──

    #[test]
    fn tab_toggles_pane_and_arrows_move_within_up_providers() {
        let mut app = app_with(
            vec![
                provider("ollama", "Ollama", true, &[]),
                provider("vllm", "vLLM", true, &[]),
                provider("llama-cpp", "llama.cpp", false, &[]),
            ],
            vec![],
        );
        assert_eq!(app.pane, Pane::Requests);
        app.handle_key(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.pane, Pane::Providers);

        app.handle_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(app.selected_provider, 1);
        // Clamped to the 2 up providers — the down one is not selectable.
        app.handle_key(KeyCode::Down, KeyModifiers::NONE);
        assert_eq!(app.selected_provider, 1);
        app.handle_key(KeyCode::Up, KeyModifiers::NONE);
        assert_eq!(app.selected_provider, 0);

        app.handle_key(KeyCode::Tab, KeyModifiers::NONE);
        assert_eq!(app.pane, Pane::Requests);
    }

    #[test]
    fn clear_empties_connections_and_flows_and_resumes_follow() {
        let mut app = InferenceApp::new(
            vec![],
            vec![flow("f1", FlowStatus::ResourceDelivered, None)],
            vec![
                conn("a", None, None, "2026-07-01T12:00:05.000Z"),
                conn("b", None, None, "2026-07-01T12:00:01.000Z"),
            ],
            TEST_PUBLIC_URL.to_string(),
        );
        app.handle_key(KeyCode::Down, KeyModifiers::NONE); // pin
        app.handle_key(KeyCode::Char('c'), KeyModifiers::NONE);
        assert!(app.connections.is_empty());
        assert!(app.flows.is_empty());
        assert!(app.follow);
        assert!(app.selected_id.is_none());
    }

    #[test]
    fn quit_and_web_keys_produce_actions() {
        let mut app = app_with(vec![], vec![]);
        assert_eq!(
            app.handle_key(KeyCode::Char('q'), KeyModifiers::NONE),
            Action::Quit
        );
        assert_eq!(
            app.handle_key(KeyCode::Esc, KeyModifiers::NONE),
            Action::Quit
        );
        assert_eq!(
            app.handle_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Action::Quit
        );
        assert_eq!(
            app.handle_key(KeyCode::Char('w'), KeyModifiers::NONE),
            Action::OpenWeb
        );
        assert_eq!(
            app.handle_key(KeyCode::Char('x'), KeyModifiers::NONE),
            Action::None
        );
    }

    // ── Display helpers ──

    #[test]
    fn connection_row_formatting_helpers() {
        // Pubkey shortening: first 4 + … + last 4; short strings untouched.
        assert_eq!(short_pubkey("F82JLphK9vCd3mgnUtog"), "F82J…Utog");
        assert_eq!(short_pubkey("shortkey1"), "shortkey1");

        // WHO: payer wins over client ip.
        let paid = conn(
            "a",
            Some("F82JLphK9vCd3mgnUtog"),
            None,
            "2026-07-01T12:00:01.000Z",
        );
        assert_eq!(who_label(&paid), "F82J…Utog");
        let anon = conn("b", None, None, "2026-07-01T12:00:01.000Z");
        assert_eq!(who_label(&anon), "127.0.0.1");

        // $ paid: 4 decimals; req counts: ok/total.
        assert_eq!(paid_label(0.012), "$0.0120");
        assert_eq!(paid_label(0.0), "$0.0000");
        assert_eq!(reqs_label(&anon), "3/3");

        // Models: first + overflow count.
        assert_eq!(models_label(&[]), "—");
        assert_eq!(models_label(&["a".to_string()]), "a");
        assert_eq!(
            models_label(&["a".to_string(), "b".to_string(), "c".to_string()]),
            "a +2"
        );
    }

    #[test]
    fn in_flight_indicator_matches_by_client_ip_or_provider() {
        let mut app = InferenceApp::new(
            vec![],
            vec![flow("f1", FlowStatus::InProgress, Some("ollama"))],
            vec![
                conn(
                    "by-provider",
                    None,
                    Some("ollama"),
                    "2026-07-01T12:00:05.000Z",
                ),
                conn("other", None, Some("lm-studio"), "2026-07-01T12:00:01.000Z"),
            ],
            TEST_PUBLIC_URL.to_string(),
        );
        // Flow client_ip is "::1" (helper default); conns use 127.0.0.1 —
        // so only the provider fallback matches.
        assert!(app.connection_in_flight(&app.connections[0].clone()));
        assert!(!app.connection_in_flight(&app.connections[1].clone()));

        // ip match works regardless of provider.
        app.flows[0].client_ip = "127.0.0.1".to_string();
        assert!(app.connection_in_flight(&app.connections[1].clone()));

        // Nothing spins once the flow completes.
        app.flows[0].status = FlowStatus::ResourceDelivered;
        assert!(!app.connection_in_flight(&app.connections[0].clone()));
        assert!(!app.connection_in_flight(&app.connections[1].clone()));
    }

    #[test]
    fn misc_helpers_format_colors_and_truncation() {
        assert_eq!(hex_color("#22c55e"), Some(Color::Rgb(0x22, 0xc5, 0x5e)));
        assert_eq!(hex_color("22c55e"), None);
        assert_eq!(hex_color("#22c5"), None);
        assert_eq!(truncate_str("abcdef", 4), "abc…");
        assert_eq!(truncate_str("abc", 4), "abc");
        assert_eq!(pad("ab", 4), "ab  ");
    }

    // ── Render smoke test ──

    fn render_to_text(app: &InferenceApp, width: u16, has_web: bool) -> String {
        let backend = ratatui::backend::TestBackend::new(width, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| render(frame, app, "http://127.0.0.1:1402", has_web))
            .unwrap();

        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    /// Rendered buffer as one `String` per row (for column-scoped checks).
    fn render_region_lines(app: &InferenceApp, width: u16, has_web: bool) -> Vec<String> {
        render_to_text(app, width, has_web)
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn render_smoke_test_contains_key_strings() {
        let app = InferenceApp::new(
            vec![
                provider("ollama", "Ollama", true, &["llama3.2:3b", "nomic-embed"]),
                provider("llama-cpp", "llama.cpp", false, &[]),
            ],
            // Flows feed the in-flight spinner only — their paths must
            // not render as table rows.
            vec![
                flow("f1", FlowStatus::ResourceDelivered, Some("ollama")),
                flow("f2", FlowStatus::InProgress, Some("ollama")),
            ],
            vec![conn(
                "conn-1",
                Some("F82JLphK9vCd3mgnUtog"),
                Some("ollama"),
                "2026-07-01T12:01:24.020Z",
            )],
            TEST_PUBLIC_URL.to_string(),
        );

        let text = render_to_text(&app, 120, true);

        // Sidebar: Solana logo (braille glyph fragment) + heading + identity card.
        assert!(text.contains("⣠⣶"), "missing solana logo:\n{text}");
        assert!(
            text.contains("INFERENCE SERVER"),
            "missing sidebar heading:\n{text}"
        );
        // Identity card shows the public address.
        assert!(
            text.contains("203.0.113.4"),
            "missing public address on identity card:\n{text}"
        );
        assert!(
            text.contains("2 models"),
            "missing model count on identity card:\n{text}"
        );
        // The chart is gone — no legend renders.
        assert!(
            !text.contains("tok/s ▮"),
            "chart legend should be gone:\n{text}"
        );
        assert!(text.contains("Ollama"), "missing provider title:\n{text}");
        assert!(text.contains("llama3.2:3b"), "missing model name:\n{text}");
        assert!(
            text.contains("input $0.10 · output $0.20 / 1M"),
            "missing model pricing in sidebar:\n{text}"
        );
        assert!(text.contains("web ui"), "missing web control:\n{text}");
        // Connections table: aggregates for the one connection row.
        assert!(
            text.contains("CONNECTIONS"),
            "missing connections table title:\n{text}"
        );
        assert!(
            text.contains("F82J…Utog"),
            "missing shortened payer:\n{text}"
        );
        assert!(text.contains("$0.0120"), "missing paid aggregate:\n{text}");
        assert!(text.contains("450"), "missing completion tokens:\n{text}");
        assert!(text.contains("3/3"), "missing ok/total requests:\n{text}");
        // Per-message rows are gone: flow paths no longer render.
        assert!(
            !text.contains("/v1/chat"),
            "per-message flow rows should be gone:\n{text}"
        );
        assert!(
            !text.contains("REQUESTS"),
            "requests table should be gone:\n{text}"
        );
        // No header row, and down providers are not rendered at all.
        assert!(
            !text.contains("Pay Inference"),
            "header row should be gone:\n{text}"
        );
        assert!(
            !text.contains("not detected"),
            "down provider rendered:\n{text}"
        );
        assert!(
            !text.contains("llama.cpp"),
            "down provider card rendered:\n{text}"
        );
        assert!(
            !text.contains("DETAIL"),
            "detail panel should be gone:\n{text}"
        );
        // The connections table (right pane, x >= 45) stays borderless; the
        // sidebar identity card is intentionally bordered, so scope the
        // check to the connections region.
        let connections_borderless = render_region_lines(&app, 120, true).iter().all(|line| {
            let right: String = line.chars().skip(45).collect();
            !right.contains('╭') && !right.contains('┌')
        });
        assert!(
            connections_borderless,
            "connections pane should render no border glyphs"
        );
        // The sidebar card, by contrast, draws a rounded border.
        assert!(
            text.contains('╭'),
            "identity card should render a rounded border:\n{text}"
        );
    }

    #[test]
    fn render_smoke_test_empty_state_shows_no_providers_detected() {
        let app = app_with(vec![provider("ollama", "Ollama", false, &[])], vec![]);

        let text = render_to_text(&app, 100, false);

        assert!(
            text.contains("no inference server detected"),
            "missing empty state:\n{text}"
        );
        assert!(
            text.contains("waiting for connections…"),
            "missing empty connections state:\n{text}"
        );
        assert!(!text.contains("Ollama"), "down provider rendered:\n{text}");
        assert!(
            !text.contains("web ui"),
            "web control without web_url:\n{text}"
        );
    }
}
