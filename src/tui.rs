use crate::cleaner::clean_transcripts_filtered;
use crate::cli::{ScanArgs, UiArgs};
use crate::config::PolicyConfig;
use crate::report::FullScanReport;
use crate::rules::Severity;
use crate::run_scan_report;
use crate::tap::{default_live_log_path, WiretapEvent};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::{Backend, CrosstermBackend, TestBackend};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap};
use ratatui::{Frame, Terminal};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Once;
use std::time::{Duration, Instant};

static TUI_PANIC_HOOK_ONCE: Once = Once::new();

fn ensure_tui_panic_hook() {
    TUI_PANIC_HOOK_ONCE.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let _ = disable_raw_mode();
            let mut stdout = io::stdout();
            let _ = execute!(stdout, LeaveAlternateScreen);
            prev(info);
        }));
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    Secrets = 0,
    Mcp = 1,
    Live = 2,
    Pii = 3,
}

impl ActiveTab {
    fn next(self) -> Self {
        match self {
            ActiveTab::Secrets => ActiveTab::Mcp,
            ActiveTab::Mcp => ActiveTab::Live,
            ActiveTab::Live => ActiveTab::Pii,
            ActiveTab::Pii => ActiveTab::Secrets,
        }
    }

    fn prev(self) -> Self {
        match self {
            ActiveTab::Secrets => ActiveTab::Pii,
            ActiveTab::Mcp => ActiveTab::Secrets,
            ActiveTab::Live => ActiveTab::Mcp,
            ActiveTab::Pii => ActiveTab::Live,
        }
    }
}

pub struct DashboardApp {
    pub scan_args: ScanArgs,
    pub include_code: bool,
    pub report: FullScanReport,
    pub live_log_path: Option<PathBuf>,
    pub live_events: Vec<WiretapEvent>,
    pub tab: ActiveTab,
    pub secret_state: TableState,
    pub mcp_state: TableState,
    pub live_state: TableState,
    pub pii_state: TableState,
    pub confirming_scrub: bool,
    pub status_msg: String,
}

impl DashboardApp {
    pub fn new(args: &UiArgs) -> Self {
        let scan_args = ScanArgs {
            paths: args.paths.clone(),
            config: args.config.clone(),
            trust_project_config: args.trust_project_config,
            no_config: args.no_config,
            ..Default::default()
        };
        let report = run_scan_report(&scan_args);
        let live_log_path = args.log.clone().or_else(default_live_log_path);
        let live_events = read_recent_wiretap_events(live_log_path.as_ref(), 250);

        let mut app = Self {
            scan_args,
            include_code: args.include_code,
            report,
            live_log_path,
            live_events,
            tab: ActiveTab::Secrets,
            secret_state: TableState::default(),
            mcp_state: TableState::default(),
            live_state: TableState::default(),
            pii_state: TableState::default(),
            confirming_scrub: false,
            status_msg:
                "Keys: [1-4/Tab] switch tabs · [j/k or ↑/↓] move · [c] scrub selected secret · [r] rescan · [q/Ctrl+C] quit"
                    .to_string(),
        };
        app.clamp_selections();
        app
    }

    pub fn reload_live_events(&mut self) {
        self.live_events = read_recent_wiretap_events(self.live_log_path.as_ref(), 250);
        self.clamp_selections();
    }

    pub fn rescan(&mut self) {
        self.confirming_scrub = false;
        self.report = run_scan_report(&self.scan_args);
        self.reload_live_events();
        self.status_msg = format!(
            "Rescanned in {}ms — {} secret(s), {} MCP/plugin risk(s), {} PII item(s).",
            self.report.duration.as_millis(),
            self.report.transcripts.secret_findings.len(),
            self.report.mcp_findings.len(),
            self.report.transcripts.pii_findings.len()
        );
    }

    fn current_len(&self) -> usize {
        match self.tab {
            ActiveTab::Secrets => self.report.transcripts.secret_findings.len(),
            ActiveTab::Mcp => self.report.mcp_findings.len(),
            ActiveTab::Live => self.live_events.len(),
            ActiveTab::Pii => self.report.transcripts.pii_findings.len(),
        }
    }

    fn active_table_state_mut(&mut self) -> &mut TableState {
        match self.tab {
            ActiveTab::Secrets => &mut self.secret_state,
            ActiveTab::Mcp => &mut self.mcp_state,
            ActiveTab::Live => &mut self.live_state,
            ActiveTab::Pii => &mut self.pii_state,
        }
    }

    fn clamp_selections(&mut self) {
        clamp_state(
            &mut self.secret_state,
            self.report.transcripts.secret_findings.len(),
        );
        clamp_state(&mut self.mcp_state, self.report.mcp_findings.len());
        clamp_state(&mut self.live_state, self.live_events.len());
        clamp_state(
            &mut self.pii_state,
            self.report.transcripts.pii_findings.len(),
        );
    }

    pub fn move_down(&mut self) {
        let len = self.current_len();
        if len == 0 {
            return;
        }
        let st = self.active_table_state_mut();
        let next = match st.selected() {
            Some(i) if i + 1 < len => i + 1,
            _ => 0,
        };
        st.select(Some(next));
    }

    pub fn move_up(&mut self) {
        let len = self.current_len();
        if len == 0 {
            return;
        }
        let st = self.active_table_state_mut();
        let prev = match st.selected() {
            Some(0) | None => len - 1,
            Some(i) => i - 1,
        };
        st.select(Some(prev));
    }

    fn collect_scrubbable_paths_for_finding(
        &self,
        finding: &crate::scanner::TranscriptFinding,
    ) -> (Vec<PathBuf>, usize) {
        let unique_paths: Vec<PathBuf> = if finding.locations.is_empty() {
            vec![finding.first_path.clone()]
        } else {
            finding
                .locations
                .iter()
                .map(|loc| loc.path.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        if self.include_code {
            return (unique_paths, 0);
        }
        let mut allowed = Vec::new();
        let mut skipped_non_session = 0usize;
        for p in unique_paths {
            if crate::discovery::is_safe_default_clean_target(&p) {
                allowed.push(p);
            } else {
                skipped_non_session += 1;
            }
        }
        (allowed, skipped_non_session)
    }

    pub fn request_scrub_selected_secret_file(&mut self) {
        if self.tab != ActiveTab::Secrets {
            return;
        }
        let Some(idx) = self.secret_state.selected() else {
            return;
        };
        let Some(finding) = self.report.transcripts.secret_findings.get(idx).cloned() else {
            return;
        };
        let (allowed_paths, skipped_non_session) =
            self.collect_scrubbable_paths_for_finding(&finding);
        if allowed_paths.is_empty() && skipped_non_session > 0 {
            self.confirming_scrub = false;
            self.status_msg = format!(
                "Refused to scrub non-session file {} (restart with `leaktap ui --include-code` to modify source/config files).",
                finding.first_file
            );
            return;
        }
        self.confirming_scrub = true;
        self.status_msg = format!(
            "Confirm in-place scrub of {} ({}) across {} session file(s)? Press [y] to apply or [n/Esc] to cancel.",
            finding.rule_name,
            finding.masked,
            allowed_paths.len().max(1)
        );
    }

    /// Processes a single terminal key press. Returns `true` when the dashboard should exit.
    pub fn handle_key_event(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return false;
        }

        // CRITICAL: In raw terminal mode, `Ctrl+C` arrives as `KeyCode::Char('c')` with `KeyModifiers::CONTROL`.
        // Always check `CONTROL` modifiers FIRST so `Ctrl+C` / `Ctrl+D` exits cleanly without touching any files.
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            if matches!(
                key.code,
                KeyCode::Char('c') | KeyCode::Char('C') | KeyCode::Char('d') | KeyCode::Char('D')
            ) {
                self.confirming_scrub = false;
                return true;
            }
            return false;
        }

        if self.confirming_scrub {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.confirming_scrub = false;
                    self.scrub_selected_secret_file();
                }
                _ => {
                    self.confirming_scrub = false;
                    self.status_msg = "Scrub cancelled — no files modified.".to_string();
                }
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
                self.tab = self.tab.next();
            }
            KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => {
                self.tab = self.tab.prev();
            }
            KeyCode::Char('1') => self.tab = ActiveTab::Secrets,
            KeyCode::Char('2') => self.tab = ActiveTab::Mcp,
            KeyCode::Char('3') => self.tab = ActiveTab::Live,
            KeyCode::Char('4') => self.tab = ActiveTab::Pii,
            KeyCode::Down | KeyCode::Char('j') => self.move_down(),
            KeyCode::Up | KeyCode::Char('k') => self.move_up(),
            KeyCode::Char('r') => self.rescan(),
            KeyCode::Char('c') if !key.modifiers.contains(KeyModifiers::ALT) => {
                self.request_scrub_selected_secret_file();
            }
            _ => {}
        }
        false
    }

    pub fn scrub_selected_secret_file(&mut self) {
        if self.tab != ActiveTab::Secrets {
            return;
        }
        let Some(idx) = self.secret_state.selected() else {
            return;
        };
        let Some(finding) = self.report.transcripts.secret_findings.get(idx).cloned() else {
            return;
        };

        let (allowed_paths, skipped_non_session) =
            self.collect_scrubbable_paths_for_finding(&finding);
        if allowed_paths.is_empty() {
            self.status_msg = format!(
                "Refused to scrub non-session file {} (restart with `leaktap ui --include-code` to modify source/config files).",
                finding.first_file
            );
            return;
        }

        let policy = PolicyConfig::load_with_options(
            self.scan_args.config.as_deref(),
            &self.scan_args.paths,
            self.scan_args.trust_project_config,
            self.scan_args.no_config,
        )
        .ok();

        match clean_transcripts_filtered(
            &allowed_paths,
            true,
            false,
            policy.as_ref(),
            Some(&finding.fingerprint),
        ) {
            Ok(summary) => {
                self.report = run_scan_report(&self.scan_args);
                self.clamp_selections();
                if !summary.skipped_binary_files.is_empty() && summary.total_redactions == 0 {
                    self.status_msg = format!(
                        "Skipped binary SQLite file {} (use CLI session clear to purge DB rows).",
                        finding.first_file
                    );
                } else if skipped_non_session > 0 {
                    self.status_msg = format!(
                        "Scrubbed {} instance(s) across {} session file(s); skipped {} repo/config file(s) (pass --include-code).",
                        summary.total_redactions,
                        summary.files_modified.len(),
                        skipped_non_session
                    );
                } else {
                    self.status_msg = format!(
                        "Scrubbed {} instance(s) of {} across {} file(s).",
                        summary.total_redactions,
                        finding.masked,
                        summary.files_modified.len()
                    );
                }
            }
            Err(err) => {
                self.status_msg = format!("Clean failed on {}: {err}", finding.first_file);
            }
        }
    }
}

fn clamp_state(state: &mut TableState, len: usize) {
    if len == 0 {
        state.select(None);
    } else {
        let sel = state.selected().unwrap_or(0).min(len - 1);
        state.select(Some(sel));
    }
}

pub fn run_ui(args: &UiArgs) -> io::Result<i32> {
    let mut app = DashboardApp::new(args);

    if args.once {
        let snapshot = render_snapshot_text(&mut app, 110, 28)?;
        print!("{snapshot}");
        return Ok(0);
    }

    ensure_tui_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = event_loop(&mut terminal, &mut app);

    let _ = disable_raw_mode();
    let _ = execute!(terminal.backend_mut(), LeaveAlternateScreen);
    let _ = terminal.show_cursor();

    res?;
    Ok(0)
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut DashboardApp) -> io::Result<()>
where
    io::Error: From<B::Error>,
{
    let mut last_live_poll = Instant::now();

    loop {
        terminal.draw(|f| draw_dashboard(f, app))?;

        if event::poll(Duration::from_millis(120))? {
            if let Event::Key(key) = event::read()? {
                if app.handle_key_event(key) {
                    return Ok(());
                }
            }
        }

        if last_live_poll.elapsed() >= Duration::from_millis(400) {
            app.reload_live_events();
            last_live_poll = Instant::now();
        }
    }
}

pub fn render_snapshot_text(app: &mut DashboardApp, width: u16, height: u16) -> io::Result<String> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("TestBackend init is infallible");
    terminal
        .draw(|f| draw_dashboard(f, app))
        .expect("TestBackend draw is infallible");

    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        let mut line = String::new();
        for x in 0..width {
            line.push_str(buf[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    Ok(out)
}

pub fn draw_dashboard(f: &mut Frame, app: &mut DashboardApp) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(6),
            Constraint::Length(2),
        ])
        .split(f.area());

    draw_top_tabs(f, app, chunks[0]);

    match app.tab {
        ActiveTab::Secrets => {
            draw_secrets_table(f, app, chunks[1]);
            draw_secret_detail(f, app, chunks[2]);
        }
        ActiveTab::Mcp => {
            draw_mcp_table(f, app, chunks[1]);
            draw_mcp_detail(f, app, chunks[2]);
        }
        ActiveTab::Live => {
            draw_live_table(f, app, chunks[1]);
            draw_live_detail(f, app, chunks[2]);
        }
        ActiveTab::Pii => {
            draw_pii_table(f, app, chunks[1]);
            draw_pii_detail(f, app, chunks[2]);
        }
    }

    let footer_style = if app.confirming_scrub {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(&app.status_msg, footer_style),
    ]));
    f.render_widget(footer, chunks[3]);
}

fn draw_top_tabs(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let sec_n = app.report.transcripts.secret_findings.len();
    let mcp_n = app.report.mcp_findings.len();
    let live_n = app.live_events.len();
    let pii_n = app.report.transcripts.pii_findings.len();

    let titles = vec![
        Line::from(format!(" [1] Transcript Leaks ({sec_n}) ")),
        Line::from(format!(" [2] MCP & Plugin Risks ({mcp_n}) ")),
        Line::from(format!(" [3] Live Wiretap ({live_n}) ")),
        Line::from(format!(" [4] Context & PII ({pii_n}) ")),
    ];

    let title_block = Block::default().borders(Borders::ALL).title(format!(
        " leaktap v{} — {} file(s) scanned in {}ms ",
        env!("CARGO_PKG_VERSION"),
        app.report.transcripts.files_scanned + app.report.mcp_files_scanned,
        app.report.duration.as_millis()
    ));

    let tabs = Tabs::new(titles)
        .block(title_block)
        .select(app.tab as usize)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn draw_secrets_table(f: &mut Frame, app: &mut DashboardApp, area: Rect) {
    let header = Row::new(vec!["Severity", "Type", "Masked Value", "Hits", "Location"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .report
        .transcripts
        .secret_findings
        .iter()
        .map(|item| {
            Row::new(vec![
                Cell::from(item.severity.as_str()).style(severity_style(item.severity)),
                Cell::from(item.rule_name.clone()),
                Cell::from(item.masked.clone()).style(Style::default().fg(Color::Yellow)),
                Cell::from(format!("{}x", item.occurrences)),
                Cell::from(format!("{}:{}", item.first_file, item.first_line)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(20),
            Constraint::Length(22),
            Constraint::Length(6),
            Constraint::Min(24),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Detected Secrets "),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.secret_state);
}

fn draw_secret_detail(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let text = if let Some(idx) = app.secret_state.selected() {
        if let Some(item) = app.report.transcripts.secret_findings.get(idx) {
            vec![
                Line::from(vec![
                    Span::styled("Rule: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{} ({})  ", item.rule_name, item.rule_id)),
                    Span::styled("FP: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{}  ", item.fingerprint)),
                    Span::styled("First seen: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{}:{}", item.first_file, item.first_line)),
                ]),
                Line::from(format!(
                    "Appears {} time(s) across {} file(s). Press [c] then [y] to scrub ONLY this secret across session file(s).",
                    item.occurrences, item.distinct_files
                )),
            ]
        } else {
            vec![Line::from("No secret selected.")]
        }
    } else {
        vec![Line::from("✓ Clean — 0 leaked secrets found.")]
    };

    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Details "))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_mcp_table(f: &mut Frame, app: &mut DashboardApp, area: Rect) {
    let header = Row::new(vec!["Severity", "Target", "File", "Issue"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .report
        .mcp_findings
        .iter()
        .map(|m| {
            let loc = if m.line > 0 {
                format!("{}:{}", m.config_file, m.line)
            } else {
                m.config_file.clone()
            };
            Row::new(vec![
                Cell::from(m.severity.as_str()).style(severity_style(m.severity)),
                Cell::from(m.server_name.clone()),
                Cell::from(loc),
                Cell::from(m.message.clone()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(22),
            Constraint::Length(26),
            Constraint::Min(28),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" MCP, Plugin, Hook & Skill Audit "),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.mcp_state);
}

fn draw_mcp_detail(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let text = if let Some(idx) = app.mcp_state.selected() {
        if let Some(m) = app.report.mcp_findings.get(idx) {
            let loc = if m.line > 0 {
                format!("{}:{}", m.config_file, m.line)
            } else {
                m.config_file.clone()
            };
            vec![
                Line::from(format!(
                    "`{}` in {} ({} · fp:{})",
                    m.server_name, loc, m.rule_id, m.fingerprint
                )),
                Line::from(m.message.clone()),
            ]
        } else {
            vec![Line::from("No finding selected.")]
        }
    } else {
        vec![Line::from(
            "✓ Clean — 0 risky MCP, plugin, hook, or skill settings detected.",
        )]
    };

    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Details "))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_live_table(f: &mut Frame, app: &mut DashboardApp, area: Rect) {
    let header = Row::new(vec!["Severity", "Stream", "Kind", "Detail"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .live_events
        .iter()
        .map(|ev| {
            let sev_style = match ev.severity.as_str() {
                "CRITICAL" => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                "HIGH" => Style::default().fg(Color::Yellow),
                _ => Style::default().fg(Color::Cyan),
            };
            Row::new(vec![
                Cell::from(ev.severity.clone()).style(sev_style),
                Cell::from(ev.stream.clone()),
                Cell::from(ev.kind.clone()),
                Cell::from(ev.detail.clone()),
            ])
        })
        .collect();

    let log_label = app
        .live_log_path
        .as_deref()
        .map(crate::discovery::shorten_home)
        .unwrap_or_else(|| "~/.leaktap/live.jsonl".to_string());

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(13),
            Constraint::Length(18),
            Constraint::Min(32),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Live Wiretap Stream ({log_label}) ")),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.live_state);
}

fn draw_live_detail(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let text = if let Some(idx) = app.live_state.selected() {
        if let Some(ev) = app.live_events.get(idx) {
            vec![
                Line::from(format!(
                    "[{}] stream=`{}` rule=`{}`",
                    ev.severity, ev.stream, ev.rule_id
                )),
                Line::from(ev.detail.clone()),
            ]
        } else {
            vec![Line::from("No live event selected.")]
        }
    } else {
        vec![
            Line::from("No live wiretap events recorded yet."),
            Line::from(
                "Run `leaktap claude` (or `leaktap codex` / `leaktap agy`) in another terminal to stream live events here.",
            ),
        ]
    };

    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Live Event "))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_pii_table(f: &mut Frame, app: &mut DashboardApp, area: Rect) {
    let header = Row::new(vec!["Severity", "Type", "Masked Value", "Hits", "Location"]).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = app
        .report
        .transcripts
        .pii_findings
        .iter()
        .map(|item| {
            Row::new(vec![
                Cell::from(item.severity.as_str()).style(severity_style(item.severity)),
                Cell::from(item.rule_name.clone()),
                Cell::from(item.masked.clone()).style(Style::default().fg(Color::Cyan)),
                Cell::from(format!("{}x", item.occurrences)),
                Cell::from(format!("{}:{}", item.first_file, item.first_line)),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(22),
            Constraint::Length(24),
            Constraint::Length(6),
            Constraint::Min(24),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Outbound Context & Internal Metadata (Emails & Hostnames) "),
    )
    .row_highlight_style(
        Style::default()
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▸ ");

    f.render_stateful_widget(table, area, &mut app.pii_state);
}

fn draw_pii_detail(f: &mut Frame, app: &DashboardApp, area: Rect) {
    let text = if let Some(idx) = app.pii_state.selected() {
        if let Some(item) = app.report.transcripts.pii_findings.get(idx) {
            vec![
                Line::from(vec![
                    Span::styled("Rule: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{} ({})  ", item.rule_name, item.rule_id)),
                    Span::styled("First seen: ", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(format!("{}:{}", item.first_file, item.first_line)),
                ]),
                Line::from(format!(
                    "Appears {} time(s) across {} file(s). (`leaktap clean` leaves emails and hostnames untouched; pass `--no-pii` during `scan` to hide.)",
                    item.occurrences, item.distinct_files
                )),
            ]
        } else {
            vec![Line::from("No metadata item selected.")]
        }
    } else {
        vec![Line::from(
            "✓ Clean — 0 personal emails or internal *.corp/*.internal hostnames detected.",
        )]
    };

    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title(" Details "))
        .wrap(Wrap { trim: true });
    f.render_widget(p, area);
}

fn severity_style(sev: Severity) -> Style {
    match sev {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::Yellow),
        Severity::Medium => Style::default().fg(Color::Cyan),
    }
}

const LIVE_LOG_TAIL_BYTES: u64 = 256 * 1024;

pub fn read_recent_wiretap_events(path: Option<&PathBuf>, max_items: usize) -> Vec<WiretapEvent> {
    let Some(p) = path else {
        return Vec::new();
    };
    let Ok(mut file) = File::open(p) else {
        return Vec::new();
    };
    let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut skip_partial_first_line = false;
    if file_len > LIVE_LOG_TAIL_BYTES {
        let start = file_len - LIVE_LOG_TAIL_BYTES;
        if file.seek(SeekFrom::Start(start - 1)).is_ok() {
            let mut prev = [0u8; 1];
            if file.read_exact(&mut prev).is_ok() && prev[0] != b'\n' {
                skip_partial_first_line = true;
            }
        }
    }
    let mut reader = BufReader::new(file);
    if skip_partial_first_line {
        let mut discard = Vec::new();
        let _ = reader.read_until(b'\n', &mut discard);
    }
    let mut events: Vec<WiretapEvent> = reader
        .lines()
        .map_while(Result::ok)
        .filter_map(|line| serde_json::from_str::<WiretapEvent>(&line).ok())
        .collect();
    // Show newest events at the top
    events.reverse();
    events.truncate(max_items);
    events
}
