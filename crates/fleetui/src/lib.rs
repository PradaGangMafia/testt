//! Read-mostly terminal dashboard for a coordinator state directory.
//!
//! The UI reads the same encrypted SQLite database as `coordctl`. `v` toggles
//! revocation of the selected agent; `r` reloads immediately.

#![forbid(unsafe_code)]

use std::{
    path::Path,
    time::{Duration, Instant},
};

use db::Database;
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Tabs},
    Frame,
};

/// Top-level section.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tab {
    /// Enrolled hosts.
    Agents,
    /// Findings.
    Findings,
    /// Stored artifacts.
    Artifacts,
    /// Schedules.
    Schedules,
    /// Events.
    Events,
}

impl Tab {
    /// Ordered tabs for the tab bar.
    pub const ALL: [Tab; 5] = [
        Tab::Agents,
        Tab::Findings,
        Tab::Artifacts,
        Tab::Schedules,
        Tab::Events,
    ];
    /// Display title.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Agents => "Agents",
            Tab::Findings => "Findings",
            Tab::Artifacts => "Artifacts",
            Tab::Schedules => "Schedules",
            Tab::Events => "Events",
        }
    }
}

/// One rendered row in the active table.
#[derive(Clone, Debug, Default)]
pub struct Entry {
    /// Short route tag or identifier.
    pub key: String,
    /// Secondary columns.
    pub values: Vec<String>,
}

/// Everything the dashboard shows at one point in time.
#[derive(Default)]
pub struct Snapshot {
    /// Agent rows.
    pub agents: Vec<Entry>,
    /// Finding rows.
    pub findings: Vec<Entry>,
    /// Artifact rows.
    pub artifacts: Vec<Entry>,
    /// Schedule rows.
    pub schedules: Vec<Entry>,
    /// Event rows.
    pub events: Vec<Entry>,
    /// Counters: agents, results, findings, events.
    pub stats: (u64, u64, u64, u64),
}

fn tag(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Loads a snapshot from the database.
pub fn load(database: &Database) -> Result<Snapshot, db::Error> {
    let mut snapshot = Snapshot::default();
    let stats = database.stats()?;
    snapshot.stats = (stats.agents, stats.results, stats.findings, stats.events);
    for agent in database.agents()? {
        snapshot.agents.push(Entry {
            key: tag(&agent.route_tag),
            values: vec![
                agent.last_seen.to_string(),
                agent.results.to_string(),
                if agent.revoked { "yes" } else { "no" }.into(),
            ],
        });
    }
    for finding in database.recent_findings(200)? {
        snapshot.findings.push(Entry {
            key: finding.kind,
            values: vec![
                finding.severity.to_string(),
                finding.dedupe_key,
                finding.data,
            ],
        });
    }
    for artifact in database.artifacts()? {
        snapshot.artifacts.push(Entry {
            key: artifact.kind,
            values: vec![
                artifact.size.to_string(),
                artifact.path,
                artifact.sha256[..12.min(artifact.sha256.len())].to_owned(),
            ],
        });
    }
    for schedule in database.schedules()? {
        snapshot.schedules.push(Entry {
            key: tag(&schedule.route_tag),
            values: vec![
                format!("{}@{}", schedule.mod_id, schedule.version),
                format!("every {}s", schedule.every_s),
                schedule.next_at.to_string(),
            ],
        });
    }
    for (kind, detail, at) in database.recent_events(200)? {
        snapshot.events.push(Entry {
            key: kind,
            values: vec![detail, at.to_string()],
        });
    }
    Ok(snapshot)
}

/// Draws the dashboard.
pub fn draw(frame: &mut Frame<'_>, snapshot: &Snapshot, tab: Tab) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let (agents, results, findings, events) = snapshot.stats;
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("AGENT FLEET", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(
                "   agents {agents}  results {results}  findings {findings}  events {events}"
            )),
        ])),
        chunks[0],
    );

    let titles = Tab::ALL.iter().map(|tab| tab.title());
    frame.render_widget(
        Tabs::new(titles)
            .select(
                Tab::ALL
                    .iter()
                    .position(|candidate| *candidate == tab)
                    .unwrap_or(0),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        chunks[1],
    );

    let rows: Vec<Row> = match tab {
        Tab::Agents => snapshot
            .agents
            .iter()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.key.clone()),
                    Cell::from(entry.values[0].clone()),
                    Cell::from(entry.values[1].clone()),
                    Cell::from(entry.values[2].clone()),
                ])
            })
            .collect(),
        other => {
            let entries = match other {
                Tab::Findings => &snapshot.findings,
                Tab::Artifacts => &snapshot.artifacts,
                Tab::Schedules => &snapshot.schedules,
                Tab::Events => &snapshot.events,
                Tab::Agents => unreachable!(),
            };
            entries
                .iter()
                .map(|entry| {
                    let mut cells = vec![Cell::from(entry.key.clone())];
                    cells.extend(entry.values.iter().cloned().map(Cell::from));
                    Row::new(cells)
                })
                .collect()
        }
    };
    let widths: &[Constraint] = match tab {
        Tab::Agents => &[
            Constraint::Length(18),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Min(6),
        ],
        Tab::Findings => &[
            Constraint::Length(12),
            Constraint::Length(4),
            Constraint::Min(24),
        ],
        Tab::Artifacts => &[
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Min(24),
            Constraint::Length(12),
        ],
        Tab::Schedules => &[
            Constraint::Length(18),
            Constraint::Min(20),
            Constraint::Length(12),
            Constraint::Length(12),
        ],
        Tab::Events => &[
            Constraint::Length(18),
            Constraint::Min(24),
            Constraint::Length(12),
        ],
    };
    frame.render_widget(
        Table::new(rows, widths).block(Block::default().borders(Borders::ALL).title(tab.title())),
        chunks[2],
    );
    frame.render_widget(
        Paragraph::new("1-5/tab section   v revoke/unrevoke selected   r reload   q quit")
            .style(Style::default().fg(Color::DarkGray)),
        chunks[3],
    );
}

/// Runs the interactive loop until `q`.
pub fn run(state: &Path) -> std::io::Result<()> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::Terminal;

    let database =
        coordd::open_database(state).map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut tab = Tab::Agents;
    let mut selected = 0_usize;

    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut snapshot = load(&database).map_err(std::io::Error::other)?;
    let mut refreshed = Instant::now();
    loop {
        terminal.draw(|frame| draw(frame, &snapshot, tab))?;
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('r') => {
                        snapshot = load(&database).map_err(std::io::Error::other)?;
                        refreshed = Instant::now();
                    }
                    KeyCode::Tab | KeyCode::Char('1') => tab = Tab::Agents,
                    KeyCode::Char('2') => tab = Tab::Findings,
                    KeyCode::Char('3') => tab = Tab::Artifacts,
                    KeyCode::Char('4') => tab = Tab::Schedules,
                    KeyCode::Char('5') => tab = Tab::Events,
                    KeyCode::Down | KeyCode::Char('j') => selected = selected.saturating_add(1),
                    KeyCode::Up | KeyCode::Char('k') => selected = selected.saturating_sub(1),
                    KeyCode::Char('v') if tab == Tab::Agents => {
                        if let Some(row) = snapshot.agents.get(selected) {
                            if let Some(agent) = database
                                .agents()
                                .map_err(std::io::Error::other)?
                                .into_iter()
                                .find(|agent| tag(&agent.route_tag) == row.key)
                            {
                                database
                                    .set_revoked(&agent.route_tag, !agent.revoked)
                                    .map_err(std::io::Error::other)?;
                                snapshot = load(&database).map_err(std::io::Error::other)?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        if refreshed.elapsed() >= Duration::from_secs(2) {
            snapshot = load(&database).map_err(std::io::Error::other)?;
            refreshed = Instant::now();
        }
    }
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
