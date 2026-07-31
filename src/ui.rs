//! Terminal rendering.
//!
//! The layout degrades in stages rather than refusing to draw: on a short
//! terminal the detail pane goes first, then the header, and the check list —
//! the only thing that actually matters — is the last to be given up.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};

use crate::app::{ActionState, App, Row, Summary};
use crate::checks::Severity;
use crate::history::{SPARK_WIDTH, spark_glyph};

pub use crate::timefmt::{format_age, format_local, format_ts};

const HEADER_H: u16 = 3;
const DETAIL_H: u16 = 6;
const FOOTER_H: u16 = 1;
/// Below this the detail pane is dropped.
const DETAIL_MIN_H: u16 = 14;
/// Below this the header is dropped too.
const HEADER_MIN_H: u16 = 6;
/// Below this we can only apologise.
const MIN_H: u16 = 3;

const SPINNER: [&str; 4] = ["|", "/", "-", "\\"];
const LABEL_W: usize = 22;

/// Rendering state that must survive between frames (the list scroll offset).
#[derive(Default)]
pub struct UiState {
    list: ListState,
}

pub fn draw(f: &mut Frame, app: &App, ui: &mut UiState) {
    let area = f.area();

    if area.height < MIN_H || area.width < 20 {
        draw_too_small(f, area);
        return;
    }

    let show_header = area.height >= HEADER_MIN_H;
    let show_detail = area.height >= DETAIL_MIN_H;

    let constraints = [
        Constraint::Length(if show_header { HEADER_H } else { 0 }),
        Constraint::Min(1),
        Constraint::Length(if show_detail { DETAIL_H } else { 0 }),
        Constraint::Length(FOOTER_H),
    ];
    let chunks = Layout::vertical(constraints).split(area);

    if show_header {
        draw_header(f, chunks[0], app);
    }
    draw_list(f, chunks[1], app, ui);
    if show_detail {
        draw_detail(f, chunks[2], app);
    }
    draw_footer(f, chunks[3], app);

    if app.show_help {
        draw_help(f, area);
    }
    if app.action_is_modal() {
        draw_action(f, area, app);
    }
}

// ---------------------------------------------------------------------------
// Sections
// ---------------------------------------------------------------------------

fn draw_too_small(f: &mut Frame, area: Rect) {
    let msg = if area.height < 2 {
        "too small".to_string()
    } else {
        format!("Terminal too small (need >{MIN_H} rows)")
    };
    f.render_widget(
        Paragraph::new(msg)
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Center),
        area,
    );
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let title = " OPSEC Health Dashboard ";
    let stamp = match app.age() {
        Some(age) => format!(
            "{}  ({})  ",
            format_local(app.last_refresh),
            format_age(age)
        ),
        None => "refreshing…  ".to_string(),
    };

    // Two borders plus the leading space of the title.
    let used = title.chars().count() + stamp.chars().count() + 2;
    let pad = (area.width as usize).saturating_sub(used);

    let line = Line::from(vec![
        Span::styled(
            title,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" ".repeat(pad)),
        Span::styled(stamp, Style::default().fg(Color::DarkGray)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(severity_color(app.worst())));
    f.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_list(f: &mut Frame, area: Rect, app: &App, ui: &mut UiState) {
    let visible = app.visible();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(summary_line(app.summary()))
        .title_alignment(Alignment::Left);

    if visible.is_empty() {
        let msg = "nothing to show — press [f] to include passing checks";
        f.render_widget(
            Paragraph::new(msg)
                .style(Style::default().fg(Color::DarkGray))
                .alignment(Alignment::Center)
                .block(block),
            area,
        );
        return;
    }

    let inner_width = area.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = visible
        .iter()
        .map(|&i| {
            row_item(
                &app.rows[i],
                app.spinner,
                inner_width,
                &app.series(app.rows[i].id),
            )
        })
        .collect();

    let list = List::new(items).block(block).highlight_style(
        Style::default()
            .bg(Color::Rgb(38, 42, 52))
            .add_modifier(Modifier::BOLD),
    );

    ui.list.select(Some(app.cursor.min(visible.len() - 1)));
    f.render_stateful_widget(list, area, &mut ui.list);
}

fn row_item(row: &Row, spinner: usize, width: usize, series: &[Severity]) -> ListItem<'static> {
    let stale = row.running && row.result.is_some();
    let severity = row.severity();

    let (tag, color) = match (row.running && row.result.is_none(), severity) {
        (true, _) | (_, None) => (
            SPINNER[spinner % SPINNER.len()].to_string(),
            Color::DarkGray,
        ),
        // An accepted risk keeps its real tag — hiding it would defeat the
        // point — but is drawn in blue so it reads as "known" rather than
        // "on fire".
        (_, Some(sev)) if row.is_accepted() => (sev.tag().to_string(), Color::Blue),
        (_, Some(sev)) => (sev.tag().to_string(), severity_color(sev)),
    };

    let label = truncate(&row.label, LABEL_W);
    let label_pad = LABEL_W.saturating_sub(label.chars().count());

    // 1 leading space + 4 tag + 2 gap + label + 1 gap, plus 1 column of margin
    // so a truncated message never touches the border.
    let fixed = LABEL_W + 9;
    // The trend only earns its space once the message still has room to be
    // readable; on a narrow terminal the message wins.
    let show_spark = !series.is_empty() && width >= fixed + 24 + SPARK_WIDTH + 2;
    let spark_room = if show_spark { SPARK_WIDTH + 2 } else { 0 };

    let message_budget = width.saturating_sub(fixed + spark_room).max(8);
    let message = truncate(row.message(), message_budget);
    let message_pad = message_budget.saturating_sub(message.chars().count());

    let dim = if stale {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default()
    };

    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            format!("{tag:<4}"),
            dim.fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(label, dim.fg(Color::White)),
        Span::raw(" ".repeat(label_pad + 1)),
        Span::styled(message, dim.fg(color)),
    ];

    if show_spark {
        spans.push(Span::raw(" ".repeat(message_pad + 2)));
        // Right-align the trend by padding out short histories.
        let lead = SPARK_WIDTH.saturating_sub(series.len());
        if lead > 0 {
            spans.push(Span::raw(" ".repeat(lead)));
        }
        for severity in series {
            spans.push(Span::styled(
                spark_glyph(*severity).to_string(),
                Style::default().fg(severity_color(*severity)),
            ));
        }
    }

    ListItem::new(Line::from(spans))
}

fn summary_line(s: Summary) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let counters = [
        (s.fail, "fail", Color::Red),
        (s.warn, "warn", Color::Yellow),
        (s.unknown, "unknown", Color::DarkGray),
        (s.pass, "pass", Color::Green),
    ];
    for (count, name, color) in counters {
        let style = if count == 0 {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(color).add_modifier(Modifier::BOLD)
        };
        spans.push(Span::styled(format!("{count} {name}"), style));
        spans.push(Span::raw("  "));
    }
    if s.accepted > 0 {
        spans.push(Span::styled(
            format!("{} accepted", s.accepted),
            Style::default().fg(Color::Blue),
        ));
        spans.push(Span::raw("  "));
    }
    if s.running > 0 {
        spans.push(Span::styled(
            format!("{} running", s.running),
            Style::default().fg(Color::Cyan),
        ));
        spans.push(Span::raw(" "));
    }
    Line::from(spans)
}

fn draw_detail(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Details ")
        .padding(Padding::horizontal(1));

    let Some(row) = app.selected() else {
        f.render_widget(block, area);
        return;
    };

    let severity = row.severity();
    let color = severity.map(severity_color).unwrap_or(Color::DarkGray);
    let tag = severity.map(Severity::tag).unwrap_or("....");

    let mut lines = vec![Line::from(vec![
        Span::styled(
            row.label.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(tag, Style::default().fg(color).add_modifier(Modifier::BOLD)),
    ])];

    lines.push(Line::styled(
        row.message().to_string(),
        Style::default().fg(color),
    ));

    let accepted = row.result.as_ref().and_then(|r| r.accepted.as_deref());
    let hint = row.result.as_ref().and_then(|r| r.hint.as_deref());

    match (accepted, hint) {
        (Some(reason), _) => lines.push(Line::styled(
            format!("✓ accepted: {reason}"),
            Style::default().fg(Color::Blue),
        )),
        (None, Some(hint)) => lines.push(Line::styled(
            format!("→ {hint}"),
            Style::default().fg(Color::Cyan),
        )),
        (None, None) if !row.about.is_empty() => lines.push(Line::styled(
            row.about.to_string(),
            Style::default().fg(Color::DarkGray),
        )),
        _ => {}
    }

    if let Some(fix) = row.result.as_ref().and_then(|r| r.fix.as_deref()) {
        lines.push(Line::from(vec![
            key("x"),
            Span::raw(" "),
            Span::styled(format!("$ {fix}"), Style::default().fg(Color::Yellow)),
        ]));
    }

    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let auto = if app.auto_refresh {
        format!("auto {}s", app.interval.as_secs())
    } else {
        "auto off".to_string()
    };

    let keys = Line::from(vec![
        Span::raw(" "),
        key("j/k"),
        Span::raw(" move  "),
        key("r"),
        Span::raw(" refresh  "),
        key("a"),
        Span::raw(format!(" {auto}  ")),
        key("s"),
        Span::raw(format!(" sort:{}  ", app.sort.label())),
        key("f"),
        Span::raw(format!(" {}  ", app.filter.label())),
        key("?"),
        Span::raw(" help  "),
        key("q"),
        Span::raw(" quit"),
    ]);
    f.render_widget(Paragraph::new(keys), area);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let entries: &[(&str, &str)] = &[
        ("j / ↓", "next check"),
        ("k / ↑", "previous check"),
        ("g / G", "first / last check"),
        ("r", "refresh now"),
        ("a", "toggle auto-refresh"),
        ("+ / -", "auto-refresh interval"),
        ("s", "sort by registry order or severity"),
        ("f", "show all checks or problems only"),
        ("x / Enter", "run the selected check's fix (asks first)"),
        ("? / h", "toggle this help"),
        ("q / Esc / Ctrl-C", "quit"),
    ];

    let mut lines: Vec<Line> = vec![Line::raw("")];
    for (keys, description) in entries {
        lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("{keys:<18}"),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(*description),
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "  Checks marked ???? could not be determined — that is not a pass.",
        Style::default().fg(Color::DarkGray),
    ));

    let popup = centered(60, lines.len() as u16 + 2, area);
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Keys "),
        ),
        popup,
    );
}

/// The confirm-then-run overlay for a remediation command.
///
/// The command is rendered in full, on its own line, in a colour that says
/// "this will change your system". There is no default action and no way to
/// reach the running state except by pressing `y` while looking at it.
fn draw_action(f: &mut Frame, area: Rect, app: &App) {
    let (title, border, lines) = match &app.action {
        ActionState::Idle => return,

        ActionState::Confirm { label, command, .. } => (
            " Run fix? ".to_string(),
            Color::Yellow,
            vec![
                Line::styled(
                    label.clone(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::styled(
                    format!("  $ {command}"),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::from(vec![
                    key("y"),
                    Span::raw(" run   "),
                    key("d"),
                    Span::raw(" dry run   "),
                    key("n"),
                    Span::raw(" cancel"),
                ]),
            ],
        ),

        ActionState::Running { command, .. } => (
            " Running… ".to_string(),
            Color::Cyan,
            vec![
                Line::styled(format!("  $ {command}"), Style::default().fg(Color::Cyan)),
                Line::raw(""),
                Line::styled(
                    "waiting for the command to finish",
                    Style::default().fg(Color::DarkGray),
                ),
            ],
        ),

        ActionState::Done {
            command,
            success,
            output,
            ..
        } => {
            let (title, color, verdict) = match success {
                Some(true) => (" Fix applied ", Color::Green, "succeeded — rechecking"),
                Some(false) => (" Fix failed ", Color::Red, "command exited non-zero"),
                None => (" Dry run ", Color::Cyan, "not executed"),
            };
            (
                title.to_string(),
                color,
                vec![
                    Line::styled(format!("  $ {command}"), Style::default().fg(color)),
                    Line::styled(verdict.to_string(), Style::default().fg(color)),
                    Line::raw(""),
                    Line::styled(output.clone(), Style::default().fg(Color::DarkGray)),
                    Line::raw(""),
                    Line::from(vec![key("any key"), Span::raw(" dismiss")]),
                ],
            )
        }
    };

    let popup = centered(72, (lines.len() as u16 + 4).min(area.height), area);
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: true }).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border))
                .padding(Padding::horizontal(1))
                .title(title),
        ),
        popup,
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn key(k: &str) -> Span<'static> {
    Span::styled(
        format!("[{k}]"),
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

pub fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Pass => Color::Green,
        Severity::Warn => Color::Yellow,
        Severity::Fail => Color::Red,
        Severity::Unknown => Color::DarkGray,
    }
}

/// Truncate to `max` display cells, marking the cut with `…`.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    if max <= 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width.saturating_sub(width)) / 2,
        area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    )
}
