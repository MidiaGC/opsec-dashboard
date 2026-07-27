use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::App;
use crate::checks::{CheckResult, Status};

const HEADER_H: u16 = 3;
const CELL_H: u16 = 3;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();

    if area.height < HEADER_H + CELL_H {
        draw_too_small(f, area);
        return;
    }

    let rows = app.checks.len() as u16;
    let chunks = Layout::vertical([
        Constraint::Length(HEADER_H),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(f, chunks[0], app);

    let body_area = chunks[1];
    let overflow = body_area.height / CELL_H < rows;
    // Reserve one row at the bottom of body for the overflow hint when needed.
    let cells_area = if overflow {
        Rect::new(body_area.x, body_area.y, body_area.width, body_area.height.saturating_sub(1))
    } else {
        body_area
    };

    let mut drawn: u16 = 0;
    for (i, result) in app.checks.iter().enumerate() {
        let y = cells_area.y + (i as u16) * CELL_H;
        if y + CELL_H > cells_area.bottom() {
            break;
        }
        let cell = Rect::new(cells_area.x, y, cells_area.width, CELL_H);
        draw_check(f, cell, result);
        drawn += 1;
    }

    draw_footer(f, chunks[2]);

    if drawn < rows {
        let msg = format!(" (+{} checks hidden — resize to view)", rows - drawn);
        let pos = cells_area.y + drawn * CELL_H;
        let info = Rect::new(body_area.x, pos, body_area.width, 1);
        f.render_widget(
            Paragraph::new(msg).style(Style::default().fg(Color::DarkGray)),
            info,
        );
    }
}

fn draw_too_small(f: &mut Frame, area: Rect) {
    let msg = if area.height < 2 {
        "too small".to_string()
    } else {
        format!("Terminal too small (need >{} rows)", HEADER_H + CELL_H)
    };
    let p = Paragraph::new(msg)
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Center);
    f.render_widget(p, area);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let title = Span::styled(
        " OPSEC Health Dashboard ",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    );

    let stamp = Span::raw(format!("  refreshed {}  ", format_ts(app.last_refresh)));

    let line = Line::from(vec![title, stamp]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));
    let para = Paragraph::new(line).alignment(Alignment::Center).block(block);
    f.render_widget(para, area);
}

fn draw_check(f: &mut Frame, area: Rect, result: &CheckResult) {
    let (text, color) = match &result.status {
        Status::Pass(m) => (format!("PASS  {m}"), Color::Green),
        Status::Warn(m) => (format!("WARN  {m}"), Color::Yellow),
        Status::Fail(m) => (format!("FAIL  {m}"), Color::Red),
        Status::Unknown(m) => (format!("???   {m}"), Color::DarkGray),
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(color))
        .title(Span::styled(
            format!(" {} ", result.label),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ));
    let paragraph = Paragraph::new(text).style(Style::default().fg(color)).block(block);
    f.render_widget(paragraph, area);
}

fn draw_footer(f: &mut Frame, area: Rect) {
    let hint = Paragraph::new(Line::from(vec![
        Span::raw("[r] refresh  "),
        Span::raw("[q] quit"),
    ]));
    f.render_widget(hint, area);
}

pub fn format_ts(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let day = secs / 86400;
    let rem = secs % 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;

    let z = day as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m_ = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_ = if m_ <= 2 { y + 1 } else { y };
    format!("{y_:04}-{m_:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}
