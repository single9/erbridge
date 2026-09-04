use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::event::{self, Event as CEvent, KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};

use crate::stats::Registry;

const TICK: Duration = Duration::from_millis(250);

/// Restores the terminal on drop, so it's cleaned up even if this future is
/// cancelled mid-poll (e.g. the backing forward/serve/connect task exits
/// first, racing this one via `tokio::select!`).
struct RestoreGuard;

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub async fn run(registry: Registry) -> Result<()> {
    let mut terminal = ratatui::try_init().context(
        "failed to initialize the terminal UI (not running in a real terminal?); \
         pass --headless to run without it",
    )?;
    let _guard = RestoreGuard;

    let mut last_sample = (
        registry.totals().bytes_in,
        registry.totals().bytes_out,
        Instant::now(),
    );

    loop {
        while event::poll(Duration::from_secs(0))? {
            if let CEvent::Key(key) = event::read()? {
                let quit = matches!(key.code, KeyCode::Char('q') | KeyCode::Esc)
                    || (key.code == KeyCode::Char('c')
                        && key.modifiers.contains(KeyModifiers::CONTROL));
                if quit {
                    return Ok(());
                }
            }
        }

        let totals = registry.totals();
        let elapsed = last_sample.2.elapsed().as_secs_f64().max(0.001);
        let rate_in = (totals.bytes_in.saturating_sub(last_sample.0)) as f64 / elapsed;
        let rate_out = (totals.bytes_out.saturating_sub(last_sample.1)) as f64 / elapsed;
        last_sample = (totals.bytes_in, totals.bytes_out, Instant::now());

        let live = registry.live_connections();
        let log = registry.recent_log();

        terminal.draw(|frame| render(frame, &totals, rate_in, rate_out, &live, &log))?;
        tokio::time::sleep(TICK).await;
    }
}

fn render(
    frame: &mut Frame,
    totals: &crate::stats::Totals,
    rate_in: f64,
    rate_out: f64,
    live: &[crate::stats::ConnectionInfo],
    log: &[String],
) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(8),
            Constraint::Length(1),
        ])
        .split(area);

    render_summary(frame, chunks[0], totals, rate_in, rate_out);
    render_connections(frame, chunks[1], live);
    render_log(frame, chunks[2], log);
    render_footer(frame, chunks[3]);
}

fn render_summary(
    frame: &mut Frame,
    area: Rect,
    totals: &crate::stats::Totals,
    rate_in: f64,
    rate_out: f64,
) {
    let text = format!(
        " live: {}   total conns: {}   in: {} ({}/s)   out: {} ({}/s)",
        totals.live_connections,
        totals.total_connections,
        human_bytes(totals.bytes_in),
        human_bytes(rate_in as u64),
        human_bytes(totals.bytes_out),
        human_bytes(rate_out as u64),
    );
    let block = Block::default().title(" erbridge ").borders(Borders::ALL);
    frame.render_widget(Paragraph::new(text).block(block), area);
}

fn render_connections(frame: &mut Frame, area: Rect, live: &[crate::stats::ConnectionInfo]) {
    let header = Row::new(vec![
        "label",
        "proto",
        "source",
        "destination",
        "in",
        "out",
        "dur",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));
    let rows = live.iter().map(|c| {
        Row::new(vec![
            Cell::from(c.label.clone()),
            Cell::from(c.protocol.to_string()),
            Cell::from(c.source.clone()),
            Cell::from(c.destination.clone()),
            Cell::from(human_bytes(
                c.bytes_in.load(std::sync::atomic::Ordering::Relaxed),
            )),
            Cell::from(human_bytes(
                c.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
            )),
            Cell::from(format!("{:.0}s", c.duration().as_secs_f64())),
        ])
    });
    let widths = [
        Constraint::Percentage(20),
        Constraint::Length(6),
        Constraint::Percentage(22),
        Constraint::Percentage(22),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .title(" connections ")
                .borders(Borders::ALL),
        )
        .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_log(frame: &mut Frame, area: Rect, log: &[String]) {
    let visible_rows = area.height.saturating_sub(2) as usize;
    let start = log.len().saturating_sub(visible_rows);
    let lines: Vec<Line> = log[start..]
        .iter()
        .map(|l| Line::from(l.as_str()))
        .collect();
    let block = Block::default().title(" events ").borders(Borders::ALL);
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_footer(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(" q / esc / ctrl+c: quit").style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}
