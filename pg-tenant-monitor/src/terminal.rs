use ratatui::crossterm::cursor::MoveTo;
use ratatui::crossterm::ExecutableCommand;
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::{Terminal, backend::CrosstermBackend};
use ratatui::layout::Constraint;
use ratatui::style::{Style, Color};
use std::error::Error;
use dashmap::DashMap;
use std::sync::Arc;
use std::io::Stdout;

pub fn draw_monitor(terminal: &mut Terminal<CrosstermBackend<Stdout>>, query_stats:  &Arc<DashMap<String, (i32, u64)>>) -> Result<(), Box<dyn Error>> {
    terminal.draw(|f| {
        let header = Row::new(vec! [
            "tenant_id",
            "query_count",
            "total_cpu_time_us",
        ]).style(Style::default()
            .fg(Color::White)
            .bg(Color::Rgb(0, 51, 102))
        );

        let widths = [
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(20),
        ];

        let rows: Vec<Row> = query_stats.iter()
            .map(|e| {Row::new(vec![e.key().to_string(), e.value().0.to_string(), e.value().1.to_string()])})
            .collect();

        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default()
                .title("TENANT RESOURCE MONITOR")
                .borders(Borders::ALL));

        f.render_widget(table, f.area());
    })?;
    Ok(())
}

pub fn exit_monitor(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<(), Box<dyn Error>> {
    terminal.clear()?;
    terminal.backend_mut().execute(MoveTo(0, 0))?;
    Ok(())
}
