mod ebpf;
mod terminal;
mod event;

use std::error::Error;
use ebpf::{attach_uprobe, init_ebpf};
use event::{receive_perf_events_async, update_stats_async, ProcessedQueryEvent};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::stdout;
use terminal::{draw_monitor, exit_monitor};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tokio::signal;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut ebpf = init_ebpf()?;
    attach_uprobe(&mut ebpf)?;

    let (tx, rx) = mpsc::channel::<ProcessedQueryEvent>(1000);
    let stats: Arc<DashMap<String, (i32, u64)>> = Arc::new(DashMap::new());
    receive_perf_events_async(&mut ebpf, tx).await?;
    update_stats_async(stats.clone(), rx).await?;

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    terminal.clear()?;
    let mut interval = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = interval.tick() => {
                draw_monitor(&mut terminal, &stats)?;
            }
            _ = signal::ctrl_c() => {
                exit_monitor(&mut terminal)?;
                break;
            }
        }
    }
    Ok(())
}
