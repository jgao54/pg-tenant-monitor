use std::error::Error;
use aya::{maps::MapData, Ebpf};
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use tokio::task;
use tokio::sync::mpsc::{Sender, Receiver};
use regex::Regex;
use pg_tenant_monitor_common::{QueryEvent, QUERY_TEXT_LEN};
use dashmap::DashMap;
use std::sync::Arc;

pub struct ProcessedQueryEvent {
    pub tenant_id: String,
    pub duration_micro: u64,
}

pub async fn receive_perf_events_async(ebpf: &mut Ebpf, tx: Sender<ProcessedQueryEvent>) -> Result<(), Box<dyn Error>> {
    let mut perf_array = get_ebpf_perf_array(ebpf)?;

    // BPF_MAP_TYPE_PERF_EVENT_ARRAY is allocated per cpu, so we need to read from all of them
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        start_event_listener_task(&mut perf_array, cpu_id, tx.clone())?;
    }
    Ok(())
}

pub async fn update_stats_async(stats: Arc<DashMap<String, (i32, u64)>>, mut rx: Receiver<ProcessedQueryEvent>) -> Result<(), Box<dyn Error>> {
    task::spawn(async move {
        loop {
            while let Some(event) = rx.recv().await {
                stats.entry(event.tenant_id)
                    .and_modify(|stats| {
                        stats.0 += 1;
                        stats.1 += event.duration_micro;
                    })
                    .or_insert((1, event.duration_micro));
            }
        }
    });

    Ok(())
}

fn start_event_listener_task(perf_array: &mut AsyncPerfEventArray<MapData>, cpu_id: u32, tx: Sender<ProcessedQueryEvent>) -> Result<(), Box<dyn Error>> {
    let mut input_buffer = perf_array.open(cpu_id, None)?;
    let mut output_buffers = vec![BytesMut::with_capacity(QUERY_TEXT_LEN); 100];

    // Use a separate background thread to continuously poll from per-cpu BPF_MAP_TYPE_PERF_EVENT_ARRAY
    task::spawn(async move {
        loop {
            if let Ok(events) = input_buffer.read_events(&mut output_buffers).await {
                for elem in output_buffers.iter_mut().take(events.read) {
                    let data = unsafe { *(elem.as_mut_ptr() as *const QueryEvent) };
                    if let Some(event) = process_event(data) {
                        if let Err(_) = tx.send(event).await {
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

fn get_ebpf_perf_array(ebpf: &mut Ebpf) -> Result<AsyncPerfEventArray<MapData>, Box<dyn Error>> {
    let events_map = ebpf.take_map("EVENTS")
        .ok_or("Failed to get EVENTS map")?;
    AsyncPerfEventArray::try_from(events_map)
        .map_err(Into::into)
}

fn process_event(event: QueryEvent) -> Option<ProcessedQueryEvent> {
    let query = String::from_utf8_lossy(&event.query);
    let tenant_id = extract_tenant_id(&query)?;
    let duration_micro = event.duration_micro;

    Some(ProcessedQueryEvent {
        tenant_id,
        duration_micro,
    })
}

fn extract_tenant_id(query: &str) -> Option<String> {
    let re = Regex::new(r"tenant_id\s*=\s*(\d+)").unwrap();
    re.captures(query)
        .map(|caps| caps[1].to_string())
}
