#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_ktime_get_boot_ns, bpf_printk, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext}
};
use pg_tenant_monitor_common::{QueryByteArray, QueryEvent, QUERY_TEXT_LEN};

#[repr(C)]
struct QueryInfo {
    query: QueryByteArray,
    start_time: u64,
}

#[map]
// Keep track of active queries by pid_tgid
static mut QUERIES: HashMap<u64, QueryInfo> = HashMap::with_max_entries(10000, 0);

#[map]
// Queue query events for processing in user space
pub static mut EVENTS: PerfEventArray<QueryEvent> = PerfEventArray::new(0);

#[uprobe]
pub fn exec_simple_query_enter(ctx: ProbeContext) {
    let pid_tgid = bpf_get_current_pid_tgid(); 
    let query = match extract_query(&ctx) {
        Some(query) => query,
        None => {
            return;
        }
    };
    let start_time = get_ktime_ms();
    let info = QueryInfo { query, start_time};
    insert_query(pid_tgid, info);
}

#[uretprobe]
pub fn exec_simple_query_return(ctx: RetProbeContext) {
    let pid_tgid = bpf_get_current_pid_tgid(); 
    let info = match lookup_info(pid_tgid) {
        Some(info) => info,
        None => {
            return;
        }
    };
    let end_time = get_ktime_ms();
    let duration_micro = end_time - info.start_time;
    let event = QueryEvent {
        query: info.query,
        duration_micro: duration_micro,
    };
    enqueue_event(ctx, event);
    remove_query(pid_tgid);
}

fn insert_query(pid_tgid: u64, info: QueryInfo) {
    unsafe {
        let _ = QUERIES.insert(&pid_tgid, &info, 0).map_err(|_| {
            bpf_printk!(b"Insert failed");
        });
    }
}

fn remove_query(pid_tgid: u64) {
    unsafe {
        let _ = QUERIES.remove(&pid_tgid).map_err(|_| {
            bpf_printk!(b"Remove failed");
        });
    }
}

fn lookup_info(pid_tgid: u64) -> Option<&'static QueryInfo> {
    unsafe {
        QUERIES.get(&pid_tgid).or_else(|| {
            bpf_printk!(b"Lookup failed");
            None
        })
    }
}

fn extract_query(ctx: &ProbeContext) -> Option<QueryByteArray> {
    let arg0: *const core::ffi::c_char = ctx.arg(0)?;
    let mut buf: QueryByteArray = [0u8; QUERY_TEXT_LEN];
    unsafe { 
        bpf_probe_read_user_str_bytes(arg0 as *const u8, &mut buf).ok()?;
    }
    Some(buf)
}

fn enqueue_event(ctx: RetProbeContext, event: QueryEvent) {
    unsafe { EVENTS.output(&ctx, &event, 0) }
}

fn get_ktime_ms() -> u64 {
    let ts = unsafe { bpf_ktime_get_boot_ns() };
    ts / 1000
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
