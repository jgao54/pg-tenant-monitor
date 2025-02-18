use log::{debug, warn};
use std::error::Error;
use aya::programs::UProbe;

// The path to the target binary, which is the PostgreSQL server binary.
const TARGET: &str = "/usr/lib/postgresql/16/bin/postgres";

// Offset for 'exec_simple_query' is found using the following command:
// $ gdb /usr/lib/postgresql/16/bin/postgres
// (gdb)  info address exec_simple_query
// TODO: find offset reliably at runtime
const EXEC_SIMPLE_QUERY_OFFSET: u64 = 0x5408b0;

// eBPF programs that get attached to the target
// We use 'exec_smple_query' to proxy query cpu time, but
// technically this only measures the wall-clock time between
// the entry and exit of this function.
// TODO: make this more precise by subtracting time not doing
// actual CPU work.
const EBPF_PROGRAMS: [&str; 2] = ["exec_simple_query_enter", "exec_simple_query_return"];

pub fn init_ebpf() -> Result<aya::Ebpf, Box<dyn Error>> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // Include eBPF object file as raw bytes at compile-time and load it at runtime.
    let mut ebpf: aya::Ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/pg-tenant-monitor")))?;

    // Initialize eBPF logger
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    Ok(ebpf)
}

pub fn attach_uprobe(ebpf: &mut aya::Ebpf) -> Result<(), Box<dyn Error>> {
    for program in &EBPF_PROGRAMS {
        let program: &mut UProbe = ebpf.program_mut(program).unwrap().try_into()?;
        program.load()?;
        program.attach(None, EXEC_SIMPLE_QUERY_OFFSET, TARGET, None)?;
    }
    Ok(())
}
