#![no_std]

// Limited by stack size in ebpf program
// TODO: although ebpf stack limits 512 bytes, should be able to
// directly buffer data in the per-cpu map to bypass this constrant
pub const QUERY_TEXT_LEN: usize = 128;
pub type QueryByteArray = [u8; QUERY_TEXT_LEN];

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QueryEvent {
    pub query: [u8; QUERY_TEXT_LEN],
    pub duration_micro: u64,
}
