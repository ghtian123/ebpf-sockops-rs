use aya_bpf::{macros::map, maps::SockHash};

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IdxMapKey {
    pub sip: u32,
    pub dip: u32,
    pub sport: u32,
    pub dport: u32,
}

#[map(name = "sockmap_rs")]
pub static mut SOCKMAP: SockHash<IdxMapKey> = SockHash::with_max_entries(10240, 0);
