#![no_std]
#![no_main]

use aya_bpf::{helpers::bpf_printk, macros::sock_ops, programs::SockOpsContext};

mod common;
use common::*;

const AF_INET: u32 = 2;

const BPF_NOEXIST: u64 = 1;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;

#[sock_ops(name = "sockops_rs")]
pub fn sockops_rs(ctx: SockOpsContext) -> u32 {
    match try_sockops_rs(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sockops_rs(ctx: SockOpsContext) -> Result<u32, u32> {
    match ctx.op() {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            //ipv4
            if ctx.family() == AF_INET {
                if bpf_sock_ops_ipv4(ctx).is_err() {
                    return Err(1);
                }
            }
        }
        _ => {}
    }

    Ok(0)
}

fn bpf_sock_ops_ipv4(ctx: SockOpsContext) -> Result<(), u32> {
    //本地sock
    if ctx.remote_ip4() == 16777343 && ctx.local_ip4() == 16777343 {
        let mut key = sk_extract4_key(&ctx);

        let sk_ops = unsafe { ctx.ops.as_mut().unwrap() };

        // unsafe {
        //     bpf_printk!(b"find local sock remote port is: %d", ctx.remote_port());
        // }

        unsafe {
            return match SOCKMAP.update(&mut key, sk_ops, BPF_NOEXIST) {
                Ok(()) => Ok(()),
                Err(code) => Err(code as u32),
            };
        }
    }
    Ok(())
}

fn sk_extract4_key(ctx: &SockOpsContext) -> IdxMapKey {
    let mut key = IdxMapKey::default();
    key.dip = ctx.remote_ip4();
    key.sip = ctx.local_ip4();
    key.sport = ctx.local_port();
    key.dport = ctx.remote_port();
    key
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
