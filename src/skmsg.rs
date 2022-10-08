#![no_std]
#![no_main]

use aya_bpf::{helpers::bpf_printk, macros::sk_msg, programs::SkMsgContext};

mod common;
use common::*;

const BPF_F_INGRESS: u64 = 1;
const AF_INET: u32 = 2;

#[sk_msg(name = "skmsg_rs")]
pub fn skmsg_rs(ctx: SkMsgContext) -> u32 {
    if unsafe { (*ctx.msg).family } == AF_INET {
        match try_skmsg_rs(ctx) {
            Ok(ret) => ret,
            Err(ret) => ret,
        };
    };
    0
}

fn try_skmsg_rs(ctx: SkMsgContext) -> Result<u32, u32> {
    let (rip4, lip4) = unsafe {
        let rip4 = (*ctx.msg).remote_ip4;
        let lip4 = (*ctx.msg).local_ip4;
        (rip4, lip4)
    };

    if rip4 == 16777343 && lip4 == 16777343 {
        let mut key = unsafe { sk_msg_extract4_key(&ctx) };
        let ret = unsafe { SOCKMAP.redirect_msg(&ctx, &mut key, BPF_F_INGRESS) };
        // unsafe {
        //     bpf_printk!(b"%d send to %d result is %d", lip4, rip4, ret);
        // }
        return Ok(ret as u32);
    }
    Ok(0)
}

unsafe fn sk_msg_extract4_key(ctx: &SkMsgContext) -> IdxMapKey {
    let mut key = IdxMapKey::default();
    key.sip = (*ctx.msg).remote_ip4;
    key.dip = (*ctx.msg).local_ip4;
    key.dport = (*ctx.msg).local_port;
    key.sport = (*ctx.msg).remote_port;
    key
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
