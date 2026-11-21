//! Ring 3 capability broker. It holds the only unbadged (minter) capability
//! to the filesystem and hands each client a SEND copy minted with a fresh
//! badge, which the filesystem uses as the client's identity. It can later
//! revoke a client's access system-wide by badge.
//!
//! Requests: 1 = get a filesystem capability; 2 = relinquish (revoke) the
//! badge in word 1. The demo broker trusts relinquish requests; a production
//! broker would check the requester's own badge on the broker endpoint.
#![no_std]
#![no_main]

use centinela_userland::{
    FLAG_KERNEL_ORIGIN, Line, reply_and_wait, reply_minting, reply_wait, revoke,
};

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64, fs_minter: u64) -> ! {
    let mut next_badge = 0x100;
    let mut message = reply_wait(endpoint);
    loop {
        let words = message.words;
        message = if message.status != 0 || message.flags & FLAG_KERNEL_ORIGIN != 0 {
            reply_and_wait(endpoint, [3, 0, 0, 0])
        } else {
            match words[0] {
                1 => {
                    next_badge += 1;
                    reply_minting(endpoint, fs_minter, next_badge)
                }
                2 => {
                    let revoked = revoke(fs_minter, words[1]);
                    Line::new()
                        .push(b"broker: revoked badge ")
                        .number(words[1])
                        .push(b" (")
                        .number(revoked)
                        .push(b" capability)")
                        .print();
                    reply_and_wait(endpoint, [0, revoked, 0, 0])
                }
                _ => reply_and_wait(endpoint, [3, 0, 0, 0]),
            }
        };
    }
}
