//! Filesystem client that obtains a badged capability from the broker.
//! Role (4th start argument): 1 and 2 = isolated tenants that write the same
//! file name with different secrets; 2 then relinquishes its badge and must
//! be terminated on its next use; 3 tries to re-mint its badge (forgery).
#![no_std]
#![no_main]

use centinela_userland::{
    FLAG_MINT_BADGE, Line, RIGHT_SEND, SYS_IPC_CALL, call, exit, ipc, pack, write,
};

fn fs(cap: u64, words: [u64; 4]) -> [u64; 4] {
    call(cap, words).map_or([u64::MAX, 0, 0, 0], |reply| reply.words)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(broker: u64, _unused: u64, _unused2: u64, role: u64) -> ! {
    let Some(reply) = call(broker, [1, 0, 0, 0]) else {
        exit(10)
    };
    // The granted handle arrives in the last word; the badge in word 2.
    let (cap, badge) = (reply.words[3], reply.words[2]);
    if cap == 0 {
        exit(11)
    }
    if role == 3 {
        // Forgery: pass our badged capability on, minting it as badge 0x101
        // (another tenant). The kernel must refuse and terminate us.
        ipc(
            SYS_IPC_CALL,
            broker,
            3 | (RIGHT_SEND << 8) | FLAG_MINT_BADGE,
            [9, 0, 0x101, cap],
        );
        write("badge forgery was not stopped");
        exit(12)
    }
    let secret: &[u8] = if role == 1 { b"tenant-A" } else { b"tenant-B" };
    let opened = fs(cap, [1, pack(b"doc"), 1, 0]);
    if opened[0] != 0 {
        exit(13)
    }
    fs(cap, [2, opened[1] | (8 << 8), pack(secret), 0]);
    let read = fs(cap, [3, opened[1], 0, 0]);
    let mut visible = 0;
    for index in 0..8 {
        if fs(cap, [4, index, 0, 0])[0] == 0 {
            visible += 1;
        }
    }
    let isolated = read[0] == 0 && read[2] == pack(secret) && visible == 1;
    Line::new()
        .push(b"tenant badge ")
        .number(badge)
        .push(if isolated {
            b": reads back its own secret; sees 1 of the filesystem's files"
        } else {
            b": ISOLATION FAILURE"
        })
        .print();
    if !isolated {
        exit(14)
    }
    if role == 2 {
        call(broker, [2, badge, 0, 0]);
        // The revoked handle is now stale: this call must terminate us.
        fs(cap, [5, 0, 0, 0]);
        write("revoked capability still worked");
        exit(15)
    }
    exit(0)
}
