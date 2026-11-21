//! Hostile filesystem client: every request is malformed. The ramfs service
//! must answer each with an error and keep serving everyone else.
#![no_std]
#![no_main]

use centinela_userland::{Line, call, exit, pack};

#[unsafe(no_mangle)]
pub extern "C" fn _start(fs: u64) -> ! {
    let opened = call(fs, [1, pack(b"fz"), 1, 0]).map_or(u64::MAX, |r| r.words[1]);
    let attacks: [[u64; 4]; 8] = [
        [99, 0, 0, 0],                  // unknown operation
        [1, 0, 1, 0],                   // empty name
        [2, 7, 0, 0],                   // write to a descriptor never opened
        [2, opened | (200 << 8), 0, 0], // write longer than a message
        [3, 255, 0, 0],                 // read a bogus descriptor
        [3, opened, u64::MAX, 0],       // read far past the end of the file
        [4, 1000, 0, 0],                // list beyond the table
        [3, u64::MAX, 0, 0],            // descriptor overflow
    ];
    let mut accepted = 0;
    for attack in attacks {
        match call(fs, attack) {
            Some(reply) if reply.words[0] == 0 => accepted += 1,
            Some(_) => {}
            None => exit(100),
        }
    }
    Line::new()
        .push(b"fs-fuzzer: ")
        .number(8 - accepted)
        .push(b"/8 malformed requests rejected by ramfs")
        .print();
    exit(accepted)
}
