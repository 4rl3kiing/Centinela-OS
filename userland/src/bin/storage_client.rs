//! Client of the persistent storage service. Role (start argument): 1 saves
//! a note and reads it back; 2 sends malformed requests and checks that every
//! one is refused while the service keeps running.
#![no_std]
#![no_main]

use centinela_userland::{Line, call, exit, pack, write};

const EBUSY: u64 = 16;

fn request(storage: u64, words: [u64; 4]) -> [u64; 4] {
    call(storage, words).map_or([u64::MAX, 0, 0, 0], |reply| reply.words)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(storage: u64, _unused: u64, _unused2: u64, role: u64) -> ! {
    if role == 2 {
        let attacks: [[u64; 4]; 6] = [
            [99, 0, 0, 0],                          // unknown operation
            [2, 4, 0, 0],                           // data without BEGIN
            [3, 0, 0, 0],                           // commit without BEGIN
            [4, pack(b"boot-cou"), pack(b"nt"), 0], // another owner's file
            [1, pack(b"bad/name"), 0, 0],           // invalid name (refused at commit)
            [5, pack(b"missing"), 0, 0],            // delete what does not exist
        ];
        let mut refused = 0;
        for (index, attack) in attacks.iter().enumerate() {
            let status = request(storage, *attack)[0];
            if index == 4 {
                // BEGIN accepts the name; the atomic commit must refuse it.
                if request(storage, [3, 0, 0, 0])[0] != 0 {
                    refused += 1;
                }
            } else if status != 0 {
                refused += 1;
            }
        }
        Line::new()
            .push(b"storage-fuzzer: ")
            .number(refused)
            .push(b"/6 malformed requests refused")
            .print();
        exit(if refused == 6 { 0 } else { 1 })
    }

    let note = b"Centinela-OS guarda esta nota en NVMe con CFS.";
    // Another client may be staging a file (one staging at a time): retry
    // while the service answers EBUSY. Each call blocks, so others progress.
    let mut begin = request(storage, [1, pack(b"nota.txt"), 0, 0])[0];
    for _ in 0..10_000 {
        if begin != EBUSY {
            break;
        }
        begin = request(storage, [1, pack(b"nota.txt"), 0, 0])[0];
    }
    if begin != 0 {
        exit(2)
    }
    for chunk in note.chunks(16) {
        let low = pack(&chunk[..chunk.len().min(8)]);
        let high = if chunk.len() > 8 {
            pack(&chunk[8..])
        } else {
            0
        };
        if request(storage, [2, chunk.len() as u64, low, high])[0] != 0 {
            exit(3)
        }
    }
    let committed = request(storage, [3, 0, 0, 0]);
    if committed[0] != 0 {
        exit(4)
    }
    let mut back = [0u8; 64];
    let mut offset = 0usize;
    loop {
        let reply = request(storage, [4, pack(b"nota.txt"), 0, offset as u64]);
        let count = reply[1] as usize;
        if reply[0] != 0 || count == 0 || offset + count > back.len() {
            break;
        }
        let mut chunk = [0u8; 16];
        chunk[..8].copy_from_slice(&reply[2].to_le_bytes());
        chunk[8..].copy_from_slice(&reply[3].to_le_bytes());
        back[offset..offset + count.min(16)].copy_from_slice(&chunk[..count.min(16)]);
        offset += count;
    }
    if &back[..offset] != note {
        write("storage-client: read-back mismatch");
        exit(5)
    }
    Line::new()
        .push(b"storage-client: saved and read back nota.txt (")
        .number(note.len() as u64)
        .push(b" bytes) at volume generation ")
        .number(committed[2])
        .print();
    exit(0)
}
