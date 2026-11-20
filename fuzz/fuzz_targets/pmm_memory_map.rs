#![no_main]

use centinela_kernel::memory::pmm::{
    LimineMemoryMapEntry, LimineMemoryMapResponse, Pmm,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let count = (data.len() / 24).min(8);
    if count == 0 {
        return;
    }

    let mut entries = Vec::with_capacity(count);
    for chunk in data.chunks_exact(24).take(count) {
        let base = u64::from_le_bytes(chunk[0..8].try_into().expect("fixed-size chunk"));
        let length = u64::from_le_bytes(chunk[8..16].try_into().expect("fixed-size chunk"));
        let raw_type = u64::from_le_bytes(chunk[16..24].try_into().expect("fixed-size chunk"));
        entries.push(LimineMemoryMapEntry {
            base,
            length,
            entry_type: raw_type & 1,
        });
    }

    let pointers: Vec<*const LimineMemoryMapEntry> =
        entries.iter().map(|entry| entry as *const _).collect();
    let response = LimineMemoryMapResponse {
        revision: 0,
        entry_count: pointers.len() as u64,
        entries: pointers.as_ptr(),
    };

    let mut bitmap = [u64::MAX; 4];
    let mut allocated = [0_u64; 4];
    let Ok(mut pmm) = Pmm::new(&mut bitmap, &mut allocated) else {
        return;
    };

    // SAFETY: the response, pointer array and all entries remain alive and
    // correctly aligned for the duration of initialize_from_limine.
    if unsafe { pmm.initialize_from_limine(&response, 0x1000, 0x3000) }.is_ok() {
        for _ in 0..256 {
            let Some(frame) = pmm.allocate_frame() else {
                break;
            };
            let _ = pmm.free_frame(frame);
        }
    }
});
