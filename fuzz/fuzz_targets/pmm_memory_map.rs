#![no_main]

use centinela_kernel::memory::pmm::{LimineMemoryMapEntry, LimineMemoryMapResponse, Pmm};
use libfuzzer_sys::fuzz_target;

const ENTRY_BYTES: usize = 24;
const HEADER_BYTES: usize = 16;

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("fixed-size slice"))
}

fuzz_target!(|data: &[u8]| {
    // Header: fuzzer-chosen kernel physical range, so reservation edge cases
    // (unaligned, overlapping, beyond the ceiling, inverted) are exercised.
    if data.len() < HEADER_BYTES + ENTRY_BYTES {
        return;
    }
    let kernel_start = read_u64(&data[0..8]) % (1 << 20);
    let kernel_end = read_u64(&data[8..16]) % (1 << 20);
    let body = &data[HEADER_BYTES..];

    let count = (body.len() / ENTRY_BYTES).min(16);
    let mut entries = Vec::with_capacity(count);
    for chunk in body.chunks_exact(ENTRY_BYTES).take(count) {
        entries.push(LimineMemoryMapEntry {
            base: read_u64(&chunk[0..8]),
            length: read_u64(&chunk[8..16]),
            // Cover every Limine region type (0..=8) plus one unknown value.
            entry_type: read_u64(&chunk[16..24]) % 10,
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
    let initialized = unsafe { pmm.initialize_from_limine(&response, kernel_start, kernel_end) };
    if initialized.is_err() {
        // Failed initialization must leave the allocator fully reserved.
        assert_eq!(pmm.free_frames(), 0);
        return;
    }

    let before = pmm.free_frames();
    let mut frames = Vec::new();
    while let Some(frame) = pmm.allocate_frame() {
        assert_eq!(frame % 4096, 0, "frames must be page aligned");
        assert_ne!(frame, 0, "frame zero must never be handed out");
        assert!(
            frame + 4096 <= kernel_start || frame >= kernel_end.div_ceil(4096) * 4096,
            "kernel frames must stay reserved"
        );
        frames.push(frame);
        if frames.len() > 256 {
            break;
        }
    }
    for frame in frames {
        assert_eq!(pmm.free_frame(frame), Ok(()));
        assert!(
            pmm.free_frame(frame).is_err(),
            "double free must be rejected"
        );
    }
    assert_eq!(pmm.free_frames(), before, "accounting must be restored");
});
