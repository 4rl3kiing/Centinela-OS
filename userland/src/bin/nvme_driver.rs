//! Ring 3 NVMe driver self-test (phase 7, step 1).
//!
//! Brings the controller up (see `centinela_userland::nvme`), writes the
//! namespace's last LBA (kept outside the CFS volume) and reads it back, then
//! submits a read whose data pointer lies outside the domain; the kernel
//! checks that the IOMMU blocked and recorded it.
#![no_std]
#![no_main]

use centinela_userland::nvme::Nvme;
use centinela_userland::{Line, exit, write};

/// IOVA no DMA page of ours uses: the IOMMU must refuse it.
const ROGUE_IOVA: u64 = 0x7fff_0000;

fn fail(message: &str, code: u64) -> ! {
    write(message);
    exit(code)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_unused: u64, _unused2: u64, _unused3: u64, mmio: u64) -> ! {
    let mut line = Line::new();
    let mut nvme = match Nvme::bring_up(mmio, &mut line) {
        Ok(nvme) => nvme,
        Err((message, code)) => fail(message, code),
    };
    let block_size = nvme.block_size;
    // The last LBA is reserved for this self-test (the storage service's
    // volume ends before it).
    let test_lba = nvme.blocks - 1;
    let marker = b"Centinela-OS NVMe block written by a Ring 3 driver";
    let mut pattern = [0u8; 4096];
    for (offset, byte) in pattern.iter_mut().enumerate() {
        *byte = (offset % 251) as u8;
    }
    pattern[..marker.len()].copy_from_slice(marker);
    nvme.write_page(5, 0, &pattern[..block_size]);
    if !nvme.transfer(true, test_lba, 1, 5) {
        fail("nvme: write failed", 11);
    }
    if !nvme.transfer(false, test_lba, 1, 6) {
        fail("nvme: read failed", 12);
    }
    let mut back = [0u8; 4096];
    nvme.read_page(6, 0, &mut back[..block_size]);
    if back[..block_size] != pattern[..block_size] {
        fail("nvme: data read back differs from data written", 13);
    }
    line.push(b"; namespace 1: ")
        .number(nvme.blocks)
        .push(b" blocks of ")
        .number(block_size as u64)
        .push(b" B; block written and read back (IOMMU-confined DMA)");
    line.print();

    // A read into an IOVA outside our domain must be refused by the IOMMU.
    // Controllers differ in how they report the failed transfer (QEMU's even
    // reports success), so the proof is the IOMMU fault the kernel counts.
    let command = centinela_userland::nvme::Command {
        opcode: 0x02,
        namespace: 1,
        data: ROGUE_IOVA,
        dwords: [test_lba as u32, (test_lba >> 32) as u32, 0],
    };
    let rogue = nvme.io.run(&nvme.controller, command);
    let mut report = Line::new();
    report.push(b"nvme: out-of-domain read submitted (controller status ");
    match rogue {
        Some(status) => report.number(u64::from(status)),
        None => report.push(b"timeout"),
    };
    report.push(b"); the IOMMU decides").print();
    exit(0)
}
