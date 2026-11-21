//! Ring 3 NVMe driver (phase 7, step 1).
//!
//! Controller registers come through BAR 0, mapped into this driver
//! uncached (user, RW, NX); PCI configuration stays kernel-only. Queues and
//! data buffers live in DMA pages mapped both here and in the controller's
//! own IOMMU domain, so the controller can reach those pages and nothing
//! else. Completions are polled (MSI-X delivery is a later step).
//!
//! Self-test: reset and enable the controller, identify it and namespace 1,
//! create one I/O queue pair, write a block and read it back, then submit a
//! read whose data pointer lies outside the domain; the kernel checks that
//! the IOMMU blocked and recorded it.
#![no_std]
#![no_main]

use centinela_userland::{Line, dma_alloc, exit, sleep, write};

const CAP: u64 = 0x00;
const CC: u64 = 0x14;
const CSTS: u64 = 0x1c;
const AQA: u64 = 0x24;
const ASQ: u64 = 0x28;
const ACQ: u64 = 0x30;
const PAGE: usize = 4096;
/// Entries per queue (one page of 64-byte submissions).
const QUEUE_DEPTH: u16 = 16;
/// Test block (LBA) used for the write/read-back check.
const TEST_LBA: u64 = 1;
/// IOVA no DMA page of ours uses: the IOMMU must refuse it.
const ROGUE_IOVA: u64 = 0x7fff_0000;

struct Controller {
    mmio: u64,
    stride: u64,
}

impl Controller {
    fn read32(&self, register: u64) -> u32 {
        // SAFETY: The kernel mapped the controller's register BAR at `mmio`.
        unsafe { core::ptr::read_volatile((self.mmio + register) as *const u32) }
    }
    fn read64(&self, register: u64) -> u64 {
        u64::from(self.read32(register)) | u64::from(self.read32(register + 4)) << 32
    }
    fn write32(&self, register: u64, value: u32) {
        // SAFETY: As in `read32`.
        unsafe { core::ptr::write_volatile((self.mmio + register) as *mut u32, value) }
    }
    fn write64(&self, register: u64, value: u64) {
        self.write32(register, value as u32);
        self.write32(register + 4, (value >> 32) as u32);
    }
    fn doorbell(&self, queue: u16, completion: bool, value: u16) {
        let index = 2 * u64::from(queue) + u64::from(completion);
        self.write32(0x1000 + index * (4 << self.stride), u32::from(value));
    }
}

/// One submission/completion queue pair living in two DMA pages.
struct Queue {
    id: u16,
    submissions: *mut u8,
    completions: *mut u8,
    tail: u16,
    head: u16,
    phase: bool,
    next_command: u16,
}

fn put(base: *mut u8, offset: usize, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        // SAFETY: Callers stay inside their own DMA pages.
        unsafe { core::ptr::write_volatile(base.add(offset + index), *byte) };
    }
}

fn get(base: *const u8, offset: usize) -> u8 {
    // SAFETY: As in `put`.
    unsafe { core::ptr::read_volatile(base.add(offset)) }
}

fn get32(base: *const u8, offset: usize) -> u32 {
    u32::from_le_bytes([
        get(base, offset),
        get(base, offset + 1),
        get(base, offset + 2),
        get(base, offset + 3),
    ])
}

fn get64(base: *const u8, offset: usize) -> u64 {
    u64::from(get32(base, offset)) | u64::from(get32(base, offset + 4)) << 32
}

/// Fields of a submission queue entry this driver uses.
struct Command {
    opcode: u8,
    namespace: u32,
    data: u64,
    dwords: [u32; 3],
}

impl Queue {
    /// Submits `command` and polls (bounded, sleeping between polls) for its
    /// completion. Returns the 15-bit status (0 = success) or `None` on
    /// timeout.
    fn run(&mut self, controller: &Controller, command: Command) -> Option<u16> {
        let id = self.next_command;
        self.next_command = self.next_command.wrapping_add(1);
        let mut entry = [0u8; 64];
        entry[0] = command.opcode;
        entry[2..4].copy_from_slice(&id.to_le_bytes());
        entry[4..8].copy_from_slice(&command.namespace.to_le_bytes());
        entry[24..32].copy_from_slice(&command.data.to_le_bytes());
        for (index, dword) in command.dwords.iter().enumerate() {
            entry[40 + 4 * index..44 + 4 * index].copy_from_slice(&dword.to_le_bytes());
        }
        put(self.submissions, usize::from(self.tail) * 64, &entry);
        self.tail = (self.tail + 1) % QUEUE_DEPTH;
        controller.doorbell(self.id, false, self.tail);
        for _ in 0..500 {
            for _ in 0..10_000 {
                let offset = usize::from(self.head) * 16;
                let status = u16::from_le_bytes([
                    get(self.completions, offset + 14),
                    get(self.completions, offset + 15),
                ]);
                if (status & 1 != 0) == self.phase {
                    let completed = u16::from_le_bytes([
                        get(self.completions, offset + 12),
                        get(self.completions, offset + 13),
                    ]);
                    self.head = (self.head + 1) % QUEUE_DEPTH;
                    if self.head == 0 {
                        self.phase = !self.phase;
                    }
                    controller.doorbell(self.id, true, self.head);
                    if completed != id {
                        return None;
                    }
                    return Some(status >> 1);
                }
                core::hint::spin_loop();
            }
            sleep(1);
        }
        None
    }
}

fn fail(message: &str, code: u64) -> ! {
    write(message);
    exit(code)
}

fn ascii(buffer: *const u8, start: usize, length: usize, line: &mut Line) {
    let mut bytes = [0u8; 40];
    let length = length.min(bytes.len());
    for (index, byte) in bytes[..length].iter_mut().enumerate() {
        let value = get(buffer, start + index);
        *byte = if (0x20..0x7f).contains(&value) {
            value
        } else {
            b'?'
        };
    }
    let trimmed = bytes[..length].trim_ascii_end();
    line.push(trimmed);
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_unused: u64, _unused2: u64, _unused3: u64, mmio: u64) -> ! {
    let mut controller = Controller { mmio, stride: 0 };
    let capabilities = controller.read64(CAP);
    controller.stride = (capabilities >> 32) & 0xf;
    // CAP.TO is in 500 ms units; poll in 10 ms sleeps.
    let ready_polls = ((capabilities >> 24) & 0xff).max(1) * 50;
    let max_entries = (capabilities & 0xffff) + 1;
    if max_entries < u64::from(QUEUE_DEPTH) || (capabilities >> 37) & 1 == 0 {
        fail(
            "nvme: controller lacks the NVM command set or queue depth",
            2,
        );
    }

    // Disable, then wait for not-ready.
    controller.write32(CC, 0);
    if !(0..ready_polls).any(|_| {
        let ready = controller.read32(CSTS) & 1 == 0;
        if !ready {
            sleep(1);
        }
        ready
    }) {
        fail("nvme: controller did not disable", 3);
    }

    // Pages: 0 admin SQ, 1 admin CQ, 2 I/O SQ, 3 I/O CQ, 4 identify,
    // 5 write buffer, 6 read buffer.
    let Some(dma) = dma_alloc(7) else {
        fail("nvme: no DMA pages", 4)
    };
    let page = |index: usize| {
        // SAFETY: `index` < 7, inside the DMA pages just mapped.
        unsafe { dma.address.add(index * PAGE) }
    };
    let iova = |index: usize| dma.iova + (index * PAGE) as u64;
    let depth = u32::from(QUEUE_DEPTH - 1);
    controller.write32(AQA, depth << 16 | depth);
    controller.write64(ASQ, iova(0));
    controller.write64(ACQ, iova(1));
    // Enable: NVM command set, 4 KiB pages, 64-byte SQE (2^6), 16-byte CQE (2^4).
    controller.write32(CC, 1 | 6 << 16 | 4 << 20);
    if !(0..ready_polls).any(|_| {
        let status = controller.read32(CSTS);
        if status & 2 != 0 {
            fail("nvme: controller fatal status", 5);
        }
        let ready = status & 1 != 0;
        if !ready {
            sleep(1);
        }
        ready
    }) {
        fail("nvme: controller did not become ready", 6);
    }

    let mut admin = Queue {
        id: 0,
        submissions: page(0),
        completions: page(1),
        tail: 0,
        head: 0,
        phase: true,
        next_command: 1,
    };
    let ok = |status: Option<u16>| status == Some(0);
    // Identify controller (CNS 1), then namespace 1 (CNS 0).
    let identify = |admin: &mut Queue, controller: &Controller, namespace: u32, cns: u32| {
        admin.run(
            controller,
            Command {
                opcode: 0x06,
                namespace,
                data: iova(4),
                dwords: [cns, 0, 0],
            },
        )
    };
    if !ok(identify(&mut admin, &controller, 0, 1)) {
        fail("nvme: identify controller failed", 7);
    }
    let mut line = Line::new();
    line.push(b"nvme: controller '");
    ascii(page(4), 24, 40, &mut line);
    line.push(b"'");
    if !ok(identify(&mut admin, &controller, 1, 0)) {
        fail("nvme: identify namespace 1 failed", 8);
    }
    let blocks = get64(page(4), 0);
    let format = usize::from(get(page(4), 26) & 0xf);
    let block_shift = u32::from(get(page(4), 128 + 4 * format + 2));
    if blocks <= TEST_LBA || !(9..=12).contains(&block_shift) {
        fail("nvme: namespace 1 unusable (size or block format)", 9);
    }
    let block_size = 1usize << block_shift;

    // I/O completion queue 1 (physically contiguous, polled), then I/O
    // submission queue 1 bound to it.
    if !ok(admin.run(
        &controller,
        Command {
            opcode: 0x05,
            namespace: 0,
            data: iova(3),
            dwords: [depth << 16 | 1, 1, 0],
        },
    )) || !ok(admin.run(
        &controller,
        Command {
            opcode: 0x01,
            namespace: 0,
            data: iova(2),
            dwords: [depth << 16 | 1, 1 << 16 | 1, 0],
        },
    )) {
        fail("nvme: could not create the I/O queue pair", 10);
    }
    let mut io = Queue {
        id: 1,
        submissions: page(2),
        completions: page(3),
        tail: 0,
        head: 0,
        phase: true,
        next_command: 1,
    };

    // Write a recognizable block, read it back into a different page.
    let marker = b"Centinela-OS NVMe block written by a Ring 3 driver";
    put(page(5), 0, marker);
    for offset in marker.len()..block_size {
        put(page(5), offset, &[(offset % 251) as u8]);
    }
    let lba = [TEST_LBA as u32, (TEST_LBA >> 32) as u32, 0];
    if !ok(io.run(
        &controller,
        Command {
            opcode: 0x01,
            namespace: 1,
            data: iova(5),
            dwords: lba,
        },
    )) {
        fail("nvme: write failed", 11);
    }
    if !ok(io.run(
        &controller,
        Command {
            opcode: 0x02,
            namespace: 1,
            data: iova(6),
            dwords: lba,
        },
    )) {
        fail("nvme: read failed", 12);
    }
    if (0..block_size).any(|offset| get(page(5), offset) != get(page(6), offset)) {
        fail("nvme: data read back differs from data written", 13);
    }
    line.push(b"; namespace 1: ")
        .number(blocks)
        .push(b" blocks of ")
        .number(block_size as u64)
        .push(b" B; block written and read back (IOMMU-confined DMA)");
    line.print();

    // A read into an IOVA outside our domain must be refused by the IOMMU.
    // Controllers differ in how they report the failed transfer (QEMU's
    // even reports success), so the proof is the IOMMU fault the kernel
    // counts, not this status.
    let rogue = io.run(
        &controller,
        Command {
            opcode: 0x02,
            namespace: 1,
            data: ROGUE_IOVA,
            dwords: lba,
        },
    );
    let mut report = Line::new();
    report.push(b"nvme: out-of-domain read submitted (controller status ");
    match rogue {
        Some(status) => report.number(u64::from(status)),
        None => report.push(b"timeout"),
    };
    report.push(b"); the IOMMU decides").print();
    exit(0)
}
