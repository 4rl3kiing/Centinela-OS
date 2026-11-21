//! Polled NVMe controller access for Ring 3 drivers.
//!
//! Registers come through BAR 0 (mapped by the kernel, uncached, NX); queues
//! and data buffers live in DMA pages that are also mapped in the
//! controller's own IOMMU domain, so the controller reaches nothing else.

use crate::{DmaRegion, Line, dma_alloc, sleep};

const CAP: u64 = 0x00;
const CC: u64 = 0x14;
const CSTS: u64 = 0x1c;
const AQA: u64 = 0x24;
const ASQ: u64 = 0x28;
const ACQ: u64 = 0x30;
pub const PAGE: usize = 4096;
/// Entries per queue (one page of 64-byte submissions).
const QUEUE_DEPTH: u16 = 16;

pub struct Controller {
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
pub struct Queue {
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
pub struct Command {
    pub opcode: u8,
    pub namespace: u32,
    pub data: u64,
    pub dwords: [u32; 3],
}

impl Queue {
    /// Submits `command` and polls (bounded, sleeping between polls) for its
    /// completion. Returns the 15-bit status (0 = success) or `None` on
    /// timeout.
    pub fn run(&mut self, controller: &Controller, command: Command) -> Option<u16> {
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

/// DMA pages used by [`Nvme`]: 0 admin SQ, 1 admin CQ, 2 I/O SQ, 3 I/O CQ,
/// 4 identify / scratch, 5 and 6 data buffers.
pub const DMA_PAGES: u64 = 7;

/// A controller brought up with one polled I/O queue pair on namespace 1.
pub struct Nvme {
    pub controller: Controller,
    pub admin: Queue,
    pub io: Queue,
    pub dma: DmaRegion,
    /// Namespace 1 size in LBAs and the LBA size in bytes.
    pub blocks: u64,
    pub block_size: usize,
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
    line.push(bytes[..length].trim_ascii_end());
}

impl Nvme {
    fn page(&self, index: usize) -> *mut u8 {
        // SAFETY: Callers pass indices below DMA_PAGES (mapped by dma_alloc).
        unsafe { self.dma.address.add(index * PAGE) }
    }

    /// Copies `bytes` into DMA page `page` at `offset` (bounds-checked).
    pub fn write_page(&self, page: usize, offset: usize, bytes: &[u8]) -> bool {
        let fits = page < DMA_PAGES as usize
            && offset
                .checked_add(bytes.len())
                .is_some_and(|end| end <= PAGE);
        if fits {
            put(self.page(page), offset, bytes);
        }
        fits
    }

    /// Copies from DMA page `page` at `offset` into `out` (bounds-checked).
    pub fn read_page(&self, page: usize, offset: usize, out: &mut [u8]) -> bool {
        let fits = page < DMA_PAGES as usize
            && offset.checked_add(out.len()).is_some_and(|end| end <= PAGE);
        if fits {
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = get(self.page(page), offset + index);
            }
        }
        fits
    }

    pub fn iova(&self, index: usize) -> u64 {
        self.dma.iova + (index * PAGE) as u64
    }

    /// Resets and enables the controller, identifies it and namespace 1 and
    /// creates I/O queue pair 1. On failure returns a message and exit code.
    /// `line` receives the controller model.
    pub fn bring_up(mmio: u64, line: &mut Line) -> Result<Self, (&'static str, u64)> {
        let mut controller = Controller { mmio, stride: 0 };
        let capabilities = controller.read64(CAP);
        controller.stride = (capabilities >> 32) & 0xf;
        // CAP.TO is in 500 ms units; poll in 10 ms sleeps.
        let ready_polls = ((capabilities >> 24) & 0xff).max(1) * 50;
        let max_entries = (capabilities & 0xffff) + 1;
        if max_entries < u64::from(QUEUE_DEPTH) || (capabilities >> 37) & 1 == 0 {
            return Err((
                "nvme: controller lacks the NVM command set or queue depth",
                2,
            ));
        }
        controller.write32(CC, 0);
        if !(0..ready_polls).any(|_| {
            let ready = controller.read32(CSTS) & 1 == 0;
            if !ready {
                sleep(1);
            }
            ready
        }) {
            return Err(("nvme: controller did not disable", 3));
        }
        let dma = dma_alloc(DMA_PAGES).ok_or(("nvme: no DMA pages", 4))?;
        let depth = u32::from(QUEUE_DEPTH - 1);
        let iova = |index: usize| dma.iova + (index * PAGE) as u64;
        controller.write32(AQA, depth << 16 | depth);
        controller.write64(ASQ, iova(0));
        controller.write64(ACQ, iova(1));
        // Enable: NVM command set, 4 KiB pages, 64-byte SQE, 16-byte CQE.
        controller.write32(CC, 1 | 6 << 16 | 4 << 20);
        let mut fatal = false;
        let ready = (0..ready_polls).any(|_| {
            let status = controller.read32(CSTS);
            fatal |= status & 2 != 0;
            let ready = status & 1 != 0 || fatal;
            if !ready {
                sleep(1);
            }
            ready
        });
        if fatal {
            return Err(("nvme: controller fatal status", 5));
        }
        if !ready {
            return Err(("nvme: controller did not become ready", 6));
        }
        // SAFETY: Page indices below DMA_PAGES.
        let page = |index: usize| unsafe { dma.address.add(index * PAGE) };
        let mut admin = Queue {
            id: 0,
            submissions: page(0),
            completions: page(1),
            tail: 0,
            head: 0,
            phase: true,
            next_command: 1,
        };
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
        if identify(&mut admin, &controller, 0, 1) != Some(0) {
            return Err(("nvme: identify controller failed", 7));
        }
        line.push(b"nvme: controller '");
        ascii(page(4), 24, 40, line);
        line.push(b"'");
        if identify(&mut admin, &controller, 1, 0) != Some(0) {
            return Err(("nvme: identify namespace 1 failed", 8));
        }
        let blocks = get64(page(4), 0);
        let format = usize::from(get(page(4), 26) & 0xf);
        let block_shift = u32::from(get(page(4), 128 + 4 * format + 2));
        if blocks < 16 || !(9..=12).contains(&block_shift) {
            return Err(("nvme: namespace 1 unusable (size or block format)", 9));
        }
        let created = admin.run(
            &controller,
            Command {
                opcode: 0x05,
                namespace: 0,
                data: iova(3),
                dwords: [depth << 16 | 1, 1, 0],
            },
        ) == Some(0)
            && admin.run(
                &controller,
                Command {
                    opcode: 0x01,
                    namespace: 0,
                    data: iova(2),
                    dwords: [depth << 16 | 1, 1 << 16 | 1, 0],
                },
            ) == Some(0);
        if !created {
            return Err(("nvme: could not create the I/O queue pair", 10));
        }
        let io = Queue {
            id: 1,
            submissions: page(2),
            completions: page(3),
            tail: 0,
            head: 0,
            phase: true,
            next_command: 1,
        };
        Ok(Self {
            controller,
            admin,
            io,
            dma,
            blocks,
            block_size: 1 << block_shift,
        })
    }

    /// Reads or writes `count` LBAs at `lba` through DMA page `page` (at most
    /// one page per command). Returns true on success.
    pub fn transfer(&mut self, write: bool, lba: u64, count: u16, page: usize) -> bool {
        let command = Command {
            opcode: if write { 0x01 } else { 0x02 },
            namespace: 1,
            data: self.iova(page),
            dwords: [
                lba as u32,
                (lba >> 32) as u32,
                u32::from(count.saturating_sub(1)),
            ],
        };
        self.io.run(&self.controller, command) == Some(0)
    }

    /// Makes completed writes durable (NVMe FLUSH).
    pub fn flush(&mut self) -> bool {
        let command = Command {
            opcode: 0x00,
            namespace: 1,
            data: 0,
            dwords: [0, 0, 0],
        };
        self.io.run(&self.controller, command) == Some(0)
    }
}
