//! Ring 3 Intel 82540EM (e1000) network driver.
//!
//! Registers are reached through BAR 0, which the kernel mapped into this
//! driver uncached (user, RW, NX); PCI configuration stays kernel-only.
//! Descriptor rings and packet buffers live in DMA
//! pages that the kernel mapped into this driver *and* into the NIC's own
//! IOMMU domain, so the NIC can reach those pages and nothing else.
//!
//! Self-test against QEMU's user-mode network: send an ARP request for the
//! gateway 10.0.2.2, receive the reply by DMA, then point one transmit
//! descriptor outside the domain to prove the IOMMU blocks it.
#![no_std]
#![no_main]

use centinela_userland::{Line, dma_alloc, exit, sleep, write};

const CTRL: u32 = 0x0000;
const STATUS: u32 = 0x0008;
const RCTL: u32 = 0x0100;
const TCTL: u32 = 0x0400;
const TIPG: u32 = 0x0410;
const RDBAL: u32 = 0x2800;
const RDBAH: u32 = 0x2804;
const RDLEN: u32 = 0x2808;
const RDH: u32 = 0x2810;
const RDT: u32 = 0x2818;
const TDBAL: u32 = 0x3800;
const TDBAH: u32 = 0x3804;
const TDLEN: u32 = 0x3808;
const TDH: u32 = 0x3810;
const TDT: u32 = 0x3818;
const IMC: u32 = 0x00d8;
const RAL0: u32 = 0x5400;
const RAH0: u32 = 0x5404;
const DESCRIPTORS: u32 = 8;
const PAGE: usize = 4096;

struct Nic {
    mmio: u64,
}

impl Nic {
    fn read(&self, register: u32) -> u32 {
        // SAFETY: The kernel mapped the NIC's register BAR at `mmio`.
        unsafe { core::ptr::read_volatile((self.mmio + u64::from(register)) as *const u32) }
    }
    fn write(&self, register: u32, value: u32) {
        // SAFETY: As in `read`.
        unsafe { core::ptr::write_volatile((self.mmio + u64::from(register)) as *mut u32, value) }
    }
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

fn put_u64(base: *mut u8, offset: usize, value: u64) {
    put(base, offset, &value.to_le_bytes());
}

/// Polls `done`, sleeping one 10 ms tick between polls (no CPU used while
/// the NIC or the network catches up), for at most `ticks` ticks.
fn wait_for(ticks: u32, mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..ticks {
        if done() {
            return true;
        }
        sleep(1);
    }
    done()
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(_unused: u64, _unused2: u64, _unused3: u64, mmio: u64) -> ! {
    let nic = Nic { mmio };
    // Reset, mask every interrupt (the driver polls), link up.
    nic.write(IMC, 0xffff_ffff);
    nic.write(CTRL, nic.read(CTRL) | 1 << 26);
    if !wait_for(100, || nic.read(CTRL) & (1 << 26) == 0) {
        exit(1)
    }
    nic.write(IMC, 0xffff_ffff);
    nic.write(CTRL, nic.read(CTRL) | 1 << 6);

    let low = nic.read(RAL0);
    let high = nic.read(RAH0);
    let mac = [
        low as u8,
        (low >> 8) as u8,
        (low >> 16) as u8,
        (low >> 24) as u8,
        high as u8,
        (high >> 8) as u8,
    ];

    // Page 0: RX ring; page 1: TX ring; pages 2-5: RX buffers; page 6: TX buffer.
    let Some(dma) = dma_alloc(7) else { exit(2) };
    let rx_ring = dma.address;
    // SAFETY: Offsets within the 7 DMA pages just mapped.
    let (tx_ring, rx_buffers, tx_buffer) = unsafe {
        (
            dma.address.add(PAGE),
            dma.address.add(2 * PAGE),
            dma.address.add(6 * PAGE),
        )
    };
    let iova = |page: usize| dma.iova + (page * PAGE) as u64;
    for index in 0..DESCRIPTORS as usize {
        put_u64(rx_ring, index * 16, iova(2) + (index * 2048) as u64);
    }
    nic.write(RDBAL, iova(0) as u32);
    nic.write(RDBAH, (iova(0) >> 32) as u32);
    nic.write(RDLEN, DESCRIPTORS * 16);
    nic.write(RDH, 0);
    nic.write(RDT, DESCRIPTORS - 1);
    // Enable, accept broadcast, strip CRC, 2 KiB buffers.
    nic.write(RCTL, 1 << 1 | 1 << 15 | 1 << 26);
    nic.write(TDBAL, iova(1) as u32);
    nic.write(TDBAH, (iova(1) >> 32) as u32);
    nic.write(TDLEN, DESCRIPTORS * 16);
    nic.write(TDH, 0);
    nic.write(TDT, 0);
    nic.write(TCTL, 1 << 1 | 1 << 3 | 0x10 << 4 | 0x40 << 12);
    nic.write(TIPG, 10 | 8 << 10 | 6 << 20);

    // ARP request: who has 10.0.2.2? tell 10.0.2.15.
    let mut frame = [0u8; 60];
    frame[..6].copy_from_slice(&[0xff; 6]);
    frame[6..12].copy_from_slice(&mac);
    frame[12..14].copy_from_slice(&[0x08, 0x06]);
    frame[14..22].copy_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 1]);
    frame[22..28].copy_from_slice(&mac);
    frame[28..32].copy_from_slice(&[10, 0, 2, 15]);
    frame[38..42].copy_from_slice(&[10, 0, 2, 2]);
    put(tx_buffer, 0, &frame);
    let send = |slot: usize, address: u64| {
        put_u64(tx_ring, slot * 16, address);
        put(tx_ring, slot * 16 + 8, &60u16.to_le_bytes());
        // CMD: end of packet, insert FCS, report status.
        put(tx_ring, slot * 16 + 11, &[1 | 2 | 8]);
        put(tx_ring, slot * 16 + 12, &[0]);
        nic.write(TDT, slot as u32 + 1);
    };
    // Link autonegotiation takes a while after reset; RX is refused until up.
    if !wait_for(300, || nic.read(STATUS) & 2 != 0) {
        write("e1000: link never came up");
        exit(5)
    }
    send(0, iova(6));
    if !wait_for(300, || get(tx_ring, 12) & 1 != 0) {
        write("e1000: transmit never completed");
        exit(3)
    }

    // Wait for the ARP reply from the gateway (any slot).
    let mut gateway = None;
    let found = wait_for(300, || {
        for index in 0..DESCRIPTORS as usize {
            if get(rx_ring, index * 16 + 12) & 1 == 0 {
                continue;
            }
            // SAFETY: Buffer `index` is inside the RX buffer pages.
            let packet = unsafe { rx_buffers.add(index * 2048) };
            let is_reply = get(packet, 12) == 0x08
                && get(packet, 13) == 0x06
                && get(packet, 21) == 2
                && (28..32).all(|i| get(packet, i) == [10, 0, 2, 2][i - 28]);
            if is_reply {
                let mut mac = [0u8; 6];
                for (i, byte) in mac.iter_mut().enumerate() {
                    *byte = get(packet, 22 + i);
                }
                gateway = Some(mac);
                return true;
            }
            put(rx_ring, index * 16 + 12, &[0]);
        }
        false
    });
    let Some(gateway) = gateway.filter(|_| found) else {
        write("e1000: no ARP reply from the gateway");
        exit(4)
    };
    let mut line = Line::new();
    line.push(b"e1000: link ")
        .push(if nic.read(STATUS) & 2 != 0 {
            b"up"
        } else {
            b"down"
        })
        .push(b"; ARP reply from 10.0.2.2 at ");
    for (i, byte) in gateway.iter().enumerate() {
        let hex = b"0123456789abcdef";
        line.push(&[hex[usize::from(byte >> 4)], hex[usize::from(byte & 15)]]);
        if i < 5 {
            line.push(b":");
        }
    }
    line.push(b" (TX and RX by IOMMU-confined DMA)").print();

    // Hostile descriptor: point the NIC outside its domain. The IOMMU must
    // block the read; the kernel reports the fault when it tears down.
    send(1, 0x7fff_0000);
    wait_for(100, || nic.read(TDH) == 2);
    write("e1000: sent a descriptor outside the DMA domain");
    exit(0)
}
