//! Ring 3 16550 UART driver (COM2). It owns no hardware privilege: every
//! port access is a kernel-mediated syscall checked against its grant, and
//! its interrupt arrives as a kernel-origin IPC notice. The self-test runs
//! the UART in loopback mode, so each byte sent raises a real IRQ 3.
#![no_std]
#![no_main]

use centinela_userland::{exit, irq_ack, port_in, port_out, wait_irq, write};

const BASE: u16 = 0x2f8;
const DATA: u16 = BASE;
const IER: u16 = BASE + 1;
const FCR: u16 = BASE + 2;
const LCR: u16 = BASE + 3;
const MCR: u16 = BASE + 4;
const LSR: u16 = BASE + 5;
const IRQ: u64 = 3;
const PROBE: &[u8] = b"CENTINELA";

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64) -> ! {
    port_out(IER, 0);
    port_out(LCR, 0x80);
    port_out(DATA, 1);
    port_out(IER, 0);
    port_out(LCR, 0x03);
    port_out(FCR, 0x07);
    // Loopback + OUT2: transmitted bytes come straight back and interrupt.
    port_out(MCR, 0x18);
    for _ in 0..32 {
        if port_in(LSR) & 1 == 0 {
            break;
        }
        port_in(DATA);
    }
    port_out(IER, 0x01);
    irq_ack();

    let mut received = 0usize;
    for &byte in PROBE {
        port_out(DATA, byte);
        // A notice may be stale (no data yet): re-arm and keep waiting.
        let mut got = None;
        for _ in 0..8 {
            wait_irq(endpoint, IRQ);
            let ready = port_in(LSR) & 1 != 0;
            if ready {
                got = Some(port_in(DATA));
            }
            irq_ack();
            if got.is_some() {
                break;
            }
        }
        if got == Some(byte) {
            received += 1;
        }
    }
    port_out(IER, 0);
    port_out(MCR, 0);
    if received == PROBE.len() {
        write("uart: 9/9 loopback bytes received through IRQ 3 notices");
        exit(0)
    }
    write("uart: loopback bytes lost");
    exit(1)
}
