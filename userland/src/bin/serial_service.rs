//! Ring 3 serial console service (COM3, IRQ 4) for the shell.
//!
//! Clients ask for input with `OP_READ`; when no byte is buffered the reply
//! is deferred (the caller stays blocked in the kernel, costing no CPU) until
//! the UART interrupts. Hardware access is kernel-mediated: this task holds
//! only the COM3 port window and IRQ 4.
#![no_std]
#![no_main]

use centinela_userland::{
    FLAG_KERNEL_ORIGIN, irq_ack, pack, port_in, port_out, reply_and_wait, reply_wait, wait_deferred,
};

const BASE: u16 = 0x3e8;
const IER: u16 = BASE + 1;
const MCR: u16 = BASE + 4;
const LSR: u16 = BASE + 5;
const IRQ: u64 = 4;
const OP_READ: u64 = 1;
const EINVAL: u64 = 3;

struct Ring {
    bytes: [u8; 256],
    head: usize,
    tail: usize,
}

impl Ring {
    fn push(&mut self, byte: u8) {
        let next = (self.tail + 1) % self.bytes.len();
        if next != self.head {
            self.bytes[self.tail] = byte;
            self.tail = next;
        }
    }
    fn pop(&mut self) -> Option<u8> {
        (self.head != self.tail).then(|| {
            let byte = self.bytes[self.head];
            self.head = (self.head + 1) % self.bytes.len();
            byte
        })
    }
    fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}

fn drain(ring: &mut Ring) {
    for _ in 0..64 {
        if port_in(LSR) & 1 == 0 {
            break;
        }
        ring.push(port_in(BASE));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64) -> ! {
    let mut ring = Ring {
        bytes: [0; 256],
        head: 0,
        tail: 0,
    };
    // Keep the line settings and FIFO mode as found: reprogramming the FIFO
    // would discard input that is already waiting.
    port_out(IER, 0);
    port_out(MCR, 0x08);
    drain(&mut ring);
    port_out(IER, 0x01);
    irq_ack();

    let mut pending = false;
    let mut reply: Option<[u64; 4]> = None;
    loop {
        let message = match reply.take() {
            Some(words) => reply_and_wait(endpoint, words),
            None if pending => wait_deferred(endpoint),
            None => reply_wait(endpoint),
        };
        if message.is_irq_notice(IRQ) {
            drain(&mut ring);
            irq_ack();
        } else if message.status == 0 && message.flags & FLAG_KERNEL_ORIGIN == 0 {
            if message.words[0] == OP_READ {
                pending = true;
            } else {
                reply = Some([EINVAL, 0, 0, 0]);
            }
        }
        drain(&mut ring);
        if pending && !ring.is_empty() {
            let mut chunk = [0u8; 16];
            let mut count = 0;
            while count < chunk.len() {
                let Some(byte) = ring.pop() else { break };
                chunk[count] = byte;
                count += 1;
                if byte == b'\n' {
                    break;
                }
            }
            reply = Some([count as u64, pack(&chunk[..8]), pack(&chunk[8..]), 0]);
            pending = false;
        }
    }
}
