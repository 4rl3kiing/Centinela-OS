//! Ring 3 i8042/PS/2 keyboard driver. It may touch only ports 0x60 and 0x64
//! (the kernel refuses 0x61, system control, which sits between them) and
//! receives IRQ 1 as a kernel-origin IPC notice. The self-test checks the
//! controller and drives a real keyboard interrupt with the ECHO command.
#![no_std]
#![no_main]

use centinela_userland::{exit, irq_ack, port_in, port_out, wait_irq, write};

const DATA: u16 = 0x60;
const STATUS: u16 = 0x64;
const IRQ: u64 = 1;

fn wait_input_clear() -> bool {
    (0..100_000).any(|_| port_in(STATUS) & 2 == 0)
}

fn read_polled() -> Option<u8> {
    (0..100_000)
        .find(|_| port_in(STATUS) & 1 != 0)
        .map(|_| port_in(DATA))
}

fn command(byte: u8) -> bool {
    wait_input_clear() && {
        port_out(STATUS, byte);
        true
    }
}

fn flush() {
    for _ in 0..32 {
        if port_in(STATUS) & 1 == 0 {
            break;
        }
        port_in(DATA);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64) -> ! {
    // Quiesce both PS/2 ports and drain stale bytes.
    if !command(0xad) || !command(0xa7) {
        exit(1);
    }
    flush();
    if !command(0x20) {
        exit(2);
    }
    let Some(config) = read_polled() else { exit(3) };
    // Controller self-test (0x55) and first-port test (0x00).
    if !command(0xaa) || read_polled() != Some(0x55) {
        exit(4);
    }
    if !command(0xab) || read_polled() != Some(0x00) {
        exit(5);
    }
    // Port 1 interrupt on, port 1 clock on (self-test may reset the config).
    let config = (config | 0x01) & !0x10;
    if !command(0x60) || !wait_input_clear() {
        exit(6);
    }
    port_out(DATA, config);
    if !command(0xae) {
        exit(7);
    }
    flush();
    irq_ack();

    // ECHO: the keyboard answers 0xEE, raising a real IRQ 1.
    let mut echoes = 0;
    for _ in 0..3 {
        if !wait_input_clear() {
            exit(8);
        }
        port_out(DATA, 0xee);
        let mut reply = None;
        for _ in 0..8 {
            wait_irq(endpoint, IRQ);
            if port_in(STATUS) & 1 != 0 {
                reply = Some(port_in(DATA));
            }
            irq_ack();
            if reply.is_some() {
                break;
            }
        }
        if reply == Some(0xee) {
            echoes += 1;
        }
    }
    if echoes == 3 {
        write(
            "kbd: controller self-test passed; 3/3 keyboard echoes received through IRQ 1 notices",
        );
        exit(0)
    }
    write("kbd: keyboard echo lost");
    exit(9)
}
