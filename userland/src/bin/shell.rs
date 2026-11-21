//! Ring 3 command shell. Input comes from the serial console service, files
//! from the RAM filesystem service and datagrams from the network service:
//! the shell holds only SEND capabilities to those three endpoints and has
//! no hardware, filesystem or network authority of its own.
#![no_std]
#![no_main]

use centinela_userland::{Line, call, exit, pack, unpack, write};

const OP_READ: u64 = 1;
const FS_OPEN: u64 = 1;
const FS_WRITE: u64 = 2;
const FS_READ: u64 = 3;
const FS_LIST: u64 = 4;
const FS_NULL: u64 = 5;
const NET_BIND: u64 = 1;
const NET_SEND: u64 = 2;
const NET_RECV: u64 = 3;
const BENCH_ROUNDS: u64 = 1000;

struct Shell {
    console: u64,
    fs: u64,
    net: u64,
}

fn rdtsc() -> u64 {
    // SAFETY: RDTSC is unprivileged unless CR4.TSD is set; no memory access.
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn split(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&b| b == b' ') {
        Some(space) => (&line[..space], &line[space + 1..]),
        None => (line, &[]),
    }
}

impl Shell {
    fn read_line<'b>(&self, buffer: &'b mut [u8; 96]) -> &'b [u8] {
        let mut length = 0;
        loop {
            let Some(reply) = call(self.console, [OP_READ, 0, 0, 0]) else {
                write("shell: console service unavailable");
                exit(10)
            };
            let count = (reply.words[0] as usize).min(16);
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&reply.words[1].to_le_bytes());
            bytes[8..].copy_from_slice(&reply.words[2].to_le_bytes());
            for &byte in &bytes[..count] {
                if byte == b'\n' || byte == b'\r' {
                    if length > 0 {
                        return &buffer[..length];
                    }
                } else if length < buffer.len() {
                    buffer[length] = byte;
                    length += 1;
                }
            }
        }
    }

    fn fs(&self, words: [u64; 4]) -> [u64; 4] {
        call(self.fs, words).map_or([u64::MAX, 0, 0, 0], |reply| reply.words)
    }

    fn net(&self, words: [u64; 4]) -> [u64; 4] {
        call(self.net, words).map_or([u64::MAX, 0, 0, 0], |reply| reply.words)
    }

    fn write_file(&self, name: &[u8], text: &[u8]) {
        let opened = self.fs([FS_OPEN, pack(name), 1, 0]);
        if opened[0] != 0 || name.len() > 8 || name.is_empty() {
            Line::new()
                .push(b"write: cannot create ")
                .push(name)
                .print();
            return;
        }
        for chunk in text.chunks(16) {
            let low = pack(&chunk[..chunk.len().min(8)]);
            let high = if chunk.len() > 8 {
                pack(&chunk[8..])
            } else {
                0
            };
            let result = self.fs([FS_WRITE, opened[1] | ((chunk.len() as u64) << 8), low, high]);
            if result[0] != 0 {
                write("write: filesystem refused the data");
                return;
            }
        }
        Line::new()
            .push(b"write: ")
            .push(name)
            .push(b" (")
            .number(text.len() as u64)
            .push(b" bytes)")
            .print();
    }

    fn cat(&self, name: &[u8]) {
        let opened = self.fs([FS_OPEN, pack(name), 0, 0]);
        if opened[0] != 0 {
            Line::new()
                .push(b"cat: ")
                .push(name)
                .push(b": no such file")
                .print();
            return;
        }
        let mut line = Line::new();
        line.push(b"cat ").push(name).push(b": ");
        let mut offset = 0;
        loop {
            let reply = self.fs([FS_READ, opened[1], offset, 0]);
            let length = reply[1] as usize;
            if reply[0] != 0 || length == 0 {
                break;
            }
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&reply[2].to_le_bytes());
            bytes[8..].copy_from_slice(&reply[3].to_le_bytes());
            line.push(&bytes[..length.min(16)]);
            offset += length as u64;
        }
        line.print();
    }

    fn ls(&self) {
        let mut count = 0;
        for index in 0..8 {
            let reply = self.fs([FS_LIST, index, 0, 0]);
            if reply[0] == 0 {
                let mut name = [0u8; 8];
                let length = unpack(reply[1], &mut name);
                Line::new()
                    .push(b"ls: ")
                    .push(&name[..length])
                    .push(b" (")
                    .number(reply[2])
                    .push(b" bytes)")
                    .print();
                count += 1;
            }
        }
        Line::new()
            .push(b"ls: ")
            .number(count)
            .push(b" file(s)")
            .print();
    }

    fn net_test(&self) {
        let bind = self.net([NET_BIND, 7, 0, 0]);
        let sent = self.net([NET_SEND, 7 | (4 << 16), pack(b"ping"), 0]);
        let received = self.net([NET_RECV, 7, 0, 0]);
        let refused = self.net([NET_SEND, 9 | (4 << 16), pack(b"lost"), 0]);
        let ok = bind[0] == 0
            && sent[0] == 0
            && received[0] == 0
            && received[1] == 4
            && received[2] == pack(b"ping")
            && refused[0] != 0;
        if ok {
            Line::new()
                .push(b"net: udp loopback echo 'ping' ok (checksum ")
                .number(received[3])
                .push(b"); unbound port refused")
                .print();
        } else {
            write("net: loopback test FAILED");
        }
    }

    fn bench(&self) {
        let start = rdtsc();
        let mut failures = 0;
        for _ in 0..BENCH_ROUNDS {
            if self.fs([FS_NULL, 0, 0, 0])[0] != 0 {
                failures += 1;
            }
        }
        let cycles = rdtsc().wrapping_sub(start) / BENCH_ROUNDS;
        Line::new()
            .push(b"bench: ")
            .number(BENCH_ROUNDS)
            .push(b" IPC round trips to ramfs, avg ")
            .number(cycles)
            .push(b" TSC cycles each; ")
            .number(failures)
            .push(b" failures")
            .print();
    }

    fn run(&self) -> ! {
        write("shell: ready (commands: help echo write cat ls net bench exit)");
        let mut buffer = [0u8; 96];
        loop {
            let line = self.read_line(&mut buffer);
            Line::new().push(b"centinela> ").push(line).print();
            let (command, rest) = split(line);
            match command {
                b"help" => {
                    write("shell: help echo write cat ls net bench exit");
                }
                b"echo" => Line::new().push(b"echo: ").push(rest).print(),
                b"write" => {
                    let (name, text) = split(rest);
                    self.write_file(name, text);
                }
                b"cat" => self.cat(rest),
                b"ls" => self.ls(),
                b"net" => self.net_test(),
                b"bench" => self.bench(),
                b"exit" => {
                    write("shell: bye");
                    exit(0)
                }
                _ => Line::new()
                    .push(b"shell: unknown command: ")
                    .push(command)
                    .print(),
            }
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(console: u64, fs: u64, net: u64) -> ! {
    Shell { console, fs, net }.run()
}
