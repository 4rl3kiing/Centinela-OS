//! Ring 3 network service, loopback interface only: UDP-style datagrams
//! between local tasks with RFC 1071 checksums verified on delivery.
//! A physical NIC needs DMA, which the IOMMU denies until per-device
//! mappings exist; until then this service is the network boundary.
#![no_std]
#![no_main]

use centinela_userland::{FLAG_KERNEL_ORIGIN, reply_and_wait, reply_wait, write};

const OP_BIND: u64 = 1;
const OP_SEND: u64 = 2;
const OP_RECV: u64 = 3;
const EINVAL: u64 = 3;
const EADDRINUSE: u64 = 5;
const ECONNREFUSED: u64 = 6;
const ENOBUFS: u64 = 7;
const EAGAIN: u64 = 8;
const EBADMSG: u64 = 9;

#[derive(Clone, Copy, Default)]
struct Datagram {
    port: u16,
    length: u8,
    data: u64,
    checksum: u16,
}

/// RFC 1071 Internet checksum over a pseudo header (port, length) + data.
fn checksum(port: u16, length: u8, data: u64) -> u16 {
    let mut sum = u32::from(port) + u32::from(length);
    for chunk in data.to_be_bytes().chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64) -> ! {
    let mut bound = [0u16; 8];
    let mut queue = [None::<Datagram>; 8];
    write("netsvc: loopback interface up (UDP datagrams, RFC 1071 checksums)");
    let mut message = reply_wait(endpoint);
    loop {
        let words = message.words;
        let reply = if message.status != 0 || message.flags & FLAG_KERNEL_ORIGIN != 0 {
            [EINVAL, 0, 0, 0]
        } else {
            match words[0] {
                OP_BIND => match u16::try_from(words[1]) {
                    Ok(0) | Err(_) => [EINVAL, 0, 0, 0],
                    Ok(port) if bound.contains(&port) => [EADDRINUSE, 0, 0, 0],
                    Ok(port) => match bound.iter().position(|&p| p == 0) {
                        Some(slot) => {
                            bound[slot] = port;
                            [0, 0, 0, 0]
                        }
                        None => [ENOBUFS, 0, 0, 0],
                    },
                },
                OP_SEND => {
                    let port = (words[1] & 0xffff) as u16;
                    let length = words[1] >> 16;
                    if length > 8 || port == 0 {
                        [EINVAL, 0, 0, 0]
                    } else if !bound.contains(&port) {
                        [ECONNREFUSED, 0, 0, 0]
                    } else {
                        let length = length as u8;
                        let data = words[2] & (u64::MAX >> (64 - 8 * u32::from(length.max(1))));
                        let data = if length == 0 { 0 } else { data };
                        match queue.iter().position(Option::is_none) {
                            Some(slot) => {
                                queue[slot] = Some(Datagram {
                                    port,
                                    length,
                                    data,
                                    checksum: checksum(port, length, data),
                                });
                                [0, 0, 0, 0]
                            }
                            None => [ENOBUFS, 0, 0, 0],
                        }
                    }
                }
                OP_RECV => {
                    let port = words[1] as u16;
                    let slot = queue
                        .iter()
                        .position(|d| d.is_some_and(|d| d.port == port && port != 0));
                    match slot.and_then(|slot| queue[slot].take()) {
                        Some(d) if checksum(d.port, d.length, d.data) == d.checksum => {
                            [0, u64::from(d.length), d.data, u64::from(d.checksum)]
                        }
                        Some(_) => [EBADMSG, 0, 0, 0],
                        None => [EAGAIN, 0, 0, 0],
                    }
                }
                _ => [EINVAL, 0, 0, 0],
            }
        };
        message = reply_and_wait(endpoint, reply);
    }
}
