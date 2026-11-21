//! Ring 3 RAM filesystem service. Every request is untrusted: file
//! descriptors, offsets and lengths are bounds-checked and answered with an
//! error code, so a hostile client can neither crash the service nor reach
//! memory outside the file it names.
#![no_std]
#![no_main]

use centinela_userland::{FLAG_KERNEL_ORIGIN, map_memory, reply_and_wait, reply_wait, write};

const MAX_FILES: usize = 8;
const FILE_SIZE: usize = 4096;
const OP_OPEN: u64 = 1;
const OP_WRITE: u64 = 2;
const OP_READ: u64 = 3;
const OP_LIST: u64 = 4;
const OP_NULL: u64 = 5;
const EBADF: u64 = 1;
const ENOSPC: u64 = 2;
const EINVAL: u64 = 3;
const ENOENT: u64 = 4;

struct Fs {
    storage: *mut u8,
    names: [u64; MAX_FILES],
    sizes: [usize; MAX_FILES],
}

impl Fs {
    fn file(&mut self, fd: u64) -> Option<usize> {
        let fd = usize::try_from(fd).ok()?;
        (fd < MAX_FILES && self.names[fd] != 0).then_some(fd)
    }

    fn data(&mut self, fd: usize) -> &mut [u8] {
        // SAFETY: `storage` maps MAX_FILES zeroed RW pages owned by this task
        // and `fd < MAX_FILES` was checked by `file`.
        unsafe { core::slice::from_raw_parts_mut(self.storage.add(fd * FILE_SIZE), FILE_SIZE) }
    }

    fn handle(&mut self, words: [u64; 4]) -> [u64; 4] {
        match words[0] {
            OP_OPEN => {
                let (name, create) = (words[1], words[2] == 1);
                if name == 0 {
                    return [EINVAL, 0, 0, 0];
                }
                if let Some(fd) = self.names.iter().position(|&n| n == name) {
                    return [0, fd as u64, self.sizes[fd] as u64, 0];
                }
                if !create {
                    return [ENOENT, 0, 0, 0];
                }
                match self.names.iter().position(|&n| n == 0) {
                    Some(fd) => {
                        self.names[fd] = name;
                        self.sizes[fd] = 0;
                        [0, fd as u64, 0, 0]
                    }
                    None => [ENOSPC, 0, 0, 0],
                }
            }
            OP_WRITE => {
                let Some(fd) = self.file(words[1] & 0xff) else {
                    return [EBADF, 0, 0, 0];
                };
                let length = (words[1] >> 8) as usize;
                if length > 16 {
                    return [EINVAL, 0, 0, 0];
                }
                let size = self.sizes[fd];
                if size + length > FILE_SIZE {
                    return [ENOSPC, 0, 0, 0];
                }
                let mut bytes = [0u8; 16];
                bytes[..8].copy_from_slice(&words[2].to_le_bytes());
                bytes[8..].copy_from_slice(&words[3].to_le_bytes());
                self.data(fd)[size..size + length].copy_from_slice(&bytes[..length]);
                self.sizes[fd] = size + length;
                [0, self.sizes[fd] as u64, 0, 0]
            }
            OP_READ => {
                let Some(fd) = self.file(words[1]) else {
                    return [EBADF, 0, 0, 0];
                };
                let size = self.sizes[fd];
                let Ok(offset) = usize::try_from(words[2]) else {
                    return [EINVAL, 0, 0, 0];
                };
                if offset > size {
                    return [EINVAL, 0, 0, 0];
                }
                let length = (size - offset).min(16);
                let mut bytes = [0u8; 16];
                bytes[..length].copy_from_slice(&self.data(fd)[offset..offset + length]);
                let low = u64::from_le_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
                let high = u64::from_le_bytes(bytes[8..].try_into().unwrap_or([0; 8]));
                [0, length as u64, low, high]
            }
            OP_LIST => match self.file(words[1]) {
                Some(fd) => [0, self.names[fd], self.sizes[fd] as u64, 0],
                None => [ENOENT, 0, 0, 0],
            },
            OP_NULL => [0, 0, 0, 0],
            _ => [EINVAL, 0, 0, 0],
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start(endpoint: u64) -> ! {
    let Ok(storage) = map_memory(MAX_FILES as u64) else {
        write("ramfs: no storage");
        centinela_userland::exit(1)
    };
    let mut fs = Fs {
        storage,
        names: [0; MAX_FILES],
        sizes: [0; MAX_FILES],
    };
    write("ramfs: serving 8 files x 4 KiB over IPC");
    let mut message = reply_wait(endpoint);
    loop {
        let reply = if message.status == 0 && message.flags & FLAG_KERNEL_ORIGIN == 0 {
            fs.handle(message.words)
        } else {
            [EINVAL, 0, 0, 0]
        };
        message = reply_and_wait(endpoint, reply);
    }
}
