//! Hostile CFS images: mounting, checking and updating arbitrary bytes must
//! never panic, loop forever or touch blocks outside the device.
#![no_main]

use centinela_cfs::{BLOCK_SIZE, Block, BlockDevice, Error, Volume, bitmap_words};
use libfuzzer_sys::fuzz_target;

struct Image {
    blocks: Vec<Block>,
}

impl BlockDevice for Image {
    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error> {
        *buffer = *self.blocks.get(block as usize).ok_or(Error::Io)?;
        Ok(())
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error> {
        *self.blocks.get_mut(block as usize).ok_or(Error::Io)? = *buffer;
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let count = (data.len() / BLOCK_SIZE).clamp(8, 16);
    let mut blocks = vec![[0u8; BLOCK_SIZE]; count];
    for (index, chunk) in data.chunks(BLOCK_SIZE).take(count).enumerate() {
        blocks[index][..chunk.len()].copy_from_slice(chunk);
    }
    let mut image = Image { blocks };
    let mut bitmap = vec![0u64; bitmap_words(count as u64)];
    if let Ok(mut volume) = Volume::mount(&mut image, &mut bitmap) {
        let _ = volume.check();
        let _ = volume.write_file(7, b"fuzz", data.get(..100).unwrap_or(data));
        let _ = volume.delete(7, b"fuzz");
    }
});
