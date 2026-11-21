//! Host tool for Centinela CFS volumes stored in image files.
//!
//! cfs-tool mkfs IMAGE [LABEL [BLOCKS]]   (BLOCKS: volume size, default all)
//! cfs-tool fsck IMAGE
//! cfs-tool ls   IMAGE
//! cfs-tool put  IMAGE NAME FILE [OWNER]
//! cfs-tool get  IMAGE NAME [OWNER]        (content to stdout)

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::process::ExitCode;

use centinela_cfs::{BLOCK_SIZE, Block, BlockDevice, Error, Volume, bitmap_words, format};

struct Image {
    file: File,
    blocks: u64,
}

impl Image {
    fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let blocks = file.metadata()?.len() / BLOCK_SIZE as u64;
        Ok(Self { file, blocks })
    }
}

impl BlockDevice for Image {
    fn block_count(&self) -> u64 {
        self.blocks
    }
    fn read(&mut self, block: u64, buffer: &mut Block) -> Result<(), Error> {
        self.file
            .seek(SeekFrom::Start(block * BLOCK_SIZE as u64))
            .and_then(|_| self.file.read_exact(buffer))
            .map_err(|_| Error::Io)
    }
    fn write(&mut self, block: u64, buffer: &Block) -> Result<(), Error> {
        self.file
            .seek(SeekFrom::Start(block * BLOCK_SIZE as u64))
            .and_then(|_| self.file.write_all(buffer))
            .map_err(|_| Error::Io)
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.file.sync_data().map_err(|_| Error::Io)
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let usage = "usage: cfs-tool mkfs|fsck|ls|put|get IMAGE ...";
    let command = args.get(1).ok_or(usage)?;
    let path = args.get(2).ok_or(usage)?;
    let mut image = Image::open(path).map_err(|e| format!("{path}: {e}"))?;
    if command == "mkfs" {
        let label = args.get(3).map_or("centinela", String::as_str);
        if let Some(blocks) = args.get(4) {
            let blocks: u64 = blocks
                .parse()
                .map_err(|_| format!("bad block count {blocks}"))?;
            if blocks > image.blocks {
                return Err(format!(
                    "{blocks} blocks exceed the image ({})",
                    image.blocks
                ));
            }
            image.blocks = blocks;
        }
        format(&mut image, label.as_bytes()).map_err(|e| format!("mkfs: {e:?}"))?;
        println!("formatted {path}: {} blocks, label {label}", image.blocks);
        return Ok(());
    }
    // Volumes may be smaller than the image (NVMe disks reserve their last
    // 4 KiB for the driver self-test); the superblock records the size.
    let mut bitmap = vec![0u64; bitmap_words(image.blocks)];
    let mut volume = Volume::mount(image, &mut bitmap).map_err(|e| format!("mount: {e:?}"))?;
    let owner = |index: usize| -> Result<u64, String> {
        args.get(index)
            .map_or(Ok(0), |o| o.parse().map_err(|_| format!("bad owner {o}")))
    };
    match command.as_str() {
        "fsck" => {
            let files = volume.check().map_err(|e| format!("fsck: {e:?}"))?;
            let sb = volume.superblock();
            println!(
                "clean: generation {}, {files} files, {} of {} blocks free",
                sb.generation,
                volume.free_blocks(),
                sb.block_count
            );
        }
        "ls" => {
            for entry in volume.entries() {
                println!(
                    "{:>8} {:>10}  {}",
                    entry.owner,
                    entry.size,
                    String::from_utf8_lossy(entry.name())
                );
            }
        }
        "put" => {
            let name = args.get(3).ok_or(usage)?;
            let source = args.get(4).ok_or(usage)?;
            let data = std::fs::read(source).map_err(|e| format!("{source}: {e}"))?;
            volume
                .write_file(owner(5)?, name.as_bytes(), &data)
                .map_err(|e| format!("put: {e:?}"))?;
        }
        "get" => {
            let name = args.get(3).ok_or(usage)?;
            let owner = owner(4)?;
            let size = volume
                .lookup(owner, name.as_bytes())
                .ok_or("get: not found")?
                .size as usize;
            let mut data = vec![0u8; size];
            volume
                .read(owner, name.as_bytes(), 0, &mut data)
                .map_err(|e| format!("get: {e:?}"))?;
            std::io::stdout()
                .write_all(&data)
                .map_err(|e| e.to_string())?;
        }
        _ => return Err(usage.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
