//! Text console on the bootloader framebuffer.
//!
//! The kernel log goes to every available sink: COM1 and, when the
//! bootloader set up a linear framebuffer, the screen. Physical machines
//! without a serial port show the log here.
//!
//! The console draws 8x8 glyphs doubled vertically into 8x16 cells. It
//! only accepts 32-bit RGB framebuffers inside the higher half; anything
//! else leaves the console disabled (fail closed: no write is made to a
//! buffer whose geometry was not validated).
//!
//! All drawing happens under the serial console lock, which serializes
//! every writer on every CPU.

use crate::font;

/// Cell size in pixels.
pub const CELL_WIDTH: u32 = 8;
pub const CELL_HEIGHT: u32 = 16;
/// Largest framebuffer accepted (bytes), a sanity bound on firmware data.
pub const MAX_BYTES: u64 = 256 * 1024 * 1024;

const FOREGROUND: (u8, u8, u8) = (0xd0, 0xd0, 0xd0);
const BACKGROUND: (u8, u8, u8) = (0x00, 0x00, 0x00);

/// Framebuffer description as reported by the bootloader.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramebufferInfo {
    /// Virtual address of the first pixel.
    pub address: u64,
    pub width: u64,
    pub height: u64,
    /// Bytes per scanline.
    pub pitch: u64,
    pub bits_per_pixel: u16,
    /// 1 = RGB in the Limine protocol.
    pub memory_model: u8,
    pub red: ColorField,
    pub green: ColorField,
    pub blue: ColorField,
}

/// Position and width of one color channel in a pixel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColorField {
    pub size: u8,
    pub shift: u8,
}

/// Why a framebuffer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferError {
    NotRgb,
    UnsupportedDepth,
    EmptyGeometry,
    PitchTooSmall,
    TooLarge,
    BadAddress,
    BadColorField,
}

/// Validated geometry and pixel encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    /// Bytes per scanline.
    pub pitch: u32,
    pub columns: u32,
    pub rows: u32,
    pub foreground: u32,
    pub background: u32,
}

impl FramebufferInfo {
    /// Checks the bootloader's description before any pixel is written.
    pub fn validate(&self) -> Result<Geometry, FramebufferError> {
        if self.memory_model != 1 {
            return Err(FramebufferError::NotRgb);
        }
        if self.bits_per_pixel != 32 {
            return Err(FramebufferError::UnsupportedDepth);
        }
        if self.width < u64::from(CELL_WIDTH) || self.height < u64::from(CELL_HEIGHT) {
            return Err(FramebufferError::EmptyGeometry);
        }
        let row_bytes = self
            .width
            .checked_mul(4)
            .ok_or(FramebufferError::TooLarge)?;
        if self.pitch < row_bytes || !self.pitch.is_multiple_of(4) {
            return Err(FramebufferError::PitchTooSmall);
        }
        let bytes = self
            .pitch
            .checked_mul(self.height)
            .ok_or(FramebufferError::TooLarge)?;
        if bytes > MAX_BYTES || self.width > u64::from(u32::MAX) {
            return Err(FramebufferError::TooLarge);
        }
        // Higher half, 4-byte aligned, and the whole buffer stays canonical.
        let end = self
            .address
            .checked_add(bytes)
            .ok_or(FramebufferError::BadAddress)?;
        if self.address < 0xffff_8000_0000_0000
            || !self.address.is_multiple_of(4)
            || end < self.address
        {
            return Err(FramebufferError::BadAddress);
        }
        for field in [self.red, self.green, self.blue] {
            if field.size == 0
                || field.size > 8
                || u32::from(field.size) + u32::from(field.shift) > 32
            {
                return Err(FramebufferError::BadColorField);
            }
        }
        let width = self.width as u32;
        let height = self.height as u32;
        Ok(Geometry {
            address: self.address,
            width,
            height,
            pitch: self.pitch as u32,
            columns: width / CELL_WIDTH,
            rows: height / CELL_HEIGHT,
            foreground: self.encode(FOREGROUND),
            background: self.encode(BACKGROUND),
        })
    }

    /// Packs an 8-bit-per-channel color into this framebuffer's format.
    pub fn encode(&self, (r, g, b): (u8, u8, u8)) -> u32 {
        let channel = |value: u8, field: ColorField| {
            (u32::from(value) >> (8 - u32::from(field.size).min(8))) << field.shift
        };
        channel(r, self.red) | channel(g, self.green) | channel(b, self.blue)
    }
}

/// Glyph for a character; unknown characters render as '?'.
pub fn glyph(character: char) -> &'static [u8; 8] {
    let code = character as u32;
    match code {
        0x20..=0x7e => &font::BASIC[code as usize],
        0xa0..=0xff => &font::LATIN1[(code - 0xa0) as usize],
        _ => &font::BASIC[b'?' as usize],
    }
}

/// Pixel target the console draws into (the real framebuffer, or a host
/// buffer in tests).
pub trait Surface {
    fn put(&mut self, x: u32, y: u32, color: u32);
    fn get(&self, x: u32, y: u32) -> u32;
    /// Moves scanlines `[from, from + count)` to start at `to` (`to < from`).
    fn move_lines(&mut self, from: u32, to: u32, count: u32);
}

/// Cursor and text state, independent of where the pixels live.
#[derive(Clone, Copy, Debug)]
pub struct Console {
    pub geometry: Geometry,
    column: u32,
    row: u32,
}

impl Console {
    pub const fn new(geometry: Geometry) -> Self {
        Self {
            geometry,
            column: 0,
            row: 0,
        }
    }

    pub fn cursor(&self) -> (u32, u32) {
        (self.column, self.row)
    }

    /// Fills the whole surface with the background color.
    pub fn clear(&mut self, surface: &mut impl Surface) {
        for y in 0..self.geometry.height {
            for x in 0..self.geometry.width {
                surface.put(x, y, self.geometry.background);
            }
        }
        self.column = 0;
        self.row = 0;
    }

    pub fn write_str(&mut self, surface: &mut impl Surface, text: &str) {
        for character in text.chars() {
            self.write_char(surface, character);
        }
    }

    fn write_char(&mut self, surface: &mut impl Surface, character: char) {
        match character {
            '\n' => self.newline(surface),
            '\r' => self.column = 0,
            '\t' => {
                let next = (self.column / 8 + 1) * 8;
                while self.column < next.min(self.geometry.columns) {
                    self.draw(surface, ' ');
                }
            }
            // Other control characters are dropped, never drawn.
            character if (character as u32) < 0x20 || character == '\u{7f}' => {}
            character => self.draw(surface, character),
        }
    }

    fn draw(&mut self, surface: &mut impl Surface, character: char) {
        if self.column >= self.geometry.columns {
            self.newline(surface);
        }
        let bitmap = glyph(character);
        let x0 = self.column * CELL_WIDTH;
        let y0 = self.row * CELL_HEIGHT;
        for (line, bits) in bitmap.iter().enumerate() {
            for doubled in 0..2 {
                let y = y0 + line as u32 * 2 + doubled;
                for bit in 0..CELL_WIDTH {
                    let color = if bits >> bit & 1 != 0 {
                        self.geometry.foreground
                    } else {
                        self.geometry.background
                    };
                    surface.put(x0 + bit, y, color);
                }
            }
        }
        self.column += 1;
    }

    fn newline(&mut self, surface: &mut impl Surface) {
        self.column = 0;
        if self.row + 1 < self.geometry.rows {
            self.row += 1;
            return;
        }
        // Scroll one text row up and blank the last row.
        let used = self.geometry.rows * CELL_HEIGHT;
        surface.move_lines(CELL_HEIGHT, 0, used - CELL_HEIGHT);
        for y in used - CELL_HEIGHT..used {
            for x in 0..self.geometry.width {
                surface.put(x, y, self.geometry.background);
            }
        }
    }
}

/// The bootloader framebuffer as a `Surface`.
#[cfg(target_os = "none")]
struct Screen(Geometry);

#[cfg(target_os = "none")]
impl Screen {
    fn pixel(&self, x: u32, y: u32) -> *mut u32 {
        let offset = u64::from(y) * u64::from(self.0.pitch) + u64::from(x) * 4;
        (self.0.address + offset) as *mut u32
    }
}

#[cfg(target_os = "none")]
impl Surface for Screen {
    fn put(&mut self, x: u32, y: u32, color: u32) {
        if x < self.0.width && y < self.0.height {
            // SAFETY: `x`/`y` are inside the validated geometry, so the pixel
            // lies inside the bootloader framebuffer mapped in the HHDM.
            unsafe { self.pixel(x, y).write_volatile(color) }
        }
    }

    fn get(&self, x: u32, y: u32) -> u32 {
        if x < self.0.width && y < self.0.height {
            // SAFETY: As in `put`.
            unsafe { self.pixel(x, y).read_volatile() }
        } else {
            0
        }
    }

    fn move_lines(&mut self, from: u32, to: u32, count: u32) {
        let height = self.0.height;
        if to >= from || from.saturating_add(count) > height {
            return;
        }
        let pitch = self.0.pitch as usize;
        let source = self.pixel(0, from) as *const u8;
        let target = self.pixel(0, to) as *mut u8;
        // SAFETY: Both ranges are whole scanlines inside the validated
        // framebuffer; `copy` handles the overlap.
        unsafe { core::ptr::copy(source, target, pitch * count as usize) }
    }
}

#[cfg(target_os = "none")]
mod live {
    use super::{Console, FramebufferError, FramebufferInfo, Screen, Surface};
    use core::cell::UnsafeCell;

    struct Slot(UnsafeCell<Option<Console>>);
    // SAFETY: The slot is only touched under the serial console lock (see
    // `crate::serial::write`) or before other CPUs start.
    unsafe impl Sync for Slot {}

    static CONSOLE: Slot = Slot(UnsafeCell::new(None));

    /// Validates the framebuffer, clears it, and proves it is writable by
    /// drawing a glyph and reading it back. Returns the geometry on success.
    pub fn init(info: &FramebufferInfo) -> Result<super::Geometry, FramebufferError> {
        let geometry = info.validate()?;
        let mut screen = Screen(geometry);
        let mut console = Console::new(geometry);
        console.clear(&mut screen);
        // Readback: the top-left pixel row of 'T' is fully lit.
        console.write_str(&mut screen, "T\r");
        let lit = screen.get(1, 0) == geometry.foreground;
        console.clear(&mut screen);
        if !lit {
            return Err(FramebufferError::BadAddress);
        }
        crate::serial::console(|_| {
            // SAFETY: Under the console lock (or single CPU at boot).
            unsafe { *CONSOLE.0.get() = Some(console) };
        });
        Ok(geometry)
    }

    /// Draws `text` if a console is active. Caller holds the console lock.
    pub(crate) fn write(text: &str) {
        // SAFETY: Called only from `serial::write` inside `console`.
        if let Some(console) = unsafe { (*CONSOLE.0.get()).as_mut() } {
            let mut screen = Screen(console.geometry);
            console.write_str(&mut screen, text);
        }
    }
}

#[cfg(target_os = "none")]
pub use live::init;
#[cfg(target_os = "none")]
pub(crate) use live::write;

/// Host builds have no screen: validation only, nothing is drawn.
#[cfg(not(target_os = "none"))]
pub fn init(info: &FramebufferInfo) -> Result<Geometry, FramebufferError> {
    info.validate()
}

/// Host builds have no screen.
#[cfg(not(target_os = "none"))]
pub(crate) fn write(_text: &str) {}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn info() -> FramebufferInfo {
        FramebufferInfo {
            address: 0xffff_8000_fd00_0000,
            width: 64,
            height: 48,
            pitch: 64 * 4,
            bits_per_pixel: 32,
            memory_model: 1,
            red: ColorField { size: 8, shift: 16 },
            green: ColorField { size: 8, shift: 8 },
            blue: ColorField { size: 8, shift: 0 },
        }
    }

    struct Buffer {
        width: u32,
        pixels: Vec<u32>,
    }

    impl Surface for Buffer {
        fn put(&mut self, x: u32, y: u32, color: u32) {
            self.pixels[(y * self.width + x) as usize] = color;
        }
        fn get(&self, x: u32, y: u32) -> u32 {
            self.pixels[(y * self.width + x) as usize]
        }
        fn move_lines(&mut self, from: u32, to: u32, count: u32) {
            let w = self.width as usize;
            self.pixels.copy_within(
                from as usize * w..(from + count) as usize * w,
                to as usize * w,
            );
        }
    }

    fn buffer(geometry: &Geometry) -> Buffer {
        Buffer {
            width: geometry.width,
            pixels: vec![0x1234; (geometry.width * geometry.height) as usize],
        }
    }

    #[test]
    fn accepts_standard_rgb32() {
        let geometry = info().validate().unwrap();
        assert_eq!((geometry.columns, geometry.rows), (8, 3));
        assert_eq!(geometry.foreground, 0x00d0_d0d0);
    }

    #[test]
    fn rejects_hostile_geometry() {
        let mut bad = info();
        bad.memory_model = 0;
        assert_eq!(bad.validate(), Err(FramebufferError::NotRgb));
        bad = info();
        bad.bits_per_pixel = 24;
        assert_eq!(bad.validate(), Err(FramebufferError::UnsupportedDepth));
        bad = info();
        bad.pitch = 10;
        assert_eq!(bad.validate(), Err(FramebufferError::PitchTooSmall));
        bad = info();
        bad.address = 0x1000;
        assert_eq!(bad.validate(), Err(FramebufferError::BadAddress));
        bad = info();
        bad.address = u64::MAX - 3;
        assert_eq!(bad.validate(), Err(FramebufferError::BadAddress));
        bad = info();
        bad.height = u64::MAX;
        assert_eq!(bad.validate(), Err(FramebufferError::TooLarge));
        bad = info();
        bad.width = 0;
        assert_eq!(bad.validate(), Err(FramebufferError::EmptyGeometry));
        bad = info();
        bad.red = ColorField { size: 8, shift: 30 };
        assert_eq!(bad.validate(), Err(FramebufferError::BadColorField));
    }

    #[test]
    fn encodes_bgr_and_narrow_channels() {
        let mut bgr = info();
        bgr.red = ColorField { size: 8, shift: 0 };
        bgr.blue = ColorField { size: 8, shift: 16 };
        assert_eq!(bgr.encode((0xff, 0, 0)), 0xff);
        let mut rgb565 = info();
        rgb565.red = ColorField { size: 5, shift: 11 };
        assert_eq!(rgb565.encode((0xff, 0, 0)) >> 11, 0x1f);
    }

    #[test]
    fn glyph_lookup_covers_spanish_text() {
        assert_ne!(glyph('ñ'), glyph('?'));
        assert_ne!(glyph('á'), glyph('?'));
        assert_eq!(glyph('\u{4e2d}'), glyph('?'));
    }

    #[test]
    fn draws_and_wraps_and_scrolls() {
        let geometry = info().validate().unwrap();
        let mut surface = buffer(&geometry);
        let mut console = Console::new(geometry);
        console.clear(&mut surface);
        assert!(surface.pixels.iter().all(|&p| p == geometry.background));
        console.write_str(&mut surface, "T");
        assert_eq!(surface.get(1, 0), geometry.foreground);
        assert_eq!(console.cursor(), (1, 0));
        // 8 columns: the ninth character wraps.
        console.write_str(&mut surface, "\r123456789");
        assert_eq!(console.cursor(), (1, 1));
        // Reach the last row, then scroll: row 1 must now hold old row 2.
        console.write_str(&mut surface, "\nX");
        assert_eq!(console.cursor(), (1, 2));
        let row = |surface: &Buffer, r: u32| -> Vec<u32> {
            (r * CELL_HEIGHT..(r + 1) * CELL_HEIGHT)
                .flat_map(|y| (0..geometry.width).map(move |x| (x, y)))
                .map(|(x, y)| surface.get(x, y))
                .collect()
        };
        let old_last = row(&surface, 2);
        console.write_str(&mut surface, "\nY");
        assert_eq!(console.cursor(), (1, 2));
        assert_eq!(row(&surface, 1), old_last);
        // Control characters are not drawn.
        let snapshot = surface.pixels.clone();
        console.write_str(&mut surface, "\u{1b}\u{7}");
        assert_eq!(surface.pixels, snapshot);
    }
}
