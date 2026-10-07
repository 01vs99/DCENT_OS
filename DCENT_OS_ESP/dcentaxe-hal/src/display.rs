//! Display driver for DCENT_axe boards.
//!
//! When `display-ssd1306` feature is active: full SSD1306 OLED driver (128x32, I2C).
//! When `display-none` feature is active: no-op stub with the same API (headless boards).
//!
//! This file is the I2C **transport** only. Every routine that decides which
//! pixels are set — the 5x7 font, the glyph blitter, text/centred-text layout,
//! the bitmap / sparkline / progress-bar helpers, the XOR rectangle and the
//! notification queue's ordering rules — lives in the host-pure
//! [`crate::display_convert`] module so it can be executed, rendered to PNG and
//! asserted in the host test gate with no hardware. Same split as
//! `tmp451_convert.rs`/`tmp451.rs` and `pca9544_convert.rs`/`pca9544.rs`.
//!
//! The public API of `Ssd1306Display` is unchanged by that split, and
//! `display_convert`'s differential tests pin every drawing routine
//! byte-for-byte against the pre-split implementation.

// The notification record is shared by both variants so a `display-none` board
// and an SSD1306 board cannot drift apart on the queue's data shape.
pub use crate::display_convert::OledNotification;

// ============================================================================
// Headless stub — all display calls become no-ops, saves ~20KB flash
// ============================================================================
#[cfg(feature = "display-none")]
mod headless {
    use crate::i2c::I2cBus;

    pub struct Ssd1306Display {
        pub initialized: bool,
        pub inverted: bool,
        pub notifications: Vec<super::OledNotification>,
    }

    impl Ssd1306Display {
        pub fn new() -> Self {
            Self {
                initialized: false,
                inverted: false,
                notifications: Vec::new(),
            }
        }
        pub fn notify(&mut self, _l0: &str, _l1: &str, _l2: &str, _l3: &str) {}
        pub fn notify_urgent(&mut self, _l0: &str, _l1: &str, _l2: &str, _l3: &str) {}
        pub fn has_urgent_notification(&self) -> bool {
            false
        }
        pub fn show_notification_if_pending(&mut self, _i2c: &mut I2cBus<'_>) -> bool {
            false
        }
        pub fn init(&mut self, _i2c: &mut I2cBus<'_>) -> Result<(), crate::i2c::I2cError> {
            log::info!("Headless board — no display");
            Ok(())
        }
        pub fn set_flip(
            &mut self,
            _i2c: &mut I2cBus<'_>,
            _flip: bool,
        ) -> Result<(), crate::i2c::I2cError> {
            Ok(())
        }
        pub fn clear(&mut self) {}
        pub fn flush(&self, _i2c: &mut I2cBus<'_>) -> Result<(), crate::i2c::I2cError> {
            Ok(())
        }
        pub fn draw_char(&mut self, _x: usize, _y: usize, _ch: char) {}
        pub fn draw_text(&mut self, _x: usize, _y: usize, _text: &str) {}
        pub fn draw_centered(&mut self, _y: usize, _text: &str) {}
        pub fn set_pixel(&mut self, _x: usize, _y: usize, _on: bool) {}
        pub fn draw_hline(&mut self, _x: usize, _y: usize, _len: usize) {}
        pub fn draw_vline(&mut self, _x: usize, _y: usize, _len: usize) {}
        pub fn invert_display(&self, _i2c: &mut I2cBus<'_>, _invert: bool) {}
        pub fn set_contrast(&self, _i2c: &mut I2cBus<'_>, _brightness: u8) {}
        pub fn draw_bitmap(&mut self, _x: usize, _y: usize, _data: &[u8], _w: usize, _h: usize) {}
        pub fn draw_bitmap_2x(&mut self, _x: usize, _y: usize, _data: &[u8], _w: usize, _h: usize) {
        }
        pub fn draw_sparkline(&mut self, _x: usize, _y: usize, _values: &[f32], _bar_width: usize) {
        }
        pub fn draw_progress_bar(&mut self, _x: usize, _y: usize, _width: usize, _ratio: f32) {}
        pub fn show_status(
            &mut self,
            _i2c: &mut I2cBus<'_>,
            _l0: &str,
            _l1: &str,
            _l2: &str,
            _l3: &str,
        ) {
        }
    }
}

#[cfg(feature = "display-none")]
pub use headless::*;

// ============================================================================
// Full SSD1306 OLED driver
// ============================================================================
#[cfg(feature = "display-ssd1306")]
use crate::display_convert::{FrameBuffer, PAGES, WIDTH};
#[cfg(feature = "display-ssd1306")]
use crate::i2c::{I2cBus, I2cError};

#[cfg(feature = "display-ssd1306")]
/// SSD1306 I2C address (0x3C is standard for BitAxe OLED)
const SSD1306_ADDR: u8 = 0x3C;

#[cfg(feature = "display-ssd1306")]
const CMD_SINGLE: u8 = 0x00;
#[cfg(feature = "display-ssd1306")]
const CMD_STREAM: u8 = 0x00;
#[cfg(feature = "display-ssd1306")]
const DATA_STREAM: u8 = 0x40;

#[cfg(feature = "display-ssd1306")]
pub struct Ssd1306Display {
    /// Framebuffer: 4 pages of 128 bytes each (1 bit per pixel, column-major).
    /// All drawing lives in the host-pure `display_convert::FrameBuffer`.
    framebuf: FrameBuffer,
    /// Whether the display was successfully initialized
    pub initialized: bool,
    /// Whether the display is flipped 180 degrees
    pub inverted: bool,
    /// Notification queue — shown for 1 display tick then removed
    pub notifications: Vec<OledNotification>,
}

#[cfg(feature = "display-ssd1306")]
impl Ssd1306Display {
    /// Create a new display instance (uninitialized).
    pub fn new() -> Self {
        Self {
            framebuf: FrameBuffer::new(),
            initialized: false,
            inverted: false,
            notifications: Vec::new(),
        }
    }

    /// Push a non-urgent notification to display on a later OLED update tick.
    /// Keep this queue small so status pages are not starved by flavor chatter.
    pub fn notify(&mut self, line0: &str, line1: &str, line2: &str, line3: &str) {
        if !self.initialized {
            return;
        }
        crate::display_convert::push_normal(&mut self.notifications, line0, line1, line2, line3);
    }

    /// Push an urgent notification that preempts position 0 in the queue.
    /// Use for safety-critical messages (fan stall, thermal) that must not be dropped.
    pub fn notify_urgent(&mut self, line0: &str, line1: &str, line2: &str, line3: &str) {
        if !self.initialized {
            return;
        }
        crate::display_convert::push_urgent(&mut self.notifications, line0, line1, line2, line3);
    }

    /// Whether an urgent notification is waiting at the front of the queue.
    pub fn has_urgent_notification(&self) -> bool {
        crate::display_convert::has_urgent(&self.notifications)
    }

    /// Check if there's a pending notification. If so, display it and remove it.
    /// Returns true if a notification was shown (caller should skip normal display).
    pub fn show_notification_if_pending(&mut self, i2c: &mut I2cBus<'_>) -> bool {
        if !self.initialized {
            self.notifications.clear();
            return false;
        }
        if let Some(notif) = crate::display_convert::take_next(&mut self.notifications) {
            self.show_status(i2c, &notif.line0, &notif.line1, &notif.line2, &notif.line3);
            true
        } else {
            false
        }
    }

    /// Initialize the SSD1306 display. Returns Ok(()) if the display responds.
    /// Fails gracefully if no display is connected — mining continues without it.
    pub fn init(&mut self, i2c: &mut I2cBus<'_>) -> Result<(), I2cError> {
        // Check if display is present
        if !i2c.probe(SSD1306_ADDR) {
            log::warn!("No SSD1306 OLED found at 0x{:02X}", SSD1306_ADDR);
            return Err(I2cError::DeviceNotFound(SSD1306_ADDR));
        }

        // SSD1306 init sequence for 128x32
        let init_cmds: &[u8] = &[
            0xAE, // Display OFF
            0xD5, 0x80, // Set display clock divide ratio (default)
            0xA8, 0x1F, // Set multiplex ratio = 31 (32 rows - 1)
            0xD3, 0x00, // Set display offset = 0
            0x40, // Set display start line = 0
            0x8D, 0x14, // Enable charge pump (0x14 = enabled)
            0x20, 0x00, // Set memory addressing mode = horizontal
            0xA0, // Set segment re-map (column 0 = SEG0) — correct for BitAxe Gamma
            0xC0, // Set COM output scan direction (normal) — correct for BitAxe Gamma
            0xDA, 0x02, // Set COM pins hardware config (sequential, no remap)
            0x81, 0xCF, // Set contrast = 0xCF (high — good daylight readability)
            0xD9, 0xF1, // Set pre-charge period
            0xDB, 0x40, // Set VCOMH deselect level
            0xA4, // Display follows RAM content
            0xA6, // Normal display (not inverted)
            0xAF, // Display ON
        ];

        // Send init commands one at a time
        for &cmd in init_cmds {
            i2c.write(SSD1306_ADDR, &[CMD_SINGLE, cmd])?;
        }

        self.initialized = true;
        self.clear();
        self.flush(i2c)?;

        log::info!("SSD1306 OLED display initialized (128x32)");
        Ok(())
    }

    /// Flip the display 180 degrees (invert orientation).
    /// Useful when the BitAxe is mounted upside-down.
    pub fn set_flip(&mut self, i2c: &mut I2cBus<'_>, flip: bool) -> Result<(), I2cError> {
        if !self.initialized {
            return Ok(());
        }
        self.inverted = flip;
        if flip {
            // Flipped 180 degrees from default
            i2c.write(SSD1306_ADDR, &[CMD_SINGLE, 0xA1])?; // SEG re-map: col 127 = SEG0
            i2c.write(SSD1306_ADDR, &[CMD_SINGLE, 0xC8])?; // COM scan: remapped
        } else {
            // Default orientation (correct for BitAxe Gamma)
            i2c.write(SSD1306_ADDR, &[CMD_SINGLE, 0xA0])?; // SEG re-map: col 0 = SEG0
            i2c.write(SSD1306_ADDR, &[CMD_SINGLE, 0xC0])?; // COM scan: normal
        }
        log::info!(
            "Display orientation: {}",
            if flip { "flipped 180" } else { "normal" }
        );
        Ok(())
    }

    /// Clear the framebuffer (all pixels off).
    pub fn clear(&mut self) {
        self.framebuf.clear();
    }

    /// Flush the entire framebuffer to the display over I2C.
    pub fn flush(&self, i2c: &mut I2cBus<'_>) -> Result<(), I2cError> {
        if !self.initialized {
            return Ok(());
        }

        // Set column and page address range for full screen
        i2c.write(SSD1306_ADDR, &[CMD_STREAM, 0x21, 0x00, 0x7F])?; // Column 0-127
        i2c.write(SSD1306_ADDR, &[CMD_STREAM, 0x22, 0x00, (PAGES - 1) as u8])?; // Page 0-3

        // Send framebuffer data page by page (I2C max transaction ~128 bytes safe)
        for page in 0..PAGES {
            let mut buf = [0u8; WIDTH + 1];
            buf[0] = DATA_STREAM;
            buf[1..].copy_from_slice(self.framebuf.page(page));
            i2c.write(SSD1306_ADDR, &buf)?;
        }

        Ok(())
    }

    /// Draw a character at pixel position (x, y) using the built-in 5x7 font.
    /// y should be 0, 8, 16, or 24 for the 4 text rows.
    ///
    /// Kept (private, as it has always been) so this variant's method set stays
    /// aligned with the `display-none` stub's, which exposes `draw_char`
    /// publicly. That asymmetry predates this lane and is left for an O lane to
    /// resolve; removing the method here would widen it rather than close it.
    #[allow(dead_code)]
    fn draw_char(&mut self, x: usize, y: usize, ch: char) {
        self.framebuf.draw_char(x, y, ch);
    }

    /// Draw a text string at pixel position (x, y).
    /// Characters are 6px wide (5px glyph + 1px spacing).
    pub fn draw_text(&mut self, x: usize, y: usize, text: &str) {
        self.framebuf.draw_text(x, y, text);
    }

    /// Draw centered text on a given row (y = 0, 8, 16, or 24).
    pub fn draw_centered(&mut self, y: usize, text: &str) {
        self.framebuf.draw_centered(y, text);
    }

    /// Set a single pixel in the framebuffer.
    pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
        self.framebuf.set_pixel(x, y, on);
    }

    /// Draw a horizontal line from (x, y) for `len` pixels.
    pub fn draw_hline(&mut self, x: usize, y: usize, len: usize) {
        self.framebuf.draw_hline(x, y, len);
    }

    /// Draw a vertical line from (x, y) for `len` pixels.
    pub fn draw_vline(&mut self, x: usize, y: usize, len: usize) {
        self.framebuf.draw_vline(x, y, len);
    }

    /// Invert the display (swap black/white) via SSD1306 command.
    /// Zero framebuffer cost — just a display mode toggle.
    pub fn invert_display(&self, i2c: &mut I2cBus<'_>, invert: bool) {
        if !self.initialized {
            return;
        }
        let cmd = if invert { 0xA7 } else { 0xA6 };
        let _ = i2c.write(SSD1306_ADDR, &[CMD_SINGLE, cmd]);
    }

    /// Set display contrast (brightness) via SSD1306 command (0x00-0xFF).
    /// Useful for breathing effects, dramatic reveals, and visual "sound effects".
    pub fn set_contrast(&self, i2c: &mut I2cBus<'_>, brightness: u8) {
        if !self.initialized {
            return;
        }
        // Must be a single I2C transaction — 0x81 expects its parameter
        // byte within the same STOP. Split writes cause silent failure.
        let _ = i2c.write(SSD1306_ADDR, &[CMD_STREAM, 0x81, brightness]);
    }

    /// Draw a 1-bit bitmap at pixel position (x, y).
    /// `data` is column-major: each byte is 8 vertical pixels, LSB = top.
    /// `w` = width in pixels, `h` = height in pixels (must be multiple of 8).
    pub fn draw_bitmap(&mut self, x: usize, y: usize, data: &[u8], w: usize, h: usize) {
        self.framebuf.draw_bitmap(x, y, data, w, h);
    }

    /// Draw a 1-bit bitmap scaled 2x. Used for full-height companion moments.
    pub fn draw_bitmap_2x(&mut self, x: usize, y: usize, data: &[u8], w: usize, h: usize) {
        self.framebuf.draw_bitmap_2x(x, y, data, w, h);
    }

    /// Draw a sparkline using block characters (▁▂▃▄▅▆▇█).
    /// `values` is a slice of normalized values (0.0 - 1.0).
    /// Drawn at pixel row `y` (top of the sparkline area), spanning 8 pixels tall.
    /// Each value gets `bar_width` pixels wide.
    pub fn draw_sparkline(&mut self, x: usize, y: usize, values: &[f32], bar_width: usize) {
        self.framebuf.draw_sparkline(x, y, values, bar_width);
    }

    /// Draw a progress bar at (x, y) with given width and fill ratio (0.0-1.0).
    pub fn draw_progress_bar(&mut self, x: usize, y: usize, width: usize, ratio: f32) {
        self.framebuf.draw_progress_bar(x, y, width, ratio);
    }

    /// XOR a rectangular region — toggles all pixels in the area.
    /// Used for inverted text boxes (e.g., Matrix rain stat overlays).
    pub fn xor_rect(&mut self, x: usize, y: usize, w: usize, h: usize) {
        if !self.initialized {
            return;
        }
        self.framebuf.xor_rect(x, y, w, h);
    }

    /// Show a simple 4-line status screen. Each line is centered.
    /// Pass empty string "" to skip a line.
    pub fn show_status(
        &mut self,
        i2c: &mut I2cBus<'_>,
        line0: &str,
        line1: &str,
        line2: &str,
        line3: &str,
    ) {
        if !self.initialized {
            return;
        }
        self.framebuf.draw_status([line0, line1, line2, line3]);
        let _ = self.flush(i2c);
    }
}
