//! Host-pure SSD1306 framebuffer, 5x7 glyph core and notification queue.
//!
//! The espidf half of the panel driver (`display.rs`) is I2C transport and
//! nothing else: the init command list, `flush`, `set_flip`, `invert_display`
//! and `set_contrast`. Everything that decides which *pixels* are set — the
//! font table, the glyph blitter, the text/centred-text layout, the bitmap,
//! sparkline and progress-bar helpers, the XOR rectangle, and the
//! notification queue's ordering rules — lives here so it can be executed,
//! rendered and asserted on a host with no hardware.
//!
//! Same split as `tmp451_convert.rs`/`tmp451.rs` and
//! `pca9544_convert.rs`/`pca9544.rs`. This module is compiled
//! **unconditionally** (no `display-*` feature gate) and re-included into
//! `dcentaxe-core` via `#[path]` so its `#[cfg(test)]` tests run in the host
//! gate.
//!
//! # Why this module exists
//!
//! Before this split the OLED had **zero** tests. `display.rs` contained no
//! `#[test]`, `dcentaxe-core` never referenced it, and the only evidence the
//! panel rendered anything was a bench photograph. That made the panel the one
//! user-facing surface in the firmware with no executable contract at all.
//!
//! # The panel geometry is a hard constraint, not a preference
//!
//! The bench unit's panel is a 128x32 SSD1306 (`display.rs` init sets
//! multiplex ratio 0x1F = 31 rows, and logs `128x32`). The font is 5 px wide
//! drawn on a 6 px pitch, and [`draw_text`](FrameBuffer::draw_text) stops as
//! soon as the next glyph would not fit, so a line starting at x = 0 holds
//! **exactly [`TEXT_COLUMNS`] = 21 characters** and a 4-row screen holds
//! [`TEXT_ROWS`] = 4 lines.
//!
//! Text longer than that is **silently clipped** — no ellipsis, no wrap, no
//! error. [`centered_columns_rendered`] and [`centered_is_clipped`] make that
//! behaviour measurable so a caller (or a test) can see the clip instead of
//! discovering it on a bench photo.
//!
//! # Byte-identical
//!
//! Every routine below is a verbatim move of the pre-refactor code in
//! `display.rs`, including its quirks (`draw_centered` measures `str::len()`
//! in **bytes**, `draw_progress_bar` assumes `width >= 1`, `xor_rect`'s
//! clamping expression). Behaviour changes belong in a later lane and must be
//! argued for; this module only makes the existing behaviour observable. The
//! `pre_refactor_reference` module in the tests below is a transcription of
//! the original algorithms and every drawing routine is differentially
//! compared against it.

// The glyph blitter is a VERBATIM move of code that has never been host-
// compiled before (`display.rs` is `#[cfg(target_os = "espidf")]`), so clippy
// is seeing it for the first time and two style lints fire on its original
// shape. Rewriting them would break the byte-identical-move contract this lane
// rests on and make the diff unauditable, so they are allowed here — narrowly,
// in this file only — instead of being silenced repo-wide or "tidied" into a
// behaviour change.
#![allow(clippy::manual_range_contains, clippy::needless_range_loop)]

// ─────────────────────────────────────────────────────────────────────────────
// Geometry
// ─────────────────────────────────────────────────────────────────────────────

/// Panel width in pixels.
pub const WIDTH: usize = 128;
/// Panel height in pixels.
pub const HEIGHT: usize = 32;
/// SSD1306 pages (8 pixel rows each).
pub const PAGES: usize = HEIGHT / 8;
/// Framebuffer size in bytes (1 bit per pixel, column-major within a page).
pub const FRAME_BYTES: usize = WIDTH * PAGES;

/// Glyph width in pixels (the font cell, without the inter-character gap).
pub const GLYPH_WIDTH_PX: usize = 5;
/// Horizontal advance per character: 5 px glyph + 1 px gap.
pub const CHAR_PITCH_PX: usize = 6;

/// Characters that fit on one line when drawn from x = 0.
///
/// `draw_text` breaks when `cx + 5 > 128`, so the last glyph starts at x = 120
/// and column 21 (x = 126) never renders.
pub const TEXT_COLUMNS: usize = 21;
/// Text rows on a 128x32 panel at 8 px pitch.
pub const TEXT_ROWS: usize = 4;
/// The `y` baseline of each text row, as `show_status` uses them.
pub const ROW_Y: [usize; TEXT_ROWS] = [0, 8, 16, 24];

/// Soft cap on queued non-urgent notifications (`notify`).
pub const MAX_NORMAL_QUEUE_LEN: usize = 3;
/// Hard cap on the whole queue after an urgent insert (`notify_urgent`).
pub const MAX_QUEUE_LEN_AFTER_URGENT: usize = 5;

// ─────────────────────────────────────────────────────────────────────────────
// Notification queue
// ─────────────────────────────────────────────────────────────────────────────

/// One queued 4-line panel message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OledNotification {
    pub line0: String,
    pub line1: String,
    pub line2: String,
    pub line3: String,
    pub urgent: bool,
}

impl OledNotification {
    /// The four lines in row order, as `show_status` consumes them.
    pub fn lines(&self) -> [&str; TEXT_ROWS] {
        [&self.line0, &self.line1, &self.line2, &self.line3]
    }
}

/// Queue a non-urgent notification.
///
/// Verbatim move of `Ssd1306Display::notify`'s queue policy: at three or more
/// queued messages the OLDEST non-urgent entry is evicted to make room; if
/// every entry is urgent the new message is DROPPED rather than displacing
/// safety traffic.
pub fn push_normal(
    queue: &mut Vec<OledNotification>,
    line0: &str,
    line1: &str,
    line2: &str,
    line3: &str,
) {
    // Keep newest normal events, but never let them bury IP/hashrate/block pages.
    if queue.len() >= MAX_NORMAL_QUEUE_LEN {
        if let Some(pos) = queue.iter().position(|notif| !notif.urgent) {
            queue.remove(pos);
        } else {
            return;
        }
    }
    queue.push(OledNotification {
        line0: line0.to_string(),
        line1: line1.to_string(),
        line2: line2.to_string(),
        line3: line3.to_string(),
        urgent: false,
    });
}

/// Queue an urgent notification at the FRONT of the queue.
///
/// Verbatim move of `Ssd1306Display::notify_urgent`: the message preempts
/// position 0 and the queue is then trimmed from the BACK, so the oldest
/// flavour chatter is dropped and safety traffic is kept.
pub fn push_urgent(
    queue: &mut Vec<OledNotification>,
    line0: &str,
    line1: &str,
    line2: &str,
    line3: &str,
) {
    let notif = OledNotification {
        line0: line0.to_string(),
        line1: line1.to_string(),
        line2: line2.to_string(),
        line3: line3.to_string(),
        urgent: true,
    };
    queue.insert(0, notif);
    // Trim excess from the back (drop gamification, keep safety)
    while queue.len() > MAX_QUEUE_LEN_AFTER_URGENT {
        queue.pop();
    }
}

/// Whether the message at the front of the queue is urgent.
pub fn has_urgent(queue: &[OledNotification]) -> bool {
    queue.first().map(|notif| notif.urgent).unwrap_or(false)
}

/// Pop the front message, if any.
pub fn take_next(queue: &mut Vec<OledNotification>) -> Option<OledNotification> {
    if queue.is_empty() {
        None
    } else {
        Some(queue.remove(0))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Text metrics
// ─────────────────────────────────────────────────────────────────────────────

/// How many characters `draw_text` will actually render starting at `x`.
///
/// This is the measurement `draw_text` performs implicitly and then throws
/// away: it stops as soon as `cx + 5 > WIDTH`.
pub fn columns_rendered_from(x: usize, text: &str) -> usize {
    let mut cx = x;
    let mut drawn = 0usize;
    for _ in text.chars() {
        if cx + GLYPH_WIDTH_PX > WIDTH {
            break;
        }
        drawn += 1;
        cx += CHAR_PITCH_PX;
    }
    drawn
}

/// The x origin `draw_centered` picks for `text`.
///
/// NOTE the pre-existing quirk this preserves: the width estimate is
/// `str::len()`, i.e. **UTF-8 bytes**, not characters. A line containing any
/// multi-byte character is therefore mis-centred (and the character itself
/// renders as a blank, because the font only covers ASCII 32..127).
pub fn centered_origin_x(text: &str) -> usize {
    let text_width = text.len() * CHAR_PITCH_PX;
    if text_width < WIDTH {
        (WIDTH - text_width) / 2
    } else {
        0
    }
}

/// How many characters of `text` survive `draw_centered`.
pub fn centered_columns_rendered(text: &str) -> usize {
    columns_rendered_from(centered_origin_x(text), text)
}

/// Whether `draw_centered` will silently drop characters off the right edge.
pub fn centered_is_clipped(text: &str) -> bool {
    centered_columns_rendered(text) < text.chars().count()
}

/// Whether a line respects the 21-column budget of a 128x32 panel.
pub fn line_fits(text: &str) -> bool {
    text.chars().count() <= TEXT_COLUMNS
}

/// Derive progress through the current subsidy-halving epoch from a real
/// coinbase height and the selected network's halving interval.
///
/// Height zero is the firmware's "no decoded height yet" sentinel, so it
/// returns `None` rather than drawing an authoritative-looking empty bar.
/// Interval zero is likewise rejected instead of dividing by zero. At an
/// exact halving boundary the new epoch has just begun: progress is zero and
/// `blocks_to_halving` names the full interval until the *next* boundary.
pub fn halving_progress(block_height: u32, interval: u32) -> Option<(f32, u32)> {
    if block_height == 0 || interval == 0 {
        return None;
    }

    let blocks_into_epoch = block_height % interval;
    let progress = blocks_into_epoch as f32 / interval as f32;
    let blocks_to_halving = interval - blocks_into_epoch;
    Some((progress, blocks_to_halving))
}

// ─────────────────────────────────────────────────────────────────────────────
// Mining-state truth ladder (shared with the web dashboard)
// ─────────────────────────────────────────────────────────────────────────────

/// One rung of the mining truth ladder - the vocabulary the 128x32 panel and
/// the web dashboard must agree on.
///
/// The web resolves exactly this ladder in `update()`
/// (`dcentaxe/src/dashboard.rs`, the `tbMiningPill` / `heroMiningState` block):
///
/// ```text
/// var miningEnabled  = d.dcentaxe ? d.dcentaxe.miningEnabled !== false : hrGH > 0;
/// var activeHashrate = hrGH > 0;
/// var mining         = miningEnabled && activeHashrate;
/// mining ? 'MINING' : miningEnabled ? 'READY' : 'STANDBY'
/// ```
///
/// with the pill first-painting `PENDING` until `/api/system/info` arrives.
///
/// # Why the panel needs this type
///
/// Before it the OLED had **no** rung vocabulary at all. Page 0 printed one
/// ad-hoc six-armed ternary (`OFF/HOT/SLEEP/FED/NITE/HASH`) and the companion
/// page a second, differently-worded one
/// (`Offline/TOO HOT/Zzz.../Nom nonce/Proud!/Mining hard`) - and the two gated
/// on DIFFERENT discriminators (page 0's face on the boot-time `mining_enabled`,
/// its word on the runtime `runtime_mining_active`), so a board killed at
/// runtime could show a non-standby face beside `OFF`. A permitted-but-idle
/// board (`Ready`) and a stopped one (`Standby`) both collapsed into
/// `SLEEP`/`Zzz...`, so the panel could not tell them apart at all. Both are
/// `CRITIC_RUBRIC.md` H7: the panel contradicting the web on one line.
///
/// The flavour words are not gone - they are DECORATIONS now (`HOT`, `FED`,
/// `NITE`), appended AFTER the rung word by [`fit_line`] and dropped first when
/// the 21-column line runs out. A decoration never replaces the rung.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MiningRung {
    /// No telemetry yet. The state is UNKNOWN - not "off".
    TelemetryPending,
    /// Mining is permitted and hashrate is positive.
    Mining,
    /// Mining is permitted; hashrate is not (yet) positive.
    Ready,
    /// Mining is not permitted: stopped, killed, or never started.
    Standby,
}

impl MiningRung {
    /// Every rung, in ladder order.
    pub const ALL: [MiningRung; 4] = [
        MiningRung::TelemetryPending,
        MiningRung::Mining,
        MiningRung::Ready,
        MiningRung::Standby,
    ];

    /// The panel word - byte-identical to the web topbar pill's text, so a
    /// photograph of the panel and a screenshot of the dashboard can be
    /// compared with no translation table in between.
    pub const fn panel_word(self) -> &'static str {
        match self {
            MiningRung::TelemetryPending => "PENDING",
            MiningRung::Mining => "MINING",
            MiningRung::Ready => "READY",
            MiningRung::Standby => "STANDBY",
        }
    }

    /// The web dashboard's `data-state` id for this rung.
    pub const fn web_state_id(self) -> &'static str {
        match self {
            MiningRung::TelemetryPending => "pending",
            MiningRung::Mining => "mining",
            MiningRung::Ready => "ready",
            MiningRung::Standby => "standby",
        }
    }

    /// The web hero badge's mixed-case label for this rung.
    pub const fn web_label(self) -> &'static str {
        match self {
            MiningRung::TelemetryPending => "Telemetry pending",
            MiningRung::Mining => "Mining",
            MiningRung::Ready => "Ready",
            MiningRung::Standby => "Standby",
        }
    }
}

/// Resolve the rung from the same three inputs the web's `update()` uses.
///
/// * `telemetry_ready` - the caller actually has data. The web sets this when
///   the first `/api/system/info` response lands. The firmware's carousel has
///   already read this tick's stats snapshot before it draws, so it passes
///   `true`; `TelemetryPending` is the BOOT screens' rung.
/// * `mining_enabled` - mining is permitted RIGHT NOW. On the panel that is
///   `runtime_mining_active` (boot-time permission AND no runtime kill), never
///   the boot-time flag on its own - mixing the two is the original defect.
/// * `active_hashrate` - hashrate is strictly positive: the same test the web
///   makes (`hrGH > 0`), not a "> 1 GH/s" heuristic, so the two surfaces cannot
///   disagree in the band between them.
pub fn resolve_rung(
    telemetry_ready: bool,
    mining_enabled: bool,
    active_hashrate: bool,
) -> MiningRung {
    if !telemetry_ready {
        MiningRung::TelemetryPending
    } else if mining_enabled && active_hashrate {
        MiningRung::Mining
    } else if mining_enabled {
        MiningRung::Ready
    } else {
        MiningRung::Standby
    }
}

/// Compose a panel line that fits `budget` columns **by construction**.
///
/// `required` words always render, joined by single spaces. `optional`
/// decorations are then appended in order, each one only if it still fits; a
/// decoration that does not fit is skipped and a later, shorter one may still
/// be taken.
///
/// This is why a long block height or a decoration can never push the rung word
/// off the panel: [`FrameBuffer::draw_text`] clips from the RIGHT, silently,
/// with no ellipsis - so whatever is last is what disappears. Putting the
/// truth first and the flavour last makes the clip harmless.
///
/// If `required` alone is already over budget the result is returned unchanged
/// (the panel still clips it, but nothing is made worse); a test pins that case
/// rather than leaving it to chance.
pub fn fit_line(required: &[&str], optional: &[&str], budget: usize) -> String {
    let mut out = String::new();
    for word in required {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    let mut used = out.chars().count();
    for word in optional {
        if word.is_empty() {
            continue;
        }
        let cost = 1 + word.chars().count();
        if used + cost > budget {
            continue;
        }
        out.push(' ');
        out.push_str(word);
        used += cost;
    }
    out
}

/// Compose a `RUNG: detail` status line that **cannot** overflow the panel.
///
/// P1-O2 round 2, critic findings 1 and 2. The four boot/init `show_status`
/// lines in `main.rs` were raw `format!` results handed straight to
/// [`FrameBuffer::draw_text`], which clips at column 21 from the RIGHT,
/// silently, with no ellipsis. The tightest of them was 20 of 21 columns: one
/// column of headroom, guarded by nothing. Renaming a rung, or turning
/// `disabled` into `disabled by safety`, would have pushed the
/// operator-facing half of the line off the glass with every test green.
///
/// The budget is structural here. The rung word is unconditional; the detail
/// is appended only if the WHOLE of it fits. A detail that cannot fit is
/// dropped, so the worst case is a terse-but-true `STANDBY` rather than a
/// half word or a clipped rung - the same rule [`fit_line`] applies to its
/// decorations, for the one shape `fit_line`'s space-joined form cannot
/// express: the colon.
///
/// It takes the WORD, not the [`MiningRung`], so every call site still names
/// its rung (`MiningRung::Ready.panel_word()`) in the source. The
/// `dcentaxe-core` contract reads those names to prove which rung each screen
/// claims; a helper that swallowed the enum would hide exactly that.
pub fn rung_status_line(rung_word: &str, detail: &str) -> String {
    let head = rung_word.chars().count();
    let tail = detail.chars().count();
    if tail == 0 || head + 2 + tail > TEXT_COLUMNS {
        return rung_word.to_string();
    }
    let mut out = String::with_capacity(rung_word.len() + 2 + detail.len());
    out.push_str(rung_word);
    out.push_str(": ");
    out.push_str(detail);
    out
}

/// The ONE decoration table every panel surface shares.
///
/// P1-O2 round 2, critic finding 6. Page 0 chose from `HOT`/`FED`/`NITE` and
/// the companion page from `HOT`/`FED`/`WOW`, each with its own priority
/// chain, so a single tick could decorate page 0 and leave page 7 bare - two
/// surfaces disagreeing about the same instant, which is the small cousin of
/// the rung disagreement this lane exists to end. Both pages now ask this
/// table, and a `dcentaxe-core` source contract pins that they ask it with
/// identical inputs.
///
/// Priority is urgency, not page order: the thermal flag first (it is the
/// only decoration carrying a warning), then the two event flashes that fade
/// within a few ticks, then the ambient day/night hint. At most one
/// decoration is ever returned.
///
/// Decorations are always OPTIONAL: [`fit_line`] drops them before it would
/// touch the rung word, so a slot too narrow for one - the 11-column pet room
/// cannot hold `STANDBY NITE` - shows the truth without the flavour, never the
/// flavour without the truth.
pub fn rung_decoration(
    too_hot: bool,
    share_flash: bool,
    achievement_flash: bool,
    night: bool,
) -> &'static [&'static str] {
    if too_hot {
        &["HOT"]
    } else if share_flash {
        &["FED"]
    } else if achievement_flash {
        &["WOW"]
    } else if night {
        &["NITE"]
    } else {
        &[]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Framebuffer
// ─────────────────────────────────────────────────────────────────────────────

/// The 512-byte SSD1306 framebuffer plus every pure drawing routine.
///
/// Layout: 4 pages of 128 bytes; byte `page * 128 + x` holds the 8 vertical
/// pixels of column `x` in that page, LSB = topmost.
#[derive(Clone)]
pub struct FrameBuffer {
    buf: [u8; FRAME_BYTES],
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameBuffer {
    /// A blank framebuffer (all pixels off).
    pub const fn new() -> Self {
        Self {
            buf: [0; FRAME_BYTES],
        }
    }

    /// The raw bytes, in the order `flush` pushes them.
    pub fn as_bytes(&self) -> &[u8; FRAME_BYTES] {
        &self.buf
    }

    /// One SSD1306 page (128 bytes).
    pub fn page(&self, page: usize) -> &[u8] {
        let start = page * WIDTH;
        &self.buf[start..start + WIDTH]
    }

    /// Read a single pixel. Out-of-range coordinates read as off.
    pub fn pixel(&self, x: usize, y: usize) -> bool {
        if x >= WIDTH || y >= HEIGHT {
            return false;
        }
        self.buf[(y / 8) * WIDTH + x] & (1 << (y % 8)) != 0
    }

    /// Clear the framebuffer (all pixels off).
    pub fn clear(&mut self) {
        self.buf.fill(0);
    }

    /// Draw a character at pixel position (x, y) using the built-in 5x7 font.
    /// y should be 0, 8, 16, or 24 for the 4 text rows.
    pub fn draw_char(&mut self, x: usize, y: usize, ch: char) {
        let idx = ch as usize;
        let glyph = if idx >= 32 && idx < 128 {
            &FONT_5X7[idx - 32]
        } else {
            &FONT_5X7[0] // space for unknown chars
        };

        let page = y / 8;
        let bit_offset = y % 8;

        for col in 0..5 {
            let px = x + col;
            if px >= WIDTH {
                break;
            }

            let col_data = glyph[col];

            if bit_offset == 0 {
                // Aligned to page boundary — fast path
                if page < PAGES {
                    self.buf[page * WIDTH + px] |= col_data;
                }
            } else {
                // Spans two pages
                if page < PAGES {
                    self.buf[page * WIDTH + px] |= col_data << bit_offset;
                }
                if page + 1 < PAGES {
                    self.buf[(page + 1) * WIDTH + px] |= col_data >> (8 - bit_offset);
                }
            }
        }
    }

    /// Draw a text string at pixel position (x, y).
    /// Characters are 6px wide (5px glyph + 1px spacing).
    pub fn draw_text(&mut self, x: usize, y: usize, text: &str) {
        let mut cx = x;
        for ch in text.chars() {
            if cx + 5 > WIDTH {
                break;
            }
            self.draw_char(cx, y, ch);
            cx += 6; // 5px char + 1px gap
        }
    }

    /// Draw centered text on a given row (y = 0, 8, 16, or 24).
    pub fn draw_centered(&mut self, y: usize, text: &str) {
        let text_width = text.len() * 6;
        let x = if text_width < WIDTH {
            (WIDTH - text_width) / 2
        } else {
            0
        };
        self.draw_text(x, y, text);
    }

    /// The framebuffer half of `Ssd1306Display::show_status`: clear, then
    /// centre each non-empty line on its row. The I2C flush stays in the
    /// transport.
    pub fn draw_status(&mut self, lines: [&str; TEXT_ROWS]) {
        self.clear();
        for (row, line) in lines.iter().enumerate() {
            if !line.is_empty() {
                self.draw_centered(ROW_Y[row], line);
            }
        }
    }

    /// Set a single pixel in the framebuffer.
    pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
        if x >= WIDTH || y >= HEIGHT {
            return;
        }
        let page = y / 8;
        let bit = y % 8;
        let idx = page * WIDTH + x;
        if on {
            self.buf[idx] |= 1 << bit;
        } else {
            self.buf[idx] &= !(1 << bit);
        }
    }

    /// Draw a horizontal line from (x, y) for `len` pixels.
    pub fn draw_hline(&mut self, x: usize, y: usize, len: usize) {
        for i in 0..len {
            self.set_pixel(x + i, y, true);
        }
    }

    /// Draw a vertical line from (x, y) for `len` pixels.
    pub fn draw_vline(&mut self, x: usize, y: usize, len: usize) {
        for i in 0..len {
            self.set_pixel(x, y + i, true);
        }
    }

    /// Draw a 1-bit bitmap at pixel position (x, y).
    /// `data` is column-major: each byte is 8 vertical pixels, LSB = top.
    /// `w` = width in pixels, `h` = height in pixels (must be multiple of 8).
    pub fn draw_bitmap(&mut self, x: usize, y: usize, data: &[u8], w: usize, h: usize) {
        let pages = h / 8;
        for page in 0..pages {
            for col in 0..w {
                let src_idx = page * w + col;
                if src_idx >= data.len() {
                    break;
                }
                let px = x + col;
                let py = y + page * 8;
                if px >= WIDTH || py >= HEIGHT {
                    continue;
                }
                let dst_page = py / 8;
                let bit_offset = py % 8;
                let col_data = data[src_idx];
                if bit_offset == 0 {
                    if dst_page < PAGES {
                        self.buf[dst_page * WIDTH + px] |= col_data;
                    }
                } else {
                    if dst_page < PAGES {
                        self.buf[dst_page * WIDTH + px] |= col_data << bit_offset;
                    }
                    if dst_page + 1 < PAGES {
                        self.buf[(dst_page + 1) * WIDTH + px] |= col_data >> (8 - bit_offset);
                    }
                }
            }
        }
    }

    /// Draw a 1-bit bitmap scaled 2x. Used for full-height companion moments.
    pub fn draw_bitmap_2x(&mut self, x: usize, y: usize, data: &[u8], w: usize, h: usize) {
        for col in 0..w {
            for row in 0..h {
                let src_idx = (row / 8) * w + col;
                if src_idx >= data.len() || (data[src_idx] & (1u8 << (row % 8))) == 0 {
                    continue;
                }
                let px = x + col * 2;
                let py = y + row * 2;
                self.set_pixel(px, py, true);
                self.set_pixel(px + 1, py, true);
                self.set_pixel(px, py + 1, true);
                self.set_pixel(px + 1, py + 1, true);
            }
        }
    }

    /// Draw a sparkline using block characters (bottom-anchored bars).
    /// `values` is a slice of normalized values (0.0 - 1.0).
    /// Drawn at pixel row `y` (top of the sparkline area), spanning 8 pixels tall.
    /// Each value gets `bar_width` pixels wide.
    pub fn draw_sparkline(&mut self, x: usize, y: usize, values: &[f32], bar_width: usize) {
        let max_height: usize = 7; // max 7 pixels tall
        for (i, &val) in values.iter().enumerate() {
            let bar_height = ((val.clamp(0.0, 1.0) * max_height as f32) as usize).max(1);
            let bx = x + i * bar_width;
            // Draw bar from bottom up
            for w in 0..bar_width.min(2) {
                for h in 0..bar_height {
                    self.set_pixel(bx + w, y + max_height - h, true);
                }
            }
        }
    }

    /// Draw a progress bar at (x, y) with given width and fill ratio (0.0-1.0).
    ///
    /// NOTE: `width` must be >= 1 — `x + width - 1` underflows at 0. That is
    /// the pre-refactor behaviour and is preserved deliberately; every shipping
    /// call site passes a literal width.
    pub fn draw_progress_bar(&mut self, x: usize, y: usize, width: usize, ratio: f32) {
        let filled = ((ratio.clamp(0.0, 1.0) * width as f32) as usize).min(width);
        // Top border
        self.draw_hline(x, y, width);
        // Bottom border
        self.draw_hline(x, y + 4, width);
        // Left/right borders
        self.set_pixel(x, y + 1, true);
        self.set_pixel(x, y + 2, true);
        self.set_pixel(x, y + 3, true);
        self.set_pixel(x + width - 1, y + 1, true);
        self.set_pixel(x + width - 1, y + 2, true);
        self.set_pixel(x + width - 1, y + 3, true);
        // Fill
        for fx in 0..filled {
            self.set_pixel(x + 1 + fx, y + 1, true);
            self.set_pixel(x + 1 + fx, y + 2, true);
            self.set_pixel(x + 1 + fx, y + 3, true);
        }
    }

    /// XOR a rectangular region — toggles all pixels in the area.
    /// Used for inverted text boxes (e.g., Matrix rain stat overlays).
    pub fn xor_rect(&mut self, x: usize, y: usize, w: usize, h: usize) {
        for py in y..y.min(32).max(y) + h.min(32 - y.min(31)) {
            for px in x..x.min(128).max(x) + w.min(128 - x.min(127)) {
                if px < 128 && py < 32 {
                    let page = py / 8;
                    let bit = py % 8;
                    self.buf[page * 128 + px] ^= 1 << bit;
                }
            }
        }
    }
}

/// Render a 4-line status screen exactly as `Ssd1306Display::show_status`
/// composes it, without touching a bus.
pub fn render_status(lines: [&str; TEXT_ROWS]) -> FrameBuffer {
    let mut fb = FrameBuffer::new();
    fb.draw_status(lines);
    fb
}

// ==========================================================================
// Built-in 5x7 pixel font (ASCII 32-127, 96 characters)
// Each character is 5 bytes — one byte per column, LSB = top pixel.
// ==========================================================================
#[rustfmt::skip]
pub const FONT_5X7: [[u8; 5]; 96] = [
    [0x00,0x00,0x00,0x00,0x00], // 32 ' '
    [0x00,0x00,0x5F,0x00,0x00], // 33 '!'
    [0x00,0x07,0x00,0x07,0x00], // 34 '"'
    [0x14,0x7F,0x14,0x7F,0x14], // 35 '#'
    [0x24,0x2A,0x7F,0x2A,0x12], // 36 '$'
    [0x23,0x13,0x08,0x64,0x62], // 37 '%'
    [0x36,0x49,0x55,0x22,0x50], // 38 '&'
    [0x00,0x05,0x03,0x00,0x00], // 39 '''
    [0x00,0x1C,0x22,0x41,0x00], // 40 '('
    [0x00,0x41,0x22,0x1C,0x00], // 41 ')'
    [0x08,0x2A,0x1C,0x2A,0x08], // 42 '*'
    [0x08,0x08,0x3E,0x08,0x08], // 43 '+'
    [0x00,0x50,0x30,0x00,0x00], // 44 ','
    [0x08,0x08,0x08,0x08,0x08], // 45 '-'
    [0x00,0x60,0x60,0x00,0x00], // 46 '.'
    [0x20,0x10,0x08,0x04,0x02], // 47 '/'
    [0x3E,0x51,0x49,0x45,0x3E], // 48 '0'
    [0x00,0x42,0x7F,0x40,0x00], // 49 '1'
    [0x42,0x61,0x51,0x49,0x46], // 50 '2'
    [0x21,0x41,0x45,0x4B,0x31], // 51 '3'
    [0x18,0x14,0x12,0x7F,0x10], // 52 '4'
    [0x27,0x45,0x45,0x45,0x39], // 53 '5'
    [0x3C,0x4A,0x49,0x49,0x30], // 54 '6'
    [0x01,0x71,0x09,0x05,0x03], // 55 '7'
    [0x36,0x49,0x49,0x49,0x36], // 56 '8'
    [0x06,0x49,0x49,0x29,0x1E], // 57 '9'
    [0x00,0x36,0x36,0x00,0x00], // 58 ':'
    [0x00,0x56,0x36,0x00,0x00], // 59 ';'
    [0x00,0x08,0x14,0x22,0x41], // 60 '<'
    [0x14,0x14,0x14,0x14,0x14], // 61 '='
    [0x41,0x22,0x14,0x08,0x00], // 62 '>'
    [0x02,0x01,0x51,0x09,0x06], // 63 '?'
    [0x32,0x49,0x79,0x41,0x3E], // 64 '@'
    [0x7E,0x11,0x11,0x11,0x7E], // 65 'A'
    [0x7F,0x49,0x49,0x49,0x36], // 66 'B'
    [0x3E,0x41,0x41,0x41,0x22], // 67 'C'
    [0x7F,0x41,0x41,0x22,0x1C], // 68 'D'
    [0x7F,0x49,0x49,0x49,0x41], // 69 'E'
    [0x7F,0x09,0x09,0x01,0x01], // 70 'F'
    [0x3E,0x41,0x41,0x51,0x32], // 71 'G'
    [0x7F,0x08,0x08,0x08,0x7F], // 72 'H'
    [0x00,0x41,0x7F,0x41,0x00], // 73 'I'
    [0x20,0x40,0x41,0x3F,0x01], // 74 'J'
    [0x7F,0x08,0x14,0x22,0x41], // 75 'K'
    [0x7F,0x40,0x40,0x40,0x40], // 76 'L'
    [0x7F,0x02,0x04,0x02,0x7F], // 77 'M'
    [0x7F,0x04,0x08,0x10,0x7F], // 78 'N'
    [0x3E,0x41,0x41,0x41,0x3E], // 79 'O'
    [0x7F,0x09,0x09,0x09,0x06], // 80 'P'
    [0x3E,0x41,0x51,0x21,0x5E], // 81 'Q'
    [0x7F,0x09,0x19,0x29,0x46], // 82 'R'
    [0x46,0x49,0x49,0x49,0x31], // 83 'S'
    [0x01,0x01,0x7F,0x01,0x01], // 84 'T'
    [0x3F,0x40,0x40,0x40,0x3F], // 85 'U'
    [0x1F,0x20,0x40,0x20,0x1F], // 86 'V'
    [0x7F,0x20,0x18,0x20,0x7F], // 87 'W'
    [0x63,0x14,0x08,0x14,0x63], // 88 'X'
    [0x03,0x04,0x78,0x04,0x03], // 89 'Y'
    [0x61,0x51,0x49,0x45,0x43], // 90 'Z'
    [0x00,0x00,0x7F,0x41,0x41], // 91 '['
    [0x02,0x04,0x08,0x10,0x20], // 92 '\'
    [0x41,0x41,0x7F,0x00,0x00], // 93 ']'
    [0x04,0x02,0x01,0x02,0x04], // 94 '^'
    [0x40,0x40,0x40,0x40,0x40], // 95 '_'
    [0x00,0x01,0x02,0x04,0x00], // 96 '`'
    [0x20,0x54,0x54,0x54,0x78], // 97 'a'
    [0x7F,0x48,0x44,0x44,0x38], // 98 'b'
    [0x38,0x44,0x44,0x44,0x20], // 99 'c'
    [0x38,0x44,0x44,0x48,0x7F], // 100 'd'
    [0x38,0x54,0x54,0x54,0x18], // 101 'e'
    [0x08,0x7E,0x09,0x01,0x02], // 102 'f'
    [0x08,0x14,0x54,0x54,0x3C], // 103 'g'
    [0x7F,0x08,0x04,0x04,0x78], // 104 'h'
    [0x00,0x44,0x7D,0x40,0x00], // 105 'i'
    [0x20,0x40,0x44,0x3D,0x00], // 106 'j'
    [0x00,0x7F,0x10,0x28,0x44], // 107 'k'
    [0x00,0x41,0x7F,0x40,0x00], // 108 'l'
    [0x7C,0x04,0x18,0x04,0x78], // 109 'm'
    [0x7C,0x08,0x04,0x04,0x78], // 110 'n'
    [0x38,0x44,0x44,0x44,0x38], // 111 'o'
    [0x7C,0x14,0x14,0x14,0x08], // 112 'p'
    [0x08,0x14,0x14,0x18,0x7C], // 113 'q'
    [0x7C,0x08,0x04,0x04,0x08], // 114 'r'
    [0x48,0x54,0x54,0x54,0x20], // 115 's'
    [0x04,0x3F,0x44,0x40,0x20], // 116 't'
    [0x3C,0x40,0x40,0x20,0x7C], // 117 'u'
    [0x1C,0x20,0x40,0x20,0x1C], // 118 'v'
    [0x3C,0x40,0x30,0x40,0x3C], // 119 'w'
    [0x44,0x28,0x10,0x28,0x44], // 120 'x'
    [0x0C,0x50,0x50,0x50,0x3C], // 121 'y'
    [0x44,0x64,0x54,0x4C,0x44], // 122 'z'
    [0x00,0x08,0x36,0x41,0x00], // 123 '{'
    [0x00,0x00,0x7F,0x00,0x00], // 124 '|'
    [0x00,0x41,0x36,0x08,0x00], // 125 '}'
    [0x08,0x08,0x2A,0x1C,0x08], // 126 '~'
    [0x08,0x1C,0x2A,0x08,0x08], // 127 DEL
];

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─────────────────────────────────────────────────────────────────────
    // Pre-refactor reference implementation.
    //
    // A verbatim transcription of the routines as they stood in
    // `dcentaxe-hal/src/display.rs` BEFORE this split (commit b3071167c,
    // file SHA-256 1b5ad064…41e). It operates on a bare `[u8; 512]` and is
    // never used outside these tests; every drawing routine above is
    // differentially compared against it so "byte-identical" is a executed
    // assertion, not a claim in a report.
    //
    // The reference intentionally borrows `super::FONT_5X7`: the font table's
    // own integrity is proven separately, and independently, by
    // `font_table_digest_matches_pre_refactor_bytes` below (whose expected
    // constant was computed from the pre-refactor file's bytes, not from this
    // module).
    // ─────────────────────────────────────────────────────────────────────
    mod pre_refactor_reference {
        use super::super::FONT_5X7;

        pub const WIDTH: usize = 128;
        pub const HEIGHT: usize = 32;
        pub const PAGES: usize = HEIGHT / 8;

        pub struct Ref {
            pub framebuf: [u8; WIDTH * PAGES],
        }

        impl Ref {
            pub fn blank() -> Self {
                Self {
                    framebuf: [0; WIDTH * PAGES],
                }
            }

            pub fn clear(&mut self) {
                self.framebuf.fill(0);
            }

            pub fn draw_char(&mut self, x: usize, y: usize, ch: char) {
                let idx = ch as usize;
                let glyph = if idx >= 32 && idx < 128 {
                    &FONT_5X7[idx - 32]
                } else {
                    &FONT_5X7[0]
                };

                let page = y / 8;
                let bit_offset = y % 8;

                for col in 0..5 {
                    let px = x + col;
                    if px >= WIDTH {
                        break;
                    }

                    let col_data = glyph[col];

                    if bit_offset == 0 {
                        if page < PAGES {
                            self.framebuf[page * WIDTH + px] |= col_data;
                        }
                    } else {
                        if page < PAGES {
                            self.framebuf[page * WIDTH + px] |= col_data << bit_offset;
                        }
                        if page + 1 < PAGES {
                            self.framebuf[(page + 1) * WIDTH + px] |= col_data >> (8 - bit_offset);
                        }
                    }
                }
            }

            pub fn draw_text(&mut self, x: usize, y: usize, text: &str) {
                let mut cx = x;
                for ch in text.chars() {
                    if cx + 5 > WIDTH {
                        break;
                    }
                    self.draw_char(cx, y, ch);
                    cx += 6;
                }
            }

            pub fn draw_centered(&mut self, y: usize, text: &str) {
                let text_width = text.len() * 6;
                let x = if text_width < WIDTH {
                    (WIDTH - text_width) / 2
                } else {
                    0
                };
                self.draw_text(x, y, text);
            }

            pub fn set_pixel(&mut self, x: usize, y: usize, on: bool) {
                if x >= WIDTH || y >= HEIGHT {
                    return;
                }
                let page = y / 8;
                let bit = y % 8;
                let idx = page * WIDTH + x;
                if on {
                    self.framebuf[idx] |= 1 << bit;
                } else {
                    self.framebuf[idx] &= !(1 << bit);
                }
            }

            pub fn draw_hline(&mut self, x: usize, y: usize, len: usize) {
                for i in 0..len {
                    self.set_pixel(x + i, y, true);
                }
            }

            pub fn draw_vline(&mut self, x: usize, y: usize, len: usize) {
                for i in 0..len {
                    self.set_pixel(x, y + i, true);
                }
            }

            pub fn draw_bitmap(&mut self, x: usize, y: usize, data: &[u8], w: usize, h: usize) {
                let pages = h / 8;
                for page in 0..pages {
                    for col in 0..w {
                        let src_idx = page * w + col;
                        if src_idx >= data.len() {
                            break;
                        }
                        let px = x + col;
                        let py = y + page * 8;
                        if px >= WIDTH || py >= HEIGHT {
                            continue;
                        }
                        let dst_page = py / 8;
                        let bit_offset = py % 8;
                        let col_data = data[src_idx];
                        if bit_offset == 0 {
                            if dst_page < PAGES {
                                self.framebuf[dst_page * WIDTH + px] |= col_data;
                            }
                        } else {
                            if dst_page < PAGES {
                                self.framebuf[dst_page * WIDTH + px] |= col_data << bit_offset;
                            }
                            if dst_page + 1 < PAGES {
                                self.framebuf[(dst_page + 1) * WIDTH + px] |=
                                    col_data >> (8 - bit_offset);
                            }
                        }
                    }
                }
            }

            pub fn draw_bitmap_2x(&mut self, x: usize, y: usize, data: &[u8], w: usize, h: usize) {
                for col in 0..w {
                    for row in 0..h {
                        let src_idx = (row / 8) * w + col;
                        if src_idx >= data.len() || (data[src_idx] & (1u8 << (row % 8))) == 0 {
                            continue;
                        }
                        let px = x + col * 2;
                        let py = y + row * 2;
                        self.set_pixel(px, py, true);
                        self.set_pixel(px + 1, py, true);
                        self.set_pixel(px, py + 1, true);
                        self.set_pixel(px + 1, py + 1, true);
                    }
                }
            }

            pub fn draw_sparkline(&mut self, x: usize, y: usize, values: &[f32], bar_width: usize) {
                let max_height: usize = 7;
                for (i, &val) in values.iter().enumerate() {
                    let bar_height = ((val.clamp(0.0, 1.0) * max_height as f32) as usize).max(1);
                    let bx = x + i * bar_width;
                    for w in 0..bar_width.min(2) {
                        for h in 0..bar_height {
                            self.set_pixel(bx + w, y + max_height - h, true);
                        }
                    }
                }
            }

            pub fn draw_progress_bar(&mut self, x: usize, y: usize, width: usize, ratio: f32) {
                let filled = ((ratio.clamp(0.0, 1.0) * width as f32) as usize).min(width);
                self.draw_hline(x, y, width);
                self.draw_hline(x, y + 4, width);
                self.set_pixel(x, y + 1, true);
                self.set_pixel(x, y + 2, true);
                self.set_pixel(x, y + 3, true);
                self.set_pixel(x + width - 1, y + 1, true);
                self.set_pixel(x + width - 1, y + 2, true);
                self.set_pixel(x + width - 1, y + 3, true);
                for fx in 0..filled {
                    self.set_pixel(x + 1 + fx, y + 1, true);
                    self.set_pixel(x + 1 + fx, y + 2, true);
                    self.set_pixel(x + 1 + fx, y + 3, true);
                }
            }

            pub fn xor_rect(&mut self, x: usize, y: usize, w: usize, h: usize) {
                for py in y..y.min(32).max(y) + h.min(32 - y.min(31)) {
                    for px in x..x.min(128).max(x) + w.min(128 - x.min(127)) {
                        if px < 128 && py < 32 {
                            let page = py / 8;
                            let bit = py % 8;
                            self.framebuf[page * 128 + px] ^= 1 << bit;
                        }
                    }
                }
            }

            /// `show_status` minus the I2C flush.
            pub fn show_status(&mut self, l0: &str, l1: &str, l2: &str, l3: &str) {
                self.clear();
                if !l0.is_empty() {
                    self.draw_centered(0, l0);
                }
                if !l1.is_empty() {
                    self.draw_centered(8, l1);
                }
                if !l2.is_empty() {
                    self.draw_centered(16, l2);
                }
                if !l3.is_empty() {
                    self.draw_centered(24, l3);
                }
            }
        }
    }

    use pre_refactor_reference::Ref;

    /// Deterministic xorshift so the differential sweep is reproducible with
    /// no dev-dependency.
    struct Rng(u64);
    impl Rng {
        fn new(seed: u64) -> Self {
            Rng(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next_u64() % (n as u64)) as usize
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 1. Byte-identity proofs
    // ─────────────────────────────────────────────────────────────────────

    /// The font table survived the move byte for byte.
    ///
    /// The expected FNV-1a-64 digest and checksum were computed OUTSIDE this
    /// crate, over the 480 font bytes parsed from the pre-refactor
    /// `display.rs` at commit b3071167c (file SHA-256
    /// 1b5ad0646a5303f0e747ee7c49a03e1adbae8892a2ac22363b34eacb289e141e).
    /// A single flipped bit anywhere in the table fails this.
    #[test]
    fn font_table_digest_matches_pre_refactor_bytes() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut sum: u32 = 0;
        for glyph in FONT_5X7.iter() {
            for &b in glyph.iter() {
                h ^= b as u64;
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
                sum += b as u32;
            }
        }
        assert_eq!(
            h, 0xCE16_EE06_4813_7D51,
            "FONT_5X7 changed during the display_convert split — the OLED font is not \
             refactorable, every glyph must survive byte for byte"
        );
        assert_eq!(sum, 22_046, "FONT_5X7 byte sum drifted");
        assert_eq!(FONT_5X7.len(), 96, "font must cover ASCII 32..=127");
    }

    /// Every text path renders byte-identically to the pre-refactor code, for
    /// a corpus that spans the whole ASCII range, every row, every start x,
    /// and lines from empty to well past the clip point.
    #[test]
    fn text_rendering_is_byte_identical_to_the_pre_refactor_code() {
        let alphabet: Vec<char> = (32u8..128u8).map(|c| c as char).collect();
        let mut rng = Rng::new(0x0DED_01ED_1306_0001);
        let mut cases = 0usize;

        // Exhaustive: every glyph, at a page-aligned and an unaligned y (the
        // two branches of draw_char), at x values that straddle the right edge.
        for &ch in alphabet.iter() {
            for y in [0usize, 3, 8, 16, 24, 25, 31] {
                for x in [0usize, 1, 60, 120, 123, 124, 127] {
                    let mut a = FrameBuffer::new();
                    let mut b = Ref::blank();
                    a.draw_char(x, y, ch);
                    b.draw_char(x, y, ch);
                    assert_eq!(
                        a.as_bytes().as_slice(),
                        b.framebuf.as_slice(),
                        "draw_char drift at ch={ch:?} x={x} y={y}"
                    );
                    cases += 1;
                }
            }
        }

        // Randomized strings, including over-long and non-ASCII (the font only
        // covers ASCII 32..127, and `draw_centered` measures BYTES — both
        // quirks must survive the move unchanged).
        for _ in 0..2000 {
            let len = rng.below(40);
            let mut s = String::new();
            for _ in 0..len {
                if rng.below(20) == 0 {
                    s.push(['\u{b0}', '\u{e9}', '\u{2588}', '\u{2581}', '\u{3a9}'][rng.below(5)]);
                } else {
                    s.push(alphabet[rng.below(alphabet.len())]);
                }
            }
            let x = rng.below(130);
            let y = rng.below(34);

            let mut a = FrameBuffer::new();
            let mut b = Ref::blank();
            a.draw_text(x, y, &s);
            b.draw_text(x, y, &s);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "draw_text drift at x={x} y={y} s={s:?}"
            );

            let row = ROW_Y[rng.below(TEXT_ROWS)];
            let mut a = FrameBuffer::new();
            let mut b = Ref::blank();
            a.draw_centered(row, &s);
            b.draw_centered(row, &s);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "draw_centered drift at y={row} s={s:?}"
            );
            cases += 1;
        }

        assert!(cases > 5000, "differential sweep must be substantive");
    }

    /// The geometry helpers (pixels, lines, bitmaps, sparkline, progress bar,
    /// XOR rect) render byte-identically to the pre-refactor code.
    #[test]
    fn geometry_helpers_are_byte_identical_to_the_pre_refactor_code() {
        let mut rng = Rng::new(0x51D1_3060_0000_0001);

        for _ in 0..500 {
            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            let (x, y, len) = (rng.below(140), rng.below(40), rng.below(40));
            a.draw_hline(x, y, len);
            b.draw_hline(x, y, len);
            assert_eq!(a.as_bytes().as_slice(), b.framebuf.as_slice(), "draw_hline");

            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            a.draw_vline(x, y, len);
            b.draw_vline(x, y, len);
            assert_eq!(a.as_bytes().as_slice(), b.framebuf.as_slice(), "draw_vline");

            // set_pixel, including the clearing path
            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            for _ in 0..40 {
                let (px, py, on) = (rng.below(140), rng.below(40), rng.below(2) == 0);
                a.set_pixel(px, py, on);
                b.set_pixel(px, py, on);
            }
            assert_eq!(a.as_bytes().as_slice(), b.framebuf.as_slice(), "set_pixel");
        }

        // Bitmaps at every page offset, including short data slices.
        for _ in 0..400 {
            let w = 1 + rng.below(24);
            let h = 8 * (1 + rng.below(4));
            let full = w * (h / 8);
            let take = if rng.below(4) == 0 {
                rng.below(full.max(1))
            } else {
                full
            };
            let data: Vec<u8> = (0..take).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
            let (x, y) = (rng.below(132), rng.below(36));

            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            a.draw_bitmap(x, y, &data, w, h);
            b.draw_bitmap(x, y, &data, w, h);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "draw_bitmap x={x} y={y} w={w} h={h} len={}",
                data.len()
            );

            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            a.draw_bitmap_2x(x, y, &data, w, h);
            b.draw_bitmap_2x(x, y, &data, w, h);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "draw_bitmap_2x x={x} y={y} w={w} h={h}"
            );
        }

        // Sparkline + progress bar over the full ratio range.
        for i in 0..400 {
            let n = 1 + rng.below(30);
            let values: Vec<f32> = (0..n)
                .map(|_| (rng.below(300) as f32 / 200.0) - 0.25) // includes out-of-range
                .collect();
            let (x, y, bw) = (rng.below(120), rng.below(24), 1 + rng.below(4));
            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            a.draw_sparkline(x, y, &values, bw);
            b.draw_sparkline(x, y, &values, bw);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "draw_sparkline x={x} y={y} bw={bw}"
            );

            let ratio = (i as f32 / 399.0) * 1.5 - 0.25;
            let width = 1 + rng.below(60);
            let (px, py) = (rng.below(60), rng.below(26));
            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            a.draw_progress_bar(px, py, width, ratio);
            b.draw_progress_bar(px, py, width, ratio);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "draw_progress_bar x={px} y={py} w={width} r={ratio}"
            );
        }

        // XOR rect, including the odd clamping expression.
        for _ in 0..500 {
            let (x, y, w, h) = (rng.below(140), rng.below(40), rng.below(40), rng.below(40));
            let (mut a, mut b) = (FrameBuffer::new(), Ref::blank());
            a.draw_text(0, 0, "seed pattern");
            b.draw_text(0, 0, "seed pattern");
            a.xor_rect(x, y, w, h);
            b.xor_rect(x, y, w, h);
            assert_eq!(
                a.as_bytes().as_slice(),
                b.framebuf.as_slice(),
                "xor_rect x={x} y={y} w={w} h={h}"
            );
        }
    }

    /// `draw_status` composes exactly what `show_status` composed.
    #[test]
    fn status_composition_is_byte_identical_to_the_pre_refactor_show_status() {
        let corpus: [[&str; 4]; 8] = [
            ["", "", "", ""],
            ["DCENT_axe v0.3.0", "Mining", "1.21 TH/s", "IP: 203.0.113.5"],
            ["A", "", "C", ""],
            ["", "B", "", "D"],
            [
                "DCENT_axe v0.3.0",
                "Mining disabled",
                "Board has no rail actuator: no enable GPIO and no commandable regulator",
                "IP: 203.0.113.5",
            ],
            ["012345678901234567890", "x", "y", "z"],
            ["0123456789012345678901", "x", "y", "z"],
            [
                "!! FAN STALL",
                "fan0 0 RPM",
                "cutting hash",
                "reboot to resume",
            ],
        ];
        for lines in corpus.iter() {
            let got = render_status(*lines);
            let mut want = Ref::blank();
            want.show_status(lines[0], lines[1], lines[2], lines[3]);
            assert_eq!(
                got.as_bytes().as_slice(),
                want.framebuf.as_slice(),
                "show_status drift for {lines:?}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 2. Notification queue
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn normal_notifications_evict_the_oldest_normal_entry() {
        let mut q = Vec::new();
        for i in 0..5 {
            push_normal(&mut q, &format!("n{i}"), "", "", "");
        }
        assert_eq!(q.len(), MAX_NORMAL_QUEUE_LEN);
        assert_eq!(q[0].line0, "n2", "oldest normal entries are evicted first");
        assert_eq!(q[2].line0, "n4");
        assert!(q.iter().all(|n| !n.urgent));
    }

    #[test]
    fn a_full_urgent_queue_drops_the_normal_message_rather_than_safety_traffic() {
        let mut q = Vec::new();
        for i in 0..3 {
            push_urgent(&mut q, &format!("u{i}"), "", "", "");
        }
        push_normal(&mut q, "chatter", "", "", "");
        assert_eq!(q.len(), 3, "the normal message must be dropped, not queued");
        assert!(q.iter().all(|n| n.urgent));
    }

    #[test]
    fn urgent_notifications_preempt_position_zero_and_trim_from_the_back() {
        let mut q = Vec::new();
        for i in 0..3 {
            push_normal(&mut q, &format!("n{i}"), "", "", "");
        }
        for i in 0..4 {
            push_urgent(&mut q, &format!("u{i}"), "", "", "");
        }
        assert_eq!(q.len(), MAX_QUEUE_LEN_AFTER_URGENT);
        assert_eq!(q[0].line0, "u3", "newest urgent is at the front");
        assert!(has_urgent(&q));
        // Trimming from the back drops the OLDEST normal chatter first.
        assert!(!q.iter().any(|n| n.line0 == "n2"));
    }

    #[test]
    fn take_next_pops_the_front_and_reports_empty_honestly() {
        let mut q = Vec::new();
        assert!(take_next(&mut q).is_none());
        assert!(!has_urgent(&q));
        push_normal(&mut q, "a", "b", "c", "d");
        let got = take_next(&mut q).expect("one queued");
        assert_eq!(got.lines(), ["a", "b", "c", "d"]);
        assert!(q.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────
    // 3. The 21-column budget
    // ─────────────────────────────────────────────────────────────────────

    /// How many glyphs `draw_text` ACTUALLY put on the panel, read back out of
    /// the framebuffer rather than recomputed from the same stopping rule.
    ///
    /// Glyph cells are 5 px wide on a 6 px pitch, so they never overlap: a lit
    /// pixel anywhere in `[x + 6k, x + 6k + 5)` can only have come from glyph
    /// `k`. `draw_text` is a prefix operation, so the first dark cell ends the
    /// count. The caller must use a character whose glyph is non-blank.
    fn glyphs_drawn_by_draw_text(x: usize, y: usize, text: &str) -> usize {
        let mut fb = FrameBuffer::new();
        fb.draw_text(x, y, text);

        let mut drawn = 0usize;
        for k in 0..text.chars().count() {
            let cx = x + k * CHAR_PITCH_PX;
            let mut lit = false;
            'cell: for col in 0..GLYPH_WIDTH_PX {
                let px = cx + col;
                if px >= WIDTH {
                    break;
                }
                for row in 0..8 {
                    let py = y + row;
                    if py < HEIGHT && fb.pixel(px, py) {
                        lit = true;
                        break 'cell;
                    }
                }
            }
            if !lit {
                break;
            }
            drawn += 1;
        }
        drawn
    }

    /// [`columns_rendered_from`] must agree with what [`FrameBuffer::draw_text`]
    /// actually draws, at EVERY origin — not only at `x = 0` and the centred
    /// origins the rest of the suite happens to exercise.
    ///
    /// # The hole this closes
    ///
    /// Round 1 of lane P1-I2 shipped this metric with a live mutation hole,
    /// found by the P1-I2 critic: changing the metric's
    /// `cx + GLYPH_WIDTH_PX > WIDTH` to `>=` left all 13 tests of the module
    /// GREEN. The only origin the suite reached was `x = 0` (where `cx` is
    /// always a multiple of 6, and 123 is not) and centred origins derived from
    /// it, so the one boundary case that separates `>` from `>=` — `cx = 123`,
    /// the last glyph that fits exactly, ending on the panel's final column 127
    /// — was never evaluated. A metric that is only ever called at one origin is
    /// only ever tested at one origin.
    ///
    /// This test reaches `cx = 123` from every origin congruent to 3 mod 6
    /// (x = 3, 9, ..., 123) and reads the answer out of the framebuffer, so it
    /// cannot be satisfied by a second copy of the same expression.
    #[test]
    fn columns_rendered_from_agrees_with_draw_text_at_every_origin() {
        // 'H' is 0x7F,0x08,0x08,0x08,0x7F — non-blank in every column, so a
        // drawn cell is unmistakably lit and a skipped one unmistakably dark.
        let text: String = "H".repeat(TEXT_COLUMNS + 8);

        let mut boundary_origins = 0usize;
        for &y in ROW_Y.iter() {
            for x in 0..=(WIDTH + 4) {
                let metric = columns_rendered_from(x, &text);
                let actual = glyphs_drawn_by_draw_text(x, y, &text);
                assert_eq!(
                    metric, actual,
                    "origin x={x}, y={y}: columns_rendered_from says {metric} \
                     glyphs render, but draw_text actually drew {actual}"
                );
                // Count the origins that walk the cursor onto the exact
                // boundary the mutant breaks, so a future refactor that stops
                // reaching it fails loudly instead of going quiet.
                if x <= WIDTH - GLYPH_WIDTH_PX && (WIDTH - GLYPH_WIDTH_PX - x) % CHAR_PITCH_PX == 0
                {
                    boundary_origins += 1;
                }
            }
        }
        assert_eq!(
            boundary_origins,
            ROW_Y.len() * 21,
            "the sweep must keep reaching cx = {} (the last glyph that fits \
             exactly); if this count changes the mutation coverage changed with it",
            WIDTH - GLYPH_WIDTH_PX
        );

        // The boundary itself, stated once in the open so the intent survives a
        // rewrite of the sweep above: a glyph whose last column is 127 fits;
        // one starting a single pixel later does not.
        assert_eq!(columns_rendered_from(WIDTH - GLYPH_WIDTH_PX, "H"), 1);
        assert_eq!(glyphs_drawn_by_draw_text(WIDTH - GLYPH_WIDTH_PX, 0, "H"), 1);
        assert_eq!(columns_rendered_from(WIDTH - GLYPH_WIDTH_PX + 1, "H"), 0);
        assert_eq!(
            glyphs_drawn_by_draw_text(WIDTH - GLYPH_WIDTH_PX + 1, 0, "H"),
            0
        );
        // And reached through a real origin rather than a hand-placed one:
        // x = 3 walks 3, 9, ... 123 and must render 21 glyphs, not 20.
        assert_eq!(columns_rendered_from(3, &text), 21);
        assert_eq!(glyphs_drawn_by_draw_text(3, 0, &text), 21);
    }

    #[test]
    fn twenty_one_columns_is_the_measured_capacity_of_a_128px_line() {
        assert_eq!(columns_rendered_from(0, &"W".repeat(40)), TEXT_COLUMNS);
        assert_eq!(columns_rendered_from(0, &"W".repeat(21)), 21);
        assert_eq!(columns_rendered_from(0, &"W".repeat(22)), 21);
        // Centring buys nothing: at 22 characters the origin is already 0.
        assert_eq!(centered_origin_x(&"W".repeat(21)), 1);
        assert_eq!(centered_origin_x(&"W".repeat(22)), 0);
        assert_eq!(centered_columns_rendered(&"W".repeat(21)), 21);
        assert_eq!(centered_columns_rendered(&"W".repeat(22)), 21);
        assert!(!centered_is_clipped(&"W".repeat(21)));
        assert!(centered_is_clipped(&"W".repeat(22)));
        assert!(line_fits(&"W".repeat(21)));
        assert!(!line_fits(&"W".repeat(22)));
    }

    #[test]
    fn halving_progress_rejects_unknown_height_and_invalid_interval() {
        assert_eq!(halving_progress(0, 210_000), None);
        assert_eq!(halving_progress(868_123, 0), None);
    }

    #[test]
    fn halving_progress_resets_at_a_boundary_and_counts_to_the_next_one() {
        assert_eq!(halving_progress(840_000, 210_000), Some((0.0, 210_000)));

        let (almost, remaining) =
            halving_progress(839_999, 210_000).expect("known mainnet height");
        assert_eq!(remaining, 1);
        assert!((almost - 209_999.0 / 210_000.0).abs() < f32::EPSILON);
    }

    #[test]
    fn halving_progress_handles_a_large_mainnet_height_and_regtest_interval() {
        let (mainnet, mainnet_left) =
            halving_progress(868_123, 210_000).expect("known mainnet height");
        assert_eq!(mainnet_left, 181_877);
        assert!((mainnet - 28_123.0 / 210_000.0).abs() < f32::EPSILON);

        let (regtest, regtest_left) =
            halving_progress(151, 150).expect("known regtest height");
        assert_eq!(regtest_left, 149);
        assert!((regtest - 1.0 / 150.0).abs() < f32::EPSILON);
    }

    /// The lane's acceptance criterion: any 4-line input a caller hands the
    /// panel is checked, line by line, against the 21-column budget.
    #[test]
    fn every_line_of_a_compliant_status_screen_is_within_twenty_one_columns() {
        let compliant: [[&str; 4]; 5] = [
            [
                "DCENT_axe v0.3.0",
                "Mining",
                "1.21 TH/s  58C",
                "203.0.113.5",
            ],
            ["DCENT_axe v0.3.0", "Ready", "0.00 TH/s  41C", "203.0.113.5"],
            ["DCENT_axe v0.3.0", "Standby", "hash cut", "203.0.113.5"],
            ["!! POWER FAULT", "rail cut", "see dashboard", "203.0.113.5"],
            ["012345678901234567890", "", "", "012345678901234567890"],
        ];
        for lines in compliant.iter() {
            for (row, line) in lines.iter().enumerate() {
                assert!(
                    line_fits(line),
                    "row {row} is {} columns, the panel holds {TEXT_COLUMNS}: {line:?}",
                    line.chars().count()
                );
                assert!(
                    !centered_is_clipped(line),
                    "row {row} would be silently clipped: {line:?}"
                );
            }
            // And the rendered frame agrees with the metric: every row that
            // carries text lights at least one pixel in its own page.
            let fb = render_status(*lines);
            for (row, line) in lines.iter().enumerate() {
                assert_eq!(
                    centered_columns_rendered(line),
                    line.chars().count(),
                    "row {row} lost characters on the panel: {line:?}"
                );
                let lit = fb.page(row).iter().any(|&b| b != 0);
                assert_eq!(
                    lit,
                    !line.trim().is_empty(),
                    "page {row} lit={lit} does not match the line it was given: {line:?}"
                );
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // 4. PNG evidence renderer
    // ─────────────────────────────────────────────────────────────────────

    mod png {
        //! A dependency-free PNG writer: grayscale 8-bit, zlib with STORED
        //! deflate blocks. Test-only, so it costs the firmware nothing.

        fn crc32(data: &[u8]) -> u32 {
            let mut crc: u32 = 0xFFFF_FFFF;
            for &b in data {
                crc ^= b as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            !crc
        }

        fn adler32(data: &[u8]) -> u32 {
            let (mut a, mut b) = (1u32, 0u32);
            for &byte in data {
                a = (a + byte as u32) % 65521;
                b = (b + a) % 65521;
            }
            (b << 16) | a
        }

        fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            let mut typed = Vec::with_capacity(4 + data.len());
            typed.extend_from_slice(kind);
            typed.extend_from_slice(data);
            out.extend_from_slice(&typed);
            out.extend_from_slice(&crc32(&typed).to_be_bytes());
        }

        fn zlib_stored(raw: &[u8]) -> Vec<u8> {
            let mut out = vec![0x78, 0x01];
            let mut offset = 0usize;
            loop {
                let take = (raw.len() - offset).min(65_535);
                let final_block = offset + take >= raw.len();
                out.push(if final_block { 1 } else { 0 });
                out.extend_from_slice(&(take as u16).to_le_bytes());
                out.extend_from_slice(&(!(take as u16)).to_le_bytes());
                out.extend_from_slice(&raw[offset..offset + take]);
                offset += take;
                if final_block {
                    break;
                }
            }
            out.extend_from_slice(&adler32(raw).to_be_bytes());
            out
        }

        /// Encode an 8-bit grayscale image (row-major, `w * h` bytes).
        pub fn encode_gray(w: usize, h: usize, pixels: &[u8]) -> Vec<u8> {
            assert_eq!(pixels.len(), w * h);
            let mut raw = Vec::with_capacity(h * (w + 1));
            for row in 0..h {
                raw.push(0); // filter: None
                raw.extend_from_slice(&pixels[row * w..(row + 1) * w]);
            }

            let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
            let mut ihdr = Vec::new();
            ihdr.extend_from_slice(&(w as u32).to_be_bytes());
            ihdr.extend_from_slice(&(h as u32).to_be_bytes());
            ihdr.extend_from_slice(&[8, 0, 0, 0, 0]); // depth 8, gray, deflate, none, no interlace
            chunk(&mut png, b"IHDR", &ihdr);
            chunk(&mut png, b"IDAT", &zlib_stored(&raw));
            chunk(&mut png, b"IEND", &[]);
            png
        }
    }

    const SCALE: usize = 4;
    const MARGIN: usize = 8;
    const BACKGROUND: u8 = 0x28;
    const BEZEL: u8 = 0x70;
    const PIXEL_OFF: u8 = 0x08;
    const PIXEL_ON: u8 = 0xFF;

    /// Environment variable that redirects the harness's PNG output.
    ///
    /// Set it to collect the frames somewhere explicit, e.g. a campaign
    /// evidence folder:
    ///
    /// ```text
    /// DCENTAXE_OLED_EVIDENCE_DIR=…/projects/.axe-gauntlet/pass1/P1-I2/oled \
    ///   cargo test -p dcentaxe-core oled_render_
    /// ```
    const EVIDENCE_DIR_ENV: &str = "DCENTAXE_OLED_EVIDENCE_DIR";

    /// Where the render harness writes its PNGs and text reports.
    ///
    /// # Why this is not a path inside the repository
    ///
    /// Round 1 of lane P1-I2 pointed this at
    /// `…/projects/.axe-gauntlet/pass1/P1-I2/oled`, so an ordinary
    /// `cargo test -p dcentaxe-hal` created directories and wrote nine files
    /// into the working tree. The P1-I2 critic called that out: gitignoring the
    /// path stops `git status` noticing, but a unit test that writes into the
    /// checkout on every run is still writing into the checkout on every run.
    ///
    /// The default is therefore the CARGO TARGET directory — derived from the
    /// test binary's own location (`<target>/<triple>/<profile>/deps/…`), so it
    /// follows `CARGO_TARGET_DIR` wherever it is pointed and lands in
    /// regenerable build output rather than in source. Setting
    /// [`EVIDENCE_DIR_ENV`] overrides it for an evidence run.
    fn evidence_dir() -> std::path::PathBuf {
        let dir = match std::env::var_os(EVIDENCE_DIR_ENV) {
            Some(explicit) => std::path::PathBuf::from(explicit),
            None => std::env::current_exe()
                .ok()
                // …/deps/<test-binary> -> …/deps -> …/<profile>
                .and_then(|exe| {
                    exe.parent()
                        .and_then(|deps| deps.parent())
                        .map(std::path::Path::to_path_buf)
                })
                .unwrap_or_else(std::env::temp_dir)
                .join("oled-evidence"),
        };
        std::fs::create_dir_all(&dir).expect("create OLED evidence directory");
        dir
    }

    /// Blow the 128x32 framebuffer up to a legible grayscale image with a
    /// 1-pixel bezel so the panel edge (and therefore the clip point) is
    /// visible.
    fn frame_to_png_bytes(fb: &FrameBuffer) -> (usize, usize, Vec<u8>) {
        let pw = WIDTH * SCALE;
        let ph = HEIGHT * SCALE;
        let w = pw + 2 * MARGIN;
        let h = ph + 2 * MARGIN;
        let mut img = vec![BACKGROUND; w * h];

        // Bezel: a 2px ring just outside the panel.
        for yy in (MARGIN - 2)..(MARGIN + ph + 2) {
            for xx in (MARGIN - 2)..(MARGIN + pw + 2) {
                let inside = yy >= MARGIN && yy < MARGIN + ph && xx >= MARGIN && xx < MARGIN + pw;
                if !inside {
                    img[yy * w + xx] = BEZEL;
                }
            }
        }

        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                let shade = if fb.pixel(x, y) { PIXEL_ON } else { PIXEL_OFF };
                for dy in 0..SCALE {
                    for dx in 0..SCALE {
                        let px = MARGIN + x * SCALE + dx;
                        let py = MARGIN + y * SCALE + dy;
                        img[py * w + px] = shade;
                    }
                }
            }
        }
        (w, h, img)
    }

    fn write_frame_png(name: &str, fb: &FrameBuffer) -> std::path::PathBuf {
        let (w, h, img) = frame_to_png_bytes(fb);
        let bytes = png::encode_gray(w, h, &img);
        let path = evidence_dir().join(name);
        std::fs::write(&path, &bytes).expect("write OLED PNG");
        path
    }

    fn column_report(lines: &[&str; TEXT_ROWS]) -> String {
        let mut out = String::new();
        for (row, line) in lines.iter().enumerate() {
            let want = line.chars().count();
            let got = centered_columns_rendered(line);
            out.push_str(&format!(
                "  line{row}: {want:>3} cols requested, {got:>3} rendered, x0={:>3}{} {line:?}\n",
                centered_origin_x(line),
                if got < want { "  <-- CLIPPED" } else { "" },
            ));
        }
        out
    }

    /// Render arbitrary 4-line input to PNG and assert the 21-column budget.
    ///
    /// This is the harness the lane exists to provide: any state a caller can
    /// put on the panel is now renderable and checkable on a host.
    #[test]
    fn oled_render_status_screens_to_png() {
        let mut manifest = String::new();
        manifest.push_str(
            "DCENT_axe OLED render harness — SSD1306 128x32, 5x7 font on 6px pitch\n\
             Panel capacity: 21 columns x 4 rows. Rendered by\n\
             dcentaxe-hal/src/display_convert.rs::tests::oled_render_status_screens_to_png\n\n",
        );

        let compliant: [(&str, [&str; 4]); 4] = [
            (
                "status-mining.png",
                [
                    "DCENT_axe v0.3.0",
                    "Mining",
                    "1.21 TH/s  58C",
                    "203.0.113.5",
                ],
            ),
            (
                "status-ready.png",
                ["DCENT_axe v0.3.0", "Ready", "0.00 TH/s  41C", "203.0.113.5"],
            ),
            (
                "status-standby.png",
                ["DCENT_axe v0.3.0", "Standby", "hash cut", "203.0.113.5"],
            ),
            (
                "columns-21-exact.png",
                [
                    "012345678901234567890",
                    "WWWWWWWWWWWWWWWWWWWWW",
                    "iiiiiiiiiiiiiiiiiiiii",
                    ".....................",
                ],
            ),
        ];

        for (name, lines) in compliant.iter() {
            for (row, line) in lines.iter().enumerate() {
                assert!(
                    line_fits(line),
                    "{name} row {row} exceeds {TEXT_COLUMNS} columns: {line:?}"
                );
                assert!(
                    !centered_is_clipped(line),
                    "{name} row {row} would be silently clipped: {line:?}"
                );
            }
            let fb = render_status(*lines);
            let path = write_frame_png(name, &fb);
            assert!(path.exists());
            manifest.push_str(&format!(
                "{name}  [within budget]\n{}\n",
                column_report(lines)
            ));
        }

        // 22 columns: one glyph is dropped with no ellipsis and no error.
        let overflow = ["0123456789012345678901", "22 columns, 21 render", "", ""];
        let fb = render_status(overflow);
        write_frame_png("columns-22-overflow.png", &fb);
        assert_eq!(centered_columns_rendered(overflow[0]), TEXT_COLUMNS);
        assert!(centered_is_clipped(overflow[0]));
        manifest.push_str(&format!(
            "columns-22-overflow.png  [1 glyph dropped]\n{}\n",
            column_report(&overflow)
        ));

        // A font sheet so a reader can confirm every glyph survived the move.
        let mut sheet = FrameBuffer::new();
        let all: Vec<char> = (32u8..128u8).map(|c| c as char).collect();
        for (row, chunk) in all.chunks(21).enumerate() {
            if row >= TEXT_ROWS {
                break;
            }
            let line: String = chunk.iter().collect();
            sheet.draw_text(0, ROW_Y[row], &line);
        }
        write_frame_png("font-sheet-ascii-32-115.png", &sheet);
        manifest.push_str(
            "font-sheet-ascii-32-115.png  [first 84 of the 96 glyphs; the panel holds 4x21]\n\n",
        );

        std::fs::write(evidence_dir().join("MANIFEST.txt"), manifest).expect("write manifest");
    }

    /// The lane's headline evidence: the exact `show_status` call from
    /// `main.rs`'s fail-closed "mining disabled" screen, whose reason string
    /// is 71 characters on a 21-column panel.
    ///
    /// This asserts the DEFECT, it does not fix it — the fix (wrap, or a short
    /// code plus a dashboard pointer) is a later lane. What changes here is
    /// that the clip is now measured and rendered instead of only visible on a
    /// bench photograph.
    #[test]
    fn oled_render_mining_disabled_truncation_evidence() {
        let lines = [
            "DCENT_axe v0.3.0",
            "Mining disabled",
            "Board has no rail actuator: no enable GPIO and no commandable regulator",
            "IP: 203.0.113.5",
        ];

        let reason = lines[2];
        assert_eq!(reason.chars().count(), 71, "the reason string is 71 chars");
        assert!(
            !line_fits(reason),
            "this screen is the canonical over-budget case"
        );
        assert_eq!(
            centered_columns_rendered(reason),
            TEXT_COLUMNS,
            "the panel shows exactly the first {TEXT_COLUMNS} characters"
        );
        assert_eq!(
            reason.chars().take(TEXT_COLUMNS).collect::<String>(),
            "Board has no rail act",
            "and the operator reads a sentence that stops mid-word"
        );

        // Lines 0, 1 and 3 do fit — only the reason is lost.
        for row in [0usize, 1, 3] {
            assert!(
                line_fits(lines[row]),
                "row {row} should fit: {:?}",
                lines[row]
            );
        }

        let fb = render_status(lines);
        let path = write_frame_png("truncation-mining-disabled.png", &fb);
        assert!(path.exists(), "truncation evidence PNG must be written");

        // What the panel would have to say to stay inside the budget: proof
        // the harness can score a candidate fix without a bench unit.
        let wrapped = [
            "!! MINING DISABLED",
            "No rail actuator:",
            "no EN GPIO, no PMBus",
            "IP: 203.0.113.5",
        ];
        for (row, line) in wrapped.iter().enumerate() {
            assert!(
                line_fits(line) && !centered_is_clipped(line),
                "candidate row {row} still over budget: {line:?}"
            );
        }
        write_frame_png("truncation-candidate-wrapped.png", &render_status(wrapped));

        std::fs::write(
            evidence_dir().join("truncation-mining-disabled.txt"),
            format!(
                "OLED truncation evidence — SSD1306 128x32, 21 columns x 4 rows\n\
                 Rendered by dcentaxe-hal/src/display_convert.rs\n\
                 ::tests::oled_render_mining_disabled_truncation_evidence\n\n\
                 show_status(\n  {:?},\n  {:?},\n  {:?},\n  {:?}\n)\n\n{}\n\
                 truncation-mining-disabled.png   = what the panel shows today.\n\
                 truncation-candidate-wrapped.png = an ILLUSTRATION ONLY of a\n\
                 within-budget rewrite. It is NOT wired to any call site and no\n\
                 firmware string was changed by this lane; it exists to show the\n\
                 harness can score a candidate fix on a host, without a bench unit.\n",
                lines[0],
                lines[1],
                lines[2],
                lines[3],
                column_report(&lines)
            ),
        )
        .expect("write truncation report");
    }

    /// A written PNG is a real PNG: signature, chunk CRCs and the zlib
    /// checksum all verify. Without this the evidence could be a corrupt file
    /// nobody opened.
    #[test]
    fn the_written_png_is_structurally_valid() {
        let fb = render_status(["DCENT_axe", "self test", "png writer", "ok"]);
        let (w, h, img) = frame_to_png_bytes(&fb);
        let bytes = png::encode_gray(w, h, &img);

        assert_eq!(
            &bytes[0..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
        );

        // Walk the chunks and re-check every CRC.
        let mut pos = 8usize;
        let mut kinds: Vec<String> = Vec::new();
        while pos + 8 <= bytes.len() {
            let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            let kind = String::from_utf8(bytes[pos + 4..pos + 8].to_vec()).unwrap();
            let end = pos + 8 + len;
            let stored = u32::from_be_bytes(bytes[end..end + 4].try_into().unwrap());
            let mut crc: u32 = 0xFFFF_FFFF;
            for &b in &bytes[pos + 4..end] {
                crc ^= b as u32;
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0xEDB8_8320
                    } else {
                        crc >> 1
                    };
                }
            }
            assert_eq!(!crc, stored, "chunk {kind} CRC mismatch");
            kinds.push(kind);
            pos = end + 4;
        }
        assert_eq!(pos, bytes.len(), "trailing bytes after IEND");
        assert_eq!(kinds, vec!["IHDR", "IDAT", "IEND"]);
    }

    /// P1-O5: render the exact page-2 halving composition at every arithmetic
    /// edge named by the lane brief. Height zero intentionally draws no bar;
    /// the other three frames use only `halving_progress` output.
    #[test]
    fn oled_render_halving_progress_edges() {
        fn render(height: u32, interval: u32) -> (FrameBuffer, String, Option<(f32, u32)>) {
            let halving = halving_progress(height, interval);
            let title = match halving {
                Some((_, blocks_to_halving)) => {
                    format!("HALVING: {blocks_to_halving} LEFT")
                }
                None => "HALVING: DATA WAIT".to_string(),
            };
            assert!(line_fits(&title), "halving title clips: {title:?}");

            let mut fb = FrameBuffer::new();
            fb.draw_centered(0, &title);
            if let Some((progress, _)) = halving {
                fb.draw_progress_bar(2, 9, 80, progress);
                fb.draw_text(86, 8, &format!("{:.0}%", progress * 100.0));
            }
            fb.draw_centered(16, "Perfect Weather 58C");
            fb.draw_text(0, 24, "Fan:65% Stable");
            (fb, title, halving)
        }

        let cases = [
            ("p1-o5-halving-height-zero.png", 0, 210_000),
            ("p1-o5-halving-boundary-mainnet.png", 840_000, 210_000),
            ("p1-o5-halving-large-mainnet.png", 868_123, 210_000),
            ("p1-o5-halving-regtest.png", 151, 150),
        ];
        let mut report = String::from(
            "P1-O5 honest halving-progress frames\n\
             Source: coinbase block height + ChainId::subsidy_halving_interval()\n\
             Geometry: title row <=21 cols; bar x=2..81; percent begins x=86.\n\n",
        );

        for (name, height, interval) in cases {
            let (fb, title, halving) = render(height, interval);
            assert!(write_frame_png(name, &fb).exists());
            let bar_pixels = (2..82).any(|x| (8..16).any(|y| fb.pixel(x, y)));
            assert_eq!(
                bar_pixels,
                halving.is_some(),
                "height {height}: a bar may exist iff height truth exists"
            );
            report.push_str(&format!(
                "{name}: height={height} interval={interval} result={halving:?} \
                 title_cols={} title={title:?} bar={bar_pixels}\n",
                title.chars().count(),
            ));
        }

        std::fs::write(
            evidence_dir().join("p1-o5-halving-progress.txt"),
            report,
        )
        .expect("write P1-O5 halving report");
    }

    // -------------------------------------------------------------------
    // P1-O2: the mining truth ladder the panel shares with the dashboard
    // -------------------------------------------------------------------

    /// The resolver reproduces the web `update()` ladder for every input.
    ///
    /// This is the whole point of the lane: one function, two surfaces. If it
    /// ever stops matching the dashboard's ternary the panel starts lying, and
    /// the source contract in `dcentaxe-core` pins the ternary itself.
    #[test]
    fn resolver_matches_the_web_update_ladder() {
        // telemetry pending wins over everything - it is "unknown", not "off".
        for &enabled in &[false, true] {
            for &hashing in &[false, true] {
                assert_eq!(
                    resolve_rung(false, enabled, hashing),
                    MiningRung::TelemetryPending,
                    "no data yet must never be reported as a mining state"
                );
            }
        }
        assert_eq!(resolve_rung(true, true, true), MiningRung::Mining);
        assert_eq!(resolve_rung(true, true, false), MiningRung::Ready);
        assert_eq!(resolve_rung(true, false, true), MiningRung::Standby);
        assert_eq!(resolve_rung(true, false, false), MiningRung::Standby);
    }

    /// `ready` and `standby` must be TELLABLE APART on the panel. The old
    /// vocabulary collapsed both into `SLEEP` (page 0) / `Zzz...` (page 7).
    #[test]
    fn ready_is_distinguishable_from_standby_on_the_panel() {
        let ready = resolve_rung(true, true, false);
        let standby = resolve_rung(true, false, false);
        assert_ne!(ready, standby);
        assert_ne!(ready.panel_word(), standby.panel_word());
        assert_eq!(ready.panel_word(), "READY");
        assert_eq!(standby.panel_word(), "STANDBY");
    }

    /// Every rung's words are distinct on all three surfaces, and every panel
    /// word fits the panel on its own.
    #[test]
    fn every_rung_word_is_distinct_and_fits_the_panel() {
        let mut panel: Vec<&str> = Vec::new();
        let mut ids: Vec<&str> = Vec::new();
        for rung in MiningRung::ALL {
            let w = rung.panel_word();
            assert!(line_fits(w), "{w:?} does not fit {TEXT_COLUMNS} columns");
            assert_eq!(w, w.to_ascii_uppercase(), "the panel word is uppercase");
            assert_eq!(
                w,
                rung.web_label().to_ascii_uppercase().replace("TELEMETRY ", ""),
                "the panel word must be the web label, uppercased"
            );
            panel.push(w);
            ids.push(rung.web_state_id());
        }
        panel.sort_unstable();
        panel.dedup();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(panel.len(), MiningRung::ALL.len());
        assert_eq!(ids.len(), MiningRung::ALL.len());
    }

    /// `fit_line` is a budget guarantee, not a hope: over every rung, every
    /// decoration set and every plausible block height, the composed line fits.
    #[test]
    fn fit_line_never_exceeds_the_panel_budget() {
        let blocks = [
            "B:---",
            "B:1",
            "B:868123",
            "B:9999999",
            "B:12345678",
            "BLK:---",
            "BLK:868123",
        ];
        let decos: [&[&str]; 5] = [
            &[],
            &["HOT"],
            &["FED"],
            &["NITE"],
            &["HOT", "FED", "NITE"],
        ];
        for rung in MiningRung::ALL {
            for block in blocks {
                for deco in decos {
                    let line = fit_line(&[rung.panel_word(), block], deco, TEXT_COLUMNS);
                    assert!(
                        line_fits(&line),
                        "page-0 line over budget: {line:?} ({} cols)",
                        line.chars().count()
                    );
                    assert!(
                        line.starts_with(rung.panel_word()),
                        "the rung word must lead the line: {line:?}"
                    );
                    assert!(
                        line.contains(block),
                        "the block anchor must survive: {line:?}"
                    );
                }
                // The companion page's narrower activity slot.
                for deco in decos {
                    let line = fit_line(&[rung.panel_word()], deco, PAGE7_ACTIVITY_COLUMNS);
                    assert!(
                        line.chars().count() <= PAGE7_ACTIVITY_COLUMNS,
                        "page-7 activity over its {PAGE7_ACTIVITY_COLUMNS}-column slot: {line:?}"
                    );
                    assert!(line.starts_with(rung.panel_word()));
                }
            }
        }
    }

    /// An over-budget `required` part is returned unchanged rather than
    /// silently mangled, and no decoration is added on top of it.
    #[test]
    fn fit_line_does_not_make_an_already_over_budget_line_worse() {
        let long = "0123456789012345678901234";
        let out = fit_line(&[long], &["HOT"], TEXT_COLUMNS);
        assert_eq!(out, long);
    }

    /// The columns available to page 7's `activity` slot in the pet-room
    /// layout: `draw_text(22, 25, activity)` with `draw_text(90, 24, watts)`
    /// to its right, so (90 - 22) / 6 = 11 characters.
    const PAGE7_ACTIVITY_COLUMNS: usize = 11;

    /// Page-0 / page-7 geometry transcribed from `dcentaxe/src/main.rs`'s
    /// carousel arms, so the harness renders what the firmware renders.
    ///
    /// The pixel-art sprite and the hashrate sparkline are drawn by `main.rs`
    /// from tables that live in that binary crate; here their FOOTPRINT is
    /// outlined so the frame shows how much room the text really has, without
    /// pretending to reproduce the art. Every text row is composed by the SAME
    /// shared helpers the firmware calls ([`resolve_rung`] + [`fit_line`]) -
    /// that join is what the `dcentaxe-core` source contract pins.
    fn render_page0(rung: MiningRung, hr: &str, temp: &str, deco: &[&str], block: &str) -> FrameBuffer {
        let mut fb = FrameBuffer::new();
        // sprite footprint: draw_bitmap(0, 0, active_sprite, 8, 8)
        fb.draw_hline(0, 0, 8);
        fb.draw_hline(0, 7, 8);
        fb.draw_vline(0, 0, 8);
        fb.draw_vline(7, 0, 8);
        fb.draw_text(10, 0, &format!("{hr} {temp}"));
        // sparkline footprint: draw_sparkline(0, 8, &norm, 2) = 32 px wide
        fb.draw_hline(0, 15, 32);
        fb.draw_text(36, 8, "12.5W 21J/T");
        fb.draw_text(0, 16, "OK:142 ER:0 d:9.1M");
        fb.draw_text(0, 24, &fit_line(&[rung.panel_word(), block], deco, TEXT_COLUMNS));
        fb
    }

    fn render_page7_full(rung: MiningRung, hr: &str, temp: &str, deco: &[&str], block: &str) -> FrameBuffer {
        let mut fb = FrameBuffer::new();
        // creature footprint: draw_bitmap_2x(0, 0, creature_sprite, 16, 16) = 32x32
        fb.draw_hline(0, 0, 32);
        fb.draw_hline(0, 31, 32);
        fb.draw_vline(0, 0, 32);
        fb.draw_vline(31, 0, 32);
        fb.draw_text(36, 0, "Axel");
        // main.rs fits this against the TIGHTER pet-room slot (11), not the
        // 15 columns available here, so the word does not change width when
        // the layout flips. The harness must do the same or it is not
        // rendering what the firmware renders.
        fb.draw_text(36, 8, &fit_line(&[rung.panel_word()], deco, PAGE7_ACTIVITY_COLUMNS));
        fb.draw_text(36, 16, &format!("{hr} {temp}"));
        fb.draw_text(36, 24, block);
        fb
    }

    /// `draw_text(36, 8, activity)` on a 128 px panel: (128 - 36) / 6 = 15.
    /// Headroom only - `main.rs` composes against [`PAGE7_ACTIVITY_COLUMNS`].
    const PAGE7_FULL_ACTIVITY_COLUMNS: usize = 15;

    /// The lane's headline evidence: page 0 and page 7 rendered in the
    /// `mining`, `ready` and `standby` scenarios, with the 21-column check per
    /// line, so the panel's words can be put beside the dashboard probe's.
    #[test]
    fn oled_render_truth_ladder_pages() {
        let scenarios: [(&str, MiningRung, &str, &str, &[&str]); 3] = [
            ("mining", resolve_rung(true, true, true), "1.21T", "58C", &["FED"]),
            ("ready", resolve_rung(true, true, false), "0.00", "41C", &[]),
            ("standby", resolve_rung(true, false, false), "0.00", "--C", &[]),
        ];

        let mut report = String::new();
        report.push_str(
            "DCENT_axe OLED truth-ladder evidence - SSD1306 128x32, 21 cols x 4 rows\n\
             Rendered by dcentaxe-hal/src/display_convert.rs\n\
             ::tests::oled_render_truth_ladder_pages\n\n\
             Every state word below comes from the SAME resolve_rung()/fit_line()\n\
             the firmware carousel calls; the sprite and sparkline areas are drawn\n\
             as outlines (their art lives in dcentaxe/src/main.rs), so the frames\n\
             show the real text budget without faking the pixel art.\n\n",
        );

        for (name, rung, hr, temp, deco) in scenarios {
            let block = if rung == MiningRung::Standby {
                "B:---"
            } else {
                "B:868123"
            };

            let p0_line3 = fit_line(&[rung.panel_word(), block], deco, TEXT_COLUMNS);
            let p7_line1 = fit_line(&[rung.panel_word()], deco, PAGE7_ACTIVITY_COLUMNS);
            let p7_room = fit_line(&[rung.panel_word()], deco, PAGE7_ACTIVITY_COLUMNS);

            let page0 = [
                format!("{hr} {temp}").to_string(),
                "12.5W 21J/T".to_string(),
                "OK:142 ER:0 d:9.1M".to_string(),
                p0_line3.clone(),
            ];
            let page7 = [
                "Axel".to_string(),
                p7_line1.clone(),
                format!("{hr} {temp}"),
                block.to_string(),
            ];

            for (label, lines) in [("page0", &page0), ("page7", &page7)] {
                for (row, line) in lines.iter().enumerate() {
                    assert!(
                        line_fits(line),
                        "{name}/{label} row {row} exceeds {TEXT_COLUMNS} columns: {line:?}"
                    );
                }
            }
            assert!(
                p7_room.chars().count() <= PAGE7_ACTIVITY_COLUMNS,
                "{name} page7 pet-room activity over budget: {p7_room:?}"
            );
            assert!(
                PAGE7_ACTIVITY_COLUMNS <= PAGE7_FULL_ACTIVITY_COLUMNS,
                "the shared companion budget must fit BOTH layouts"
            );
            assert_eq!(
                p7_line1, p7_room,
                "the companion word must not change when the layout flips"
            );
            // The rung word is present, verbatim, on both pages.
            assert!(p0_line3.contains(rung.panel_word()));
            assert!(p7_line1.contains(rung.panel_word()));
            assert!(p7_room.contains(rung.panel_word()));

            write_frame_png(
                &format!("p1-o2-page0-{name}.png"),
                &render_page0(rung, hr, temp, deco, block),
            );
            write_frame_png(
                &format!("p1-o2-page7-{name}.png"),
                &render_page7_full(rung, hr, temp, deco, block),
            );

            report.push_str(&format!(
                "scenario {name}: rung={:?} panel_word={:?} web_state_id={:?} web_label={:?}\n\
                 \x20 page0 row3        : {:>2} cols  {:?}\n\
                 \x20 page7 activity    : {:>2} cols  {:?}  (full-pet slot has 15)\n\
                 \x20 page7 pet-room    : {:>2} cols  {:?}  (pet-room slot has 11)\n\
                 \x20 files             : p1-o2-page0-{name}.png, p1-o2-page7-{name}.png\n\n",
                rung,
                rung.panel_word(),
                rung.web_state_id(),
                rung.web_label(),
                p0_line3.chars().count(),
                p0_line3,
                p7_line1.chars().count(),
                p7_line1,
                p7_room.chars().count(),
                p7_room,
            ));
        }

        // The three scenarios must land on three DIFFERENT words - the defect
        // this lane exists to fix was ready and standby reading the same.
        let words: Vec<&str> = scenarios
            .iter()
            .map(|(_, rung, _, _, _)| rung.panel_word())
            .collect();
        let mut uniq = words.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), 3, "mining/ready/standby must read differently: {words:?}");

        std::fs::write(evidence_dir().join("p1-o2-truth-ladder.txt"), report)
            .expect("write truth-ladder report");
    }

    // -------------------------------------------------------------------
    // P1-O2 round 2: the boot/init screens, the flipped panel, and the one
    // shared decoration table (critic findings 1, 2, 3, 6 and 7).
    // -------------------------------------------------------------------

    /// The panel's own 180-degree flip, modelled on the host.
    ///
    /// `Ssd1306Display::set_flip` writes `0xA1` (segment re-map: column 127
    /// becomes SEG0) and `0xC8` (COM output scan direction remapped). Together
    /// they rotate the raster by 180 degrees INSIDE the panel: the framebuffer
    /// the firmware composes is byte-identical either way, which is why a
    /// flipped unit can be reasoned about here instead of only on a bench.
    /// The transform is test-only on purpose - shipping it would add code to
    /// every image for a rotation the SSD1306 performs in hardware for free.
    fn flip_180(fb: &FrameBuffer) -> FrameBuffer {
        let mut out = FrameBuffer::new();
        for y in 0..HEIGHT {
            for x in 0..WIDTH {
                if fb.pixel(x, y) {
                    out.set_pixel(WIDTH - 1 - x, HEIGHT - 1 - y, true);
                }
            }
        }
        out
    }

    /// Row 0 of every boot/init screen: `format!("DCENT_axe v{}", VERSION)`.
    // Lead fix at merge (blind critic P1-O2 round 2): derived, not a literal a release bump would
    // silently outdate; the workspace version is the same one main.rs prints as `VERSION`.
    const HARNESS_VERSION_ROW: &str = concat!("DCENT_axe v", env!("CARGO_PKG_VERSION"));

    /// The four rung-bearing boot/init screens, with row 1 composed by the
    /// SAME [`rung_status_line`] the firmware calls.
    fn init_screens() -> Vec<(&'static str, [String; TEXT_ROWS])> {
        let ip = "IP: 203.0.113.5".to_string();
        vec![
            (
                "p1-o2-r2-boot.png",
                [
                    HARNESS_VERSION_ROW.to_string(),
                    "D-Central Tech.".to_string(),
                    rung_status_line(MiningRung::TelemetryPending.panel_word(), "no telemetry"),
                    "Booting...".to_string(),
                ],
            ),
            (
                "p1-o2-r2-init-ready-chips-ok.png",
                [
                    HARNESS_VERSION_ROW.to_string(),
                    rung_status_line(MiningRung::Ready.panel_word(), &format!("{} chips OK", 6)),
                    ip.clone(),
                    "Connecting to pool...".to_string(),
                ],
            ),
            (
                "p1-o2-r2-init-standby-asic-failed.png",
                [
                    HARNESS_VERSION_ROW.to_string(),
                    rung_status_line(MiningRung::Standby.panel_word(), "ASIC FAILED"),
                    ip.clone(),
                    "Dashboard active".to_string(),
                ],
            ),
            (
                "p1-o2-r2-init-standby-disabled.png",
                [
                    // P1-O1 rebuilt this screen. It used to be
                    // [version, rung, raw mining_block_reason, IP] and row 2
                    // over-ran the panel every time — 29 of 29 reasons clipped.
                    // It is now [rung, "!! CODE", action, IP], every row bounded
                    // by construction, so the version row moves off THIS screen
                    // (only) to buy the operator a next step. The fixture
                    // follows the firmware; it is not a museum piece, and the
                    // clipped shape is still rendered as `before` evidence by
                    // `oled_render_fail_closed_reason_screens`.
                    rung_status_line(MiningRung::Standby.panel_word(), "disabled"),
                    crate::block_reason::code_row(
                        crate::block_reason::BlockReason::RailNoActuator,
                        0,
                    ),
                    crate::block_reason::BlockReason::RailNoActuator
                        .action()
                        .to_string(),
                    ip,
                ],
            ),
        ]
    }

    /// Critic finding 3: the four boot/init screens this lane re-worded, plus
    /// the flipped boot frame, RENDERED rather than only asserted about.
    #[test]
    fn oled_render_boot_and_init_screens() {
        let mut report = String::new();
        report.push_str(
            "DCENT_axe OLED - P1-O2 round 2 boot/init evidence\n\
             SSD1306 128x32, 5x7 font on 6px pitch: 21 columns x 4 rows.\n\
             Rendered by dcentaxe-hal/src/display_convert.rs\n\
             ::tests::oled_render_boot_and_init_screens\n\n\
             Row 1 of every frame is composed by rung_status_line(), the same\n\
             bounded composer main.rs calls; the other rows are the firmware's\n\
             own literals for that screen.\n\n",
        );

        for (name, lines) in init_screens() {
            let refs: [&str; TEXT_ROWS] = [&lines[0], &lines[1], &lines[2], &lines[3]];
            let fb = render_status(refs);
            let path = write_frame_png(name, &fb);
            assert!(path.exists());
            let clipped = refs.iter().any(|l| centered_is_clipped(l));
            report.push_str(&format!(
                "{name}  [{}]\n{}\n",
                if clipped {
                    "A ROW IS CLIPPED - see the row marked CLIPPED below"
                } else {
                    "within budget"
                },
                column_report(&refs)
            ));
            // Row 1 is the rung line, the only row this lane owns. It must
            // never be the row that gets clipped.
            assert!(
                !centered_is_clipped(refs[1]),
                "{name}: the rung line is clipped: {:?}",
                refs[1]
            );
        }

        // The flipped boot frame: same composition, panel rotated 180 degrees.
        let boot = init_screens().remove(0).1;
        let refs: [&str; TEXT_ROWS] = [&boot[0], &boot[1], &boot[2], &boot[3]];
        let flipped = flip_180(&render_status(refs));
        write_frame_png("p1-o2-r2-boot-flipped.png", &flipped);
        report.push_str(
            "p1-o2-r2-boot-flipped.png  [the boot frame above, panel rotated\n\
             \x20 180 deg by SSD1306 commands 0xA1 + 0xC8. The framebuffer is\n\
             \x20 unchanged, so every column count above holds on a flipped unit.\n\
             \x20 Note the ordering defect this makes visible and does NOT fix:\n\
             \x20 main.rs applies set_flip AFTER the boot frames, so a flipped\n\
             \x20 unit shows these frames the wrong way up - lane P1-O1's rider.]\n\n",
        );

        std::fs::write(evidence_dir().join("p1-o2-r2-init-screens.txt"), report)
            .expect("write init-screen report");
    }

    /// P1-O1: EVERY fail-closed reason, rendered.
    ///
    /// The lane's whole claim is "no operator ever sees a clipped refusal
    /// again", and the only way to show that is to draw all of them. This
    /// renders the composed screen for every [`crate::block_reason::BlockReason`]
    /// — plus the counted variant at its widest, the flipped case, and the
    /// pre-lane clipped shape as `before` evidence — and writes `MANIFEST.txt`
    /// with the per-row column counts for the lot.
    #[test]
    fn oled_render_fail_closed_reason_screens() {
        use crate::block_reason::{blocked_screen, BlockReason};

        fn slug(code: &str) -> String {
            code.chars()
                .map(|c| match c {
                    'A'..='Z' | '0'..='9' => c.to_ascii_lowercase(),
                    _ => '-',
                })
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        }

        let ip = "203.0.113.42";
        let rung = rung_status_line(MiningRung::Standby.panel_word(), "disabled");
        let mut manifest = String::new();
        manifest.push_str(
            "DCENT_axe OLED - P1-O1 fail-closed reason evidence\n\
             SSD1306 128x32, 5x7 font on 6px pitch: 21 columns x 4 rows.\n\
             Rendered by dcentaxe-hal/src/display_convert.rs\n\
             ::tests::oled_render_fail_closed_reason_screens\n\n\
             Screen shape: [rung] [!! CODE] [action] [IP]. Rows 1-3 are composed\n\
             by block_reason::{code_row, action, ip_row}; row 0 by the same\n\
             rung_status_line() main.rs calls. `rendered` below is what\n\
             draw_centered + draw_text actually put on the glass.\n\n",
        );

        let mut frames: Vec<(String, [String; TEXT_ROWS])> = Vec::new();
        for reason in BlockReason::ALL {
            let name = format!("p1-o1-blocked-{}.png", slug(reason.code()));
            frames.push((name, blocked_screen(&rung, reason, 3, ip)));
        }
        // The one variant that interpolates a number, at its widest: 21 of 21
        // columns exactly, which is why the guard proves it rather than
        // sampling it.
        frames.push((
            "p1-o1-blocked-safe-mode-wdt-x255.png".to_string(),
            blocked_screen(&rung, BlockReason::SafeModeWdt, 255, "255.255.255.255"),
        ));
        // An address the row cannot hold: DROPPED whole, never truncated into
        // something an operator would type.
        frames.push((
            "p1-o1-blocked-address-too-long.png".to_string(),
            blocked_screen(&rung, BlockReason::RailNoActuator, 0, "2001:db8::1234:5678"),
        ));

        let mut clipped_rows = 0usize;
        for (name, lines) in &frames {
            let refs: [&str; TEXT_ROWS] = [&lines[0], &lines[1], &lines[2], &lines[3]];
            let fb = render_status(refs);
            assert!(write_frame_png(name, &fb).exists());
            for line in refs.iter() {
                if centered_is_clipped(line) {
                    clipped_rows += 1;
                }
            }
            manifest.push_str(&format!("{name}\n{}\n", column_report(&refs)));
        }
        assert_eq!(
            clipped_rows, 0,
            "{clipped_rows} rows of the fail-closed evidence set are clipped — \
             the lane's entire claim is that this number is zero"
        );

        // The flipped case: same framebuffer, panel rotated 180 degrees, so
        // every column count above holds on a flipped unit too.
        let flipped_src = blocked_screen(&rung, BlockReason::RailNoActuator, 0, ip);
        let refs: [&str; TEXT_ROWS] = [
            &flipped_src[0],
            &flipped_src[1],
            &flipped_src[2],
            &flipped_src[3],
        ];
        write_frame_png(
            "p1-o1-blocked-rail-no-actuator-flipped.png",
            &flip_180(&render_status(refs)),
        );
        manifest.push_str(
            "p1-o1-blocked-rail-no-actuator-flipped.png  [the frame above,\n\
             \x20 rotated 180 deg by SSD1306 0xA1 + 0xC8; framebuffer unchanged]\n\n",
        );

        // BEFORE: the same refusal as the firmware drew it until this lane.
        // Line 2 requests 71 columns and renders 21: `Board has no rail act`.
        let before: [&str; TEXT_ROWS] = [
            HARNESS_VERSION_ROW,
            &rung,
            "Board has no rail actuator: no enable GPIO and no commandable regulator",
            "IP: 203.0.113.42",
        ];
        write_frame_png("p1-o1-before-clipped-reason.png", &render_status(before));
        assert!(
            centered_is_clipped(before[2]),
            "the `before` frame is supposed to demonstrate the clip"
        );
        manifest.push_str(&format!(
            "p1-o1-before-clipped-reason.png  [BEFORE this lane: the raw\n\
             \x20 mining_block_reason on row 2, and no action row at all]\n{}\n",
            column_report(&before)
        ));

        std::fs::write(evidence_dir().join("MANIFEST.txt"), manifest).expect("write manifest");
    }

    /// Critic finding 6: page 0 and page 7 decorate the same tick the same
    /// way now. This pair is a NITE tick - before round 2 page 0 showed `NITE`
    /// and the companion page showed nothing at all.
    #[test]
    fn oled_render_decoration_alignment() {
        let rung = resolve_rung(true, true, true);
        let deco = rung_decoration(false, false, false, true);
        assert_eq!(deco, &["NITE"][..], "a night tick decorates with NITE");

        let p0 = render_page0(rung, "1.21T", "58C", deco, "B:868123");
        let p7 = render_page7_full(rung, "1.21T", "58C", deco, "B:868123");
        write_frame_png("p1-o2-r2-page0-night-deco.png", &p0);
        write_frame_png("p1-o2-r2-page7-night-deco.png", &p7);

        let row3 = fit_line(&[rung.panel_word(), "B:868123"], deco, TEXT_COLUMNS);
        let pet = fit_line(&[rung.panel_word()], deco, PAGE7_ACTIVITY_COLUMNS);
        assert_eq!(row3, "MINING B:868123 NITE");
        assert_eq!(pet, "MINING NITE");
        assert!(line_fits(&row3));
        assert!(pet.chars().count() <= PAGE7_ACTIVITY_COLUMNS);

        std::fs::write(
            evidence_dir().join("p1-o2-r2-decoration-alignment.txt"),
            format!(
                "P1-O2 round 2 - ONE decoration table, both pages, same tick\n\n\
                 inputs : too_hot=false share_flash=false achievement_flash=false night=true\n\
                 table  : rung_decoration(..) -> {deco:?}\n\n\
                 page0 row3     : {:>2} cols  {row3:?}\n\
                 \x20                  file p1-o2-r2-page0-night-deco.png\n\
                 page7 activity : {:>2} cols  {pet:?}\n\
                 \x20                  file p1-o2-r2-page7-night-deco.png\n\n\
                 Before round 2 the companion page had no night arm at all, so\n\
                 this same tick rendered page0 \"MINING B:868123 NITE\" beside a\n\
                 bare page7 \"MINING\".\n",
                row3.chars().count(),
                pet.chars().count(),
            ),
        )
        .expect("write decoration alignment report");
    }

    /// [`rung_status_line`] is a guarantee, not a hope: for every rung and
    /// every detail - including absurd ones - the result fits the panel, is
    /// not clipped by `draw_text`, and still leads with the rung word.
    #[test]
    fn rung_status_line_can_never_overflow_or_lose_the_rung() {
        let long = "x".repeat(1000);
        let details: [&str; 9] = [
            "",
            "no telemetry",
            "disabled",
            "ASIC FAILED",
            "0 chips OK",
            "255 chips OK",
            "disabled by safety",
            "Board has no rail actuator: no enable GPIO and no commandable regulator",
            &long,
        ];
        for rung in MiningRung::ALL {
            for detail in details {
                let line = rung_status_line(rung.panel_word(), detail);
                assert!(
                    line_fits(&line),
                    "{rung:?} + {detail:?} overflows: {line:?} ({} cols)",
                    line.chars().count()
                );
                assert!(
                    line.starts_with(rung.panel_word()),
                    "the rung word must lead the line: {line:?}"
                );
                assert!(
                    !centered_is_clipped(&line),
                    "draw_text would silently clip {line:?}"
                );
                let whole_fits =
                    rung.panel_word().chars().count() + 2 + detail.chars().count() <= TEXT_COLUMNS;
                if !detail.is_empty() && whole_fits {
                    assert!(line.ends_with(detail), "a detail that fits is kept whole");
                } else {
                    assert_eq!(
                        line,
                        rung.panel_word(),
                        "a detail that cannot fit is dropped whole, never halved"
                    );
                }
            }
        }
    }

    /// The four concrete boot/init lines, for every chip count a `u8` can
    /// report, with the two tightest widths pinned so a reword is a decision.
    #[test]
    fn the_four_rung_bearing_init_screens_fit_the_panel() {
        let mut lines = vec![
            rung_status_line(MiningRung::TelemetryPending.panel_word(), "no telemetry"),
            rung_status_line(MiningRung::Standby.panel_word(), "ASIC FAILED"),
            rung_status_line(MiningRung::Standby.panel_word(), "disabled"),
        ];
        for n in 0u16..=255 {
            lines.push(rung_status_line(
                MiningRung::Ready.panel_word(),
                &format!("{n} chips OK"),
            ));
        }
        for line in &lines {
            assert!(
                line_fits(line),
                "{line:?} needs {} of {TEXT_COLUMNS} columns",
                line.chars().count()
            );
            assert!(!centered_is_clipped(line));
        }
        assert_eq!(
            rung_status_line(MiningRung::TelemetryPending.panel_word(), "no telemetry")
                .chars()
                .count(),
            TEXT_COLUMNS,
            "the boot line sits exactly ON the budget: it degrades to PENDING \
             rather than clipping, but any longer detail would vanish entirely"
        );
        assert_eq!(
            rung_status_line(MiningRung::Standby.panel_word(), "ASIC FAILED")
                .chars()
                .count(),
            20
        );
    }

    /// One table, four inputs, at most one answer, urgency order - and no
    /// decoration can ever displace a rung word.
    #[test]
    fn rung_decoration_is_one_table_with_a_single_answer() {
        for hot in [false, true] {
            for fed in [false, true] {
                for wow in [false, true] {
                    for night in [false, true] {
                        let d = rung_decoration(hot, fed, wow, night);
                        assert!(d.len() <= 1, "at most one decoration: {d:?}");
                        let expect: &[&str] = if hot {
                            &["HOT"]
                        } else if fed {
                            &["FED"]
                        } else if wow {
                            &["WOW"]
                        } else if night {
                            &["NITE"]
                        } else {
                            &[]
                        };
                        assert_eq!(d, expect);
                        for rung in MiningRung::ALL {
                            let wide = fit_line(&[rung.panel_word()], d, TEXT_COLUMNS);
                            let narrow =
                                fit_line(&[rung.panel_word()], d, PAGE7_ACTIVITY_COLUMNS);
                            assert!(wide.starts_with(rung.panel_word()));
                            assert!(narrow.starts_with(rung.panel_word()));
                            assert!(line_fits(&wide));
                            assert!(narrow.chars().count() <= PAGE7_ACTIVITY_COLUMNS);
                        }
                    }
                }
            }
        }
    }

    /// Critic finding 7, pinned as a DECISION rather than left an accident: at
    /// an 8-digit block height the decorated page-0 line needs 22 of 21
    /// columns, so the decoration is what goes. That is the intended trade -
    /// the rung and the block anchor are data, `HOT` is flavour - and the
    /// thermal condition it hints at is on page 0 row 0 as a real temperature
    /// and on the urgent notification screens regardless.
    #[test]
    fn an_eight_digit_block_height_drops_the_decoration_not_the_rung() {
        let rung = resolve_rung(true, false, false);
        let block = "B:12345678";
        assert_eq!(rung.panel_word(), "STANDBY");
        assert_eq!(
            rung.panel_word().len() + 1 + block.len() + 1 + "HOT".len(),
            22,
            "the decorated line would need 22 of 21 columns"
        );
        let line = fit_line(&[rung.panel_word(), block], &["HOT"][..], TEXT_COLUMNS);
        assert_eq!(line, "STANDBY B:12345678");
        assert!(line_fits(&line));
        // One digit shorter and the decoration is taken again: nothing here
        // depends on a special case, only on the budget.
        let ok = fit_line(&[rung.panel_word(), "B:8681234"], &["HOT"][..], TEXT_COLUMNS);
        assert_eq!(ok, "STANDBY B:8681234 HOT");
        assert!(line_fits(&ok));
    }
}
