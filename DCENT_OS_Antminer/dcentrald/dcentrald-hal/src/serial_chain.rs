//! Serial-based hash chain transport for ASIC communication.
//!
//! Provides an interface parallel to `FpgaChain` but using a standard Linux
//! serial port (NS16550A UART) instead of FPGA register FIFOs. This is used in
//! two scenarios:
//!
//!   1. **Zynq S19 hybrid mode:** PL UARTs (ttyS1-4) handle ASIC commands,
//!      while the FPGA UIO work engine handles work-tx/work-rx separately.
//!      In this mode, only the command path goes through SerialChainBackend;
//!      work dispatch still uses FpgaChain's work_tx/work_rx UIO devices.
//!
//!   2. **Pure serial platforms** (Amlogic, BeagleBone): Commands AND work
//!      share the same serial port. The protocol preamble distinguishes them.
//!
//! ## Protocol Framing
//!
//! Unlike the FPGA cmd FIFO which strips/adds preamble and CRC automatically,
//! the serial port requires software to handle the full wire protocol:
//!
//!   Command (host -> ASIC): [0x55] [0xAA] [header] [length] [payload...] [CRC5]
//!   Response (ASIC -> host): [0xAA] [0x55] [chip-specific body]
//!
//! ## Response formats
//!
//! Generic BM1397/BM1398-family handling uses a 9-byte wire response
//! (`AA 55` + 7-byte body):
//!   [0xAA] [0x55] [raw nonce bytes x4] [midstate_idx] [job_id] [crc5+flags]
//!
//! S19k/BM1366 uses an 11-byte wire response (`AA 55` + 9-byte body):
//!   [0xAA] [0x55] [raw nonce/value bytes x4] [midstate/address]
//!   [job/register] [version bytes x2] [crc5+flags]
//! The effective Braiins header/submission nonce is reconstructed by the
//! protocol layer; these raw bytes are not labelled network-order here.
//!
//! BM1387 sends 7-byte responses:
//!   [0xAA] [0x55] [raw nonce bytes x4] [crc5+addr]
//!
//! The response length is chip-dependent and must be set via `set_response_len()`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use crate::serial::{pl_uart_assert_mcr_out2, pl_uart_diag_registers, DevmemUart, SerialChain};
use crate::{HalError, Result};

#[path = "serial_chain_tx_observation.rs"]
mod tx_observation;

// ---------------------------------------------------------------------------
// UART backend abstraction — file-based (/dev/ttyS*) or devmem (/dev/mem)
// ---------------------------------------------------------------------------

/// UART backend: either kernel driver or direct register access.
enum UartBackend {
    /// Kernel serial driver (/dev/ttyS*). Works when no IRQ conflict.
    File(SerialChain),
    /// Direct register access via /dev/mem. Bypasses kernel driver.
    /// Used on S19j Pro where IRQ conflicts break the kernel driver.
    Devmem(DevmemUart),
}

impl UartBackend {
    fn kind_label(&self) -> &'static str {
        match self {
            UartBackend::File(_) => "serial-kernel-uart",
            UartBackend::Devmem(_) => "serial-devmem-uart",
        }
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<()> {
        match self {
            UartBackend::File(s) => s.write_bytes(data),
            UartBackend::Devmem(d) => d.write_bytes(data),
        }
    }

    fn read_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            UartBackend::File(s) => s.read_bytes(buf),
            UartBackend::Devmem(d) => Ok(d.read_bytes(buf)),
        }
    }

    fn set_baud(&mut self, baud: u32) -> Result<()> {
        match self {
            UartBackend::File(s) => s.set_baud(baud),
            UartBackend::Devmem(d) => d.set_baud(baud),
        }
    }

    fn drain_tx(&mut self) -> Result<()> {
        match self {
            UartBackend::File(s) => s.flush(),
            UartBackend::Devmem(d) => {
                d.drain_tx();
                Ok(())
            }
        }
    }

    fn flush_io(&mut self) -> Result<()> {
        match self {
            UartBackend::File(s) => s.flush_io(),
            UartBackend::Devmem(d) => {
                d.flush_io();
                Ok(())
            }
        }
    }

    fn flush_rx(&mut self) -> Result<()> {
        match self {
            UartBackend::File(serial) => serial.flush_rx(),
            UartBackend::Devmem(serial) => serial.flush_rx(),
        }
    }

    fn baud(&self) -> u32 {
        match self {
            UartBackend::File(s) => s.baud(),
            UartBackend::Devmem(d) => d.baud(),
        }
    }

    fn path(&self) -> &str {
        match self {
            UartBackend::File(s) => s.path(),
            UartBackend::Devmem(d) => d.path(),
        }
    }

    fn diagnostic_registers(&self) -> Option<(u32, u32, u32)> {
        match self {
            // BLK-1b: the kernel File backend can't report its own registers, so
            // read them via a one-shot /dev/mem map (forensics; OBSERVE OUT2).
            UartBackend::File(s) => pl_uart_diag_registers(s.path()),
            UartBackend::Devmem(d) => Some(d.diagnostic_registers()),
        }
    }

    /// Assert MCR OUT2 on the chain UART (BLK-1b). On the kernel `of_serial`
    /// backend this pokes `MCR=0x0B` via `/dev/mem` for `a lab unit`-fingerprint units
    /// (the FPGA UART TX-clock gate the kernel path never asserts). On the
    /// devmem backend OUT2 is already written at open, so this is a no-op.
    fn assert_mcr_out2(&self) -> Result<Option<(u32, u32)>> {
        match self {
            UartBackend::File(s) => {
                // F2 (DCENT_FPGA): TIOCMBIS FIRST so OUT2 enters the kernel port->mctrl
                // shadow and survives any later termios op; then the /dev/mem poke
                // guarantees the bit is set NOW and reads it back to OBSERVE. Both are
                // self-gated to `a lab unit` — no-op on every other unit. TIOCMBIS is also the
                // matrix's zero-AC "does the kernel honor OUT2" probe, captured for free.
                if let Err(e) = s.set_modem_dtr_rts_out2() {
                    tracing::warn!(
                        error = %e,
                        "TIOCMBIS(DTR|RTS|OUT2) failed (kernel may mask OUT2) — devmem poke will still set it"
                    );
                }
                pl_uart_assert_mcr_out2(s.path())
            }
            UartBackend::Devmem(_) => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Command preamble (host -> ASIC).
const CMD_PREAMBLE: [u8; 2] = [0x55, 0xAA];

/// Response preamble (ASIC -> host).
const RESP_PREAMBLE: [u8; 2] = [0xAA, 0x55];

/// Maximum command frame size (preamble + header + length + 8 payload + CRC).
#[allow(dead_code)]
const MAX_CMD_FRAME: usize = 16;

/// Maximum response frame size (preamble + 9-byte BM1366 body).
#[allow(dead_code)]
const MAX_RESP_FRAME: usize = 11;

/// Default response body length (after preamble). Generic BM139X body 7.
/// : this default is **not** the BM1366 UART body. S19k/BM1366
/// must use [`BM1366_UART_RESP_BODY_LEN`] (9) so the wire is 11 bytes.
const DEFAULT_RESP_BODY_LEN: usize = 7;

/// BM139X response body length (after preamble).
pub const BM139X_RESP_BODY_LEN: usize = 7;

/// BM1366 UART body after `AA 55` (ESP 11-byte wire). Do **not** pass
/// [`crate` wire total 11] into `set_response_len` as a body.
pub const BM1366_UART_RESP_BODY_LEN: usize = 9;

/// BM1387 response body length (after preamble).
pub const BM1387_RESP_BODY_LEN: usize = 5;

/// Read timeout for command responses (ms).
const CMD_RESPONSE_TIMEOUT_MS: u64 = 500;

/// Read timeout for nonce polling (ms). Short for tight mining loop.
const NONCE_POLL_TIMEOUT_MS: u64 = 10;

// ---------------------------------------------------------------------------
// CRC-5 (must match protocol.rs, duplicated here to avoid circular dep)
// ---------------------------------------------------------------------------

/// Calculate CRC-5 for command packets.
/// Polynomial: 0x05, initial value: 0x1F.
fn crc5(data: &[u8]) -> u8 {
    let mut crc: u8 = 0x1F;
    for &byte in data {
        for i in (0..8).rev() {
            let bit = (byte >> i) & 1;
            let crc_bit = (crc >> 4) & 1;
            crc <<= 1;
            if bit ^ crc_bit != 0 {
                crc ^= 0x05;
            }
            crc &= 0x1F;
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// SerialChainBackend
// ---------------------------------------------------------------------------

/// Serial-based hash chain transport.
///
/// Wraps a `SerialChain` (raw serial port) with ASIC protocol framing:
/// preamble insertion, CRC computation, response parsing, and frame assembly.
///
/// Thread-safe: the inner serial port is wrapped in a Mutex so multiple
/// threads (e.g., heartbeat thread + mining thread) can share access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialRxObservation {
    /// Bytes returned by the OS/UART backend to the framed response path.
    pub wire_bytes: u64,
    /// Complete response frames accepted by the response assembler.
    pub framed_responses: u64,
    /// Complete BM1366-shaped candidates rejected by the full-frame CRC5
    /// remainder gate before they could reach protocol consumers.
    pub crc_rejected_frames: u64,
    /// Bytes currently retained while waiting for a complete frame.
    pub buffered_bytes: usize,
}

pub struct SerialChainBackend {
    /// UART backend (thread-safe via Mutex). Either file-based or devmem.
    serial: Mutex<UartBackend>,
    /// Chain ID for logging.
    chain_id: u8,
    /// Expected response body length (after preamble), chip-dependent.
    /// 5 bytes for BM1387, 7 bytes for BM139X. `AtomicUsize` so the
    /// `Bm1397PlusChainBackend` trait setter can take `&self`.
    resp_body_len: AtomicUsize,
    /// Circular receive buffer for response frame assembly.
    /// Protected by the same mutex as serial (accessed together).
    /// Stored separately to allow partial frame accumulation across reads.
    rx_buf: Mutex<RxBuffer>,
    /// Bounded budget for logging raw RX that did not assemble into a frame.
    rx_unframed_log_budget: AtomicU32,
    /// Bounded budget for logging timeout exits with buffered RX residue.
    rx_timeout_log_budget: AtomicU32,
    /// Cumulative bytes observed below the response frame assembler.
    rx_wire_bytes: AtomicU64,
    /// Cumulative complete frames accepted by the response frame assembler.
    rx_framed_responses: AtomicU64,
}

fn preview_hex(bytes: &[u8], max: usize) -> String {
    bytes
        .iter()
        .take(max)
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Circular receive buffer for assembling response frames from the byte stream.
///
/// Serial UARTs deliver bytes asynchronously. A response frame may arrive
/// split across multiple read() calls, or multiple frames may arrive in
/// a single read(). This buffer accumulates raw bytes and scans for the
/// response preamble (0xAA 0x55) to extract complete frames.
struct RxBuffer {
    buf: Vec<u8>,
    /// Number of valid bytes in buf[0..len].
    len: usize,
    /// Complete BM1366 candidates rejected since construction.
    crc_rejected: u64,
    /// Complete nonce bodies retained by an owner register conversation.
    retained: VecDeque<Vec<u8>>,
}

impl RxBuffer {
    fn new() -> Self {
        Self {
            buf: vec![0u8; 1024],
            len: 0,
            crc_rejected: 0,
            retained: VecDeque::new(),
        }
    }

    /// Append new data to the buffer.
    fn push(&mut self, data: &[u8]) {
        let avail = self.buf.len() - self.len;
        if data.len() > avail {
            // Grow the buffer
            self.buf.resize(self.len + data.len() + 256, 0);
        }
        self.buf[self.len..self.len + data.len()].copy_from_slice(data);
        self.len += data.len();
    }

    /// Try to extract a complete response frame from the buffer.
    ///
    /// Scans for the response preamble (0xAA 0x55), then checks if enough
    /// bytes follow for a complete frame. If found, copies the frame body
    /// (without preamble) into `out` and removes the consumed bytes.
    ///
    /// Returns the number of body bytes extracted, or 0 if no complete frame.
    fn try_extract_frame(&mut self, body_len: usize, out: &mut [u8]) -> usize {
        if let Some(body) = self.retained.pop_front() {
            let count = body.len().min(out.len());
            out[..count].copy_from_slice(&body[..count]);
            return count;
        }
        let frame_len = 2 + body_len; // preamble + body

        // Scan for preamble
        let mut i = 0;
        while i + 1 < self.len {
            if self.buf[i] == RESP_PREAMBLE[0] && self.buf[i + 1] == RESP_PREAMBLE[1] {
                // Found preamble at position i
                if i + frame_len <= self.len {
                    if body_len == BM1366_UART_RESP_BODY_LEN
                        && crc5(&self.buf[i + 2..i + frame_len]) != 0
                    {
                        self.crc_rejected = self.crc_rejected.saturating_add(1);
                        // Do not consume a whole false candidate: an embedded
                        // or immediately following AA55 may start a valid
                        // response. Advance the hunter by one byte.
                        i += 1;
                        continue;
                    }
                    // Complete frame available
                    let body_start = i + 2;
                    let copy_len = body_len.min(out.len());
                    out[..copy_len].copy_from_slice(&self.buf[body_start..body_start + copy_len]);

                    // Remove consumed bytes (everything up to and including this frame)
                    let consumed = i + frame_len;
                    self.buf.copy_within(consumed..self.len, 0);
                    self.len -= consumed;
                    return copy_len;
                } else {
                    // Incomplete frame — discard bytes before the preamble and wait
                    if i > 0 {
                        self.buf.copy_within(i..self.len, 0);
                        self.len -= i;
                    }
                    return 0;
                }
            }
            i += 1;
        }

        // No preamble found — discard all but the last byte (could be start of preamble)
        if self.len > 1 {
            self.buf[0] = self.buf[self.len - 1];
            self.len = 1;
        }
        0
    }

    /// Discard all buffered data.
    fn clear(&mut self) {
        self.len = 0;
        self.retained.clear();
    }
}

/// Exclusive, nonblocking I/O borrowed from the already admitted serial owner.
/// No transport is opened, cloned, or shared. All phases use one absolute
/// deadline, including TX and stale-RX draining. Kernel flags and interleaved
/// nonce bodies are restored even when the conversation returns an error.
pub struct BoundedSerialResponseIo<'a> {
    backend: &'a mut UartBackend,
    rx: &'a mut RxBuffer,
    body_len: usize,
    deadline: Instant,
    cancelled: &'a dyn Fn() -> bool,
    original_flags: Option<i32>,
    retained: Vec<Vec<u8>>,
    wire_bytes: &'a AtomicU64,
}

impl BoundedSerialResponseIo<'_> {
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn is_cancelled(&self) -> bool {
        (self.cancelled)()
    }
    pub fn response_body_len(&self) -> usize {
        self.body_len
    }

    pub fn check_budget(&self) -> Result<()> {
        if self.is_cancelled() {
            return Err(HalError::Platform("register conversation cancelled".into()));
        }
        if Instant::now() >= self.deadline {
            return Err(HalError::Platform(
                "register conversation deadline expired".into(),
            ));
        }
        Ok(())
    }

    /// Command frame only; no flush/tcdrain whose wait escapes the deadline.
    pub fn send_command(&mut self, body: &[u8]) -> Result<()> {
        if !matches!(
            body,
            [0x42, 0x05, _, _] | [0x41 | 0x51, 0x09, _, _, _, _, _, _]
        ) {
            return Err(HalError::Platform(
                "bounded owner conversation only accepts BM1397+ register commands".into(),
            ));
        }
        let mut frame = Vec::with_capacity(body.len() + 3);
        frame.extend_from_slice(&CMD_PREAMBLE);
        frame.extend_from_slice(body);
        frame.push(crc5(body));
        let mut sent = 0;
        while sent < frame.len() {
            self.check_budget()?;
            let count = match self.backend {
                UartBackend::File(serial) => serial.try_write_bounded(&frame[sent..])?,
                UartBackend::Devmem(serial) => serial.try_write_bounded(&frame[sent..])?,
            };
            sent += count;
            if count == 0 {
                std::thread::yield_now();
            }
        }
        self.check_budget()
    }

    /// Bounded replacement for tcdrain / spin-count waits before changing baud.
    pub fn drain_tx(&mut self) -> Result<()> {
        loop {
            self.check_budget()?;
            let empty = match self.backend {
                UartBackend::File(serial) => serial.bounded_tx_empty()?,
                UartBackend::Devmem(serial) => serial.bounded_tx_empty(),
            };
            if empty {
                return self.check_budget();
            }
            std::thread::yield_now();
        }
    }

    /// One nonblocking parser step, with no independent timeout or mutex wait.
    pub fn poll_response(&mut self) -> Result<Option<Vec<u8>>> {
        self.check_budget()?;
        let mut body = vec![0; self.body_len];
        let mut count = self.rx.try_extract_frame(self.body_len, &mut body);
        if count == 0 {
            let mut bytes = [0; 256];
            let received = self.backend.read_bytes(&mut bytes)?;
            self.wire_bytes
                .fetch_add(received as u64, Ordering::Relaxed);
            self.rx.push(&bytes[..received]);
            count = self.rx.try_extract_frame(self.body_len, &mut body);
        }
        if let Err(error) = self.check_budget() {
            if count != 0 {
                self.retained.push(body[..count].to_vec());
            }
            return Err(error);
        }
        Ok((count != 0).then(|| body[..count].to_vec()))
    }

    pub fn retain_nonce(&mut self, body: Vec<u8>) -> Result<()> {
        // Stop admission before the queue can grow without bound. Previously
        // retained shares survive this error and re-enter the normal RX path.
        if body.len() != self.body_len {
            return Err(HalError::Platform(
                "retained nonce has wrong response layout".into(),
            ));
        }
        self.retained.push(body);
        if self.retained.len() > 256 {
            return Err(HalError::Platform(
                "register conversation nonce retention full".into(),
            ));
        }
        Ok(())
    }

    fn restore_flags(&mut self) -> Result<()> {
        if let (Some(flags), UartBackend::File(serial)) = (self.original_flags, &mut self.backend) {
            serial.restore_io_flags(flags)?;
            self.original_flags = None;
        }
        Ok(())
    }
}

impl Drop for BoundedSerialResponseIo<'_> {
    fn drop(&mut self) {
        for body in self.retained.drain(..).rev() {
            self.rx.retained.push_front(body);
        }
        if let Err(error) = self.restore_flags() {
            tracing::error!(%error, "failed to restore owner serial flags after register conversation");
        }
    }
}

/// Captured transport selection after any lab-only IRQ handoff completes.
/// This parameter selects an adapter; it does not authorize hardware access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SerialBackendPreference {
    #[default]
    PlatformDefault,
    PreferKernel,
}

impl SerialChainBackend {
    pub fn with_bounded_response_io<T>(
        &mut self,
        deadline: Instant,
        cancelled: &dyn Fn() -> bool,
        conversation: impl FnOnce(&mut BoundedSerialResponseIo<'_>) -> Result<T>,
    ) -> Result<T> {
        if cancelled() || Instant::now() >= deadline {
            return Err(HalError::Platform(
                "register conversation cancelled or expired before admission".into(),
            ));
        }
        let body_len = self.resp_body_len.load(Ordering::Relaxed);
        if !matches!(body_len, 7 | 9) {
            return Err(HalError::Platform(
                "register conversation refuses unsupported response format (including BM1387)"
                    .into(),
            ));
        }
        // Exclusive &mut self gives direct access, never waiting on an owner
        // mutex while a clock budget silently expires.
        let backend = self
            .serial
            .get_mut()
            .map_err(|_| HalError::Platform("serial owner poisoned".into()))?;
        let rx = self
            .rx_buf
            .get_mut()
            .map_err(|_| HalError::Platform("serial RX owner poisoned".into()))?;
        let original_flags = match backend {
            UartBackend::File(serial) => Some(serial.begin_bounded_io()?),
            UartBackend::Devmem(_) => None,
        };
        let mut io = BoundedSerialResponseIo {
            backend,
            rx,
            body_len,
            deadline,
            cancelled,
            original_flags,
            retained: Vec::new(),
            wire_bytes: &self.rx_wire_bytes,
        };
        let result = conversation(&mut io);
        io.restore_flags()?;
        result
    }

    /// Open a serial chain backend on the given device path.
    ///
    /// `chain_id` is used for logging and error context.
    /// `baud` is the initial baud rate (typically 115200 for enumeration).
    pub fn open(chain_id: u8, device: &str, baud: u32) -> Result<Self> {
        Self::open_with_preference(chain_id, device, baud, SerialBackendPreference::PlatformDefault)
    }

    pub fn open_with_preference(
        chain_id: u8,
        device: &str,
        baud: u32,
        preference: SerialBackendPreference,
    ) -> Result<Self> {
        // PL UARTs on Zynq (/dev/ttyS1-4) have broken kernel IRQ handling.
        // Always use devmem for these. File-based for everything else.
        let (backend, selection) = if preference != SerialBackendPreference::PreferKernel && Self::needs_devmem(device) {
            // On am2 we want the direct-register UART path without tearing down
            // the kernel tty binding. The dedicated no-unbind path exists for
            // this board family because unbinding can perturb adjacent system
            // state (notably PSU/I2C bring-up) while providing no benefit to
            // our polled devmem I/O path.
            let devmem = DevmemUart::open_no_unbind(device, baud)?;
            (UartBackend::Devmem(devmem), "devmem-required-zynq-pl-uart")
        } else {
            match SerialChain::open(device, baud) {
                Ok(serial) => {
                    tracing::info!(chain_id, device, baud, "Serial chain backend opened (file)");
                    (UartBackend::File(serial), "kernel-open")
                }
                Err(file_err) => {
                    tracing::warn!(chain_id, device, baud, error = %file_err,
                        "File-based serial open failed, trying devmem bypass");
                    let devmem = DevmemUart::open_no_unbind(device, baud)?;
                    (UartBackend::Devmem(devmem), "kernel-failed-devmem-fallback")
                }
            }
        };
        Self::log_open_diagnostics(chain_id, device, baud, "normal", selection, &backend);

        Ok(Self {
            serial: Mutex::new(backend),
            chain_id,
            resp_body_len: AtomicUsize::new(DEFAULT_RESP_BODY_LEN),
            rx_buf: Mutex::new(RxBuffer::new()),
            rx_unframed_log_budget: AtomicU32::new(8),
            rx_timeout_log_budget: AtomicU32::new(8),
            rx_wire_bytes: AtomicU64::new(0),
            rx_framed_responses: AtomicU64::new(0),
        })
    }

    /// Open an exclusively held Linux UART without a platform fallback.
    ///
    /// Exact native routes whose admission already binds their Linux device
    /// path use this factory. A failed open must not acquire an AM2 /dev/mem
    /// UART through the generic compatibility factory. SerialChain retains
    /// the file and its TIOCEXCL claim for the complete backend lifetime.
    pub fn open_native_linux_only(chain_id: u8, device: &str, baud: u32) -> Result<Self> {
        let backend = UartBackend::File(SerialChain::open(device, baud)?);
        // Generic diagnostics may inspect AM2 PL registers through /dev/mem.
        // This exact Linux factory has no authority for those observations.
        tracing::info!(chain_id, device, baud, "Exclusive native Linux UART opened");
        Ok(Self {
            serial: Mutex::new(backend),
            chain_id,
            resp_body_len: AtomicUsize::new(DEFAULT_RESP_BODY_LEN),
            rx_buf: Mutex::new(RxBuffer::new()),
            rx_unframed_log_budget: AtomicU32::new(8),
            rx_timeout_log_budget: AtomicU32::new(8),
            rx_wire_bytes: AtomicU64::new(0),
            rx_framed_responses: AtomicU64::new(0),
        })
    }

    /// Assert MCR OUT2 on the chain UART (BLK-1b, 2026-06-10).
    ///
    /// MUST be called AFTER the final `set_baud` (e.g. after the RE-018 Phase-A0
    /// B9600->B115200 port-wake), because the kernel `of_serial` driver may
    /// rewrite MCR on a termios/baud change and clear OUT2. On `a lab unit` the OUT2 bit
    /// gates the FPGA UART TX clock-out; the kernel transport never asserts it
    /// (no live IRQ after the IRQ-165 unbind), so this pokes it directly. No-op on
    /// Baseline (non-`a lab unit`/non-override) units and on the devmem backend (already
    /// 0x0B at open) — fleet/handoff byte-identical.
    pub fn assert_mcr_out2(&self) -> Result<()> {
        let backend = self.serial.lock().unwrap();
        let path = backend.path().to_string();
        let kind = backend.kind_label();
        match backend.assert_mcr_out2()? {
            Some((before, after)) => tracing::info!(
                chain_id = self.chain_id,
                device = %path,
                backend = kind,
                mcr_before = format_args!("0x{:02X}", before),
                mcr_after = format_args!("0x{:02X}", after),
                "chain UART MCR OUT2 asserted (BLK-1b: .25 FPGA UART TX-clock gate; expect after=0x0B)"
            ),
            None => tracing::debug!(
                chain_id = self.chain_id,
                device = %path,
                backend = kind,
                "chain UART MCR OUT2 assert skipped (baseline unit, or devmem already 0x0B)"
            ),
        }
        Ok(())
    }

    /// Snapshot the chain UART MCR/IER/LSR (BLK-1b forensics). Works on BOTH the
    /// kernel (`File`, via one-shot `/dev/mem` read) and devmem backends so a live
    /// run can OBSERVE OUT2 (and TX-drain via LSR) mid-walk instead of inferring.
    /// Read-only; returns `None` if the registers can't be read.
    pub fn diagnostic_registers(&self) -> Option<(u32, u32, u32)> {
        self.serial.lock().unwrap().diagnostic_registers()
    }

    /// Open in passthrough mode — preserve existing baud rate from previous firmware.
    pub fn open_passthrough(chain_id: u8, device: &str) -> Result<Self> {
        Self::open_passthrough_with_preference(chain_id, device, SerialBackendPreference::PlatformDefault)
    }

    pub fn open_passthrough_with_preference(
        chain_id: u8,
        device: &str,
        preference: SerialBackendPreference,
    ) -> Result<Self> {
        let (backend, selection) = if preference != SerialBackendPreference::PreferKernel && Self::needs_devmem(device) {
            // On am2 passthrough, preserve inherited UART state instead of
            // resetting FIFOs / rewriting baud during attach.
            let devmem = DevmemUart::open_preserve_state(device, crate::serial::BAUD_3125000)?;
            (
                UartBackend::Devmem(devmem),
                "passthrough-devmem-required-zynq-pl-uart",
            )
        } else {
            match SerialChain::open_passthrough(device) {
                Ok(serial) => {
                    tracing::info!(
                        chain_id,
                        device,
                        "Serial chain backend opened (passthrough/file)"
                    );
                    (UartBackend::File(serial), "passthrough-kernel-open")
                }
                Err(file_err) => {
                    tracing::warn!(chain_id, device, error = %file_err,
                        "Passthrough serial open failed, trying preserve-state devmem bypass at 3.125M");
                    let devmem =
                        DevmemUart::open_preserve_state(device, crate::serial::BAUD_3125000)?;
                    (
                        UartBackend::Devmem(devmem),
                        "passthrough-kernel-failed-devmem-fallback",
                    )
                }
            }
        };
        Self::log_open_diagnostics(
            chain_id,
            device,
            crate::serial::BAUD_3125000,
            "passthrough",
            selection,
            &backend,
        );

        Ok(Self {
            serial: Mutex::new(backend),
            chain_id,
            resp_body_len: AtomicUsize::new(DEFAULT_RESP_BODY_LEN),
            rx_buf: Mutex::new(RxBuffer::new()),
            rx_unframed_log_budget: AtomicU32::new(8),
            rx_timeout_log_budget: AtomicU32::new(8),
            rx_wire_bytes: AtomicU64::new(0),
            rx_framed_responses: AtomicU64::new(0),
        })
    }

    /// S19k/BM1366 passthrough: fail-closed body 9. Generic `open_passthrough`
    /// still constructs at HAL DEFAULT 7 (BM139X). Do not first-read BM1366
    /// on that default.
    pub fn open_passthrough_bm1366(chain_id: u8, device: &str) -> Result<Self> {
        let s = Self::open_passthrough(chain_id, device)?;
        s.set_response_len(BM1366_UART_RESP_BODY_LEN);
        Ok(s)
    }

    /// Check if a device path requires devmem bypass (PL UARTs on Zynq).
    ///
    /// Zynq PL UARTs at 0x4100x000 share IRQs with UIO FPGA devices,
    /// which breaks the kernel 8250 serial driver (writes block forever
    /// waiting for TX empty interrupts that never fire).
    ///
    /// Amlogic A113D (S19j Pro, S21) uses standard kernel meson_uart driver
    /// for /dev/ttyS1-3 with no IRQ conflicts — devmem bypass not needed.
    /// Detection: /dev/uio0 exists only on Zynq (FPGA present).
    fn needs_devmem(device: &str) -> bool {
        // Diagnostic escape hatch: stock bosminer on .139 uses the kernel ttyS
        // path, so allow a one-shot kernel-backed experiment without changing
        // the default am2 behavior for every caller.
        if dcentrald_common::lab_env::var_os("DCENT_PREFER_KERNEL_UART").is_some() {
            return false;
        }

        Self::needs_devmem_with_uio_presence(device, Self::zynq_uio_present())
    }

    fn zynq_uio_present() -> bool {
        if let Ok(entries) = std::fs::read_dir("/sys/class/uio") {
            for entry in entries.flatten() {
                let name_path = entry.path().join("name");
                if let Ok(name) = std::fs::read_to_string(name_path) {
                    if Self::uio_name_marks_zynq(&name) {
                        return true;
                    }
                }
            }
        }

        // Some stripped rescue images expose device nodes without populated
        // `/sys/class/uio/*/name`. In that case, require both a UIO node and a
        // Zynq/am2 platform marker so future non-Zynq platforms with unrelated
        // UIO devices do not get forced onto the PL-UART devmem path.
        if let Ok(entries) = std::fs::read_dir("/dev") {
            let has_uio_node = entries
                .flatten()
                .filter_map(|entry| entry.file_name().into_string().ok())
                .any(|name| {
                    name.strip_prefix("uio").is_some_and(|suffix| {
                        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
                    })
                });
            return has_uio_node && Self::platform_marks_zynq_am2();
        }

        false
    }

    fn uio_name_marks_zynq(name: &str) -> bool {
        let name = name.trim();
        name.starts_with("chain")
            || matches!(
                name,
                "fan-control" | "board-control" | "miner-glitch-monitor"
            )
    }

    fn platform_marks_zynq_am2() -> bool {
        for path in [
            "/etc/bos_platform",
            "/etc/dcentos/platform",
            "/etc/dcentos/board_target",
            "/proc/device-tree/compatible",
        ] {
            let Ok(raw) = std::fs::read(path) else {
                continue;
            };
            let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
            if Self::platform_marker_text_marks_zynq_am2(&text) {
                return true;
            }
        }
        false
    }

    fn platform_marker_text_marks_zynq_am2(text: &str) -> bool {
        let text = text.to_ascii_lowercase();
        text.contains("zynq") || text.contains("am2-s19")
    }

    fn needs_devmem_with_uio_presence(device: &str, uio_present: bool) -> bool {
        // Only Zynq PL UARTs need devmem bypass (FPGA IRQ conflict)
        // Amlogic, BeagleBone, CVitek: standard kernel UART works fine
        if !uio_present {
            return false;
        }
        matches!(
            device,
            "/dev/ttyS1" | "/dev/ttyS2" | "/dev/ttyS3" | "/dev/ttyS4"
        )
    }

    fn log_open_diagnostics(
        chain_id: u8,
        requested_device: &str,
        requested_baud: u32,
        open_mode: &'static str,
        selection: &'static str,
        backend: &UartBackend,
    ) {
        let backend_kind = backend.kind_label();
        let device = backend.path();
        let baud = backend.baud();
        if let Some((mcr, ier, lsr)) = backend.diagnostic_registers() {
            tracing::info!(
                chain_id,
                backend_kind,
                device,
                requested_device,
                baud,
                requested_baud,
                open_mode,
                selection,
                mcr = format_args!("0x{:02X}", mcr),
                ier = format_args!("0x{:02X}", ier),
                lsr = format_args!("0x{:02X}", lsr),
                "SerialChainBackend open diagnostics"
            );
        } else {
            tracing::info!(
                chain_id,
                backend_kind,
                device,
                requested_device,
                baud,
                requested_baud,
                open_mode,
                selection,
                "SerialChainBackend open diagnostics"
            );
        }
    }

    /// Set the expected response body length (chip-dependent).
    ///
    /// Call this after chip detection:
    ///   - BM1387: `set_response_len(BM1387_RESP_BODY_LEN)` (5 bytes)
    ///   - BM139X: `set_response_len(BM139X_RESP_BODY_LEN)` (7 bytes)
    pub fn set_response_len(&self, body_len: usize) {
        self.resp_body_len.store(body_len, Ordering::Relaxed);
        tracing::debug!(
            chain_id = self.chain_id,
            body_len,
            "Set response body length"
        );
    }

    /// Current response body length after preamble.
    pub fn response_body_len(&self) -> usize {
        self.resp_body_len.load(Ordering::Relaxed)
    }

    /// Fail-closed: BM1366 first-read must be body 9. Generic
    /// `open_passthrough` constructs at DEFAULT 7.
    pub fn require_bm1366_response_body(&self) -> Result<()> {
        let n = self.response_body_len();
        if n != BM1366_UART_RESP_BODY_LEN {
            return Err(HalError::Platform(format!(
                "BM1366 first-read body must be {}, not {} (skipped open_passthrough_bm1366 or set_response_len(9))",
                BM1366_UART_RESP_BODY_LEN, n
            )));
        }
        Ok(())
    }

    /// Set VTIME on the underlying serial port.
    /// VTIME=0 makes reads fully non-blocking (for async-friendly polling).
    /// No-op for devmem backend (already polled).
    pub fn set_vtime(&self, vtime: u8) -> Result<()> {
        let mut backend = self.serial.lock().unwrap();
        match &mut *backend {
            UartBackend::File(s) => s.set_vtime(vtime),
            UartBackend::Devmem(_) => Ok(()),
        }
    }

    /// Set the underlying serial port to non-blocking mode.
    /// No-op for devmem backend (already polled/non-blocking).
    pub fn set_nonblocking(&self) -> Result<()> {
        let mut serial = self.serial.lock().unwrap();
        match &mut *serial {
            UartBackend::File(s) => s.set_nonblocking(),
            UartBackend::Devmem(_) => Ok(()),
        }
    }

    /// Set the UART baud rate.
    ///
    /// Supports both standard rates (via termios) and custom rates like
    /// 1.5625 Mbaud and 3.125 Mbaud (via BOTHER/termios2 ioctl).
    pub fn set_baud(&self, baud: u32) -> Result<()> {
        let mut backend = self.serial.lock().unwrap();
        backend.drain_tx()?;
        backend.set_baud(baud)?;
        tracing::info!(
            chain_id = self.chain_id,
            baud,
            "Serial chain baud rate changed"
        );
        Ok(())
    }

    /// Drain the transmit side without discarding receive data.
    pub fn drain_tx(&self) -> Result<()> {
        let mut backend = self.serial.lock().unwrap();
        backend.drain_tx()
    }

    /// Get the current baud rate.
    pub fn baud(&self) -> u32 {
        self.serial.lock().unwrap().baud()
    }

    /// Flush RX and TX buffers (discard all pending data).
    pub fn flush_io(&self) -> Result<()> {
        let mut backend = self.serial.lock().unwrap();
        backend.flush_io()?;
        self.rx_buf.lock().unwrap().clear();
        Ok(())
    }

    /// Discard stale kernel/MMIO and assembled RX, preserving queued TX.
    /// Keep the same serial-then-parser lock order as the complete flush.
    pub fn flush_rx(&self) -> Result<()> {
        let mut backend = self.serial.lock().unwrap();
        backend.flush_rx()?;
        self.rx_buf.lock().unwrap().clear();
        Ok(())
    }

    /// Write already-framed bytes directly to the chain UART.
    ///
    /// This bypasses the command/work helper framing but still uses the active
    /// backend selected by [`SerialChainBackend::open`]. It is intended for
    /// platform bring-up code that already builds byte-exact BM13xx frames.
    pub fn write_raw_bytes(&self, data: &[u8]) -> Result<()> {
        let mut backend = self.serial.lock().unwrap();
        backend.write_bytes(data)
    }

    /// Read raw UART bytes for up to `timeout_ms`.
    ///
    /// This bypasses the response-frame assembler. Callers that mix raw reads
    /// with [`read_all_responses`](Self::read_all_responses) should flush first
    /// so stale buffered parser bytes do not cross streams.
    pub fn read_raw_bytes_timeout(&self, buf: &mut [u8], timeout_ms: u64) -> Result<usize> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        let mut n_total = 0usize;

        while n_total < buf.len() {
            let n = {
                let mut backend = self.serial.lock().unwrap();
                backend.read_bytes(&mut buf[n_total..])?
            };

            if n > 0 {
                n_total += n;
                continue;
            }

            if std::time::Instant::now() >= deadline {
                break;
            }

            std::thread::yield_now();
        }

        Ok(n_total)
    }

    // -----------------------------------------------------------------------
    // Command transmission
    // -----------------------------------------------------------------------

    /// Send a raw command frame to the ASIC chain.
    ///
    /// `payload` is the command bytes WITHOUT preamble and WITHOUT CRC.
    /// This method prepends [0x55, 0xAA] and appends the CRC-5 byte.
    ///
    /// Example: to send GetAddress broadcast (header=0x54, len=0x05, reg=0x00):
    ///   send_cmd(&[0x54, 0x05, 0x00, 0x00])
    pub fn send_cmd(&self, payload: &[u8]) -> Result<()> {
        let crc = crc5(payload);

        let mut frame = Vec::with_capacity(2 + payload.len() + 1);
        frame.extend_from_slice(&CMD_PREAMBLE);
        frame.extend_from_slice(payload);
        frame.push(crc);

        let mut backend = self.serial.lock().unwrap();
        backend.write_bytes(&frame)?;

        tracing::trace!(
            chain_id = self.chain_id,
            frame_len = frame.len(),
            payload_hex = %hex_str(payload),
            crc = format_args!("0x{:02X}", crc),
            "TX cmd"
        );

        Ok(())
    }

    /// Send a FIFO-style command (32-bit word, as used by FpgaChain).
    ///
    /// This is a compatibility shim: the FPGA cmd FIFO takes 32-bit words
    /// in LSB-first byte order and auto-prepends preamble + auto-appends CRC.
    /// This method unpacks the word into bytes, prepends preamble, and appends CRC.
    ///
    /// For single-word commands (GetAddress, ChainInactive, SetChipAddress):
    ///   The 32-bit word encodes [header, length, byte2, byte3] in LSB-first order.
    pub fn send_cmd_word(&self, word: u32) -> Result<()> {
        // Unpack LSB-first: byte0 = bits[7:0], byte1 = bits[15:8], etc.
        let bytes = word.to_le_bytes();

        // The FPGA FIFO format packs: [header, length, ...] in LSB-first.
        // The length field tells us how many bytes the ASIC expects (including header).
        let length = bytes[1] as usize;

        // Sanity check: length should be 5 (short cmd) or 9 (register write)
        if !(3..=12).contains(&length) {
            return Err(HalError::Platform(format!(
                "serial cmd_word invalid length field {}: word=0x{:08X}",
                length, word
            )));
        }

        // Build the payload (header + len + data, without preamble/CRC).
        // For a 5-byte command: payload = [header, length, data0, data1]
        //   -> wire: [0x55, 0xAA, header, length, data0, data1, CRC5]
        // The FPGA auto-generates the preamble and CRC; we do it in software.
        let payload_len = length - 1; // -1 because length includes the CRC byte
        let payload = &bytes[..payload_len.min(4)];

        self.send_cmd(payload)
    }

    /// Send a two-word FIFO command (register write: word0 + word1).
    ///
    /// Matches `fifo_cmd_write_reg_bcast_full()` and `fifo_cmd_write_reg_full()`
    /// from the protocol module. These encode a 9-byte command as two 32-bit words.
    pub fn send_cmd_words(&self, word0: u32, word1: u32) -> Result<()> {
        let b0 = word0.to_le_bytes();
        let b1 = word1.to_le_bytes();

        // Combine into payload: [header, length, hw_addr, reg, val_BE[0..4]]
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&b0);
        payload[4..8].copy_from_slice(&b1);

        // Length field is payload[1]; for register writes it's 0x09 (9 bytes total).
        // The payload we send is 8 bytes (header + len + 6 data), CRC is appended.
        self.send_cmd(&payload)
    }

    // -----------------------------------------------------------------------
    // Response reception
    // -----------------------------------------------------------------------

    /// Snapshot cumulative receive activity on both sides of the frame
    /// assembler. This is diagnostic-only: reading it does not flush bytes,
    /// alter timeouts, or change serial scheduling.
    pub fn rx_observation(&self) -> SerialRxObservation {
        let rx = self.rx_buf.lock().unwrap();
        SerialRxObservation {
            wire_bytes: self.rx_wire_bytes.load(Ordering::Relaxed),
            framed_responses: self.rx_framed_responses.load(Ordering::Relaxed),
            crc_rejected_frames: rx.crc_rejected,
            buffered_bytes: rx.len,
        }
    }

    /// Read a single command response from the serial port.
    ///
    /// Blocks up to `CMD_RESPONSE_TIMEOUT_MS` waiting for a complete response
    /// frame. Returns the response body bytes (without preamble) or None if
    /// no response arrives within the timeout.
    ///
    /// The response body is `resp_body_len` bytes (5 for BM1387, 7 for BM139X).
    pub fn read_cmd_response(&self) -> Result<Option<Vec<u8>>> {
        self.read_response_timeout(CMD_RESPONSE_TIMEOUT_MS)
    }

    /// Read a nonce response from the serial port (short timeout for polling).
    ///
    /// Returns the response body or None if no nonce is available.
    /// Uses a short timeout suitable for tight mining loops.
    pub fn read_nonce_response(&self) -> Result<Option<Vec<u8>>> {
        self.read_response_timeout(NONCE_POLL_TIMEOUT_MS)
    }

    /// Read a response with a specified timeout.
    fn read_response_timeout(&self, timeout_ms: u64) -> Result<Option<Vec<u8>>> {
        let body_len = self.resp_body_len.load(Ordering::Relaxed);
        let mut out = vec![0u8; body_len];
        let mut observed_bytes = 0usize;

        // First check if we already have a complete frame buffered
        {
            let mut rx = self.rx_buf.lock().unwrap();
            let n = rx.try_extract_frame(body_len, &mut out);
            if n > 0 {
                self.rx_framed_responses.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(out[..n].to_vec()));
            }
        }

        // Read more data from serial port
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        let mut tmp = [0u8; 256];

        while std::time::Instant::now() < deadline {
            let n = {
                let mut backend = self.serial.lock().unwrap();
                backend.read_bytes(&mut tmp)?
            };

            if n > 0 {
                observed_bytes += n;
                self.rx_wire_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let mut rx = self.rx_buf.lock().unwrap();
                rx.push(&tmp[..n]);
                let extracted = rx.try_extract_frame(body_len, &mut out);
                if extracted > 0 {
                    self.rx_framed_responses.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some(out[..extracted].to_vec()));
                }

                if self
                    .rx_unframed_log_budget
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
                    .is_ok()
                {
                    let buffered_len = rx.len;
                    let buffered_preview = preview_hex(&rx.buf[..rx.len.min(24)], 24);
                    tracing::info!(
                        chain_id = self.chain_id,
                        body_len,
                        chunk_len = n,
                        buffered_len,
                        chunk = %preview_hex(&tmp[..n], 24),
                        buffered = %buffered_preview,
                        "serial_rx_unframed_bytes"
                    );
                }
            }
        }

        if observed_bytes > 0 {
            let rx = self.rx_buf.lock().unwrap();
            if rx.len > 0
                && self
                    .rx_timeout_log_budget
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1))
                    .is_ok()
            {
                tracing::info!(
                    chain_id = self.chain_id,
                    body_len,
                    timeout_ms,
                    observed_bytes,
                    buffered_len = rx.len,
                    buffered = %preview_hex(&rx.buf[..rx.len.min(24)], 24),
                    "serial_rx_timeout_with_buffered_bytes"
                );
            }
        }

        Ok(None)
    }

    /// Read all available response frames (non-blocking drain).
    ///
    /// Returns a Vec of response bodies. Useful for reading all chip
    /// responses after a broadcast command (e.g., GetAddress).
    pub fn read_all_responses(&self, max_wait_ms: u64) -> Result<Vec<Vec<u8>>> {
        let mut responses = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_wait_ms);
        let body_len = self.resp_body_len.load(Ordering::Relaxed);
        let mut out = vec![0u8; body_len];
        let mut tmp = [0u8; 512];

        // First drain anything already buffered
        loop {
            let mut rx = self.rx_buf.lock().unwrap();
            let n = rx.try_extract_frame(body_len, &mut out);
            if n > 0 {
                self.rx_framed_responses.fetch_add(1, Ordering::Relaxed);
                responses.push(out[..n].to_vec());
            } else {
                break;
            }
        }

        // Read from serial until timeout
        while std::time::Instant::now() < deadline {
            let n = {
                let mut backend = self.serial.lock().unwrap();
                backend.read_bytes(&mut tmp)?
            };

            if n > 0 {
                self.rx_wire_bytes.fetch_add(n as u64, Ordering::Relaxed);
                let mut rx = self.rx_buf.lock().unwrap();
                rx.push(&tmp[..n]);

                // Extract all complete frames from this batch
                loop {
                    let extracted = rx.try_extract_frame(body_len, &mut out);
                    if extracted > 0 {
                        self.rx_framed_responses.fetch_add(1, Ordering::Relaxed);
                        responses.push(out[..extracted].to_vec());
                    } else {
                        break;
                    }
                }
            }
        }

        tracing::debug!(
            chain_id = self.chain_id,
            count = responses.len(),
            "Read {} responses from serial",
            responses.len()
        );

        Ok(responses)
    }

    // -----------------------------------------------------------------------
    // Work dispatch (for pure-serial platforms, not hybrid Zynq)
    // -----------------------------------------------------------------------

    /// Send mining work data as raw bytes (with preamble and CRC-16).
    ///
    /// `work_bytes` should include: [header, length, work_data...]
    /// This method prepends the preamble and appends CRC-16.
    ///
    /// On hybrid Zynq platforms, work dispatch goes through the FPGA work_tx
    /// UIO device instead — this method is for pure-serial platforms only.
    pub fn send_work(&self, work_bytes: &[u8]) -> Result<()> {
        // CRC-16 CCITT-FALSE over the payload (without preamble)
        let crc = crc16(work_bytes);

        let mut frame = Vec::with_capacity(2 + work_bytes.len() + 2);
        frame.extend_from_slice(&CMD_PREAMBLE);
        frame.extend_from_slice(work_bytes);
        frame.push((crc >> 8) as u8); // CRC MSB first
        frame.push((crc & 0xFF) as u8);

        let mut backend = self.serial.lock().unwrap();
        backend.write_bytes(&frame)?;

        tracing::trace!(chain_id = self.chain_id, frame_len = frame.len(), "TX work");

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Convenience: FPGA-compatible command helpers
    // -----------------------------------------------------------------------

    /// Send GetAddress broadcast command.
    ///
    /// Equivalent to writing FIFO_CMD_GET_ADDRESS to the FPGA cmd FIFO.
    /// Wire: [0x55, 0xAA, 0x54, 0x05, 0x00, 0x00, CRC5]
    pub fn send_get_address(&self) -> Result<()> {
        self.send_cmd(&[0x54, 0x05, 0x00, 0x00])
    }

    /// Send Chain Inactive broadcast command.
    ///
    /// Equivalent to writing FIFO_CMD_CHAIN_INACTIVE to the FPGA cmd FIFO.
    /// Wire: [0x55, 0xAA, 0x55, 0x05, 0x00, 0x00, CRC5]
    pub fn send_chain_inactive(&self) -> Result<()> {
        self.send_cmd(&[0x55, 0x05, 0x00, 0x00])
    }

    /// Send SetChipAddress command to assign an address to the next chip.
    ///
    /// Equivalent to writing fifo_cmd_set_address(addr) to the FPGA cmd FIFO.
    /// Wire: [0x55, 0xAA, 0x41, 0x05, addr, 0x00, CRC5]
    pub fn send_set_address(&self, addr: u8) -> Result<()> {
        self.send_cmd(&[0x41, 0x05, addr, 0x00])
    }

    // -----------------------------------------------------------------------
    // BM1397+ command helpers (different header bytes from BM1387)
    // BM1387: 0x54 (read), 0x55 (inactive), 0x41 (set_addr)
    // BM1397+: 0x52 (read), 0x53 (inactive), 0x40 (set_addr)
    // -----------------------------------------------------------------------

    /// Send GetAddress broadcast command (BM1397+ format).
    ///
    /// BM1397/BM1398/BM1362+ use header 0x52 instead of BM1387's 0x54.
    /// Wire: [0x55, 0xAA, 0x52, 0x05, 0x00, 0x00, CRC5]
    pub fn send_get_address_bm1397plus(&self) -> Result<()> {
        self.send_cmd(&[0x52, 0x05, 0x00, 0x00])
    }

    /// Broadcast `read_register(reg)` (BM1397+/BM136x). GetAddress is `reg=0`.
    /// FastUART is `reg=0x28` → `55 AA 52 05 00 28 CRC5`.
    /// Not single-chip `42 05`.
    pub fn send_read_reg_broadcast_bm1397plus(&self, reg: u8) -> Result<()> {
        self.send_cmd(&[0x52, 0x05, 0x00, reg])
    }

    /// Send Chain Inactive broadcast command (BM1397+ format).
    ///
    /// BM1397/BM1398/BM1362+ use header 0x53 instead of BM1387's 0x55.
    /// Wire: [0x55, 0xAA, 0x53, 0x05, 0x00, 0x00, CRC5]
    pub fn send_chain_inactive_bm1397plus(&self) -> Result<()> {
        self.send_cmd(&[0x53, 0x05, 0x00, 0x00])
    }

    /// Send SetChipAddress command (BM1397+ format).
    ///
    /// BM1397/BM1398/BM1362+ use header 0x40 instead of BM1387's 0x41.
    /// Wire: [0x55, 0xAA, 0x40, 0x05, addr, 0x00, CRC5]
    pub fn send_set_address_bm1397plus(&self, addr: u8) -> Result<()> {
        self.send_cmd(&[0x40, 0x05, addr, 0x00])
    }

    /// Send a broadcast register write.
    ///
    /// Equivalent to fifo_cmd_write_reg_bcast_full(reg, value).
    /// Wire: [0x55, 0xAA, 0x58, 0x09, 0x00, reg, value_BE[0..4], CRC5]
    pub fn send_write_reg_broadcast(&self, reg: u8, value: u32) -> Result<()> {
        let vb = value.to_be_bytes();
        self.send_cmd(&[0x58, 0x09, 0x00, reg, vb[0], vb[1], vb[2], vb[3]])
    }

    /// Send a single-chip register write.
    ///
    /// Equivalent to fifo_cmd_write_reg_full(chip_addr, reg, value).
    /// Wire: [0x55, 0xAA, 0x48, 0x09, chip_addr, reg, value_BE[0..4], CRC5]
    pub fn send_write_reg(&self, chip_addr: u8, reg: u8, value: u32) -> Result<()> {
        let vb = value.to_be_bytes();
        self.send_cmd(&[0x48, 0x09, chip_addr, reg, vb[0], vb[1], vb[2], vb[3]])
    }

    /// Send a broadcast register write (BM1397+/BM136x format).
    ///
    /// BM1397+ uses header 0x51 = TYPE_CMD(0x40) | GROUP_ALL(0x10) | CMD_WRITE(0x01).
    /// BM1387 uses 0x58 (CMD_SETCONFIG) which is different and incompatible.
    /// Wire: [0x55, 0xAA, 0x51, 0x09, 0x00, reg, value_BE[0..4], CRC5]
    pub fn send_write_reg_broadcast_bm1397plus(&self, reg: u8, value: u32) -> Result<()> {
        let vb = value.to_be_bytes();
        self.send_cmd(&[0x51, 0x09, 0x00, reg, vb[0], vb[1], vb[2], vb[3]])
    }

    /// Send a single-chip register write (BM1397+/BM136x format).
    ///
    /// BM1397+ uses header 0x41 = TYPE_CMD(0x40) | GROUP_SINGLE(0x00) | CMD_WRITE(0x01).
    /// BM1387 uses 0x48 (CMD_SETCONFIG) which is different and incompatible.
    /// Wire: [0x55, 0xAA, 0x41, 0x09, chip_addr, reg, value_BE[0..4], CRC5]
    pub fn send_write_reg_bm1397plus(&self, chip_addr: u8, reg: u8, value: u32) -> Result<()> {
        let vb = value.to_be_bytes();
        self.send_cmd(&[0x41, 0x09, chip_addr, reg, vb[0], vb[1], vb[2], vb[3]])
    }

    /// Send a register read command.
    ///
    /// Equivalent to fifo_cmd_read_register(chip_addr, reg).
    /// Wire: [0x55, 0xAA, 0x44, 0x05, chip_addr, reg, CRC5]
    pub fn send_read_reg(&self, chip_addr: u8, reg: u8) -> Result<()> {
        self.send_cmd(&[0x44, 0x05, chip_addr, reg])
    }

    /// Send a single-chip register read command (BM1397+/BM136x format).
    ///
    /// BM1397+ uses header 0x42 = TYPE_CMD(0x40) | GROUP_SINGLE(0x00) | CMD_READ(0x02).
    /// BM1387 uses 0x44, which is incompatible with BM1397-family chips.
    /// Wire: [0x55, 0xAA, 0x42, 0x05, chip_addr, reg, CRC5]
    pub fn send_read_reg_bm1397plus(&self, chip_addr: u8, reg: u8) -> Result<()> {
        self.send_cmd(&[0x42, 0x05, chip_addr, reg])
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> u8 {
        self.chain_id
    }

    /// Get the device path.
    pub fn device_path(&self) -> String {
        self.serial.lock().unwrap().path().to_string()
    }
}

// SAFETY: SerialChainBackend is Send+Sync because mutable state is behind
// Mutex or represented by atomics.
unsafe impl Send for SerialChainBackend {}
unsafe impl Sync for SerialChainBackend {}

// ---------------------------------------------------------------------------
// Bm1397PlusChainBackend impl: every method delegates to an existing
// inherent method. See `dcentrald-hal/src/chain_backend.rs` for the trait
// declaration and transport-boundary rationale. `a lab unit` command/init canon is
// PL UART (`/dev/ttyS1` + `/dev/ttyS3`), not default FPGA FIFO.
// ---------------------------------------------------------------------------

impl crate::chain_backend::Bm1397PlusChainBackend for SerialChainBackend {
    fn set_baud_rate(&self, baud: u32) -> Result<()> {
        self.set_baud(baud)
    }

    fn set_response_body_len(&self, body_len: usize) -> Result<()> {
        self.set_response_len(body_len);
        Ok(())
    }

    fn send_get_address_bm1397plus(&self) -> Result<()> {
        SerialChainBackend::send_get_address_bm1397plus(self)
    }

    fn send_chain_inactive_bm1397plus(&self) -> Result<()> {
        SerialChainBackend::send_chain_inactive_bm1397plus(self)
    }

    fn send_set_address_bm1397plus(&self, addr: u8) -> Result<()> {
        SerialChainBackend::send_set_address_bm1397plus(self, addr)
    }

    fn send_write_reg_broadcast_bm1397plus(&self, reg: u8, value: u32) -> Result<()> {
        SerialChainBackend::send_write_reg_broadcast_bm1397plus(self, reg, value)
    }

    fn send_write_reg_bm1397plus(&self, chip_addr: u8, reg: u8, value: u32) -> Result<()> {
        SerialChainBackend::send_write_reg_bm1397plus(self, chip_addr, reg, value)
    }

    fn send_read_reg_bm1397plus(&self, chip_addr: u8, reg: u8) -> Result<()> {
        SerialChainBackend::send_read_reg_bm1397plus(self, chip_addr, reg)
    }

    fn read_response_frame(&self, out: &mut [u8], timeout_ms: u64) -> Result<usize> {
        match self.read_response_timeout(timeout_ms)? {
            Some(body) => {
                let n = out.len().min(body.len());
                out[..n].copy_from_slice(&body[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    fn read_all_responses(&self, max_wait_ms: u64) -> Result<Vec<Vec<u8>>> {
        SerialChainBackend::read_all_responses(self, max_wait_ms)
    }

    fn send_work_frame(&self, frame: &[u8]) -> Result<()> {
        // On serial-only platforms (Amlogic, AM3 BB) work and command share
        // the byte stream, so work dispatch goes through `write_raw_bytes`.
        // In s19j-hybrid mode this method is never reached for work — the
        // hybrid path keeps work-tx on the FPGA UIO; only commands traverse
        // the trait. Kept here for shim completeness and pure-serial reuse.
        self.write_raw_bytes(frame)
    }

    fn poll_nonce_frame(&self, out: &mut [u8], timeout_ms: u64) -> Result<usize> {
        // Honour caller's timeout via `read_response_timeout` rather than
        // the hard-coded `NONCE_POLL_TIMEOUT_MS` used by `read_nonce_response`.
        match self.read_response_timeout(timeout_ms)? {
            Some(body) => {
                let n = out.len().min(body.len());
                out[..n].copy_from_slice(&body[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    fn chain_id(&self) -> u8 {
        SerialChainBackend::chain_id(self)
    }

    fn transport_label(&self) -> &'static str {
        self.serial.lock().unwrap().kind_label()
    }
}

// ---------------------------------------------------------------------------
// CRC-16 CCITT-FALSE (duplicated from protocol.rs to avoid circular dep)
// ---------------------------------------------------------------------------

/// CRC-16 CCITT-FALSE (public for diagnostic use).
pub fn crc16_public(data: &[u8]) -> u16 {
    crc16(data)
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Hex formatting helper
// ---------------------------------------------------------------------------

fn hex_str(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::{
        RxBuffer, SerialChainBackend, BM1366_UART_RESP_BODY_LEN, BM1387_RESP_BODY_LEN,
        BM139X_RESP_BODY_LEN, DEFAULT_RESP_BODY_LEN,
    };

    fn bounded_owner_pty() -> (SerialChainBackend, std::fs::File, std::fs::File) {
        use std::os::fd::{AsRawFd, FromRawFd};
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes two valid descriptor outputs; optional
        // name, termios and winsize pointers are null. Tests contact only a
        // local pseudo-terminal, never a miner or physical UART.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: successful openpty returned two new, separately owned fds.
        let master = unsafe { std::fs::File::from_raw_fd(master) };
        // SAFETY: this is the other new descriptor, consumed exactly once.
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let path = format!("/proc/self/fd/{}", slave.as_raw_fd());
        let serial = SerialChainBackend::open(0, &path, 115200).unwrap();
        (serial, master, slave)
    }

    fn owner_file_flags(serial: &SerialChainBackend) -> i32 {
        let backend = serial.serial.lock().unwrap();
        let super::UartBackend::File(file) = &*backend else {
            panic!("PTY must be file backed")
        };
        // SAFETY: live descriptor, integer-only F_GETFL operation.
        unsafe { libc::fcntl(file.raw_fd(), libc::F_GETFL) }
    }

    #[test]
    fn native_linux_factory_retains_exclusive_file_and_preserves_open_error() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: local PTY descriptor outputs are valid pointers; optional
        // name, termios and size are absent. No hardware is contacted.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: the successful call returned two fresh descriptors, each
        // adopted exactly once by its File owner.
        let _master = unsafe { std::fs::File::from_raw_fd(master) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave) };
        let path = format!("/proc/self/fd/{}", slave.as_raw_fd());
        let serial = SerialChainBackend::open_native_linux_only(2, &path, 115200).unwrap();
        assert_eq!(serial.chain_id(), 2);
        let backend = serial.serial.lock().unwrap();
        let super::UartBackend::File(file) = &*backend else {
            panic!("native Linux factory selected a non-Linux backend")
        };
        let mut exclusive = 0;
        // SAFETY: TIOCGEXCL writes one integer for this live local PTY fd.
        assert_eq!(
            unsafe { libc::ioctl(file.raw_fd(), libc::TIOCGEXCL, &mut exclusive) },
            0
        );
        assert_eq!(exclusive, 1);
        drop(backend);
        let absent = format!("/dcent-test-absent-uart-{}", std::process::id());
        let direct = crate::serial::SerialChain::open(&absent, 115200)
            .err()
            .unwrap()
            .to_string();
        let native = SerialChainBackend::open_native_linux_only(0, &absent, 115200)
            .err()
            .unwrap()
            .to_string();
        assert_eq!(
            native, direct,
            "must preserve Linux failure without AM2 fallback"
        );
    }

    #[test]
    fn fresh_rx_flush_preserves_unread_queued_tx_and_clears_both_rx_layers() {
        use std::io::{Read, Write};
        use std::os::fd::AsRawFd;
        use std::time::{Duration, Instant};
        let (serial, mut master, slave) = bounded_owner_pty();
        // Seed stale input independently of the parser's already retained body.
        master
            .write_all(&[0xaa, 0x55, 1, 2, 3, 4, 5, 6, 7])
            .unwrap();
        let mut input = libc::pollfd {
            fd: slave.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live local PTY descriptor and one initialized pollfd.
        assert_eq!(unsafe { libc::poll(&mut input, 1, 1_000) }, 1);
        serial.rx_buf.lock().unwrap().retained.push_back(vec![9; 7]);

        // Fill TX until actual backpressure while the peer reads nothing.
        // This makes queued-output preservation observable, without a sleep.
        let bytes: Vec<u8> = (0..65_536).map(|index| index as u8).collect();
        let sent = {
            let mut backend = serial.serial.lock().unwrap();
            let super::UartBackend::File(file) = &mut *backend else {
                panic!("PTY must be file backed")
            };
            let flags = file.begin_bounded_io().unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut sent = 0;
            while sent < bytes.len() {
                assert!(Instant::now() < deadline);
                let count = file.try_write_bounded(&bytes[sent..]).unwrap();
                if count == 0 {
                    break;
                }
                sent += count;
            }
            file.restore_io_flags(flags).unwrap();
            assert!(
                sent > 0 && sent < bytes.len(),
                "expected real TX backpressure"
            );
            sent
        };
        serial.flush_rx().unwrap();
        assert_eq!(serial.rx_observation().buffered_bytes, 0);
        assert!(serial.rx_buf.lock().unwrap().retained.is_empty());
        input.revents = 0;
        // SAFETY: same owned local descriptor; zero timeout is a read-only poll.
        assert_eq!(unsafe { libc::poll(&mut input, 1, 0) }, 0);

        let deadline = Instant::now() + Duration::from_secs(1);
        let mut observed = vec![0; sent];
        let mut received = 0;
        while received < sent {
            assert!(Instant::now() < deadline, "RX flush discarded committed TX");
            let mut output = libc::pollfd {
                fd: master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one initialized poll descriptor for the owned PTY peer.
            assert_eq!(unsafe { libc::poll(&mut output, 1, 100) }, 1);
            received += master.read(&mut observed[received..]).unwrap();
        }
        assert_eq!(observed, bytes[..sent]);
        serial.send_get_address_bm1397plus().unwrap();
        let mut query = [0; 7];
        master.read_exact(&mut query).unwrap();
        assert_eq!(&query[..6], &[0x55, 0xaa, 0x52, 5, 0, 0]);
    }

    #[test]
    fn bounded_register_owner_restores_flags_and_retains_nonces_on_error_and_unwind() {
        use std::time::{Duration, Instant};
        let (mut serial, _master, _slave) = bounded_owner_pty();
        let flags = owner_file_flags(&serial);
        let result: crate::Result<()> = serial.with_bounded_response_io(
            Instant::now() + Duration::from_secs(1),
            &|| false,
            |io| {
                io.retain_nonce(vec![1; 7])?;
                io.retain_nonce(vec![2; 7])?;
                Err(crate::HalError::Platform("injected failure".into()))
            },
        );
        assert!(result.is_err());
        assert_eq!(owner_file_flags(&serial), flags);
        assert_eq!(serial.read_response_timeout(0).unwrap(), Some(vec![1; 7]));
        assert_eq!(serial.read_response_timeout(0).unwrap(), Some(vec![2; 7]));
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: crate::Result<()> = serial.with_bounded_response_io(
                Instant::now() + Duration::from_secs(1),
                &|| false,
                |io| {
                    io.retain_nonce(vec![3; 7])?;
                    panic!("injected owner unwind");
                },
            );
        }));
        assert!(panic.is_err());
        assert_eq!(owner_file_flags(&serial), flags);
        assert_eq!(serial.read_response_timeout(0).unwrap(), Some(vec![3; 7]));
    }

    #[test]
    fn bounded_register_owner_stops_unread_pty_tx_at_total_deadline() {
        use std::time::{Duration, Instant};
        let (mut serial, _master, _slave) = bounded_owner_pty();
        let flags = owner_file_flags(&serial);
        let started = Instant::now();
        let result: crate::Result<()> =
            serial.with_bounded_response_io(started + Duration::from_millis(30), &|| false, |io| {
                // The peer never drains TX. A blocking write_all here would
                // hang indefinitely once the PTY output queue fills.
                loop {
                    io.send_command(&[0x42, 0x05, 0, 8])?;
                }
            });
        assert!(result.unwrap_err().to_string().contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(owner_file_flags(&serial), flags);
    }

    #[test]
    fn bounded_register_owner_retention_limit_preserves_terminal_nonce() {
        use std::time::{Duration, Instant};
        let (mut serial, _master, _slave) = bounded_owner_pty();
        let result: crate::Result<()> = serial.with_bounded_response_io(
            Instant::now() + Duration::from_secs(1),
            &|| false,
            |io| {
                for index in 0..257_u16 {
                    let mut nonce = vec![0; 7];
                    nonce[..2].copy_from_slice(&index.to_be_bytes());
                    io.retain_nonce(nonce)?;
                }
                panic!("retention must terminate the conversation at its limit");
            },
        );
        assert!(result.unwrap_err().to_string().contains("retention full"));
        for index in 0..257_u16 {
            let body = serial.read_response_timeout(0).unwrap().unwrap();
            assert_eq!(&body[..2], &index.to_be_bytes());
        }
        assert_eq!(serial.read_response_timeout(0).unwrap(), None);
        serial.set_response_len(super::BM1387_RESP_BODY_LEN);
        assert!(serial
            .with_bounded_response_io(Instant::now() + Duration::from_secs(1), &|| false, |_| Ok(
                ()
            ))
            .is_err());
    }

    #[test]
    fn bounded_register_owner_cancellation_prevents_following_write() {
        use std::io::Read;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};
        let (mut serial, mut master, _slave) = bounded_owner_pty();
        let stopped = AtomicBool::new(false);
        let result: crate::Result<()> = serial.with_bounded_response_io(
            Instant::now() + Duration::from_secs(1),
            &|| stopped.load(Ordering::Relaxed),
            |io| {
                io.send_command(&[0x42, 0x05, 0, 8])?;
                stopped.store(true, Ordering::Relaxed);
                io.send_command(&[0x51, 0x09, 0, 0x28, 0x11, 0x30, 0, 0])
            },
        );
        assert!(result.unwrap_err().to_string().contains("cancelled"));
        let mut frame = [0; 7];
        master.read_exact(&mut frame).unwrap();
        assert_eq!(&frame[..6], &[0x55, 0xaa, 0x42, 0x05, 0, 8]);
    }

    // -----------------------------------------------------------------------
    // RxBuffer::try_extract_frame — the byte-stream frame assembler shared by
    // BOTH gating chips (BM1387 / BM1362 via SerialChainBackend). Ported from
    // the `rx_buffer_*` tests on the default-OFF FPGA twin
    // (`fpga_chain_backend.rs`), adapted to this struct's API
    // (`try_extract_frame` / `clear`) and per-chip `resp_body_len`.
    //
    // resp_body_len contract (pinned from the code, after the 2-byte preamble):
    //   BM1387  -> 5 bytes  (BM1387_RESP_BODY_LEN)
    //   BM139X  -> 7 bytes  (BM139X_RESP_BODY_LEN; also DEFAULT_RESP_BODY_LEN)
    // -----------------------------------------------------------------------

    /// Pin the per-chip response body lengths so a silent constant change is
    /// caught — these drive every frame extraction below and on live hardware.
    #[test]
    fn resp_body_len_constants_are_pinned_per_chip() {
        assert_eq!(BM1387_RESP_BODY_LEN, 5, "BM1387 response body is 5 bytes");
        assert_eq!(BM139X_RESP_BODY_LEN, 7, "BM139X response body is 7 bytes");
        assert_eq!(
            DEFAULT_RESP_BODY_LEN, BM139X_RESP_BODY_LEN,
            "default body length must match BM139X (7)"
        );
        assert_eq!(
            BM1366_UART_RESP_BODY_LEN, 9,
            "BM1366 UART body is 9 (11-byte wire); not HAL default 7"
        );
        assert_ne!(DEFAULT_RESP_BODY_LEN, BM1366_UART_RESP_BODY_LEN);
        let src = include_str!("serial_chain.rs");
        assert!(src.contains("fn open_passthrough_bm1366"));
        assert!(src.contains("set_response_len(BM1366_UART_RESP_BODY_LEN)"));
        assert!(src.contains("fn require_bm1366_response_body"));
        assert!(src.contains("fn response_body_len"));
        assert!(src.contains("S19k/BM1366 uses an 11-byte wire response"));
        // 2026-08-28 C1 convergence fix: this fence is scoped to the
        // PRODUCTION source only. As written (whole-file `src.contains`) it
        // was self-referential — the retired blanket "all BM136x chips send
        // 9-byte responses" doc sentence matched the assert's own literal, so
        // the test failed from the moment it landed no matter what production
        // said. The fence's intent — that the retired blanket claim stays out
        // of production docs — is preserved by the split below.
        let production = src
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("production source");
        assert!(
            !production.contains("BM1362/BM1366/BM1368/BM1370 chips send 9-byte nonce responses")
        );
    }

    /// (a) A complete BM139X (7-byte body) frame at the correct length is
    /// extracted, skipping leading noise and leaving trailing noise behind.
    #[test]
    fn rx_buffer_extracts_complete_bm139x_frame_skipping_noise() {
        let mut rx = RxBuffer::new();
        // noise + preamble + 7-byte body + trailing noise.
        rx.push(&[0xFF, 0x00]);
        rx.push(&[0xAA, 0x55]);
        rx.push(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        rx.push(&[0xDE, 0xAD]);

        let mut out = [0u8; BM139X_RESP_BODY_LEN];
        let n = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out);
        assert_eq!(n, BM139X_RESP_BODY_LEN);
        assert_eq!(out, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    /// (a') A complete BM1387 (5-byte body) frame at the BM1387 length is
    /// extracted — pins the second gating chip's shorter body.
    #[test]
    fn rx_buffer_extracts_complete_bm1387_frame() {
        let mut rx = RxBuffer::new();
        rx.push(&[0xAA, 0x55, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5]); // preamble + 5-byte body

        let mut out = [0u8; BM1387_RESP_BODY_LEN];
        let n = rx.try_extract_frame(BM1387_RESP_BODY_LEN, &mut out);
        assert_eq!(n, BM1387_RESP_BODY_LEN);
        assert_eq!(out, [0xA1, 0xB2, 0xC3, 0xD4, 0xE5]);
    }

    /// BM1366 11-byte wire (`AA 55` + 9). Track-1 GetAddress / nonce hunt.
    #[test]
    fn rx_buffer_extracts_complete_bm1366_frame() {
        let mut rx = RxBuffer::new();
        rx.push(&[
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x10,
        ]);
        let mut out = [0u8; BM1366_UART_RESP_BODY_LEN];
        let n = rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut out);
        assert_eq!(n, BM1366_UART_RESP_BODY_LEN);
        assert_eq!(out, [0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x10]);
        assert_eq!(rx.len, 0);
    }

    /// Body-7 on an 11-byte BM1366 wire cuts version+trailer off. Not Silence.
    #[test]
    fn rx_buffer_body7_on_bm1366_wire_leaves_trailer() {
        let wire = [
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x10,
        ];
        let mut rx = RxBuffer::new();
        rx.push(&wire);
        let mut out7 = [0u8; BM139X_RESP_BODY_LEN];
        let n7 = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out7);
        assert_eq!(n7, BM139X_RESP_BODY_LEN);
        assert_eq!(out7, [0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00]);
        assert_eq!(rx.len, 2, "version+trailer must remain after body-7 cut");
        let mut out9 = [0u8; BM1366_UART_RESP_BODY_LEN];
        assert_eq!(
            rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut out9),
            0
        );
    }

    /// `set_response_len(11)` hunts a 13-byte frame. Incomplete on 11-byte wire.
    #[test]
    fn rx_buffer_body11_on_bm1366_wire_is_incomplete() {
        let mut rx = RxBuffer::new();
        rx.push(&[
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x10,
        ]);
        let mut out = [0u8; 11];
        assert_eq!(rx.try_extract_frame(11, &mut out), 0);
        assert_eq!(rx.len, 11);
    }

    /// Two back-to-back ChipAddress frames extract as two 9-byte bodies.
    #[test]
    fn rx_buffer_two_bm1366_frames() {
        let mut rx = RxBuffer::new();
        rx.push(&[
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ]);
        rx.push(&[
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x10,
        ]);
        let mut a = [0u8; BM1366_UART_RESP_BODY_LEN];
        let mut b = [0u8; BM1366_UART_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut a), 9);
        assert_eq!(rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut b), 9);
        assert_eq!(a[3], 0x00);
        assert_eq!(b[3], 0x02);
        assert_eq!(rx.len, 0);
    }

    #[test]
    fn rx_buffer_rejects_crc_bad_bm1366_candidate_then_recovers_valid_frame() {
        let mut bad = [
            0xAA, 0x55, 0x13, 0x66, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x10,
        ];
        bad[4] ^= 0x01;
        let good = [
            0xAA, 0x55, 0x40, 0x1B, 0x16, 0x52, 0x00, 0x4F, 0x66, 0x5F, 0x8D,
        ];
        let mut rx = RxBuffer::new();
        rx.push(&bad);
        rx.push(&good);
        let mut out = [0u8; BM1366_UART_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut out), 9);
        assert_eq!(out, good[2..]);
        assert_eq!(rx.crc_rejected, 1);
        assert_eq!(rx.len, 0);
    }

    #[test]
    fn rx_buffer_crc_resync_preserves_overlapping_valid_preamble() {
        let good = [
            0xAA, 0x55, 0x22, 0x4E, 0x64, 0xC8, 0x00, 0x48, 0x72, 0xC0, 0x90,
        ];
        let mut overlapped = vec![0xAA, 0x55];
        overlapped.extend_from_slice(&good);
        let mut rx = RxBuffer::new();
        rx.push(&overlapped);
        let mut out = [0u8; BM1366_UART_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut out), 9);
        assert_eq!(out, good[2..]);
        assert_eq!(rx.crc_rejected, 1);
        assert_eq!(rx.len, 0);
    }

    /// Mid-stream body-len change: extract(7) of first 11-byte wire, then
    /// extract(9) after the next 11-byte wire is pushed. Recovers the next
    /// frame. First cut stays 7 bytes.
    #[test]
    fn rx_buffer_body7_then_body9_recovers_next() {
        let first = [
            0xAA, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x80,
        ];
        let next = [
            0xAA, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x9F,
        ];
        let mut rx = RxBuffer::new();
        rx.push(&first);
        let mut cut7 = [0u8; BM139X_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut cut7), 7);
        assert_eq!(cut7, [0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00]);
        assert_eq!(rx.len, 2);
        rx.push(&next);
        assert_eq!(rx.len, 13);
        let mut rec9 = [0u8; BM1366_UART_RESP_BODY_LEN];
        assert_eq!(
            rx.try_extract_frame(BM1366_UART_RESP_BODY_LEN, &mut rec9),
            9
        );
        assert_eq!(rec9, next[2..]);
        assert_eq!(rx.len, 0);
    }

    /// Fuzz: the ASIC-nonce framing layer must NEVER panic and must stay
    /// memory-bounded for ANY adversarial byte stream — flaky chip, UART line
    /// noise, truncated frames, preamble floods, all-zero — at any body length.
    /// This is the shared RX framing for the S9/S17/S19/S21 serial-chain nonce
    /// path; it now carries the same never-panics guarantee the pool-message,
    /// cgminer-command, and BM1362 serial-nonce parsers already have. A flaky
    /// chip streaming garbage is untrusted input just like a hostile pool.
    #[test]
    fn try_extract_frame_never_panics_and_stays_bounded_on_arbitrary_input() {
        // Deterministic LCG — no RNG dependency (matches the other fuzz pins).
        let mut lcg: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (lcg >> 33) as u32
        };
        for body_len in [1usize, BM1387_RESP_BODY_LEN, BM139X_RESP_BODY_LEN, 32] {
            let mut rx = RxBuffer::new();
            let mut out = vec![0u8; body_len];
            for _ in 0..4000 {
                let choice = next() % 4;
                let chunk_len = (next() % 300) as usize;
                let mut chunk = Vec::with_capacity(chunk_len);
                for j in 0..chunk_len {
                    chunk.push(match choice {
                        0 => (next() & 0xFF) as u8, // random noise
                        1 if j % 2 == 0 => 0xAA,    // preamble flood
                        1 => 0x55,
                        2 => 0xAA, // half-preamble spam
                        _ => 0x00, // all-zero
                    });
                }
                rx.push(&chunk);
                // Drain every complete frame; each must respect the output cap.
                loop {
                    let n = rx.try_extract_frame(body_len, &mut out);
                    assert!(
                        n <= body_len.min(out.len()),
                        "extracted {n} > cap {} (body_len {body_len})",
                        body_len.min(out.len())
                    );
                    if n == 0 {
                        break;
                    }
                }
                // Memory-bounded: after a full drain the buffer holds at most a
                // single incomplete frame (< preamble + body), never the whole
                // chunk backlog — so a garbage flood can't OOM the daemon.
                assert!(
                    rx.len < 2 + body_len,
                    "rx buffer grew to {} bytes (>= frame_len {}) — unbounded backlog",
                    rx.len,
                    2 + body_len
                );
            }
        }
    }

    /// (b) An incomplete buffer (preamble at i==0 but fewer than a full frame
    /// of bytes) extracts nothing and RETAINS the bytes; once the rest of the
    /// body arrives the next call extracts the complete frame.
    #[test]
    fn rx_buffer_returns_zero_for_incomplete_frame_and_retains_bytes() {
        let mut rx = RxBuffer::new();
        rx.push(&[0xAA, 0x55, 0x11, 0x22]); // preamble + only 2 of 7 body bytes
        let mut out = [0u8; BM139X_RESP_BODY_LEN];
        let n = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out);
        assert_eq!(n, 0, "incomplete frame must not extract");

        // Bytes were retained — completing the body extracts on the next call.
        rx.push(&[0x33, 0x44, 0x55, 0x66, 0x77]);
        let n = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out);
        assert_eq!(n, BM139X_RESP_BODY_LEN);
        assert_eq!(out, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    /// (b') A buffer with no preamble at all extracts nothing and does not panic
    /// (it keeps only the trailing byte as a possible split-preamble start).
    #[test]
    fn rx_buffer_no_preamble_extracts_nothing() {
        let mut rx = RxBuffer::new();
        rx.push(&[0x01, 0x02, 0x03, 0x04, 0x05]); // pure noise, no 0xAA 0x55
        let mut out = [0u8; BM139X_RESP_BODY_LEN];
        let n = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out);
        assert_eq!(n, 0, "no preamble => no frame");
    }

    /// (c) `out` shorter than the body must not over-read or panic: only
    /// `out.len()` bytes are copied, and exactly one full frame is consumed
    /// from the buffer (so the next frame still extracts cleanly).
    #[test]
    fn rx_buffer_out_shorter_than_body_does_not_over_read() {
        let mut rx = RxBuffer::new();
        // Frame 1 (7-byte body) then frame 2 (7-byte body).
        rx.push(&[0xAA, 0x55, 1, 2, 3, 4, 5, 6, 7]);
        rx.push(&[0xAA, 0x55, 8, 9, 10, 11, 12, 13, 14]);

        // out only has room for 3 bytes although body_len is 7.
        let mut out = [0u8; 3];
        let n = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out);
        assert_eq!(n, 3, "copy is clamped to out.len()");
        assert_eq!(out, [1, 2, 3]);

        // The full first frame was consumed; the second frame is intact.
        let mut out_full = [0u8; BM139X_RESP_BODY_LEN];
        let n = rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out_full);
        assert_eq!(n, BM139X_RESP_BODY_LEN);
        assert_eq!(out_full, [8, 9, 10, 11, 12, 13, 14]);
    }

    /// (d) Multiple frames concatenated are extracted one per call, with the
    /// buffer drained (returns 0) once no complete frame remains.
    #[test]
    fn rx_buffer_handles_back_to_back_frames_then_drains() {
        let mut rx = RxBuffer::new();
        rx.push(&[0xAA, 0x55, 1, 2, 3, 4, 5, 6, 7]);
        rx.push(&[0xAA, 0x55, 8, 9, 10, 11, 12, 13, 14]);

        let mut out = [0u8; BM139X_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out), 7);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out), 7);
        assert_eq!(out, [8, 9, 10, 11, 12, 13, 14]);
        assert_eq!(
            rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out),
            0,
            "buffer drained: no further complete frame"
        );
    }

    /// (d') Leftover bytes after a complete frame are retained and assembled
    /// once the rest of the trailing frame arrives across a later push.
    #[test]
    fn rx_buffer_retains_leftover_after_extract() {
        let mut rx = RxBuffer::new();
        // One full frame followed by the start of a second frame.
        rx.push(&[0xAA, 0x55, 1, 2, 3, 4, 5, 6, 7, 0xAA, 0x55, 8, 9]);

        let mut out = [0u8; BM139X_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out), 7);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7]);

        // Partial second frame: nothing yet, bytes retained.
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out), 0);

        // Complete the second frame -> it now extracts.
        rx.push(&[10, 11, 12, 13, 14]);
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out), 7);
        assert_eq!(out, [8, 9, 10, 11, 12, 13, 14]);
    }

    /// `clear()` discards all buffered data so a stale partial frame cannot
    /// cross into a fresh read cycle (used by `flush_io`).
    #[test]
    fn rx_buffer_clear_discards_partial_frame() {
        let mut rx = RxBuffer::new();
        rx.push(&[0xAA, 0x55, 1, 2, 3]); // partial frame
        rx.clear();
        rx.push(&[0xAA, 0x55, 1, 2, 3, 4, 5, 6, 7]);
        let mut out = [0u8; BM139X_RESP_BODY_LEN];
        assert_eq!(rx.try_extract_frame(BM139X_RESP_BODY_LEN, &mut out), 7);
        assert_eq!(out, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn beaglebone_ttyo_paths_never_require_devmem() {
        for device in ["/dev/ttyO1", "/dev/ttyO2", "/dev/ttyO4", "/dev/ttyO5"] {
            assert!(
                !SerialChainBackend::needs_devmem(device),
                "{} must stay on the kernel omap-serial path",
                device
            );
        }
    }

    #[test]
    fn amlogic_ttys_do_not_require_devmem_without_zynq_uio() {
        for device in ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS4"] {
            assert!(
                !SerialChainBackend::needs_devmem_with_uio_presence(device, false),
                "{} must stay on the kernel meson_uart path when no Zynq UIO exists",
                device
            );
        }
    }

    #[test]
    fn zynq_pl_ttys_still_require_devmem_when_uio_exists() {
        for device in ["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3", "/dev/ttyS4"] {
            assert!(
                SerialChainBackend::needs_devmem_with_uio_presence(device, true),
                "{} must keep the Zynq PL UART devmem bypass when UIO exists",
                device
            );
        }
    }

    #[test]
    fn live_x19_uio_names_mark_zynq_even_without_uio0() {
        for name in [
            "chain2-common",
            "chain2-cmd-rx",
            "chain4-work-tx",
            "fan-control",
            "board-control",
            "miner-glitch-monitor",
        ] {
            assert!(
                SerialChainBackend::uio_name_marks_zynq(name),
                "{} must mark the X19 AM2 Zynq UIO topology",
                name
            );
        }
    }

    #[test]
    fn unrelated_uio_names_do_not_mark_zynq() {
        for name in ["", "uio_pdrv_genirq", "gpiochip", "i2c-controller"] {
            assert!(
                !SerialChainBackend::uio_name_marks_zynq(name),
                "{} must not force the Zynq PL UART devmem bypass",
                name
            );
        }
    }

    #[test]
    fn zynq_platform_markers_enable_uio_node_fallback() {
        for marker in [
            "zynq-bm3-am2",
            "am2-s19jpro-zynq",
            "am2-s19j",
            "xlnx,zynq-7000",
        ] {
            assert!(
                SerialChainBackend::platform_marker_text_marks_zynq_am2(marker),
                "{} must allow the rescue-image UIO node fallback",
                marker
            );
        }
    }

    #[test]
    fn non_zynq_platform_markers_do_not_enable_uio_node_fallback() {
        for marker in ["am3-bb", "amlogic-a113d-s21", "cv1835-s19jpro", ""] {
            assert!(
                !SerialChainBackend::platform_marker_text_marks_zynq_am2(marker),
                "{} must not force the Zynq PL UART devmem bypass",
                marker
            );
        }
    }
}

#[path = "serial_chain_raw_io.rs"]
mod raw_io;
pub use raw_io::{RawIoStatus, RawReadAttempt, RawWriteAttempt};

pub use crate::serial::tx_observation::{BackendKind, Reading, TxDrainAttempt};

#[path = "serial_chain_baud_transition.rs"]
mod baud_transition;
pub use crate::serial::baud_transition::{
    BaudTransitionAttempt, EnumerationBaudAttempt, NativeBbBaud,
};
