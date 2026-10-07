//! Correlated BM1397+ register conversations on an existing transport owner.
//!
//! Layout/CRC authority: contracts/asic-wire/v1/bm13xx-response-crc5.json,
//! independently sniffed BM1397 and our BM1362 UART captures. FPGA packing:
//! held Braiins `braiins_io.rs::recv_response` and `bm13xx_core.vhd`
//! st_write_cmd1/2 (two LE FIFO words, padding before the CRC). No BM1387
//! caller is supported. Correlation proves
//! chip/register/type/CRC, not temporal uniqueness: this wire has no request
//! ID and cannot distinguish a late identical reply after an earlier read.

use crate::protocol::bm13xx_command_response_crc5;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterResponseLayout {
    Body7,
    Body9,
}

impl RegisterResponseLayout {
    pub const fn body_len(self) -> usize {
        match self {
            Self::Body7 => 7,
            Self::Body9 => 9,
        }
    }
    pub fn from_body_len(len: usize) -> Option<Self> {
        match len {
            7 => Some(Self::Body7),
            9 => Some(Self::Body9),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterReply {
    pub chip_address: u8,
    pub register_address: u8,
    pub value: u32,
}

/// Braiins RTL st_write_cmd2 emits `response(6) & 00 & response(5) &
/// response(4)`: the CRC occupies the HIGH byte, not the third byte.
/// Source: held zynq-io-am1-s9-braiins bm13xx_core.vhd:1019-1034.
pub fn braiins_command_fifo_body(words: [u32; 2]) -> Option<Vec<u8>> {
    let metadata = words[1].to_le_bytes();
    if metadata[2] != 0 {
        return None;
    }
    let mut body = words[0].to_le_bytes().to_vec();
    body.extend([metadata[0], metadata[1], metadata[3]]);
    Some(body)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseKind {
    Register(RegisterReply),
    Nonce,
    Invalid,
}

pub fn classify_response(body: &[u8], layout: RegisterResponseLayout) -> ResponseKind {
    if body.len() != layout.body_len() {
        return ResponseKind::Invalid;
    }
    let trailer = body[body.len() - 1];
    if trailer & 0x60 != 0 {
        return ResponseKind::Invalid;
    }
    if trailer & 0x80 != 0 {
        // The held BM136x nine-byte job captures falsify applying the
        // seven-byte RTL payload init to their extended response layout.
        // Use the established full-body remainder for this UART dialect.
        let valid = match layout {
            RegisterResponseLayout::Body9 => crate::protocol::crc5(body) == 0,
            RegisterResponseLayout::Body7 => {
                crate::protocol::bm13xx_job_response_crc5(&body[..6]) == trailer & 0x1f
            }
        };
        return if valid {
            ResponseKind::Nonce
        } else {
            ResponseKind::Invalid
        };
    }
    if bm13xx_command_response_crc5(&body[..body.len() - 1]) != trailer & 0x1f
        || (layout == RegisterResponseLayout::Body9 && body[6..8] != [0, 0])
    {
        return ResponseKind::Invalid;
    }
    ResponseKind::Register(RegisterReply {
        value: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
        chip_address: body[4],
        register_address: body[5],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterTransactionError {
    Deadline,
    Cancelled,
    Transport,
}

/// Each method is nonblocking or must honor `deadline`, including send and
/// drain. Implementations retain unsolicited nonces for their normal consumer.
/// The exclusive borrow covers the whole transaction, not one packet at a time.
pub trait RegisterConversationIo {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn cancelled(&self) -> bool;
    fn poll(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>, RegisterTransactionError>;
    fn send_read(
        &mut self,
        chip: u8,
        register: u8,
        deadline: Instant,
    ) -> Result<(), RegisterTransactionError>;
    fn retain_nonce(&mut self, body: Vec<u8>) -> Result<(), RegisterTransactionError>;
    fn idle(&mut self) {
        std::thread::yield_now();
    }
}

fn check(
    io: &impl RegisterConversationIo,
    deadline: Instant,
) -> Result<(), RegisterTransactionError> {
    if io.cancelled() {
        Err(RegisterTransactionError::Cancelled)
    } else if io.now() >= deadline {
        Err(RegisterTransactionError::Deadline)
    } else {
        Ok(())
    }
}

/// Drain currently available stale replies then request one register. All
/// invalid/mismatched traffic consumes the SAME total budget; never reset a
/// quiet timeout on noise. No automatic retry can conceal partial transport TX.
pub fn read_register(
    io: &mut impl RegisterConversationIo,
    layout: RegisterResponseLayout,
    chip: u8,
    register: u8,
    deadline: Instant,
) -> Result<RegisterReply, RegisterTransactionError> {
    loop {
        check(io, deadline)?;
        let body = io.poll(deadline)?;
        if let Some(body) = body {
            if classify_response(&body, layout) == ResponseKind::Nonce {
                io.retain_nonce(body)?;
            }
            check(io, deadline)?;
        } else {
            break;
        }
    }
    check(io, deadline)?;
    io.send_read(chip, register, deadline)?;
    loop {
        check(io, deadline)?;
        match io.poll(deadline)? {
            Some(body) => match classify_response(&body, layout) {
                ResponseKind::Register(reply) => {
                    check(io, deadline)?;
                    if reply.chip_address == chip && reply.register_address == register {
                        return Ok(reply);
                    }
                }
                ResponseKind::Nonce => {
                    io.retain_nonce(body)?;
                    check(io, deadline)?;
                }
                ResponseKind::Invalid => check(io, deadline)?,
            },
            None => {
                check(io, deadline)?;
                io.idle();
            }
        }
    }
}

impl RegisterConversationIo for dcentrald_hal::serial_chain::BoundedSerialResponseIo<'_> {
    fn cancelled(&self) -> bool {
        self.is_cancelled()
    }
    fn poll(&mut self, _: Instant) -> Result<Option<Vec<u8>>, RegisterTransactionError> {
        self.poll_response().map_err(|_| serial_failure(self))
    }
    fn send_read(
        &mut self,
        chip: u8,
        register: u8,
        _: Instant,
    ) -> Result<(), RegisterTransactionError> {
        self.send_command(&[0x42, 0x05, chip, register])
            .map_err(|_| serial_failure(self))
    }
    fn retain_nonce(&mut self, body: Vec<u8>) -> Result<(), RegisterTransactionError> {
        self.retain_nonce(body)
            .map_err(|_| RegisterTransactionError::Transport)
    }
}

fn serial_failure(
    io: &dcentrald_hal::serial_chain::BoundedSerialResponseIo<'_>,
) -> RegisterTransactionError {
    if io.is_cancelled() {
        RegisterTransactionError::Cancelled
    } else if Instant::now() >= io.deadline() {
        RegisterTransactionError::Deadline
    } else {
        RegisterTransactionError::Transport
    }
}

/// Model/register-specific comparison only. Write values remain unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterReadbackExpectation {
    expected: u32,
    mask: u32,
}

impl RegisterReadbackExpectation {
    pub fn for_write(chip_id: u16, register: u8, written: u32) -> Option<Self> {
        if !matches!(chip_id, 0x1362 | 0x1366 | 0x1368 | 0x1370 | 0x1397 | 0x1398) {
            return None;
        }
        match register {
            // PLL readback must report locked; don't confuse status with data.
            0x08 => Some(Self {
                expected: written | 0x8000_0000,
                mask: u32::MAX,
            }),
            // BM1370 0x9000FFFF -> 0x8000FFFF was measured during bring-up;
            // ignore only the observed non-round-tripping bit, never mask the
            // version mask or blindly clear gen-code bits in a write.
            0xa4 if chip_id == 0x1370 && written & 0x3000_0000 == 0x1000_0000 => Some(Self {
                expected: written,
                mask: !0x1000_0000,
            }),
            0x14 | 0x18 | 0xa4 => Some(Self {
                expected: written,
                mask: u32::MAX,
            }),
            _ => None,
        }
    }
    pub const fn matches(self, observed: u32) -> bool {
        (observed & self.mask) == (self.expected & self.mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::time::Duration;

    struct FakeIo {
        now: Instant,
        cancelled: bool,
        sent: usize,
        delay_send: Duration,
        before: VecDeque<Vec<u8>>,
        after: VecDeque<Vec<u8>>,
        retained: Vec<Vec<u8>>,
        cancel_after_send: bool,
    }
    impl FakeIo {
        fn new() -> Self {
            Self {
                now: Instant::now(),
                cancelled: false,
                sent: 0,
                delay_send: Duration::ZERO,
                before: VecDeque::new(),
                after: VecDeque::new(),
                retained: Vec::new(),
                cancel_after_send: false,
            }
        }
    }
    impl RegisterConversationIo for FakeIo {
        fn now(&self) -> Instant {
            self.now
        }
        fn cancelled(&self) -> bool {
            self.cancelled
        }
        fn poll(&mut self, _: Instant) -> Result<Option<Vec<u8>>, RegisterTransactionError> {
            self.now += Duration::from_millis(1);
            Ok(if self.sent == 0 {
                self.before.pop_front()
            } else {
                self.after.pop_front()
            })
        }
        fn send_read(&mut self, _: u8, _: u8, _: Instant) -> Result<(), RegisterTransactionError> {
            self.sent += 1;
            self.now += self.delay_send;
            self.cancelled |= self.cancel_after_send;
            Ok(())
        }
        fn retain_nonce(&mut self, body: Vec<u8>) -> Result<(), RegisterTransactionError> {
            self.retained.push(body);
            Ok(())
        }
        fn idle(&mut self) {
            self.now += Duration::from_millis(1);
        }
    }
    fn body(chip: u8, reg: u8, value: u32, extended: bool) -> Vec<u8> {
        let mut b = value.to_be_bytes().to_vec();
        b.extend([chip, reg]);
        if extended {
            b.extend([0, 0]);
        }
        b.push(bm13xx_command_response_crc5(&b));
        b
    }
    fn nonce() -> Vec<u8> {
        // Independent BM1370 Bitaxe capture from REFERENCE.md:770; the
        // trailer is captured, not manufactured by the validator under test.
        vec![0x18, 0, 0xa6, 0x40, 2, 0x99, 0x22, 0xf9, 0x91]
    }

    #[test]
    fn register_capture_layouts_match_held_independent_vectors() {
        for (wire, layout, chip, value) in [
            (
                vec![0x13, 0x97, 0x18, 0, 0, 0, 6],
                RegisterResponseLayout::Body7,
                0,
                0x13971800,
            ),
            (
                vec![0x13, 0x62, 3, 0xca, 0xca, 0, 0, 0, 8],
                RegisterResponseLayout::Body9,
                0xca,
                0x136203ca,
            ),
        ] {
            assert_eq!(
                classify_response(&wire, layout),
                ResponseKind::Register(RegisterReply {
                    chip_address: chip,
                    register_address: 0,
                    value
                })
            );
            let mut bad = wire.clone();
            bad[0] ^= 1;
            assert_eq!(classify_response(&bad, layout), ResponseKind::Invalid);
        }
        assert_eq!(RegisterResponseLayout::from_body_len(5), None);
        for mut job in [
            nonce(),
            vec![0x40, 0x1b, 0x16, 0x52, 0, 0x4f, 0x66, 0x5f, 0x8d],
        ] {
            // Second body is held S19k .88 UART capture, not an invented
            // trailer. Neither fixture authorizes changing its attribution.
            assert_eq!(
                classify_response(&job, RegisterResponseLayout::Body9),
                ResponseKind::Nonce
            );
            job[0] ^= 1;
            assert_eq!(
                classify_response(&job, RegisterResponseLayout::Body9),
                ResponseKind::Invalid
            );
        }
    }

    #[test]
    fn register_fifo_fixture_uses_rtl_padding_before_high_byte_crc() {
        // Independent BM1397 sniff payload/trailer, packed by held RTL.
        let body = braiins_command_fifo_body([0x0018_9713, 0x0600_0000]).unwrap();
        assert_eq!(body, [0x13, 0x97, 0x18, 0, 0, 0, 6]);
        assert!(matches!(
            classify_response(&body, RegisterResponseLayout::Body7),
            ResponseKind::Register(_)
        ));
        assert!(braiins_command_fifo_body([0x0018_9713, 0x0006_0000]).is_none());
    }

    #[test]
    fn register_transaction_preserves_nonces_and_rejects_stale_wrong_chip_register_and_crc() {
        let mut io = FakeIo::new();
        io.before.extend([body(2, 0x60, 1, true), nonce()]);
        let mut corrupt = body(2, 0x60, 6, true);
        corrupt[8] ^= 1;
        io.after.extend([
            body(4, 0x60, 2, true),
            nonce(),
            body(2, 0x28, 3, true),
            corrupt,
            body(2, 0x60, 7, true),
        ]);
        let deadline = io.now + Duration::from_millis(50);
        assert_eq!(
            read_register(&mut io, RegisterResponseLayout::Body9, 2, 0x60, deadline)
                .unwrap()
                .value,
            7
        );
        assert_eq!(io.retained, vec![nonce(), nonce()]);
        assert_eq!(io.sent, 1);
    }

    #[test]
    fn register_total_deadline_covers_stale_drain_send_and_noise() {
        for phase in 0..3 {
            let mut io = FakeIo::new();
            match phase {
                0 => io.before.extend((0..50).map(|_| body(0, 0, 1, false))),
                1 => io.delay_send = Duration::from_millis(30),
                _ => io.after.extend((0..50).map(|_| body(1, 1, 1, false))),
            }
            let deadline = io.now + Duration::from_millis(10);
            assert_eq!(
                read_register(&mut io, RegisterResponseLayout::Body7, 2, 8, deadline),
                Err(RegisterTransactionError::Deadline)
            );
            assert_eq!(io.sent, usize::from(phase != 0));
        }
    }

    #[test]
    fn register_cancellation_before_and_after_send_is_terminal() {
        for before in [true, false] {
            let mut io = FakeIo::new();
            io.cancelled = before;
            io.cancel_after_send = !before;
            let deadline = io.now + Duration::from_secs(1);
            assert_eq!(
                read_register(&mut io, RegisterResponseLayout::Body7, 2, 8, deadline),
                Err(RegisterTransactionError::Cancelled)
            );
            assert_eq!(io.sent, usize::from(!before));
        }
    }

    #[test]
    fn register_readback_masks_preserve_version_mask_and_require_pll_lock() {
        let a4 = RegisterReadbackExpectation::for_write(0x1370, 0xa4, 0x9000ffff).unwrap();
        assert!(a4.matches(0x8000ffff));
        assert!(a4.matches(0x9000ffff));
        assert!(!a4.matches(0x8000fffe));
        assert!(!a4.matches(0));
        assert!(
            !RegisterReadbackExpectation::for_write(0x1370, 0xa4, 0xb000ffff)
                .unwrap()
                .matches(0xa000ffff)
        );
        assert!(
            !RegisterReadbackExpectation::for_write(0x1362, 0xa4, 0x9000ffff)
                .unwrap()
                .matches(0x8000ffff)
        );
        let pll = RegisterReadbackExpectation::for_write(0x1370, 8, 0x40a80230).unwrap();
        assert!(pll.matches(0xc0a80230));
        assert!(!pll.matches(0x40a80230));
        assert!(RegisterReadbackExpectation::for_write(0x1387, 8, 0).is_none());
        assert!(RegisterReadbackExpectation::for_write(0x1370, 0xa8, 0).is_none());
    }
}
