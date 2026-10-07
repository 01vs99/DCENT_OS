//! Held AM3 production GPIO PSU profiles for S19k and S21 families.
//!
//! Evidence: campaign evidence/r13/production-psu.md and retained AArch64
//! bytes, SHA256 64e120df8c8011aa5199c87ebbd30276766ec3c746d597ab67a6119cf1c3cbe1.
//! Provider 0x8640ac: SDA477/SCL476, timing argument333; version 0x8c24c8: address0x10.
//! All access stays behind one mutex and physical-fabric lease. Async callers
//! use spawn_blocking; cancellation cannot drop a transaction's retained owner.

use crate::i2c::I2cRawFabricLease;
use crate::{HalError, Result};
use dcentrald_fabric_lease::topology::AM3_PSU_GPIO;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{Duration, Instant};

const ADDRESS: u8 = 0x10;
const MAX_REPLY: usize = 32;
const RESPONSE_WAIT: Duration = Duration::from_millis(350);
/// DCENT scheduling policy, below the held profile's enabled 20-second
/// duration. We do not claim that profile field proves an exact timeout.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

fn protocol_error(detail: impl Into<String>) -> HalError {
    HalError::I2c {
        bus: 1,
        addr: ADDRESS,
        detail: format!("AM3 GPIO PSU: {}", detail.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    RegisterByteSum,
    DirectWordSum,
}

impl Mode {
    fn checksum(self, bytes: &[u8]) -> Result<u16> {
        match self {
            Self::RegisterByteSum => Ok(bytes
                .iter()
                .fold(0u16, |sum, byte| sum.wrapping_add(*byte as u16))),
            Self::DirectWordSum if bytes.len() % 2 == 0 => {
                Ok(bytes.chunks_exact(2).fold(0u16, |sum, word| {
                    sum.wrapping_add(u16::from_le_bytes([word[0], word[1]]))
                }))
            }
            Self::DirectWordSum => Err(protocol_error("word-checksum frame has odd length")),
        }
    }

    fn frame(self, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() > MAX_REPLY - 4 {
            return Err(protocol_error("oversized frame"));
        }
        let mut frame = vec![0x55, 0xaa, (payload.len() + 4) as u8, command];
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&self.checksum(&frame[2..])?.to_le_bytes());
        Ok(frame)
    }

    fn parse(self, command: u8, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < 6
            || frame[..2] != [0x55, 0xaa]
            || frame[2] as usize + 2 != frame.len()
            || frame[3] != command
        {
            return Err(protocol_error(
                "response preamble, length or command mismatch",
            ));
        }
        let end = frame.len() - 2;
        let observed = u16::from_le_bytes([frame[end], frame[end + 1]]);
        if self.checksum(&frame[2..end])? != observed {
            return Err(protocol_error("response checksum mismatch"));
        }
        Ok(frame[4..end].to_vec())
    }
}

trait PsuWire: Send {
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
    fn read_byte(&mut self) -> Result<u8>;
    fn wait(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Hardware-version scope selected by the admitted native carrier. A model
/// name never substitutes for the subsequent version query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProductionProfile {
    /// Independent .78 production constructor0x829ed4, versions75..77.
    S19kApw121215,
    /// Modern production constructor0x84e964, versions75..77.
    S21Apw121215,
    /// Exact classic BHB42601/21/41 uses the same AM3 registry key3 PSU
    /// provider8640ac and measured selector86d430. Admit only the retained
    /// APW12 production constructor84e964 (versions75..77).
    ClassicApw121215,
    /// Modern production constructor0x84eaf8, versionc1 only. This protocol
    /// profile is not itself an admission for an unjoined BM1370 carrier.
    ModernApw171215,
    /// Pro/XP production factory discovers the PSU independently of the
    /// hashboard model. Only the two traced modern rail families are selected.
    ModernProXpAuto,
}

impl ProductionProfile {
    fn select(self, version: u16) -> Option<Self> {
        match self {
            Self::S19kApw121215 | Self::S21Apw121215 | Self::ClassicApw121215
                if matches!(version, 0x75..=0x77) =>
            {
                Some(self)
            }
            Self::ModernApw171215 if version == 0xc1 => Some(self),
            Self::ModernProXpAuto => match version {
                0x75..=0x77 => Some(Self::S21Apw121215),
                0xc1 => Some(Self::ModernApw171215),
                _ => None,
            },
            _ => None,
        }
    }

    fn voltage_code(self, voltage: f64, firmware: Option<u16>) -> Result<u8> {
        let (minimum, maximum, intercept, slope) = match self {
            Self::S19kApw121215 | Self::S21Apw121215 | Self::ClassicApw121215 => {
                (11.96, 15.2, 15.2, -0.0127058)
            }
            Self::ModernApw171215 => {
                // Stock S19j XP0df09c..: hardwarec1/c2 share table arms5fae4
                // and6009c. Command01 firmware low byte<=3 selects1275-85*V;
                // >3 selects1083.75-70.833333*V. Modern bosminer84eaf8
                // independently confirms the latter15.3/-0.014117647 law.
                let firmware = firmware.ok_or_else(|| {
                    protocol_error("APW17 voltage requires measured firmware word")
                })?;
                if firmware as u8 <= 3 {
                    if !voltage.is_finite() || !(12.0..=15.0).contains(&voltage) {
                        return Err(protocol_error("legacy APW17 voltage outside12..15V"));
                    }
                    // Stock vcvt.s32 truncates; do not apply modern fcvtas rounding.
                    return Ok((1275.0 - 85.0 * voltage).trunc() as u8);
                }
                (12.0, 15.0, 15.3, -0.014117647)
            }
            Self::ModernProXpAuto => {
                return Err(protocol_error("voltage requires a measured PSU profile"));
            }
        };
        if !voltage.is_finite() || !(minimum..=maximum).contains(&voltage) {
            return Err(protocol_error(format!(
                "voltage outside {self:?} {minimum}..{maximum} V envelope"
            )));
        }
        // Production fcvtas rounds nearest, ties away from zero.
        let code = ((voltage - intercept) / slope).round();
        if !(0.0..=255.0).contains(&code) {
            return Err(protocol_error("voltage code exceeds byte envelope"));
        }
        Ok(code as u8)
    }
}

struct Protocol<W> {
    wire: W,
    mode: Mode,
    version: Option<u16>,
    firmware: Option<u16>,
    profile: ProductionProfile,
}

impl<W: PsuWire> Protocol<W> {
    fn command(&mut self, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
        for byte in self.mode.frame(command, payload)? {
            match self.mode {
                Mode::RegisterByteSum => self.wire.write(&[0x11, byte])?,
                Mode::DirectWordSum => self.wire.write(&[byte])?,
            }
        }
        // Exact held version delay; conservatively retained for the other
        // finite commands as DCENT policy until their delay is independently bound.
        self.wire.wait(RESPONSE_WAIT);
        let mut previous = 0;
        for _ in 0..MAX_REPLY {
            let byte = self.wire.read_byte()?;
            if previous == 0x55 && byte == 0xaa {
                let len = self.wire.read_byte()? as usize;
                if !(4..=MAX_REPLY).contains(&len) {
                    return Err(protocol_error("response length out of bounds"));
                }
                let mut frame = vec![0x55, 0xaa, len as u8];
                for _ in 0..len - 1 {
                    frame.push(self.wire.read_byte()?);
                }
                return self.mode.parse(command, &frame);
            }
            previous = byte;
        }
        Err(protocol_error(
            "response preamble absent from bounded window",
        ))
    }

    fn discover(&mut self) -> Result<u16> {
        // A failed new observation must not retain authorization from an old
        // version. The immutable profile remains the admitted carrier scope.
        self.version = None;
        self.firmware = None;
        // 0x8c88d4 drains at most32 bytes; 0x20 is a count, not the address.
        for _ in 0..32 {
            match self.wire.read_byte() {
                Ok(_) => {}
                Err(HalError::I2c { .. }) => break,
                Err(error) => return Err(error),
            }
        }
        self.mode = Mode::RegisterByteSum;
        let reply = match self.command(0x02, &[]) {
            Ok(reply) => reply,
            Err(HalError::I2c { .. }) => {
                for _ in 0..32 {
                    match self.wire.read_byte() {
                        Ok(_) => {}
                        Err(HalError::I2c { .. }) => break,
                        Err(error) => return Err(error),
                    }
                }
                self.mode = Mode::DirectWordSum;
                self.command(0x02, &[])?
            }
            Err(error) => return Err(error),
        };
        let bytes: [u8; 2] = reply
            .try_into()
            .map_err(|_| protocol_error("version payload is not u16"))?;
        let version = u16::from_le_bytes(bytes);
        // Constructors0x84e964 and0x84eaf8 independently bind the modern
        // APW12 and APW17 laws. Other versions remain unselected.
        if self.profile.select(version).is_none() {
            return Err(protocol_error(format!(
                "no held production rail profile for version {version:#06x}"
            )));
        }
        // Discovery's fallback is only a probe. Operational encoding comes
        // from the selected version profile: constructor0x84e964 sets+c8=0
        // for75..77, while constructor0x84eaf8 sets+c8=2 for c1. The
        // production sender only treats1 as direct/word-sum; both0 and2 use
        // register/byte-sum. Startup0x8c90f8 copies the selected profile.
        self.mode = Mode::RegisterByteSum;
        if self.profile.select(version) == Some(ProductionProfile::ModernApw171215) {
            // Exact stock query5b54c sends55aa04010500, receives eight bytes,
            // and decodes response payload[0..2] as LEu16. A failed query
            // cannot default to a voltage law or retain prior authorization.
            let reply = self.command(0x01, &[])?;
            let bytes: [u8; 2] = reply
                .try_into()
                .map_err(|_| protocol_error("APW17 firmware payload is not u16"))?;
            self.firmware = Some(u16::from_le_bytes(bytes));
        }
        self.version = Some(version);
        Ok(version)
    }

    fn set_voltage(&mut self, voltage: f64) -> Result<()> {
        let version = self
            .version
            .ok_or_else(|| protocol_error("voltage requested before version selection"))?;
        let selected = self
            .profile
            .select(version)
            .ok_or_else(|| protocol_error("measured version has no admitted PSU profile"))?;
        let n = selected.voltage_code(voltage, self.firmware)?;
        let payload = match self.mode {
            Mode::RegisterByteSum => (n as u16).to_le_bytes().to_vec(),
            Mode::DirectWordSum => (n as u32).to_le_bytes().to_vec(),
        };
        let reply = self.command(0x83, &payload)?;
        // Production parser0x8c50a8 requires a u16 in mode0 and u32 in
        // mode1. Require the returned setting to match our request before
        // advancing the native startup sequence (DCENT readback policy).
        if reply != payload {
            return Err(protocol_error("voltage setting readback mismatch"));
        }
        Ok(())
    }

    fn heartbeat(&mut self) -> Result<()> {
        if self.version.is_none() {
            return Err(protocol_error(
                "heartbeat requested before version selection",
            ));
        }
        self.command(
            match self.mode {
                Mode::RegisterByteSum => 0x0a,
                Mode::DirectWordSum => 0x0e,
            },
            &[],
        )?;
        Ok(())
    }

    fn initialize(&mut self, voltage: f64) -> Result<()> {
        self.set_voltage(voltage)?;
        // Parser0x8c4acc calls0x8c1f98: exactly two bytes, value0 or1.
        // Native startup requires the returned watchdog state to be enabled.
        if self.command(0x81, &[1, 0])? != [1, 0] {
            return Err(protocol_error("watchdog enable readback mismatch"));
        }
        self.heartbeat()
    }
}

/// Only clones of this exact retained owner can issue commands. Closing is
/// terminal; re-opening requires a new admitted hardware session.
#[derive(Clone)]
pub(super) struct S21PsuService {
    inner: Arc<Mutex<Option<Protocol<GpioWire>>>>,
    terminal: Arc<AtomicBool>,
}

impl S21PsuService {
    pub(super) fn open(profile: ProductionProfile) -> Result<Self> {
        let terminal = Arc::new(AtomicBool::new(false));
        let wire = GpioWire::open(Arc::clone(&terminal))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Some(Protocol {
                wire,
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile,
            }))),
            terminal,
        })
    }

    fn with<R>(&self, f: impl FnOnce(&mut Protocol<GpioWire>) -> Result<R>) -> Result<R> {
        if self.terminal.load(Ordering::SeqCst) {
            return Err(protocol_error("PSU service terminally fenced"));
        }
        let mut owner = self
            .inner
            .lock()
            .map_err(|_| protocol_error("PSU service mutex poisoned"))?;
        if self.terminal.load(Ordering::SeqCst) {
            return Err(protocol_error("PSU service fenced while waiting"));
        }
        f(owner
            .as_mut()
            .ok_or_else(|| protocol_error("PSU service closed"))?)
    }

    pub(super) fn discover(&self) -> Result<u16> {
        self.with(Protocol::discover)
    }
    pub(super) fn initialize(&self, voltage: f64) -> Result<()> {
        self.with(|psu| psu.initialize(voltage))
    }
    pub(super) fn heartbeat(&self) -> Result<()> {
        self.with(Protocol::heartbeat)
    }
    pub(super) fn fence(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }

    pub(super) fn close_until(&self, deadline: Instant) -> Result<()> {
        self.fence();
        loop {
            match self.inner.try_lock() {
                Ok(mut owner) => {
                    owner.take();
                    return Ok(());
                }
                Err(TryLockError::Poisoned(_)) => {
                    return Err(protocol_error(
                        "PSU owner poisoned; physical lease retained",
                    ))
                }
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(protocol_error(
                        "PSU transaction did not quiesce before deadline",
                    ))
                }
            }
        }
    }
}

/// Open-drain sysfs implementation. Every pin operation checks I/O errors;
/// the older AM2 bit-bang helper intentionally has a different fabric and
/// must not be repurposed using environment-selected pins or dialects.
struct GpioWire {
    lease: I2cRawFabricLease,
    terminal: Arc<AtomicBool>,
    root: PathBuf,
}

impl GpioWire {
    fn open(terminal: Arc<AtomicBool>) -> Result<Self> {
        let lease = I2cRawFabricLease::reserve_bitbang(AM3_PSU_GPIO)?;
        let wire = Self {
            lease,
            terminal,
            root: PathBuf::from("/sys/class/gpio"),
        };
        for pin in [476, 477] {
            let path = wire.root.join(format!("gpio{pin}"));
            if !path.exists() {
                fs::write(wire.root.join("export"), pin.to_string())
                    .map_err(|e| HalError::Platform(format!("S21 PSU GPIO{pin} export: {e}")))?;
                let deadline = Instant::now() + Duration::from_millis(500);
                while !path.exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            fs::write(path.join("active_low"), "0")
                .map_err(|e| HalError::Platform(format!("S21 PSU GPIO{pin} polarity: {e}")))?;
            if fs::read_to_string(path.join("active_low"))?.trim() != "0" {
                return Err(HalError::Platform(format!(
                    "S21 PSU GPIO{pin} polarity readback"
                )));
            }
            wire.pin(pin, true)?;
        }
        Ok(wire)
    }

    fn pin(&self, pin: u32, high: bool) -> Result<()> {
        self.lease.validate_current_process()?;
        fs::write(
            self.root.join(format!("gpio{pin}/direction")),
            if high { "in" } else { "low" },
        )
        .map_err(|e| HalError::Platform(format!("S21 PSU GPIO{pin}: {e}")))
    }

    fn sample(&self, pin: u32) -> Result<bool> {
        self.lease.validate_current_process()?;
        let raw = fs::read_to_string(self.root.join(format!("gpio{pin}/value")))?;
        match raw.trim() {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(HalError::Platform(format!(
                "S21 PSU GPIO{pin} nonbinary readback"
            ))),
        }
    }

    // Conservative DCENT sysfs timing policy. The provider's argument333
    // is retained as evidence; its unit is not inferred as333Hz here.
    fn delay() {
        std::thread::sleep(Duration::from_micros(1_001));
    }
    fn clock_high(&self) -> Result<()> {
        self.pin(476, true)?;
        // DCENT bounded clock-stretch policy; no unbounded stuck-line loop.
        let end = Instant::now() + Duration::from_millis(20);
        while !self.sample(476)? {
            if Instant::now() >= end {
                return Err(protocol_error("SCL stuck low"));
            }
            std::thread::sleep(Duration::from_micros(100));
        }
        Ok(())
    }
    fn start(&self) -> Result<()> {
        self.lease.validate_current_process()?;
        if self.terminal.load(Ordering::SeqCst) {
            return Err(protocol_error("terminal fence before wire transaction"));
        }
        self.pin(477, true)?;
        Self::delay();
        self.clock_high()?;
        Self::delay();
        if !self.sample(477)? {
            return Err(protocol_error("SDA stuck low before START"));
        }
        self.pin(477, false)?;
        Self::delay();
        self.pin(476, false)?;
        Ok(())
    }
    fn stop(&self) -> Result<()> {
        self.pin(477, false)?;
        Self::delay();
        self.clock_high()?;
        Self::delay();
        self.pin(477, true)?;
        Self::delay();
        Ok(())
    }
    fn bit(&self, high: bool) -> Result<()> {
        self.pin(477, high)?;
        Self::delay();
        self.clock_high()?;
        Self::delay();
        self.pin(476, false)?;
        Self::delay();
        Ok(())
    }
    fn read_bit(&self) -> Result<bool> {
        self.pin(477, true)?;
        Self::delay();
        self.clock_high()?;
        Self::delay();
        let value = self.sample(477)?;
        self.pin(476, false)?;
        Self::delay();
        Ok(value)
    }
    fn byte(&self, byte: u8) -> Result<()> {
        for shift in (0..8).rev() {
            self.bit((byte >> shift) & 1 != 0)?;
        }
        if self.read_bit()? {
            return Err(protocol_error("address/data NACK"));
        }
        Ok(())
    }
    fn transaction<R>(&self, body: impl FnOnce() -> Result<R>) -> Result<R> {
        self.start()?;
        let result = body();
        let stop = self.stop();
        match result {
            Ok(value) => stop.map(|_| value),
            Err(error) => {
                if let Err(stop_error) = stop {
                    tracing::error!(%stop_error, "S21 PSU STOP after failed transaction");
                }
                Err(error)
            }
        }
    }
}

impl PsuWire for GpioWire {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.transaction(|| {
            self.byte(ADDRESS << 1)?;
            for byte in bytes {
                self.byte(*byte)?;
            }
            Ok(())
        })
    }
    fn read_byte(&mut self) -> Result<u8> {
        self.transaction(|| {
            self.byte((ADDRESS << 1) | 1)?;
            let mut value = 0;
            for _ in 0..8 {
                value = (value << 1) | u8::from(self.read_bit()?);
            }
            self.bit(true)?;
            Ok(value)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Wire {
        writes: Vec<Vec<u8>>,
        replies: VecDeque<Option<u8>>,
        waits: usize,
    }
    impl PsuWire for Wire {
        fn write(&mut self, bytes: &[u8]) -> Result<()> {
            self.writes.push(bytes.to_vec());
            Ok(())
        }
        fn read_byte(&mut self) -> Result<u8> {
            self.replies
                .pop_front()
                .flatten()
                .ok_or_else(|| protocol_error("fixture NACK"))
        }
        fn wait(&mut self, duration: Duration) {
            assert_eq!(duration, RESPONSE_WAIT);
            self.waits += 1;
        }
    }
    fn reply(mode: Mode, cmd: u8, payload: &[u8]) -> Vec<Option<u8>> {
        mode.frame(cmd, payload)
            .unwrap()
            .into_iter()
            .map(Some)
            .collect()
    }

    #[test]
    fn production_version_rail_watchdog_heartbeat_execute_on_same_transport() {
        let mut replies = VecDeque::from([None]); // bounded initial drain
        for (cmd, payload) in [
            (2, &[0x76, 0][..]),
            (0x83, &[130, 0][..]),
            (0x81, &[1, 0][..]),
            (0x0a, &[0; 8][..]),
        ] {
            replies.extend(reply(Mode::RegisterByteSum, cmd, payload));
        }
        let mut psu = Protocol {
            wire: Wire {
                writes: vec![],
                replies,
                waits: 0,
            },
            mode: Mode::RegisterByteSum,
            version: None,
            firmware: None,
            profile: ProductionProfile::S21Apw121215,
        };
        assert_eq!(psu.discover().unwrap(), 0x76);
        psu.initialize(13.55).unwrap();
        let observed: Vec<u8> = psu
            .wire
            .writes
            .iter()
            .map(|tx| {
                assert_eq!(tx.len(), 2);
                assert_eq!(tx[0], 0x11);
                tx[1]
            })
            .collect();
        assert_eq!(
            observed,
            [
                0x55, 0xaa, 4, 2, 6, 0, 0x55, 0xaa, 6, 0x83, 130, 0, 0x0b, 1, 0x55, 0xaa, 6, 0x81,
                1, 0, 0x88, 0, 0x55, 0xaa, 4, 0x0a, 0x0e, 0
            ]
        );
        assert!(psu.wire.replies.is_empty());
        assert_eq!(psu.wire.waits, 4);
    }

    #[test]
    fn production_fallback_discovers_then_selects_version_bound_profile() {
        let mut replies = VecDeque::from([None, None, None]); // drain, failed mode0 query, fallback drain
        replies.extend(reply(Mode::DirectWordSum, 2, &[0x76, 0]));
        replies.extend(reply(Mode::RegisterByteSum, 0x0a, &[0; 8]));
        let mut psu = Protocol {
            wire: Wire {
                writes: vec![],
                replies,
                waits: 0,
            },
            mode: Mode::RegisterByteSum,
            version: None,
            firmware: None,
            profile: ProductionProfile::S21Apw121215,
        };
        assert_eq!(psu.discover().unwrap(), 0x76);
        psu.heartbeat().unwrap();
        assert_eq!(psu.mode, Mode::RegisterByteSum);
        assert_eq!(
            psu.wire.writes[6..12],
            vec![vec![0x55], vec![0xaa], vec![4], vec![2], vec![4], vec![2]]
        );
        assert_eq!(
            psu.wire.writes[12..],
            vec![
                vec![0x11, 0x55],
                vec![0x11, 0xaa],
                vec![0x11, 4],
                vec![0x11, 0x0a],
                vec![0x11, 0x0e],
                vec![0x11, 0]
            ]
        );
    }

    #[test]
    fn production_voltage_rounding_and_response_corruption_are_checked() {
        assert_eq!(
            ProductionProfile::S21Apw121215
                .voltage_code(13.55, None)
                .unwrap(),
            130
        );
        assert_eq!(
            ProductionProfile::S21Apw121215
                .voltage_code(15.2, None)
                .unwrap(),
            0
        );
        for bad in [f64::NAN, f64::INFINITY, 11.95, 15.21] {
            assert!(ProductionProfile::S21Apw121215
                .voltage_code(bad, None)
                .is_err());
        }
        let mut frame = Mode::RegisterByteSum.frame(2, &[0x76, 0]).unwrap();
        frame[4] ^= 1;
        assert!(Mode::RegisterByteSum.parse(2, &frame).is_err());
        assert!(Mode::RegisterByteSum
            .parse(0x83, &Mode::RegisterByteSum.frame(2, &[0x76, 0]).unwrap())
            .is_err());
    }

    #[test]
    fn incomplete_or_different_setting_reply_never_advances_to_watchdog() {
        for payload in [&[][..], &[129, 0][..], &[130, 0, 0, 0][..]] {
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies: reply(Mode::RegisterByteSum, 0x83, payload).into(),
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: Some(0x76),
                firmware: None,
                profile: ProductionProfile::S21Apw121215,
            };
            assert!(psu.initialize(13.55).is_err());
            assert_eq!(psu.wire.writes.len(), 8);
            assert_eq!(psu.wire.waits, 1);
        }
    }
    #[test]
    fn s19k_and_apw17_production_profiles_execute_their_exact_rail_commands() {
        for (profile, version, volts, code, sum) in [
            (ProductionProfile::S19kApw121215, 0x76, 13.9, 102u8, 0xefu16),
            (
                ProductionProfile::ModernApw171215,
                0xc1,
                13.55,
                124u8,
                0x105u16,
            ),
        ] {
            let mut replies = VecDeque::from([None]);
            for (cmd, payload) in [
                (2, vec![version, 0]),
                (0x83, vec![code, 0]),
                (0x81, vec![1, 0]),
                (0x0a, vec![0, 0]),
            ] {
                replies.extend(reply(Mode::RegisterByteSum, cmd, &payload));
                if cmd == 2 && version == 0xc1 {
                    replies.extend(reply(Mode::RegisterByteSum, 1, &[4, 0]));
                }
            }
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile,
            };
            assert_eq!(psu.discover().unwrap(), u16::from(version));
            psu.initialize(volts).unwrap();
            let emitted: Vec<u8> = psu
                .wire
                .writes
                .iter()
                .map(|tx| {
                    assert_eq!(tx[0], 0x11);
                    assert_eq!(tx.len(), 2);
                    tx[1]
                })
                .collect();
            let start = if version == 0xc1 { 12 } else { 6 };
            if version == 0xc1 {
                assert_eq!(&emitted[6..12], &[0x55, 0xaa, 4, 1, 5, 0]);
            }
            assert_eq!(
                &emitted[start..start + 8],
                &[0x55, 0xaa, 6, 0x83, code, 0, sum as u8, (sum >> 8) as u8]
            );
            assert_eq!(
                &emitted[start + 8..],
                &[0x55, 0xaa, 6, 0x81, 1, 0, 0x88, 0, 0x55, 0xaa, 4, 0x0a, 0x0e, 0]
            );
            assert!(psu.wire.replies.is_empty());
            assert_eq!(psu.wire.waits, if version == 0xc1 { 5 } else { 4 });
        }
    }

    #[test]
    fn pro_xp_auto_executes_each_measured_production_rail_profile() {
        for (version, code, sum, selected) in [
            (0x75, 142, 0x117u16, ProductionProfile::S21Apw121215),
            (0x76, 142, 0x117u16, ProductionProfile::S21Apw121215),
            (0x77, 142, 0x117u16, ProductionProfile::S21Apw121215),
            (0xc1, 135, 0x110u16, ProductionProfile::ModernApw171215),
        ] {
            let mut replies = VecDeque::from([None]);
            for (command, payload) in [
                (2, vec![version, 0]),
                (0x83, vec![code, 0]),
                (0x81, vec![1, 0]),
                (0x0a, vec![0, 0]),
            ] {
                replies.extend(reply(Mode::RegisterByteSum, command, &payload));
                if command == 2 && version == 0xc1 {
                    replies.extend(reply(Mode::RegisterByteSum, 1, &[4, 0]));
                }
            }
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile: ProductionProfile::ModernProXpAuto,
            };
            assert_eq!(psu.discover().unwrap(), u16::from(version));
            assert_eq!(psu.profile.select(u16::from(version)), Some(selected));
            psu.initialize(13.4).unwrap();
            let emitted: Vec<u8> = psu
                .wire
                .writes
                .iter()
                .map(|tx| {
                    assert_eq!(tx.len(), 2);
                    assert_eq!(tx[0], 0x11);
                    tx[1]
                })
                .collect();
            assert_eq!(&emitted[..6], &[0x55, 0xaa, 4, 2, 6, 0]);
            let start = if version == 0xc1 { 12 } else { 6 };
            if version == 0xc1 {
                assert_eq!(&emitted[6..12], &[0x55, 0xaa, 4, 1, 5, 0]);
            }
            assert_eq!(
                &emitted[start..start + 8],
                &[0x55, 0xaa, 6, 0x83, code, 0, sum as u8, (sum >> 8) as u8]
            );
            assert_eq!(
                &emitted[start + 8..],
                &[0x55, 0xaa, 6, 0x81, 1, 0, 0x88, 0, 0x55, 0xaa, 4, 0x0a, 0x0e, 0]
            );
            assert!(psu.wire.replies.is_empty());
            assert_eq!(psu.wire.waits, if version == 0xc1 { 5 } else { 4 });
        }
    }

    #[test]
    fn pro_xp_auto_enforces_selected_envelope_and_ack_before_watchdog() {
        // 15.1V is within the APW12 law but outside the APW17 envelope.
        for (version, allowed) in [(0x76, true), (0xc1, false)] {
            let mut replies = VecDeque::from([None]);
            replies.extend(reply(Mode::RegisterByteSum, 2, &[version, 0]));
            if version == 0xc1 {
                replies.extend(reply(Mode::RegisterByteSum, 1, &[4, 0]));
            }
            if allowed {
                replies.extend(reply(Mode::RegisterByteSum, 0x83, &[8, 0]));
            }
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile: ProductionProfile::ModernProXpAuto,
            };
            psu.discover().unwrap();
            assert_eq!(psu.set_voltage(15.1).is_ok(), allowed);
            assert_eq!(psu.wire.writes.len(), if allowed { 14 } else { 12 });
        }
        for (version, wrong_code) in [(0x76, 135), (0xc1, 142)] {
            let mut replies = VecDeque::from([None]);
            replies.extend(reply(Mode::RegisterByteSum, 2, &[version, 0]));
            if version == 0xc1 {
                replies.extend(reply(Mode::RegisterByteSum, 1, &[4, 0]));
            }
            replies.extend(reply(Mode::RegisterByteSum, 0x83, &[wrong_code, 0]));
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile: ProductionProfile::ModernProXpAuto,
            };
            psu.discover().unwrap();
            assert!(psu
                .initialize(13.4)
                .unwrap_err()
                .to_string()
                .contains("readback mismatch"));
            assert_eq!(
                psu.wire.writes.len(),
                if version == 0xc1 { 20 } else { 14 },
                "bad voltage ACK must prevent watchdog enable"
            );
        }
    }

    #[test]
    fn pro_xp_auto_unknown_rediscovery_revokes_prior_rail_authorization() {
        for version in [0x71u16, 0xc2, 0x0176] {
            let mut replies = VecDeque::from([None]);
            replies.extend(reply(Mode::RegisterByteSum, 2, &[0x76, 0]));
            replies.push_back(None);
            replies.extend(reply(Mode::RegisterByteSum, 2, &version.to_le_bytes()));
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile: ProductionProfile::ModernProXpAuto,
            };
            assert_eq!(psu.discover().unwrap(), 0x76);
            assert!(psu.discover().is_err());
            assert_eq!(psu.version, None);
            assert!(psu.initialize(13.4).is_err());
            assert!(psu.heartbeat().is_err());
            assert_eq!(
                psu.wire.writes.len(),
                12,
                "only version queries may reach the wire"
            );
        }
    }

    #[test]
    fn production_profiles_do_not_admit_other_psu_families() {
        for (profile, version) in [
            (ProductionProfile::S19kApw121215, 0xc1),
            (ProductionProfile::S21Apw121215, 0x71),
            (ProductionProfile::ModernApw171215, 0xc2),
            (ProductionProfile::ModernApw171215, 0x76),
        ] {
            let mut replies = VecDeque::from([None]);
            replies.extend(reply(Mode::RegisterByteSum, 2, &[version, 0]));
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile,
            };
            assert!(psu.discover().is_err());
            assert!(psu.initialize(13.55).is_err());
            assert_eq!(
                psu.wire.writes.len(),
                6,
                "only version query may reach the wire"
            );
        }
        assert_eq!(
            ProductionProfile::ModernApw171215
                .voltage_code(15.0, Some(4))
                .unwrap(),
            21
        );
        assert_eq!(
            ProductionProfile::ModernApw171215
                .voltage_code(12.0, Some(4))
                .unwrap(),
            234
        );
        assert!(ProductionProfile::ModernApw171215
            .voltage_code(15.01, Some(4))
            .is_err());
    }
    #[test]
    fn apw17_measured_firmware_word_selects_legacy_and_modern_voltage_commands() {
        // Independent stock conversion branches: <=3 is1275-85*V; >3 is
        //1083.75-70.833333*V. High firmware byte does not select the law.
        for (firmware, code) in [(3u16, 136u8), (4, 135), (0x0103, 136), (0x0104, 135)] {
            let mut replies = VecDeque::from([None]);
            for (command, payload) in [
                (2, vec![0xc1, 0]),
                (1, firmware.to_le_bytes().to_vec()),
                (0x83, vec![code, 0]),
                (0x81, vec![1, 0]),
                (0x0a, vec![0, 0]),
            ] {
                replies.extend(reply(Mode::RegisterByteSum, command, &payload));
            }
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile: ProductionProfile::ModernProXpAuto,
            };
            psu.discover().unwrap();
            assert_eq!(psu.firmware, Some(firmware));
            psu.initialize(13.4).unwrap();
            let emitted: Vec<_> = psu
                .wire
                .writes
                .iter()
                .map(|tx| {
                    assert_eq!(tx[0], 0x11);
                    tx[1]
                })
                .collect();
            assert_eq!(
                &emitted[..12],
                &[0x55, 0xaa, 4, 2, 6, 0, 0x55, 0xaa, 4, 1, 5, 0]
            );
            let sum = 6u16 + 0x83 + u16::from(code);
            assert_eq!(
                &emitted[12..20],
                &[0x55, 0xaa, 6, 0x83, code, 0, sum as u8, (sum >> 8) as u8]
            );
            assert!(psu.wire.replies.is_empty());
        }
        assert!(ProductionProfile::ModernApw171215
            .voltage_code(13.4, None)
            .is_err());
    }

    #[test]
    fn failed_apw17_firmware_rediscovery_revokes_voltage_and_watchdog_authority() {
        for malformed in [vec![], vec![3], vec![3, 0, 0]] {
            let mut replies = VecDeque::from([None]);
            replies.extend(reply(Mode::RegisterByteSum, 2, &[0xc1, 0]));
            replies.extend(reply(Mode::RegisterByteSum, 1, &[4, 0]));
            replies.push_back(None);
            replies.extend(reply(Mode::RegisterByteSum, 2, &[0xc1, 0]));
            replies.extend(reply(Mode::RegisterByteSum, 1, &malformed));
            let mut psu = Protocol {
                wire: Wire {
                    writes: vec![],
                    replies,
                    waits: 0,
                },
                mode: Mode::RegisterByteSum,
                version: None,
                firmware: None,
                profile: ProductionProfile::ModernApw171215,
            };
            psu.discover().unwrap();
            assert!(psu.discover().is_err());
            assert_eq!(psu.version, None);
            assert_eq!(psu.firmware, None);
            assert!(psu.initialize(13.4).is_err());
            assert!(psu.heartbeat().is_err());
            assert_eq!(
                psu.wire.writes.len(),
                24,
                "only the two hardware and two firmware queries were emitted"
            );
        }
        let mut replies = VecDeque::from([None]);
        replies.extend(reply(Mode::RegisterByteSum, 2, &[0xc1, 0]));
        let mut bad = Mode::RegisterByteSum.frame(1, &[4, 0]).unwrap();
        bad[4] ^= 1;
        replies.extend(bad.into_iter().map(Some));
        let mut psu = Protocol {
            wire: Wire {
                writes: vec![],
                replies,
                waits: 0,
            },
            mode: Mode::RegisterByteSum,
            version: None,
            firmware: None,
            profile: ProductionProfile::ModernApw171215,
        };
        assert!(psu.discover().is_err());
        assert!(psu.set_voltage(13.4).is_err());
        assert_eq!(psu.wire.writes.len(), 12);
    }
}
