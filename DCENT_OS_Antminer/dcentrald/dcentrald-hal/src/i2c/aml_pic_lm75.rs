//! Classic AML BHB42601/21/41 PIC-local LM75 bridge.
//!
//! Source: held bosminer.unpacked-r13 SHA256 64e120df8c8011aa5199c87ebbd30276766ec3c746d597ab67a6119cf1c3cbe1,
//! constructor 0x8c7554, pointer select 0x8e6054, read 0x8e6788,
//! parser 0x8decc8, signed 9-bit conversion 0x8e73e0. See campaign R10
//! aml-pic-lm75-original-vectors-v2.json. The diagnostic AM2 reader has a different
//! response budget and must not be used here.
//!
//! The request runs entirely inside the existing I2C worker. No public route
//! constructor exists: only the classic AML application owner binds fresh
//! model, firmware and current-boot transport observations. This module grants
//! no voltage, reset, firmware transition or mining-readiness authority.

use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Clone)]
pub(crate) struct AmlPicLm75Route {
    authority: Weak<I2cSafetyAuthority>,
    generation: u64,
    board: u32,
    chain: u8,
}

impl std::fmt::Debug for AmlPicLm75Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmlPicLm75Route")
            .field("board", &self.board)
            .field("chain", &self.chain)
            .field("generation", &self.generation)
            .finish()
    }
}

impl AmlPicLm75Route {
    pub(super) fn bind(service: &I2cServiceHandle, board: u32, chain: u8) -> Result<Self> {
        let route = Self {
            authority: Arc::downgrade(&service.safety),
            generation: service.safety.generation.load(Ordering::SeqCst),
            board,
            chain,
        };
        route.validate(service.bus, &service.safety, 0x48)?;
        Ok(route)
    }

    pub(crate) fn chain(&self) -> u8 {
        self.chain
    }

    pub(super) fn address(&self) -> u8 {
        // Original sender 0x8e239c..a4: physical chain + 0x1f.
        self.chain.saturating_add(0x1f)
    }

    pub(super) fn validate_identity(
        &self,
        bus: u8,
        authority: &Arc<I2cSafetyAuthority>,
    ) -> Result<()> {
        if bus != 0
            || !matches!(self.board, 42601 | 42621 | 42641)
            || !(1..=3).contains(&self.chain)
            || !self
                .authority
                .upgrade()
                .is_some_and(|bound| Arc::ptr_eq(&bound, authority))
        {
            return Err(fault(
                self.address(),
                "classic AML PIC route/model/sensor/owner is not current",
            ));
        }
        Ok(())
    }

    pub(super) fn validate(
        &self,
        bus: u8,
        authority: &Arc<I2cSafetyAuthority>,
        sensor: u8,
    ) -> Result<()> {
        self.validate_identity(bus, authority)?;
        if !(0x48..=0x4b).contains(&sensor)
            || !authority.validate(I2cOperationIntent::UnclassifiedMutation, self.generation)
        {
            return Err(fault(
                self.address(),
                "classic AML PIC sensor/generation is not current",
            ));
        }
        Ok(())
    }
}

/// A complete checked PIC response, preserving the actual two sensor bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AmlPicLm75Sample {
    raw: [u8; 2],
}

impl AmlPicLm75Sample {
    pub(crate) fn raw_be(self) -> [u8; 2] {
        self.raw
    }

    pub(crate) fn celsius(self) -> f64 {
        // Exact original LM75A reader: signed 9-bit field, half-degree units.
        f64::from(i16::from_be_bytes(self.raw) >> 7) * 0.5
    }
}

pub(super) fn fault(addr: u8, detail: impl Into<String>) -> HalError {
    HalError::I2c {
        bus: 0,
        addr,
        detail: detail.into(),
    }
}

fn frame(opcode: u8, sensor: u8, argument: u8) -> [u8; 8] {
    let sum = 6_u16 + u16::from(opcode) + u16::from(sensor) + u16::from(argument);
    let [hi, lo] = sum.to_be_bytes();
    [0x55, 0xaa, 6, opcode, sensor, argument, hi, lo]
}

fn decode(addr: u8, reply: &[u8; 7]) -> Result<AmlPicLm75Sample> {
    let sum: u16 = reply[..5].iter().map(|&byte| u16::from(byte)).sum();
    if reply[0] != 7
        || reply[1] != 0x3c
        || reply[2] != 1
        || u16::from_be_bytes([reply[5], reply[6]]) != sum
    {
        return Err(fault(
            addr,
            format!(
                "classic AML PIC LM75 reply failed length/opcode/status/checksum: {reply:02x?}"
            ),
        ));
    }
    Ok(AmlPicLm75Sample {
        raw: [reply[3], reply[4]],
    })
}

pub(super) trait Wire {
    fn bus(&self) -> u8;
    fn select(&mut self, addr: u8) -> Result<()>;
    fn write_byte(&mut self, byte: u8) -> Result<()>;
    fn read_byte(&mut self) -> Result<u8>;
    fn delay(&mut self, duration: Duration);
}

impl Wire for I2cBus {
    fn bus(&self) -> u8 {
        self.bus
    }
    fn select(&mut self, addr: u8) -> Result<()> {
        self.validate_raw_fabric_owner()?;
        #[cfg(feature = "sim-hal")]
        if self.sim_backend.is_some() {
            self.current_addr = Some(addr);
            return Ok(());
        }
        if self.devmem {
            return Err(fault(
                addr,
                "classic AML PIC requires the retained kernel adapter",
            ));
        }
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| fault(addr, "classic AML PIC adapter is closed"))?;
        // Original AML backend934894 ->934af4 selects with I2C_SLAVE703.
        // Do not inherit the legacy AM2 environment-dependent FORCE selector.
        if unsafe { libc::ioctl(file.as_raw_fd(), I2C_SLAVE_SAFE as _, addr as libc::c_int) } < 0 {
            return Err(fault(
                addr,
                format!(
                    "classic AML PIC I2C_SLAVE failed: {}",
                    std::io::Error::last_os_error()
                ),
            ));
        }
        self.current_addr = Some(addr);
        Ok(())
    }
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        self.write_exact(&[byte], "classic AML PIC LM75 byte")
    }
    fn read_byte(&mut self) -> Result<u8> {
        let mut byte = [0];
        let count = self.read(&mut byte)?;
        if count != 1 {
            return Err(fault(
                self.current_addr.unwrap_or(0),
                "classic AML PIC short byte read",
            ));
        }
        Ok(byte[0])
    }
    fn delay(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

pub(super) fn live(permit: &I2cSafetyPermit, addr: u8, deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(fault(addr, "classic AML PIC LM75 deadline elapsed"));
    }
    permit.validate_admission(0, addr)
}

pub(super) fn wait(
    wire: &mut impl Wire,
    permit: &I2cSafetyPermit,
    addr: u8,
    deadline: Instant,
    ms: u64,
) -> Result<()> {
    live(permit, addr, deadline)?;
    let duration = Duration::from_millis(ms);
    if deadline.saturating_duration_since(Instant::now()) < duration {
        return Err(fault(
            addr,
            "classic AML PIC LM75 settling delay exceeds deadline",
        ));
    }
    wire.delay(duration);
    live(permit, addr, deadline)
}

fn sequence(
    wire: &mut impl Wire,
    route: &AmlPicLm75Route,
    sensor: u8,
    permit: &I2cSafetyPermit,
    deadline: Instant,
    started: &mut bool,
) -> Result<AmlPicLm75Sample> {
    let addr = route.address();
    {
        let _stage = permit.begin_stage(0, addr, "classic AML PIC selection")?;
        wire.select(addr)?;
    }
    for (opcode, argument, read_len) in [(0x3b, 0, 2), (0x3c, 2, 7)] {
        if opcode == 0x3c {
            // Original 0x8e68d4..ec waits 100 ms before issuing READ.
            wait(wire, permit, addr, deadline, 100)?;
        }
        for byte in frame(opcode, sensor, argument) {
            live(permit, addr, deadline)?;
            let _stage = permit.begin_stage(0, addr, "classic AML PIC frame byte")?;
            *started = true;
            wire.write_byte(byte)?;
        }
        // Original shared sender 0x8dfc5c..74 waits 50 ms after a frame.
        wait(wire, permit, addr, deadline, 50)?;
        let mut reply = [0; 7];
        for byte in &mut reply[..read_len] {
            live(permit, addr, deadline)?;
            let _stage = permit.begin_stage(0, addr, "classic AML PIC reply byte")?;
            *byte = wire.read_byte()?;
        }
        if opcode == 0x3b && reply[..2] != [0x3b, 1] {
            return Err(fault(
                addr,
                format!("classic AML PIC pointer ACK rejected: {:02x?}", &reply[..2]),
            ));
        }
        if opcode == 0x3c {
            let sample = decode(addr, &reply)?;
            live(permit, addr, deadline)?;
            return Ok(sample);
        }
    }
    unreachable!("fixed PIC operation pair always ends with a READ")
}

fn execute_on(
    wire: &mut impl Wire,
    route: &AmlPicLm75Route,
    sensor: u8,
    permit: &I2cSafetyPermit,
    deadline: Instant,
) -> Result<AmlPicLm75Sample> {
    route.validate(wire.bus(), &permit.authority, sensor)?;
    live(permit, route.address(), deadline)?;
    guarded(wire, permit, route.address(), |wire, started| {
        sequence(wire, route, sensor, permit, deadline, started)
    })
}

pub(super) fn guarded<W: Wire, T>(
    wire: &mut W,
    permit: &I2cSafetyPermit,
    addr: u8,
    operation: impl FnOnce(&mut W, &mut bool) -> Result<T>,
) -> Result<T> {
    let mut started = false;
    let result = catch_unwind(AssertUnwindSafe(|| operation(wire, &mut started)))
        .unwrap_or_else(|_| Err(fault(addr, "classic AML PIC worker operation panicked")));
    if result.is_err() && started {
        // Publish failure before the worker can serve a waiting normal request.
        // The fixed parser cleanup remains inside this same owner's transaction.
        permit
            .authority
            .classic_aml_pic_unresolved
            .store(true, Ordering::SeqCst);
        permit.authority.latch_terminal_safe_off();
        let _cleanup = permit.begin_terminal_safe_cleanup_stage();
        let mut cleanup_failure = None;
        for _ in 0..16 {
            if let Err(error) = wire.write_byte(0) {
                // Keep attempting the fixed sixteen-byte cleanup after a NACK.
                // A failed attempt never permits normal parser use to resume.
                cleanup_failure.get_or_insert(error);
            }
        }
        if let Some(error) = cleanup_failure {
            let original = match result {
                Err(original) => original,
                Ok(_) => unreachable!("cleanup follows a failed operation"),
            };
            return Err(fault(
                addr,
                format!("{}; mandatory PIC parser flush failed: {error}", original),
            ));
        }
    }
    result
}

pub(super) fn execute(
    i2c: &mut I2cBus,
    route: &AmlPicLm75Route,
    sensor: u8,
    permit: &I2cSafetyPermit,
    deadline: Instant,
) -> Result<AmlPicLm75Sample> {
    if !i2c.timeout_is_verified(I2C_SERVICE_DEFAULT_TIMEOUT_JIFFIES) {
        return Err(fault(
            route.address(),
            "classic AML PIC requires the retained verified I2C timeout",
        ));
    }
    execute_on(i2c, route, sensor, permit, deadline)
}

struct CallerDrop {
    service: I2cServiceHandle,
    completed: bool,
}

impl Drop for CallerDrop {
    fn drop(&mut self) {
        if !self.completed {
            self.service.latch_terminal_safe_off();
        }
    }
}

impl I2cServiceHandle {
    /// Internal only: requires the sealed classic AML application owner's route.
    pub(crate) async fn read_classic_aml_pic_lm75_at(
        &self,
        route: &AmlPicLm75Route,
        sensor: u8,
        deadline: Instant,
    ) -> Result<AmlPicLm75Sample> {
        route.validate(self.bus, &self.safety, sensor)?;
        let route = route.clone();
        let addr = route.address();
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let request = I2cRequest::ReadClassicAmlPicLm75 {
            addr,
            route,
            sensor,
            deadline,
            reply_tx,
        };
        let budget = I2cRequestBudget::for_request_until(&request, deadline)
            .ok_or_else(|| fault(addr, "classic AML PIC deadline elapsed before admission"))?;
        let mut cancellation = CallerDrop {
            service: self.clone(),
            completed: false,
        };
        let service = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            service.submit_with_intent_budget(
                addr,
                I2cOperationIntent::UnclassifiedMutation,
                request,
                reply_rx,
                budget,
            )
        })
        .await
        .map_err(|error| fault(addr, format!("classic AML PIC request worker: {error}")));
        if matches!(&result, Ok(Ok(_))) {
            cancellation.completed = true;
        }
        result?
    }
}

#[cfg(test)]
#[path = "aml_pic_lm75_tests.rs"]
mod tests;
