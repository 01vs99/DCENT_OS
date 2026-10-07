//! Fixed classic AML application requests. The platform owner supplies fresh
//! protected factory identity; this worker never resets or starts firmware.
use super::aml_pic_lm75::{self as bridge, AmlPicLm75Route, Wire};
use super::*;

pub(crate) fn factory_page(
    service: &I2cServiceHandle,
    addr: u8,
    deadline: Instant,
) -> Result<Vec<u8>> {
    if service.bus != 1 || !(0x50..=0x52).contains(&addr) {
        return Err(HalError::Platform(
            "classic AML factory endpoint must be bus1/50..52".into(),
        ));
    }
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let req = I2cRequest::ReadClassicAmlFactoryPage {
        addr,
        deadline,
        reply_tx,
    };
    let budget = I2cRequestBudget::for_request_until(&req, deadline)
        .ok_or_else(|| HalError::Platform("classic AML factory deadline elapsed".into()))?;
    service.submit_with_intent_budget(
        addr,
        I2cOperationIntent::UnclassifiedMutation,
        req,
        reply_rx,
        budget,
    )
}

pub(super) fn execute_factory_page(
    bus: &mut I2cBus,
    addr: u8,
    permit: &I2cSafetyPermit,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let result = (|| {
        if bus.bus != 1
            || !(0x50..=0x52).contains(&addr)
            || Instant::now() >= deadline
            || !bus.timeout_is_verified(I2C_SERVICE_DEFAULT_TIMEOUT_JIFFIES)
        {
            return Err(HalError::Platform(
                "classic AML factory route/timeout/deadline rejected".into(),
            ));
        }
        let _stage = permit.begin_stage(1, addr, "classic AML protected factory page")?;
        let bytes =
            bus.read_protected_hashboard_eeprom_span(addr, HashboardEepromSpan::FullPage)?;
        permit.validate_admission(1, addr)?;
        if Instant::now() >= deadline {
            return Err(HalError::Platform(
                "classic AML factory completion missed deadline".into(),
            ));
        }
        Ok(bytes)
    })();
    if result.is_err() {
        permit.authority.latch_terminal_safe_off();
    }
    result
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum Operation {
    Version,
    Heartbeat,
    Voltage,
    Enable,
    Disable,
}

impl Operation {
    pub(super) fn byte_budget(self) -> usize {
        self.frame().len() + self.reply_len() + 16
    }

    fn frame(self) -> &'static [u8] {
        match self {
            Self::Version => &[0x55, 0xaa, 4, 0x17, 0, 0x1b],
            Self::Heartbeat => &[0x55, 0xaa, 4, 0x16, 0, 0x1a],
            Self::Voltage => &[0x55, 0xaa, 4, 0x3a, 0, 0x3e],
            Self::Enable => &[0x55, 0xaa, 5, 0x15, 1, 0, 0x1b],
            Self::Disable => &[0x55, 0xaa, 5, 0x15, 0, 0, 0x1a],
        }
    }
    fn reply_len(self) -> usize {
        match self {
            Self::Version => 5,
            Self::Heartbeat => 6,
            Self::Voltage => 7,
            Self::Disable | Self::Enable => 2,
        }
    }
    fn validate(self, addr: u8, bytes: &[u8]) -> Result<()> {
        let accepted = match self {
            // Deliberately exact: neither a caller hint nor a short/bare reply
            // can admit fw86, a bootloader or an unsupported application.
            Self::Version => bytes == [5, 0x17, 0x89, 0, 0xa5],
            Self::Heartbeat => {
                bytes.len() == 6
                    && bytes[0] == 6
                    && bytes[1] == 0x16
                    && bytes[2] == 1
                    && u16::from_be_bytes([bytes[4], bytes[5]])
                        == bytes[..4].iter().map(|&b| u16::from(b)).sum::<u16>()
            }
            Self::Disable | Self::Enable => bytes == [0x15, 1],
            Self::Voltage => {
                bytes.len() == 7
                    && bytes[0] == 7
                    && bytes[1] == 0x3a
                    && bytes[2] == 1
                    && u16::from_be_bytes([bytes[5], bytes[6]])
                        == bytes[..5].iter().map(|&b| u16::from(b)).sum::<u16>()
            }
        };
        if accepted {
            Ok(())
        } else {
            Err(bridge::fault(
                addr,
                format!("classic AML PIC {self:?} reply rejected: {bytes:02x?}"),
            ))
        }
    }
}

/// Available only after the actual retained worker observes the exact fw89
/// response. Construction is restricted to the platform's factory observer.
pub(crate) struct Endpoint {
    route: AmlPicLm75Route,
}

impl Endpoint {
    pub(crate) fn chain(&self) -> u8 {
        self.route.chain()
    }

    pub(crate) async fn observe(
        service: &I2cServiceHandle,
        board: u32,
        chain: u8,
        deadline: Instant,
    ) -> Result<Self> {
        let route = AmlPicLm75Route::bind(service, board, chain)?;
        request(service, &route, Operation::Version, deadline).await?;
        Ok(Self { route })
    }

    pub(crate) async fn heartbeat(
        &self,
        service: &I2cServiceHandle,
        deadline: Instant,
    ) -> Result<u8> {
        let reply = request(service, &self.route, Operation::Heartbeat, deadline).await?;
        Ok(reply[3])
    }

    pub(crate) async fn temperature(
        &self,
        service: &I2cServiceHandle,
        sensor: u8,
        deadline: Instant,
    ) -> Result<bridge::AmlPicLm75Sample> {
        service
            .read_classic_aml_pic_lm75_at(&self.route, sensor, deadline)
            .await
    }

    pub(crate) async fn voltage(
        &self,
        service: &I2cServiceHandle,
        deadline: Instant,
    ) -> Result<[u8; 2]> {
        let reply = request(service, &self.route, Operation::Voltage, deadline).await?;
        Ok([reply[3], reply[4]])
    }

    pub(crate) async fn enable(&self, service: &I2cServiceHandle, deadline: Instant) -> Result<()> {
        request(service, &self.route, Operation::Enable, deadline)
            .await
            .map(|_| ())
    }

    /// Reserved fixed cut remains available after ordinary generation closes.
    /// It reports an ACK, never an electrical cutoff measurement.
    pub(crate) async fn disable(
        &self,
        service: &I2cServiceHandle,
        deadline: Instant,
    ) -> Result<()> {
        self.route.validate_identity(service.bus, &service.safety)?;
        let service = service.clone();
        let route = self.route.clone();
        tokio::task::spawn_blocking(move || {
            let addr = route.address();
            let budget = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| bridge::fault(addr, "classic AML PIC disable deadline elapsed"))?;
            let mailbox = service.safe_off_mailbox.as_ref().ok_or_else(|| {
                bridge::fault(addr, "classic AML PIC needs retained terminal lane")
            })?;
            let (reply_tx, reply_rx) = mpsc::sync_channel(1);
            service.commit_pre_management_safe_off(addr, |permit| {
                mailbox.enqueue(
                    service.bus,
                    addr,
                    I2cSafeOffKey::ClassicAmlPicDisable { addr },
                    I2cSafeOffOperation::ClassicAmlPicDisable { route, deadline },
                    permit,
                    I2cSafeOffWaiter::Unit(reply_tx),
                )
            })?;
            wait_for_reserved_safe_off_receipt_with_budget(
                service.bus,
                addr,
                reply_rx,
                "classic AML PIC acknowledged disable",
                budget,
            )
        })
        .await
        .map_err(|error| {
            bridge::fault(
                self.route.address(),
                format!("classic AML cut worker: {error}"),
            )
        })?
    }
}

struct Cancellation {
    service: I2cServiceHandle,
    complete: bool,
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        if !self.complete {
            self.service.latch_terminal_safe_off();
        }
    }
}

async fn request(
    service: &I2cServiceHandle,
    route: &AmlPicLm75Route,
    operation: Operation,
    deadline: Instant,
) -> Result<Vec<u8>> {
    route.validate(service.bus, &service.safety, 0x48)?;
    let addr = route.address();
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    let req = I2cRequest::ClassicAmlPicApplication {
        addr,
        route: route.clone(),
        operation,
        deadline,
        reply_tx,
    };
    let budget = I2cRequestBudget::for_request_until(&req, deadline)
        .ok_or_else(|| bridge::fault(addr, "classic AML application deadline elapsed"))?;
    let mut cancellation = Cancellation {
        service: service.clone(),
        complete: false,
    };
    let service = service.clone();
    let result = tokio::task::spawn_blocking(move || {
        service.submit_with_intent_budget(
            addr,
            I2cOperationIntent::UnclassifiedMutation,
            req,
            reply_rx,
            budget,
        )
    })
    .await
    .map_err(|error| bridge::fault(addr, format!("classic AML application worker: {error}")))?;
    cancellation.complete = result.is_ok();
    result
}

fn execute_on(
    wire: &mut impl Wire,
    route: &AmlPicLm75Route,
    operation: Operation,
    permit: &I2cSafetyPermit,
    deadline: Instant,
) -> Result<Vec<u8>> {
    if matches!(operation, Operation::Disable) && permit.intent == I2cOperationIntent::SafeOff {
        route.validate_identity(wire.bus(), &permit.authority)?;
    } else {
        route.validate(wire.bus(), &permit.authority, 0x48)?;
    }
    let addr = route.address();
    bridge::live(permit, addr, deadline)?;
    bridge::guarded(wire, permit, addr, |wire, started| {
        {
            let _stage = permit.begin_stage(0, addr, "classic AML PIC selection")?;
            wire.select(addr)?;
        }
        for &byte in operation.frame() {
            bridge::live(permit, addr, deadline)?;
            let _stage = permit.begin_stage(0, addr, "classic AML PIC application frame")?;
            *started = true;
            wire.write_byte(byte)?;
        }
        bridge::wait(wire, permit, addr, deadline, 50)?;
        let mut reply = vec![0; operation.reply_len()];
        for byte in &mut reply {
            bridge::live(permit, addr, deadline)?;
            let _stage = permit.begin_stage(0, addr, "classic AML PIC application reply")?;
            *byte = wire.read_byte()?;
        }
        operation.validate(addr, &reply)?;
        bridge::live(permit, addr, deadline)?;
        let bit = 1 << (route.chain() - 1);
        match operation {
            Operation::Version | Operation::Enable => {
                permit
                    .authority
                    .classic_aml_pic_active
                    .fetch_or(bit, Ordering::SeqCst);
            }
            Operation::Disable => {
                permit
                    .authority
                    .classic_aml_pic_active
                    .fetch_and(!bit, Ordering::SeqCst);
            }
            Operation::Heartbeat | Operation::Voltage => {}
        }
        Ok(reply)
    })
}

pub(super) fn execute(
    bus: &mut I2cBus,
    route: &AmlPicLm75Route,
    operation: Operation,
    permit: &I2cSafetyPermit,
    deadline: Instant,
) -> Result<Vec<u8>> {
    if !bus.timeout_is_verified(I2C_SERVICE_DEFAULT_TIMEOUT_JIFFIES) {
        return Err(bridge::fault(
            route.address(),
            "classic AML application timeout is unverified",
        ));
    }
    execute_on(bus, route, operation, permit, deadline)
}

#[cfg(test)]
#[path = "aml_pic_application_tests.rs"]
mod tests;
