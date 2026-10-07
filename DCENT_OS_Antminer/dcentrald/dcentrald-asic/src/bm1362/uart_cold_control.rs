//! Cold-stage commands through the held original UART, outside the work ring.
//! No command here proves physical reset, rail readiness, ASIC idle or population.
//! Register/value selection and full initialization ordering remain caller-owned.
use super::*;
use crate::bm1362::{
    build_broadcast_write_frame, build_chain_inactive_frame, build_get_address_frame,
    build_set_chip_address_frame, build_single_write_frame,
};
use crate::drivers::bm1362::regs;
use crate::protocol::{CMD_PREAMBLE, RESP_PREAMBLE};
use dcentrald_hal::serial_chain::{BaudTransitionAttempt, EnumerationBaudAttempt, NativeBbBaud};
use std::time::Duration;

#[path = "uart_assigned_scan.rs"]
mod assigned_scan;
pub(crate) use assigned_scan::AssignedScanObservation;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColdRegister {
    VersionMask,
    InitControl,
    CoreControl,
    TicketMask,
    IoDriver,
    AnalogMux,
    NonceRange,
    Pll0,
    FastUart,
}
impl ColdRegister {
    fn address(self) -> u8 {
        match self {
            Self::VersionMask => regs::VERSION_MASK,
            Self::InitControl => regs::INIT_CONTROL,
            Self::CoreControl => regs::CORE_REG_CTRL,
            Self::TicketMask => regs::TICKET_MASK,
            Self::IoDriver => regs::IO_DRIVER_STRENGTH,
            Self::AnalogMux => regs::ANALOG_MUX,
            Self::NonceRange => regs::HASH_COUNTING_NUMBER,
            Self::Pll0 => regs::PLL0,
            Self::FastUart => regs::FAST_UART_CONFIG,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ColdControl {
    GetAddress,
    /// Read-only actual kernel input/output rate plus retained cache observation.
    ObserveEnumerationBaud,
    HostBaud(NativeBbBaud),
    ChainInactive,
    SetChipAddress(u8),
    Broadcast {
        register: ColdRegister,
        value: u32,
    },
    Chip {
        address: u8,
        register: ColdRegister,
        value: u32,
    },
    MiscBroadcast(u32),
    MiscChip {
        address: u8,
        value: u32,
    },
    /// Fixed GetAddress plus 50ms settle and 100ms raw response window, as in
    /// the retained BB reset-baseline caller. Count is never chip population.
    ResetBaseline,
    /// Actual bounded UART window assessed against caller-declared addresses.
    /// Coverage is historical byte evidence, never physical population proof.
    AssignedScan {
        expected_addresses: Vec<u8>,
    },
}
enum Step {
    Write(Vec<u8>),
    Delay(u32),
}
fn wire(frame: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CMD_PREAMBLE.len() + frame.len());
    bytes.extend_from_slice(&CMD_PREAMBLE);
    bytes.extend_from_slice(frame);
    bytes
}
fn plan(control: &ColdControl) -> Vec<Step> {
    let frame = match *control {
        ColdControl::HostBaud(_) | ColdControl::ObserveEnumerationBaud => return Vec::new(),
        ColdControl::GetAddress | ColdControl::ResetBaseline | ColdControl::AssignedScan { .. } => {
            Some(wire(&build_get_address_frame()))
        }
        ColdControl::ChainInactive => Some(wire(&build_chain_inactive_frame())),
        ColdControl::SetChipAddress(address) => Some(wire(&build_set_chip_address_frame(address))),
        ColdControl::Broadcast { register, value } => Some(wire(&build_broadcast_write_frame(
            register.address(),
            value,
        ))),
        ColdControl::Chip {
            address,
            register,
            value,
        } => Some(wire(&build_single_write_frame(
            address,
            register.address(),
            value,
        ))),
        ColdControl::MiscBroadcast(_) | ColdControl::MiscChip { .. } => None,
    };
    if let Some(frame) = frame {
        return vec![Step::Write(frame)];
    }
    let source = match *control {
        ColdControl::MiscBroadcast(value) => {
            dcentrald_common::plan_misc_ctrl_triple_write_broadcast(value)
        }
        ColdControl::MiscChip { address, value } => {
            dcentrald_common::plan_misc_ctrl_triple_write_chip(address, value)
        }
        _ => unreachable!("single command returned above"),
    };
    source
        .into_iter()
        .map(|step| match step {
            dcentrald_common::TransportOp::SendWriteRegBroadcastBm1397Plus { reg, value } => {
                Step::Write(wire(&build_broadcast_write_frame(reg, value)))
            }
            dcentrald_common::TransportOp::SendWriteRegBm1397Plus {
                chip_addr,
                reg,
                value,
            } => Step::Write(wire(&build_single_write_frame(chip_addr, reg, value))),
            dcentrald_common::TransportOp::DelayMs { ms } => Step::Delay(ms),
            _ => unreachable!("retained MiscCtrl plan contains only writes and delays"),
        })
        .collect()
}

#[derive(Clone, Debug)]
pub(crate) struct ColdWrite {
    pub started_at: Instant,
    pub requested: Vec<u8>,
    pub attempt: RawWriteAttempt,
}
#[derive(Clone, Debug)]
pub(crate) struct ColdDelay {
    pub milliseconds: u32,
    pub started_at: Instant,
    pub completed_at: Option<Instant>,
}
#[derive(Clone, Debug)]
pub(crate) struct ResetBaselineObservation {
    pub window_started_at: Option<Instant>,
    pub window_completed_at: Option<Instant>,
    pub raw: Vec<u8>,
    pub reads: Vec<RawReadAttempt>,
    /// CRC-clean reset-baseline response count only; duplicate frames are not
    /// distinct chip identities, assigned coverage or a factory-population join.
    pub observed_frames: Option<u8>,
}
#[derive(Clone, Debug)]
pub(crate) struct ColdControlAttempt {
    pub chain: usize,
    pub control: ColdControl,
    pub started_at: Instant,
    pub deadline: Instant,
    pub writes: Vec<ColdWrite>,
    pub delays: Vec<ColdDelay>,
    pub baseline: Option<ResetBaselineObservation>,
    pub assigned_scan: Option<AssignedScanObservation>,
    pub host_baud: Option<BaudTransitionAttempt>,
    pub enumeration_baud: Option<EnumerationBaudAttempt>,
    pub caller_completed_at: Option<Instant>,
    pub failure: Option<String>,
}

struct ControlScope {
    stop: DispatchStop,
    completed: bool,
}
impl ControlScope {
    fn enter(stop: &DispatchStop) -> Result<Self, String> {
        stop.state
            .compare_exchange(HELD, HELD | CONTROL, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "cold control requires the sole held, live UART admission".to_owned())?;
        Ok(Self {
            stop: stop.clone(),
            completed: false,
        })
    }
}
impl Drop for ControlScope {
    fn drop(&mut self) {
        if !self.completed {
            self.stop.stop();
        }
        self.stop.state.fetch_and(!CONTROL, Ordering::SeqCst);
    }
}
fn check(stop: &DispatchStop, deadline: Instant) -> Result<(), String> {
    if stop.snapshot().permanently_stopped {
        return Err("cold control observed terminal stop".into());
    }
    if Instant::now() >= deadline {
        return Err("cold control original deadline expired".into());
    }
    Ok(())
}
fn wait(
    stop: &DispatchStop,
    deadline: Instant,
    milliseconds: u32,
    delays: &mut Vec<ColdDelay>,
) -> Result<(), String> {
    check(stop, deadline)?;
    let started = Instant::now();
    let end = started + Duration::from_millis(u64::from(milliseconds));
    delays.push(ColdDelay {
        milliseconds,
        started_at: started,
        completed_at: None,
    });
    while Instant::now() < end {
        check(stop, deadline)?;
        std::thread::sleep(
            Duration::from_millis(1)
                .min(end.saturating_duration_since(Instant::now()))
                .min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    check(stop, deadline)?;
    delays
        .last_mut()
        .expect("reserved actual delay")
        .completed_at = Some(Instant::now());
    Ok(())
}

fn baseline(
    uart: &mut SerialUart,
    stop: &DispatchStop,
    deadline: Instant,
    output: &mut ColdControlAttempt,
) -> Result<(), String> {
    output.baseline = Some(ResetBaselineObservation {
        window_started_at: None,
        window_completed_at: None,
        raw: Vec::new(),
        reads: Vec::new(),
        observed_frames: None,
    });
    wait(stop, deadline, 50, &mut output.delays)?;
    // Existing reset-baseline validator accepts at most u8::MAX responses.
    // Read one extra byte to detect overflow rather than accepting a truncated
    // maximum-size window. This bounded collector never flushes queued data.
    const MAX_RAW: usize = (u8::MAX as usize) * 9;
    const MAX_READS: usize = 128;
    let result = output
        .baseline
        .as_mut()
        .expect("reserved baseline observation");
    let started = Instant::now();
    let end = started + Duration::from_millis(100);
    result.window_started_at = Some(started);
    while Instant::now() < end {
        check(stop, deadline)?;
        if result.reads.len() == MAX_READS {
            return Err("reset-baseline raw caller read bound reached".into());
        }
        let capacity = (MAX_RAW + 1 - result.raw.len()).min(256);
        let mut bytes = vec![0; capacity];
        let attempt = uart
            .backend
            .read_raw_once_bounded(&mut bytes, deadline, &|| {
                stop.snapshot().permanently_stopped
            });
        result.raw.extend_from_slice(&attempt.bytes);
        let complete = attempt.status.caller_completed_at.is_some()
            && attempt.status.failure.is_none()
            && attempt.status.restore_error.is_none();
        let empty = attempt.returned_count == Some(0);
        result.reads.push(attempt);
        if !complete {
            return Err("reset-baseline raw read failed, stopped or expired".into());
        }
        if result.raw.len() > MAX_RAW {
            return Err("reset-baseline raw response bound exceeded".into());
        }
        if empty {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    check(stop, deadline)?;
    result.window_completed_at = Some(Instant::now());
    if result.raw.is_empty()
        || result.raw.len() % 9 != 0
        || result
            .raw
            .chunks_exact(9)
            .any(|frame| frame[..2] != RESP_PREAMBLE)
    {
        return Err("reset-baseline window is empty, incomplete or has a foreign preamble".into());
    }
    let validated = crate::bm1362::unassigned_address::validate_unassigned_address_window(
        result.raw.chunks_exact(9).map(|frame| &frame[2..]),
    )
    .map_err(|error| format!("reset-baseline response validation: {error:?}"))?;
    result.observed_frames = Some(validated.observed_frames().get());
    Ok(())
}

pub(super) fn control_held(
    owner: &mut BbSerialDispatchOwner,
    chain: usize,
    control: &ColdControl,
    deadline: Instant,
) -> ColdControlAttempt {
    control_inner(&mut owner.inner, chain, control, deadline)
}
impl BbSerialDispatchHold<'_> {
    pub(crate) fn cold_control_until(
        &mut self,
        chain: usize,
        control: &ColdControl,
        deadline: Instant,
    ) -> ColdControlAttempt {
        control_inner(self.inner.owner, chain, control, deadline)
    }
}
fn control_inner(
    owner: &mut BbDispatchOwner<SerialUart>,
    chain: usize,
    control: &ColdControl,
    deadline: Instant,
) -> ColdControlAttempt {
    let mut output = ColdControlAttempt {
        chain,
        control: control.clone(),
        started_at: Instant::now(),
        deadline,
        writes: Vec::new(),
        delays: Vec::new(),
        baseline: None,
        assigned_scan: None,
        host_baud: None,
        enumeration_baud: None,
        caller_completed_at: None,
        failure: None,
    };
    let stop = owner.stop.clone();
    let mut scope = match ControlScope::enter(&stop) {
        Ok(scope) => scope,
        Err(error) => {
            output.failure = Some(error);
            return output;
        }
    };
    let result = (|| -> Result<(), String> {
        check(&stop, deadline)?;
        // This path is for startup only. It never resets work attribution or
        // drains a pending mining response to manufacture a clean cold state.
        if owner
            .transport
            .state
            .iter()
            .any(|state| state.has_dispatched)
        {
            return Err("cold control refuses a transport that has dispatched mining work".into());
        }
        if owner
            .transport
            .rx_bm1362_serial
            .iter()
            .any(|bytes| !bytes.is_empty())
        {
            return Err("cold control refuses unresolved mining parser bytes".into());
        }
        if let ColdControl::AssignedScan { expected_addresses } = control {
            assigned_scan::validate_expected(expected_addresses)?;
            output.assigned_scan = Some(AssignedScanObservation::new(expected_addresses.clone()));
        }
        let uart = owner
            .transport
            .chains
            .get_mut(chain)
            .ok_or_else(|| "cold control chain outside original UART set".to_owned())?;
        for step in plan(control) {
            check(&stop, deadline)?;
            match step {
                Step::Write(requested) => {
                    let started_at = Instant::now();
                    let attempt = uart.backend.write_raw_until(&requested, deadline, &|| {
                        stop.snapshot().permanently_stopped
                    });
                    let complete = attempt.status.caller_completed_at.is_some()
                        && attempt.status.failure.is_none()
                        && attempt.status.restore_error.is_none()
                        && attempt.accepted_bytes == requested.len();
                    output.writes.push(ColdWrite {
                        started_at,
                        requested,
                        attempt,
                    });
                    if !complete {
                        return Err(
                            "cold control raw write was partial, failed, stopped or late".into(),
                        );
                    }
                }
                Step::Delay(milliseconds) => {
                    wait(&stop, deadline, milliseconds, &mut output.delays)?
                }
            }
        }
        if matches!(control, ColdControl::ResetBaseline) {
            baseline(uart, &stop, deadline, &mut output)?;
        }
        if matches!(control, ColdControl::AssignedScan { .. }) {
            assigned_scan::collect(uart, &stop, deadline, &mut output)?;
        }
        if matches!(control, ColdControl::ObserveEnumerationBaud) {
            let attempt = uart
                .backend
                .observe_native_bb_enumeration_baud_until(deadline, &|| {
                    stop.snapshot().permanently_stopped
                });
            let complete = attempt.caller_completed_at.is_some() && attempt.failure.is_none();
            output.enumeration_baud = Some(attempt);
            if !complete {
                return Err("cold enumeration baud observation failed, stopped or expired".into());
            }
        }
        if let ColdControl::HostBaud(baud) = control {
            let attempt = uart
                .backend
                .transition_native_bb_baud_until(*baud, deadline, &|| {
                    stop.snapshot().permanently_stopped
                });
            let complete = attempt.caller_completed_at.is_some() && attempt.failure.is_none();
            output.host_baud = Some(attempt);
            if !complete {
                return Err("cold host baud transition failed, stopped or expired".into());
            }
        }
        check(&stop, deadline)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            output.caller_completed_at = Some(Instant::now());
            scope.completed = true;
        }
        Err(error) => output.failure = Some(error),
    }
    output
}

#[cfg(test)]
#[path = "uart_cold_control_tests.rs"]
mod tests;
