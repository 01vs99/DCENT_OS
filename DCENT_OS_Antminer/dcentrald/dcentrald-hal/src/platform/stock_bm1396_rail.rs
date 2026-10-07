//! Exact PIC rail acquisition: original full70 source population/wire vectors.
//! S17e opcode29 + opcode28, T17e opcode37; no generic PIC fallback or retry.
use super::*;

const CAPACITY: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RailFrameObservation {
    chain: u8,
    opcode: u8,
    request: [u8; 6],
    transmitted: usize,
    response: Vec<u8>,
    framing_complete: bool,
    received_at: Option<Instant>,
    completed_at: Option<Instant>,
}
impl RailFrameObservation {
    pub fn chain(&self) -> u8 {
        self.chain
    }
    pub fn opcode(&self) -> u8 {
        self.opcode
    }
    pub fn request(&self) -> &[u8; 6] {
        &self.request
    }
    pub fn completed_request_bytes(&self) -> usize {
        self.transmitted
    }
    pub fn response(&self) -> &[u8] {
        &self.response
    }
    pub fn framing_complete(&self) -> bool {
        self.framing_complete
    }
    pub fn received_at(&self) -> Option<Instant> {
        self.received_at
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RailSample {
    chain: u8,
    raw_voltage: u16,
    raw_reference: u16,
    voltage_v: f64,
    received_at: Instant,
}
impl RailSample {
    pub fn chain(&self) -> u8 {
        self.chain
    }
    pub fn raw_voltage(&self) -> u16 {
        self.raw_voltage
    }
    pub fn raw_reference(&self) -> u16 {
        self.raw_reference
    }
    pub fn voltage_v(&self) -> f64 {
        self.voltage_v
    }
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RailSnapshot {
    issuer: Arc<()>,
    sequence: u64,
    commanded: CommandedVoltage,
    frames: Vec<RailFrameObservation>,
    samples: Vec<RailSample>,
    within_target: Option<bool>,
    completed_at: Option<Instant>,
}
impl RailSnapshot {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn commanded_voltage(&self) -> CommandedVoltage {
        self.commanded
    }
    pub fn frames(&self) -> &[RailFrameObservation] {
        &self.frames
    }
    pub fn samples(&self) -> &[RailSample] {
        &self.samples
    }
    pub fn all_within_target(&self) -> Option<bool> {
        self.within_target
    }
    pub fn completed_at(&self) -> Option<Instant> {
        self.completed_at
    }
}

impl<H: Hardware> PicApplication<H> {
    pub fn rail_snapshots(&self) -> Result<Vec<RailSnapshot>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?
            .rails
            .iter()
            .cloned()
            .collect())
    }

    /// Acknowledges only the exact completed oldest snapshot from this owner.
    /// Caller custody then retains its original raw frame and timing evidence.
    pub fn acknowledge_rail_snapshot(&self, snapshot: &RailSnapshot) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?;
        if !Arc::ptr_eq(&snapshot.issuer, &self.owner.identity)
            || snapshot.completed_at.is_none()
            || state.rails.front() != Some(snapshot)
        {
            return Err(
                "BM1396 rail acknowledgment requires oldest exact completed owner snapshot".into(),
            );
        }
        state.rails.pop_front();
        Ok(())
    }

    /// Read every selected chain through its exact model-specific PIC route.
    /// Target is the retained accepted voltage request, never a caller scalar.
    /// A complete snapshot can report a below/above-tolerance rail; only its
    /// actual predicate is retained. Runtime requires new consecutive checks.
    /// Partial bytes and attempts remain retained across cancellation/failure.
    pub async fn acquire_commanded_rail_voltages(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<RailSnapshot, String> {
        let app = Arc::clone(self);
        self.owner
            .worker(deadline, false, move |_owner| {
                let lease = app.voltage_lease(deadline)?;
                app.acquire_rail_locked(&lease, deadline)
            })
            .await
    }

    /// Caller holds this application's logical voltage sequence lease.
    /// Shared by public acquisition and the retained consecutive verifier.
    pub(super) fn acquire_rail_locked(
        &self,
        lease: &VoltageLease<'_>,
        deadline: Instant,
    ) -> Result<RailSnapshot, String> {
        self.require_voltage_lease(lease)?;
        let app = self;
        let owner = &self.owner;
        app.require_health(deadline)?;
        owner.query_presence(deadline)?;
        let sequence = {
            let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
            if state.rails.len() >= CAPACITY {
                return Err("BM1396 retained rail snapshot capacity exhausted".into());
            }
            let commanded = state
                .last_voltage
                .ok_or("BM1396 rail check requires retained completed voltage request")?;
            let sequence = state.next_rail;
            state.next_rail = sequence
                .checked_add(1)
                .ok_or("BM1396 rail sequence exhausted")?;
            state.rails.push_back(RailSnapshot {
                issuer: Arc::clone(&owner.identity),
                sequence,
                commanded,
                frames: Vec::new(),
                samples: Vec::new(),
                within_target: None,
                completed_at: None,
            });
            sequence
        };
        for &chain in &owner.chains {
            // Keep voltage stable through the entire population. Release
            // the physical lane between chains for admitted heartbeats.
            let _lane = owner.lock(&owner.management, deadline, false)?;
            app.require_health(deadline)?;
            owner.query_presence(deadline)?;
            let ((voltage, received_at), reference) = match owner.model {
                Model::S17e => (
                    app.rail_frame(sequence, chain, 0x29, 9, deadline)?,
                    Some(app.rail_frame(sequence, chain, 0x28, 13, deadline)?.0),
                ),
                Model::T17e => (app.rail_frame(sequence, chain, 0x37, 11, deadline)?, None),
            };
            let (raw_voltage, raw_reference, voltage_v) =
                decode(owner.model, &voltage, reference.as_deref())?;
            app.rail_update(sequence, |snapshot| {
                snapshot.samples.push(RailSample {
                    chain,
                    raw_voltage,
                    raw_reference,
                    voltage_v,
                    received_at,
                })
            })?;
        }
        owner.query_presence(deadline)?;
        app.require_health(deadline)?;
        let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
        let snapshot = state
            .rails
            .back_mut()
            .filter(|snapshot| snapshot.sequence == sequence)
            .ok_or("BM1396 rail snapshot custody lost")?;
        if snapshot.samples.len() != owner.chains.len() || snapshot.samples.is_empty() {
            return Err("BM1396 rail population incomplete".into());
        }
        let target = f64::from(snapshot.commanded.requested_cv) / 100.0;
        snapshot.within_target = Some(
            snapshot
                .samples
                .iter()
                .all(|sample| (sample.voltage_v - target).abs() <= 1.0),
        );
        snapshot.completed_at = Some(Instant::now());
        Ok(snapshot.clone())
    }

    fn rail_update(
        &self,
        sequence: u64,
        update: impl FnOnce(&mut RailSnapshot),
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?;
        let snapshot = state
            .rails
            .back_mut()
            .filter(|snapshot| snapshot.sequence == sequence)
            .ok_or("BM1396 rail snapshot custody lost")?;
        update(snapshot);
        Ok(())
    }

    fn rail_frame_update(
        &self,
        sequence: u64,
        update: impl FnOnce(&mut RailFrameObservation),
    ) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC observations poisoned")?;
        let frame = state
            .rails
            .back_mut()
            .filter(|snapshot| snapshot.sequence == sequence)
            .and_then(|snapshot| snapshot.frames.last_mut())
            .ok_or("BM1396 rail frame custody lost")?;
        update(frame);
        Ok(())
    }

    fn rail_frame(
        &self,
        sequence: u64,
        chain: u8,
        opcode: u8,
        response_len: usize,
        deadline: Instant,
    ) -> Result<(Vec<u8>, Instant), String> {
        let owner = &self.owner;
        owner.chain(chain)?;
        owner.check(deadline, false)?;
        if owner.management_fault.load(Ordering::SeqCst) {
            return Err("BM1396 management portal unresolved".into());
        }
        let request = [0x55, 0xaa, 4, opcode, 0, 4 + opcode];
        self.rail_update(sequence, |snapshot| {
            snapshot.frames.push(RailFrameObservation {
                chain,
                opcode,
                request,
                transmitted: 0,
                response: Vec::with_capacity(response_len),
                framing_complete: false,
                received_at: None,
                completed_at: None,
            })
        })?;
        let prefix = 0x0040_0000 | (u32::from(chain) << 16);
        let mut fault = FaultGuard::new(&owner.management_fault, &owner.terminal);
        for byte in request {
            owner.management_byte_locked(prefix | u32::from(byte), deadline, false)?;
            self.rail_frame_update(sequence, |frame| frame.transmitted += 1)?;
        }
        owner.delay(Duration::from_millis(500), deadline, false)?;
        let mut response = Vec::with_capacity(response_len);
        for _ in 0..response_len {
            let byte = owner.management_byte_locked(prefix | 0x0200_0000, deadline, false)?;
            response.push(byte);
            self.rail_frame_update(sequence, |frame| frame.response.push(byte))?;
        }
        // Real final byte is retained before deadline/terminal status. A bad
        // complete reply does not fabricate an incomplete management portal.
        fault.complete();
        let received_at = Instant::now();
        self.rail_frame_update(sequence, |frame| {
            frame.framing_complete = true;
            frame.received_at = Some(received_at);
        })?;
        owner.check(deadline, false)?;
        owner.delay(Duration::from_millis(500), deadline, false)?;
        if !bm1396_pic_response_accepted(&response, response_len as u8, opcode) {
            return Err("BM1396 rail PIC length/opcode rejected".into());
        }
        owner.check(deadline, false)?;
        self.rail_frame_update(sequence, |frame| frame.completed_at = Some(Instant::now()))?;
        Ok((response, received_at))
    }
}

pub(in crate::platform::stock_bm1396) fn decode(
    model: Model,
    voltage: &[u8],
    reference: Option<&[u8]>,
) -> Result<(u16, u16, f64), String> {
    let (voltage, reference, divisor) = match model {
        Model::S17e => {
            let reference = reference.ok_or("BM1396 S17e reference reply missing")?;
            if !bm1396_pic_response_accepted(voltage, 9, 0x29)
                || !bm1396_pic_response_accepted(reference, 13, 0x28)
            {
                return Err("BM1396 S17e voltage/reference envelope".into());
            }
            let checksum = voltage[..7]
                .iter()
                .map(|&byte| u16::from(byte))
                .sum::<u16>();
            if u16::from_be_bytes([voltage[7], voltage[8]]) != checksum {
                return Err("BM1396 S17e voltage reply checksum".into());
            }
            (
                u16::from_be_bytes([voltage[3], voltage[4]]),
                u16::from_be_bytes([reference[9], reference[10]]),
                4096.0,
            )
        }
        Model::T17e => {
            if reference.is_some() || !bm1396_pic_response_accepted(voltage, 11, 0x37) {
                return Err("BM1396 T17e combined ADC envelope".into());
            }
            (
                u16::from_be_bytes([voltage[5], voltage[6]]),
                u16::from_be_bytes([voltage[7], voltage[8]]),
                1024.0,
            )
        }
    };
    let reference_v = (f64::from(reference) * 3.3) * (1.0 / divisor);
    if !(f64::from(2.36f32)..=f64::from(2.64f32)).contains(&reference_v) {
        return Err("BM1396 PIC ADC reference outside original window".into());
    }
    let scale = f64::from((reference_v / 2.5) as f32 * divisor as f32);
    let measured = ((f64::from(voltage) * 3.3) / scale) * f64::from(7.6f32);
    if !measured.is_finite() {
        return Err("BM1396 nonfinite PIC rail voltage".into());
    }
    Ok((voltage, reference, measured))
}
