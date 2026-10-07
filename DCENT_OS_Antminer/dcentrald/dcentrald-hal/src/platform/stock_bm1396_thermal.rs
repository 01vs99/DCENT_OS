//! Exact signed four-position thermal setup and automatic register-44 producer.
//! Source/replays: R06 native-thermal-source-v1 and bridge/topology vectors.
//! Everything shares the existing ASIC owner; no cache is mistaken for fresh IO.
use super::*;
use dcentrald_common::bm1396_contract::{
    bm1396_sensor_channel0_temperature, bm1396_sensor_channel1_temperature,
    bm1396_write_register_frame, Bm1396SensorSamplingMode,
};
use dcentrald_common::bm1396_work::Bm1396RegisterRecord;

const SENSOR_ADDRESS: u32 = 0x0098_0000;
const SNAPSHOT_CAPACITY: usize = 16;
const SOURCE_MAX_AGE: Duration = Duration::from_millis(6960);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SensorPosition {
    ordinal: u8,
    wire_address: u8,
}
impl SensorPosition {
    pub fn chip_ordinal(self) -> u8 {
        self.ordinal
    }
    pub fn wire_address(self) -> u8 {
        self.wire_address
    }
}
/// Original constructors: S17e 4bb74, T17e 4c764. Ordinals are not manufacturer IDs.
pub const fn sensor_positions(model: Model) -> [SensorPosition; 4] {
    let (ordinals, interval) = match model {
        Model::S17e => ([27, 35, 99, 107], 1),
        Model::T17e => ([17, 12, 65, 60], 3),
    };
    [
        SensorPosition {
            ordinal: ordinals[0],
            wire_address: ordinals[0] * interval,
        },
        SensorPosition {
            ordinal: ordinals[1],
            wire_address: ordinals[1] * interval,
        },
        SensorPosition {
            ordinal: ordinals[2],
            wire_address: ordinals[2] * interval,
        },
        SensorPosition {
            ordinal: ordinals[3],
            wire_address: ordinals[3] * interval,
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemperatureRecord {
    epoch: u64,
    historical: bool,
    register: Bm1396RegisterRecord,
    position: u8,
    ordinal: u8,
    channel0_raw: u8,
    channel1_raw: u8,
    received_at: Instant,
}
impl TemperatureRecord {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn is_historical(&self) -> bool {
        self.historical
    }
    pub fn register(&self) -> &Bm1396RegisterRecord {
        &self.register
    }
    pub fn position(&self) -> u8 {
        self.position
    }
    pub fn chip_ordinal(&self) -> u8 {
        self.ordinal
    }
    pub fn raw_channels(&self) -> [u8; 2] {
        [self.channel0_raw, self.channel1_raw]
    }
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
    pub fn temperatures_c(&self, mode: Bm1396SensorSamplingMode) -> [i16; 2] {
        [
            bm1396_sensor_channel0_temperature(self.channel0_raw),
            bm1396_sensor_channel1_temperature(self.channel1_raw, mode),
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThermalConfiguration {
    issuer: Arc<()>,
    model: Model,
    mode: Bm1396SensorSamplingMode,
    host_baud_register: u32,
    manufacturers: Vec<(u8, u8, u8)>,
    setup_records: Vec<PreservedReturn>,
    completed_at: Instant,
}
impl ThermalConfiguration {
    pub fn model(&self) -> Model {
        self.model
    }
    pub fn sampling_mode(&self) -> Bm1396SensorSamplingMode {
        self.mode
    }
    pub fn host_baud_register(&self) -> u32 {
        self.host_baud_register
    }
    /// Actual chain, ASIC wire address, separately read manufacturer ID.
    pub fn manufacturers(&self) -> &[(u8, u8, u8)] {
        &self.manufacturers
    }
    pub fn raw_setup_records(&self) -> &[PreservedReturn] {
        &self.setup_records
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThermalSnapshot {
    epoch: u64,
    issuer: Arc<()>,
    sequence: u64,
    mode: Bm1396SensorSamplingMode,
    samples: Vec<TemperatureRecord>,
    records: Vec<PreservedReturn>,
    completed_at: Instant,
}
impl ThermalSnapshot {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn samples(&self) -> &[TemperatureRecord] {
        &self.samples
    }
    pub fn raw_records(&self) -> &[PreservedReturn] {
        &self.records
    }
    pub fn sampling_mode(&self) -> Bm1396SensorSamplingMode {
        self.mode
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
    pub fn is_fresh_at(&self, now: Instant) -> bool {
        self.samples.iter().all(|sample| {
            now.checked_duration_since(sample.received_at)
                .is_some_and(|age| age < SOURCE_MAX_AGE)
        })
    }
}

#[derive(Default)]
pub(super) struct State {
    epoch: u64,
    config: Option<ThermalConfiguration>,
    automatic_allowed: bool,
    started: bool,
    snapshots: VecDeque<ThermalSnapshot>,
    next_snapshot: u64,
}
impl State {
    pub(super) fn complete_configuration(&self) -> Option<&ThermalConfiguration> {
        self.started.then(|| self.config.as_ref()).flatten()
    }

    pub(super) fn has_pending_snapshots(&self) -> bool {
        !self.snapshots.is_empty()
    }

    pub(super) fn configuration_matches_host(&self, host: u32) -> bool {
        self.started
            && self
                .config
                .as_ref()
                .is_some_and(|config| config.host_baud_register == host)
    }
}

impl<H: Hardware> Transport<H> {
    pub fn thermal_configuration(&self) -> Result<Option<ThermalConfiguration>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        Ok(state
            .thermal
            .as_ref()
            .filter(|thermal| thermal.started)
            .and_then(|thermal| thermal.config.clone()))
    }

    /// One cold configuration after chip assignment. Reads each exact sensor
    /// chip's live MiscCtrl, preserves unrelated bits, and verifies every ASIC
    /// write and sensor configuration readback. No unknown manufacturer fallback.
    pub async fn configure_thermal(
        self: &Arc<Self>,
        mode: Bm1396SensorSamplingMode,
        deadline: Instant,
    ) -> Result<(), String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.configure_thermal_serviced(&mut state, mode, deadline, &mut |_, _| Ok(()))
        })
        .await
    }

    pub(super) fn configure_thermal_serviced(
        &self,
        state: &mut AsicState,
        mode: Bm1396SensorSamplingMode,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        if state.thermal.is_some()
            || !state.publications.is_empty()
            || self.hardware.read(DHASH)? & RUN != 0
        {
            return Err(
                "BM1396 thermal setup requires unused cold engine and one configuration".into(),
            );
        }
        state.thermal = Some(State {
            epoch: state.thermal_epoch,
            next_snapshot: state
                .prior_thermal
                .as_ref()
                .map_or(0, |old| old.next_snapshot),
            ..State::default()
        });
        let mut fault = FaultGuard::new(&self.asic_fault, &self.terminal);
        self.query_presence(deadline)?;
        let host = self.hardware.read(0x3c)?;
        self.query_predrain(state, deadline)?;
        let mut records = Vec::new();
        let mut manufacturers = Vec::new();
        for &chain in &self.chains {
            for position in sensor_positions(self.model) {
                let chip = position.wire_address;
                let misc = self.thermal_query(
                    state,
                    chain,
                    chip,
                    0x18,
                    host,
                    deadline,
                    &mut records,
                    service,
                )?;
                let enabled_misc = (misc & !0x70) | 0x4030;
                self.thermal_write(state, chain, chip, 0x18, enabled_misc, deadline, service)?;
                if self.thermal_query(
                    state,
                    chain,
                    chip,
                    0x18,
                    host,
                    deadline,
                    &mut records,
                    service,
                )? != enabled_misc
                {
                    return Err("BM1396 thermal MiscCtrl readback mismatch".into());
                }
                self.thermal_write(state, chain, chip, 0x54, 0, deadline, service)?;
                if self.thermal_query(
                    state,
                    chain,
                    chip,
                    0x54,
                    host,
                    deadline,
                    &mut records,
                    service,
                )? != 0
                {
                    return Err("BM1396 thermal register54 readback mismatch".into());
                }
                let before = self.thermal_query(
                    state,
                    chain,
                    chip,
                    0x1c,
                    host,
                    deadline,
                    &mut records,
                    service,
                )?;
                Self::thermal_bridge_ready(before)?;
                let manufacturer = self.sensor_read(
                    state,
                    chain,
                    chip,
                    0xfe,
                    host,
                    deadline,
                    &mut records,
                    service,
                )?;
                if !matches!(manufacturer, 0x1a | 0x55) {
                    return Err("BM1396 exact source sensor manufacturer is not 1a/55".into());
                }
                for (register, data) in [(9, 4), (0x11, 0)] {
                    self.thermal_write(
                        state,
                        chain,
                        chip,
                        0x1c,
                        0x0101_0000 | SENSOR_ADDRESS | (u32::from(register) << 8) | u32::from(data),
                        deadline,
                        service,
                    )?;
                    self.query_receive_window_serviced(state, 1, host, deadline, |state| {
                        service(state, CommandServicePoint::IdleReceive)
                    })?;
                    let completion = self.thermal_query(
                        state,
                        chain,
                        chip,
                        0x1c,
                        host,
                        deadline,
                        &mut records,
                        service,
                    )?;
                    Self::thermal_bridge_ready(completion)?;
                    // Source verifies by a following read, not by treating
                    // this transport completion as measured sensor state.
                    if self.sensor_read(
                        state,
                        chain,
                        chip,
                        register,
                        host,
                        deadline,
                        &mut records,
                        service,
                    )? != data
                    {
                        return Err("BM1396 sensor configuration readback mismatch".into());
                    }
                }
                manufacturers.push((chain, chip, manufacturer));
            }
        }
        // Retain all setup reply custody before enabling automatic returns.
        // A failed automatic start leaves the incomplete state inaccessible
        // as a configuration receipt, but its raw setup records remain held.
        let ids: Vec<_> = records.iter().map(PreservedReturn::sequence).collect();
        let thermal = state.thermal.as_mut().expect("claimed");
        thermal.config = Some(ThermalConfiguration {
            issuer: Arc::clone(&self.identity),
            model: self.model,
            mode,
            host_baud_register: host,
            manufacturers,
            setup_records: records,
            completed_at: Instant::now(),
        });
        thermal.automatic_allowed = true;
        for &chain in &self.chains {
            for position in sensor_positions(self.model) {
                for _ in 0..2 {
                    self.thermal_write(
                        state,
                        chain,
                        position.wire_address,
                        0x1c,
                        0x0700_0000 | SENSOR_ADDRESS,
                        deadline,
                        service,
                    )?;
                }
            }
        }
        self.query_presence(deadline)?;
        self.query_host(host, deadline)?;
        service(state, CommandServicePoint::IdleReceive)?;
        let thermal = state.thermal.as_mut().expect("claimed");
        thermal.started = true;
        thermal.config.as_mut().expect("retained").completed_at = Instant::now();
        state.pending.retain(|raw| !ids.contains(&raw.sequence()));
        fault.complete();
        Ok(())
    }

    fn thermal_write(
        &self,
        state: &mut AsicState,
        chain: u8,
        chip: u8,
        register: u8,
        value: u32,
        deadline: Instant,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<(), String> {
        self.command_and_receive_locked(
            state,
            chain,
            &bm1396_write_register_frame(false, chip, register, value),
            deadline,
            service,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn thermal_query(
        &self,
        state: &mut AsicState,
        chain: u8,
        chip: u8,
        register: u8,
        host: u32,
        deadline: Instant,
        records: &mut Vec<PreservedReturn>,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<u32, String> {
        let replies = self.query_locked_serviced(
            state,
            chain,
            Some(chip),
            register,
            host,
            deadline,
            &mut *service,
        )?;
        let value = match replies.first().map(PreservedReturn::payload) {
            Some(ReturnPayload::Register(value)) if replies.len() == 1 => value.value,
            _ => return Err("BM1396 missing unique thermal register reply".into()),
        };
        records.extend(replies);
        Ok(value)
    }

    fn thermal_bridge_ready(value: u32) -> Result<(), String> {
        if value & 0xe000_0000 != 0 {
            return Err("BM1396 sensor bridge status is unresolved; no retry".into());
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sensor_read(
        &self,
        state: &mut AsicState,
        chain: u8,
        chip: u8,
        register: u8,
        host: u32,
        deadline: Instant,
        records: &mut Vec<PreservedReturn>,
        service: &mut dyn FnMut(&mut AsicState, CommandServicePoint) -> Result<(), String>,
    ) -> Result<u8, String> {
        self.thermal_write(
            state,
            chain,
            chip,
            0x1c,
            0x0100_0000 | SENSOR_ADDRESS | (u32::from(register) << 8),
            deadline,
            service,
        )?;
        self.query_receive_window_serviced(state, 1, host, deadline, |state| {
            service(state, CommandServicePoint::IdleReceive)
        })?;
        let value =
            self.thermal_query(state, chain, chip, 0x1c, host, deadline, records, service)?;
        Self::thermal_bridge_ready(value)?;
        if (value >> 8) as u8 != register {
            return Err("BM1396 sensor bridge register echo mismatch".into());
        }
        Ok(value as u8)
    }

    pub(super) fn decode_temperature(
        &self,
        state: &AsicState,
        register: Bm1396RegisterRecord,
    ) -> Result<TemperatureRecord, String> {
        let (epoch, historical) = if let Some(current) = state
            .thermal
            .as_ref()
            .filter(|thermal| thermal.automatic_allowed)
        {
            (current.epoch, false)
        } else if let Some(previous) = state
            .prior_thermal
            .as_ref()
            .filter(|thermal| thermal.automatic_allowed)
        {
            if state
                .requalification_deadline
                .is_none_or(|deadline| Instant::now() >= deadline)
            {
                return Err(
                    "T17e historical thermal receive is outside bounded requalification".into(),
                );
            }
            (previous.epoch, true)
        } else {
            return Err("BM1396 unsolicited temperature before owned sensor setup".into());
        };
        if register.value & 0xff00_ff00 != 0x100 {
            return Err("BM1396 automatic temperature status word invalid".into());
        }
        let positions = sensor_positions(self.model);
        let position = positions
            .iter()
            .position(|position| position.wire_address == register.chip_address)
            .ok_or("BM1396 temperature address outside exact source positions")?;
        Ok(TemperatureRecord {
            epoch,
            historical,
            register,
            position: position as u8,
            ordinal: positions[position].ordinal,
            channel0_raw: (register.value >> 16) as u8,
            channel1_raw: register.value as u8,
            received_at: Instant::now(),
        })
    }

    pub fn pending_thermal_snapshots(&self) -> Result<Vec<ThermalSnapshot>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        Ok(state
            .thermal
            .as_ref()
            .map(|thermal| thermal.snapshots.iter().cloned().collect())
            .unwrap_or_default())
    }

    pub fn acknowledge_thermal_snapshot(&self, snapshot: &ThermalSnapshot) -> Result<(), String> {
        let mut state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner busy or poisoned")?;
        self.acknowledge_thermal_snapshot_locked(&mut state, snapshot)
    }

    pub(super) fn acknowledge_thermal_snapshot_locked(
        &self,
        state: &mut AsicState,
        snapshot: &ThermalSnapshot,
    ) -> Result<(), String> {
        let thermal = state
            .thermal
            .as_mut()
            .ok_or("BM1396 thermal setup absent")?;
        if !Arc::ptr_eq(&snapshot.issuer, &self.identity)
            || snapshot.epoch != state.thermal_epoch
            || snapshot.epoch != thermal.epoch
            || thermal.snapshots.front() != Some(snapshot)
        {
            return Err("BM1396 thermal acknowledgment is foreign, stale or out of order".into());
        }
        thermal.snapshots.pop_front();
        Ok(())
    }

    /// Capture a new complete population already consumed by this ASIC owner.
    /// Cold control uses this while retaining its ASIC mutex and continuously
    /// receiving during the separate PIC worker's physical operations.
    pub(super) fn collect_thermal_locked(
        &self,
        state: &mut AsicState,
        watermark: u64,
        deadline: Instant,
    ) -> Result<Option<ThermalSnapshot>, String> {
        self.check(deadline, false)?;
        let thermal = state
            .thermal
            .as_ref()
            .filter(|thermal| thermal.started)
            .ok_or("BM1396 complete thermal setup absent")?;
        if thermal.snapshots.len() >= SNAPSHOT_CAPACITY {
            return Err("BM1396 retained thermal snapshot capacity exhausted".into());
        }
        let mode = thermal.config.as_ref().expect("started").mode;
        let mut samples = Vec::new();
        for &chain in &self.chains {
            for position in 0..4 {
                if let Some(sample) = state
                    .pending
                    .iter()
                    .rev()
                    .filter(|raw| raw.sequence() >= watermark)
                    .find_map(|raw| match raw.payload() {
                        ReturnPayload::Temperature(sample)
                            if sample.register.chain_slot == chain
                                && sample.position == position
                                && !sample.historical
                                && sample.epoch == thermal.epoch =>
                        {
                            Some(sample.clone())
                        }
                        _ => None,
                    })
                {
                    samples.push(sample);
                }
            }
        }
        if samples.len() != self.chains.len() * 4 {
            return Ok(None);
        }
        let now = Instant::now();
        if samples
            .iter()
            .any(|sample| now.duration_since(sample.received_at) >= SOURCE_MAX_AGE)
        {
            return Err("BM1396 thermal full-position collection became stale".into());
        }
        self.query_presence(deadline)?;
        let records: Vec<_> = state
            .pending
            .iter()
            .filter(|raw| {
                matches!(raw.payload(), ReturnPayload::Temperature(sample)
                if !sample.historical && sample.epoch == thermal.epoch)
            })
            .cloned()
            .collect();
        let thermal = state.thermal.as_mut().expect("started");
        let sequence = thermal
            .next_snapshot
            .checked_add(1)
            .ok_or("BM1396 thermal sequence overflow")?;
        let snapshot = ThermalSnapshot {
            epoch: thermal.epoch,
            issuer: Arc::clone(&self.identity),
            sequence,
            mode,
            samples,
            records,
            completed_at: now,
        };
        thermal.snapshots.push_back(snapshot.clone());
        thermal.next_snapshot = sequence;
        state.pending.retain(|raw| {
            !matches!(raw.payload(), ReturnPayload::Temperature(sample)
                if !sample.historical && sample.epoch == thermal.epoch)
        });
        Ok(Some(snapshot))
    }

    /// Requires one newly received automatic record for every selected chain's
    /// four positions. Old pending records cannot qualify this observation.
    /// All consumed temperature records move into retained snapshot custody;
    /// nonce and unrelated register custody remains in the original queue.
    pub async fn sample_thermal(self: &Arc<Self>, deadline: Instant) -> Result<u64, String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            let thermal = state
                .thermal
                .as_ref()
                .filter(|thermal| thermal.started)
                .ok_or("BM1396 complete thermal setup absent")?;
            if thermal.snapshots.len() >= SNAPSHOT_CAPACITY {
                return Err("BM1396 retained thermal snapshot capacity exhausted".into());
            }
            let mut fault = FaultGuard::new(&this.asic_fault, &this.terminal);
            this.query_presence(deadline)?;
            this.query_predrain(&mut state, deadline)?;
            // Records already observed by another actor have real timestamps but
            // cannot fulfill this fresh collection. They remain retained too.
            let watermark = state.next_return;
            for _ in 0..697 {
                this.receive_locked(&mut state, 128, deadline)?;
                if let Some(snapshot) =
                    this.collect_thermal_locked(&mut state, watermark, deadline)?
                {
                    fault.complete();
                    return Ok(snapshot.sequence());
                }
                this.delay(Duration::from_millis(10), deadline, false)?;
            }
            Err("BM1396 fresh thermal full-position collection exhausted".into())
        })
        .await
    }
}
