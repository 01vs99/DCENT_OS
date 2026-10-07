//! Source-backed S15/T15 local board-temperature sensors on the ASIC I2C bridge.
//! Source/replay: evidence/r04/power-thermal-{source,topology-replay-v1}.json.
//! No physical conversion timestamp or measured ASIC-junction temperature exists
//! on this route. The stock PCB+15 value is explicitly an estimate here.
use super::*;
use dcentrald_common::bm1391_stock_return::{Bm1391StockNonceReturn, Bm1391StockRegisterReturn};
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

const MAX_PENDING_NONCES: usize = 4096;
const MAX_RETURN_WINDOW: usize = 4096;
const BRIDGE: u8 = 0x1c;
const MISC_CONTROL: u8 = 0x18;
const I2C_ENABLE_BITS: u32 = 0x4030;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThermalSensor {
    pub chain: u8,
    pub chip_address: u8,
    /// Full stock bridge address byte, not a Linux seven-bit I2C address.
    pub sensor_address: u8,
    pub manufacturer: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardTemperature {
    pub sensor: ThermalSensor,
    pub raw_extended: u8,
    pub pcb_celsius: i16,
    /// Original arithmetic PCB+15; never a measured ASIC temperature.
    pub estimated_chip_celsius: i16,
    /// Host receipt time of the correlated register reply. The bridge has no
    /// request ID or physical conversion timestamp; this is not either one.
    pub observed_at: Instant,
    pub bridge_reply: Bm1391StockRegisterReturn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreservedThermalNonce {
    /// Monotonic within this retained service. A repeated snapshot repeats IDs.
    pub sequence: u64,
    pub record: Bm1391StockNonceReturn,
}

#[derive(Debug)]
pub struct ThermalOutcome<T> {
    pub result: Result<T, String>,
    /// Process these with the same mining epoch/work registry as normal FIFO
    /// returns, then acknowledge. They remain retained even if this result is
    /// dropped or the async caller is cancelled while its worker returns.
    pub pending_nonces: Vec<PreservedThermalNonce>,
    pub discarded_register_replies: usize,
}

struct NonceCustody {
    pending: VecDeque<PreservedThermalNonce>,
    next_sequence: u64,
    highest_exposed: u64,
}
impl Default for NonceCustody {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            next_sequence: 1,
            highest_exposed: 0,
        }
    }
}

/// One service per retained transport. Keep this Arc through terminal worker
/// drain and nonce acknowledgment. The caller must retain current mining-epoch
/// custody: read replies carry no wire request ID, and arbitrarily delayed
/// identical replies cannot be distinguished by any software correlation.
pub struct ThermalApplication<R: Registers> {
    owner: Arc<Transport<R>>,
    endpoints: Vec<(u8, u8)>,
    sensors: Mutex<Option<Vec<ThermalSensor>>>,
    operation: Mutex<()>,
    in_flight: AtomicUsize,
    nonces: Mutex<NonceCustody>,
}

// Count queued workers as well as running ones. A cancelled future may leave a
// worker not yet scheduled; an ordinary mutex barrier alone misses that case.
struct ThermalWorker<R: Registers>(Arc<ThermalApplication<R>>);
impl<R: Registers> Drop for ThermalWorker<R> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<R: Registers> ThermalApplication<R> {
    /// Join this owner's pre-enable full EEPROM observations to the current
    /// complete ASIC census. No management IO occurs here, so heartbeat service
    /// remains available after power enable. The sealed pages belong to this
    /// exact retained transport; they are observations at PIC admission time,
    /// not a new physical EEPROM read or a hotplug-proof identity.
    pub fn from_pic_observation(
        pic: &Arc<PicApplication<R>>,
        population: &[Census],
        deadline: Instant,
    ) -> Result<Arc<Self>, String> {
        let owner = pic.transport().clone();
        owner.active(deadline)?;
        let model = owner
            .registers
            .model()
            .ok_or("BM1391 thermal mapping lacks model identity")?;
        if population.len() != owner.chains.len()
            || population
                .iter()
                .map(|c| c.chain)
                .ne(owner.chains.iter().copied())
            || pic
                .observed_pages()
                .iter()
                .map(|(chain, _)| *chain)
                .ne(owner.chains.iter().copied())
        {
            return Err(
                "BM1391 retained PIC pages/census do not cover the exact population".into(),
            );
        }
        for census in population {
            validate_census(model, census)?;
        }
        owner
            .thermal_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1391 transport already has thermal custody".to_string())?;
        let result = (|| {
            let mut endpoints = Vec::new();
            for (census, (_, page)) in population.iter().zip(pic.observed_pages()) {
                endpoints.extend(topology_from_page(model, census, page)?);
            }
            owner.active(deadline)?;
            Ok(Arc::new(Self {
                owner: owner.clone(),
                endpoints,
                sensors: Mutex::new(None),
                operation: Mutex::new(()),
                in_flight: AtomicUsize::new(0),
                nonces: Mutex::new(NonceCustody::default()),
            }))
        })();
        if result.is_err() {
            owner.latch_terminal();
        }
        result
    }

    /// Bind the original type1 topology to fresh complete read-only EEPROM
    /// pages and a complete observed BM1391 population. No sensor command is
    /// emitted here. Initialization remains a separate reviewable operation.
    /// Use from_pic_observation in the enabled native lifecycle: a full-page
    /// read holds the management lane and can delay ongoing PIC heartbeats.
    pub async fn observe(
        owner: Arc<Transport<R>>,
        model: Model,
        population: &[Census],
        deadline: Instant,
    ) -> Result<Arc<Self>, String> {
        if owner.registers.model() != Some(model) {
            return Err("BM1391 thermal model does not match the retained mapping".into());
        }
        if population.len() != owner.chains.len()
            || population
                .iter()
                .map(|c| c.chain)
                .ne(owner.chains.iter().copied())
        {
            return Err("BM1391 thermal census does not match the retained population".into());
        }
        for census in population {
            validate_census(model, census)?;
        }
        owner
            .thermal_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1391 transport already has thermal custody".to_string())?;
        let mut cancellation = AsyncCancellation::new(owner.clone());
        let result = async {
            let mut endpoints = Vec::new();
            for census in population {
                let page = owner.read_eeprom(census.chain, deadline).await?;
                endpoints.extend(topology_from_page(model, census, &page)?);
            }
            owner.active(deadline)?;
            Ok(Arc::new(Self {
                owner: owner.clone(),
                endpoints,
                sensors: Mutex::new(None),
                operation: Mutex::new(()),
                in_flight: AtomicUsize::new(0),
                nonces: Mutex::new(NonceCustody::default()),
            }))
        }
        .await;
        if result.is_err() {
            owner.latch_terminal();
        }
        cancellation.complete();
        result
    }

    pub async fn initialize(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> ThermalOutcome<Vec<ThermalSensor>> {
        self.run(deadline, |service, deadline, delay, discarded| {
            service.initialize_locked(deadline, delay, discarded)
        })
        .await
    }

    pub async fn sample(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> ThermalOutcome<Vec<BoardTemperature>> {
        self.run(deadline, |service, deadline, delay, discarded| {
            service.sample_locked(deadline, delay, discarded)
        })
        .await
    }

    async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        deadline: Instant,
        operation: impl FnOnce(
                &Self,
                Instant,
                &mut dyn FnMut(u64) -> Result<(), String>,
                &mut usize,
            ) -> Result<T, String>
            + Send
            + 'static,
    ) -> ThermalOutcome<T> {
        let mut cancellation = AsyncCancellation::new(self.owner.clone());
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let worker = ThermalWorker(self.clone());
        let result = tokio::task::spawn_blocking(move || {
            let service = &worker.0;
            let _operation = Transport::<R>::lock_lane_until(&service.operation, deadline)?;
            let mut discarded = 0;
            let result = service.owner.with_asic_lane(deadline, || {
                service.owner.active(deadline)?;
                operation(
                    service,
                    deadline,
                    &mut |milliseconds| service.delay(milliseconds, deadline),
                    &mut discarded,
                )
            });
            Ok::<_, String>(ThermalOutcome {
                result,
                pending_nonces: service.snapshot_nonces(),
                discarded_register_replies: discarded,
            })
        })
        .await;
        let outcome = match result {
            Ok(Ok(outcome)) => outcome,
            other => {
                self.owner.latch_terminal();
                ThermalOutcome {
                    result: Err(match other {
                        Ok(Err(error)) => error,
                        Err(error) => format!("BM1391 thermal worker: {error}"),
                        Ok(Ok(_)) => unreachable!(),
                    }),
                    pending_nonces: self.snapshot_nonces(),
                    discarded_register_replies: 0,
                }
            }
        };
        cancellation.complete();
        outcome
    }

    /// Wait for queued and running thermal workers, then snapshot retained
    /// nonces. Works after terminal/cancellation. It does not drain the FPGA:
    /// the runtime retains responsibility for unread FIFO records and epoch cut.
    pub async fn pending_nonces_after_drain(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Vec<PreservedThermalNonce>, String> {
        let service = self.clone();
        tokio::task::spawn_blocking(move || loop {
            if Instant::now() >= deadline {
                return Err("BM1391 thermal nonce worker drain timed out".into());
            }
            if service.in_flight.load(Ordering::SeqCst) == 0 {
                let _operation = Transport::<R>::lock_lane_until(&service.operation, deadline)?;
                if service.in_flight.load(Ordering::SeqCst) == 0 {
                    return Ok(service.snapshot_nonces());
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        })
        .await
        .map_err(|e| format!("BM1391 thermal nonce drain worker: {e}"))?
    }

    /// Call only after all exposed nonce records through this sequence have
    /// been processed. Acknowledgment is idempotent and never touches hardware.
    pub fn acknowledge_nonces_through(&self, sequence: u64) -> Result<(), String> {
        let mut custody = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        if sequence > custody.highest_exposed {
            return Err("BM1391 thermal nonce acknowledgment exceeds exposed custody".into());
        }
        while custody
            .pending
            .front()
            .is_some_and(|n| n.sequence <= sequence)
        {
            custody.pending.pop_front();
        }
        Ok(())
    }

    fn snapshot_nonces(&self) -> Vec<PreservedThermalNonce> {
        let mut custody = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(last) = custody.pending.back() {
            custody.highest_exposed = last.sequence;
        }
        custody.pending.iter().copied().collect()
    }

    fn delay(&self, milliseconds: u64, deadline: Instant) -> Result<(), String> {
        let until = Instant::now() + Duration::from_millis(milliseconds);
        loop {
            self.owner.active(deadline)?;
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return Ok(());
            };
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }

    // Same retained ASIC lane and decoder as ordinary returns. Preserve every
    // consumed nonce before population validation, including invalid stock flags
    // or a wrong chain: canonical mining classification must receive them too.
    fn read_retaining_nonce(
        &self,
        deadline: Instant,
    ) -> Result<Option<Bm1391StockFpgaReturn>, String> {
        self.owner.active(deadline)?;
        if self.owner.registers.read(RETURN_COUNT)? & 0x1ff == 0 {
            return Ok(None);
        }
        let mut custody = self.nonces.lock().unwrap_or_else(|e| e.into_inner());
        if custody.pending.len() >= MAX_PENDING_NONCES || custody.next_sequence == u64::MAX {
            return Err("BM1391 thermal nonce custody is full; FIFO remains unread".into());
        }
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.owner.registers.read(RETURN0)?.to_le_bytes());
        bytes[4..].copy_from_slice(&self.owner.registers.read(RETURN1)?.to_le_bytes());
        let record = decode_bm1391_stock_fpga_return(&bytes).map_err(|e| format!("{e:?}"))?;
        if let Bm1391StockFpgaReturn::Nonce(nonce) = record {
            let sequence = custody.next_sequence;
            custody.pending.push_back(PreservedThermalNonce {
                sequence,
                record: nonce,
            });
            custody.next_sequence += 1;
        }
        Ok(Some(record))
    }

    fn drain_existing(&self, deadline: Instant, discarded: &mut usize) -> Result<(), String> {
        for _ in 0..MAX_RETURN_WINDOW {
            match self.read_retaining_nonce(deadline)? {
                None => return Ok(()),
                Some(Bm1391StockFpgaReturn::Nonce(_)) => {}
                Some(Bm1391StockFpgaReturn::Register(_)) => *discarded += 1,
            }
        }
        Err("BM1391 thermal pre-request return drain exceeded its bound".into())
    }

    fn read_register_locked(
        &self,
        chain: u8,
        chip: u8,
        register: u8,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
        discarded: &mut usize,
    ) -> Result<Bm1391StockRegisterReturn, String> {
        self.drain_existing(deadline, discarded)?;
        // Original S15 81128 / T15 810f0 waits80ms after publishing a read.
        // This native500ms response cap is an operational bound, not a measured
        // propagation maximum. Never retry an unresolved read request.
        let reply_deadline = deadline.min(Instant::now() + Duration::from_millis(500));
        self.owner.publish_command_locked(
            chain,
            &Transport::<R>::short_frame(0x42, chip, register),
            reply_deadline,
        )?;
        delay(80)?;
        for _ in 0..MAX_RETURN_WINDOW {
            self.owner.active(reply_deadline)?;
            match self.read_retaining_nonce(reply_deadline)? {
                Some(Bm1391StockFpgaReturn::Register(reply))
                    if reply.chain_slot == chain
                        && reply.chip_address == chip
                        && reply.register == register =>
                {
                    if !census::response_crc_valid(reply) {
                        return Err("BM1391 thermal correlated register reply has bad CRC".into());
                    }
                    return Ok(reply);
                }
                Some(Bm1391StockFpgaReturn::Register(_)) => *discarded += 1,
                Some(Bm1391StockFpgaReturn::Nonce(_)) => {}
                None => delay(1)?,
            }
        }
        Err("BM1391 thermal response window exceeded its bound".into())
    }

    fn bridge_ready(
        &self,
        chain: u8,
        chip: u8,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
        discarded: &mut usize,
    ) -> Result<Bm1391StockRegisterReturn, String> {
        // Original response reader refuses bits31/30; five bounded observations
        // can wait for a busy bridge, without replaying the sensor transaction.
        for _ in 0..5 {
            let reply =
                self.read_register_locked(chain, chip, BRIDGE, deadline, delay, discarded)?;
            if reply.value & 0xc000_0000 == 0 {
                return Ok(reply);
            }
            delay(1)?;
        }
        Err("BM1391 ASIC temperature bridge remained busy or faulted".into())
    }

    fn sensor_read(
        &self,
        sensor: ThermalSensor,
        register: u8,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
        discarded: &mut usize,
    ) -> Result<Bm1391StockRegisterReturn, String> {
        self.bridge_ready(
            sensor.chain,
            sensor.chip_address,
            deadline,
            delay,
            discarded,
        )?;
        self.owner.publish_command_locked(
            sensor.chain,
            &bridge_frame::<R>(
                sensor.chip_address,
                sensor.sensor_address,
                register,
                0,
                false,
            ),
            deadline,
        )?;
        delay(1)?;
        let reply = self.bridge_ready(
            sensor.chain,
            sensor.chip_address,
            deadline,
            delay,
            discarded,
        )?;
        delay(1)?;
        self.owner.active(deadline)?;
        if (reply.value >> 8) as u8 != register {
            return Err("BM1391 temperature sensor register echo mismatch".into());
        }
        Ok(reply)
    }

    fn configure_extended(
        &self,
        sensor: ThermalSensor,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
        discarded: &mut usize,
    ) -> Result<(), String> {
        self.bridge_ready(
            sensor.chain,
            sensor.chip_address,
            deadline,
            delay,
            discarded,
        )?;
        self.owner.publish_command_locked(
            sensor.chain,
            &bridge_frame::<R>(sensor.chip_address, sensor.sensor_address, 9, 4, true),
            deadline,
        )?;
        self.bridge_ready(
            sensor.chain,
            sensor.chip_address,
            deadline,
            delay,
            discarded,
        )?;
        delay(1)?;
        let reply = self.sensor_read(sensor, 9, deadline, delay, discarded)?;
        // Stock erroneously accepts register OR value. Require both, because
        // interpreting the local temperature depends on extended scale being4.
        if reply.value as u8 != 4 {
            return Err("BM1391 temperature extended-range configuration readback mismatch".into());
        }
        Ok(())
    }

    fn initialize_locked(
        &self,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
        discarded: &mut usize,
    ) -> Result<Vec<ThermalSensor>, String> {
        if self
            .sensors
            .lock()
            .map_err(|_| "BM1391 thermal state poisoned")?
            .is_some()
        {
            return Err("BM1391 thermal sensors are already initialized".into());
        }
        let mut sensors = Vec::new();
        for &(chain, chip) in &self.endpoints {
            let previous =
                self.read_register_locked(chain, chip, MISC_CONTROL, deadline, delay, discarded)?;
            let enabled = previous.value | I2C_ENABLE_BITS;
            self.owner.publish_command_locked(
                chain,
                &Transport::<R>::register_frame(chip, false, MISC_CONTROL, enabled),
                deadline,
            )?;
            let actual =
                self.read_register_locked(chain, chip, MISC_CONTROL, deadline, delay, discarded)?;
            if actual.value != enabled {
                return Err("BM1391 sensor bridge MiscCtrl readback mismatch".into());
            }
            let mut observed = None;
            for sensor_address in [0x98, 0x9a, 0x9c] {
                let mut sensor = ThermalSensor {
                    chain,
                    chip_address: chip,
                    sensor_address,
                    manufacturer: 0,
                };
                let reply = self.sensor_read(sensor, 0xfe, deadline, delay, discarded)?;
                let manufacturer = reply.value as u8;
                if matches!(manufacturer, 0x55 | 0x1a | 0x41) {
                    sensor.manufacturer = manufacturer;
                    observed = Some(sensor);
                    break;
                }
            }
            let sensor = observed
                .ok_or("BM1391 sensor manufacturer is not supported at this proved endpoint")?;
            self.configure_extended(sensor, deadline, delay, discarded)?;
            sensors.push(sensor);
        }
        self.owner.active(deadline)?;
        *self
            .sensors
            .lock()
            .map_err(|_| "BM1391 thermal state poisoned")? = Some(sensors.clone());
        Ok(sensors)
    }

    fn sample_locked(
        &self,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
        discarded: &mut usize,
    ) -> Result<Vec<BoardTemperature>, String> {
        let sensors = self
            .sensors
            .lock()
            .map_err(|_| "BM1391 thermal state poisoned")?
            .clone()
            .ok_or("BM1391 thermal sensors have not completed initialization")?;
        let mut samples = Vec::new();
        for sensor in sensors {
            let reply = self.sensor_read(sensor, 0, deadline, delay, discarded)?;
            let raw_extended = reply.value as u8;
            let pcb_celsius = i16::from(raw_extended) - 0x40;
            samples.push(BoardTemperature {
                sensor,
                raw_extended,
                pcb_celsius,
                estimated_chip_celsius: pcb_celsius + 15,
                observed_at: Instant::now(),
                bridge_reply: reply,
            });
        }
        self.owner.active(deadline)?;
        Ok(samples)
    }
}

fn bridge_frame<R: Registers>(
    chip: u8,
    sensor: u8,
    register: u8,
    data: u8,
    write: bool,
) -> [u8; 12] {
    // Original S15 7ccf4 / T15 7ccbc: 41 09 CHIP 1c 01 SENSOR REG DATA CRC5.
    Transport::<R>::register_frame(
        chip,
        false,
        BRIDGE,
        0x0100_0000
            | (u32::from(sensor | u8::from(write)) << 16)
            | (u32::from(register) << 8)
            | u32::from(data),
    )
}

fn validate_census(model: Model, census: &Census) -> Result<(), String> {
    if census.replies.len() != usize::from(model.expected_chips()) {
        return Err("BM1391 thermal topology requires a complete exact model census".into());
    }
    for (index, reply) in census.replies.iter().copied().enumerate() {
        if reply.chain_slot != census.chain
            || reply.register != 0
            || reply.value >> 16 != 0x1391
            || !census::response_crc_valid(reply)
            || usize::from(reply.chip_address) != index * usize::from(model.address_interval())
        {
            return Err("BM1391 thermal census address, identity or CRC mismatch".into());
        }
    }
    Ok(())
}

fn topology_from_page(
    model: Model,
    census: &Census,
    page: &[u8; 256],
) -> Result<Vec<(u8, u8)>, String> {
    validate_census(model, census)?;
    let crc = dcentrald_common::bm1391_stock_work::bm1391_stock_job_crc16(&page[..254]);
    if !matches!(page[0], 0x7e | 0x7f) || crc != u16::from_le_bytes([page[254], page[255]]) {
        return Err("BM1391 thermal EEPROM header or complete-page CRC is invalid".into());
    }
    if page[0x79] != 1 {
        return Err(
            "BM1391 thermal EEPROM type is outside the source-validated type1 topology".into(),
        );
    }
    // Original topology producer81988/81950 overwrites four one-based sensor
    // positions and zero offsets. Initializer822e0/822a8 applies model interval.
    let positions = match model {
        Model::S15 => [18, 13, 54, 49],
        Model::T15 => [15, 11, 45, 41],
    };
    Ok(positions
        .into_iter()
        .map(|position| (census.chain, (position - 1) * model.address_interval()))
        .collect())
}

#[cfg(test)]
#[path = "stock_bm1391_thermal_tests.rs"]
mod tests;
