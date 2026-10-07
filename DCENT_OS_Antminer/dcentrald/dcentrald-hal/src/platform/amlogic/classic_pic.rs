//! Retained classic AML PIC observation/application owner. Power commands stay
//! private to the joined classic power owner; no firmware transition is exposed.
#[path = "classic_power.rs"]
mod power;
use super::*;
use crate::i2c::{aml_pic_application::Endpoint, I2cServiceOwner, I2cServiceTerminalFence};
use dcentrald_api_types::deployed_eeprom::decode_deployed_eeprom;
use dcentrald_api_types::hashboard_eeprom::observed_protocol_from_deployed_page;
use dcentrald_api_types::zhiju_eeprom::Crc5Check;
use dcentrald_common::AsicProtocolIdentity;
pub use power::{ClassicAmlPowerOwner, ClassicHealth, ClassicPowerCloseReport};

fn error(message: impl Into<String>) -> HalError {
    HalError::Platform(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    boot_id: String,
    populated: [bool; 3],
}

trait Observation: Send + Sync {
    /// Initial cold-state admission is distinct from retained identity. Power
    /// startup deliberately changes reset/rail GPIOs after this check.
    fn admit_boot(&self) -> Result<()> {
        Ok(())
    }
    fn read(&self) -> Result<Snapshot>;
}
struct LiveObservation;

/// Stock's subtype file is optional consistency metadata on a native image.
/// It is not a substitute for this owner's fresh factory and PIC observations.
fn read_optional_subtype(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(cause) => Err(error(format!("classic subtype metadata: {cause}"))),
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(error("classic subtype must be a regular file when present"));
            }
            fs::read_to_string(path)
                .map(|value| Some(value.trim_matches(['\0', '\n', '\r', ' ']).to_owned()))
                .map_err(|cause| error(format!("classic subtype read: {cause}")))
        }
    }
}

impl Observation for LiveObservation {
    fn admit_boot(&self) -> Result<()> {
        validate_amlogic_boot_safe_handoff_for(|platform, target| {
            platform == "am3-aml-s19jpro" && target == "am3-s19jpro-aml"
        })
        .map(|_| ())
    }
    fn read(&self) -> Result<Snapshot> {
        let read = |path: &str| {
            fs::read_to_string(path)
                .map(|s| s.trim_matches(['\0', '\n', '\r', ' ']).to_owned())
                .map_err(|e| error(format!("classic AML identity {path}: {e}")))
        };
        let marker = read("/etc/dcentos-platform")?;
        if read("/etc/dcentos/board_target")? != "am3-s19jpro-aml" {
            return Err(error("classic AML retained board target changed"));
        }
        let subtype = read_optional_subtype(Path::new("/etc/subtype"))?;
        let model = read("/proc/device-tree/model")?;
        let boot_id = read("/proc/sys/kernel/random/boot_id")?;
        let populated = read_plug_topology_checked()?;
        validate_observations(
            &marker,
            subtype.as_deref(),
            &model,
            &boot_id,
            populated,
            S21_UARTS.map(|uart| Path::new(uart).exists()),
        )
    }
}

fn validate_observations(
    marker: &str,
    subtype: Option<&str>,
    model: &str,
    boot_id: &str,
    populated: [bool; 3],
    uarts: [bool; 3],
) -> Result<Snapshot> {
    if marker != "am3-aml-s19jpro"
        || subtype.is_some_and(|value| value != "AMLCtrl_BHB42XXX")
        || !model.to_ascii_lowercase().contains("amlogic")
        || boot_id.len() != 36
        || boot_id.chars().filter(|c| *c != '-').count() != 32
        || !boot_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
        || !populated.iter().any(|&p| p)
        || populated.iter().zip(uarts).any(|(&p, uart)| p && !uart)
    {
        return Err(error(
            "classic AML current controller/boot/population/UART identity rejected",
        ));
    }
    Ok(Snapshot {
        boot_id: boot_id.to_owned(),
        populated,
    })
}

#[derive(Default)]
struct Cancellation {
    terminal: AtomicBool,
    fences: Mutex<Vec<I2cServiceTerminalFence>>,
}
impl Cancellation {
    fn latch(&self) {
        self.terminal.store(true, Ordering::SeqCst);
        for fence in self.fences.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            fence.latch_terminal_safe_off();
        }
    }
    fn live(&self, deadline: Instant) -> Result<()> {
        if self.terminal.load(Ordering::SeqCst) || Instant::now() >= deadline {
            return Err(error(
                "classic AML application cancelled or deadline elapsed",
            ));
        }
        Ok(())
    }
    fn retain(&self, owner: &I2cServiceOwner) -> Result<()> {
        let fence = owner.terminal_fence();
        let mut fences = self.fences.lock().unwrap_or_else(|e| e.into_inner());
        if self.terminal.load(Ordering::SeqCst) {
            fence.latch_terminal_safe_off();
            return Err(error("classic AML service opened after cancellation"));
        }
        fences.push(fence);
        Ok(())
    }
}
struct Attempt {
    cancellation: Arc<Cancellation>,
    complete: bool,
}
impl Attempt {
    fn new(cancellation: &Arc<Cancellation>) -> Self {
        Self {
            cancellation: cancellation.clone(),
            complete: false,
        }
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.complete {
            self.cancellation.latch();
        }
    }
}

struct Custody {
    pic: Option<I2cServiceOwner>,
    identity: Option<I2cServiceOwner>,
}
impl Drop for Custody {
    fn drop(&mut self) {
        for owner in [&self.pic, &self.identity].into_iter().flatten() {
            owner.terminal_fence().latch_terminal_safe_off();
        }
    }
}
struct Prepared {
    custody: Custody,
    snapshot: Snapshot,
    boards: Vec<(u8, u32)>,
    cancellation: Arc<Cancellation>,
}

fn validate_factory_page(page: &[u8]) -> Result<u32> {
    if page.len() != 256 {
        return Err(error("classic AML complete factory page required"));
    }
    let observed = decode_deployed_eeprom(page)
        .map_err(|e| error(format!("classic AML factory decoder: {e}")))?;
    let board = match observed.board_name.as_str() {
        "BHB42601" => 42601,
        "BHB42621" => 42621,
        "BHB42641" => 42641,
        _ => {
            return Err(error(format!(
                "classic AML factory SKU {} rejected",
                observed.board_name
            )))
        }
    };
    if observed.board_class != 4
        || observed.region_1_crc5 != Crc5Check::Match
        || observed.board_serial.trim().is_empty()
        || observed_protocol_from_deployed_page(page) != Some(AsicProtocolIdentity::Bm1362)
    {
        return Err(error(
            "classic AML factory class/checksum/serial/silicon rejected",
        ));
    }
    Ok(board)
}

fn prepare(
    observation: &dyn Observation,
    cancellation: Arc<Cancellation>,
    deadline: Instant,
    spawn: impl Fn(u8) -> Result<I2cServiceOwner>,
) -> Result<Prepared> {
    let mut attempt = Attempt::new(&cancellation);
    cancellation.live(deadline)?;
    observation.admit_boot()?;
    cancellation.live(deadline)?;
    let snapshot = observation.read()?;
    cancellation.live(deadline)?;
    let identity = spawn(1)?;
    cancellation.retain(&identity)?;
    if identity.request_handle().bus() != 1 {
        return Err(error("classic AML factory service must own bus1"));
    }
    identity.request_handle().set_timeout(10)?;
    cancellation.live(deadline)?;
    let pic = spawn(0)?;
    cancellation.retain(&pic)?;
    if pic.request_handle().bus() != 0 {
        return Err(error("classic AML PIC service must own bus0"));
    }
    let custody = Custody {
        pic: Some(pic),
        identity: Some(identity),
    };
    custody
        .pic
        .as_ref()
        .unwrap()
        .request_handle()
        .set_timeout(10)?;
    let mut boards = Vec::new();
    for (slot, present) in snapshot.populated.iter().enumerate() {
        if !present {
            continue;
        }
        cancellation.live(deadline)?;
        let first = crate::i2c::aml_pic_application::factory_page(
            &custody.identity.as_ref().unwrap().request_handle(),
            0x50 + slot as u8,
            deadline,
        )?;
        cancellation.live(deadline)?;
        let second = crate::i2c::aml_pic_application::factory_page(
            &custody.identity.as_ref().unwrap().request_handle(),
            0x50 + slot as u8,
            deadline,
        )?;
        if first != second {
            return Err(error(format!(
                "classic AML slot{slot} factory page changed"
            )));
        }
        boards.push((slot as u8 + 1, validate_factory_page(&first)?));
    }
    cancellation.live(deadline)?;
    if observation.read()? != snapshot {
        return Err(error(
            "classic AML population/boot changed during factory observation",
        ));
    }
    attempt.complete = true;
    Ok(Prepared {
        custody,
        snapshot,
        boards,
        cancellation,
    })
}

#[derive(Debug)]
pub struct ClassicHeartbeatRound {
    /// Physical chain and raw DAC/status byte; no measured voltage is inferred.
    pub chains: Vec<(u8, u8)>,
    pub stable_rounds: u8,
}
#[derive(Debug)]
pub struct ClassicTemperature {
    pub chain: u8,
    pub sensor: u8,
    pub raw_be: [u8; 2],
    pub celsius: f64,
}
#[derive(Debug)]
pub struct ClassicVoltage {
    pub chain: u8,
    pub raw_be: [u8; 2],
    /// Selected fw89 ADC conversion, not a physical calibration certificate.
    pub volts: f64,
}

fn fw89_adc_volts(raw_be: [u8; 2]) -> f64 {
    // Original selected89 observer8d9b10, arithmetic8d9c30..58.
    f64::from(u16::from_be_bytes(raw_be)) * 0.02448 - 0.35
}
#[derive(Debug)]
pub struct ClassicCloseReport {
    /// Fixed command acknowledgements, never physical cutoff measurements.
    pub cuts: Vec<(u8, std::result::Result<(), String>)>,
    pub workers_closed: bool,
}
struct State {
    endpoints: Vec<Endpoint>,
    last_round: Option<Instant>,
    stable: u8,
    custody: Arc<Mutex<Custody>>,
    cuts: Vec<(u8, std::result::Result<(), String>)>,
}

/// Current-boot classic BHB42601/21/41 application and thermal custody.
/// It observes factory pages itself on protected bus1, then fw89 on bus0.
/// Generic controller handles, addresses and mutable route tokens are private.
pub struct ClassicAmlPicOwner {
    boards: Vec<(u8, u32)>,
    state: tokio::sync::Mutex<State>,
    pic: I2cServiceHandle,
    snapshot: Snapshot,
    observation: Arc<dyn Observation>,
    cancellation: Arc<Cancellation>,
}
impl Drop for ClassicAmlPicOwner {
    fn drop(&mut self) {
        self.cancellation.latch();
    }
}

impl ClassicAmlPicOwner {
    fn gpio437_recipe(&self) -> Result<Gpio437DriveRecipe> {
        let names: Vec<_> = self
            .boards
            .iter()
            .map(|(_, board)| format!("BHB{board}"))
            .collect();
        let names: Vec<_> = names.iter().map(String::as_str).collect();
        amlogic_gpio437::resolve_population_recipe("am3-s19jpro-aml", &names).map_err(|cause| {
            error(format!(
                "classic GPIO437 identity polarity refused: {cause:?}"
            ))
        })
    }

    pub async fn observe_at(deadline: Instant) -> Result<Self> {
        Self::observe_with(Arc::new(LiveObservation), deadline, |bus| {
            spawn_owned_i2c_service_no_register_touch_with_denylist_and_reserved_preparation(
                bus,
                AMLOGIC_EEPROM_DENYLIST.to_vec(),
                || Ok(()),
            )
            .map_err(|e| error(format!("classic AML retained bus{bus}: {e}")))
        })
        .await
    }

    async fn observe_with(
        observation: Arc<dyn Observation>,
        deadline: Instant,
        spawn: impl Fn(u8) -> Result<I2cServiceOwner> + Send + 'static,
    ) -> Result<Self> {
        let cancellation = Arc::new(Cancellation::default());
        let mut attempt = Attempt::new(&cancellation);
        let worker_cancel = cancellation.clone();
        let worker_observation = observation.clone();
        let prepared = tokio::task::spawn_blocking(move || {
            prepare(worker_observation.as_ref(), worker_cancel, deadline, spawn)
        })
        .await
        .map_err(|e| error(format!("classic AML identity worker: {e}")))??;
        let pic = prepared.custody.pic.as_ref().unwrap().request_handle();
        let mut endpoints = Vec::new();
        for &(chain, board) in &prepared.boards {
            cancellation.live(deadline)?;
            endpoints.push(Endpoint::observe(&pic, board, chain, deadline).await?);
        }
        cancellation.live(deadline)?;
        let final_observation = observation.clone();
        let final_cancel = cancellation.clone();
        let observed = tokio::task::spawn_blocking(move || {
            final_cancel.live(deadline)?;
            let value = final_observation.read()?;
            final_cancel.live(deadline)?;
            Ok::<_, HalError>(value)
        })
        .await
        .map_err(|e| error(format!("classic AML final identity worker: {e}")))??;
        if observed != prepared.snapshot {
            return Err(error("classic AML identity changed during PIC observation"));
        }
        attempt.complete = true;
        Ok(Self {
            boards: prepared.boards,
            state: tokio::sync::Mutex::new(State {
                endpoints,
                last_round: None,
                stable: 0,
                custody: Arc::new(Mutex::new(prepared.custody)),
                cuts: Vec::new(),
            }),
            pic,
            snapshot: prepared.snapshot,
            observation,
            cancellation: prepared.cancellation,
        })
    }

    pub fn physical_chains(&self) -> Vec<u8> {
        self.snapshot
            .populated
            .iter()
            .enumerate()
            .filter(|(_, p)| **p)
            .map(|(i, _)| i as u8 + 1)
            .collect()
    }

    fn fence(&self) {
        self.cancellation.latch();
    }

    /// This private step is consumed only by the joined power owner. The
    /// caller's deadline is narrowed to the retained five-round freshness
    /// limit; the actual worker checks it before each emitted byte.
    async fn enable_at(&self, deadline: Instant) -> Result<()> {
        let mut attempt = Attempt::new(&self.cancellation);
        let state = tokio::time::timeout_at(deadline.into(), self.state.lock())
            .await
            .map_err(|_| error("classic AML enable admission deadline elapsed"))?;
        self.validate_current(deadline).await?;
        let until = state
            .last_round
            .filter(|_| state.stable == 5)
            .and_then(|last| last.checked_add(Duration::from_secs(3)))
            .ok_or_else(|| error("classic AML enable requires five stable heartbeat rounds"))?;
        let deadline = deadline.min(until);
        self.cancellation.live(deadline)?;
        for endpoint in &state.endpoints {
            endpoint.enable(&self.pic, deadline).await?;
        }
        self.validate_current(deadline).await?;
        attempt.complete = true;
        Ok(())
    }

    async fn validate_current(&self, deadline: Instant) -> Result<()> {
        self.cancellation.live(deadline)?;
        let observation = self.observation.clone();
        let cancellation = self.cancellation.clone();
        let observed = tokio::task::spawn_blocking(move || {
            cancellation.live(deadline)?;
            let observed = observation.read()?;
            cancellation.live(deadline)?;
            Ok::<_, HalError>(observed)
        })
        .await
        .map_err(|e| error(format!("classic AML revalidation worker: {e}")))??;
        if observed != self.snapshot {
            return Err(error("classic AML retained boot/population changed"));
        }
        Ok(())
    }

    pub async fn heartbeat_round_at(&self, deadline: Instant) -> Result<ClassicHeartbeatRound> {
        let mut attempt = Attempt::new(&self.cancellation);
        let mut state = tokio::time::timeout_at(deadline.into(), self.state.lock())
            .await
            .map_err(|_| error("classic AML heartbeat admission deadline elapsed"))?;
        self.validate_current(deadline).await?;
        let mut chains = Vec::new();
        for endpoint in &state.endpoints {
            chains.push((
                endpoint.chain(),
                endpoint.heartbeat(&self.pic, deadline).await?,
            ));
        }
        self.validate_current(deadline).await?;
        let now = Instant::now();
        match state
            .last_round
            .map(|last| now.saturating_duration_since(last))
        {
            None => {
                state.stable = 1;
                state.last_round = Some(now);
            }
            Some(age) if age > Duration::from_secs(3) => {
                state.stable = 1;
                state.last_round = Some(now);
            }
            Some(age) if age >= Duration::from_secs(1) => {
                state.stable = state.stable.saturating_add(1).min(5);
                state.last_round = Some(now);
            }
            Some(_) => {} // Fast repeated reads cannot manufacture five ticks.
        }
        attempt.complete = true;
        Ok(ClassicHeartbeatRound {
            chains,
            stable_rounds: state.stable,
        })
    }

    /// Read all four PIC-local sensors for one retained physical chain.
    pub async fn temperatures_at(
        &self,
        chain: u8,
        deadline: Instant,
    ) -> Result<Vec<ClassicTemperature>> {
        let mut attempt = Attempt::new(&self.cancellation);
        let state = tokio::time::timeout_at(deadline.into(), self.state.lock())
            .await
            .map_err(|_| error("classic AML thermal admission deadline elapsed"))?;
        self.validate_current(deadline).await?;
        let endpoint = state
            .endpoints
            .iter()
            .find(|endpoint| endpoint.chain() == chain)
            .ok_or_else(|| error("classic AML temperature chain is absent"))?;
        let mut values = Vec::new();
        for sensor in 0x48..=0x4b {
            let value = endpoint.temperature(&self.pic, sensor, deadline).await?;
            values.push(ClassicTemperature {
                chain,
                sensor,
                raw_be: value.raw_be(),
                celsius: value.celsius(),
            });
        }
        self.validate_current(deadline).await?;
        attempt.complete = true;
        Ok(values)
    }

    /// Observe every retained application's ADC through its exact fw89 path.
    /// Callers must check their own requested rail envelope before admitting work.
    pub async fn voltages_at(&self, deadline: Instant) -> Result<Vec<ClassicVoltage>> {
        let mut attempt = Attempt::new(&self.cancellation);
        let state = tokio::time::timeout_at(deadline.into(), self.state.lock())
            .await
            .map_err(|_| error("classic AML rail observation admission deadline elapsed"))?;
        self.validate_current(deadline).await?;
        let mut values = Vec::new();
        for endpoint in &state.endpoints {
            let raw_be = endpoint.voltage(&self.pic, deadline).await?;
            values.push(ClassicVoltage {
                chain: endpoint.chain(),
                raw_be,
                volts: fw89_adc_volts(raw_be),
            });
        }
        self.validate_current(deadline).await?;
        attempt.complete = true;
        Ok(values)
    }

    /// Latch both ordinary lanes before waiting for a running sample. Every
    /// retained PIC receives its fixed reserved cut, even after a sibling fails.
    /// A close timeout retains the workers for an explicit later close attempt.
    pub async fn close_at(&self, deadline: Instant) -> Result<ClassicCloseReport> {
        self.cancellation.latch();
        let mut state = tokio::time::timeout_at(deadline.into(), self.state.lock())
            .await
            .map_err(|_| error("classic AML terminal admission deadline elapsed"))?;
        for index in 0..state.endpoints.len() {
            let chain = state.endpoints[index].chain();
            if state.cuts.iter().any(|(attempted, _)| *attempted == chain) {
                continue;
            }
            // Record admission before await: cancellation must not replay a
            // partially completed cut against a parser of uncertain state.
            let result_index = state.cuts.len();
            state
                .cuts
                .push((chain, Err("cut completion was not observed".into())));
            let result = state.endpoints[index]
                .disable(&self.pic, deadline)
                .await
                .map_err(|e| e.to_string());
            state.cuts[result_index].1 = result;
        }
        let custody = state.custody.clone();
        // State retains the exact join owners even if this future is dropped
        // while its blocking closure is running or still queued.
        let workers_closed = tokio::task::spawn_blocking(move || {
            let mut custody = custody.lock().unwrap_or_else(|e| e.into_inner());
            if custody
                .pic
                .as_mut()
                .is_some_and(|owner| owner.close_and_join_until(deadline).is_ok())
            {
                custody.pic = None;
            }
            if custody
                .identity
                .as_mut()
                .is_some_and(|owner| owner.close_and_join_until(deadline).is_ok())
            {
                custody.identity = None;
            }
            custody.pic.is_none() && custody.identity.is_none()
        })
        .await
        .map_err(|e| error(format!("classic AML worker close task: {e}")))?;
        Ok(ClassicCloseReport {
            cuts: state.cuts.clone(),
            workers_closed,
        })
    }
}

#[cfg(test)]
#[path = "classic_pic_tests.rs"]
mod tests;
