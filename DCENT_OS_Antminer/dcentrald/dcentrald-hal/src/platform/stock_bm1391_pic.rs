//! Exact application-only dsPIC service for the retained BM1391 management portal.
//! S15 7e304/7d5d4, T15 7e2cc/7d59c; original-machine replay in
//! evidence/r04/native-pic-application-machine-code-vectors.json.
//! No bootloader command, EEPROM mutation or generic PIC opcode is exposed.
use super::*;

const IIC: u32 = 0x30;

#[derive(Clone, Copy, Debug)]
struct Route {
    chain: u8,
    selector: u8,
}

impl Route {
    fn new(model: Model, chain: u8, revision: u16) -> Self {
        // Original model predicate is false in the S15 release. T15's
        // observed EEPROM hardware revision0100 swaps physical lanes1/2.
        let selector = if model == Model::T15 && revision == 0x0100 && chain != 0 {
            3 - chain
        } else {
            chain
        };
        Self { chain, selector }
    }

    fn from_page(model: Model, chain: u8, page: &[u8; 256]) -> Result<Self, String> {
        // T15 checker750bc/loader77888: reflected CRC16/MODBUS over0..fd,
        // stored little-endian atfe/ff. The fa/fb hardware revision participates
        // in that checksum. Reject the original format/CRC fallback paths.
        if !matches!(page[0], 0x7e | 0x7f) {
            return Err("BM1391 PIC route requires an original 7e/7f EEPROM format".into());
        }
        let crc = dcentrald_common::bm1391_stock_work::bm1391_stock_job_crc16(&page[..254]);
        if crc != u16::from_le_bytes([page[254], page[255]]) {
            return Err("BM1391 PIC route EEPROM CRC mismatch".into());
        }
        Ok(Self::new(
            model,
            chain,
            u16::from_be_bytes([page[250], page[251]]),
        ))
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Heartbeat,
    Enable,
    Disable,
}
impl Operation {
    fn frame(self) -> &'static [u8] {
        match self {
            Self::Heartbeat => &[0x55, 0xaa, 4, 0x16, 0, 0x1a],
            Self::Enable => &[0x55, 0xaa, 5, 0x15, 1, 0, 0x1b],
            Self::Disable => &[0x55, 0xaa, 5, 0x15, 0, 0, 0x1a],
        }
    }
}

/// The retained application endpoints. Routing observation does not establish
/// ASIC identity, permissible voltage, cooling or physical rail state. The
/// runtime must compose those before enabling, and retain this owner for off.
pub struct PicApplication<R: Registers> {
    owner: Arc<Transport<R>>,
    routes: Vec<Route>,
    // Protected by the same management lane as the physical transaction.
    health: Mutex<Health>,
    enable_attempted: AtomicBool,
    // Set only around an already-admitted fixed heartbeat, while the same
    // management mutex excludes every other physical operation. A terminal
    // cutoff can finish this harmless frame without admitting a new frame.
    heartbeat_finishing: AtomicBool,
    /// Complete read-only pages captured by this owner before application
    /// enable. Thermal admission joins these to the later current ASIC census
    /// without starving the management lane with another three-page read.
    observed_pages: Vec<(u8, [u8; 256])>,
}

#[derive(Default)]
struct Health {
    last: [Option<Instant>; 3],
    stable_rounds: u8,
}

/// Per-chain fixed-off acknowledgments, never electrical cutoff evidence.
#[derive(Debug)]
pub struct PicOffReport {
    pub chains: Vec<(u8, Result<(), String>)>,
}
impl PicOffReport {
    pub fn all_acknowledged(&self) -> bool {
        !self.chains.is_empty() && self.chains.iter().all(|(_, result)| result.is_ok())
    }
}

// Dropping an async operation cancels its still-running blocking worker through
// the transport latch. The retained runtime remains responsible for terminal off.
struct Cancellation<R: Registers> {
    owner: Arc<Transport<R>>,
    completed: bool,
}

struct HeartbeatFinish<'a>(&'a AtomicBool);
impl Drop for HeartbeatFinish<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
impl<R: Registers> Drop for Cancellation<R> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.latch_terminal();
        }
    }
}

impl<R: Registers> PicApplication<R> {
    #[cfg(test)]
    pub(super) fn from_test_routes(
        owner: Arc<Transport<R>>,
        model: Model,
        revision: u16,
    ) -> Arc<Self> {
        Arc::new(Self {
            routes: owner
                .chains
                .iter()
                .map(|&chain| Route::new(model, chain, revision))
                .collect(),
            owner,
            health: Mutex::default(),
            enable_attempted: AtomicBool::new(false),
            heartbeat_finishing: AtomicBool::new(false),
            observed_pages: Vec::new(),
        })
    }
    /// Observe every selected full EEPROM through this transport's read-only
    /// management lane and retain exactly one application endpoint population.
    /// Application heartbeat is still required before the fixed enable operation.
    pub async fn observe(
        owner: Arc<Transport<R>>,
        model: Model,
        deadline: Instant,
    ) -> Result<Arc<Self>, String> {
        if owner.registers.model() != Some(model) {
            return Err("BM1391 PIC model differs from the current-boot mapping".into());
        }
        if owner
            .pic_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("BM1391 PIC population already has a retained owner".into());
        }
        let mut cancellation = Cancellation {
            owner: owner.clone(),
            completed: false,
        };
        let result = async {
            let mut routes = Vec::with_capacity(owner.chains.len());
            let mut observed_pages = Vec::with_capacity(owner.chains.len());
            for &chain in &owner.chains {
                let page = owner.read_eeprom(chain, deadline).await?;
                let route = Route::from_page(model, chain, &page)?;
                if routes
                    .iter()
                    .any(|prior: &Route| prior.selector == route.selector)
                {
                    return Err("BM1391 EEPROM revisions alias two populated PIC selectors".into());
                }
                routes.push(route);
                observed_pages.push((chain, page));
            }
            owner.active(deadline)?;
            Ok(Arc::new(Self {
                owner: owner.clone(),
                routes,
                health: Mutex::default(),
                enable_attempted: AtomicBool::new(false),
                heartbeat_finishing: AtomicBool::new(false),
                observed_pages,
            }))
        }
        .await;
        if result.is_err() {
            owner.latch_terminal();
        }
        cancellation.completed = true;
        result
    }

    pub(super) fn transport(&self) -> &Arc<Transport<R>> {
        &self.owner
    }

    pub(super) fn observed_pages(&self) -> &[(u8, [u8; 256])] {
        &self.observed_pages
    }
    /// Immutable original full-page observations captured before enable, for
    /// exact source/profile joins. This performs no new EEPROM transaction.
    pub fn eeprom_observations(&self) -> &[(u8, [u8; 256])] {
        &self.observed_pages
    }

    pub(super) fn require_voltage_health(&self, deadline: Instant) -> Result<(), String> {
        self.require_health(deadline, 5)
    }

    /// Read-only freshness of this owner's actual selected PIC acknowledgments.
    /// Includes heartbeats interleaved by enable; performs no management IO.
    pub fn check_application_health(&self, deadline: Instant) -> Result<(), String> {
        self.require_health(deadline, 1)
    }

    fn require_health(&self, deadline: Instant, rounds: u8) -> Result<(), String> {
        self.owner.active(deadline)?;
        let health = self
            .health
            .lock()
            .map_err(|_| "BM1391 PIC health lock poisoned")?;
        if health.stable_rounds < rounds
            || self.routes.iter().any(|route| {
                !health.last[usize::from(route.chain)]
                    .is_some_and(|time| time.elapsed() < Duration::from_secs(3))
            })
        {
            return Err(
                "BM1391 PIC control requires fresh application heartbeats for every selected route"
                    .into(),
            );
        }
        Ok(())
    }

    fn check(&self, deadline: Instant, terminal_off: bool) -> Result<(), String> {
        if self.owner.management_fault.load(Ordering::SeqCst) {
            return Err(
                "BM1391 management transaction remains unresolved; independent cutoff required"
                    .into(),
            );
        }
        let finishing_after_cut =
            self.owner.terminal() && self.heartbeat_finishing.load(Ordering::SeqCst);
        if Instant::now() >= deadline
            || (!terminal_off && self.owner.terminal() && !finishing_after_cut)
        {
            Err("BM1391 PIC transaction is terminal or expired".into())
        } else {
            // Check throughout every byte/settle phase after possible power-on.
            // A batch-entry observation cannot authorize an arbitrarily slow
            // transaction while a sibling PIC loses application liveness.
            if !terminal_off && !finishing_after_cut && self.enable_attempted.load(Ordering::SeqCst)
            {
                self.require_health(deadline, 1)?;
            }
            Ok(())
        }
    }

    fn delay(
        &self,
        milliseconds: u64,
        deadline: Instant,
        terminal_off: bool,
    ) -> Result<(), String> {
        let until = Instant::now() + Duration::from_millis(milliseconds);
        loop {
            self.check(deadline, terminal_off)?;
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return Ok(());
            };
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }

    // Caller retains management lane over complete request, settling and reply.
    fn transaction(
        &self,
        route: Route,
        operation: Operation,
        deadline: Instant,
        terminal_off: bool,
        delay: &mut impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut issued = false;
        let mut response_complete = false;
        let result = (|| {
            self.check(deadline, terminal_off)?;
            delay(100)?;
            // Do not begin a new heartbeat merely because the pre-frame wait
            // overlapped shutdown. Once admitted here, only this one fixed
            // heartbeat may finish after the independent source cutoff.
            self.check(deadline, terminal_off)?;
            let _heartbeat_finish = if matches!(operation, Operation::Heartbeat) {
                self.heartbeat_finishing.store(true, Ordering::SeqCst);
                Some(HeartbeatFinish(&self.heartbeat_finishing))
            } else {
                None
            };
            if matches!(operation, Operation::Enable) {
                // Queue and settle time cannot turn an old check into new
                // energization authority at the first physical PIC byte.
                self.require_health(deadline, 1)?;
                self.enable_attempted.store(true, Ordering::SeqCst);
            }
            let prefix = 0x0040_0000 | (u32::from(route.selector) << 16);
            let mut byte = |word: u32| -> Result<u8, String> {
                self.check(deadline, terminal_off)?;
                issued = true;
                self.owner.registers.write(IIC, word)?;
                // Exact FPGA executor869c4/868e4: five milliseconds before
                // each completion read, at most101 polls. Completion bit31 is
                // the only evidenced hardware status; it is not an I2C ACK.
                for _ in 0..101 {
                    delay(5)?;
                    self.check(deadline, terminal_off)?;
                    let response = self.owner.registers.read(IIC)?;
                    if response & 0x8000_0000 != 0 {
                        return Ok(response as u8);
                    }
                }
                Err("BM1391 PIC byte completion timed out".into())
            };
            for &value in operation.frame() {
                byte(prefix | u32::from(value))?;
            }
            // End byte closure's mutable borrow before inter-phase delay.
            drop(byte);
            delay(400)?;
            let mut response = [0; 6];
            let count = if matches!(operation, Operation::Heartbeat) {
                6
            } else {
                2
            };
            for value in &mut response[..count] {
                self.check(deadline, terminal_off)?;
                self.owner.registers.write(IIC, prefix | 0x0200_0000)?;
                let mut completed = false;
                for _ in 0..101 {
                    delay(5)?;
                    self.check(deadline, terminal_off)?;
                    let word = self.owner.registers.read(IIC)?;
                    if word & 0x8000_0000 != 0 {
                        *value = word as u8;
                        completed = true;
                        break;
                    }
                }
                if !completed {
                    return Err("BM1391 PIC reply byte timed out".into());
                }
            }
            // Preserve the checks actually present in each original function.
            // Unknown response bytes are not invented firmware/checksum fields.
            response_complete = true;
            // Keep fully consumed portal certainty, while refusing a final
            // acknowledgment read that returned after its absolute deadline.
            self.check(deadline, terminal_off)?;
            let accepted = match operation {
                Operation::Heartbeat => response[1] == 0x16 && response[2] == 1,
                Operation::Enable | Operation::Disable => response[..2] == [0x15, 1],
            };
            if !accepted {
                return Err(format!(
                    "BM1391 PIC chain{} application acknowledgment rejected",
                    route.chain
                ));
            }
            if !terminal_off && self.owner.terminal() {
                return Err("BM1391 PIC heartbeat consumed after terminal cutoff; normal admission stays closed".into());
            }
            if matches!(operation, Operation::Heartbeat) {
                self.health
                    .lock()
                    .map_err(|_| "BM1391 PIC health lock poisoned")?
                    .last[usize::from(route.chain)] = Some(Instant::now());
            }
            Ok(())
        })();
        if result.is_err() {
            if issued && !response_complete {
                self.owner.management_fault.store(true, Ordering::SeqCst);
            }
            self.owner.latch_terminal();
        }
        result
    }

    fn batch_with_delay(
        &self,
        operation: Operation,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let _management = match self.owner.lock_management_until(deadline) {
            Ok(lane) => lane,
            Err(error) => {
                self.owner.latch_terminal();
                return Err(error);
            }
        };
        let result = (|| {
            self.check(deadline, false)?;
            if matches!(operation, Operation::Disable)
                && self.enable_attempted.load(Ordering::SeqCst)
            {
                return Err(
                    "BM1391 startup disable cannot follow enable; terminal off is required".into(),
                );
            }
            if matches!(operation, Operation::Heartbeat) {
                let mut health = self
                    .health
                    .lock()
                    .map_err(|_| "BM1391 PIC health lock poisoned")?;
                let stale = self.routes.iter().any(|route| {
                    !health.last[usize::from(route.chain)]
                        .is_some_and(|time| time.elapsed() < Duration::from_secs(3))
                });
                if stale {
                    health.stable_rounds = 0;
                    if self.enable_attempted.load(Ordering::SeqCst) {
                        return Err(
                            "BM1391 PIC application heartbeat custody expired after enable".into(),
                        );
                    }
                }
            }
            for &route in &self.routes {
                if matches!(operation, Operation::Enable) {
                    self.require_health(deadline, 1)?;
                }
                self.transaction(route, operation, deadline, false, &mut delay)?;
            }
            if matches!(operation, Operation::Heartbeat) {
                self.require_health(deadline, 0)?;
                let mut health = self
                    .health
                    .lock()
                    .map_err(|_| "BM1391 PIC health lock poisoned")?;
                health.stable_rounds = health.stable_rounds.saturating_add(1);
            }
            Ok(())
        })();
        if result.is_err() {
            self.owner.latch_terminal();
        }
        result
    }

    async fn batch(
        self: &Arc<Self>,
        operation: Operation,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut cancellation = Cancellation {
            owner: self.owner.clone(),
            completed: false,
        };
        let app = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            app.batch_with_delay(operation, deadline, |ms| app.delay(ms, deadline, false))
        })
        .await
        .map_err(|e| format!("BM1391 PIC worker: {e}"));
        if result.is_err() {
            self.owner.latch_terminal();
        }
        cancellation.completed = true;
        result?
    }

    /// Complete round-robin application liveness through the retained IIC owner.
    pub async fn heartbeat(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        self.batch(Operation::Heartbeat, deadline).await
    }

    /// Original cold path S15 4faac / T15 4fadc sends application disable
    /// before first enable. Keep normal startup alive only on complete ACKs.
    /// Runtime owns the surrounding source delay, GPIO and reset sequence.
    /// Once enable has been attempted, only terminal_off may send disable.
    pub async fn disable_for_startup(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        self.batch(Operation::Disable, deadline).await
    }

    fn enable_with_heartbeats_with_delay(
        &self,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        let _management = match self.owner.lock_management_until(deadline) {
            Ok(lane) => lane,
            Err(error) => {
                self.owner.latch_terminal();
                return Err(error);
            }
        };
        let result = (|| {
            self.require_health(deadline, 1)?;
            for &route in &self.routes {
                self.transaction(route, Operation::Enable, deadline, false, &mut delay)?;
                // Three consecutive enables followed by a heartbeat round
                // would put successive acknowledgments about3.315s apart.
                // Servicing the full population after each enable keeps the
                // nominal original-delay interval at2.225s for three PICs.
                // Actual elapsed checks remain authoritative under slow IO.
                for &heartbeat_route in &self.routes {
                    self.transaction(
                        heartbeat_route,
                        Operation::Heartbeat,
                        deadline,
                        false,
                        &mut delay,
                    )?;
                }
                self.require_health(deadline, 1)?;
                let mut health = self
                    .health
                    .lock()
                    .map_err(|_| "BM1391 PIC health lock poisoned")?;
                health.stable_rounds = health.stable_rounds.saturating_add(1);
            }
            Ok(())
        })();
        if result.is_err() {
            self.owner.latch_terminal();
        }
        result
    }

    /// Fixed application enables, each followed by all selected heartbeats.
    /// Retains the management lane for the whole sequence; an independent
    /// heartbeat actor must not be relied on to acquire it between frames.
    /// No voltage setting or bootloader transition is exposed.
    pub async fn enable(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        let mut cancellation = Cancellation {
            owner: self.owner.clone(),
            completed: false,
        };
        let app = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            app.enable_with_heartbeats_with_delay(deadline, |ms| app.delay(ms, deadline, false))
        })
        .await
        .map_err(|e| format!("BM1391 PIC enable worker: {e}"));
        if result.is_err() {
            self.owner.latch_terminal();
        }
        cancellation.completed = true;
        result?
    }

    fn terminal_off_with_delay(
        &self,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<PicOffReport, String> {
        self.owner.latch_terminal();
        // Drain in the same ASIC-then-management order as terminal_drain.
        let _asic = self.owner.lock_until(deadline)?;
        let _management = self.owner.lock_management_until(deadline)?;
        let mut chains = Vec::with_capacity(self.routes.len());
        for &route in &self.routes {
            // Continue siblings after a fully consumed rejected ACK. An unresolved
            // byte/partial frame marks the portal faulty and blocks further writes.
            chains.push((
                route.chain,
                self.transaction(route, Operation::Disable, deadline, true, &mut delay),
            ));
        }
        Ok(PicOffReport { chains })
    }

    /// Close normal traffic first, then attempt every retained fixed-off endpoint
    /// under one absolute deadline. Failed or late ACKs remain explicit failures.
    pub async fn terminal_off(self: &Arc<Self>, deadline: Instant) -> Result<PicOffReport, String> {
        self.owner.latch_terminal();
        let app = self.clone();
        tokio::task::spawn_blocking(move || {
            app.terminal_off_with_delay(deadline, |ms| app.delay(ms, deadline, true))
        })
        .await
        .map_err(|e| format!("BM1391 PIC terminal worker: {e}"))?
    }
}

#[cfg(test)]
#[path = "stock_bm1391_pic_tests.rs"]
mod tests;
