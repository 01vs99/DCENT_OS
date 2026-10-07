//! Selected S19J_IO_V2 GPIO lifecycle on the daemon's original safety guard.
//! Host command history only; this module issues no Mining/Disarm capability.
use super::*;
use dcentrald_hal::platform::beaglebone::DEFAULT_BOARD_TARGET_V2_0;
use dcentrald_hal::platform::beaglebone_cold_boot::PreparedBoardEnable;
use std::sync::Mutex;

// Existing selected platform accessors and retained cold recipe: physical
// rst0..rst3, not the legacy static [5,4,27,22] map. GPIO65 is not involved.
const RESET_PINS: [u32; 4] = [49, 60, 27, 22];
const AUX_SETTLE: Duration = Duration::from_millis(3000);
const MAX_EVENTS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SelectedReset {
    pub chain_id: u8,
    pub gpio: u32,
}
pub(super) fn selected_resets(
    platform: &BeagleBonePlatform,
    ids: &[u8],
) -> Result<Vec<SelectedReset>> {
    anyhow::ensure!(
        platform.board_target_name() == DEFAULT_BOARD_TARGET_V2_0
            && platform.chain_reset_gpios_v2_0() == RESET_PINS
            && platform.board_enable_gpio_v2_0() == 59
            && platform.board_target().board_enable_active_high(),
        "retained GPIO requires exact selected S19J_IO_V2 topology"
    );
    anyhow::ensure!(
        !ids.is_empty() && ids.len() <= RESET_PINS.len(),
        "selected reset count must be 1..=4"
    );
    let mut seen = [false; 4];
    ids.iter()
        .map(|&id| {
            let i = usize::from(id);
            anyhow::ensure!(
                i < RESET_PINS.len() && !seen[i],
                "selected reset IDs must be distinct physical IDs0..=3"
            );
            seen[i] = true;
            Ok(SelectedReset {
                chain_id: id,
                gpio: RESET_PINS[i],
            })
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum GpioPhase {
    Prepare,
    EnableAuxiliary,
    PostPicReset,
    TerminalReset,
}
#[derive(Clone, Debug)]
pub(super) struct GpioEvent {
    pub gpio: u32,
    pub action: &'static str,
    pub attribute: &'static str,
    pub requested: Vec<u8>,
    pub started_at: Instant,
    pub returned_at: Option<Instant>,
    pub observed: Vec<u8>,
    pub number: Option<u64>,
    pub error: Option<String>,
}
#[derive(Clone, Debug)]
pub(super) struct GpioCall {
    pub sequence: u64,
    pub phase: GpioPhase,
    pub deadline: Instant,
    pub started_at: Instant,
    /// Actual blocking worker return, including errors and late returns.
    pub worker_returned_at: Option<Instant>,
    pub completed_at: Option<Instant>,
    pub joined_at: Option<Instant>,
    pub promoted_at: Option<Instant>,
    /// Future destruction without promotion: cancellation or error return.
    pub unpromoted_exit_at: Option<Instant>,
    pub join_failure: Option<String>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug)]
pub(super) struct GpioRefusal {
    pub phase: GpioPhase,
    pub deadline: Instant,
    pub observed_at: Instant,
    pub error: String,
}
#[derive(Clone, Debug)]
pub(super) struct GpioHistory {
    pub selected: Vec<SelectedReset>,
    pub events: Vec<GpioEvent>,
    pub calls: Vec<GpioCall>,
    pub never_energized_consumed_at: Option<Instant>,
    pub retained_reset_attributes: usize,
    pub extra_cutoff_opened_at: Option<Instant>,
    pub stopped: bool,
    pub closed_at: Option<Instant>,
    pub close_deadline: Option<Instant>,
    pub close_joined_at: Option<Instant>,
    pub cancel_lane_dropped_at: Option<Instant>,
    /// Retained even when the bounded detailed event log has filled.
    pub last_cutoff: Option<GpioEvent>,
    pub unlogged_cutoffs: usize,
    pub last_admission_refusal: Option<GpioRefusal>,
}
type History = Arc<Mutex<GpioHistory>>;
fn lock(history: &History) -> std::sync::MutexGuard<'_, GpioHistory> {
    history.lock().unwrap_or_else(|error| error.into_inner())
}
fn observed<T>(
    history: &History,
    gpio: u32,
    action: &'static str,
    attribute: &'static str,
    requested: &[u8],
    work: impl FnOnce() -> Result<(T, Vec<u8>, Option<u64>)>,
) -> Result<T> {
    let index = {
        let mut log = lock(history);
        anyhow::ensure!(
            log.events.len() < MAX_EVENTS,
            "retained GPIO observation limit reached"
        );
        let index = log.events.len();
        log.events.push(GpioEvent {
            gpio,
            action,
            attribute,
            requested: requested.to_vec(),
            started_at: Instant::now(),
            returned_at: None,
            observed: Vec::new(),
            number: None,
            error: None,
        });
        index
    };
    let result = work();
    let returned = Instant::now();
    let mut log = lock(history);
    let event = &mut log.events[index];
    event.returned_at = Some(returned);
    match result {
        Ok((value, bytes, number)) => {
            event.observed = bytes;
            event.number = number;
            Ok(value)
        }
        Err(error) => {
            event.error = Some(format!("{error:#}"));
            Err(error)
        }
    }
}
fn active(stop: &AtomicBool, deadline: Instant, terminal: bool) -> Result<()> {
    anyhow::ensure!(
        terminal || !stop.load(Ordering::SeqCst),
        "retained GPIO normal lane stopped"
    );
    anyhow::ensure!(
        Instant::now() < deadline,
        "retained GPIO original deadline expired"
    );
    Ok(())
}
fn delay(
    history: &History,
    stop: &AtomicBool,
    deadline: Instant,
    duration: Duration,
) -> Result<()> {
    active(stop, deadline, false)?;
    observed(history, 0, "delay", "clock", &[], || {
        let end = Instant::now() + duration;
        while Instant::now() < end {
            active(stop, deadline, false)?;
            thread::sleep(
                Duration::from_millis(1).min(end.saturating_duration_since(Instant::now())),
            );
        }
        active(stop, deadline, false)?;
        Ok(((), Vec::new(), Some(duration.as_millis() as u64)))
    })
}
fn directory_exists(
    history: &History,
    gpio: u32,
    path: &Path,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<bool> {
    let exists = observed(history, gpio, "metadata", "directory", &[], || {
        active(stop, deadline, false)?;
        let exists = match std::fs::metadata(path) {
            Ok(metadata) => metadata.is_dir(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        Ok((exists, Vec::new(), Some(u64::from(exists))))
    })?;
    active(stop, deadline, false)?;
    Ok(exists)
}

struct ResetOwner {
    selected: SelectedReset,
    direction: Option<File>,
    active_low: Option<File>,
    value: Option<File>,
    access: Option<(Arc<AtomicBool>, Instant, bool)>,
    #[cfg(test)]
    after_write: Option<Arc<tests::IoPause>>,
}
impl ResetOwner {
    fn new(selected: SelectedReset) -> Self {
        Self {
            selected,
            direction: None,
            active_low: None,
            value: None,
            access: None,
            #[cfg(test)]
            after_write: None,
        }
    }
    fn check(&self) -> Result<()> {
        let (stop, deadline, terminal) = self
            .access
            .as_ref()
            .context("original GPIO access scope missing")?;
        active(stop, *deadline, *terminal)
    }
    fn file(&mut self, attr: &'static str) -> Result<&mut File> {
        match attr {
            "direction" => &mut self.direction,
            "active_low" => &mut self.active_low,
            "value" => &mut self.value,
            _ => unreachable!(),
        }
        .as_mut()
        .context("retained reset attribute has not actually opened")
    }
    fn seek(&mut self, history: &History, attr: &'static str) -> Result<()> {
        self.check()?;
        let gpio = self.selected.gpio;
        observed(history, gpio, "seek", attr, &[], || {
            self.check()?;
            let position = self.file(attr)?.seek(SeekFrom::Start(0))?;
            Ok((position, Vec::new(), Some(position)))
        })
        .and_then(|position| {
            anyhow::ensure!(position == 0, "retained GPIO seek did not return offset0");
            Ok(())
        })?;
        self.check()
    }
    fn read(&mut self, history: &History, attr: &'static str) -> Result<String> {
        self.seek(history, attr)?;
        let gpio = self.selected.gpio;
        let bytes = observed(history, gpio, "read", attr, &[], || {
            self.check()?;
            let mut bytes = vec![0; 64];
            let n = self.file(attr)?.read(&mut bytes)?;
            bytes.truncate(n);
            Ok((bytes.clone(), bytes, Some(n as u64)))
        })?;
        self.check()?;
        anyhow::ensure!(
            bytes.len() < 64,
            "retained GPIO attribute exceeded bounded read"
        );
        Ok(String::from_utf8(bytes)?.trim().to_owned())
    }
    fn write(&mut self, history: &History, attr: &'static str, value: &[u8]) -> Result<()> {
        self.seek(history, attr)?;
        let gpio = self.selected.gpio;
        let n = observed(history, gpio, "write", attr, value, || {
            self.check()?;
            let n = self.file(attr)?.write(value)?;
            Ok((n, value[..n].to_vec(), Some(n as u64)))
        })?;
        #[cfg(test)]
        if self
            .after_write
            .as_ref()
            .is_some_and(|pause| pause.attribute == attr)
        {
            self.after_write.take().unwrap().after_actual_write();
        }
        self.check()?;
        anyhow::ensure!(
            n == value.len(),
            "retained GPIO attribute write was partial"
        );
        Ok(())
    }
    fn expect(&mut self, history: &History, attr: &'static str, expected: &str) -> Result<()> {
        let actual = self.read(history, attr)?;
        anyhow::ensure!(
            actual == expected,
            "retained GPIO{} {} mismatch: expected {expected:?}, observed {actual:?}",
            self.selected.gpio,
            attr
        );
        Ok(())
    }
    fn topology(&mut self, history: &History, mode: Am3BbRetainedReadbackMode) -> Result<()> {
        self.expect(history, "direction", mode.expected_direction())?;
        self.expect(history, "active_low", "1")
    }
    fn command(
        &mut self,
        history: &History,
        mode: Am3BbRetainedReadbackMode,
        asserted: bool,
    ) -> Result<()> {
        self.topology(history, mode)?;
        self.write(history, "value", if asserted { b"1" } else { b"0" })?;
        self.expect(history, "value", if asserted { "1" } else { "0" })
    }
    fn raw_assert_fallback(&mut self) {
        // Kernel direction=low is physically LOW regardless of active_low.
        // Best effort through the original descriptor, with no receipt claim.
        if let Some(file) = self.direction.as_mut() {
            let _ = file
                .seek(SeekFrom::Start(0))
                .and_then(|_| file.write_all(b"low"));
        }
    }
}

struct Core {
    guard: Am3BbRunSafetyGuard,
    never_energized: Option<Am3BbNeverEnergized>,
    resets: Vec<ResetOwner>,
    export: Option<File>,
    pending_cutoff: Option<Am3BbPreparedBoardCutoff>,
    root: std::path::PathBuf,
    mode: Am3BbRetainedReadbackMode,
    prepared: bool,
    enabled: bool,
    pulsed: bool,
    attempted_on: bool,
    terminal_complete: bool,
    #[cfg(test)]
    after_terminal_completion: Option<Arc<tests::IoPause>>,
}
impl Core {
    fn prepare(&mut self, history: &History, stop: &AtomicBool, deadline: Instant) -> Result<()> {
        anyhow::ensure!(
            !self.prepared && self.pending_cutoff.is_none(),
            "GPIO preparation is one-shot"
        );
        active(stop, deadline, false)?;
        let io = &self.guard.board_enable.io;
        // Reuse the exact cutoff-only implementation and original terminal /
        // sole-ON-writer fence. The other heartbeat and panic lanes stay owned.
        self.pending_cutoff = Some(observed(
            history,
            59,
            "open-cutoff-lane",
            "retained-lifecycle",
            &[],
            || {
                active(stop, deadline, false)?;
                let cutoff = Am3BbPreparedBoardCutoff::open_at(
                    &self.root,
                    59,
                    "0",
                    "retained-lifecycle",
                    self.mode,
                    Arc::clone(&io.terminal),
                    Arc::clone(&io.on_writer_thread),
                )?;
                Ok((cutoff, Vec::new(), None))
            },
        )?);
        lock(history).extra_cutoff_opened_at = Some(Instant::now());
        active(stop, deadline, false)?;
        observed(
            history,
            59,
            "cutoff-preflight",
            "direction=low",
            b"low",
            || {
                active(stop, deadline, false)?;
                self.pending_cutoff.as_ref().unwrap().write_off_checked()?;
                Ok(((), Vec::new(), None))
            },
        )?;
        active(stop, deadline, false)?;
        for reset in &mut self.resets {
            active(stop, deadline, false)?;
            let gpio = reset.selected.gpio;
            let directory = am3_bb_gpio_dir_at(&self.root, gpio);
            if !directory_exists(history, gpio, &directory, stop, deadline)? {
                if self.export.is_none() {
                    self.export = Some(observed(history, gpio, "open", "export", &[], || {
                        active(stop, deadline, false)?;
                        let file = std::fs::OpenOptions::new()
                            .write(true)
                            .open(self.root.join("export"))?;
                        Ok((file, Vec::new(), None))
                    })?);
                    active(stop, deadline, false)?;
                }
                let bytes = gpio.to_string().into_bytes();
                // A concurrent export may report EBUSY; only actual later node
                // materialization permits opening. Its error remains recorded.
                let position = observed(history, gpio, "seek", "export", &[], || {
                    active(stop, deadline, false)?;
                    let position = self.export.as_mut().unwrap().seek(SeekFrom::Start(0))?;
                    Ok((position, Vec::new(), Some(position)))
                })?;
                active(stop, deadline, false)?;
                anyhow::ensure!(position == 0, "retained export seek did not return offset0");
                let export_result = observed(history, gpio, "write", "export", &bytes, || {
                    let file = self.export.as_mut().unwrap();
                    active(stop, deadline, false)?;
                    let n = file.write(&bytes)?;
                    Ok((n, bytes[..n].to_vec(), Some(n as u64)))
                });
                active(stop, deadline, false)?;
                if let Ok(n) = export_result {
                    anyhow::ensure!(n == bytes.len(), "GPIO export write was partial");
                }
                let end = deadline.min(Instant::now() + Duration::from_millis(250));
                while !directory_exists(history, gpio, &directory, stop, end)? {
                    active(stop, end, false)?;
                    thread::sleep(Duration::from_millis(2));
                }
            }
            for attr in ["direction", "active_low", "value"] {
                active(stop, deadline, false)?;
                let file = observed(history, gpio, "open-read-write", attr, &[], || {
                    active(stop, deadline, false)?;
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(directory.join(attr))?;
                    Ok((file, Vec::new(), None))
                })?;
                match attr {
                    "direction" => reset.direction = Some(file),
                    "active_low" => reset.active_low = Some(file),
                    "value" => reset.value = Some(file),
                    _ => unreachable!(),
                }
                lock(history).retained_reset_attributes += 1;
                active(stop, deadline, false)?;
            }
        }
        // Every selected descriptor is retained before the first reset change.
        for reset in &mut self.resets {
            active(stop, deadline, false)?;
            reset.write(history, "direction", b"low")?;
            reset.expect(history, "direction", self.mode.expected_direction())?;
            active(stop, deadline, false)?;
            reset.write(history, "active_low", b"1")?;
            reset.expect(history, "active_low", "1")?;
            reset.command(history, self.mode, true)?;
            active(stop, deadline, false)?;
        }
        self.prepared = true;
        Ok(())
    }
    fn enable(&mut self, history: &History, stop: &AtomicBool, deadline: Instant) -> Result<()> {
        active(stop, deadline, false)?;
        anyhow::ensure!(
            self.prepared && !self.enabled && self.never_energized.is_some(),
            "auxiliary enable requires original prepared one-shot owner"
        );
        for reset in &mut self.resets {
            active(stop, deadline, false)?;
            reset.topology(history, self.mode)?;
            reset.expect(history, "value", "1")?;
        }
        anyhow::ensure!(
            self.guard.safe_pwm <= AM3_BB_FAN_HARD_CAP_PWM,
            "quiet fan cap invalid"
        );
        observed(
            history,
            0,
            "checked-fan",
            "safe-pwm",
            &[self.guard.safe_pwm],
            || {
                active(stop, deadline, false)?;
                let fan = self
                    .guard
                    .fan
                    .as_ref()
                    .context("original checked fan owner missing")?;
                let receipt = fan.set_speed_checked(self.guard.safe_pwm)?;
                anyhow::ensure!(
                    receipt.observed_pwm() <= AM3_BB_FAN_HARD_CAP_PWM,
                    "quiet fan readback exceeded cap"
                );
                Ok(((), vec![receipt.observed_pwm()], None))
            },
        )?;
        active(stop, deadline, false)?;
        // The exact original watchdog token is destroyed immediately before
        // the existing sole ON method. That method marks outcome unknown
        // before publishing/writing and preserves its mandatory failure recut.
        let never = self
            .never_energized
            .take()
            .context("original never-energized token missing")?;
        self.attempted_on = true;
        lock(history).never_energized_consumed_at = Some(Instant::now());
        drop(never);
        observed(history, 59, "original-board-enable", "value", b"1", || {
            active(stop, deadline, false)?;
            self.guard.board_enable.assert_checked()?;
            Ok(((), Vec::new(), None))
        })?;
        active(stop, deadline, false)?;
        delay(history, stop, deadline, AUX_SETTLE)?;
        self.enabled = true;
        Ok(())
    }
    fn pulse(&mut self, history: &History, stop: &AtomicBool, deadline: Instant) -> Result<()> {
        anyhow::ensure!(
            self.enabled && !self.pulsed,
            "reset pulse requires completed original auxiliary operation and no prior pulse"
        );
        self.pulsed = true;
        for reset in &mut self.resets {
            active(stop, deadline, false)?;
            reset.command(history, self.mode, true)?;
        }
        delay(
            history,
            stop,
            deadline,
            Duration::from_millis(AM3_BB_DSPIC_POST_ENABLE_RESET_ASSERT_MS),
        )?;
        for reset in &mut self.resets {
            active(stop, deadline, false)?;
            reset.command(history, self.mode, false)?;
            delay(
                history,
                stop,
                deadline,
                Duration::from_millis(AM3_BB_DSPIC_INTER_CHAIN_RESET_MS),
            )?;
        }
        delay(
            history,
            stop,
            deadline,
            Duration::from_millis(AM3_BB_DSPIC_POST_ENABLE_RESET_RELEASE_MS),
        )
    }
    fn terminal(&mut self, history: &History, stop: &AtomicBool, deadline: Instant) -> Result<()> {
        // A later failed attempt cannot inherit an earlier terminal completion.
        self.terminal_complete = false;
        stop.store(true, Ordering::SeqCst);
        // The physical cutoff precedes any bounded diagnostic-log admission.
        let started = Instant::now();
        let cutoff = self.guard.board_enable.cut_checked();
        record_cut(history, "original-cutoff", started, &cutoff);
        // Failed cutoff stays a terminal failure, but does not suppress the
        // independently retained reset/capped-cooling attempts.
        let mut failure = cutoff.err();
        for reset in &mut self.resets {
            if let Err(error) = (|| -> Result<()> {
                active(stop, deadline, true)?;
                // Cut first; this assertion also works after partial setup or
                // polarity drift. It never writes to an unowned descriptor.
                reset.write(history, "direction", b"low")?;
                reset.expect(history, "direction", self.mode.expected_direction())?;
                reset.write(history, "active_low", b"1")?;
                reset.command(history, self.mode, true)
            })() {
                failure = Some(error);
            }
        }
        observed(
            history,
            0,
            "checked-fan",
            "quiet-coast",
            &[self.guard.safe_pwm],
            || {
                active(stop, deadline, true)?;
                self.guard
                    .fan
                    .as_ref()
                    .context("original fan owner missing")?
                    .set_speed_checked(self.guard.safe_pwm)?;
                Ok(((), Vec::new(), None))
            },
        )?;
        if let Some(error) = failure {
            return Err(error);
        }
        active(stop, deadline, true)?;
        self.terminal_complete = true;
        Ok(())
    }
}
impl Drop for Core {
    fn drop(&mut self) {
        // Actual original cutoff is first; reset fallbacks never reopen paths.
        self.guard.cut_board_enable_fallback();
        for reset in &mut self.resets {
            reset.raw_assert_fallback();
        }
        // The unchanged guard Drop still owns capped cooling and cutoff. Its
        // legacy reset-number list was emptied only after actual adoption.
    }
}

fn record_cut(
    history: &History,
    action: &'static str,
    started: Instant,
    result: &Result<Am3BbCutoffTiming>,
) {
    let returned = Instant::now();
    let mut log = lock(history);
    log.stopped = true;
    let event = GpioEvent {
        gpio: 59,
        action,
        attribute: "direction=low",
        requested: b"low".to_vec(),
        started_at: started,
        returned_at: Some(returned),
        observed: Vec::new(),
        number: None,
        error: result.as_ref().err().map(|e| format!("{e:#}")),
    };
    log.last_cutoff = Some(event.clone());
    if log.events.len() < MAX_EVENTS {
        log.events.push(event);
    } else {
        log.unlogged_cutoffs = log.unlogged_cutoffs.saturating_add(1);
    }
}
fn cutoff_now(
    history: &History,
    cutoff: &Am3BbPreparedBoardCutoff,
    action: &'static str,
) -> Result<()> {
    let started = Instant::now();
    let result = cutoff.cut_checked();
    record_cut(history, action, started, &result);
    result.map(|_| ())
}

struct Pending {
    stop: Arc<AtomicBool>,
    cutoff: Option<Arc<Am3BbPreparedBoardCutoff>>,
    history: History,
    call_index: Option<usize>,
    complete: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if !self.complete {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(cutoff) = &self.cutoff {
                let _ = cutoff_now(&self.history, cutoff, "cancel-cutoff");
            }
            let mut history = lock(&self.history);
            history.stopped = true;
            if let Some(index) = self.call_index {
                history.calls[index].unpromoted_exit_at = Some(Instant::now());
            }
        }
    }
}

pub(super) struct AdoptionFailure {
    pub error: String,
    pub guard: Am3BbRunSafetyGuard,
    pub never_energized: Am3BbNeverEnergized,
}
pub(super) struct RetainedGpioLifecycle {
    core: Option<Core>,
    task: Option<tokio::task::JoinHandle<(Core, Result<()>)>>,
    close_task: Option<tokio::task::JoinHandle<()>>,
    cutoff_receipt_issued: bool,
    terminal_promoted: bool,
    cancel_cutoff: Option<Arc<Am3BbPreparedBoardCutoff>>,
    stop: Arc<AtomicBool>,
    history: History,
}
/// Consumed original caller/resource finalization. This proves only the
/// recorded host ownership joins; no watchdog or physical safe-off authority
/// is issued here. Construction accepts the actual lifecycle, never a DTO.
pub(super) struct FinalizedGpioOwner {
    history: GpioHistory,
    original_terminal: Arc<AtomicBool>,
}
impl FinalizedGpioOwner {
    pub(super) fn history(&self) -> &GpioHistory {
        &self.history
    }
    pub(super) fn shares_terminal_fence(&self, lane: &Am3BbPreparedBoardCutoff) -> bool {
        Arc::ptr_eq(&self.original_terminal, &lane.terminal)
    }
}
pub(super) struct FinalizationRefusal {
    pub error: String,
    pub owner: RetainedGpioLifecycle,
}
impl RetainedGpioLifecycle {
    pub(super) fn adopt(
        platform: &BeagleBonePlatform,
        ids: &[u8],
        mut guard: Am3BbRunSafetyGuard,
        never_energized: Am3BbNeverEnergized,
    ) -> std::result::Result<Self, AdoptionFailure> {
        let selected = match selected_resets(platform, ids) {
            Ok(selected)
                if guard.board_enable.gpio() == 59
                    && guard.board_enable.board_enable_active_high
                    && guard.board_enable.state == Am3BbBoardEnableState::PreparedOff
                    && guard.fan.is_some()
                    && guard.safe_pwm <= AM3_BB_FAN_HARD_CAP_PWM
                    && !guard.board_enable.io.terminal.load(Ordering::SeqCst)
                    && !guard.teardown_done
                    && !guard.board_cutoff_receipt_issued
                    && guard.dspic_i2c.is_none()
                    && guard.active_dspic_addrs.is_empty() =>
            {
                selected
            }
            result => {
                return Err(AdoptionFailure {
                    error: result.err().map_or_else(
                        || "original prepared board/fan ownership differs".into(),
                        |e| e.to_string(),
                    ),
                    guard,
                    never_energized,
                })
            }
        };
        let mode = guard.board_enable.io.readback_mode;
        let stop = Arc::clone(&guard.board_enable.io.terminal);
        guard.reset_gpios.clear();
        let history = Arc::new(Mutex::new(GpioHistory {
            selected: selected.clone(),
            events: Vec::new(),
            calls: Vec::new(),
            never_energized_consumed_at: None,
            retained_reset_attributes: 0,
            extra_cutoff_opened_at: None,
            stopped: false,
            closed_at: None,
            close_deadline: None,
            close_joined_at: None,
            cancel_lane_dropped_at: None,
            last_cutoff: None,
            unlogged_cutoffs: 0,
            last_admission_refusal: None,
        }));
        Ok(Self {
            core: Some(Core {
                guard,
                never_energized: Some(never_energized),
                resets: selected.into_iter().map(ResetOwner::new).collect(),
                export: None,
                pending_cutoff: None,
                root: Path::new(AM3_BB_GPIO_SYSFS_ROOT).to_owned(),
                mode,
                prepared: false,
                enabled: false,
                pulsed: false,
                attempted_on: false,
                terminal_complete: false,
                #[cfg(test)]
                after_terminal_completion: None,
            }),
            task: None,
            close_task: None,
            cutoff_receipt_issued: false,
            terminal_promoted: false,
            cancel_cutoff: None,
            stop,
            history,
        })
    }
    pub(super) fn snapshot(&self) -> GpioHistory {
        lock(&self.history).clone()
    }
    pub(super) fn into_finalized_owner(
        self,
    ) -> std::result::Result<FinalizedGpioOwner, FinalizationRefusal> {
        let admission = (|| -> Result<GpioHistory> {
            anyhow::ensure!(
                self.task.is_none()
                    && self.close_task.is_none()
                    && self.core.is_none()
                    && self.cancel_cutoff.is_none()
                    && self.stop.load(Ordering::SeqCst),
                "original GPIO callers and resources have not actually finalized"
            );
            let history = self.snapshot();
            anyhow::ensure!(
                history.never_energized_consumed_at.is_none() || self.terminal_promoted,
                "latest terminal request lacks original timely caller promotion"
            );
            let original = history
                .close_deadline
                .context("original GPIO finalization deadline absent")?;
            anyhow::ensure!(
                history.closed_at.is_some_and(|t| t < original)
                    && history.close_joined_at.is_some_and(|t| t < original),
                "original GPIO finalization lacks timely actual owner/task joins"
            );
            anyhow::ensure!(
                history.extra_cutoff_opened_at.is_none()
                    || history.cancel_lane_dropped_at.is_some_and(|t| t < original),
                "original independent cutoff lane has not finalized timely"
            );
            Ok(history)
        })();
        match admission {
            Ok(history) => Ok(FinalizedGpioOwner {
                history,
                original_terminal: Arc::clone(&self.stop),
            }),
            Err(error) => {
                self.stop.store(true, Ordering::SeqCst);
                if let Some(cutoff) = &self.cancel_cutoff {
                    let _ = cutoff_now(&self.history, cutoff, "finalization-refused-cutoff");
                }
                lock(&self.history).stopped = true;
                Err(FinalizationRefusal {
                    error: format!("{error:#}"),
                    owner: self,
                })
            }
        }
    }
    #[cfg(all(test, feature = "sim-hal"))]
    pub(super) fn set_pre_power_fixture_root(&mut self, root: &Path) -> Result<()> {
        let root = root.canonicalize()?;
        let temporary = std::env::temp_dir().canonicalize()?;
        anyhow::ensure!(
            root.starts_with(&temporary)
                && root != temporary
                && root.file_name().is_some_and(|name| name
                    .to_string_lossy()
                    .starts_with("dcent-bb-pre-power-run-")),
            "ordinary-file fixture root must be its private temporary tree"
        );
        anyhow::ensure!(
            self.task.is_none() && self.close_task.is_none() && self.snapshot().calls.is_empty(),
            "fixture root must precede actual GPIO work"
        );
        let core = self
            .core
            .as_mut()
            .context("original fixture GPIO core absent")?;
        anyhow::ensure!(
            matches!(core.mode, Am3BbRetainedReadbackMode::OrdinaryFileFixture),
            "fixture root refuses real sysfs ownership"
        );
        core.root = root;
        Ok(())
    }

    pub(super) fn capped_fan(&self) -> Option<Am3BbCappedFan> {
        self.core.as_ref()?.guard.capped_fan()
    }
    pub(super) fn take_heartbeat_cutoff(&mut self) -> Result<Am3BbPreparedBoardCutoff> {
        self.core
            .as_mut()
            .context("actual GPIO caller owns the guard")?
            .guard
            .take_heartbeat_board_cutoff()
    }
    pub(super) fn take_panic_cutoff(&mut self) -> Result<Am3BbPreparedBoardCutoff> {
        self.core
            .as_mut()
            .context("actual GPIO caller owns the guard")?
            .guard
            .take_panic_board_cutoff()
    }
    pub(super) fn take_never_energized_after_join(&mut self) -> Result<Am3BbNeverEnergized> {
        anyhow::ensure!(
            self.task.is_none(),
            "actual GPIO caller must join before never-energized closeout"
        );
        self.stop.store(true, Ordering::SeqCst);
        self.core
            .as_mut()
            .context("original GPIO owner unavailable")?
            .never_energized
            .take()
            .context("original ON boundary already consumed never-energized token")
    }
    pub(super) async fn run_until(
        &mut self,
        phase: GpioPhase,
        deadline: Instant,
    ) -> Result<GpioHistory> {
        if phase == GpioPhase::TerminalReset {
            self.terminal_promoted = false;
        }
        let admission = (|| -> Result<()> {
            anyhow::ensure!(
                self.task.is_none() && self.close_task.is_none(),
                "original GPIO caller is still retained and unjoined"
            );
            active(&self.stop, deadline, phase == GpioPhase::TerminalReset)?;
            anyhow::ensure!(
                phase == GpioPhase::Prepare || self.cancel_cutoff.is_some(),
                "independent cancellation cutoff has not actually opened"
            );
            anyhow::ensure!(
                lock(&self.history).calls.len() < 8,
                "retained GPIO caller limit reached"
            );
            anyhow::ensure!(self.core.is_some(), "original GPIO owner is unavailable");
            Ok(())
        })();
        if let Err(error) = admission {
            let observed_at = Instant::now();
            self.stop.store(true, Ordering::SeqCst);
            if let Some(cutoff) = &self.cancel_cutoff {
                let _ = cutoff_now(&self.history, cutoff, "admission-refused-cutoff");
            }
            let mut history = lock(&self.history);
            history.stopped = true;
            history.last_admission_refusal = Some(GpioRefusal {
                phase,
                deadline,
                observed_at,
                error: format!("{error:#}"),
            });
            return Err(error);
        }
        let mut core = self
            .core
            .take()
            .context("original GPIO owner is unavailable")?;
        let index = {
            let mut log = lock(&self.history);
            let index = log.calls.len();
            log.calls.push(GpioCall {
                sequence: index as u64 + 1,
                phase,
                deadline,
                started_at: Instant::now(),
                worker_returned_at: None,
                completed_at: None,
                joined_at: None,
                promoted_at: None,
                unpromoted_exit_at: None,
                join_failure: None,
                failure: None,
            });
            index
        };
        let history = Arc::clone(&self.history);
        let stop = Arc::clone(&self.stop);
        self.task = Some(tokio::task::spawn_blocking(move || {
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
                    active(&stop, deadline, phase == GpioPhase::TerminalReset)?;
                    for reset in &mut core.resets {
                        reset.access = Some((
                            Arc::clone(&stop),
                            deadline,
                            phase == GpioPhase::TerminalReset,
                        ));
                    }
                    match phase {
                        GpioPhase::Prepare => core.prepare(&history, &stop, deadline),
                        GpioPhase::EnableAuxiliary => core.enable(&history, &stop, deadline),
                        GpioPhase::PostPicReset => core.pulse(&history, &stop, deadline),
                        GpioPhase::TerminalReset => core.terminal(&history, &stop, deadline),
                    }?;
                    active(&stop, deadline, phase == GpioPhase::TerminalReset)
                }));
            let mut result = outcome
                .unwrap_or_else(|_| Err(anyhow::anyhow!("actual GPIO blocking caller panicked")));
            let completed = Instant::now();
            if result.is_ok() && completed >= deadline {
                result = Err(anyhow::anyhow!(
                    "GPIO worker completion exceeded original deadline"
                ));
            }
            if result.is_err() {
                stop.store(true, Ordering::SeqCst);
                core.guard.cut_board_enable_fallback();
            }
            let mut log = lock(&history);
            if result.is_ok() {
                log.calls[index].completed_at = Some(completed);
            } else {
                log.calls[index].failure = result.as_ref().err().map(|e| format!("{e:#}"));
                log.stopped = true;
            }
            drop(log);
            #[cfg(test)]
            if phase == GpioPhase::TerminalReset && result.is_ok() {
                if let Some(pause) = core.after_terminal_completion.take() {
                    pause.after_actual_completion();
                }
            }
            lock(&history).calls[index].worker_returned_at = Some(Instant::now());
            (core, result)
        }));
        let mut pending = Pending {
            stop: Arc::clone(&self.stop),
            cutoff: self.cancel_cutoff.clone(),
            history: Arc::clone(&self.history),
            call_index: Some(index),
            complete: false,
        };
        self.join_actual_until(deadline).await?;
        active(&self.stop, deadline, phase == GpioPhase::TerminalReset)?;
        let promoted = Instant::now();
        anyhow::ensure!(
            promoted < deadline,
            "GPIO caller promotion exceeded original deadline"
        );
        lock(&self.history).calls[index].promoted_at = Some(promoted);
        if phase == GpioPhase::TerminalReset {
            self.terminal_promoted = true;
        }
        pending.complete = true;
        Ok(self.snapshot())
    }
    async fn join_actual_until(&mut self, deadline: Instant) -> Result<()> {
        let task = self.task.as_mut().context("no retained GPIO caller")?;
        let joined = match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task)
            .await
        {
            Ok(joined) => joined,
            Err(error) => {
                lock(&self.history)
                    .calls
                    .last_mut()
                    .expect("actual caller record")
                    .join_failure = Some(format!(
                    "actual GPIO caller did not join before deadline; handle retained: {error}"
                ));
                return Err(error)
                    .context("actual GPIO caller did not join before deadline; handle retained");
            }
        };
        self.task.take();
        lock(&self.history)
            .calls
            .last_mut()
            .expect("actual caller record")
            .joined_at = Some(Instant::now());
        if let Err(error) = &joined {
            lock(&self.history)
                .calls
                .last_mut()
                .expect("actual caller record")
                .join_failure = Some(format!(
                "actual GPIO task failed; no replacement owner: {error}"
            ));
        }
        let (mut core, result) = joined.context("actual GPIO task failed; no replacement owner")?;
        if let Some(cutoff) = core.pending_cutoff.take() {
            self.cancel_cutoff = Some(Arc::new(cutoff));
        }
        self.core = Some(core);
        result
    }
    pub(super) async fn stop_and_join_until(&mut self, deadline: Instant) -> Result<GpioHistory> {
        self.stop.store(true, Ordering::SeqCst);
        let cutoff_result = self.cancel_cutoff.as_ref().map_or(Ok(()), |cutoff| {
            cutoff_now(&self.history, cutoff, "stop-cutoff")
        });
        lock(&self.history).stopped = true;
        if self.task.is_some() {
            let result = self.join_actual_until(deadline).await;
            // An actual failed operation may now be joined. Preserve its
            // failure in history; only an outstanding caller blocks cleanup.
            if self.task.is_some() || self.core.is_none() {
                result?;
            }
        }
        cutoff_result?;
        Ok(self.snapshot())
    }
    pub(super) fn cut_with_original_budget(
        &mut self,
        budget: TeardownBudgetView,
    ) -> Result<Am3BbBoardCutoffReceipt> {
        anyhow::ensure!(
            !self.cutoff_receipt_issued,
            "original GPIO cutoff receipt already issued"
        );
        self.stop.store(true, Ordering::SeqCst);
        // This independent original-fence lane stays outside the blocking
        // caller, so cutoff never waits for ON/reset task finalization.
        let cutoff = self
            .cancel_cutoff
            .as_ref()
            .context("original cancellation cutoff has not opened")?;
        let started = Instant::now();
        let result = cutoff.cut_checked();
        // Construct and mark the one-shot original receipt before diagnostic
        // admission. Availability still requires this synchronous call to return.
        let receipt = result.as_ref().ok().map(|timing| {
            self.cutoff_receipt_issued = true;
            Am3BbBoardCutoffReceipt {
                board_enable_gpio: cutoff.gpio(),
                off_level: cutoff.off_level(),
                started_at: timing.write_started_at,
                completed_at: timing.completed_at,
                teardown_budget: budget,
            }
        });
        record_cut(&self.history, "original-budget-cutoff", started, &result);
        result?;
        // Keep actual timing even if late; the original-budget verifier decides.
        Ok(receipt.expect("actual successful cutoff constructed its receipt"))
    }
    pub(super) async fn close_until(&mut self, deadline: Instant) -> Result<GpioHistory> {
        self.stop_and_join_until(deadline).await?;
        if self.close_task.is_none() && lock(&self.history).closed_at.is_none() {
            let core = self
                .core
                .as_ref()
                .context("original GPIO owner missing before close")?;
            anyhow::ensure!(
                core.never_energized.is_none(),
                "recover original never-energized token before closing pre-power owners"
            );
            anyhow::ensure!(
                !core.attempted_on || (core.terminal_complete && self.terminal_promoted),
                "actual terminal reset/cooling operation remains incomplete"
            );
            active(&self.stop, deadline, true)?;
            let core = self.core.take().expect("checked original owner");
            lock(&self.history).close_deadline = Some(deadline);
            let history = Arc::clone(&self.history);
            self.close_task = Some(tokio::task::spawn_blocking(move || {
                // Standard File Drop is actual resource-owner finalization;
                // it does not expose kernel close errors or prove rail-off.
                drop(core);
                lock(&history).closed_at = Some(Instant::now());
            }));
        }
        let mut pending = Pending {
            stop: Arc::clone(&self.stop),
            cutoff: self.cancel_cutoff.clone(),
            history: Arc::clone(&self.history),
            call_index: None,
            complete: false,
        };
        if let Some(task) = self.close_task.as_mut() {
            let actual = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task)
                .await
                .context(
                    "actual GPIO finalizer has not joined; handle and cancellation cutoff retained",
                )?;
            self.close_task.take();
            actual.context("actual GPIO finalizer panicked; no replacement owner")?;
            lock(&self.history).close_joined_at = Some(Instant::now());
        }
        {
            let history = lock(&self.history);
            let original = history
                .close_deadline
                .context("original GPIO close deadline missing")?;
            anyhow::ensure!(
                history.closed_at.is_some_and(|t| t < original)
                    && history.close_joined_at.is_some_and(|t| t < original),
                "GPIO owner finalization lacked timely original join"
            );
        }
        pending.complete = true;
        drop(pending);
        if let Some(cutoff) = self.cancel_cutoff.take() {
            match Arc::try_unwrap(cutoff) {
                Ok(actual) => {
                    drop(actual);
                    lock(&self.history).cancel_lane_dropped_at = Some(Instant::now());
                }
                Err(retained) => {
                    self.cancel_cutoff = Some(retained);
                    anyhow::bail!(
                        "original cancellation cutoff still has a live internal consumer"
                    );
                }
            }
        }
        {
            let history = lock(&self.history);
            if history.extra_cutoff_opened_at.is_some() {
                let original = history
                    .close_deadline
                    .context("original GPIO close deadline missing")?;
                anyhow::ensure!(
                    history.cancel_lane_dropped_at.is_some_and(|t| t < original),
                    "original cancellation cutoff owner dropped after its original close deadline"
                );
            }
        }
        Ok(self.snapshot())
    }
}
impl Drop for RetainedGpioLifecycle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(cutoff) = &self.cancel_cutoff {
            let _ = cutoff_now(&self.history, cutoff, "owner-drop-cutoff");
        }
        lock(&self.history).stopped = true;
        // A retained JoinHandle dropped here detaches, never proves join. The
        // blocking caller still owns Core and its actual reset/guard resources.
        // Enclosing runtime must explicitly stop_and_join before finalization.
    }
}

#[cfg(test)]
#[path = "am3_bb_retained_gpio_tests.rs"]
mod tests;
