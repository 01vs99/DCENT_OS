//! Retained, owner-bound terminal control observations for runtime closeout.
//! GPIO pin-high, fixed PIC off ACKs and stopped software engine controls are
//! distinct observations. None is a physical measurement of hashboard rails.
use super::*;

/// Constructed only by actual retained-owner terminal operations. The fields
/// are private so a runtime cannot turn edited report booleans into authority.
pub struct TerminalControlsReceipt<R: Registers> {
    owner: Arc<Transport<R>>,
    _line_owner: Arc<PowerLine<R>>,
    _pic_owner: Arc<PicApplication<R>>,
    cutoff_attempted_at: Option<Instant>,
    cutoff_at: Option<Instant>,
    finished_at: Instant,
    cutoff_deadline: Instant,
    cleanup_deadline: Instant,
    line: Result<PowerLineOffObservation, String>,
    engine: EngineStopReport,
    pic: Result<PicOffReport, String>,
    drain: Result<(), String>,
}
impl<R: Registers> TerminalControlsReceipt<R> {
    pub fn same_owner(&self, owner: &Arc<Transport<R>>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    pub fn controls_completed(&self) -> bool {
        self.line.as_ref().is_ok_and(|line| line.pin_high)
            && self.engine.controls_clear()
            && self.pic.as_ref().is_ok_and(PicOffReport::all_acknowledged)
            && self.drain.is_ok()
            && self.owner.terminal()
            && self.cutoff_at.is_some_and(|at| at < self.cutoff_deadline)
            && self.finished_at < self.cleanup_deadline
    }
    /// Timestamp issued inside the actual GPIO worker immediately before cut.
    pub fn cutoff_attempted_at(&self) -> Option<Instant> {
        self.cutoff_attempted_at
    }
    /// Time of the independent source GPIO high observation, never rail-off.
    pub fn cutoff_observed_at(&self) -> Option<Instant> {
        self.cutoff_at
    }
    pub fn finished_at(&self) -> Instant {
        self.finished_at
    }
    pub fn line(&self) -> &Result<PowerLineOffObservation, String> {
        &self.line
    }
    pub fn engine(&self) -> &EngineStopReport {
        &self.engine
    }
    pub fn pic(&self) -> &Result<PicOffReport, String> {
        &self.pic
    }
    pub fn drain(&self) -> &Result<(), String> {
        &self.drain
    }
}

impl<R: Registers> Transport<R> {
    /// Close normal admission immediately, then cut the independent source
    /// GPIO before waiting on ASIC or management locks. Retain one absolute
    /// cutoff deadline and one later cleanup deadline issued by the runtime.
    /// All stages are attempted even when an earlier observation fails.
    ///
    /// Runtime must retain/join its actors and this async operation, fence API
    /// mutation, and validate this receipt against its watchdog-issued budget.
    /// Cancelling this future cannot create a completed receipt or reopen work.
    pub async fn close_terminal_controls(
        self: &Arc<Self>,
        line: Arc<PowerLine<R>>,
        pic: Arc<PicApplication<R>>,
        cutoff_deadline: Instant,
        cleanup_deadline: Instant,
    ) -> Result<TerminalControlsReceipt<R>, String> {
        self.latch_terminal();
        if !line.same_owner(self) || !Arc::ptr_eq(pic.transport(), self) {
            return Err("BM1391 terminal controls belong to different owners".into());
        }
        if cutoff_deadline >= cleanup_deadline {
            return Err("BM1391 terminal deadlines are not strictly ordered".into());
        }
        let task_line = line.clone();
        let cut = tokio::task::spawn_blocking(move || {
            let attempted_at = Instant::now();
            let result = task_line.terminal_high(cutoff_deadline);
            let at = result.as_ref().ok().map(|_| Instant::now());
            (result, attempted_at, at)
        })
        .await;
        let (line_result, cutoff_attempted_at, cutoff_at) = match cut {
            Ok((result, attempted_at, at)) => (result, Some(attempted_at), at),
            Err(error) => (
                Err(format!("BM1391 terminal GPIO worker: {error}")),
                None,
                None,
            ),
        };
        let owner = self.clone();
        let engine =
            match tokio::task::spawn_blocking(move || owner.terminal_stop_engine(cleanup_deadline))
                .await
            {
                Ok(report) => report,
                Err(error) => EngineStopReport {
                    errors: vec![format!("BM1391 terminal engine worker: {error}")],
                    ..EngineStopReport::default()
                },
            };
        let pic_result = pic.terminal_off(cleanup_deadline).await;
        let owner = self.clone();
        let drain = tokio::task::spawn_blocking(move || owner.terminal_drain(cleanup_deadline))
            .await
            .map_err(|error| format!("BM1391 terminal drain worker: {error}"))
            .and_then(|result| result);
        Ok(TerminalControlsReceipt {
            owner: self.clone(),
            _line_owner: line,
            _pic_owner: pic,
            cutoff_attempted_at,
            cutoff_at,
            finished_at: Instant::now(),
            cutoff_deadline,
            cleanup_deadline,
            line: line_result,
            engine,
            pic: pic_result,
            drain,
        })
    }
}

#[cfg(test)]
#[path = "stock_bm1391_closeout_tests.rs"]
mod tests;
