//! One-shot terminal observations from this actual native owner. Source-high,
//! complete PIC-disable frames and RUN-clear are controls, not measured rails.
use super::*;

pub struct TerminalControlsReceipt<H: Hardware> {
    owner: Arc<Transport<H>>,
    _line: Arc<PowerLine<H>>,
    _pic: Arc<PicApplication<H>>,
    cutoff_deadline: Instant,
    cleanup_deadline: Instant,
    finished_at: Instant,
    line: Result<PowerLineOffObservation, String>,
    engine: Result<(), String>,
    pic: Result<Vec<PicReply>, String>,
    drain: Result<(), String>,
}
impl<H: Hardware> TerminalControlsReceipt<H> {
    pub fn same_owner(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    pub fn controls_completed(&self) -> bool {
        self.owner.is_terminal()
            && self
                .line
                .as_ref()
                .is_ok_and(|line| line.pin_high && line.observed_at() < self.cutoff_deadline)
            && self.engine.is_ok()
            && self.pic.as_ref().is_ok_and(|replies| {
                replies.len() == self.owner.chains.len()
                    && replies
                        .iter()
                        .zip(&self.owner.chains)
                        .all(|(reply, chain)| reply.chain() == *chain)
            })
            && self.drain.is_ok()
            && self.finished_at < self.cleanup_deadline
    }
    pub fn cutoff_attempted_at(&self) -> Option<Instant> {
        self.line
            .as_ref()
            .ok()
            .map(PowerLineOffObservation::attempted_at)
    }
    pub fn cutoff_observed_at(&self) -> Option<Instant> {
        self.line
            .as_ref()
            .ok()
            .map(PowerLineOffObservation::observed_at)
    }
    pub fn finished_at(&self) -> Instant {
        self.finished_at
    }
    pub fn cutoff_deadline(&self) -> Instant {
        self.cutoff_deadline
    }
    pub fn cleanup_deadline(&self) -> Instant {
        self.cleanup_deadline
    }
    pub fn line(&self) -> &Result<PowerLineOffObservation, String> {
        &self.line
    }
    pub fn engine(&self) -> &Result<(), String> {
        &self.engine
    }
    pub fn pic(&self) -> &Result<Vec<PicReply>, String> {
        &self.pic
    }
    pub fn drain(&self) -> &Result<(), String> {
        &self.drain
    }
}

impl<H: Hardware> Transport<H> {
    /// Latch terminal before any await. The independent GPIO cut precedes
    /// contended ASIC/PIC operations; failure never skips a later cleanup
    /// attempt. Actual counted workers remain owned through cancellation.
    /// The runtime must retain this future and separately join its actor roster.
    pub async fn close_terminal_controls(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        pic: Arc<PicApplication<H>>,
        cutoff_deadline: Instant,
        cleanup_deadline: Instant,
    ) -> Result<TerminalControlsReceipt<H>, String> {
        self.begin_terminal();
        if !line.same_owner(self) || !pic.same_owner(self) {
            return Err("BM1396 terminal controls belong to different owners".into());
        }
        if cutoff_deadline >= cleanup_deadline {
            return Err("BM1396 terminal deadlines are not strictly ordered".into());
        }
        self.terminal_controls_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1396 terminal controls are one-shot")?;
        let line_result = line.terminal_high(cutoff_deadline).await;
        let engine = self.stop_engine(cleanup_deadline).await;
        let pic_result = pic.disable_all(cleanup_deadline, true).await;
        let drain = self.drain(cleanup_deadline).await;
        Ok(TerminalControlsReceipt {
            owner: self.clone(),
            _line: line,
            _pic: pic,
            cutoff_deadline,
            cleanup_deadline,
            finished_at: Instant::now(),
            line: line_result,
            engine,
            pic: pic_result,
            drain,
        })
    }
}
