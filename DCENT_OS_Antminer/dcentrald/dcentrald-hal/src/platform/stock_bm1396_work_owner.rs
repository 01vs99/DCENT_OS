//! Continuous ASIC owner after the actual completed final T17e ramp.
//! Sole ASIC and logical voltage custody retains actual publication/return
//! receipts through continuous thermal service and terminal closeout.
use super::*;
use std::collections::VecDeque;
use tokio::sync::mpsc::error::{TryRecvError as ChannelReceiveError, TrySendError};
#[path = "stock_bm1396_work_channel.rs"]
mod channel;
use channel::FixedWorkRequest;
pub use channel::{
    FixedWorkControl, FixedWorkEvent, FixedWorkEvents, FixedWorkHealth, FixedWorkInbox,
};

const DELIVERY_CAPACITY: usize = 256;
const LOCAL_THERMAL_CAPACITY: usize = 16;
const SERVICE_BUDGET: Duration = Duration::from_secs(1);

struct WorkCustody<H: Hardware> {
    app: Arc<PicApplication<H>>,
    final_pll: NativePllObservation,
    line: Arc<PowerLine<H>>,
    reset_word: u32,
    cutoff: i16,
    watermark: u64,
    latest: ThermalSnapshot,
    health: FixedWorkHealth,
    thermal_pending: VecDeque<ThermalSnapshot>,
    outgoing: VecDeque<FixedWorkEvent>,
    last_return_offered: Option<u64>,
    delivered_returns: VecDeque<PreservedReturn>,
    last_thermal_delivered: Option<u64>,
    publication_pending: Option<JobPublication>,
}
impl<H: Hardware> WorkCustody<H> {
    fn guard(
        &self,
        state: &AsicState,
        deadline: Instant,
        inbox: &FixedWorkInbox,
    ) -> Result<(), String> {
        if inbox.events.is_closed() || inbox.requests.is_closed() {
            return Err("BM1396 work channel owner closed during operation service".into());
        }
        let owner = &self.app.owner;
        owner.check(deadline, false)?;
        self.app.require_health(deadline)?;
        self.line.check_active_source(owner, deadline)?;
        let baud = self.final_pll.operational_baud();
        owner.query_host(baud.requested_host_register(), deadline)?;
        owner.query_presence(deadline)?;
        if owner.hardware.read(0x34)? != self.reset_word
            || state.thermal_epoch != self.final_pll.epoch()
            || state.requalification_deadline.is_some()
            || state.adc_level != self.final_pll.adc_level()
            || state.assignment.as_ref() != self.final_pll.assignment()
            || state.cold_registers.as_ref() != self.final_pll.cold_registers()
            || state.domain_adc.as_ref() != Some(self.final_pll.current_adc()?)
            || state.operational_baud.as_ref() != Some(baud)
            || state
                .thermal
                .as_ref()
                .and_then(|thermal| thermal.complete_configuration())
                != self.final_pll.thermal_configuration()
            || !state.register_observations.is_empty()
        {
            return Err("BM1396 current work epoch/source state changed".into());
        }
        self.validate_temperature(&self.latest)?;
        owner.check(deadline, false)
    }
    fn validate_temperature(&self, snapshot: &ThermalSnapshot) -> Result<(), String> {
        if snapshot.epoch() != self.final_pll.epoch()
            || snapshot
                .samples()
                .iter()
                .any(|sample| sample.is_historical() || sample.epoch() != snapshot.epoch())
        {
            return Err("BM1396 work thermal snapshot belongs to another epoch".into());
        }
        self.app.preparation_validate_thermal(snapshot, self.cutoff)
    }
    fn service(
        &mut self,
        state: &mut AsicState,
        deadline: Instant,
        inbox: &FixedWorkInbox,
    ) -> Result<(), String> {
        self.guard(state, deadline, inbox)?;
        self.app.owner.receive_locked(state, 128, deadline)?;
        for raw in &state.pending {
            match raw.payload() {
                ReturnPayload::Nonce { .. } => {}
                ReturnPayload::Temperature(sample)
                    if !sample.is_historical() && sample.epoch() == self.final_pll.epoch() =>
                {
                    if Instant::now()
                        .checked_duration_since(sample.received_at())
                        .is_none_or(|age| age >= Duration::from_millis(6960))
                    {
                        return Err("BM1396 work pending temperature stale".into());
                    }
                    for (raw, temperature) in sample
                        .raw_channels()
                        .into_iter()
                        .zip(sample.temperatures_c(self.latest.sampling_mode()))
                    {
                        if raw != 0 && temperature >= self.cutoff {
                            return Err("BM1396 work pending temperature reached cutoff".into());
                        }
                    }
                }
                _ => return Err("BM1396 work refuses unrelated or historical raw custody".into()),
            }
        }
        if self.thermal_pending.len() >= LOCAL_THERMAL_CAPACITY {
            return Err("BM1396 work thermal consumer custody exhausted".into());
        }
        if let Some(snapshot) =
            self.app
                .owner
                .collect_thermal_locked(state, self.watermark, deadline)?
        {
            // The actual HAL snapshot already owns every consumed raw record.
            // Validate before exposing it; on error it remains in that HAL slot.
            self.validate_temperature(&snapshot)?;
            self.watermark = state.next_return;
            self.latest = snapshot.clone();
            *self
                .health
                .latest
                .lock()
                .map_err(|_| "BM1396 work health custody poisoned")? = Some(snapshot.clone());
            self.thermal_pending.push_back(snapshot.clone());
            self.queue(FixedWorkEvent::Thermal(snapshot))?;
        }
        self.guard(state, deadline, inbox)
    }
    fn queue(&mut self, event: FixedWorkEvent) -> Result<(), String> {
        if self.outgoing.len() >= DELIVERY_CAPACITY {
            // Publication/raw/thermal receipt is still retained by the actual
            // owner; failure does not acknowledge or silently evict that data.
            return Err("BM1396 work delivery custody exhausted".into());
        }
        self.outgoing.push_back(event);
        Ok(())
    }
    fn offer_returns(&mut self, state: &AsicState) -> Result<(), String> {
        let previously_offered = self.last_return_offered;
        for record in state
            .pending
            .iter()
            .filter(|record| previously_offered.is_none_or(|old| record.sequence() > old))
        {
            if !matches!(record.payload(), ReturnPayload::Nonce { .. }) {
                // A partial thermal population remains the real pending head.
                // Do not offer a later nonce that exact-head ack cannot accept.
                // Actual complete thermal collection transfers those records
                // before a later service can offer the contiguous nonce prefix.
                break;
            }
            if self.outgoing.len() >= DELIVERY_CAPACITY {
                return Err("BM1396 work return delivery custody exhausted".into());
            }
            self.outgoing
                .push_back(FixedWorkEvent::Return(record.clone()));
            self.last_return_offered = Some(record.sequence());
        }
        Ok(())
    }
    fn flush(&mut self, inbox: &FixedWorkInbox) -> Result<(), String> {
        while !self.outgoing.is_empty() {
            match inbox.events.try_reserve() {
                Ok(permit) => {
                    let head = self.outgoing.front().expect("checked head");
                    match head {
                        FixedWorkEvent::Return(record) => {
                            if self.delivered_returns.len() >= DELIVERY_CAPACITY {
                                break;
                            }
                            self.delivered_returns.push_back(record.clone());
                        }
                        FixedWorkEvent::Thermal(snapshot) => {
                            self.last_thermal_delivered = Some(snapshot.sequence());
                        }
                        FixedWorkEvent::Publication(_) => {}
                    }
                    permit.send(self.outgoing.pop_front().expect("checked head"));
                }
                Err(TrySendError::Full(_)) => break,
                Err(TrySendError::Closed(_)) => {
                    return Err("BM1396 work receipt consumer closed".into())
                }
            }
        }
        Ok(())
    }
}

impl<H: Hardware> PicApplication<H> {
    /// The deadline bounds entry/DMA admission only. Once admitted, this one
    /// counted worker continuously serves bounded operations until cancellation,
    /// receiver loss, a safety refusal or the explicitly finite custody limits.
    /// Dropping this future sets the actual owner's terminal flag via its
    /// existing WaiterGuard; the detached physical worker retains all state until
    /// it observes terminal and exits. Independent source-high remains available.
    pub async fn serve_fixed_work(
        self: &Arc<Self>,
        line: Arc<PowerLine<H>>,
        mut inbox: FixedWorkInbox,
        entry_deadline: Instant,
    ) -> Result<(), String> {
        let app = self.clone();
        self.owner
            .worker(entry_deadline, false, move |owner| {
                struct TerminalOnExit<'a, T: Hardware>(&'a Arc<Transport<T>>);
                impl<T: Hardware> Drop for TerminalOnExit<'_, T> {
                    fn drop(&mut self) {
                        self.0.begin_terminal();
                    }
                }
                let _terminal = TerminalOnExit(owner);
                if !Arc::ptr_eq(&inbox.owner, &owner.identity) {
                    return Err("BM1396 work inbox belongs to another transport".into());
                }
                if inbox.events.is_closed() || inbox.requests.is_closed() {
                    return Err("BM1396 work channel owner closed before DMA admission".into());
                }
                let mut state = owner.lock(&owner.asic, entry_deadline, false)?;
                let final_pll = app
                    .native_pll_observation()?
                    .ok_or("BM1396 actual final PLL absent")?;
                if !final_pll.same_owner(owner)
                    || final_pll.completed_at().is_none()
                    || final_pll.failure().is_some()
                    || final_pll.completed_frequency_mhz().is_none()
                    || final_pll.timeout_base().is_none()
                {
                    return Err("BM1396 actual final PLL incomplete".into());
                }
                final_pll.validate_entry(owner, &state)?;
                let (reset_word, cutoff) = {
                    let transaction = PllTransaction::native(&app);
                    let admission = transaction
                        .admission
                        .lock()
                        .map_err(|_| "BM1396 final admission poisoned")?;
                    let admission = admission
                        .as_ref()
                        .ok_or("BM1396 actual final source admission absent")?;
                    if !Arc::ptr_eq(&line, &admission.line) {
                        return Err("BM1396 work source line differs from final admission".into());
                    }
                    (admission.reset_word, admission.cutoff_c)
                };
                let latest = final_pll
                    .thermal_snapshots()
                    .last()
                    .cloned()
                    .ok_or("BM1396 final thermal absent")?;
                let mut custody = WorkCustody {
                    app: app.clone(),
                    final_pll,
                    line,
                    reset_word,
                    cutoff,
                    watermark: state.next_return,
                    latest,
                    health: inbox.health.clone(),
                    thermal_pending: VecDeque::new(),
                    outgoing: VecDeque::new(),
                    last_return_offered: None,
                    delivered_returns: VecDeque::new(),
                    last_thermal_delivered: None,
                    publication_pending: None,
                };
                let lease = app.voltage_lease_serviced(entry_deadline, || {
                    custody.service(&mut state, entry_deadline, &inbox)
                })?;
                PllTransaction::native(&app).final_voltage_completion(&lease)?;
                custody.guard(&state, entry_deadline, &inbox)?;
                // The real final receipt/current voltage lease precede every DMA
                // address write. No pool request can bypass this one-shot admission.
                owner.initialize_dma_locked(&mut state, entry_deadline, |state| {
                    custody.service(state, entry_deadline, &inbox)
                })?;
                loop {
                    let service_deadline = Instant::now()
                        .checked_add(SERVICE_BUDGET)
                        .ok_or("BM1396 work service deadline overflow")?;
                    if inbox.events.is_closed() || inbox.requests.is_closed() {
                        return Err("BM1396 work channel owner closed".into());
                    }
                    custody.service(&mut state, service_deadline, &inbox)?;
                    custody.offer_returns(&state)?;
                    custody.flush(&inbox)?;
                    match inbox.requests.try_recv() {
                        Ok(FixedWorkRequest::Publication { packet, deadline }) => {
                            let deadline = deadline.min(service_deadline);
                            owner.check(deadline, false)?;
                            if custody.publication_pending.is_some() {
                                return Err(
                                    "BM1396 prior completed publication is not acknowledged".into(),
                                );
                            }
                            // Same logical lease remains held since actual startup.
                            PllTransaction::native(&app).final_voltage_completion(&lease)?;
                            let publication = owner.publish_job_locked(
                                &mut state,
                                packet,
                                false,
                                custody
                                    .final_pll
                                    .timeout_base()
                                    .ok_or("BM1396 actual timeout absent")?,
                                deadline,
                                |state| custody.service(state, deadline, &inbox),
                            )?;
                            // New-job raw data is retained by service, but is not
                            // offered until the actual completed publication precedes
                            // it on this same ordered event channel.
                            custody.publication_pending = Some(publication.clone());
                            custody.queue(FixedWorkEvent::Publication(publication))?;
                            custody.offer_returns(&state)?;
                        }
                        Ok(FixedWorkRequest::PublicationAck {
                            publication,
                            deadline,
                        }) => {
                            owner.check(deadline, false)?;
                            if !publication.same_owner(owner)
                                || !publication.completed()
                                || custody.publication_pending.as_ref() != Some(&publication)
                            {
                                return Err(
                                    "BM1396 publication acknowledgement is foreign or out of order"
                                        .into(),
                                );
                            }
                            custody.publication_pending = None;
                        }
                        Ok(FixedWorkRequest::ReturnAck { record, deadline }) => {
                            owner.check(deadline, false)?;
                            if custody.delivered_returns.front() != Some(&record) {
                                return Err(
                                    "BM1396 work return was not offered to this consumer".into()
                                );
                            }
                            owner.acknowledge_return_locked(&mut state, &record)?;
                            custody.delivered_returns.pop_front();
                        }
                        Ok(FixedWorkRequest::ThermalAck { snapshot, deadline }) => {
                            owner.check(deadline, false)?;
                            if custody.thermal_pending.front() != Some(&snapshot)
                                || custody
                                    .last_thermal_delivered
                                    .is_none_or(|last| snapshot.sequence() > last)
                            {
                                return Err(
                                    "BM1396 work thermal acknowledgement out of order".into()
                                );
                            }
                            owner.acknowledge_thermal_snapshot_locked(&mut state, &snapshot)?;
                            custody.thermal_pending.pop_front();
                        }
                        Err(ChannelReceiveError::Empty) => {}
                        Err(ChannelReceiveError::Disconnected) => {
                            return Err("BM1396 work request owner closed".into())
                        }
                    }
                    custody.flush(&inbox)?;
                    owner.delay(Duration::from_millis(1), service_deadline, false)?;
                }
            })
            .await
    }
}
