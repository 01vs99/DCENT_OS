//! Exact signed DDR job producer and retained FPGA-produced table observations.
use super::*;
use dcentrald_common::bm1396_work::{
    bm1396_parse_job_packet, bm1396_plan_job_fpga, bm1396_plan_ordered_job_dispatch,
    Bm1396OrderedJobOp,
};
use dcentrald_common::bm1396_work_binding::{
    bm1396_decode_outstanding_work, bm1396_initial_outstanding_publication, Bm1396OutstandingWork,
};

/// Stored before physical work publication, including when the waiter vanishes.
/// The packet remains available for independent complete-header CPU validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobPublication {
    issuer: Arc<()>,
    sequence: u64,
    job_id: u32,
    buffer: u8,
    packet: Arc<[u8]>,
    completed: bool,
}
impl JobPublication {
    /// Pointer identity of the actual producer, independent of value equality
    /// between otherwise identical packets published by different transports.
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.identity)
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn job_id(&self) -> u32 {
        self.job_id
    }
    pub fn buffer(&self) -> u8 {
        self.buffer
    }
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
    pub fn completed(&self) -> bool {
        self.completed
    }
}

/// Two identical uncached table copies associated with a retained published job.
/// This is not a hardware generation counter, hash qualification or a share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingObservation {
    work_id: u16,
    raw: [u8; 64],
    decoded: Bm1396OutstandingWork,
    publication: JobPublication,
}
impl OutstandingObservation {
    pub fn work_id(&self) -> u16 {
        self.work_id
    }
    pub fn raw(&self) -> &[u8; 64] {
        &self.raw
    }
    pub fn decoded(&self) -> &Bm1396OutstandingWork {
        &self.decoded
    }
    pub fn publication(&self) -> &JobPublication {
        &self.publication
    }
}

impl<H: Hardware> Transport<H> {
    /// Cold address publication under the single ASIC lane. Source host code
    /// does not write/zero the FPGA-produced 2 MiB table, and neither do we.
    pub async fn initialize_dma(self: &Arc<Self>, deadline: Instant) -> Result<(), String> {
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.initialize_dma_locked(&mut state, deadline, |_| Ok(()))
        })
        .await
    }

    pub(super) fn initialize_dma_locked(
        &self,
        state: &mut AsicState,
        deadline: Instant,
        mut service: impl FnMut(&mut AsicState) -> Result<(), String>,
    ) -> Result<(), String> {
        let this = self;
        if state.dma_initialized
            || !state.publications.is_empty()
            || this.asic_fault.load(Ordering::SeqCst)
        {
            return Err("BM1396 DMA already initialized or ASIC portal unresolved".into());
        }
        let mut fault = FaultGuard::new(&this.asic_fault, &this.terminal);
        service(state)?;
        let old = this.hardware.read(DHASH)?;
        this.store(DHASH, old & !RUN, deadline, false)?;
        this.hardware.barrier()?;
        if this.hardware.read(DHASH)? & RUN != 0 {
            return Err("BM1396 cold RUN clear not observed".into());
        }
        let initial = bm1396_initial_outstanding_publication(DMA_BASE)
            .map_err(|e| format!("BM1396 DMA plan: {e:?}"))?;
        for write in initial.writes {
            service(state)?;
            this.checked_store(write.offset, write.value, deadline, false)?;
        }
        this.check(deadline, false)?;
        state.dma_initialized = true;
        service(state)?;
        fault.complete();
        Ok(())
    }

    pub fn publications(&self) -> Result<Vec<JobPublication>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 ASIC owner is busy or poisoned")?;
        Ok(state.publications.clone())
    }

    /// Execute the original signed job plan, alternating only the two retained
    /// buffers. Publication is software completion, not physical hashing proof.
    /// Caller still owes full startup, independent cutoff and runtime health.
    pub async fn publish_job(
        self: &Arc<Self>,
        packet: Vec<u8>,
        multiversion: bool,
        timeout_base: u32,
        deadline: Instant,
    ) -> Result<JobPublication, String> {
        // Parse before queuing, bounding caller-owned allocation and validating
        // every payload slice used by the sealed common planner.
        if packet.len() > 0x10000 + 0x58 {
            return Err("BM1396 job packet exceeds bounded source buffer".into());
        }
        bm1396_parse_job_packet(&packet).map_err(|e| format!("BM1396 job packet: {e:?}"))?;
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.publish_job_locked(
                &mut state,
                packet,
                multiversion,
                timeout_base,
                deadline,
                |_| Ok(()),
            )
        })
        .await
    }

    /// Private composed-runtime entry. A caller holds the actual ASIC mutex
    /// and binds its completed final source state before passing the callback.
    /// Existing generic producer retains its explicit unqualified wrapper.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn publish_job_locked(
        &self,
        state: &mut AsicState,
        packet: Vec<u8>,
        multiversion: bool,
        timeout_base: u32,
        deadline: Instant,
        mut service: impl FnMut(&mut AsicState) -> Result<(), String>,
    ) -> Result<JobPublication, String> {
        let this = self;
        if packet.len() > 0x10000 + 0x58 {
            return Err("BM1396 job packet exceeds bounded source buffer".into());
        }
        this.check(deadline, false)?;
        if !state.dma_initialized || this.asic_fault.load(Ordering::SeqCst) {
            return Err("BM1396 DMA cold initialization is missing or unresolved".into());
        }
        let job =
            bm1396_parse_job_packet(&packet).map_err(|e| format!("BM1396 job packet: {e:?}"))?;
        if state.publications.len() >= 4096
            || state.publications.iter().any(|p| p.job_id == job.job_id)
        {
            return Err("BM1396 lifetime job custody exhausted or job ID reused".into());
        }
        let first = state.publications.is_empty();
        let buffer = state.next_buffer;
        if first && this.hardware.read(DHASH)? & RUN != 0 {
            return Err("BM1396 first job requires observed cold RUN clear".into());
        }
        // The published address must still be ours before writing its peer.
        let expected_active = DMA_BASE
            + if first || buffer == 1 {
                0x200000
            } else {
                0x210000
            };
        if this.hardware.read(0x110)? != DMA_BASE || this.hardware.read(0x118)? != expected_active {
            return Err("BM1396 DMA base or active buffer changed outside its owner".into());
        }
        let plan =
            bm1396_plan_job_fpga(&job, buffer).map_err(|e| format!("BM1396 job buffer: {e:?}"))?;
        let ordered =
            bm1396_plan_ordered_job_dispatch(&plan, DMA_BASE, multiversion, first, timeout_base)
                .map_err(|e| format!("BM1396 ordered job: {e:?}"))?;
        // Admission occurs before any DMA/store operation. The sole RUN-setting
        // final operation must remain last, so service cannot observe a new job
        // between its final store and this worker's completed publication seal.
        let operations = ordered.ops();
        if !matches!(operations.last(), Some(Bm1396OrderedJobOp::RmwFinal {
            offset: DHASH, preserve_mask, mode_word,
        }) if preserve_mask & RUN == 0 && mode_word & RUN != 0)
            || operations[..operations.len().saturating_sub(1)]
                .iter()
                .any(|operation| match *operation {
                    Bm1396OrderedJobOp::RmwFinal { .. } => true,
                    Bm1396OrderedJobOp::RmwSet {
                        offset: DHASH,
                        set_mask,
                    } => set_mask & RUN != 0,
                    Bm1396OrderedJobOp::WriteRegister(write) => write.offset == DHASH,
                    _ => false,
                })
        {
            return Err("BM1396 source publication final RUN boundary differs".into());
        }
        let publication = JobPublication {
            issuer: Arc::clone(&this.identity),
            sequence: state.publications.len() as u64 + 1,
            job_id: job.job_id,
            buffer,
            packet: Arc::from(packet),
            completed: false,
        };
        state.publications.push(publication);
        let mut fault = FaultGuard::new(&this.asic_fault, &this.terminal);
        for operation in ordered.ops() {
            service(state)?;
            this.check(deadline, false)?;
            match *operation {
                Bm1396OrderedJobOp::CopyDdrPayload {
                    absolute_address,
                    payload_offset,
                    length,
                } => {
                    let offset = dma_payload_offset(absolute_address, length, buffer)?;
                    let bytes = ordered
                        .buffer_payload()
                        .get(payload_offset..payload_offset + length)
                        .ok_or("BM1396 DDR payload slice invalid")?;
                    this.hardware.write_dma(offset, bytes)?;
                    this.hardware.barrier()?;
                }
                Bm1396OrderedJobOp::VerifyDdrPayload {
                    absolute_address,
                    payload_offset,
                    length,
                } => {
                    let offset = dma_payload_offset(absolute_address, length, buffer)?;
                    let mut observed = vec![0u8; length];
                    this.hardware.read_dma(offset, &mut observed)?;
                    if observed != ordered.buffer_payload()[payload_offset..payload_offset + length]
                    {
                        return Err("BM1396 inactive DDR payload readback differs".into());
                    }
                }
                Bm1396OrderedJobOp::RmwClear { offset, clear_mask } => {
                    let old = this.hardware.read(offset)?;
                    this.store(offset, old & !clear_mask, deadline, false)?;
                    this.hardware.barrier()?;
                }
                Bm1396OrderedJobOp::RequireClear {
                    offset,
                    clear_mask,
                    max_polls,
                    delay_call_value,
                } => {
                    let mut clear = false;
                    for _ in 0..max_polls {
                        service(state)?;
                        this.check(deadline, false)?;
                        if this.hardware.read(offset)? & clear_mask == 0 {
                            clear = true;
                            break;
                        }
                        this.delay(
                            Duration::from_millis(u64::from(delay_call_value)),
                            deadline,
                            false,
                        )?;
                    }
                    if !clear {
                        return Err("BM1396 DHASH clear deadline/poll exhaustion".into());
                    }
                }
                Bm1396OrderedJobOp::WriteRegister(write) => {
                    // Volatile uncached payload stores and their barrier
                    // precede publication of the new buffer address.
                    this.checked_store(write.offset, write.value, deadline, false)?;
                }
                Bm1396OrderedJobOp::DelayCall(value) => {
                    this.delay(Duration::from_millis(u64::from(value)), deadline, false)?
                }
                Bm1396OrderedJobOp::RmwSet { offset, set_mask } => {
                    let old = this.hardware.read(offset)?;
                    this.store(offset, old | set_mask, deadline, false)?;
                    this.hardware.barrier()?;
                }
                // The source planner emits this as the final operation. Its
                // store/barrier/readback and the completed seal stay contiguous.
                Bm1396OrderedJobOp::RmwFinal {
                    offset,
                    preserve_mask,
                    mode_word,
                } => {
                    let old = this.hardware.read(offset)?;
                    let value = (old & preserve_mask) | mode_word;
                    this.store(offset, value, deadline, false)?;
                    this.hardware.barrier()?;
                    // Source bit7 is a self-changing control; verify all
                    // other requested fields without inventing a fixed bit7.
                    if (this.hardware.read(offset)? ^ value) & !0x80 != 0 {
                        return Err("BM1396 final engine mode readback differs".into());
                    }
                }
            }
        }
        this.check(deadline, false)?;
        let saved = state.publications.last_mut().expect("retained before MMIO");
        saved.completed = true;
        let result = saved.clone();
        state.next_buffer ^= 1;
        // No receive is performed after the final RUN store until this exact
        // software publication seal is complete. New returns can now bind it.
        service(state)?;
        fault.complete();
        Ok(result)
    }

    pub(super) fn outstanding_locked(
        &self,
        state: &AsicState,
        work_id: u16,
        deadline: Instant,
    ) -> Result<OutstandingObservation, String> {
        if work_id > 0x7fff || !state.dma_initialized {
            return Err("BM1396 outstanding table is not admitted".into());
        }
        if self.hardware.read(0x110)? != DMA_BASE {
            return Err("BM1396 outstanding table base changed".into());
        }
        let offset = usize::from(work_id) * 64;
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        self.check(deadline, false)?;
        self.hardware.barrier()?;
        self.hardware.read_dma(offset, &mut first)?;
        self.hardware.barrier()?;
        self.hardware.read_dma(offset, &mut second)?;
        self.check(deadline, false)?;
        if first != second {
            return Err("BM1396 FPGA outstanding table changed during capture".into());
        }
        let decoded = bm1396_decode_outstanding_work(&first)
            .map_err(|e| format!("BM1396 table entry: {e:?}"))?;
        let publication = state
            .publications
            .iter()
            .find(|p| p.completed && p.job_id == decoded.job_id)
            .ok_or("BM1396 table job has no completed retained publication")?
            .clone();
        Ok(OutstandingObservation {
            work_id,
            raw: first,
            decoded,
            publication,
        })
    }
}

fn dma_payload_offset(absolute: u32, length: usize, buffer: u8) -> Result<usize, String> {
    let start = 0x200000 + usize::from(buffer) * 0x10000;
    let offset = absolute
        .checked_sub(DMA_BASE)
        .ok_or("BM1396 DMA address underflow")? as usize;
    if offset < start
        || offset
            .checked_add(length)
            .map_or(true, |end| end > start + 0x10000)
    {
        return Err("BM1396 write escapes its inactive 64 KiB job buffer".into());
    }
    Ok(offset)
}
