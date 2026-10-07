//! Bounded channel custody for the actual continuous work owner.
//! Fixed-domain runtime candidate; channel handles grant no startup authority.
use super::*;
use tokio::sync::mpsc as work_channel;

const REQUESTS: usize = 8;
const EVENTS: usize = 16;
const MAX_PACKET: usize = 0x10000 + 0x58;

/// This communicates actual producer receipts. There is no synthetic ready flag.
#[derive(Clone, Debug)]
pub enum FixedWorkEvent {
    Publication(JobPublication),
    Return(PreservedReturn),
    Thermal(ThermalSnapshot),
}

pub(super) enum FixedWorkRequest {
    Publication {
        packet: Vec<u8>,
        deadline: Instant,
    },
    PublicationAck {
        publication: JobPublication,
        deadline: Instant,
    },
    ReturnAck {
        record: PreservedReturn,
        deadline: Instant,
    },
    ThermalAck {
        snapshot: ThermalSnapshot,
        deadline: Instant,
    },
}

/// Queuing a request is not hardware completion. The matching actual receipt
/// must arrive through FixedWorkEvents and be joined before any pool submission.
#[derive(Clone)]
pub struct FixedWorkControl {
    requests: work_channel::Sender<FixedWorkRequest>,
}
pub struct FixedWorkEvents {
    events: work_channel::Receiver<FixedWorkEvent>,
}
/// Non-cloneable inbox made by this exact application. Possessing it does not
/// admit DMA: the worker still consumes the actual completed final PLL state.
pub struct FixedWorkInbox {
    pub(super) owner: Arc<()>,
    pub(super) requests: work_channel::Receiver<FixedWorkRequest>,
    pub(super) events: work_channel::Sender<FixedWorkEvent>,
    pub(super) health: FixedWorkHealth,
}

#[derive(Clone)]
pub struct FixedWorkHealth {
    pub(super) latest: Arc<Mutex<Option<ThermalSnapshot>>>,
}
impl FixedWorkHealth {
    /// An unchanged actual thermal receipt, never a startup-admission flag.
    pub fn latest_thermal(&self) -> Result<Option<ThermalSnapshot>, String> {
        Ok(self
            .latest
            .lock()
            .map_err(|_| "BM1396 work health custody poisoned")?
            .clone())
    }
}

impl FixedWorkControl {
    async fn enqueue(&self, request: FixedWorkRequest, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline {
            return Err("BM1396 work request deadline already elapsed".into());
        }
        let permit = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            self.requests.reserve(),
        )
        .await
        .map_err(|_| "BM1396 work request queue deadline")?
        .map_err(|_| "BM1396 actual work owner closed")?;
        // Cancellation before reservation never queues a partially owned request.
        if Instant::now() >= deadline {
            return Err("BM1396 work request admission deadline elapsed".into());
        }
        permit.send(request);
        Ok(())
    }
    pub async fn enqueue_publication(
        &self,
        packet: Vec<u8>,
        deadline: Instant,
    ) -> Result<(), String> {
        validate_fixed_packet(&packet)?;
        self.enqueue(FixedWorkRequest::Publication { packet, deadline }, deadline)
            .await
    }
    /// Registry has joined this actual completed packet before buffer progression.
    pub async fn acknowledge_publication(
        &self,
        publication: JobPublication,
        deadline: Instant,
    ) -> Result<(), String> {
        self.enqueue(
            FixedWorkRequest::PublicationAck {
                publication,
                deadline,
            },
            deadline,
        )
        .await
    }
    /// Caller has retained/qualified the exact actual return before this transfer.
    pub async fn acknowledge_return(
        &self,
        record: PreservedReturn,
        deadline: Instant,
    ) -> Result<(), String> {
        self.enqueue(FixedWorkRequest::ReturnAck { record, deadline }, deadline)
            .await
    }
    /// A copied historical thermal record can never acknowledge the new epoch.
    pub async fn acknowledge_thermal(
        &self,
        snapshot: ThermalSnapshot,
        deadline: Instant,
    ) -> Result<(), String> {
        self.enqueue(
            FixedWorkRequest::ThermalAck { snapshot, deadline },
            deadline,
        )
        .await
    }
}
impl FixedWorkEvents {
    pub async fn next(&mut self) -> Option<FixedWorkEvent> {
        self.events.recv().await
    }
}
impl<H: Hardware> PicApplication<H> {
    pub fn fixed_work_channels(
        &self,
    ) -> (
        FixedWorkControl,
        FixedWorkEvents,
        FixedWorkHealth,
        FixedWorkInbox,
    ) {
        let (requests, receiver) = work_channel::channel(REQUESTS);
        let (events, event_receiver) = work_channel::channel(EVENTS);
        let health = FixedWorkHealth {
            latest: Arc::new(Mutex::new(None)),
        };
        (
            FixedWorkControl { requests },
            FixedWorkEvents {
                events: event_receiver,
            },
            health.clone(),
            FixedWorkInbox {
                owner: self.owner.identity.clone(),
                requests: receiver,
                events,
                health,
            },
        )
    }
}

/// The runtime candidate accepts exactly the source-bound daemon encoder's
/// fixed coinbase window. The general library packet parser remains unchanged.
fn validate_fixed_packet(packet: &[u8]) -> Result<(), String> {
    if packet.len() > MAX_PACKET {
        return Err("BM1396 work request packet exceeds source bound".into());
    }
    let job = dcentrald_common::bm1396_work::bm1396_parse_job_packet(packet)
        .map_err(|error| format!("BM1396 queued job packet: {error:?}"))?;
    let window = usize::from(job.nonce2_offset);
    let payload = usize::from(job.coinbase_len)
        .checked_add(usize::from(job.merkle_branch_count) * 32)
        .ok_or("BM1396 fixed packet payload overflow")?;
    if job.flags != 3
        || job.ticket_difficulty != 0x0f
        || job.nonce2_size != 0
        || job.multiversion_enable != 0
        || job.multiversion_count != 1
        || job.merkle_branch_count > 128
        || payload > 65_534
        || packet.len() != 0x58 + payload + 2
        || window
            .checked_add(8)
            .is_none_or(|end| end > job.coinbase.len())
    {
        return Err("BM1396 packet differs from qualified fixed-domain candidate".into());
    }
    let actual = u64::from_le_bytes(
        job.coinbase[window..window + 8]
            .try_into()
            .map_err(|_| "BM1396 fixed coinbase window incomplete")?,
    );
    if job.nonce2_initial != actual {
        return Err("BM1396 fixed EN2 differs from immutable coinbase bytes".into());
    }
    // Exact retained original job producer's Modbus CRC: all bytes before the
    // final little-endian checksum, seedffff, reflected polynomiala001.
    let mut crc = 0xffffu16;
    for &byte in &packet[..packet.len() - 2] {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    if packet[packet.len() - 2..] != crc.to_le_bytes() {
        return Err("BM1396 fixed packet CRC differs".into());
    }
    Ok(())
}
