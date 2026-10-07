//! Fresh complete MiscCtrl population at the unchanged observed host rate.
//! Requests/CRC and population transition are source-backed; this combined
//! admission strategy is native policy, not a claim about FPGA reset defaults.
use super::*;
use dcentrald_common::bm1391_stock_return::{Bm1391StockNonceReturn, Bm1391StockRegisterReturn};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;

/// Sealed evidence of one completed observation interval. It cannot authorize a
/// later baud write: observe_and_switch repeats the read/join under its guard.
#[derive(Debug)]
pub struct StartupBaudReport {
    host_before: u8,
    host_after: u8,
    received_at: Instant,
    replies: Vec<Bm1391StockRegisterReturn>,
    stale_registers: usize,
}
impl StartupBaudReport {
    pub fn host_before(&self) -> u8 {
        self.host_before
    }
    pub fn host_after(&self) -> u8 {
        self.host_after
    }
    pub fn received_at(&self) -> Instant {
        self.received_at
    }
    pub fn replies(&self) -> &[Bm1391StockRegisterReturn] {
        &self.replies
    }
    pub fn stale_registers(&self) -> usize {
        self.stale_registers
    }
}

/// Retain this Arc until all queued/running workers have drained. This service
/// is exclusively for a caller-owned startup epoch with no mining work. The
/// first unexpected nonce is retained and fails the transport terminal; no
/// subsequent record is consumed. It is evidence for closeout, not valid work.
pub struct StartupObservation<R: Registers> {
    owner: Arc<Transport<R>>,
    population: Vec<Census>,
    in_flight: AtomicUsize,
    unexpected_nonce: Mutex<Option<Bm1391StockNonceReturn>>,
}
struct StartupWorker<R: Registers>(Arc<StartupObservation<R>>);
impl<R: Registers> Drop for StartupWorker<R> {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl<R: Registers> StartupObservation<R> {
    /// Census is the caller's current complete post-address census. Verify the
    /// exact pinned 72/60 population and mapping model before claiming custody.
    /// Wire replies have no request ID; a late identical old reply cannot be
    /// distinguished, and this API does not prove that reset/address setup ran.
    pub fn new(owner: Arc<Transport<R>>, population: Vec<Census>) -> Result<Arc<Self>, String> {
        let model = owner
            .registers
            .model()
            .ok_or("BM1391 startup mapping lacks model identity")?;
        if owner.terminal()
            || population.len() != owner.chains.len()
            || population
                .iter()
                .map(|c| c.chain)
                .ne(owner.chains.iter().copied())
            || population.iter().any(|census| {
                census.replies.len() != usize::from(model.expected_chips())
                    || census.replies.iter().enumerate().any(|(index, reply)| {
                        reply.chain_slot != census.chain
                            || reply.chip_address != index as u8 * model.address_interval()
                            || reply.register != 0
                            || reply.value >> 16 != 0x1391
                            || !census::response_crc_valid(*reply)
                    })
            })
        {
            return Err("BM1391 startup requires the exact complete ordered current census".into());
        }
        owner
            .startup_observation_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1391 transport already has startup observation custody".to_string())?;
        Ok(Arc::new(Self {
            owner,
            population,
            in_flight: AtomicUsize::new(0),
            unexpected_nonce: Mutex::new(None),
        }))
    }

    /// Read-only with respect to ASIC configuration and baud. Emits exact read
    /// requests. The returned report is evidence, never future write authority.
    pub async fn observe(self: &Arc<Self>, deadline: Instant) -> Result<StartupBaudReport, String> {
        self.run(None, deadline).await
    }

    /// Fresh complete read and global transition in one ASIC transaction. All
    /// chips must reply uniformly before any register18 configuration write.
    pub async fn observe_and_switch(
        self: &Arc<Self>,
        baud: StartupBaud,
        deadline: Instant,
    ) -> Result<StartupBaudReport, String> {
        self.run(Some(baud), deadline).await
    }

    async fn run(
        self: &Arc<Self>,
        baud: Option<StartupBaud>,
        deadline: Instant,
    ) -> Result<StartupBaudReport, String> {
        let mut cancellation = AsyncCancellation::new(self.owner.clone());
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let worker = StartupWorker(self.clone());
        let result = tokio::task::spawn_blocking(move || {
            worker
                .0
                .run_with_delay(baud, deadline, &mut |milliseconds| {
                    let until = Instant::now() + Duration::from_millis(milliseconds);
                    loop {
                        worker.0.owner.active(deadline)?;
                        let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                            return Ok(());
                        };
                        std::thread::sleep(remaining.min(Duration::from_millis(1)));
                    }
                })
        })
        .await
        .map_err(|e| format!("BM1391 startup observation worker: {e}"));
        if result.is_err() {
            self.owner.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn run_with_delay(
        &self,
        baud: Option<StartupBaud>,
        deadline: Instant,
        delay: &mut dyn FnMut(u64) -> Result<(), String>,
    ) -> Result<StartupBaudReport, String> {
        self.owner.with_asic_lane(deadline, || {
            self.owner.active(deadline)?;
            let control = self.owner.registers.read(COMMAND_CONTROL)?;
            if control & 0x8000_0000 != 0 || control & 0x20 != 0 {
                return Err("BM1391 startup host is busy or has an unrepresentable ASIC baud code".into());
            }
            let host = (control & 0x3f) as u8;
            let mut stale = 0;
            while self.read_startup_return(deadline)?.is_some() {
                stale += 1;
                if stale >= 511 {
                    return Err("BM1391 startup stale return stream exceeds the bounded drain".into());
                }
            }
            let mut all_replies = Vec::new();
            let mut representatives = Vec::new();
            for census in &self.population {
                self.check_host(host, deadline)?;
                self.owner.publish_command_locked(
                    census.chain, &Transport::<R>::short_frame(0x52, 0, 0x18), deadline,
                )?;
                let mut replies = BTreeMap::new();
                let mut empty_rounds = 0;
                let mut received = 0;
                // Retain the existing bounded census cadence. The request
                // codec is stock; this reg18/census join is native admission.
                while empty_rounds < 3 {
                    delay(300)?;
                    self.check_host(host, deadline)?;
                    let mut round_received = 0;
                    while let Some(reply) = self.read_startup_return(deadline)? {
                        received += 1;
                        round_received += 1;
                        if received > 511 {
                            return Err("BM1391 startup response window exceeds its bound".into());
                        }
                        if reply.chain_slot != census.chain
                            || reply.register != 0x18
                            || !census::response_crc_valid(reply)
                            || !census.replies.iter().any(|known| known.chip_address == reply.chip_address)
                            || (reply.value >> 8) & 0x1f != u32::from(host)
                        {
                            return Err("BM1391 startup reply does not match current census, CRC, register or host rate".into());
                        }
                        if let Some(previous) = replies.insert(reply.chip_address, reply) {
                            if previous != reply {
                                return Err("BM1391 startup has conflicting replies for one chip".into());
                            }
                        }
                    }
                    if round_received == 0 {
                        empty_rounds += 1;
                        delay(100)?;
                        self.check_host(host, deadline)?;
                    } else { empty_rounds = 0; }
                }
                if replies.len() != census.replies.len() {
                    return Err("BM1391 startup MiscCtrl replies do not cover every current chip".into());
                }
                let replies: Vec<_> = replies.into_values().collect();
                representatives.push(replies[0]);
                all_replies.extend(replies);
            }
            let value = all_replies[0].value;
            if all_replies.iter().any(|reply| reply.value != value) {
                return Err("BM1391 startup population MiscCtrl values are not uniform".into());
            }
            self.check_host(host, deadline)?;
            let received_at = Instant::now();
            if let Some(baud) = baud {
                self.owner.set_population_baud_locked(
                    &representatives, baud, deadline, &mut || delay(50),
                )?;
            }
            self.owner.active(deadline)?;
            Ok(StartupBaudReport {
                host_before: host,
                host_after: baud.map_or(host, |baud| baud.code() as u8),
                received_at,
                replies: all_replies,
                stale_registers: stale,
            })
        })
    }

    fn check_host(&self, host: u8, deadline: Instant) -> Result<(), String> {
        self.owner.active(deadline)?;
        let control = self.owner.registers.read(COMMAND_CONTROL)?;
        if control & 0x8000_0000 != 0 || control & 0x3f != u32::from(host) {
            return Err(
                "BM1391 startup observed host rate changed or command remained busy".into(),
            );
        }
        Ok(())
    }

    fn read_startup_return(
        &self,
        deadline: Instant,
    ) -> Result<Option<Bm1391StockRegisterReturn>, String> {
        self.owner.active(deadline)?;
        if self.owner.registers.read(RETURN_COUNT)? & 0x1ff == 0 {
            return Ok(None);
        }
        // Capture nonce custody before selected-chain admission: the generic
        // reader rejects unselected records before exposing their contents.
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.owner.registers.read(RETURN0)?.to_le_bytes());
        bytes[4..].copy_from_slice(&self.owner.registers.read(RETURN1)?.to_le_bytes());
        match decode_bm1391_stock_fpga_return(&bytes).map_err(|e| format!("{e:?}"))? {
            Bm1391StockFpgaReturn::Nonce(nonce) => {
                *self
                    .unexpected_nonce
                    .lock()
                    .map_err(|_| "BM1391 startup nonce custody poisoned")? = Some(nonce);
                Err("BM1391 startup received mining work in its declared no-work epoch".into())
            }
            Bm1391StockFpgaReturn::Register(reply) => Ok(Some(reply)),
        }
    }

    /// Wait for queued and running workers before returning the retained first
    /// unexpected nonce. Call only once the runtime has stopped new requests.
    /// No FIFO drain or physical cut is implied; unread records remain owned by
    /// the runtime closeout. Repeated snapshots return the same retained value.
    pub async fn unexpected_nonce_after_drain(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<Option<Bm1391StockNonceReturn>, String> {
        let service = self.clone();
        tokio::task::spawn_blocking(move || loop {
            if Instant::now() >= deadline {
                return Err("BM1391 startup worker drain timed out".into());
            }
            if service.in_flight.load(Ordering::SeqCst) == 0 {
                return service
                    .unexpected_nonce
                    .lock()
                    .map(|nonce| *nonce)
                    .map_err(|_| "BM1391 startup nonce custody poisoned".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        })
        .await
        .map_err(|e| format!("BM1391 startup worker drain: {e}"))?
    }
}

#[cfg(test)]
#[path = "stock_bm1391_startup_observation_tests.rs"]
mod tests;
