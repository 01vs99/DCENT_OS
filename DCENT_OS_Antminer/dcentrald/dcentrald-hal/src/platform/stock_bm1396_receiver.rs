//! Original receive loop 4e258/4ee68: persistent pair carry, not an independent
//! two-word codec. Source malformed alignment is retained and rejected here.
use super::*;
use dcentrald_common::bm1396_work::{
    bm1396_decode_nonce_record, bm1396_decode_register_record, Bm1396NonceRecord,
    Bm1396RegisterRecord,
};

const MARKER: u32 = 0x5555_aaaa;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReturnPayload {
    Nonce {
        nonce: Bm1396NonceRecord,
        outstanding: OutstandingObservation,
    },
    Register(Bm1396RegisterRecord),
    Temperature(TemperatureRecord),
    /// Bytes decoded only through the previous owned sensor configuration.
    /// These can never satisfy a current-epoch thermal population.
    HistoricalTemperature(TemperatureRecord),
    Unclassified(String),
}

/// A consumed record has permanent custody until this owner's head is explicitly
/// acknowledged. A snapshot is a copy, not a destructive drain or a pool share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreservedReturn {
    issuer: Arc<()>,
    sequence: u64,
    words: Vec<u32>,
    payload: ReturnPayload,
}
impl PreservedReturn {
    /// A copied observation keeps the exact producer's seal; payload equality
    /// alone cannot establish ownership across independently retained mappings.
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.identity)
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn words(&self) -> &[u32] {
        &self.words
    }
    pub fn payload(&self) -> &ReturnPayload {
        &self.payload
    }
}

#[derive(Default)]
pub(super) struct Assembler {
    carry: Option<[u32; 2]>,
    partial: Vec<u32>,
    enabled: bool,
}

impl<H: Hardware> Transport<H> {
    pub fn pending_returns(&self) -> Result<Vec<PreservedReturn>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 FIFO owner is busy or poisoned")?;
        Ok(state.pending.iter().cloned().collect())
    }

    /// Partial consumption remains observable even after terminal/drain. It is
    /// never silently cleared or treated as a valid record on a later retry.
    pub fn partial_return_words(&self) -> Result<Vec<u32>, String> {
        let state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 FIFO owner is busy or poisoned")?;
        Ok(state.receiver.partial.clone())
    }

    pub fn acknowledge_return(&self, record: &PreservedReturn) -> Result<(), String> {
        let mut state = self
            .asic
            .try_lock()
            .map_err(|_| "BM1396 FIFO owner is busy or poisoned")?;
        self.acknowledge_return_locked(&mut state, record)
    }

    pub(super) fn acknowledge_return_locked(
        &self,
        state: &mut AsicState,
        record: &PreservedReturn,
    ) -> Result<(), String> {
        if !Arc::ptr_eq(&record.issuer, &self.identity) || state.pending.front() != Some(record) {
            return Err("BM1396 acknowledgment is foreign, stale or out of order".into());
        }
        state.pending.pop_front();
        Ok(())
    }

    /// Process a bounded batch. Returns a count only; all popped data, including
    /// invalid records and partial words, remains attached to this owner.
    pub async fn poll_returns(
        self: &Arc<Self>,
        limit: usize,
        deadline: Instant,
    ) -> Result<usize, String> {
        if limit == 0 || limit > 128 {
            return Err("BM1396 receive batch must contain 1..128 records".into());
        }
        self.worker(deadline, false, move |this| {
            let mut state = this.lock(&this.asic, deadline, false)?;
            this.receive_locked(&mut state, limit, deadline)
        })
        .await
    }

    pub(super) fn receive_locked(
        &self,
        state: &mut AsicState,
        limit: usize,
        deadline: Instant,
    ) -> Result<usize, String> {
        if self.asic_fault.load(Ordering::SeqCst) || !state.receiver.partial.is_empty() {
            return Err("BM1396 return alignment or ASIC portal is unresolved".into());
        }
        if !state.receiver.enabled {
            let old = self.hardware.read(0x1c)?;
            self.checked_store(0x1c, old | 0x10000, deadline, false)?;
            state.receiver.enabled = true;
        }
        let mut received = 0;
        while received < limit {
            self.check(deadline, false)?;
            // Refuse BEFORE popping another record, preserving existing custody.
            if state.pending.len() >= RETURN_CAPACITY {
                return Err("BM1396 retained return capacity exhausted".into());
            }
            if self.hardware.read(0x18)? & 0x1ff < 2 {
                break;
            }
            let mut fault = FaultGuard::new(&self.asic_fault, &self.terminal);
            for offset in [0x10, 0x14] {
                self.check(deadline, false)?;
                let word = self.hardware.read(offset)?;
                state.receiver.partial.push(word);
            }
            let first = [state.receiver.partial[0], state.receiver.partial[1]];
            let (header, valid_alignment) = if first[1] == MARKER {
                let carry = state.receiver.carry;
                state.receiver.carry = Some(first);
                (carry.unwrap_or([0; 2]), carry.is_some())
            } else {
                for offset in [0x10, 0x14] {
                    self.check(deadline, false)?;
                    let word = self.hardware.read(offset)?;
                    state.receiver.partial.push(word);
                }
                let tail = [state.receiver.partial[2], state.receiver.partial[3]];
                state.receiver.carry = Some(tail);
                (first, tail[1] == MARKER)
            };
            // Publish raw custody before any classification or DMA access.
            let sequence = state.next_return;
            state.next_return = sequence
                .checked_add(1)
                .ok_or("BM1396 return sequence exhausted")?;
            state.pending.push_back(PreservedReturn {
                issuer: Arc::clone(&self.identity),
                sequence,
                words: std::mem::take(&mut state.receiver.partial),
                payload: ReturnPayload::Unclassified("classification incomplete".into()),
            });
            if !valid_alignment {
                state.pending.back_mut().expect("just retained").payload =
                    ReturnPayload::Unclassified(
                        "unknown initial carry or malformed fourth word".into(),
                    );
                return Err("BM1396 return alignment is unproved; raw words retained".into());
            }
            let mut bytes = [0u8; 8];
            bytes[..4].copy_from_slice(&header[0].to_le_bytes());
            bytes[4..].copy_from_slice(&header[1].to_le_bytes());
            let classified = if header[0] & BUSY != 0 {
                bm1396_decode_nonce_record(self.model, &bytes)
                    .map_err(|e| format!("BM1396 nonce decode: {e:?}"))
                    .and_then(|nonce| {
                        self.chain(nonce.chain_slot)?;
                        let outstanding =
                            self.outstanding_locked(state, nonce.work_id, deadline)?;
                        Ok(ReturnPayload::Nonce { nonce, outstanding })
                    })
            } else {
                bm1396_decode_register_record(&bytes)
                    .map_err(|e| format!("BM1396 register decode: {e:?}"))
                    .and_then(|record| {
                        self.chain(record.chain_slot)?;
                        if !record.is_normal_path_type() {
                            return Err("BM1396 non-normal register response type".into());
                        }
                        if record.register == 0x44 {
                            self.decode_temperature(state, record).map(|sample| {
                                if sample.is_historical() {
                                    ReturnPayload::HistoricalTemperature(sample)
                                } else {
                                    ReturnPayload::Temperature(sample)
                                }
                            })
                        } else {
                            Ok(ReturnPayload::Register(record))
                        }
                    })
            };
            match classified {
                Ok(payload) => state.pending.back_mut().expect("retained record").payload = payload,
                Err(error) => {
                    state.pending.back_mut().expect("retained record").payload =
                        ReturnPayload::Unclassified(error.clone());
                    return Err(error);
                }
            }
            self.check(deadline, false)?;
            fault.complete();
            received += 1;
        }
        Ok(received)
    }
}
