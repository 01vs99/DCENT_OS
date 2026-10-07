//! Bounded post-address BM1391 census on the retained transaction lane.
use super::*;
use dcentrald_common::bm1391_stock_return::Bm1391StockRegisterReturn;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Census {
    pub chain: u8,
    /// Sorted unique observed addresses, with complete source replies retained.
    /// The runtime must match these to its exact board population before work.
    pub replies: Vec<Bm1391StockRegisterReturn>,
}

pub(super) fn response_crc_valid(reply: Bm1391StockRegisterReturn) -> bool {
    // Original S15 41600/T15 41610 builds value BE, address, register, zero
    // and computes 51 bits. Register-type metadata is not mixed into byte6.
    let mut packet = [0; 7];
    packet[..4].copy_from_slice(&reply.value.to_be_bytes());
    packet[4] = reply.chip_address;
    packet[5] = reply.register;
    !reply.fpga_crc_error && dcentrald_common::s9se_vil::crc5_bits(&packet, 51) == reply.crc5
}

impl<R: Registers> Transport<R> {
    /// The caller performs this after address setup, with no work outstanding.
    /// Existing FIFO records are drained before one broadcast register0 request.
    /// This protocol has no read-request ID: temporal custody of the lane and
    /// the caller's cold-start epoch establish scope, not a fabricated wire tag.
    pub async fn census(
        self: &Arc<Self>,
        model: Model,
        chain: u8,
        deadline: Instant,
    ) -> Result<Census, String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.census_with_delay(model, chain, deadline, |milliseconds| {
                let until = Instant::now() + Duration::from_millis(milliseconds);
                loop {
                    owner.active(deadline)?;
                    let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                        return Ok(());
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            })
        })
        .await
        .map_err(|e| format!("BM1391 census worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn census_with_delay(
        &self,
        model: Model,
        chain: u8,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<Census, String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 census is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            let mut drained = 0;
            while self.read_return_locked(deadline)?.is_some() {
                drained += 1;
                if drained > 511 {
                    return Err("BM1391 census cannot drain active return traffic".into());
                }
            }
            self.publish_command_locked(chain, &Self::short_frame(0x52, 0, 0), deadline)?;
            let mut replies = BTreeMap::new();
            let mut empty_rounds = 0;
            let mut received = 0;
            while empty_rounds < 3 {
                // Stock census waits300ms before each queue observation and
                // another100ms on each of three consecutive empty observations.
                delay(300)?;
                self.active(deadline)?;
                let mut round_received = 0;
                while let Some(record) = self.read_return_locked(deadline)? {
                    received += 1;
                    round_received += 1;
                    if received > 511 {
                        return Err("BM1391 census exceeded one bounded response window".into());
                    }
                    let Bm1391StockFpgaReturn::Register(reply) = record else {
                        return Err("BM1391 census received outstanding mining work".into());
                    };
                    let interval = model.address_interval();
                    if reply.chain_slot != chain
                        || reply.register != 0
                        || reply.value >> 16 != 0x1391
                        || !response_crc_valid(reply)
                        || reply.chip_address % interval != 0
                        || u16::from(reply.chip_address)
                            >= (256 / u16::from(interval)) * u16::from(interval)
                    {
                        return Err("BM1391 census reply identity, address or CRC mismatch".into());
                    }
                    if let Some(previous) = replies.insert(reply.chip_address, reply) {
                        if previous != reply {
                            return Err(
                                "BM1391 census has conflicting replies for one address".into()
                            );
                        }
                    }
                }
                if round_received == 0 {
                    empty_rounds += 1;
                    delay(100)?;
                    self.active(deadline)?;
                } else {
                    empty_rounds = 0;
                }
            }
            if replies.is_empty() {
                return Err("BM1391 census observed no responding chips".into());
            }
            Ok(Census {
                chain,
                replies: replies.into_values().collect(),
            })
        })
    }
}

#[cfg(test)]
#[path = "stock_bm1391_census_tests.rs"]
mod tests;
