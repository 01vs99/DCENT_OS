//! Stock BM1391 management portal. EEPROM access is read-only by construction.
use super::*;

const GENERAL_IIC: u32 = 0x30;

impl<R: Registers> Transport<R> {
    /// Read the selected chain's complete EEPROM through the already-owned
    /// FPGA portal. The original encoder is S15 86aec / T15 86a0c, selector
    /// 50+chain, bus0, read and register-prefix bits set. No EEPROM write or
    /// generic management write operation is exposed here.
    pub async fn read_eeprom(
        self: &Arc<Self>,
        chain: u8,
        deadline: Instant,
    ) -> Result<[u8; 256], String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.read_eeprom_with_delay(chain, deadline, |milliseconds| {
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
        .map_err(|e| format!("BM1391 EEPROM worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn read_eeprom_with_delay(
        &self,
        chain: u8,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<[u8; 256], String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 EEPROM is outside the retained population".into());
        }
        let _lane = match self.lock_management_until(deadline) {
            Ok(lane) => lane,
            Err(error) => {
                self.latch_terminal();
                return Err(error);
            }
        };
        let mut unresolved = false;
        let result = (|| {
            let mut page = [0; 256];
            for (offset, byte) in page.iter_mut().enumerate() {
                self.active(deadline)?;
                // Read bit25 + prefix bit24 + device nibble A at20 + chain
                // at16 + byte offset at8. Payload is always zero for a read.
                unresolved = true;
                self.registers.write(
                    GENERAL_IIC,
                    0x03a0_0000 | (u32::from(chain) << 16) | ((offset as u32) << 8),
                )?;
                let mut completed = false;
                // Original executor sleeps5ms before each of at most101 polls.
                // Completion bit31 carries the returned byte in bits7..0.
                for _ in 0..101 {
                    delay(5)?;
                    self.active(deadline)?;
                    let word = self.registers.read(GENERAL_IIC)?;
                    if word & 0x8000_0000 != 0 {
                        *byte = word as u8;
                        completed = true;
                        unresolved = false;
                        break;
                    }
                }
                if !completed {
                    return Err("BM1391 EEPROM byte transaction timed out".into());
                }
            }
            Ok(page)
        })();
        if result.is_err() {
            if unresolved {
                self.management_fault.store(true, Ordering::SeqCst);
            }
            self.latch_terminal();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{deadline, sample_work, RecordingRegisters};
    use super::*;

    #[test]
    fn management_remains_serviceable_while_asic_startup_retains_its_lane() {
        let registers = Arc::new(RecordingRegisters::default());
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        let _asic = owner.lock_until(deadline()).unwrap();
        let page = owner
            .read_eeprom_with_delay(0, deadline(), |_| {
                assert!(owner.lane.try_lock().is_err());
                assert!(owner.management_lane.try_lock().is_err());
                Ok(())
            })
            .unwrap();
        assert_eq!(page, std::array::from_fn(|i| i as u8));
        assert_eq!(registers.state.lock().unwrap().writes.len(), 256);
    }

    #[test]
    fn terminal_barrier_waits_for_retained_management_transaction() {
        let registers = Arc::new(RecordingRegisters::default());
        let owner = Transport::new(registers, vec![0]).unwrap();
        let management = owner.lock_management_until(deadline()).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let worker_owner = owner.clone();
        let worker = std::thread::spawn(move || {
            let result = worker_owner.terminal_drain(deadline());
            sent.send(result).unwrap();
        });
        let until = deadline();
        while !owner.terminal() && Instant::now() < until {
            std::thread::yield_now();
        }
        assert!(owner.terminal());
        assert!(received.try_recv().is_err());
        drop(management);
        received
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
    }

    #[test]
    fn second_management_transaction_expires_without_interleaved_iic_commands() {
        let registers = Arc::new(RecordingRegisters::default());
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        let _management = owner.lock_management_until(deadline()).unwrap();
        assert!(owner
            .read_eeprom_with_delay(0, Instant::now() + Duration::from_millis(5), |_| Ok(()))
            .is_err());
        assert!(registers.state.lock().unwrap().writes.is_empty());
        assert!(owner.terminal());
    }

    #[test]
    fn actual_eeprom_reader_preserves_every_byte_and_never_emits_a_write_command() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../../"
        )).unwrap();
        let mut compared = 0;
        for chain in 0..3 {
            let registers = Arc::new(RecordingRegisters::default());
            let owner = Transport::new(registers.clone(), vec![chain]).unwrap();
            let mut polls = 0;
            let page = owner
                .read_eeprom_with_delay(chain, deadline(), |ms| {
                    assert_eq!(ms, 5);
                    polls += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(polls, 256);
            for (offset, byte) in page.iter().copied().enumerate() {
                assert_eq!(byte, offset as u8 ^ chain);
            }
            let state = registers.state.lock().unwrap();
            assert_eq!(state.writes.len(), 256);
            for (offset, &(register, word)) in state.writes.iter().enumerate() {
                assert_eq!(register, GENERAL_IIC);
                assert_eq!(word & 0xffff_00ff, 0x03a0_0000 | (u32::from(chain) << 16));
                assert_eq!((word >> 8) & 0xff, offset as u32);
            }
            for release in oracle["releases"].as_array().unwrap() {
                for vector in release["vectors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|v| v["chain"].as_u64() == Some(u64::from(chain)))
                {
                    let offset = vector["eeprom_offset"].as_u64().unwrap() as usize;
                    assert_eq!(
                        state.writes[offset],
                        (
                            vector["events"][0]["offset"].as_u64().unwrap() as u32,
                            vector["events"][0]["value"].as_u64().unwrap() as u32,
                        )
                    );
                    assert_eq!(page[offset], vector["response"].as_u64().unwrap() as u8);
                    assert_eq!(vector["events"][1]["delay_us"], 5000);
                    compared += 1;
                }
            }
        }
        assert_eq!(compared, 42);
    }

    #[test]
    fn eeprom_failure_or_incomplete_byte_stops_the_page_and_new_work() {
        for failure in [0, 1, 127, 255] {
            let registers = Arc::new(RecordingRegisters::default());
            registers.state.lock().unwrap().fail_at = Some(failure);
            let owner = Transport::new(registers.clone(), vec![0]).unwrap();
            assert!(owner
                .read_eeprom_with_delay(0, deadline(), |_| Ok(()))
                .is_err());
            assert!(owner.terminal());
            assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
            assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
        }
        let registers = Arc::new(RecordingRegisters {
            iic_stuck: true,
            ..Default::default()
        });
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        let mut polls = 0;
        assert!(owner
            .read_eeprom_with_delay(0, deadline(), |_| {
                polls += 1;
                Ok(())
            })
            .is_err());
        assert_eq!(polls, 101);
        assert_eq!(registers.state.lock().unwrap().writes.len(), 1);
        assert!(owner.terminal());
    }

    #[test]
    fn terminal_during_eeprom_completion_never_publishes_the_next_byte() {
        let registers = Arc::new(RecordingRegisters::default());
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(owner
            .read_eeprom_with_delay(0, deadline(), |_| {
                owner.latch_terminal();
                Ok(())
            })
            .is_err());
        assert_eq!(registers.state.lock().unwrap().writes.len(), 1);
        owner.terminal_drain(deadline()).unwrap();
    }
}
