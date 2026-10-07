use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct EngineRegisters {
    values: Mutex<BTreeMap<u32, u32>>,
    writes: Mutex<Vec<(u32, u32)>>,
    fail_write: Mutex<Option<usize>>,
    fail_offset: Mutex<Option<u32>>,
    xor_read: Mutex<Option<(u32, u32)>>,
}
impl Registers for EngineRegisters {
    fn read(&self, offset: u32) -> Result<u32, String> {
        assert_ne!(
            offset, NONCE_CONTEXT_BASE,
            "original +110 setter proves no readback ABI"
        );
        let value = match offset {
            VERSION => 0xc501,
            PRESENCE => 7,
            _ => *self.values.lock().unwrap().get(&offset).unwrap_or(&0),
        };
        Ok(value
            ^ self
                .xor_read
                .lock()
                .unwrap()
                .filter(|(at, _)| *at == offset)
                .map(|(_, xor)| xor)
                .unwrap_or(0))
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut writes = self.writes.lock().unwrap();
        let index = writes.len();
        writes.push((offset, value));
        if *self.fail_write.lock().unwrap() == Some(index)
            || *self.fail_offset.lock().unwrap() == Some(offset)
        {
            return Err("injected engine store failure".into());
        }
        self.values.lock().unwrap().insert(offset, value);
        Ok(())
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(2)
}
fn owner() -> (Arc<EngineRegisters>, Arc<Transport<EngineRegisters>>) {
    let registers = Arc::new(EngineRegisters::default());
    let owner = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
    (registers, owner)
}
fn oracle() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap()
}

#[test]
fn terminal_engine_clear_matches_both_complete_original_shutdown_traces() {
    let mut cases = 0;
    for release in oracle()["releases"].as_array().unwrap() {
        for case in release["shutdown_cases"].as_array().unwrap() {
            let (registers, transport) = owner();
            registers.values.lock().unwrap().extend([
                (
                    COMMAND_CONTROL,
                    case["initial_command_control"].as_u64().unwrap() as u32,
                ),
                (DHASH, case["initial_dhash"].as_u64().unwrap() as u32),
            ]);
            let report = transport.terminal_stop_engine(deadline());
            assert!(report.controls_clear());
            assert!(transport.terminal());
            let original: Vec<_> = case["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|event| {
                    Some((
                        event["offset"].as_u64()? as u32,
                        event["value"].as_u64()? as u32,
                    ))
                })
                .collect();
            assert_eq!(*registers.writes.lock().unwrap(), original);
            assert!(transport
                .request_register(0, 0, false, 0, deadline())
                .is_err());
            cases += 1;
        }
    }
    assert_eq!(cases, 2);
}

#[test]
fn cold_preparation_clears_prior_run_before_reserved_addresses_and_never_enables_ddr_jobs() {
    for previous in [0, 0x40, 0x81e0, 0x55aa_ffff] {
        let (registers, transport) = owner();
        registers
            .values
            .lock()
            .unwrap()
            .extend([(DHASH, previous), (FIFO_CONTROL, 0x120)]);
        let observed = transport
            .prepare_cold_engine_at(dma::DMA_BASE, dma::DMA_BYTES, deadline())
            .unwrap();
        let writes = registers.writes.lock().unwrap().clone();
        assert_eq!(writes[0], (DHASH, previous & !0x40));
        assert_eq!(writes[1..3], [(0x110, 0x0f00_0000), (0x118, 0x0f20_0000)]);
        assert_eq!(writes[4], (0x1c, 0x1_0120));
        assert_eq!(writes.len(), 5);
        assert_eq!(observed.dhash & 0x8160, 0x8100);
        assert_eq!(observed.nonce_context_base_commanded, 0x0f00_0000);
        assert_eq!(observed.job_start_base, 0x0f20_0000);
        assert!(!transport.terminal());
    }
    let (registers, transport) = owner();
    assert!(transport
        .prepare_cold_engine_at(0x3f00_0000, dma::DMA_BYTES, deadline())
        .is_err());
    assert!(registers.writes.lock().unwrap().is_empty());
}

#[test]
fn every_partial_cold_control_failure_closes_and_terminal_stop_attempts_both_controls() {
    for failed in 0..5 {
        let (registers, transport) = owner();
        *registers.fail_write.lock().unwrap() = Some(failed);
        assert!(transport
            .prepare_cold_engine_at(dma::DMA_BASE, dma::DMA_BYTES, deadline())
            .is_err());
        assert!(transport.terminal());
        assert_eq!(registers.writes.lock().unwrap().len(), failed + 1);
    }
    let (registers, transport) = owner();
    registers.values.lock().unwrap().insert(DHASH, 0x81e0);
    *registers.fail_offset.lock().unwrap() = Some(COMMAND_CONTROL);
    let report = transport.terminal_stop_engine(deadline());
    assert!(!report.controls_clear());
    assert!(!report.command_bit22_clear);
    assert!(report.dhash_bit6_clear);
    assert_eq!(report.errors.len(), 1);
    assert_eq!(registers.writes.lock().unwrap().len(), 2);
    let (registers, transport) = owner();
    *registers.xor_read.lock().unwrap() = Some((JOB_START_BASE, 4));
    assert!(transport
        .prepare_cold_engine_at(dma::DMA_BASE, dma::DMA_BYTES, deadline())
        .is_err());
    assert!(transport.terminal());
    assert_eq!(registers.writes.lock().unwrap().len(), 3);
}
