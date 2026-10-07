use super::*;
use dcentrald_common::bm1396_contract::Bm1396SensorSamplingMode;

/// A chip/sensor wire fixture driven by independent captured command words.
/// It does not call the production setup planner, query matcher or decoder.
pub(super) struct ThermalHardware {
    inner: Arc<Fake>,
    pub(super) asic_registers: Mutex<BTreeMap<(u8, u8, u8), u32>>,
    sensor_registers: Mutex<BTreeMap<(u8, u8, u8), u8>>,
    arm: Mutex<Option<(usize, Vec<u32>)>>,
    on_query: Mutex<Vec<u32>>,
    defect: AtomicU32,
}
impl ThermalHardware {
    pub(super) fn shared(inner: Arc<Fake>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            asic_registers: Mutex::new(BTreeMap::new()),
            sensor_registers: Mutex::new(BTreeMap::new()),
            arm: Mutex::new(None),
            on_query: Mutex::new(Vec::new()),
            defect: AtomicU32::new(0),
        })
    }

    fn arm(&self, words: Vec<u32>) {
        *self.arm.lock().unwrap() = Some((0, words));
    }
    fn samples(&self, chains: &[u8]) -> Vec<u32> {
        // Independent constructor replay constants, including T17e multiplication.
        let addresses = match self.inner.model {
            Model::S17e => [27, 35, 99, 107],
            Model::T17e => [51, 36, 195, 180],
        };
        chains
            .iter()
            .flat_map(|&chain| {
                addresses
                    .into_iter()
                    .flat_map(move |chip| raw(chain, chip, 0x44, 0x00700180))
            })
            .collect()
    }
}
fn raw(chain: u8, chip: u8, register: u8, value: u32) -> Vec<u32> {
    vec![
        u32::from_le_bytes([chain, register, chip, 2]),
        value,
        0x11,
        0x5555aaaa,
    ]
}
impl Hardware for ThermalHardware {
    fn model(&self) -> Model {
        self.inner.model()
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.inner.validate_owner()
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.inner.claim_transport()
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == 0x18 {
            let mut arm = self.arm.lock().unwrap();
            if self.inner.returns.lock().unwrap().is_empty() {
                if let Some((empty_reads, words)) = arm.as_mut() {
                    if *empty_reads == 2 {
                        self.inner.words(words);
                        *arm = None;
                    } else {
                        *empty_reads += 1;
                    }
                }
            }
        }
        self.inner.read(offset)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.inner.write(offset, value)?;
        if offset != BC || value & BUSY == 0 {
            return Ok(());
        }
        let (first, second) = {
            let regs = self.inner.regs.lock().unwrap();
            (regs[&0xc4].to_be_bytes(), regs[&0xc8])
        };
        let (chain, chip, reg) = (((value >> 16) & 15) as u8, first[2], first[3]);
        let defect = self.defect.load(Ordering::SeqCst);
        match first[0] {
            0x42 => {
                let mut result = *self
                    .asic_registers
                    .lock()
                    .unwrap()
                    .get(&(chain, chip, reg))
                    .unwrap_or(&0);
                if defect == 1 && reg == 0x18 && result & 0x4000 != 0 {
                    result ^= 1 << 20;
                }
                if reg == 0x1c && (result >> 8) as u8 == 0xfe {
                    if defect == 2 {
                        result |= 1 << 29;
                    }
                    if defect == 3 {
                        result ^= 1 << 8;
                    }
                }
                self.inner
                    .words(&std::mem::take(&mut *self.on_query.lock().unwrap()));
                self.inner.words(&raw(chain, chip, reg, result));
            }
            0x41 => {
                if defect == 6 && reg == 0x1c && second == 0x07980000 {
                    return Err("injected first automatic-start completion failure".into());
                }
                if !matches!(reg, 0x18 | 0x54 | 0x1c) {
                    return Err("fixture rejects unknown setup register".into());
                }
                let mut observed = second;
                if reg == 0x1c && second & 0x06000000 == 0 {
                    let sensor_reg = (second >> 8) as u8;
                    if second & 0x10000 != 0 {
                        self.sensor_registers
                            .lock()
                            .unwrap()
                            .insert((chain, chip, sensor_reg), second as u8);
                    } else {
                        let data = if sensor_reg == 0xfe {
                            if defect == 4 {
                                0x41
                            } else if chip & 1 == 0 {
                                0x1a
                            } else {
                                0x55
                            }
                        } else if defect == 5 && sensor_reg == 9 {
                            5
                        } else {
                            *self
                                .sensor_registers
                                .lock()
                                .unwrap()
                                .get(&(chain, chip, sensor_reg))
                                .unwrap_or(&0)
                        };
                        observed = (second & !255) | u32::from(data);
                    }
                }
                self.asic_registers
                    .lock()
                    .unwrap()
                    .insert((chain, chip, reg), observed);
            }
            _ => return Err("fixture rejects unknown setup command".into()),
        }
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        self.inner.read_dma(offset, out)
    }
    fn write_dma(&self, offset: usize, data: &[u8]) -> Result<(), String> {
        self.inner.write_dma(offset, data)
    }
    fn barrier(&self) -> Result<(), String> {
        self.inner.barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration)
    }
}
async fn thermal_owner(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<ThermalHardware>, Arc<Transport<ThermalHardware>>) {
    let mask = chains.iter().fold(0, |mask, chain| mask | (1 << chain));
    let hw = Arc::new(ThermalHardware {
        inner: Fake::new(model, mask),
        asic_registers: Mutex::new(BTreeMap::new()),
        sensor_registers: Mutex::new(BTreeMap::new()),
        arm: Mutex::new(None),
        on_query: Mutex::new(Vec::new()),
        defect: AtomicU32::new(0),
    });
    let addresses = match model {
        Model::S17e => [27, 35, 99, 107],
        Model::T17e => [51, 36, 195, 180],
    };
    for &chain in &chains {
        for chip in addresses {
            hw.asic_registers
                .lock()
                .unwrap()
                .insert((chain, chip, 0x18), 0x01230005);
        }
    }
    hw.inner.regs.lock().unwrap().insert(0x3c, 0x1a1a1a1a);
    let transport = Transport::observe(hw.clone(), model, chains).await.unwrap();
    (hw, transport)
}
async fn configured(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<ThermalHardware>, Arc<Transport<ThermalHardware>>) {
    let (hw, transport) = thermal_owner(model, chains).await;
    transport
        .configure_thermal(Bm1396SensorSamplingMode::Mode0, deadline())
        .await
        .unwrap();
    (hw, transport)
}

#[tokio::test]
async fn exact_source_topology_configures_each_model_and_retains_manufacturer_reads() {
    for model in [Model::S17e, Model::T17e] {
        let (hw, transport) = configured(model, vec![0, 2]).await;
        let config = transport.thermal_configuration().unwrap().unwrap();
        assert_eq!(config.manufacturers().len(), 8);
        assert!(config
            .manufacturers()
            .iter()
            .all(|(_, _, id)| matches!(id, 0x1a | 0x55)));
        assert_eq!(config.host_baud_register(), 0x1a1a1a1a);
        assert_eq!(config.raw_setup_records().len(), 72);
        assert!(transport.pending_returns().unwrap().is_empty());
        let addresses = match model {
            Model::S17e => [27, 35, 99, 107],
            Model::T17e => [51, 36, 195, 180],
        };
        for chain in [0, 2] {
            for chip in addresses {
                assert_eq!(
                    hw.asic_registers.lock().unwrap()[&(chain, chip, 0x18)],
                    0x01234035
                );
                assert_eq!(hw.sensor_registers.lock().unwrap()[&(chain, chip, 9)], 4);
                assert_eq!(hw.sensor_registers.lock().unwrap()[&(chain, chip, 0x11)], 0);
                assert_eq!(
                    hw.asic_registers.lock().unwrap()[&(chain, chip, 0x1c)],
                    0x07980000
                );
            }
        }
        let writes = hw.inner.writes();
        assert_eq!(
            writes
                .iter()
                .filter(|(offset, value)| *offset == 0xc8 && *value == 0x07980000)
                .count(),
            16
        );
        let count = writes.len();
        assert!(transport
            .configure_thermal(Bm1396SensorSamplingMode::Mode0, deadline())
            .await
            .is_err());
        assert_eq!(hw.inner.writes().len(), count);
    }
}

#[tokio::test]
async fn setup_mismatch_unknown_manufacturer_and_unresolved_bridge_never_start_automatic() {
    for defect in 1..=5 {
        let (hw, transport) = thermal_owner(Model::T17e, vec![0]).await;
        hw.defect.store(defect, Ordering::SeqCst);
        assert!(transport
            .configure_thermal(Bm1396SensorSamplingMode::Mode0, deadline())
            .await
            .is_err());
        assert!(transport.is_terminal());
        assert!(transport.thermal_configuration().unwrap().is_none());
        assert!(!transport.pending_returns().unwrap().is_empty());
        assert!(!hw
            .inner
            .writes()
            .iter()
            .any(|(offset, value)| *offset == 0xc8 && *value == 0x07980000));
        assert!(transport.asic_fault.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn incomplete_automatic_start_keeps_setup_records_and_running_engine_refuses_before_writes() {
    let (hw, transport) = thermal_owner(Model::S17e, vec![0]).await;
    hw.defect.store(6, Ordering::SeqCst);
    assert!(transport
        .configure_thermal(Bm1396SensorSamplingMode::Mode0, deadline())
        .await
        .is_err());
    assert!(transport.thermal_configuration().unwrap().is_none());
    assert_eq!(transport.pending_returns().unwrap().len(), 36);
    assert!(transport.is_terminal());
    let (hw, transport) = thermal_owner(Model::S17e, vec![0]).await;
    hw.inner.regs.lock().unwrap().insert(DHASH, RUN);
    assert!(transport
        .configure_thermal(Bm1396SensorSamplingMode::Mode0, deadline())
        .await
        .is_err());
    assert!(hw.inner.writes().is_empty());
}

#[tokio::test]
async fn fresh_full_position_samples_preserve_nonce_and_sealed_raw_custody() {
    for model in [Model::S17e, Model::T17e] {
        let (hw, transport) = configured(model, vec![0, 2]).await;
        transport.initialize_dma(deadline()).await.unwrap();
        transport
            .publish_job(packet(17), false, 400, deadline())
            .await
            .unwrap();
        hw.inner.dma.lock().unwrap()[64..68].copy_from_slice(&17u32.to_le_bytes());
        let words = [vec![0x80010080, 0, 0, 0x5555aaaa], hw.samples(&[0, 2])].concat();
        hw.arm(words);
        transport.sample_thermal(deadline()).await.unwrap();
        let snapshots = transport.pending_thermal_snapshots().unwrap();
        assert_eq!(snapshots[0].samples().len(), 8);
        assert_eq!(snapshots[0].raw_records().len(), 8);
        assert_eq!(snapshots[0].samples()[0].raw_channels(), [0x70, 0x80]);
        assert_eq!(
            snapshots[0].samples()[0].temperatures_c(Bm1396SensorSamplingMode::Mode0),
            [48, 50]
        );
        assert!(snapshots[0].is_fresh_at(snapshots[0].completed_at()));
        assert!(
            !snapshots[0].is_fresh_at(snapshots[0].completed_at() + Duration::from_millis(6960))
        );
        let pending = transport.pending_returns().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(pending[0].payload(), ReturnPayload::Nonce { .. }));
        transport
            .acknowledge_thermal_snapshot(&snapshots[0])
            .unwrap();
        assert!(transport
            .acknowledge_thermal_snapshot(&snapshots[0])
            .is_err());
    }
}

#[tokio::test]
async fn stale_fifo_and_missing_positions_cannot_fulfill_new_thermal_collection() {
    let (hw, transport) = configured(Model::S17e, vec![0]).await;
    hw.inner.words(&hw.samples(&[0]));
    hw.arm(raw(0, 27, 0x44, 0x00700180));
    assert!(transport.sample_thermal(deadline()).await.is_err());
    assert!(transport.is_terminal());
    assert!(transport.pending_thermal_snapshots().unwrap().is_empty());
    assert_eq!(transport.pending_returns().unwrap().len(), 5);
}

#[tokio::test]
async fn automatic_temperatures_coexist_with_addressed_query_and_strict_position_status() {
    let (hw, transport) = configured(Model::T17e, vec![0]).await;
    *hw.on_query.lock().unwrap() = hw.samples(&[0]);
    transport
        .query_register(0, 51, 0x18, deadline())
        .await
        .unwrap();
    assert_eq!(transport.pending_register_observations().unwrap().len(), 1);
    assert_eq!(transport.pending_returns().unwrap().len(), 4);
    for words in [
        raw(0, 17, 0x44, 0x00700180),
        raw(0, 51, 0x44, 0x80700180),
        raw(0x40, 51, 0x44, 0x00700180),
    ] {
        let (hw, transport) = configured(Model::T17e, vec![0]).await;
        hw.arm(words.clone());
        assert!(transport.sample_thermal(deadline()).await.is_err());
        assert_eq!(transport.pending_returns().unwrap()[0].words(), words);
        assert!(matches!(
            transport.pending_returns().unwrap()[0].payload(),
            ReturnPayload::Unclassified(_)
        ));
    }
}

#[tokio::test]
async fn cancelled_thermal_collection_retains_actual_worker_and_partial_fifo() {
    let (hw, transport) = configured(Model::S17e, vec![0]).await;
    let words = hw.samples(&[0]);
    hw.arm(words.clone());
    let block = ReadBlock::new(0x14);
    *hw.inner.block.lock().unwrap() = Some(block.clone());
    let copy = transport.clone();
    let task = tokio::spawn(async move { copy.sample_thermal(deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.is_err());
    assert!(transport
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    block.release();
    transport.drain(deadline()).await.unwrap();
    assert_eq!(transport.partial_return_words().unwrap(), words[..2]);
    assert!(transport.pending_thermal_snapshots().unwrap().is_empty());
}

#[tokio::test]
async fn thermal_snapshot_order_issuer_and_capacity_remain_bounded() {
    let (hw, transport) = configured(Model::S17e, vec![0]).await;
    let (_, other) = configured(Model::S17e, vec![0]).await;
    for _ in 0..16 {
        hw.arm(hw.samples(&[0]));
        transport.sample_thermal(deadline()).await.unwrap();
    }
    let snapshots = transport.pending_thermal_snapshots().unwrap();
    assert!(other.acknowledge_thermal_snapshot(&snapshots[0]).is_err());
    assert!(transport
        .acknowledge_thermal_snapshot(&snapshots[1])
        .is_err());
    hw.arm(hw.samples(&[0]));
    assert!(transport.sample_thermal(deadline()).await.is_err());
    assert_eq!(transport.pending_thermal_snapshots().unwrap().len(), 16);
    assert!(hw.arm.lock().unwrap().is_some());
}
