//! Actual native ASIC initialization and WorkLedger, followed by a real V1
//! client and independent pool. Only the chain/reset wire endpoints are modeled.
//! This does not claim the surrounding PIC/PSU/fan/watchdog coordinator ran.
use super::*;
use cold_chain::{initialize_cold_chain, ColdChainIo};
use dcentrald_stratum::StratumV1Client;
use std::cell::Cell;
use std::collections::{HashMap, VecDeque};

#[path = "../tests/sim_support/share_oracle.rs"]
mod oracle;

struct Reset(Cell<u32>);
impl ChainResetIo for Reset {
    fn read_data(&self) -> u32 {
        self.0.get()
    }
    fn assert_all(&self) {
        self.0.set(self.0.get() & !7);
    }
    fn release_slot(&self, slot: u8) {
        self.0.set(self.0.get() | (1 << slot));
    }
}

struct Chain {
    chips: u8,
    stride: u8,
    divisor: u32,
    threshold: u32,
    ctrl: Vec<u32>,
    work_time: u32,
    assigned: Vec<u8>,
    commands: Vec<Vec<u8>>,
    registers: HashMap<(u8, u8), u32>,
    sensors: HashMap<(u8, u8), u8>,
    replies: VecDeque<[u8; 8]>,
    writes: Vec<[u32; 36]>,
    nonces: VecDeque<[u32; 2]>,
    bad_pll: bool,
}
impl Chain {
    fn new(chips: u8, stride: u8, sensors: &[SensorProfile]) -> Self {
        Self {
            chips,
            stride,
            divisor: 108,
            threshold: 1848,
            ctrl: vec![],
            work_time: 0,
            assigned: vec![],
            commands: vec![],
            registers: HashMap::new(),
            sensors: sensors
                .iter()
                .map(|sensor| ((sensor.chip_address, 0xfe), 0x55))
                .collect(),
            replies: VecDeque::new(),
            writes: vec![],
            nonces: VecDeque::new(),
            bad_pll: false,
        }
    }
    fn reply(&mut self, address: u8, register: u8, value: u32) {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&value.to_be_bytes());
        bytes[4] = address;
        bytes[5] = register;
        self.replies.push_back(bytes);
    }
}
impl ChainIo for Chain {
    fn divisor(&self) -> u32 {
        self.divisor
    }
    fn set_divisor(&mut self, divisor: u32) {
        self.divisor = divisor;
    }
    fn command(&mut self, bytes: &[u8]) {
        self.commands.push(bytes.to_vec());
        match bytes[0] {
            0x52 => {
                assert_eq!(bytes, [0x52, 5, 0, 0]);
                if self.divisor == 108 {
                    for _ in 0..self.chips {
                        self.reply(0, 0, 0x1397_1800);
                    }
                }
            }
            0x53 => {
                assert_eq!(bytes, [0x53, 5, 0, 0]);
                self.assigned.clear();
            }
            0x40 => {
                assert_eq!(bytes, [0x40, 5, self.assigned.len() as u8 * self.stride, 0]);
                self.assigned.push(bytes[2]);
            }
            0x41 | 0x51 => {
                assert_eq!(bytes.len(), 8);
                assert_eq!(bytes[1], 9);
                let register = bytes[3];
                let value = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                let addresses = if bytes[0] == 0x51 {
                    self.assigned.clone()
                } else {
                    vec![bytes[2]]
                };
                for address in addresses {
                    assert!(self.assigned.contains(&address));
                    let observed = if register == 0x1c {
                        let sensor_register = (value >> 8) as u8;
                        if value & 0x10000 != 0 {
                            self.sensors.insert(
                                (
                                    address,
                                    if sensor_register == 9 {
                                        3
                                    } else {
                                        sensor_register
                                    },
                                ),
                                value as u8,
                            );
                        }
                        (u32::from(sensor_register) << 8)
                            | u32::from(
                                *self.sensors.get(&(address, sensor_register)).unwrap_or(&0),
                            )
                    } else {
                        value
                    };
                    self.registers.insert((address, register), observed);
                }
            }
            0x42 => {
                assert_eq!(bytes.len(), 4);
                assert!(self.assigned.contains(&bytes[2]));
                let value = if bytes[3] == 0 {
                    0x1397_1800
                } else if self.bad_pll && bytes[3] == 8 {
                    0
                } else {
                    *self.registers.get(&(bytes[2], bytes[3])).unwrap_or(&0)
                };
                self.reply(bytes[2], bytes[3], value);
            }
            other => panic!("unexpected native ASIC command {other:#04x}"),
        }
    }
    fn register_reply(&mut self) -> Option<[u8; 8]> {
        self.replies.pop_front()
    }
    fn work_full(&self) -> bool {
        false
    }
    fn write_work(&mut self, words: &[u32; 36]) -> Result<()> {
        assert_eq!(self.ctrl, [0x1c]);
        assert_eq!(self.assigned.len(), usize::from(self.chips));
        self.writes.push(*words);
        if words != &[0; 36] {
            // This literal historical nonce is injected at the ASIC return
            // boundary. The independent pool still verifies the full header.
            self.nonces.push_back([2_083_236_893, words[0]]);
        }
        Ok(())
    }
    fn nonce(&mut self) -> Option<[u32; 2]> {
        self.nonces.pop_front()
    }
    fn flush_work(&mut self) {
        self.nonces.clear();
        self.replies.clear();
    }
}
impl ColdChainIo for Chain {
    fn reset_fifos(&mut self) {
        self.flush_work();
    }
    fn read_work_tx_threshold(&self) -> u32 {
        self.threshold
    }
    fn write_ctrl(&mut self, value: u32) {
        self.ctrl.push(value);
    }
    fn set_work_time(&mut self, value: u32) {
        self.work_time = value;
    }
}

async fn submit_initialized_chain(io: &mut Chain, worker: &str) {
    let (address, pool) = oracle::OraclePool::spawn(worker).await;
    let mut config = crate::config::DcentraldConfig::management_only_default();
    config.pool.url = format!("stratum+tcp://{address}");
    config.pool.worker = worker.into();
    config.donation.enabled = false;
    let stratum = crate::config::build_stratum_config_with_enumerated_chips(
        &config,
        crate::config::stratum_donation_config(&config.donation),
        false,
        false,
        Some(u32::from(io.chips)),
    );
    let (job_tx, mut job_rx) = tokio::sync::mpsc::channel(8);
    let (share_tx, share_rx) = tokio::sync::mpsc::channel(8);
    let (status_tx, _status_rx) = tokio::sync::mpsc::channel(32);
    let client = StratumV1Client::new(stratum, job_tx, share_rx, status_tx);
    // Scope the client future: any timeout or assertion drops the socket;
    // OraclePool independently aborts its listener task on Drop.
    let proof = async {
        let job = job_rx.recv().await.expect("actual loopback notification");
        let work = WorkBuilder::new().next_work(&job).unwrap();
        let known =
            oracle::header(&work.extranonce2, oracle::winning_nonce(&work.extranonce2)).unwrap();
        assert_eq!(work.midstates[0], known.midstate());
        assert_eq!(work.merkle_root, known.merkle_root);
        assert_eq!(work.share_target, oracle::target());
        let mut ledger = WorkLedger::new();
        assert!(ledger.dispatch(io, work).unwrap());
        let words = io.writes.last().unwrap();
        assert_eq!(&words[..4], &[0, 0x1d00ffff, 1231006505, 0x4a5e1e4b]);
        let midstate = known.midstate();
        let expected: Vec<u32> = midstate
            .chunks_exact(4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
            .rev()
            .collect();
        for chunk in words[4..].chunks_exact(8) {
            assert_eq!(chunk, expected);
        }
        let raw = io.nonce().expect("native FIFO return");
        assert!(ledger.validate([0, raw[1]], worker).unwrap().is_none());
        let share = ledger
            .validate(raw, worker)
            .unwrap()
            .expect("actual native qualified share");
        assert!(
            ledger.validate(raw, worker).unwrap().is_none(),
            "duplicate nonce"
        );
        share_tx.send(share).await.unwrap();
        while pool.accepted_shares() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        ledger.invalidate();
        io.flush_work();
        assert!(
            ledger.validate(raw, worker).unwrap().is_none(),
            "retired work"
        );
    };
    tokio::time::timeout(Duration::from_secs(3), async {
        let client = client.run_until_sv2_retry(Duration::from_secs(2));
        tokio::pin!(client);
        tokio::select! {
            _ = proof => (),
            _ = &mut client => panic!("client ended before native share was accepted"),
        }
    })
    .await
    .expect("native V1 proof timeout");
    assert_eq!(pool.accepted_shares(), 1);
}

async fn prove_board(target: &str, chips: u8, stride: u8) {
    let profile = S17RuntimeProfile::builtin(target).unwrap();
    assert_eq!(profile.frequency_mhz, 100);
    let reset = Reset(Cell::new(0xa5a5_0010));
    assert_chain_resets(&reset).unwrap();
    for mut chain_profile in profile.chains.clone() {
        let mut io = Chain::new(chips, stride, &chain_profile.sensors);
        initialize_cold_chain(
            &mut io,
            &reset,
            &profile,
            &mut chain_profile,
            1_887_436,
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            io.assigned,
            (0..chips).map(|chip| chip * stride).collect::<Vec<_>>()
        );
        assert_eq!(io.divisor, 108);
        assert_eq!(io.work_time, 1_887_436);
        assert_eq!(io.writes.len(), 84);
        assert!(io.writes.iter().all(|words| *words == [0; 36]));
        assert_eq!(
            io.commands
                .iter()
                .filter(|bytes| bytes[..4] == [0x51, 9, 0, 0x3c])
                .count(),
            337
        );
        for sensor in &chain_profile.sensors {
            assert_eq!(sensor.model, 2);
            assert_eq!(io.sensors[&(sensor.chip_address, 3)], 4);
            assert_eq!(io.sensors[&(sensor.chip_address, 0x11)], 0xf5);
        }
        submit_initialized_chain(&mut io, &format!("offline.{target}.{}", chain_profile.slot))
            .await;
    }
    assert_eq!(reset.read_data(), 0xa5a5_0017);
    assert_chain_resets(&reset).unwrap();
    assert_eq!(reset.read_data(), 0xa5a5_0010);
}

#[tokio::test]
async fn s17_native_s17p_three_chains_init_and_independent_pool() {
    prove_board("am2-s17p", 48, 5).await;
}
#[tokio::test]
async fn s17_native_s17plus_three_chains_init_and_independent_pool() {
    prove_board("am2-s17plus", 65, 3).await;
}
#[tokio::test]
async fn s17_native_t17_three_chains_init_and_independent_pool() {
    prove_board("am2-t17", 30, 8).await;
}
#[tokio::test]
async fn s17_native_t17plus_three_chains_init_and_independent_pool() {
    prove_board("am2-t17plus", 44, 5).await;
}

#[tokio::test]
async fn s17_native_cold_chain_refuses_fifo_and_pll_faults_before_work() {
    let profile = S17RuntimeProfile::builtin("am2-s17p").unwrap();
    for bad_fifo in [true, false] {
        let reset = Reset(Cell::new(0xa5a5_0010));
        let mut chain_profile = profile.chains[0].clone();
        let mut io = Chain::new(48, 5, &chain_profile.sensors);
        io.threshold = if bad_fifo { 2048 } else { 1848 };
        io.bad_pll = !bad_fifo;
        let error = initialize_cold_chain(
            &mut io,
            &reset,
            &profile,
            &mut chain_profile,
            1_887_436,
            &CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(if bad_fifo {
            "FIFO reserve"
        } else {
            "PLL readback"
        }));
        assert!(io.writes.is_empty());
        assert!(io.nonces.is_empty());
        assert_chain_resets(&reset).unwrap();
    }
}
