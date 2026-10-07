use super::*;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

fn run<F: Future>(future: F) -> F::Output {
    struct Ready;
    impl Wake for Ready {
        fn wake(self: Arc<Self>) {}
    }
    let waker = Waker::from(Arc::new(Ready));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("recording backend must complete without external runtime"),
    }
}

fn factory() -> [u8; 256] {
    let mut bytes = [0; 256];
    bytes[1] = 180; // production9.6 V, bounded beta request9.5 V.
    bytes[121] = 1;
    bytes[122] = 2;
    bytes[123] = 31;
    bytes[124] = (-5i8) as u8;
    bytes[125] = 40;
    bytes[126] = (-4i8) as u8;
    bytes[248] = 4 << 3;
    let crc = s9se_eeprom::eeprom_payload_crc16(&bytes[..254]);
    bytes[254..].copy_from_slice(&crc.to_le_bytes());
    bytes
}

#[derive(Default)]
struct Recording {
    actions: Vec<Bm1393Action>,
    coverage_fault: bool,
    heartbeat_fault: bool,
    partial_off: bool,
    fail_temperature: bool,
    returns: Vec<[u32; 2]>,
    active: Vec<u8>,
    isolation_fault: bool,
    batch_reply: Option<Vec<bool>>,
    chain_fault: Option<(u8, &'static str)>,
}
impl Bm1393Io for Recording {
    async fn execute(&mut self, action: &Bm1393Action) -> Result<Bm1393Reply, String> {
        self.actions.push(action.clone());
        Ok(match action {
            Bm1393Action::StartCustody { chains } => {
                self.active = chains.clone();
                Bm1393Reply::Complete
            }
            Bm1393Action::ReadActiveChains => Bm1393Reply::ActiveChains(self.active.clone()),
            Bm1393Action::IsolateChain { chain } => {
                if self.isolation_fault {
                    return Err("injected incomplete chain cut".into());
                }
                self.active.retain(|c| c != chain);
                Bm1393Reply::Complete
            }
            Bm1393Action::WorkBatch { items } => {
                Bm1393Reply::Submitted(self.batch_reply.clone().unwrap_or_else(|| {
                    items
                        .iter()
                        .map(|(chain, _)| self.active.contains(chain))
                        .collect()
                }))
            }
            Bm1393Action::ReadProtectedEeprom { chain } => {
                Bm1393Reply::Eeprom(Box::new(if self.chain_fault == Some((*chain, "eeprom")) {
                    [0; 256]
                } else {
                    factory()
                }))
            }
            Bm1393Action::Pic { chain, command } => Bm1393Reply::Bytes(match command {
                Bm1393PicCommand::Version if self.chain_fault == Some((*chain, "version")) => {
                    vec![5, 0x17, 0x86, 0, 0xa2]
                }
                Bm1393PicCommand::Version => vec![5, 0x17, 1, 0, 0x1d],
                Bm1393PicCommand::Heartbeat
                    if self.heartbeat_fault || self.chain_fault == Some((*chain, "heartbeat")) =>
                {
                    return Err("injected PIC NACK (worker flushes before release)".into())
                }
                Bm1393PicCommand::Heartbeat => vec![6, 0x16, 1, 0, 0, 0x1d],
                Bm1393PicCommand::Enable(false)
                    if self.partial_off
                        && self
                            .actions
                            .iter()
                            .any(|a| matches!(a, Bm1393Action::StopWork)) =>
                {
                    vec![0x15]
                }
                Bm1393PicCommand::Enable(_) => vec![0x15, 1],
                Bm1393PicCommand::Voltage(_) => vec![0x10, 1],
            }),
            Bm1393Action::ReadChipCoverage { chain } => Bm1393Reply::Coverage(
                (0..if self.coverage_fault || self.chain_fault == Some((*chain, "coverage")) {
                    59
                } else {
                    60
                })
                    .map(|i| (i * 4, 0x1393))
                    .collect(),
            ),
            Bm1393Action::ConfigureTemperature { chain, .. }
                if self.fail_temperature || self.chain_fault == Some((*chain, "temperature")) =>
            {
                return Err("injected stale remote sensor".into())
            }
            Bm1393Action::ReadReturns { .. } => {
                Bm1393Reply::Returns(std::mem::take(&mut self.returns))
            }
            _ => Bm1393Reply::Complete,
        })
    }
}

#[test]
fn work_matches_two_independent_original_machine_code_encoders() {
    // Both files retain actual original-machine-code MMIO writes. Constants
    // below are the four captured vectors, independent of the Rust encoder.
    let s9se = include_str!("../../../../../");
    let s9k = include_str!("../../../../../");
    assert!(s9se.contains("4c05228fac5f682887c8da8b851793ae3759f72167a0bd443b60a7373197c82e"));
    assert!(s9k.contains("d09c482f9f5f7358f355dea427005eb9fc7db87efdd52e8dbe3f14e0f38118e7"));
    let data = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let midstate = std::array::from_fn(|i| 0x40 + i as u8);
    for (chain, id, header) in [
        (0, 1, 0x01800000),
        (1, 511, 0x01810000),
        (2, 0, 0x01820000),
        (15, 32674, 0x018f0000),
    ] {
        let expected = [
            header, id, 0x10111213, 0x14151617, 0x18191a1b, 0x40414243, 0x44454647, 0x48494a4b,
            0x4c4d4e4f, 0x50515253, 0x54555657, 0x58595a5b, 0x5c5d5e5f,
        ];
        assert_eq!(
            encode_bm1393_work(chain, id as u16, &data, &midstate).unwrap(),
            expected
        );
        for capture in [s9se, s9k] {
            let vector = capture
                .split("\"words\": [")
                .skip(1)
                .map(|part| {
                    part.split(']')
                        .next()
                        .unwrap()
                        .split(',')
                        .map(|number| number.trim().parse::<u32>().unwrap())
                        .collect::<Vec<_>>()
                })
                .find(|words| words[0] == header)
                .unwrap();
            assert_eq!(vector, expected);
        }
    }
    assert!(encode_bm1393_work(16, 1, &data, &midstate).is_err());
    assert!(encode_bm1393_work(0, 32768, &data, &midstate).is_err());
    assert_eq!(
        encode_bm1393_work(0, 32767, &data, &midstate).unwrap()[1],
        32767
    );
}

#[test]
fn factory_profile_uses_crc_geometry_and_stock_sensor_fallback() {
    let bytes = factory();
    let profile = Bm1393FactoryProfile::decode(&bytes).unwrap();
    assert_eq!(profile.minor(), 4);
    assert_eq!(profile.voltage_mv(), 9600);
    assert_eq!(
        profile.sites(),
        &[
            Bm1393TemperatureSite {
                chip_addr: 120,
                offset: -5
            },
            Bm1393TemperatureSite {
                chip_addr: 156,
                offset: -4
            }
        ]
    );
    assert!(profile.rail_code(9500).is_ok());
    assert!(profile.rail_code(10000).is_err());
    let mut corrupt = bytes;
    corrupt[1] ^= 1;
    assert!(Bm1393FactoryProfile::decode(&corrupt).is_err());
    let mut fallback = bytes;
    fallback[121] = 6;
    fallback[122] = 255;
    let crc = s9se_eeprom::eeprom_payload_crc16(&fallback[..254]);
    fallback[254..].copy_from_slice(&crc.to_le_bytes());
    let profile = Bm1393FactoryProfile::decode(&fallback).unwrap();
    assert_eq!(profile.preferred_sensor_device(), 0x9a);
    assert_eq!(
        profile.sites()[1],
        Bm1393TemperatureSite {
            chip_addr: 156,
            offset: -5
        }
    );
}

#[test]
fn native_start_reaches_work_and_exact_full_id_nonce_after_real_sequence() {
    let mut runtime = Bm1393Runtime::new(Recording::default(), vec![0, 2], 100, 9500).unwrap();
    run(runtime.start()).unwrap();
    assert_eq!(runtime.state(), Bm1393State::Running);
    let actions = &runtime.io().actions;
    let first_voltage = actions
        .iter()
        .position(|a| {
            matches!(
                a,
                Bm1393Action::Pic {
                    command: Bm1393PicCommand::Voltage(_),
                    ..
                }
            )
        })
        .unwrap();
    assert_eq!(
        actions[..first_voltage]
            .iter()
            .filter(|a| matches!(
                a,
                Bm1393Action::Pic {
                    command: Bm1393PicCommand::Heartbeat,
                    ..
                }
            ))
            .count(),
        10
    );
    for chain in [0, 2] {
        let assignment: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                Bm1393Action::Asic { chain: c, bytes }
                    if *c == chain && bytes.len() == 5 && bytes[0] == 0x40 =>
                {
                    Some(bytes[2])
                }
                _ => None,
            })
            .collect();
        assert_eq!(assignment, (0..64).map(|i| i * 4).collect::<Vec<_>>());
        let core_numbers: Vec<_> = actions
            .iter()
            .filter_map(|a| match a {
                Bm1393Action::Asic { chain: c, bytes }
                    if *c == chain && bytes.len() == 9 && bytes[3] == 0 =>
                {
                    Some(bytes)
                }
                _ => None,
            })
            .collect();
        assert_eq!(&core_numbers[0][4..8], &[0x13, 0x93, 0xd0, 0]);
        assert_eq!(&core_numbers[63][4..8], &[0x13, 0x93, 0xd0, 252]);
    }
    let first_core = actions.iter().position(|a| matches!(a, Bm1393Action::Asic { bytes, .. } if bytes.len() == 9 && bytes[3] == 0x3c)).unwrap();
    let bank_ids: Vec<_> = actions[first_core..]
        .iter()
        .filter_map(|a| match a {
            Bm1393Action::Asic { bytes, .. } if bytes.len() == 9 && bytes[3] == 0x3c => {
                Some(bytes[5])
            }
            _ => None,
        })
        .take(4)
        .collect();
    assert_eq!(bank_ids, vec![0, 52, 104, 156]);
    run(runtime.submit_work(2, 0x7f45, &[0x11; 12], &[0x22; 32])).unwrap();
    runtime.io_mut().returns = vec![
        [0xff45_0082, 0x7800_1207],
        [0xff45_0081, 123],
        [0x7800, 456],
    ];
    assert_eq!(
        run(runtime.poll_returns()).unwrap(),
        vec![S9SeFifoRecord::Nonce {
            chain: 2,
            work_id: 0x7f45,
            nonce3: 0x78001207
        }]
    );
    run(runtime.shutdown()).unwrap();
    assert_eq!(runtime.state(), Bm1393State::Terminal);
    assert!(run(runtime.submit_work(2, 1, &[0; 12], &[0; 32])).is_err());
}

#[test]
fn missing_chip_blocks_cores_and_always_cuts_all_selected_rails() {
    let mut runtime = Bm1393Runtime::new(
        Recording {
            coverage_fault: true,
            ..Recording::default()
        },
        vec![0, 1, 2],
        100,
        9500,
    )
    .unwrap();
    let failure = run(runtime.start()).unwrap_err();
    assert!(failure.detail.contains("coverage incomplete"));
    assert!(failure.shutdown_errors.is_empty());
    assert!(!runtime
        .io()
        .actions
        .iter()
        .any(|a| matches!(a, Bm1393Action::Work { .. })));
    let stop = runtime
        .io()
        .actions
        .iter()
        .position(|a| matches!(a, Bm1393Action::StopWork))
        .unwrap();
    let tail = &runtime.io().actions[stop..];
    for chain in [0, 1, 2] {
        assert!(tail.contains(&Bm1393Action::ChainReset {
            chain,
            asserted: true
        }));
        assert!(tail.contains(&Bm1393Action::Pic {
            chain,
            command: Bm1393PicCommand::Enable(false)
        }));
    }
    assert_eq!(tail.last(), Some(&Bm1393Action::StopCustody));
}

#[test]
fn heartbeat_failure_never_sets_voltage_and_partial_off_retains_watcher() {
    let mut runtime = Bm1393Runtime::new(
        Recording {
            heartbeat_fault: true,
            partial_off: true,
            ..Recording::default()
        },
        vec![0],
        100,
        9500,
    )
    .unwrap();
    let failure = run(runtime.start()).unwrap_err();
    assert!(failure.detail.contains("NACK"));
    assert!(!failure.shutdown_errors.is_empty());
    assert!(!runtime.io().actions.iter().any(|a| matches!(
        a,
        Bm1393Action::Pic {
            command: Bm1393PicCommand::Voltage(_) | Bm1393PicCommand::Enable(true),
            ..
        }
    )));
    assert!(!runtime.io().actions.contains(&Bm1393Action::StopCustody));
}

#[test]
fn stale_sensor_prevents_running_and_closes_out() {
    let mut runtime = Bm1393Runtime::new(
        Recording {
            fail_temperature: true,
            ..Recording::default()
        },
        vec![0],
        100,
        9500,
    )
    .unwrap();
    let failure = run(runtime.start()).unwrap_err();
    assert!(failure.detail.contains("stale remote sensor"));
    assert_eq!(runtime.state(), Bm1393State::Terminal);
    assert!(failure.shutdown_errors.is_empty());
}

#[test]
fn pic_dialect_requires_complete_crc_and_exact_ack() {
    assert_eq!(
        Bm1393PicCommand::Enable(false).wire().unwrap(),
        (vec![0x55, 0xaa, 5, 0x15, 0, 0, 0x1a], 2)
    );
    assert!(Bm1393PicCommand::Version
        .validate(&[5, 0x17, 1, 0, 0x1d])
        .is_ok());
    assert!(Bm1393PicCommand::Version
        .validate(&[5, 0x17, 0x86, 0, 0xa2])
        .is_err());
    assert!(Bm1393PicCommand::Heartbeat
        .validate(&[6, 0x16, 1, 0, 0, 0x1d])
        .is_ok());
    assert!(Bm1393PicCommand::Heartbeat
        .validate(&[6, 0x16, 1, 0, 0, 0x1c])
        .is_err());
    assert!(Bm1393PicCommand::Enable(false).validate(&[0x15]).is_err());
    assert!(Bm1393PicCommand::Enable(false)
        .validate(&[0x15, 1, 0])
        .is_err());
}

#[test]
fn runtime_chain_isolation_preserves_other_covered_chains_and_final_owned_cut() {
    let mut runtime = Bm1393Runtime::new(Recording::default(), vec![0, 1, 2], 400, 9500).unwrap();
    run(runtime.start()).unwrap();
    run(runtime.isolate_chain(1)).unwrap();
    assert_eq!(runtime.active_chains(), &[0, 2]);
    assert_eq!(runtime.state(), Bm1393State::Running);
    let items = [0, 2].map(|chain| {
        (
            chain,
            encode_bm1393_work(chain, 7, &[1; 12], &[2; 32]).unwrap(),
        )
    });
    assert_eq!(
        run(runtime.submit_batch(items.to_vec())).unwrap(),
        [true, true]
    );
    runtime.io_mut().returns = vec![[0x8007_0081, 1], [0x8007_0082, 2]];
    assert_eq!(
        run(runtime.poll_returns()).unwrap(),
        [S9SeFifoRecord::Nonce {
            chain: 2,
            work_id: 7,
            nonce3: 2
        }]
    );
    run(runtime.shutdown()).unwrap();
    let tail = runtime
        .io()
        .actions
        .iter()
        .rposition(|a| matches!(a, Bm1393Action::StopWork))
        .unwrap();
    for chain in [0, 1, 2] {
        assert!(runtime.io().actions[tail..].contains(&Bm1393Action::Pic {
            chain,
            command: Bm1393PicCommand::Enable(false)
        }));
    }
}

#[test]
fn one_bad_board_at_each_startup_proof_keeps_two_fully_covered_chains_running() {
    for phase in ["eeprom", "version", "heartbeat", "coverage", "temperature"] {
        let io = Recording {
            chain_fault: Some((1, phase)),
            ..Recording::default()
        };
        let mut runtime = Bm1393Runtime::new(io, vec![0, 1, 2], 400, 9500).unwrap();
        run(runtime.start()).unwrap();
        assert_eq!(runtime.active_chains(), &[0, 2], "{phase}");
        assert_eq!(runtime.coverage.len(), 2);
        let isolation = runtime
            .io()
            .actions
            .iter()
            .position(|a| matches!(a, Bm1393Action::IsolateChain { chain: 1 }))
            .unwrap();
        assert!(
            !runtime.io().actions[isolation + 1..]
                .iter()
                .any(|a| matches!(
                    a,
                    Bm1393Action::Work { chain: 1, .. }
                        | Bm1393Action::ChainReset {
                            chain: 1,
                            asserted: false
                        }
                        | Bm1393Action::Pic {
                            chain: 1,
                            command: Bm1393PicCommand::Voltage(_) | Bm1393PicCommand::Enable(true)
                        }
                )),
            "{phase}"
        );
        let items = [0, 2].map(|chain| {
            (
                chain,
                encode_bm1393_work(chain, 1, &[1; 12], &[2; 32]).unwrap(),
            )
        });
        assert_eq!(
            run(runtime.submit_batch(items.to_vec())).unwrap(),
            [true, true]
        );
        run(runtime.shutdown()).unwrap();
    }
}

#[test]
fn one_bad_board_with_unproved_startup_cut_still_stops_every_chain() {
    let io = Recording {
        chain_fault: Some((1, "coverage")),
        isolation_fault: true,
        ..Recording::default()
    };
    let mut runtime = Bm1393Runtime::new(io, vec![0, 1, 2], 400, 9500).unwrap();
    let failure = run(runtime.start()).unwrap_err();
    assert!(failure.detail.contains("isolation unproven"));
    assert_eq!(runtime.state(), Bm1393State::Terminal);
    assert!(runtime.io().actions.contains(&Bm1393Action::StopWork));
}

#[test]
fn unproven_isolation_last_chain_loss_and_population_resurrection_are_terminal() {
    for mode in 0..3 {
        let mut runtime = Bm1393Runtime::new(Recording::default(), vec![0, 1], 400, 9500).unwrap();
        run(runtime.start()).unwrap();
        match mode {
            0 => {
                runtime.io_mut().isolation_fault = true;
                assert!(run(runtime.isolate_chain(1)).is_err());
            }
            1 => {
                run(runtime.isolate_chain(1)).unwrap();
                assert!(run(runtime.isolate_chain(0)).is_err());
            }
            _ => {
                run(runtime.isolate_chain(1)).unwrap();
                runtime.io_mut().active.push(1);
                assert!(run(runtime.poll_returns()).is_err());
            }
        }
        assert_eq!(runtime.state(), Bm1393State::Terminal);
        assert!(runtime.io().actions.contains(&Bm1393Action::StopWork));
    }
}

#[test]
fn batch_reply_must_be_bounded_and_keep_each_chain_in_order() {
    for reply in [vec![true], vec![false, true]] {
        let mut runtime = Bm1393Runtime::new(Recording::default(), vec![0], 400, 9500).unwrap();
        run(runtime.start()).unwrap();
        runtime.io_mut().batch_reply = Some(reply);
        let work = encode_bm1393_work(0, 1, &[0; 12], &[0; 32]).unwrap();
        assert!(run(runtime.submit_batch(vec![(0, work), (0, work)])).is_err());
        assert_eq!(runtime.state(), Bm1393State::Terminal);
    }
}
