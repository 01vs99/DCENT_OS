// Included beneath serial_mining::tests to share its retained route/nonce fixtures.
use std::cell::Cell;
use std::sync::atomic::AtomicU32;

#[cfg(feature = "sim-hal")]
#[path = "../../tests/sim_support/share_oracle.rs"]
mod pool_oracle;
#[cfg(feature = "sim-hal")]
include!("modern_native_pool_tests.rs");
#[cfg(feature = "sim-hal")]
include!("am2_native_pool_tests.rs");
#[cfg(feature = "sim-hal")]
include!("s19k_native_pool_tests.rs");

const ROUTES: [(u8, &str); 3] = [(0, "/dev/ttyS3"), (1, "/dev/ttyS2"), (2, "/dev/ttyS1")];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerFault {
    None,
    MissingColdChip,
    MissingAssignedChip,
    CancelAtFirstTargetedWrite,
}

#[derive(Default)]
struct WireObservation {
    addresses: Vec<u8>,
    registers: Vec<(u8, u8, u8, u32)>,
    queries: usize,
    works: Vec<Vec<u8>>,
}

pub(crate) struct NativePeer {
    slave: File,
    path: String,
    wire: Arc<Mutex<WireObservation>>,
    stop: CancellationToken,
    thread: Option<std::thread::JoinHandle<()>>,
}

// A truncated production write must fail the peer within a bound, including
// during Drop. Polling once before read_exact would leave partial frames stuck.
fn read_peer_frame(
    master: &mut File,
    mut bytes: &mut [u8],
    stop: &CancellationToken,
) -> std::io::Result<bool> {
    let until = Instant::now() + Duration::from_secs(2);
    while !bytes.is_empty() {
        if stop.is_cancelled() {
            return Ok(false);
        }
        if Instant::now() >= until {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd and a finite per-read wait.
        let result = unsafe { libc::poll(&mut poll, 1, 50) };
        if result < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if result == 0 {
            continue;
        }
        let read = master.read(bytes)?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        bytes = &mut bytes[read..];
    }
    Ok(true)
}

impl NativePeer {
    fn new(
        slot: u8,
        count: u8,
        fault: PeerFault,
        ready: Arc<AtomicU32>,
        shutdown: CancellationToken,
    ) -> Self {
        Self::for_chip(slot, count, 0x1362, fault, ready, shutdown)
    }

    pub(crate) fn for_chip(
        slot: u8,
        count: u8,
        chip_id: u16,
        fault: PeerFault,
        ready: Arc<AtomicU32>,
        shutdown: CancellationToken,
    ) -> Self {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: openpty initializes both local descriptors, with no optional outputs.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: each newly returned fd is consumed exactly once by its own File.
        let mut master = unsafe { File::from_raw_fd(master) };
        // SAFETY: this is the distinct newly returned slave descriptor.
        let slave = unsafe { File::from_raw_fd(slave) };
        let path = format!("/proc/self/fd/{}", slave.as_raw_fd());
        let wire = Arc::new(Mutex::new(WireObservation::default()));
        let observation = wire.clone();
        let stop = CancellationToken::new();
        let peer_stop = stop.clone();
        let thread = std::thread::spawn(move || {
            while !peer_stop.is_cancelled() {
                let mut poll = libc::pollfd {
                    fd: master.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one initialized pollfd with a bounded cancellation wait.
                let result = unsafe { libc::poll(&mut poll, 1, 50) };
                assert!(result >= 0);
                if result == 0 {
                    continue;
                }
                let mut prefix = [0; 4];
                if !read_peer_frame(&mut master, &mut prefix, &peer_stop).unwrap() {
                    break;
                }
                assert_eq!(&prefix[..2], &[0x55, 0xaa]);
                if prefix[2] == 0x21 {
                    // Full-header BM1362 work is84 bytes before CRC; the frame
                    // length byte0x56 includes the silicon's CRC encoding.
                    let mut work = vec![0; 86];
                    work[..2].copy_from_slice(&prefix[2..]);
                    if !read_peer_frame(&mut master, &mut work[2..], &peer_stop).unwrap() {
                        break;
                    }
                    assert_eq!(ready.load(Ordering::Acquire), 0b111,
                        "work reached slot{slot} before all selected assigned populations completed");
                    assert_eq!(
                        &work[84..],
                        &dcentrald_hal::serial_chain::crc16_public(&work[..84]).to_be_bytes()
                    );
                    observation.lock().unwrap().works.push(work);
                    // Independent Bitcoin genesis nonce2083236893 and captured
                    // BM1362 reply layout, also used by the single-port oracle.
                    master
                        .write_all(&[0xaa, 0x55, 0x1d, 0xac, 0x2b, 0x7c, 0, 0, 0, 0, 0x90])
                        .unwrap();
                    continue;
                }
                let mut command = vec![0; prefix[3] as usize];
                assert!(command.len() >= 5);
                command[..2].copy_from_slice(&prefix[2..]);
                if !read_peer_frame(&mut master, &mut command[2..], &peer_stop).unwrap() {
                    break;
                }
                assert_eq!(
                    *command.last().unwrap(),
                    dcentrald_asic::protocol::crc5(&command[..command.len() - 1])
                );
                let mut observed = observation.lock().unwrap();
                match command[0] {
                    0x40 => observed.addresses.push(command[2]),
                    0x51 | 0x41 => {
                        assert_eq!(command.len(), 9);
                        observed.registers.push((
                            command[0],
                            command[2],
                            command[3],
                            u32::from_be_bytes(command[4..8].try_into().unwrap()),
                        ));
                        if fault == PeerFault::CancelAtFirstTargetedWrite && command[0] == 0x41 {
                            shutdown.cancel();
                        }
                    }
                    0x53 => assert_eq!(command[2..4], [0, 0]),
                    0x52 => {
                        observed.queries += 1;
                        let assigned = !observed.addresses.is_empty();
                        let mut addresses = if assigned {
                            observed.addresses.clone()
                        } else {
                            vec![0; usize::from(count)]
                        };
                        if (assigned && fault == PeerFault::MissingAssignedChip)
                            || (!assigned && fault == PeerFault::MissingColdChip)
                        {
                            addresses.pop();
                        }
                        let mut response = Vec::new();
                        for address in addresses {
                            response.extend_from_slice(&[0xaa, 0x55]);
                            if assigned {
                                response.extend_from_slice(&chip_address_body(chip_id, address));
                            } else if chip_id != 0x1362 {
                                response.extend_from_slice(&chip_address_body(chip_id, 0));
                            } else {
                                response.extend_from_slice(&[0x13, 0x62, 3, 0, 0, 0, 0x0d]);
                            }
                        }
                        master.write_all(&response).unwrap();
                        if assigned && fault != PeerFault::MissingAssignedChip {
                            ready.fetch_or(1 << slot, Ordering::AcqRel);
                        }
                    }
                    opcode => panic!("unexpected BM1362 AML command{opcode:02x}"),
                }
            }
        });
        Self {
            slave,
            path,
            wire,
            stop,
            thread: Some(thread),
        }
    }

    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) fn assigned_addresses(&self) -> Vec<u8> {
        self.wire.lock().unwrap().addresses.clone()
    }

    pub(crate) fn work_frames(&self) -> Vec<Vec<u8>> {
        self.wire.lock().unwrap().works.clone()
    }

    pub(crate) fn assert_polling_mode(&self) {
        self.assert_read_timeout(0);
    }

    pub(crate) fn assert_read_timeout(&self, deciseconds: u8) {
        // SAFETY: tcgetattr writes one initialized termios for a retained PTY fd.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_raw_fd(), &mut termios) },
            0
        );
        assert_eq!(termios.c_cc[libc::VMIN], 0);
        assert_eq!(
            termios.c_cc[libc::VTIME],
            deciseconds,
            "retained native owner changed its declared read timeout"
        );
    }
}

impl Drop for NativePeer {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            let result = thread.join();
            if !std::thread::panicking() {
                result.unwrap();
            }
        }
    }
}

fn exact_primary(
    target: &'static str,
    count: u8,
    peer: &NativePeer,
    shutdown: &CancellationToken,
) -> (
    ValidatedSerialBackend,
    ValidatedSerialAssignedGeometry,
    SerialExecutionTerminal,
) {
    use dcentrald_common::AsicProtocolIdentity;
    let cold = validate_native_cold_window(
        AsicProtocolIdentity::Bm1362,
        &vec![vec![0x13, 0x62, 3, 0, 0, 0, 0x0d]; usize::from(count)],
    )
    .unwrap();
    let admission = ValidatedSerialChainAdmission::bind_route(
        serial_route_admission(target, AsicProtocolIdentity::Bm1362),
        0,
        ROUTES[0].1,
        115_200,
        count,
        cold,
    )
    .unwrap();
    let (execution, terminal) =
        execution_fence_domain(SerialSessionToken::from_validated_for_test(&admission));
    let serial = ValidatedSerialBackend::new(
        SerialChainBackend::open(0, &peer.path, 115_200).unwrap(),
        execution,
    )
    .with_am2_energized_cancellation(shutdown.clone());
    let policy =
        IndustrialSerialPllPolicy::for_route(target, AsicProtocolIdentity::Bm1362).unwrap();
    let (serial, geometry) =
        SerialMiner::init_bm1362_aml_chain(serial, &peer.path, 115_200, count, 400, policy)
            .unwrap();
    (serial, geometry, terminal)
}

fn genesis_work() -> (WorkEntry, Vec<u8>) {
    let mut entry = sample_entry(1, 0);
    entry.prev_block_hash = [0; 32];
    entry.merkle_root = [
        0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f,
        0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e,
        0x5e, 0x4a,
    ];
    entry.ntime = 1231006505;
    entry.nbits = 0x1d00ffff;
    entry.share_target = dcentrald_stratum::work::difficulty_to_target(1.0);
    let work = serial_full_header_work(
        0,
        1,
        entry.nbits,
        entry.ntime,
        &entry.merkle_root,
        &entry.prev_block_hash,
    );
    (entry, work)
}

fn check_original_registers(wire: &WireObservation, count: u8) {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let expected: Vec<(u8, u8, u8, u32)> = oracle["runs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|run| run["chips"].as_u64() == Some(u64::from(count)))
        .flat_map(|run| run["writes"].as_array().unwrap())
        .map(|write| {
            (
                if write["target_mode"].as_u64() == Some(0) {
                    0x51
                } else {
                    0x41
                },
                write["address"].as_u64().unwrap() as u8,
                write["register"].as_u64().unwrap() as u8,
                u32::from_str_radix(write["bytes"].as_str().unwrap(), 16).unwrap(),
            )
        })
        .collect();
    let actual: Vec<_> = wire
        .registers
        .iter()
        .copied()
        .filter(|(_, _, register, _)| !matches!(*register, 0x70 | 0x08 | 0x14))
        .collect();
    assert_eq!(
        actual, expected,
        "actual UART stream differs from the held AArch64 serializer executions"
    );
}

#[test]
fn bm1362_aml_complete_three_uart_cold_init_work_rx_and_terminal_fence() {
    use dcentrald_common::AsicProtocolIdentity;
    for (target, count) in [("am3-s19jproa", 126u8), ("am3-s19jproplus", 120u8)] {
        let shutdown = CancellationToken::new();
        let ready = Arc::new(AtomicU32::new(0));
        let peers: Vec<_> = (0..3)
            .map(|slot| {
                NativePeer::new(
                    slot,
                    count,
                    PeerFault::None,
                    ready.clone(),
                    shutdown.clone(),
                )
            })
            .collect();
        let (primary, geometry, terminal) = exact_primary(target, count, &peers[0], &shutdown);
        let heartbeat_count = Cell::new(0);
        let transport = modern_native_population::initialize(
            primary,
            &geometry,
            &ROUTES,
            AsicProtocolIdentity::Bm1362,
            count,
            400,
            IndustrialSerialPllPolicy::for_route(target, AsicProtocolIdentity::Bm1362).unwrap(),
            9,
            &shutdown,
            None,
            || {
                heartbeat_count.set(heartbeat_count.get() + 1);
                Ok(())
            },
            |slot, path| {
                assert_eq!(path, ROUTES[usize::from(slot)].1);
                Ok(SerialChainBackend::open(
                    slot,
                    &peers[usize::from(slot)].path,
                    115_200,
                )?)
            },
        )
        .unwrap();
        assert_eq!(heartbeat_count.get(), 3);
        for (slot, peer) in peers.iter().enumerate() {
            peer.assert_polling_mode();
            let wire = peer.wire.lock().unwrap();
            assert_eq!(wire.queries, if slot == 0 { 2 } else { 3 });
            assert_eq!(
                wire.addresses,
                (0..count).map(|i| i * 2).collect::<Vec<_>>()
            );
            assert!(wire.works.is_empty());
            check_original_registers(&wire, count);
        }
        // No test-only set_nonblocking: exercise production's actual empty-RX
        // behavior, then require one independently validated nonce per route.
        assert!(transport.read_nonce_response().unwrap().is_none());
        let (entry, work) = genesis_work();
        let attempt = transport.send_work_with_receipt(&work);
        assert!(attempt.error.is_none());
        assert_eq!(attempt.receipt.paths.len(), 3);
        assert!(attempt.receipt.paths.iter().all(|path| path.committed));
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut paths = BTreeSet::new();
        while paths.len() < 3 {
            if let Some(body) = transport.read_nonce_response().unwrap() {
                let nonce = u32::from_le_bytes(body[..4].try_into().unwrap());
                assert_eq!(nonce, 2083236893);
                assert!(dcentrald_stratum::share_pipeline::validate_full_header(
                    &serial_build_header(&entry, 1, nonce),
                    &entry.share_target
                ));
                paths.insert(transport.last_rx_path().unwrap());
            }
            assert!(
                Instant::now() < deadline,
                "not every initialized physical UART delivered a known nonce"
            );
        }
        assert_eq!(paths, ROUTES.iter().map(|(_, path)| *path).collect());
        let _fenced = terminal.revoke();
        assert!(transport.send_work_with_receipt(&work).error.is_some());
        assert!(transport.read_nonce_response().is_err());
        for peer in &peers {
            let wire = peer.wire.lock().unwrap();
            assert_eq!(wire.works.len(), 1);
            assert_eq!(&wire.works[0][..84], work.as_slice());
        }
    }
}

#[test]
fn bm1362_aml_sibling_cold_assigned_and_cancellation_fail_without_work_capability() {
    use dcentrald_common::AsicProtocolIdentity;
    for fault in [
        PeerFault::MissingColdChip,
        PeerFault::MissingAssignedChip,
        PeerFault::CancelAtFirstTargetedWrite,
    ] {
        let shutdown = CancellationToken::new();
        let ready = Arc::new(AtomicU32::new(0));
        let peers: Vec<_> = (0..3)
            .map(|slot| {
                NativePeer::new(
                    slot,
                    126,
                    if slot == 1 { fault } else { PeerFault::None },
                    ready.clone(),
                    shutdown.clone(),
                )
            })
            .collect();
        let (primary, geometry, terminal) =
            exact_primary("am3-s19jproa", 126, &peers[0], &shutdown);
        let execution = primary.execution.clone();
        let opened = Cell::new(0);
        let result = modern_native_population::initialize(
            primary,
            &geometry,
            &ROUTES,
            AsicProtocolIdentity::Bm1362,
            126,
            400,
            IndustrialSerialPllPolicy::S19jProABm1362Native,
            9,
            &shutdown,
            None,
            || Ok(()),
            |slot, _| {
                opened.set(opened.get() + 1);
                Ok(SerialChainBackend::open(
                    slot,
                    &peers[usize::from(slot)].path,
                    115_200,
                )?)
            },
        );
        let error = result
            .err()
            .expect("incomplete/cancelled sibling must not produce a work transport");
        let detail = format!("{error:#}");
        match fault {
            PeerFault::MissingColdChip => {
                assert!(detail.contains("complete unassigned"), "{detail}")
            }
            PeerFault::MissingAssignedChip => assert!(
                detail.contains("post-assignment serial coverage"),
                "{detail}"
            ),
            PeerFault::CancelAtFirstTargetedWrite => assert!(shutdown.is_cancelled()),
            PeerFault::None => unreachable!(),
        }
        assert_eq!(opened.get(), 1);
        // The actual runtime error arm owns the physical cut and this terminal
        // fence. Here execute its serial half; this is not GPIO/rail evidence.
        let _fenced = terminal.revoke();
        assert!(execution
            .commit("rejected population cannot regain serial I/O", || Ok::<
                (),
                anyhow::Error,
            >(
                ()
            ))
            .is_err());
        assert_eq!(peers[2].wire.lock().unwrap().queries, 0);
        for peer in &peers {
            assert!(peer.wire.lock().unwrap().works.is_empty());
        }
    }
}

#[test]
fn bm1362_aml_final_heartbeat_failure_or_stop_keeps_population_unadmitted() {
    use dcentrald_common::AsicProtocolIdentity;
    for final_stop in [false, true] {
        let shutdown = CancellationToken::new();
        let ready = Arc::new(AtomicU32::new(0));
        let peers: Vec<_> = (0..3)
            .map(|slot| {
                NativePeer::new(slot, 120, PeerFault::None, ready.clone(), shutdown.clone())
            })
            .collect();
        let (primary, geometry, terminal) =
            exact_primary("am3-s19jproplus", 120, &peers[0], &shutdown);
        let ticks = Cell::new(0);
        let result = modern_native_population::initialize(
            primary,
            &geometry,
            &ROUTES,
            AsicProtocolIdentity::Bm1362,
            120,
            400,
            IndustrialSerialPllPolicy::S19jProPlusBm1362Native,
            9,
            &shutdown,
            None,
            || {
                ticks.set(ticks.get() + 1);
                if ticks.get() == 3 {
                    if final_stop {
                        shutdown.cancel();
                    } else {
                        anyhow::bail!("injected retained PSU heartbeat failure");
                    }
                }
                Ok(())
            },
            |slot, _| {
                Ok(SerialChainBackend::open(
                    slot,
                    &peers[usize::from(slot)].path,
                    115_200,
                )?)
            },
        );
        assert!(result.is_err());
        assert_eq!(ready.load(Ordering::Acquire), 0b111);
        assert_eq!(ticks.get(), 3);
        let _fenced = terminal.revoke();
        for peer in &peers {
            assert!(peer.wire.lock().unwrap().works.is_empty());
        }
    }
}
