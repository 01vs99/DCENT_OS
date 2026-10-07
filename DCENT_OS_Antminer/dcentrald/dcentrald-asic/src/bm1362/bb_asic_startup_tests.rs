use super::*;
use dcentrald_hal::bb_management_runtime::simulated::Fixture;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

const RECIPE: StartupRecipe = StartupRecipe::Am2DerivedExperimental;
fn due() -> Instant {
    Instant::now() + Duration::from_secs(15)
}
fn run(f: impl std::future::Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
        .block_on(f);
}
fn fixture(ids: &[u8]) -> (BbController, Fixture, Vec<(File, File)>) {
    let mut backends = Vec::new();
    let mut files = Vec::new();
    for &id in ids {
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: initialized outputs for a fresh local PTY; optional pointers
        // are absent. No physical serial device is contacted.
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
        // SAFETY: each distinct fresh descriptor is adopted exactly once.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: the new slave descriptor has no other owning File.
        let slave = unsafe { File::from_raw_fd(slave) };
        backends.push(
            SerialChainBackend::open_native_linux_only(
                id,
                &format!("/proc/self/fd/{}", slave.as_raw_fd()),
                115200,
            )
            .unwrap(),
        );
        files.push((master, slave));
    }
    let (management, observed) = Fixture::new(false, false);
    (
        BbController::new(
            management,
            BbUartRuntime::new(BbSerialDispatchOwner::new(backends, 20_000)),
        ),
        observed,
        files,
    )
}
fn ready(file: &File, milliseconds: i32) -> bool {
    let mut fd = libc::pollfd {
        fd: file.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: single initialized pollfd of an owned local PTY, bounded wait.
    unsafe { libc::poll(&mut fd, 1, milliseconds) == 1 }
}
fn wire(frame: &[u8]) -> Vec<u8> {
    let mut out = vec![0x55, 0xaa];
    out.extend_from_slice(frame);
    out
}
fn page(name: &str) -> Vec<u8> {
    let json: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald-api-types/src/bb_factory_profile_vectors.json"
    )))
    .unwrap();
    let raw = json["fixtures"][name]["raw"].as_str().unwrap();
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect()
}
fn collection(name: &str, addresses: &[u8]) -> BbFactoryCollection {
    let raw = page(name);
    let records: Vec<_> = addresses
        .iter()
        .rev()
        .map(|&a| (a, raw.as_slice()))
        .collect();
    BbFactoryCollection::decode(addresses, &records).unwrap()
}
fn closed(value: &BbController) {
    let state = value.snapshot();
    assert!(state.management.stopped() && state.uart.dispatch.permanently_stopped);
    assert!(
        !state.uart.caller_pending
            && !state.uart.close_caller_pending
            && !state.management_close_caller_pending
    );
    assert!(state.management_close.unwrap().caller_joined_at.is_some());
    assert!(state.uart.close.unwrap().caller_joined_at.is_some());
}

fn initial_observation(startup: &StartupAttempt, sequence: u64) {
    let first = &startup.steps[0];
    assert_eq!(
        first.step,
        StartupStep::Control {
            chain: 0,
            control: ColdControl::ObserveEnumerationBaud
        }
    );
    assert!(first.completed_at.unwrap() < startup.deadline);
    assert_eq!(first.expected_uart_sequence, Some(sequence));
    let joined = first.uart.as_ref().unwrap();
    assert_eq!(joined.sequence, sequence);
    assert!(joined.joined_at.is_some() && joined.promoted_at.is_some());
    assert_eq!(joined.deadline, startup.deadline);
    let UartOutput::Controlled(cold) = joined.output.as_ref().unwrap() else {
        panic!("actual enumeration observation missing")
    };
    assert!(cold.writes.is_empty() && cold.delays.is_empty());
    assert!(cold.baseline.is_none() && cold.host_baud.is_none() && cold.assigned_scan.is_none());
    let actual = cold.enumeration_baud.as_ref().unwrap();
    assert_eq!(actual.deadline, startup.deadline);
    assert_eq!(actual.read_result, Some(0));
    assert!(actual.read_returned_at.unwrap() >= actual.read_started_at.unwrap());
    assert!(actual.caller_completed_at.unwrap() < startup.deadline);
    assert!(actual.failure.is_none());
    assert_eq!(
        (actual.cached_before, actual.cached_after),
        (Some(115200), Some(115200))
    );
    let settings = actual.settings.as_ref().unwrap();
    assert_eq!(
        (settings.input_speed, settings.output_speed),
        (115200, 115200)
    );
}

#[test]
fn held_factory_pages_preserve_selected_order_expectations_and_numeric_pll_distinction() {
    for (name, frequency) in [("held_42601", 545), ("held_42641", 505)] {
        let factory = collection(name, &[0x52, 0x50]);
        let plan = plan(RECIPE, &factory, &[2, 0]).unwrap();
        assert_eq!(plan.recipe, RECIPE);
        for (index, chain) in plan.chains.iter().enumerate() {
            assert_eq!(chain.uart_index, index);
            assert_eq!(chain.original_chain_id, [2, 0][index]);
            assert_eq!(chain.factory_page, factory.pages()[index]);
            assert_eq!(chain.factory_page.factory_frequency_mhz(), frequency);
            assert_eq!(
                chain.expected_addresses,
                (0..126).map(|n| n * 2).collect::<Vec<u8>>()
            );
            assert!(chain
                .pll_settings
                .iter()
                .all(|p| p.table_mhz == p.decoded_mhz && p.register != 0x40a8_0265));
            assert_eq!(
                chain.pll_settings.last().unwrap().register,
                crate::drivers::bm1362::pll_lookup(frequency).0
            );
        }
        assert_eq!(decode_pll_reg_to_freq(0x40a8_0265), Some(50));
        assert_eq!(crate::drivers::bm1362::pll_lookup(525), (0x50d2_0141, 525));
        for ids in [&[0, 2][..], &[2][..], &[2, 2][..], &[2, 0, 1][..]] {
            assert!(super::plan(RECIPE, &factory, ids).is_err());
        }
    }
    assert!(plan(RECIPE, &collection("held_42601", &[0x53]), &[3]).is_err());
    assert!(plan(
        RECIPE,
        &collection("held_42601", &[0x50, 0x51, 0x52, 0x53]),
        &[0, 1, 2, 3]
    )
    .is_err());
}

#[test]
fn experimental_tail_requires_native_baud_then_strict_assigned_scan_before_pll_writes() {
    let p = plan(RECIPE, &collection("held_42601", &[0x50]), &[0]).unwrap();
    assert_eq!(
        p.steps[0],
        StartupStep::Control {
            chain: 0,
            control: ColdControl::ObserveEnumerationBaud
        }
    );
    assert_eq!(
        p.steps[1],
        StartupStep::Control {
            chain: 0,
            control: ColdControl::ResetBaseline
        }
    );
    let baud = p
        .steps
        .iter()
        .position(|s| {
            matches!(
                s,
                StartupStep::Control {
                    control: ColdControl::HostBaud(NativeBbBaud::Mining),
                    ..
                }
            )
        })
        .unwrap();
    assert_eq!(p.steps[baud + 1], StartupStep::Delay { milliseconds: 500 });
    assert_eq!(
        p.steps[baud + 2],
        StartupStep::Control {
            chain: 0,
            control: ColdControl::AssignedScan {
                expected_addresses: (0..126).map(|n| n * 2).collect()
            }
        }
    );
    assert_eq!(
        p.steps[baud + 3],
        StartupStep::Control {
            chain: 0,
            control: ColdControl::Broadcast {
                register: ColdRegister::NonceRange,
                value: 0x1381
            }
        }
    );
    assert!(!p.steps[..baud].iter().any(|s| matches!(
        s,
        StartupStep::Control {
            control: ColdControl::Broadcast {
                register: ColdRegister::Pll0,
                ..
            },
            ..
        }
    )));
    let pll: Vec<_> = p.steps[baud + 4..]
        .iter()
        .filter_map(|s| match s {
            StartupStep::Control {
                control:
                    ColdControl::Broadcast {
                        register: ColdRegister::Pll0,
                        value,
                    },
                ..
            } => Some(*value),
            _ => None,
        })
        .collect();
    assert_eq!(
        pll,
        p.chains[0]
            .pll_settings
            .iter()
            .map(|p| p.register)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        p.steps.last().unwrap(),
        &StartupStep::Delay { milliseconds: 10 }
    );
}

#[test]
fn missing_or_misordered_original_inventory_refuses_before_any_uart_bytes() {
    run(async {
        for (ids, selected) in [
            (vec![0], None),
            (vec![1], Some(vec![0x50])),
            (vec![0, 1], Some(vec![0x51, 0x50])),
        ] {
            let (mut value, observed, files) = fixture(&ids);
            if let Some(selected) = selected {
                value.diagnose_held_until(&selected, due()).await.unwrap();
            }
            let before = observed.apw_opcodes();
            assert!(value
                .initialize_asics_held_until(RECIPE, due())
                .await
                .is_err());
            let state = value.snapshot();
            assert!(state.management.stopped() && state.uart.dispatch.permanently_stopped);
            let startup = state.startup.unwrap();
            assert_eq!(startup.original_chain_ids, ids);
            assert!(startup.steps.is_empty() && startup.commands_completed_at.is_none());
            assert!(startup.failure.is_some());
            assert_eq!(observed.apw_opcodes(), before);
            for (master, _) in &files {
                assert!(!ready(master, 0));
            }
            assert!(value.close_until(due()).await);
            closed(&value);
        }
    });
}

#[test]
fn prior_cold_operation_cannot_be_relabelled_as_an_unstarted_initialization() {
    run(async {
        let (mut value, observed, mut files) = fixture(&[0]);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        value
            .cold_control_until(0, ColdControl::SetChipAddress(4), due())
            .await
            .unwrap();
        let mut arrived = [0; 7];
        files[0].0.read_exact(&mut arrived).unwrap();
        // The latest request is now Receive, so looking only at latest cannot
        // detect the previous actual cold command. Original history must do it.
        let state = value.observe_held_until(due()).await.unwrap();
        assert!(state.uart.cold_control_started);
        assert!(matches!(
            state.uart.latest.unwrap().request,
            UartRequest::Receive
        ));
        let before = observed.apw_opcodes();
        assert!(value
            .initialize_asics_held_until(RECIPE, due())
            .await
            .is_err());
        assert!(value.snapshot().startup.unwrap().steps.is_empty());
        assert!(!ready(&files[0].0, 0));
        assert_eq!(observed.apw_opcodes(), before);
        assert!(value.close_until(due()).await);
        closed(&value);
    });
}

fn expected_pre_baud() -> Vec<u8> {
    use crate::bm1362::{
        build_broadcast_write_frame as b, build_chain_inactive_frame as inactive,
        build_get_address_frame as get, build_set_chip_address_frame as address,
        build_single_write_frame as c,
    };
    let mut out = wire(&get());
    for _ in 0..3 {
        out.extend(wire(&b(0xa4, 0x9000_ffff)));
    }
    out.extend(wire(&b(0xa8, 0x0007_0000)));
    for _ in 0..3 {
        out.extend(wire(&b(0x18, 0xff0f_c100)));
    }
    for _ in 0..3 {
        out.extend(wire(&inactive()));
    }
    for n in 0..126u8 {
        out.extend(wire(&address(n * 2)));
    }
    for n in 0..126u8 {
        out.extend(wire(&c(n * 2, 0xa8, 0x0007_01f0)));
        for _ in 0..3 {
            out.extend(wire(&c(n * 2, 0x18, 0xff0f_c100)));
        }
        for v in [0x8000_8540, 0x8000_8008, 0x8000_82aa] {
            out.extend(wire(&c(n * 2, 0x3c, v)));
        }
    }
    for (reg, val) in [(0x14, 0xff), (0x58, 0x0001_1111), (0x54, 3), (0x28, 0x3011)] {
        out.extend(wire(&b(reg, val)));
    }
    for _ in 0..3 {
        out.extend(wire(&b(0x18, 0x00c1_00b0)));
    }
    out
}

#[test]
fn actual_full_pre_baud_sequence_retains_1026_writes_then_refuses_unsupported_pty_drain() {
    run(async {
        let (mut value, observed, mut files) = fixture(&[0]);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let before = observed.apw_opcodes();
        let (mut master, _slave) = files.remove(0);
        let done = Arc::new(AtomicBool::new(false));
        let peer_done = done.clone();
        let peer = std::thread::spawn(move || {
            assert!(ready(&master, 3000));
            let mut query = [0; 7];
            master.read_exact(&mut query).unwrap();
            assert_eq!(
                query.as_slice(),
                wire(&crate::bm1362::build_get_address_frame())
            );
            master
                .write_all(&[0xaa, 0x55, 0x13, 0x62, 3, 0, 0, 0, 0x0d])
                .unwrap();
            let mut arrived = query.to_vec();
            let mut buf = [0; 2048];
            let end = Instant::now() + Duration::from_secs(15);
            while Instant::now() < end {
                if ready(&master, 10) {
                    let n = master.read(&mut buf).unwrap();
                    arrived.extend_from_slice(&buf[..n]);
                } else if peer_done.load(Ordering::SeqCst) {
                    break;
                }
            }
            (master, arrived)
        });
        let deadline = due();
        let result = value.initialize_asics_held_until(RECIPE, deadline).await;
        done.store(true, Ordering::SeqCst);
        let (_master, arrived) = peer.join().unwrap();
        assert!(result.is_err());
        assert_eq!(arrived, expected_pre_baud());
        let state = value.snapshot();
        let startup = state.startup.unwrap();
        assert_eq!(startup.deadline, deadline);
        assert_eq!(startup.controller_sequence, 2);
        initial_observation(&startup, 2);
        assert_eq!(startup.recipe, RECIPE);
        assert!(startup.original_management.diagnostic_complete());
        assert!(startup.commands_completed_at.is_none() && startup.failure.is_some());
        assert_eq!(
            state.last_complete.unwrap().operation,
            ControllerOperation::DiagnoseHeld
        );
        let last = startup.steps.last().unwrap();
        assert_eq!(
            last.step,
            StartupStep::Control {
                chain: 0,
                control: ColdControl::HostBaud(NativeBbBaud::Mining)
            }
        );
        assert!(last.completed_at.is_none() && last.failure.is_some());
        let UartOutput::Controlled(baud) = last.uart.as_ref().unwrap().output.as_ref().unwrap()
        else {
            panic!("actual baud report missing")
        };
        let transition = baud.host_baud.as_ref().unwrap();
        assert!(transition.drain.as_ref().unwrap().failure.is_some());
        assert!(transition.set_started_at.is_none() && transition.readback.is_none());
        let mut writes = 0;
        for (index, step) in startup.steps.iter().enumerate() {
            assert_eq!(step.index, index);
            if index + 1 == startup.steps.len() {
                break;
            }
            assert!(step.completed_at.unwrap() < deadline);
            match &step.step {
                StartupStep::Control { .. } => {
                    let call = step.uart.as_ref().unwrap();
                    assert_eq!(call.deadline, deadline);
                    assert_eq!(Some(call.sequence), step.expected_uart_sequence);
                    assert!(call.promoted_at.is_some() && call.joined_at.is_some());
                    let UartOutput::Controlled(actual) = call.output.as_ref().unwrap() else {
                        panic!("cold result missing")
                    };
                    writes += actual.writes.len();
                    assert!(actual
                        .writes
                        .iter()
                        .all(|w| w.attempt.accepted_prefix == w.requested));
                }
                StartupStep::Delay { milliseconds } => assert!(
                    step.completed_at.unwrap().duration_since(step.started_at)
                        >= Duration::from_millis(u64::from(*milliseconds))
                ),
            }
        }
        assert_eq!(writes, 1026);
        assert_eq!(observed.apw_opcodes(), before);
        let retained_start = startup.started_at;
        assert!(value
            .initialize_asics_held_until(RECIPE, due())
            .await
            .is_err());
        assert_eq!(value.snapshot().startup.unwrap().started_at, retained_start);
        assert!(value.close_until(due()).await);
        closed(&value);
        assert!(value
            .snapshot()
            .startup
            .unwrap()
            .commands_completed_at
            .is_none());
    });
}

#[test]
fn cancelled_actual_baseline_retains_original_task_and_late_report_without_step_completion() {
    run(async {
        let (mut value, observed, mut files) = fixture(&[0]);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let before = observed.apw_opcodes();
        let (mut master, _slave) = files.remove(0);
        let deadline = due();
        let mut pending = Box::pin(value.initialize_asics_held_until(RECIPE, deadline));
        tokio::select! {
            _=&mut pending => panic!("baseline should be waiting"),
            _=async { while !ready(&master,0) { tokio::time::sleep(Duration::from_millis(1)).await; } }=>{}
        }
        let mut query = [0; 7];
        master.read_exact(&mut query).unwrap();
        assert_eq!(
            query.as_slice(),
            wire(&crate::bm1362::build_get_address_frame())
        );
        drop(pending);
        let state = value.snapshot();
        assert!(state.uart.caller_pending);
        assert!(state.uart.dispatch.permanently_stopped && state.management.stopped());
        assert!(state.startup.unwrap().steps[1].completed_at.is_none());
        assert!(value.close_until(due()).await);
        closed(&value);
        let state = value.snapshot();
        let startup = state.startup.unwrap();
        assert_eq!(startup.steps.len(), 2);
        initial_observation(&startup, 2);
        assert!(startup.commands_completed_at.is_none());
        let step = &startup.steps[1];
        assert!(step.completed_at.is_none());
        let actual = step.uart.as_ref().unwrap();
        assert_eq!(actual.sequence, 3);
        assert_eq!(Some(actual.sequence), step.expected_uart_sequence);
        assert_eq!(actual.deadline, deadline);
        assert!(actual.joined_at.is_some() && actual.promoted_at.is_none());
        let UartOutput::Controlled(cold) = actual.output.as_ref().unwrap() else {
            panic!("actual cancelled result")
        };
        assert_eq!(cold.writes.len(), 1);
        assert_eq!(cold.writes[0].attempt.accepted_prefix, query);
        assert!(cold.failure.is_some() && cold.caller_completed_at.is_none());
        assert_eq!(observed.apw_opcodes(), before);
        assert!(!ready(&master, 0));
    });
}

#[test]
fn original_deadline_expiry_preserves_actual_baseline_and_never_starts_assignment() {
    run(async {
        let (mut value, observed, mut files) = fixture(&[0]);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let before = observed.apw_opcodes();
        let deadline = Instant::now() + Duration::from_millis(40);
        assert!(value
            .initialize_asics_held_until(RECIPE, deadline)
            .await
            .is_err());
        assert!(value.close_until(due()).await);
        closed(&value);
        let startup = value.snapshot().startup.unwrap();
        assert!(startup.commands_completed_at.is_none());
        assert_eq!(startup.steps.len(), 2);
        initial_observation(&startup, 2);
        let call = startup.steps[1].uart.as_ref().unwrap();
        assert_eq!(call.sequence, 3);
        assert_eq!(call.deadline, deadline);
        assert!(call.promoted_at.is_none() && call.joined_at.is_some());
        let mut query = [0; 7];
        files[0].0.read_exact(&mut query).unwrap();
        assert_eq!(
            query.as_slice(),
            wire(&crate::bm1362::build_get_address_frame())
        );
        assert!(!ready(&files[0].0, 0));
        assert_eq!(observed.apw_opcodes(), before);
    });
}

#[test]
fn joined_runtime_observation_can_precede_startup_without_erasing_original_cold_history() {
    run(async {
        let (mut value, observed, mut files) = fixture(&[0]);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let state = value.observe_held_until(due()).await.unwrap();
        assert_eq!(
            state.last_complete.unwrap().operation,
            ControllerOperation::ObserveHeld
        );
        assert_eq!(state.uart.latest.as_ref().unwrap().sequence, 2);
        assert!(matches!(
            state.uart.latest.as_ref().unwrap().request,
            UartRequest::Receive
        ));
        assert!(!state.uart.cold_control_started);
        assert!(state.management.last_pair_sequence().is_some());
        let before = observed.apw_opcodes();
        let (mut master, _slave) = files.remove(0);
        let deadline = due();
        let mut pending = Box::pin(value.initialize_asics_held_until(RECIPE, deadline));
        tokio::select! {
            _ = &mut pending => panic!("joined observation must permit actual baseline entry"),
            _ = async { while !ready(&master, 0) { tokio::time::sleep(Duration::from_millis(1)).await; } } => {}
        }
        let mut query = [0; 7];
        master.read_exact(&mut query).unwrap();
        assert_eq!(
            query.as_slice(),
            wire(&crate::bm1362::build_get_address_frame())
        );
        drop(pending);
        let state = value.snapshot();
        assert!(state.uart.cold_control_started && state.uart.caller_pending);
        assert_eq!(
            state.last_complete.unwrap().operation,
            ControllerOperation::ObserveHeld
        );
        let startup = state.startup.unwrap();
        assert_eq!(startup.controller_sequence, 3);
        initial_observation(&startup, 3);
        assert_eq!(startup.steps.len(), 2);
        assert_eq!(startup.steps[1].expected_uart_sequence, Some(4));
        assert!(startup.steps[1].completed_at.is_none());
        assert!(value.close_until(due()).await);
        closed(&value);
        let state = value.snapshot();
        assert!(state.uart.cold_control_started);
        let startup = state.startup.unwrap();
        let actual = startup.steps[1].uart.as_ref().unwrap();
        assert_eq!(actual.sequence, 4);
        assert!(actual.joined_at.is_some() && actual.promoted_at.is_none());
        assert!(startup.commands_completed_at.is_none());
        assert_eq!(observed.apw_opcodes(), before);
        assert!(!ready(&master, 0));
    });
}

#[test]
fn actual_initial_kernel_drift_refuses_before_baseline_and_preserves_pending_bytes_and_identity() {
    run(async {
        let (mut value, observed, mut files) = fixture(&[0]);
        value.diagnose_held_until(&[0x50], due()).await.unwrap();
        let before = observed.apw_opcodes();
        let (master, slave) = &mut files[0];
        // SAFETY: initialized standard termios output for this owned local PTY.
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fixture-only actual kernel drift on the retained slave, with
        // valid settings and immediate TCSETS, never a substituted observation.
        unsafe {
            assert_eq!(libc::tcgetattr(slave.as_raw_fd(), &mut termios), 0);
            assert_eq!(libc::cfsetispeed(&mut termios, libc::B57600), 0);
            assert_eq!(libc::cfsetospeed(&mut termios, libc::B57600), 0);
            assert_eq!(
                libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &termios),
                0
            );
        }
        master.write_all(&[0xaa, 0x55, 0x13, 0x62, 9]).unwrap();
        let deadline = due();
        assert!(value
            .initialize_asics_held_until(RECIPE, deadline)
            .await
            .is_err());
        assert!(!ready(master, 0));
        let state = value.snapshot();
        assert!(state.management.stopped() && state.uart.dispatch.permanently_stopped);
        assert!(state.uart.cold_control_started);
        let startup = state.startup.unwrap();
        assert_eq!(startup.controller_sequence, 2);
        assert_eq!(startup.original_chain_ids, [0]);
        assert_eq!(startup.steps.len(), 1);
        assert!(startup.commands_completed_at.is_none());
        let first = &startup.steps[0];
        assert_eq!(
            first.step,
            StartupStep::Control {
                chain: 0,
                control: ColdControl::ObserveEnumerationBaud
            }
        );
        assert_eq!(first.expected_uart_sequence, Some(2));
        assert!(first.completed_at.is_none());
        let call = first.uart.as_ref().unwrap();
        assert_eq!(call.sequence, 2);
        assert_eq!(call.deadline, deadline);
        assert!(call.joined_at.is_some() && call.promoted_at.is_none());
        let UartOutput::Controlled(cold) = call.output.as_ref().unwrap() else {
            panic!("actual refused observation")
        };
        assert!(cold.writes.is_empty() && cold.delays.is_empty() && cold.baseline.is_none());
        let actual = cold.enumeration_baud.as_ref().unwrap();
        assert_eq!(actual.read_result, Some(0));
        assert_eq!(
            (actual.cached_before, actual.cached_after),
            (Some(115200), Some(115200))
        );
        assert_eq!(actual.settings.as_ref().unwrap().input_speed, 57600);
        assert_eq!(actual.settings.as_ref().unwrap().output_speed, 57600);
        assert!(actual.failure.is_some() && actual.caller_completed_at.is_none());
        let mut pending = [0; 5];
        slave.read_exact(&mut pending).unwrap();
        assert_eq!(pending, [0xaa, 0x55, 0x13, 0x62, 9]);
        assert_eq!(observed.apw_opcodes(), before);
        assert!(value.close_until(due()).await);
        closed(&value);
        let retained = value.snapshot().startup.unwrap();
        assert_eq!(retained.steps[0].uart.as_ref().unwrap().sequence, 2);
        assert!(retained.commands_completed_at.is_none());
    });
}
