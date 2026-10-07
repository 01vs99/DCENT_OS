//! Actual original worker/diagnostic fixtures; no ready or timestamp DTO input.
use super::*;

fn page(name: &str) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald-api-types/src/bb_factory_profile_vectors.json"
    )))
    .unwrap();
    let hex = value["fixtures"][name]["raw"].as_str().unwrap();
    (0..256)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

struct FactoryWire {
    original: Arc<Wire>,
    pages: Vec<(u8, Vec<u8>)>,
    acquired: Mutex<Vec<(u8, Vec<u8>)>>,
}

impl I2cSimBackend for FactoryWire {
    fn service_identity(&self) -> Option<usize> {
        self.original.service_identity()
    }
    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
        self.original.write(bus, addr, bytes)
    }
    fn read(&self, bus: u8, addr: u8, bytes: &mut [u8]) -> crate::Result<usize> {
        self.original.read(bus, addr, bytes)
    }
    fn write_read(&self, bus: u8, addr: u8, bytes: &[u8], out: &mut [u8]) -> crate::Result<()> {
        assert_eq!((bus, bytes, out.len()), (0, [0u8].as_slice(), 256));
        let raw = &self
            .pages
            .iter()
            .find(|(address, _)| *address == addr)
            .unwrap()
            .1;
        out.copy_from_slice(raw);
        self.acquired.lock().unwrap().push((addr, raw.clone()));
        Ok(())
    }
}

fn original(
    pages: Vec<(u8, Vec<u8>)>,
    fault: bus0::Fault,
) -> (BbManagementOwner, Rig, Arc<FactoryWire>) {
    let a = bus0::Backend::new(fault, None);
    let b = apw::Backend::new(0x76, 0x17, 0x68, None, None);
    let wire = Wire::new(RuntimeWire::new(a.clone()));
    let factory = Arc::new(FactoryWire {
        original: wire.clone(),
        pages,
        acquired: Mutex::new(Vec::new()),
    });
    let owner = BbManagementOwner::new(
        spawn_owned_sim_i2c_service(0, factory.clone(), (0x50..=0x57).collect()).unwrap(),
        spawn_owned_sim_i2c_service(1, b.clone(), (0x50..=0x57).collect()).unwrap(),
    );
    (owner, Rig { a, b, wire }, factory)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_one_two_three_page_native_collections_drive_all_selected_original_sweeps() {
    for (name, label) in [
        ("held_42601", "original_joined_exact_bhb42601_model96_one"),
        ("held_42641", "original_joined_exact_bhb42641_model96_one"),
    ] {
        for selected in [vec![0x52], vec![0x51, 0x50], vec![0x52, 0x50, 0x51]] {
            let pages = selected
                .iter()
                .map(|address| (*address, page(name)))
                .collect();
            let (mut owner, rig, factory) = original(pages, bus0::Fault::None);
            diagnose(&mut owner, &selected).await;
            owner.admit_native_optional_bridge_policy().unwrap();
            assert!(owner.admit_native_optional_bridge_policy().is_err());
            assert!(owner.admit_optional_bridge_self_fixture().is_err());
            for (index, address) in selected.iter().enumerate() {
                let prepared = owner
                    .prepare_selected_pic_optional_bridge(index, due())
                    .unwrap();
                let view = prepared.observation();
                tokio::task::spawn_blocking(move || prepared.run())
                    .await
                    .unwrap();
                let actual = view.snapshot();
                assert!(actual.native_profile_admitted);
                assert_eq!(actual.policy_source, label);
                assert_eq!(actual.factory_address, *address);
                assert_eq!(actual.native_slot, usize::from(address - 0x50));
                assert_eq!(actual.pic_address, 0x20 + address - 0x50);
                assert!(actual.first_failure.is_none(), "{actual:?}");
                assert!(actual.timely_receipt_at.is_some());
                assert!(actual.caller_finalized_at.is_some());
                assert!(actual.worker_finalized_at.is_some());
            }
            assert_eq!(
                factory.acquired.lock().unwrap().as_slice(),
                factory.pages.as_slice()
            );
            let observed = owner.diagnostics.snapshot();
            let collection = &observed
                .historical
                .as_ref()
                .unwrap()
                .bus0
                .selected_inventory
                .factory;
            for (actual, (address, expected)) in collection.pages().iter().zip(&factory.pages) {
                assert_eq!(actual.address(), *address);
                assert_eq!(actual.raw_page().as_slice(), expected);
            }
            assert_eq!(rig.wire.packets.lock().unwrap().len(), selected.len() * 4);
            finish(&mut owner).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_policy_requires_original_completed_diagnostics_and_never_auto_admits() {
    let (mut owner, rig, _) = original(vec![(0x50, page("held_42601"))], bus0::Fault::None);
    assert!(owner.admit_native_optional_bridge_policy().is_err());
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, due())
        .is_err());
    diagnose(&mut owner, &[0x50]).await;
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, due())
        .is_err());
    assert!(rig.wire.calls.lock().unwrap().is_empty());
    owner.admit_native_optional_bridge_policy().unwrap();
    assert!(owner.admit_native_optional_bridge_policy().is_err());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_foreign_mixed_crc_and_firmware_observations_cannot_mint_native_policy() {
    let scenarios = [
        (vec!["held_a126"], bus0::Fault::None),
        (vec!["unsupported_42621"], bus0::Fault::None),
        (vec!["unsupported_42699"], bus0::Fault::None),
        (vec!["held_42601", "held_42641"], bus0::Fault::None),
        (vec!["held_42641", "held_42601"], bus0::Fault::None),
        (vec!["identity_crc_mismatch"], bus0::Fault::None),
        (vec!["parameters_crc_mismatch"], bus0::Fault::None),
        (vec!["held_42601"], bus0::Fault::Firmware),
    ];
    for (names, fault) in scenarios {
        let selected: Vec<u8> = (0..names.len()).map(|index| 0x50 + index as u8).collect();
        let pages = selected
            .iter()
            .zip(names)
            .map(|(address, name)| (*address, page(name)))
            .collect();
        let (mut owner, rig, _) = original(pages, fault);
        let observed = owner.observe_pre_power_once(&selected, due()).await;
        assert!(observed.stopped_at.is_some());
        assert!(owner.admit_native_optional_bridge_policy().is_err());
        assert!(owner
            .prepare_selected_pic_optional_bridge(0, due())
            .is_err());
        assert!(rig.wire.calls.lock().unwrap().is_empty());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_original_diagnostic_deadline_cannot_be_refreshed_into_native_policy() {
    let (mut owner, rig, _) = original(vec![(0x50, page("held_42601"))], bus0::Fault::None);
    let deadline = Instant::now() + Duration::from_secs(4);
    let observed = owner.observe_pre_power_once(&[0x50], deadline).await;
    assert!(observed.stopped_at.is_none(), "{observed:?}");
    assert!(observed.diagnostics.historical.is_some());
    tokio::time::sleep_until(deadline.into()).await;
    let error = owner.admit_native_optional_bridge_policy().unwrap_err();
    assert!(error.contains("deadline"), "{error}");
    assert!(owner
        .prepare_selected_pic_optional_bridge(0, due())
        .is_err());
    assert!(rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_admission_then_terminal_before_actual_caller_never_emits_optional_work() {
    let (mut owner, rig, _) = original(vec![(0x50, page("held_42601"))], bus0::Fault::None);
    diagnose(&mut owner, &[0x50]).await;
    owner.admit_native_optional_bridge_policy().unwrap();
    let prepared = owner
        .prepare_selected_pic_optional_bridge(0, due())
        .unwrap();
    let view = prepared.observation();
    owner.cancel();
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    let actual = view.snapshot();
    assert!(actual.native_profile_admitted);
    assert!(actual.first_failure.is_some());
    assert!(actual.caller_error.is_some());
    assert!(actual.worker_started_at.is_none());
    assert!(actual.timely_receipt_at.is_none());
    assert!(owner.admit_native_optional_bridge_policy().is_err());
    assert!(rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn freshly_joined_replacement_owner_cannot_refresh_retained_original_native_attempt() {
    let (mut original_owner, original_rig, _) =
        original(vec![(0x50, page("held_42601"))], bus0::Fault::None);
    diagnose(&mut original_owner, &[0x50]).await;
    original_owner
        .admit_native_optional_bridge_policy()
        .unwrap();
    let prepared = original_owner
        .prepare_selected_pic_optional_bridge(0, due())
        .unwrap();
    let view = prepared.observation();
    original_owner.cancel();
    let (mut replacement, replacement_rig, _) =
        original(vec![(0x50, page("held_42601"))], bus0::Fault::None);
    diagnose(&mut replacement, &[0x50]).await;
    replacement.admit_native_optional_bridge_policy().unwrap();
    {
        let first = lock(&original_owner.state, &original_owner.handles);
        let second = lock(&replacement.state, &replacement.handles);
        let policy = first.pic_optional_bridge.policy.as_ref().unwrap();
        assert!(!policy.matches_owner(&replacement.state, &second));
        assert!(!Arc::ptr_eq(
            policy,
            second.pic_optional_bridge.policy.as_ref().unwrap()
        ));
    }
    tokio::task::spawn_blocking(move || prepared.run())
        .await
        .unwrap();
    assert!(view.snapshot().worker_started_at.is_none());
    assert!(view.snapshot().timely_receipt_at.is_none());
    assert!(original_rig.wire.calls.lock().unwrap().is_empty());
    assert!(replacement_rig.wire.calls.lock().unwrap().is_empty());
    finish(&mut original_owner).await;
    finish(&mut replacement).await;
}

// Descendants reuse original native factory/service fixtures without wider APIs.
#[path = "bb_management_owner_pic_optional_callers_tests.rs"]
mod retained;
