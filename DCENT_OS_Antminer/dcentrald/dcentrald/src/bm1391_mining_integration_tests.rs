//! Full native coordinator with modeled descriptors and an independent pool.
//! No runtime receipt, census, startup result or accepted share is synthesized.
use super::*;
use dcentrald_hal::platform::stock_bm1391::simulation::{Event, ExpectedWork, Fault, Rig};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};

#[path = "../tests/sim_support/share_oracle.rs"]
mod independent_pool;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static NEXT_TREE: AtomicUsize = AtomicUsize::new(0);
const LIFETIME: Duration = Duration::from_secs(300);
// The real PIC observation has its own90s bound before the unchanged180s
// startup window begins. Allow10s after those windows for the loopback share.
const SHARE_OBSERVATION: Duration = Duration::from_secs(280);

struct KernelTree(PathBuf);
impl KernelTree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "dcent-bm1391-tree-{}-{}",
            std::process::id(),
            NEXT_TREE.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        let root = Self(path);
        let one = 1_u32.to_be_bytes();
        for name in [
            "#address-cells",
            "#size-cells",
            "reserved-memory/#address-cells",
            "reserved-memory/#size-cells",
        ] {
            root.put(name, &one);
        }
        root.put("memory@0/reg", &[0, 0, 0, 0, 0x10, 0, 0, 0]);
        root.put("reserved-memory/ranges", &[]);
        root.put(
            "reserved-memory/bm1391-dma@f000000/reg",
            &[0x0f, 0, 0, 0, 1, 0, 0, 0],
        );
        root.put(
            "reserved-memory/bm1391-dma@f000000/compatible",
            b"dcent,bm1391-stock-fpga-dma\0",
        );
        root.put("reserved-memory/bm1391-dma@f000000/no-map", &[]);
        root
    }
    fn put(&self, name: &str, bytes: &[u8]) {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
}
impl Drop for KernelTree {
    fn drop(&mut self) {
        // Remove only this fixture's literal leaves and empty directories.
        // Never recurse across an unexpected mount or follow a directory link.
        for name in [
            "#address-cells",
            "#size-cells",
            "memory@0/reg",
            "reserved-memory/#address-cells",
            "reserved-memory/#size-cells",
            "reserved-memory/ranges",
            "reserved-memory/bm1391-dma@f000000/reg",
            "reserved-memory/bm1391-dma@f000000/compatible",
            "reserved-memory/bm1391-dma@f000000/no-map",
        ] {
            let _ = std::fs::remove_file(self.0.join(name));
        }
        for name in [
            "reserved-memory/bm1391-dma@f000000",
            "reserved-memory",
            "memory@0",
        ] {
            let _ = std::fs::remove_dir(self.0.join(name));
        }
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn proofs() -> Vec<ExpectedWork> {
    let genesis = independent_pool::header("00", independent_pool::winning_nonce("00")).unwrap();
    let block1 = hex::decode(concat!(
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        "982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e",
        "61bc6649ffff001d01e36299"
    ))
    .unwrap();
    let mut next = genesis;
    next.version = u32::from_le_bytes(block1[..4].try_into().unwrap());
    next.prev_hash = block1[4..36].try_into().unwrap();
    next.merkle_root = block1[36..68].try_into().unwrap();
    next.timestamp = u32::from_le_bytes(block1[68..72].try_into().unwrap());
    next.nbits = u32::from_le_bytes(block1[72..76].try_into().unwrap());
    next.nonce = u32::from_le_bytes(block1[76..80].try_into().unwrap());
    assert_eq!(next.to_wire().as_slice(), block1.as_slice());
    assert_eq!(
        hex::encode(next.display_hash()),
        "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
    );
    [genesis, next]
        .into_iter()
        .map(|header| {
            let bytes = header.to_wire();
            let state = header.midstate(); // Unchanged scalar F04 implementation, not production WorkBuilder.
            ExpectedWork {
                tail_and_midstate: std::array::from_fn(|i| {
                    if i < 3 {
                        u32::from_be_bytes(
                            bytes[64 + (2 - i) * 4..68 + (2 - i) * 4]
                                .try_into()
                                .unwrap(),
                        )
                    } else {
                        let index = 7 - (i - 3);
                        u32::from_be_bytes(state[index * 4..index * 4 + 4].try_into().unwrap())
                    }
                }),
                canonical_nonce: header.nonce,
            }
        })
        .collect()
}

fn configured(
    model: Model,
    address: std::net::SocketAddr,
) -> (DcentraldConfig, Bm1391DispatchAdmission) {
    let mut config: DcentraldConfig = toml::from_str(match model {
        Model::S15 => include_str!("../../configs/beta/am1-s15-baked-default.toml"),
        Model::T15 => include_str!("../../configs/beta/am1-t15-baked-default.toml"),
    })
    .unwrap();
    let identity = crate::daemon_lifecycle::PlatformIdentitySnapshot {
        declared_board_target: Some(model.board_target().into()),
        observed_board_target: None,
        board_desc: dcentrald_common::BoardDesc::lookup(model.board_target()),
        declared_platform_marker: Some("zynq-bm1391-stock".into()),
        declared_subtype: None,
        declared_psu_hardware_variant: None,
        observed_control_board: "modeled exact stock C501".into(),
    };
    assert!(
        crate::bm1391_admission::admit(&identity, &config).is_err(),
        "default must stay idle"
    );
    config.pool.url = format!("stratum+tcp://{address}");
    config.pool.worker = "bm1391.independent-spine".into();
    config.donation.enabled = false;
    config.mining.enabled = true;
    config.mining.version_rolling = false;
    config.api.http_bind = "127.0.0.1".into();
    config.api.http_port = 0;
    config.api.cgminer_port = 0;
    config.api.cgminer_bind_lan = false;
    config.api.websocket = false;
    config.validate().unwrap();
    let protocol = crate::configured_asic_protocol_identity(&config).unwrap();
    crate::admit_board_desc_runtime_dispatch(
        identity.board_desc,
        crate::RuntimeDispatchKind::Bm1391Native,
        true,
        protocol,
    )
    .unwrap()
    .require_asic_protocol(
        crate::RuntimeDispatchKind::Bm1391Native,
        model.board_target(),
        dcentrald_common::AsicProtocolIdentity::Bm1391,
    )
    .unwrap();
    let admission = crate::bm1391_admission::admit(&identity, &config).unwrap();
    assert_eq!(admission.model(), model);
    (config, admission)
}

async fn exact_coordinator(model: Model) {
    let _serial = SERIAL.lock().await;
    let tree = KernelTree::new();
    let expected = proofs();
    let rig = Arc::new(Rig::new(model, expected.clone(), Fault::None));
    let (address, pool) =
        independent_pool::OraclePool::spawn_with_timeout("bm1391.independent-spine", LIFETIME)
            .await;
    let (config, admission) = configured(model, address);
    let stop = CancellationToken::new();
    let observation = Arc::new(OnceLock::new());
    let (state_tx, state) = watch::channel(dcentrald_api::MinerState::empty(
        dcentrald_api::OperatingMode::Standard,
    ));
    let mut running = tokio::spawn(run_in_environment(
        config,
        stop.clone(),
        Some(state_tx),
        admission,
        RunEnvironment::Simulated {
            rig: rig.clone(),
            device_tree: tree.0.clone(),
            watchdog: observation.clone(),
        },
    ));
    let outcome: Result<()> = match tokio::time::timeout(SHARE_OBSERVATION, async {
        loop {
            if running.is_finished() {
                bail!("{model:?} coordinator ended before a validated pool share");
            }
            if pool.accepted_shares() > 0 && state.borrow().accepted > 0 {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    {
        Ok(result) => result,
        Err(error) => {
            let events = rig.events();
            let work: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Work(frame) => Some((frame[0], frame[1])),
                    _ => None,
                })
                .collect();
            let dac: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Write(0x30, value) if value & 0xffff_ff00 == 0x0520_0200 => {
                        Some(value & 0xff)
                    }
                    _ => None,
                })
                .collect();
            Err(anyhow!(
                "full stock startup/share deadline: {error}; events={}, work={}, last_work={:?}, DAC={dac:?}, pool_accepted={}, state_accepted={}, state_pool={:?}",
                events.len(), work.len(), work.last(), pool.accepted_shares(),
                state.borrow().accepted, state.borrow().pool.status,
            ))
        }
    };
    let fan_failure = outcome.is_ok() && model == Model::T15;
    if fan_failure {
        // Startup and an independently accepted share must precede the fault.
        // The real periodic health owner must observe it and own the cut.
        rig.inject(Fault::Fan);
    } else {
        stop.cancel();
    }
    let returned = tokio::time::timeout(Duration::from_secs(40), &mut running)
        .await
        .expect("real typed closeout must finish within its bound")
        .expect("coordinator task panicked");
    // Assertions follow checked cleanup even when the observation path failed.
    assert!(
        outcome.is_ok(),
        "{model:?}: {outcome:?}; runtime={returned:?}; events={:?}",
        rig.events().last()
    );
    assert!(
        returned.as_ref().is_err_and(is_terminal_safe_off),
        "{model:?}: {returned:?}"
    );
    if fan_failure {
        assert!(
            returned
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("an admitted fan stopped or disappeared"),
            "the real fan-health interruption must cause the typed closeout: {returned:?}"
        );
    }
    let watched = observation
        .get()
        .expect("real modeled watchdog worker was started");
    assert!(watched.kicks() > 0);
    assert_eq!(watched.closes(), 1);
    assert_eq!(watched.drops_armed(), 0);
    assert!(rig.source_high());
    assert!(pool.accepted_shares() > 0);
    assert!(state.borrow().accepted > 0);

    let events = rig.events();
    let first = |predicate: &dyn Fn(&Event) -> bool| events.iter().position(predicate).unwrap();
    let high = first(&|event| *event == Event::SourceHigh);
    let fan = first(&|event| matches!(event, Event::Write(0x84, 0x000f_0023)));
    let low = first(&|event| *event == Event::SourceLow);
    let reset = first(&|event| matches!(event, Event::Write(0x34, _)));
    let cold = first(&|event| matches!(event, Event::Write(0x110, 0x0f00_0000)));
    let probe = first(
        &|event| matches!(event, Event::Work(frame) if frame[0] & 0xfff0_ffff == 0x0180_0000),
    );
    assert!(high < fan && fan < low && low < reset && reset < cold && cold < probe);
    for chain in 0..3 {
        let commands: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::Command {
                    chain: actual,
                    bytes,
                } if *actual == chain => Some(bytes),
                _ => None,
            })
            .collect();
        assert!(commands
            .iter()
            .any(|frame| frame[0] == 0x52 && frame[3] == 0));
        assert!(commands
            .iter()
            .any(|frame| frame[0] == 0x52 && frame[3] == 0x18));
        assert!(commands
            .iter()
            .any(|frame| frame[0] == 0x40 && frame[2] == model.address_interval()));
        assert!(commands
            .iter()
            .any(|frame| frame[3] == 8 && frame[0] == 0x51));
        assert!(commands
            .iter()
            .any(|frame| frame[3] == 0x3c && frame[4..8] == [0x80, 0, 0x80, 4]));
        let positions = if model == Model::S15 {
            [18, 13, 54, 49]
        } else {
            [15, 11, 45, 41]
        };
        for position in positions {
            let address = (position - 1) * model.address_interval();
            assert!(
                commands.iter().any(|frame| frame[0] == 0x41
                    && frame[2] == address
                    && frame[3] == 0x1c
                    && frame[6] == 0),
                "every source-backed thermal endpoint must be sampled on chain{chain}"
            );
        }
        let dummy = events
            .iter()
            .filter(|event| {
                matches!(event, Event::Work(frame)
            if frame[0] == 0x0100_0080 | (u32::from(chain) << 16))
            })
            .count();
        assert_eq!(
            dummy, 69,
            "five warmup plus64 opening rounds on each exact chain"
        );
        for proof in &expected {
            assert!(events.iter().any(|event| matches!(event, Event::Work(frame)
                if (frame[0] >> 16) & 15 == u32::from(chain) && frame[2..] == proof.tail_and_midstate)));
        }
    }
    let last_low = events
        .iter()
        .rposition(|event| *event == Event::SourceLow)
        .unwrap();
    let final_high = events
        .iter()
        .enumerate()
        .skip(last_low + 1)
        .find(|(_, event)| **event == Event::SourceHigh)
        .unwrap()
        .0;
    assert!(!events[final_high + 1..]
        .iter()
        .any(|event| matches!(event, Event::SourceLow | Event::Work(_))));
    for request in pool.requests() {
        let request: serde_json::Value = serde_json::from_str(&request).unwrap();
        if request["method"] == "mining.submit" {
            assert!(independent_pool::accepts_submission(
                &request,
                "bm1391.independent-spine"
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s15_full_native_init_work_nonce_independent_pool_submit_and_closeout() {
    exact_coordinator(Model::S15).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t15_full_native_init_work_nonce_independent_pool_submit_and_fan_fault_cutoff() {
    exact_coordinator(Model::T15).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn modeled_transport_cannot_open_the_physical_gpio_boundary() {
    let tree = KernelTree::new();
    let rig = Rig::new(Model::S15, proofs(), Fault::None);
    let owner = rig.open_transport(Model::S15, &tree.0).unwrap();
    let error = PowerLine::open(owner, deadline(5)).await.err().unwrap();
    assert!(error.contains("cannot open a physical GPIO"), "{error}");
    assert!(rig.events().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_observed_eeprom_refuses_before_source_enable_or_work() {
    let _serial = SERIAL.lock().await;
    for model in [Model::S15, Model::T15] {
        let tree = KernelTree::new();
        let rig = Arc::new(Rig::new(model, proofs(), Fault::EepromCrc));
        let (config, admission) = configured(model, "127.0.0.1:9".parse().unwrap());
        let watched = Arc::new(OnceLock::new());
        let returned = tokio::time::timeout(
            Duration::from_secs(10),
            run_in_environment(
                config,
                CancellationToken::new(),
                None,
                admission,
                RunEnvironment::Simulated {
                    rig: rig.clone(),
                    device_tree: tree.0.clone(),
                    watchdog: watched.clone(),
                },
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(format!("{returned:#}").contains("EEPROM CRC"));
        assert!(watched.get().is_none());
        assert!(rig.source_high());
        assert!(!rig
            .events()
            .iter()
            .any(|event| matches!(event, Event::SourceLow | Event::Work(_))));
    }
}
