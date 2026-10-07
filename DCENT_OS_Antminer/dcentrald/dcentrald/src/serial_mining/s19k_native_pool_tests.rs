// Exact S19k77 cold program and ordered multi-UART custody. The execution
// fence below is explicitly an outer test fixture; no GPIO/reset/PSU/fan,
// factory EEPROM or process-independent watchdog acceptance is claimed.
fn s19k_test_multi(
    peers: &[NativePeer],
) -> (
    ValidatedS19kBm1366NativeMultiBackend,
    SerialExecutionTerminal,
) {
    let routes = dcentrald_hal::platform::amlogic::S19K_NATIVE_LOGICAL_CHAIN_ROUTES.to_vec();
    let (execution, terminal) = execution_fence_domain(SerialSessionToken {
        _run_scope: crate::runtime::safety_watchdog::WatchdogRunScope::new(),
        route: ExactSerialRoute::S19kNative,
        descriptor: SerialSessionDescriptor {
            board_target: "am3-s19k",
            identity: dcentrald_common::AsicProtocolIdentity::Bm1366,
            active_slot: 0,
            serial_device: routes[0].uart.into(),
            configured_chip_count: 77,
            industrial_pll_policy: None,
        },
    });
    assert_eq!(routes.len(), peers.len());
    let backends = routes
        .iter()
        .zip(peers)
        .map(|(route, peer)| {
            let backend = SerialChainBackend::open_native_linux_only(
                route.logical_chain,
                peer.path(),
                115_200,
            )
            .unwrap();
            let retained = ValidatedSerialBackend::new(backend, execution.clone());
            retained
                .commit("S19k PTY polling setup", || {
                    retained.backend.set_vtime(0).map_err(anyhow::Error::from)
                })
                .unwrap();
            retained
        })
        .collect();
    (
        ValidatedS19kBm1366NativeMultiBackend {
            paths: routes.iter().map(|route| route.uart).collect(),
            routes,
            backends,
            expected_chips_per_uart: 77,
        },
        terminal,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s19k_exact_typed77_init_work_nonce_independent_pool() {
    let spec = crate::model::lookup_model("s19k").unwrap();
    assert_eq!(
        (spec.model_key, spec.chip_id, spec.chips_per_chain_hint),
        ("s19k", Some(0x1366), Some(77))
    );
    let board = dcentrald_common::BoardDesc::lookup("am3-s19k").unwrap();
    assert_eq!(
        board.asic_protocol,
        dcentrald_common::AsicProtocolIdentity::Bm1366
    );
    let ready = Arc::new(AtomicU32::new(0));
    let peers: Vec<_> = (0..3)
        .map(|slot| {
            NativePeer::for_chip(
                slot,
                77,
                0x1366,
                PeerFault::None,
                ready.clone(),
                CancellationToken::new(),
            )
        })
        .collect();
    let (retained, terminal) = s19k_test_multi(&peers);
    let (retained, geometry) = SerialMiner::init_bm1366_chains(retained, 400).unwrap();
    assert_eq!(geometry.observed_chip_count.get(), 77);
    assert_eq!(geometry.applied_frequency_mhz, 400);
    assert_eq!(
        geometry.addresses,
        // Exact AML77 uses interval2; the public floor(256/77)=3 is refused.
        (0..77u8).map(|i| i * 2).collect::<Vec<_>>()
    );
    assert_eq!(ready.load(Ordering::Acquire), 7);
    for ((path, backend), (slot, expected_path)) in retained.iter().zip(ROUTES) {
        assert_eq!(path, expected_path);
        assert_eq!(backend.backend.chain_id(), slot);
        assert_eq!(backend.baud().unwrap(), 3_000_000);
    }
    for peer in &peers {
        // The exact S19k initializer restores its retained 100 ms read bound.
        peer.assert_read_timeout(1);
        assert_eq!(peer.assigned_addresses(), geometry.addresses);
        assert!(peer.work_frames().is_empty());
    }
    let transport = retained.into_work_transport().unwrap();
    independent_retained_transport_pool("am3-s19k", 77, transport, &peers, terminal).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn s19k_missing_assigned_population_refuses_typed77_work_transport() {
    let ready = Arc::new(AtomicU32::new(0));
    let peers: Vec<_> = (0..3)
        .map(|slot| {
            NativePeer::for_chip(
                slot,
                77,
                0x1366,
                if slot == 0 {
                    PeerFault::MissingAssignedChip
                } else {
                    PeerFault::None
                },
                ready.clone(),
                CancellationToken::new(),
            )
        })
        .collect();
    let (retained, terminal) = s19k_test_multi(&peers);
    let initialized = SerialMiner::init_bm1366_chains(retained, 400);
    let _fenced = terminal.revoke();
    assert!(initialized.is_err());
    assert_eq!(ready.load(Ordering::Acquire), 0);
    assert!(peers.iter().all(|peer| peer.work_frames().is_empty()));
}

#[test]
fn s19k_native_work_transport_refuses_reordered_routes() {
    let mut routes = dcentrald_hal::platform::amlogic::S19K_NATIVE_LOGICAL_CHAIN_ROUTES;
    routes.swap(0, 1);
    assert!(admit_s19k_native_multi_uart_shape(&routes, routes.len()).is_err());
    assert!(admit_s19k_native_multi_uart_shape(&routes[1..], 3).is_err());
}
