//! Real local TCP traffic through the production accept/parser/peer gate.
//! getifaddrs selects this machine's own address; no remote host is contacted.
use super::*;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::io::AsyncReadExt;
use tokio::net::TcpSocket;

fn local_nonloopback_ipv4() -> Ipv4Addr {
    let mut first: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes the output list; each non-null address is
    // checked for AF_INET before casting. The list is freed exactly once.
    unsafe {
        assert_eq!(libc::getifaddrs(&mut first), 0);
        let mut current = first;
        let mut found = None;
        while !current.is_null() {
            let entry = &*current;
            if !entry.ifa_addr.is_null()
                && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET
                && entry.ifa_flags & libc::IFF_UP as u32 != 0
            {
                let address = &*(entry.ifa_addr as *const libc::sockaddr_in);
                let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
                if !ip.is_loopback() && !ip.is_unspecified() {
                    found = Some(ip);
                    break;
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(first);
        found.expect("local non-loopback IPv4 required for actual remote-peer boundary test")
    }
}

fn state(writes: bool) -> Arc<AppState> {
    let mut miner = crate::MinerState::empty(dcentrald_api_types::OperatingMode::Standard);
    miner.pool.url = "stratum+tcp://pool.invalid:3333".into();
    miner.pool.worker = "bc1qsecretwalletmaterialthatmustbemasked.worker".into();
    let (_, rx) = tokio::sync::watch::channel(miner);
    crate::build_minimal_app_state(crate::MinimalAppStateInputs {
        api_config: crate::ApiConfig {
            cgminer_lan_writes: writes,
            ..Default::default()
        },
        pool_url: String::new(),
        pool_protocol: "sv1".into(),
        mode: dcentrald_api_types::OperatingMode::Standard,
        firmware_version: "fixture".into(),
        fan_pwm: 10,
        network_block: crate::NetworkBlockConfig::default(),
        profile_path: "fixture-profiles".into(),
        control_board_label: "Zynq am1-s9".into(),
        chip_type_label: "BM1387".into(),
        external_state_rx: Some(rx),
    })
}

async fn request(
    peer: Ipv4Addr,
    destination: SocketAddr,
    command: &str,
    parameter: Option<&str>,
) -> serde_json::Value {
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind(SocketAddrV4::new(peer, 0).into()).unwrap();
        let mut stream = socket.connect(destination).await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), peer);
        let raw = serde_json::json!({"command": command, "parameter": parameter}).to_string();
        stream.write_all(raw.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    })
    .await
    .expect("bounded local CGMiner response")
}

#[tokio::test]
async fn real_nonloopback_peer_reads_but_cannot_add_pool_set_voltage_or_batch_control() {
    let peer = local_nonloopback_ipv4();
    let app = state(false);
    let server = CgMinerServer::new(app.clone(), 0);
    let listener = server.bind().await.unwrap();
    assert!(
        listener.local_addr().unwrap().ip().is_unspecified(),
        "default must expose LAN monitoring"
    );
    let destination = SocketAddrV4::new(peer, listener.local_addr().unwrap().port()).into();
    let task = tokio::spawn(async move { server.serve(listener).await });
    let abort = task.abort_handle();
    struct Stop(tokio::task::AbortHandle);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _stop = Stop(abort);
    for (command, section) in [
        ("summary", "SUMMARY"),
        ("devs", "DEVS"),
        ("pools", "POOLS"),
        ("stats", "STATS"),
    ] {
        let reply = request(peer, destination, command, None).await;
        assert_eq!(reply["STATUS"][0]["STATUS"], "S", "{reply}");
        assert!(reply[section].is_array(), "{reply}");
        assert!(!reply
            .to_string()
            .contains("bc1qsecretwalletmaterialthatmustbemasked"));
    }
    for (command, parameter) in [
        (
            "addpool",
            Some("stratum+tcp://changed.invalid:3333,worker,secret"),
        ),
        ("voltageset", Some("session,0,12000")),
        ("summary+restart", None),
        ("summary+voltageset", None),
    ] {
        let reply = request(peer, destination, command, parameter).await;
        assert_eq!(reply["STATUS"][0]["STATUS"], "E", "{reply}");
        assert!(
            reply["STATUS"][0]["Msg"]
                .as_str()
                .unwrap()
                .contains("LAN writes disabled"),
            "{reply}"
        );
    }
    assert_eq!(
        app.state_rx.borrow().pool.url,
        "stratum+tcp://pool.invalid:3333"
    );

    // pyasic-shaped parsing of actual wire JSON: STATUS/VERSION arrays,
    // hardware Type separated from honest miner software/API version tokens.
    let response = request(peer, destination, "version", None).await;
    assert_eq!(response["STATUS"][0]["STATUS"], "S");
    let version = response["VERSION"].as_array().unwrap().first().unwrap();
    assert_eq!(
        version["Type"].as_str().unwrap().strip_prefix("Antminer "),
        Some("S9")
    );
    assert!(version["API"].as_str().unwrap().parse::<f32>().unwrap() >= 3.0);
    assert!(version["BMMiner"]
        .as_str()
        .unwrap()
        .starts_with("dcentrald/"));
    assert_eq!(version["Firmware"], "DCENTOS");
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn lan_write_opt_in_keeps_session_gate_and_loopback_opt_out_binds_locally() {
    let peer = local_nonloopback_ipv4();
    let server = CgMinerServer::new(state(true), 0);
    let listener = server.bind().await.unwrap();
    let destination = SocketAddrV4::new(peer, listener.local_addr().unwrap().port()).into();
    let task = tokio::spawn(async move { server.serve(listener).await });
    let reply = request(
        peer,
        destination,
        "voltageset",
        Some("invalid-session,0,12000"),
    )
    .await;
    task.abort();
    let _ = task.await;
    assert_eq!(reply["STATUS"][0]["STATUS"], "E");
    let message = reply["STATUS"][0]["Msg"].as_str().unwrap();
    assert!(!message.contains("LAN writes disabled"));
    assert!(message.to_ascii_lowercase().contains("session"), "{reply}");
    let mut app = state(false);
    Arc::get_mut(&mut app).unwrap().config.cgminer_bind_lan = false;
    let server = CgMinerServer::new(app, 0);
    assert!(server
        .bind()
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .ip()
        .is_loopback());
}
