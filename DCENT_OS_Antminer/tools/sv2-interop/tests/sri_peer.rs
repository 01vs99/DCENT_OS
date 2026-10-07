//! Independent SRI crypto, frame and message codecs exercise the production client.
//! No DCENT mock-pool feature, local server codec or deterministic crypto bypass.
use binary_sv2::{from_bytes, GetSize, Serialize, Sv2Option};
use common_messages_sv2::*;
use dcentrald_stratum::{types::*, v2::noise::NoiseSession, StratumV2Client};
use framing_sv2::{framing::Sv2Frame, header::Header};
use mining_sv2::*;
use noise_sv2::{NoiseEngine, Responder};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::{future::Future, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

const CHANNEL: u32 = 7;
const JOB: u32 = 42;
const NTIME: u32 = 1_783_000_000;
const VERSION: u32 = 0x2000_0000;

fn authority() -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[17; 32]).unwrap(),
    )
}

async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), f)
        .await
        .expect("SRI interop deadline")
}

struct ClientTask(tokio::task::JoinHandle<()>);
impl Drop for ClientTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Peer {
    socket: TcpStream,
    noise: NoiseEngine,
}
impl Peer {
    async fn accept(listener: &TcpListener) -> Self {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut act1 = [0; 64];
        socket.read_exact(&mut act1).await.unwrap();
        let (act2, noise) = Responder::new(authority(), 3600).step_1(act1).unwrap();
        // TCP does not preserve writes. Deliberately fragment the handshake.
        for part in act2.chunks(13) {
            socket.write_all(part).await.unwrap();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        Self { socket, noise }
    }

    async fn recv(&mut self, kind: u8, channel: bool) -> Vec<u8> {
        let mut header = vec![0; 22];
        self.socket.read_exact(&mut header).await.unwrap();
        self.noise.decrypt(&mut header).unwrap();
        let parsed = Header::from_bytes(&header).unwrap();
        assert_eq!(parsed.msg_type(), kind);
        assert_eq!(parsed.channel_msg(), channel);
        assert_eq!(parsed.ext_type_without_channel_msg(), 0);
        assert!(parsed.encrypted_len() <= 65_535, "bounded test peer");
        let mut payload = vec![0; parsed.encrypted_len()];
        self.socket.read_exact(&mut payload).await.unwrap();
        self.noise.decrypt(&mut payload).unwrap();
        payload
    }

    async fn send<T: Serialize + GetSize>(&mut self, message: T, kind: u8, channel: bool) {
        let frame: Sv2Frame<T, Vec<u8>> =
            Sv2Frame::from_message(message, kind, 0, channel).unwrap();
        let mut bytes = vec![0; frame.encoded_length()];
        frame.serialize(&mut bytes).unwrap();
        let mut header = bytes[..6].to_vec();
        let mut payload = bytes[6..].to_vec();
        self.noise.encrypt(&mut header).unwrap();
        self.noise.encrypt(&mut payload).unwrap();
        header.extend(payload);
        // Exercise incremental encrypted-header and payload receive states too.
        for part in header.chunks(11) {
            self.socket.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
    }

    async fn open(&mut self, extended: bool) {
        let mut bytes = self.recv(MESSAGE_TYPE_SETUP_CONNECTION, false).await;
        let setup: SetupConnection = from_bytes(&mut bytes).unwrap();
        assert_eq!(setup.protocol, Protocol::MiningProtocol);
        assert_eq!((setup.min_version, setup.max_version), (2, 2));
        self.send(
            SetupConnectionSuccess {
                used_version: 2,
                flags: setup.flags,
            },
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            false,
        )
        .await;
        if extended {
            let mut bytes = self
                .recv(MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, false)
                .await;
            let open: OpenExtendedMiningChannel = from_bytes(&mut bytes).unwrap();
            assert_eq!(open.nominal_hash_rate, 500_000_000_000.0);
            self.send(
                OpenExtendedMiningChannelSuccess {
                    request_id: open.request_id,
                    channel_id: CHANNEL,
                    target: (&[255; 32]).into(),
                    extranonce_size: 4,
                    extranonce_prefix: (&[0xaa, 0xbb][..]).try_into().unwrap(),
                    group_channel_id: 99,
                },
                MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
                false,
            )
            .await;
        } else {
            let mut bytes = self
                .recv(MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL, false)
                .await;
            let open: OpenStandardMiningChannel = from_bytes(&mut bytes).unwrap();
            assert_eq!(open.nominal_hash_rate, 500_000_000_000.0);
            self.send(
                OpenStandardMiningChannelSuccess {
                    request_id: open.request_id,
                    channel_id: CHANNEL,
                    target: (&[255; 32]).into(),
                    extranonce_prefix: (&[0xaa, 0xbb][..]).try_into().unwrap(),
                    group_channel_id: 99,
                },
                MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
                false,
            )
            .await;
        }
    }

    async fn future_job(&mut self, extended: bool, id: u32) {
        if extended {
            let (prefix, suffix) = coinbase_parts();
            self.send(
                NewExtendedMiningJob {
                    channel_id: CHANNEL,
                    job_id: id,
                    min_ntime: Sv2Option::new(None),
                    version: VERSION,
                    version_rolling_allowed: true,
                    merkle_path: vec![].try_into().unwrap(),
                    coinbase_tx_prefix: prefix.as_slice().try_into().unwrap(),
                    coinbase_tx_suffix: suffix.as_slice().try_into().unwrap(),
                },
                MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB,
                true,
            )
            .await;
        } else {
            self.send(
                NewMiningJob {
                    channel_id: CHANNEL,
                    job_id: id,
                    min_ntime: Sv2Option::new(None),
                    version: VERSION,
                    merkle_root: (&[0x55; 32]).into(),
                },
                MESSAGE_TYPE_NEW_MINING_JOB,
                true,
            )
            .await;
        }
    }

    async fn activate(&mut self, id: u32) {
        self.send(
            SetNewPrevHash {
                channel_id: CHANNEL,
                job_id: id,
                prev_hash: (&[0x33; 32]).into(),
                min_ntime: NTIME,
                nbits: 0x1d00ffff,
            },
            MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
            true,
        )
        .await;
    }
}

// A structurally valid coinbase with an 8-byte scriptSig: two fixed bytes,
// two pool-prefix bytes and four miner bytes; one OP_TRUE output.
fn coinbase_parts() -> (Vec<u8>, Vec<u8>) {
    let mut prefix = vec![1, 0, 0, 0, 1];
    prefix.extend([0; 32]);
    prefix.extend([255; 4]);
    prefix.extend([8, 1, 1]);
    let mut suffix = vec![255; 4];
    suffix.push(1);
    suffix.extend([0; 8]);
    suffix.extend([1, 0x51, 0, 0, 0, 0]);
    (prefix, suffix)
}

fn config(addr: std::net::SocketAddr, extended: bool) -> StratumConfig {
    let mut authority_payload = vec![1, 0];
    authority_payload.extend(authority().x_only_public_key().0.serialize());
    let key = bs58::encode(authority_payload).with_check().into_string();
    let url = format!("stratum2+tcp://{addr}/{key}");
    serde_json::from_value(serde_json::json!({
        "pool1": { "url": url, "sv2_url": url, "protocol": "sv2", "worker": "interop.worker", "password": "x" },
        "donation": { "enabled": false, "percent": 0.0, "pool_url": "", "worker": "", "password": "", "cycle_duration_s": 3600 },
        "version_rolling": extended, "version_rolling_mask": 0x1fffe000u32,
        "hash_on_disconnect": false, "nominal_hashrate_ghs": 500.0,
        "sv2_extended_channel": extended, "protocol": "sv2"
    })).unwrap()
}

fn share(job: &JobTemplate) -> ValidShare {
    ValidShare {
        work_generation: job.work_generation,
        worker_name: "interop.worker".into(),
        job_id: job.job_id.clone(),
        extranonce2: String::new(),
        ntime: format!("{:08x}", job.ntime),
        nonce: "12345678".into(),
        version_bits: None,
        version: job.version,
        achieved_difficulty: Some(1.0),
    }
}

async fn lifecycle(extended: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (job_tx, mut jobs) = mpsc::channel(32);
    let (shares, share_rx) = mpsc::channel(8);
    let (status_tx, mut statuses) = mpsc::channel(256);
    let client = StratumV2Client::new(
        config(listener.local_addr().unwrap(), extended),
        500.0,
        job_tx,
        share_rx,
        status_tx,
    );
    let _client = ClientTask(tokio::spawn(client.run()));
    let mut peer = Peer::accept(&listener).await;
    peer.open(extended).await;
    peer.future_job(extended, JOB).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), jobs.recv())
            .await
            .is_err(),
        "future work must remain parked"
    );
    peer.activate(JOB).await;
    let job = loop {
        let job = jobs.recv().await.unwrap();
        if !job.is_flush_only() {
            break job;
        }
    };
    assert_eq!(job.job_id, JOB.to_string());
    assert_eq!(job.ntime, NTIME);
    assert_eq!(job.version, VERSION);
    if extended {
        assert_eq!(job.extranonce1, [0xaa, 0xbb]);
        assert_eq!(job.extranonce2_size, 0); // header-only mining: client fixes one extranonce
        let (mut coinbase, suffix) = coinbase_parts();
        coinbase.extend([0xaa, 0xbb, 0, 0, 0, 0]);
        coinbase.extend(suffix);
        let expected: [u8; 32] = Sha256::digest(Sha256::digest(coinbase)).into();
        assert_eq!(job.merkle_root, expected);
    } else {
        assert_eq!(job.merkle_root, [0x55; 32]);
    }
    for accepted in [true, false] {
        shares.send(share(&job)).await.unwrap();
        let sequence = if extended {
            let mut bytes = peer.recv(MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, true).await;
            let submit: SubmitSharesExtended = from_bytes(&mut bytes).unwrap();
            assert_eq!(
                (
                    submit.channel_id,
                    submit.job_id,
                    submit.nonce,
                    submit.ntime,
                    submit.version
                ),
                (CHANNEL, JOB, 0x12345678, NTIME, VERSION)
            );
            assert_eq!(submit.extranonce.as_ref(), [0, 0, 0, 0]);
            submit.sequence_number
        } else {
            let mut bytes = peer.recv(MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, true).await;
            let submit: SubmitSharesStandard = from_bytes(&mut bytes).unwrap();
            assert_eq!(
                (
                    submit.channel_id,
                    submit.job_id,
                    submit.nonce,
                    submit.ntime,
                    submit.version
                ),
                (CHANNEL, JOB, 0x12345678, NTIME, VERSION)
            );
            submit.sequence_number
        };
        if accepted {
            peer.send(
                SubmitSharesSuccess {
                    channel_id: CHANNEL,
                    last_sequence_number: sequence,
                    new_submits_accepted_count: 1,
                    new_shares_sum: 1,
                },
                MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
                true,
            )
            .await;
        } else {
            peer.send(
                SubmitSharesError {
                    channel_id: CHANNEL,
                    sequence_number: sequence,
                    error_code: b"low-difficulty-share".as_slice().try_into().unwrap(),
                },
                MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
                true,
            )
            .await;
        }
        loop {
            match statuses.recv().await.unwrap() {
                StratumStatus::ShareAccepted { .. } => {
                    assert!(accepted);
                    break;
                }
                StratumStatus::ShareRejected { .. } => {
                    assert!(!accepted);
                    break;
                }
                _ => {}
            }
        }
    }
    peer.future_job(extended, JOB + 1).await;
    peer.activate(JOB + 1).await;
    let next = loop {
        let job = jobs.recv().await.unwrap();
        if !job.is_flush_only() {
            break job;
        }
    };
    assert_eq!(next.job_id, (JOB + 1).to_string());
    assert!(next.clean_jobs);
}

#[tokio::test]
async fn sri_standard_channel_lifecycle() {
    bounded(lifecycle(false)).await;
}
#[tokio::test]
async fn sri_extended_channel_lifecycle() {
    bounded(lifecycle(true)).await;
}

#[test]
fn sri_certificate_and_transport_authentication() {
    for wrong_authority in [false, true] {
        let mut client = NoiseSession::new();
        client.pool_authority_key = Some(if wrong_authority {
            Keypair::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&[18; 32]).unwrap(),
            )
            .x_only_public_key()
            .0
            .serialize()
        } else {
            authority().x_only_public_key().0.serialize()
        });
        let act1 = client.initiator_handshake_start([33; 64]).unwrap();
        let (act2, mut peer) = Responder::new(authority(), 3600)
            .step_1(act1.try_into().unwrap())
            .unwrap();
        let result = client.initiator_handshake_finish(&act2);
        if wrong_authority {
            assert!(result.is_err());
            continue;
        }
        result.unwrap();
        let mut from_client = client.encrypt(b"independent client-to-SRI").unwrap();
        peer.decrypt(&mut from_client).unwrap();
        assert_eq!(from_client, b"independent client-to-SRI");
        let mut from_peer = b"independent SRI-to-client".to_vec();
        peer.encrypt(&mut from_peer).unwrap();
        assert_eq!(
            client.decrypt(&from_peer).unwrap(),
            b"independent SRI-to-client"
        );
        assert!(
            client.decrypt(&from_peer).is_err(),
            "replayed ciphertext must fail authentication"
        );
    }
}

#[test]
fn sri_expired_certificate_is_rejected() {
    let mut client = NoiseSession::new();
    client.pool_authority_key = Some(authority().x_only_public_key().0.serialize());
    let act1 = client.initiator_handshake_start([34; 64]).unwrap();
    let (act2, _) = Responder::new(authority(), 60)
        .step_1_with_now_rng(
            act1.try_into().unwrap(),
            1_000,
            &mut secp256k1::rand::thread_rng(),
        )
        .unwrap();
    let error = client.initiator_handshake_finish(&act2).unwrap_err();
    assert!(error.contains("validity"), "{error}");
}
