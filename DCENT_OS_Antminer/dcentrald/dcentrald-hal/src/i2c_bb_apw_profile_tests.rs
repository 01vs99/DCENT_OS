//! Six authored owned-service groups; detached and uncompiled.
use super::*;
use crate::bb_apw_diagnostics::{Field, Query};
use crate::platform::sim::{SimControllerKind, SimI2cBackend, TraceEvent};

struct ProfileBackend {
    identity: SimI2cBackend,
    hardware: u16,
    firmware: u16,
    dac: u16,
    bad_calibration_checksum: bool,
    reply: Mutex<Vec<u8>>,
    trace: Mutex<Vec<TraceEvent>>,
}

impl ProfileBackend {
    fn new() -> Self {
        Self {
            identity: SimI2cBackend::with_controller(SimControllerKind::Dspic),
            hardware: 0x76,
            firmware: 0x17,
            dac: 0x23,
            bad_calibration_checksum: false,
            reply: Mutex::new(Vec::new()),
            trace: Mutex::new(Vec::new()),
        }
    }

    fn opcodes(&self) -> Vec<u8> {
        self.trace
            .lock()
            .unwrap()
            .iter()
            .filter_map(|row| {
                if let TraceEvent::I2cWrite { bytes, .. } = row {
                    Some(bytes[4])
                } else {
                    None
                }
            })
            .collect()
    }
}

impl I2cSimBackend for ProfileBackend {
    fn service_identity(&self) -> Option<usize> {
        self.identity.service_identity()
    }

    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> Result<usize> {
        assert_eq!((bus, addr), (1, 0x10));
        let opcode = bytes[4];
        let (expected, data, read_len) = match opcode {
            2 => (
                vec![0x11, 0x55, 0xaa, 4, 2, 6, 0],
                self.hardware.to_le_bytes().to_vec(),
                8,
            ),
            1 => (
                vec![0x11, 0x55, 0xaa, 4, 1, 5, 0],
                self.firmware.to_le_bytes().to_vec(),
                8,
            ),
            6 => {
                assert_eq!(
                    (self.hardware, self.firmware),
                    (0x76, 0x17),
                    "foreign identity reached calibration"
                );
                let mut data = vec![0x40];
                data.extend([0xff; 32]);
                (vec![0x11, 0x55, 0xaa, 6, 6, 0x40, 0x20, 0x6c, 0], data, 40)
            }
            3 => (
                vec![0x11, 0x55, 0xaa, 4, 3, 7, 0],
                self.dac.to_le_bytes().to_vec(),
                10,
            ),
            _ => panic!("unexpected APW control opcode {opcode:x}"),
        };
        assert_eq!(bytes, expected);
        self.trace.lock().unwrap().push(TraceEvent::I2cWrite {
            bus,
            addr,
            bytes: bytes.to_vec(),
        });
        let len = data.len() as u8 + 4;
        let checksum = u16::from(len)
            + u16::from(opcode)
            + data.iter().map(|byte| u16::from(*byte)).sum::<u16>();
        let mut raw = vec![0x55, 0xaa, len, opcode];
        raw.extend(data);
        raw.extend(checksum.to_le_bytes());
        raw.resize(read_len, 0xf5);
        if opcode == 6 && self.bad_calibration_checksum {
            raw[38] ^= 1;
        }
        *self.reply.lock().unwrap() = raw;
        Ok(bytes.len())
    }

    fn read(&self, bus: u8, addr: u8, output: &mut [u8]) -> Result<usize> {
        assert_eq!((bus, addr), (1, 0x10));
        let raw = std::mem::take(&mut *self.reply.lock().unwrap());
        assert_eq!(output.len(), raw.len());
        output.copy_from_slice(&raw);
        self.trace.lock().unwrap().push(TraceEvent::I2cRead {
            bus,
            addr,
            bytes: raw,
        });
        Ok(output.len())
    }

    fn write_read(&self, _: u8, _: u8, _: &[u8], _: &mut [u8]) -> Result<()> {
        panic!("APW requires separate delayed reply")
    }
}

#[test]
fn actual_same_owner_observes_four_phases_and_preserves_wide_dac_word() {
    for dac in [0x23, 0xffff] {
        let mut backend = ProfileBackend::new();
        backend.dac = dac;
        let backend = Arc::new(backend);
        let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let result = owner.request_handle().read_bb_apw_profile_at(deadline);
        assert!(result.failure.is_none(), "{:?}", result.failure);
        assert!(result
            .caller_completed_at
            .is_some_and(|when| when < deadline));
        assert_eq!(backend.opcodes(), [2, 1, 6, 3]);
        assert_eq!(
            result
                .queries
                .iter()
                .map(|row| row.query)
                .collect::<Vec<_>>(),
            [
                Query::Hardware,
                Query::Firmware,
                Query::Calibration,
                Query::Dac
            ]
        );
        assert_eq!(
            result
                .queries
                .iter()
                .map(|row| row.returned_reads.as_ref().unwrap()[0].len())
                .collect::<Vec<_>>(),
            [8, 8, 40, 10]
        );
        assert_eq!(
            result.queries[2].decoded,
            Ok(Field::Calibration([0xff; 32]))
        );
        assert_eq!(
            result.queries[3].decoded,
            Ok(Field::Dac {
                raw: dac,
                millivolts: if dac == 0x23 { Some(14670) } else { None }
            })
        );
        assert!(result
            .queries
            .iter()
            .all(|row| row.returned_at >= row.prepared_at && row.returned_at < deadline));
        owner
            .close_and_join_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }
}

#[test]
fn wrong_hardware_high_byte_or_firmware_stops_before_calibration_request() {
    for (hardware, firmware, expected) in [
        (0x73, 0x17, vec![2]),
        (0x176, 0x17, vec![2]),
        (0x76, 0x71, vec![2, 1]),
        (0x76, 0x117, vec![2, 1]),
    ] {
        let mut backend = ProfileBackend::new();
        backend.hardware = hardware;
        backend.firmware = firmware;
        let backend = Arc::new(backend);
        let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
        let result = owner
            .request_handle()
            .read_bb_apw_profile_at(Instant::now() + Duration::from_secs(5));
        assert_eq!(backend.opcodes(), expected);
        assert_eq!(result.queries.len(), expected.len());
        assert!(result.queries.last().unwrap().returned_reads.is_some());
        assert!(result.queries.last().unwrap().decoded.is_err());
        assert!(result.failure.is_some() && result.caller_completed_at.is_none());
        owner
            .close_and_join_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }
}

#[test]
fn invalid_calibration_preserves_actual_reply_and_prior_identity_without_dac_query() {
    let mut backend = ProfileBackend::new();
    backend.bad_calibration_checksum = true;
    let backend = Arc::new(backend);
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let result = owner
        .request_handle()
        .read_bb_apw_profile_at(Instant::now() + Duration::from_secs(5));
    assert_eq!(backend.opcodes(), [2, 1, 6]);
    assert_eq!(result.queries[0].decoded, Ok(Field::Hardware(0x76)));
    assert_eq!(result.queries[1].decoded, Ok(Field::Firmware(0x17)));
    let raw = &result.queries[2].returned_reads.as_ref().unwrap()[0];
    assert_eq!(raw.len(), 40);
    assert_eq!(&raw[37..], &[0x4b, 0x21, 0xf5]);
    assert!(result.queries[2].decoded.is_err());
    assert!(result.failure.is_some() && result.caller_completed_at.is_none());
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
}

#[test]
fn wrong_bus_expired_deadline_and_terminal_fence_have_no_query_bytes() {
    let backend = Arc::new(ProfileBackend::new());
    for bus in [0, 1] {
        let mut owner = spawn_owned_sim_i2c_service(bus, backend.clone(), Vec::new()).unwrap();
        let handle = owner.request_handle();
        let deadline = if bus == 1 {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(1)
        };
        let result = handle.read_bb_apw_profile_at(deadline);
        assert!(result.failure.is_some() && result.queries.is_empty());
        owner.terminal_fence().latch_terminal_safe_off();
        let result = handle.read_bb_apw_profile_at(Instant::now() + Duration::from_secs(1));
        assert!(result.failure.is_some() && result.queries.is_empty());
        assert!(backend.trace.lock().unwrap().is_empty());
        owner
            .close_and_join_until(Instant::now() + Duration::from_secs(1))
            .unwrap();
    }
}

#[test]
fn profile_queued_behind_blocked_transfer_expires_without_later_query() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let first_handle = handle.clone();
    let first = std::thread::spawn(move || first_handle.read_bytes(0x10, 1));
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let result = handle.read_bb_apw_profile_at(Instant::now() + Duration::from_millis(100));
    assert!(result
        .failure
        .as_ref()
        .unwrap()
        .contains("will not touch the bus"));
    assert_eq!(result.queries.len(), 1);
    assert!(result.queries[0].returned_reads.is_none());
    backend.release_transfer_stall().unwrap();
    first.join().unwrap().unwrap();
    handle.read_bytes(0x10, 1).unwrap();
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    assert!(!backend
        .drain_trace()
        .unwrap()
        .iter()
        .any(|event| matches!(event, TraceEvent::I2cWrite { .. })));
}

#[test]
fn started_profile_timeout_retains_actual_service_close_custody() {
    let backend = Arc::new(SimI2cBackend::with_controller(SimControllerKind::Dspic));
    let mut owner = spawn_owned_sim_i2c_service(1, backend.clone(), Vec::new()).unwrap();
    let handle = owner.request_handle();
    backend.arm_next_transfer_stall().unwrap();
    let caller = std::thread::spawn(move || {
        handle.read_bb_apw_profile_at(Instant::now() + Duration::from_millis(100))
    });
    assert!(backend
        .wait_for_transfer_stall(Duration::from_secs(1))
        .unwrap());
    let result = caller.join().unwrap();
    assert!(result
        .failure
        .as_ref()
        .unwrap()
        .contains("outcome is unknown"));
    assert_eq!(result.queries.len(), 1);
    assert!(result.queries[0].returned_reads.is_none());
    assert!(owner
        .close_and_join_until(Instant::now() + Duration::from_millis(10))
        .is_err());
    backend.release_transfer_stall().unwrap();
    owner
        .close_and_join_until(Instant::now() + Duration::from_secs(1))
        .unwrap();
    let trace = backend.drain_trace().unwrap();
    let writes: Vec<_> = trace
        .iter()
        .filter_map(|event| {
            if let TraceEvent::I2cWrite { bytes, .. } = event {
                Some(bytes.clone())
            } else {
                None
            }
        })
        .collect();
    assert_eq!(writes, [vec![0x11, 0x55, 0xaa, 4, 2, 6, 0]]);
}
