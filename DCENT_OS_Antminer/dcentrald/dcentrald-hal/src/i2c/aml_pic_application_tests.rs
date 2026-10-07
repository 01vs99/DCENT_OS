use super::*;
use std::collections::VecDeque;

struct Script {
    writes: Vec<u8>,
    replies: VecDeque<u8>,
    delays: Vec<u64>,
    io: usize,
    fail_at: Option<usize>,
    authority: Arc<I2cSafetyAuthority>,
    cleanup: usize,
}
impl Script {
    fn new(permit: &I2cSafetyPermit, reply: &[u8]) -> Self {
        Self {
            writes: vec![],
            replies: reply.iter().copied().collect(),
            delays: vec![],
            io: 0,
            fail_at: None,
            authority: permit.authority.clone(),
            cleanup: 0,
        }
    }
    fn step(&mut self) -> Result<()> {
        self.io += 1;
        if self.fail_at == Some(self.io) {
            Err(bridge::fault(0x20, "injected NACK"))
        } else {
            Ok(())
        }
    }
}
impl Wire for Script {
    fn bus(&self) -> u8 {
        0
    }
    fn select(&mut self, _: u8) -> Result<()> {
        Ok(())
    }
    fn write_byte(&mut self, byte: u8) -> Result<()> {
        if self.authority.terminal_safe_off.load(Ordering::SeqCst) && byte == 0 {
            self.cleanup += 1;
        }
        self.step()?;
        self.writes.push(byte);
        Ok(())
    }
    fn read_byte(&mut self) -> Result<u8> {
        self.step()?;
        self.replies
            .pop_front()
            .ok_or_else(|| bridge::fault(0x20, "short reply"))
    }
    fn delay(&mut self, d: Duration) {
        self.delays.push(d.as_millis() as u64);
    }
}
fn fixture() -> (I2cSafetyPermit, AmlPicLm75Route) {
    let (service, _receiver) = I2cServiceHandle::for_unit_tests();
    let route = AmlPicLm75Route::bind(&service, 42601, 1).unwrap();
    (
        I2cSafetyPermit {
            authority: service.safety,
            generation: 0,
            intent: I2cOperationIntent::UnclassifiedMutation,
            scope: I2cPermitScope::Generic,
        },
        route,
    )
}
fn run(
    wire: &mut Script,
    route: &AmlPicLm75Route,
    op: Operation,
    permit: &I2cSafetyPermit,
) -> Result<Vec<u8>> {
    execute_on(
        wire,
        route,
        op,
        permit,
        Instant::now() + Duration::from_secs(2),
    )
}

#[test]
fn rail_query_consumes_original_frame_and_parser_vectors() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../../"))).unwrap();
    for row in oracle["responses"].as_array().unwrap() {
        let raw = row["reply"].as_str().unwrap();
        let reply: Vec<u8> = (0..raw.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&raw[n..n + 2], 16).unwrap())
            .collect();
        let (permit, route) = fixture();
        let mut wire = Script::new(&permit, &reply);
        let accepted = row["rejection_branch"].is_null() && row["status"] == 1;
        assert_eq!(
            run(&mut wire, &route, Operation::Voltage, &permit).is_ok(),
            accepted
        );
        let actual = wire.writes[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, oracle["frame"]);
        if !accepted {
            assert_eq!(wire.cleanup, 16);
        }
    }
    assert_eq!(Operation::Voltage.byte_budget(), 29);
}

#[test]
fn application_frames_match_both_original_encoders() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../../../"))).unwrap();
    for (op, index, reply) in [
        (Operation::Version, 3, vec![5, 0x17, 0x89, 0, 0xa5]),
        (Operation::Heartbeat, 2, vec![6, 0x16, 1, 0, 0, 0x1d]),
        (Operation::Disable, 0, vec![0x15, 1]),
        (Operation::Enable, 1, vec![0x15, 1]),
    ] {
        let (mut permit, route) = fixture();
        if matches!(op, Operation::Disable) {
            permit.intent = I2cOperationIntent::SafeOff;
        }
        let mut wire = Script::new(&permit, &reply);
        assert_eq!(run(&mut wire, &route, op, &permit).unwrap(), reply);
        let actual = wire
            .writes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(actual, oracle["frames"][index]["braiins_frame"]);
        assert_eq!(actual, oracle["frames"][index]["kernel"]["frame"]);
        assert_eq!(wire.delays, [50]);
    }
}

#[test]
fn strict_observation_rejects_short_wrong_firmware_checksum_and_status() {
    for (op, reply) in [
        (Operation::Version, vec![0x89]),
        (Operation::Version, vec![5, 0x17, 0x86, 0, 0xa2]),
        (Operation::Version, vec![5, 0x17, 0x89, 0, 0xff]),
        (Operation::Heartbeat, vec![6, 0x16, 0, 0, 0, 0x1c]),
        (Operation::Heartbeat, vec![6, 0x16, 1, 0, 0, 0x1c]),
        (Operation::Heartbeat, vec![4, 0x16, 1, 0, 0, 0x1b]),
        (Operation::Disable, vec![0x15, 0]),
        (Operation::Enable, vec![0x15, 0]),
        (Operation::Disable, vec![0x16, 1]),
    ] {
        let (mut permit, route) = fixture();
        if matches!(op, Operation::Disable) {
            permit.intent = I2cOperationIntent::SafeOff;
        }
        let mut wire = Script::new(&permit, &reply);
        assert!(run(&mut wire, &route, op, &permit).is_err());
        assert_eq!(wire.cleanup, 16);
        assert_eq!(&wire.writes[op.frame().len()..], &[0; 16]);
    }
}

#[test]
fn every_application_byte_failure_closes_normal_lane_before_cleanup() {
    for (op, reply) in [
        (Operation::Version, vec![5, 0x17, 0x89, 0, 0xa5]),
        (Operation::Heartbeat, vec![6, 0x16, 1, 0, 0, 0x1d]),
        (Operation::Voltage, vec![7, 0x3a, 1, 2, 0x31, 0, 0x75]),
        (Operation::Enable, vec![0x15, 1]),
    ] {
        for fail_at in 1..=op.frame().len() + reply.len() {
            let (permit, route) = fixture();
            let mut wire = Script::new(&permit, &reply);
            wire.fail_at = Some(fail_at);
            assert!(run(&mut wire, &route, op, &permit).is_err());
            assert_eq!(wire.cleanup, 16);
            let before = wire.io;
            assert!(run(&mut wire, &route, op, &permit).is_err());
            assert_eq!(wire.io, before);
        }
    }
}

#[test]
fn terminal_cut_keeps_exact_owner_but_never_restores_normal_generation() {
    let (mut permit, route) = fixture();
    permit.authority.latch_terminal_safe_off();
    permit.intent = I2cOperationIntent::SafeOff;
    let mut wire = Script::new(&permit, &[0x15, 1]);
    run(&mut wire, &route, Operation::Disable, &permit).unwrap();
    assert_eq!(wire.writes, Operation::Disable.frame());
    assert!(run(&mut wire, &route, Operation::Heartbeat, &permit).is_err());
    let (other, _) = fixture();
    let mut other_wire = Script::new(&other, &[0x15, 1]);
    assert!(run(&mut other_wire, &route, Operation::Disable, &other).is_err());
    assert!(other_wire.writes.is_empty());
}
