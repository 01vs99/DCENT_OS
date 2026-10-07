use super::super::tests::{deadline, sample_work, RecordingRegisters};
use super::*;
use std::collections::VecDeque;
use std::sync::atomic::AtomicUsize;

struct PowerRegisters {
    inner: RecordingRegisters,
    complete_at: Option<usize>,
    iic_reads: AtomicUsize,
    fail_iic_read: bool,
    mismatch_pwm: bool,
    tach: Mutex<VecDeque<u32>>,
}
impl Default for PowerRegisters {
    fn default() -> Self {
        Self {
            inner: RecordingRegisters::default(),
            complete_at: Some(1),
            iic_reads: AtomicUsize::new(0),
            fail_iic_read: false,
            mismatch_pwm: false,
            tach: Mutex::default(),
        }
    }
}
impl Registers for PowerRegisters {
    fn read(&self, offset: u32) -> Result<u32, String> {
        match offset {
            POWER_IIC => {
                if self.fail_iic_read {
                    return Err("injected APW register read failure".into());
                }
                let count = self.iic_reads.fetch_add(1, Ordering::SeqCst) + 1;
                Ok(if self.complete_at.is_some_and(|at| count >= at) {
                    // The completion byte deliberately differs from the DAC
                    // code: completion is not output-voltage readback.
                    0x8000_005a
                } else {
                    0x5a
                })
            }
            FAN_PWM => {
                if self.mismatch_pwm {
                    return Ok(0);
                }
                self.inner
                    .state
                    .lock()
                    .unwrap()
                    .writes
                    .iter()
                    .rev()
                    .find(|(register, _)| *register == FAN_PWM)
                    .map(|(_, value)| *value)
                    .ok_or("PWM register has no prior write".into())
            }
            FAN_TACH => self
                .tach
                .lock()
                .unwrap()
                .pop_front()
                .ok_or("injected tach read failure".into()),
            _ => self.inner.read(offset),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.inner.write(offset, value)
    }
}

fn make_owner(registers: Arc<PowerRegisters>) -> Arc<Transport<PowerRegisters>> {
    Transport::new(registers, vec![0, 1, 2]).unwrap()
}

#[test]
fn apw8_matches_original_stores_and_delays_with_first_or_last_completion() {
    let original: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut compared = 0;
    for release in original["releases"].as_array().unwrap() {
        for vector in release["voltage"].as_array().unwrap() {
            let volts = vector["volts_argument"].as_f64().unwrap();
            let Ok(setting) = Apw8Setting::new(volts) else {
                continue;
            };
            let Some(poll) = vector["complete_at_poll"].as_u64() else {
                continue;
            };
            let registers = Arc::new(PowerRegisters {
                complete_at: Some(poll as usize),
                ..Default::default()
            });
            let owner = make_owner(registers.clone());
            let mut health_checks = 0;
            let value = owner
                .apw8_with_delay(
                    setting,
                    deadline(),
                    |ms| {
                        registers
                            .inner
                            .state
                            .lock()
                            .unwrap()
                            .events
                            .push(serde_json::json!({"delay_us":ms*1000}));
                        Ok(())
                    },
                    || {
                        assert!(owner.management_lane.try_lock().is_err());
                        health_checks += 1;
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(value.requested_volts, volts);
            assert_eq!(value.dac_code, vector["code"].as_u64().unwrap() as u8);
            assert_eq!(health_checks, 2);
            assert_eq!(
                registers.inner.state.lock().unwrap().events,
                *vector["events"].as_array().unwrap()
            );
            assert!(!owner.terminal());
            assert!(!owner.management_fault.load(Ordering::SeqCst));
            compared += 1;
        }
    }
    assert_eq!(compared, 36);
}

#[test]
fn apw8_rejects_nonfinite_and_outside_source_envelope() {
    for volts in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        0.0,
        16.029,
        20.281,
        100.0,
    ] {
        assert!(Apw8Setting::new(volts).is_err());
    }
    for volts in [16.03, 16.32, 18.3, 20.04, 20.28] {
        assert_eq!(Apw8Setting::new(volts).unwrap().volts, volts);
    }
}

#[test]
fn incomplete_apw8_never_reports_setting_and_quarantines_shared_portal() {
    for failure in [0, 1, 2] {
        let registers = Arc::new(PowerRegisters {
            complete_at: if failure == 2 { None } else { Some(1) },
            fail_iic_read: failure == 1,
            ..Default::default()
        });
        if failure == 0 {
            registers.inner.state.lock().unwrap().fail_at = Some(0);
        }
        let owner = make_owner(registers.clone());
        let mut delays = Vec::new();
        assert!(owner
            .apw8_with_delay(
                Apw8Setting::new(18.3).unwrap(),
                deadline(),
                |ms| {
                    delays.push(ms);
                    Ok(())
                },
                || Ok(())
            )
            .is_err());
        assert!(owner.terminal());
        assert!(owner.management_fault.load(Ordering::SeqCst));
        assert!(!delays.contains(&300));
        if failure == 2 {
            assert_eq!(registers.iic_reads.load(Ordering::SeqCst), 101);
            assert_eq!(delays.len(), 102);
        }
        assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
    }
}

#[test]
fn terminal_at_each_apw_phase_preserves_portal_completion_truth() {
    for phase in [100, 5, 300] {
        let registers = Arc::new(PowerRegisters::default());
        let owner = make_owner(registers.clone());
        assert!(owner
            .apw8_with_delay(
                Apw8Setting::new(18.3).unwrap(),
                deadline(),
                |ms| {
                    if ms == phase {
                        owner.latch_terminal();
                    }
                    Ok(())
                },
                || Ok(())
            )
            .is_err());
        assert!(owner.terminal());
        assert_eq!(owner.management_fault.load(Ordering::SeqCst), phase == 5);
        assert_eq!(
            registers.inner.state.lock().unwrap().writes.len(),
            usize::from(phase != 100)
        );
    }
}

#[test]
fn heartbeat_health_is_rechecked_after_settling_before_apw_command() {
    for failed_check in [1, 2] {
        let registers = Arc::new(PowerRegisters::default());
        let owner = make_owner(registers.clone());
        let mut checked = 0;
        assert!(owner
            .apw8_with_delay(
                Apw8Setting::new(18.3).unwrap(),
                deadline(),
                |_| Ok(()),
                || {
                    checked += 1;
                    if checked == failed_check {
                        Err("PIC heartbeat expired".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err());
        assert_eq!(checked, failed_check);
        assert!(registers.inner.state.lock().unwrap().writes.is_empty());
        assert!(owner.terminal());
        assert!(!owner.management_fault.load(Ordering::SeqCst));
    }
}

#[test]
fn quiet30_and_raw_tach_match_original_and_remain_available_after_terminal() {
    let registers = Arc::new(PowerRegisters::default());
    let owner = make_owner(registers.clone());
    owner.latch_terminal();
    owner.management_fault.store(true, Ordering::SeqCst);
    let fan = owner.quiet_fans_locked(deadline()).unwrap();
    assert_eq!(
        fan,
        QuietFanSetting {
            percent: 30,
            register_word: 0x000f_0023
        }
    );
    assert_eq!(
        registers.inner.state.lock().unwrap().writes,
        [(0x84, 0x000f_0023)]
    );
    let original: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut compared = 0;
    for release in original["releases"].as_array().unwrap() {
        for vector in release["tach"].as_array().unwrap() {
            let sample =
                FanTachSample::decode(vector["raw_word"].as_u64().unwrap() as u32).unwrap();
            assert_eq!(
                u64::from(sample.fan_index),
                vector["fan_index"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(sample.raw_count),
                vector["raw_count"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(sample.stock_rpm),
                vector["stock_rpm"].as_u64().unwrap()
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 64);
    let words = [
        0x0032,
        0x0132,
        u32::MAX,
        0x0100,
        0x0032,
        0x0132,
        0x0032,
        0x0132,
        0x0032,
        0x0132,
        0x0032,
        0x0132,
        0x0032,
        0x0132,
        0x0032,
        0x0132,
    ];
    registers.tach.lock().unwrap().extend(words);
    let snapshot = owner.tach_snapshot_locked(deadline()).unwrap();
    assert_eq!(snapshot.samples, words.map(FanTachSample::decode));
    assert!(snapshot.samples[2].is_none());
    assert_eq!(snapshot.samples[3].unwrap().stock_rpm, 0);
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 1);
}

#[test]
fn fan_readback_and_sample_errors_never_publish_a_complete_snapshot() {
    let registers = Arc::new(PowerRegisters {
        mismatch_pwm: true,
        ..Default::default()
    });
    let owner = make_owner(registers);
    assert!(owner.quiet_fans_locked(deadline()).is_err());
    assert!(owner.terminal());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
    for available in [0, 1, 15] {
        let registers = Arc::new(PowerRegisters::default());
        registers
            .tach
            .lock()
            .unwrap()
            .extend(std::iter::repeat_n(0x32, available));
        let owner = make_owner(registers);
        assert!(owner.tach_snapshot_locked(deadline()).is_err());
        assert!(owner.terminal());
    }
}

#[tokio::test]
async fn async_cooling_works_terminal_but_respects_deadline_and_lane() {
    let registers = Arc::new(PowerRegisters::default());
    let owner = make_owner(registers.clone());
    owner.latch_terminal();
    owner.set_quiet_fans(deadline()).await.unwrap();
    registers.tach.lock().unwrap().extend([0x32; 16]);
    assert_eq!(
        owner
            .fan_tach_snapshot(deadline())
            .await
            .unwrap()
            .samples
            .len(),
        16
    );
    let held = owner.lock_fan_until(deadline()).unwrap();
    assert!(owner
        .set_quiet_fans(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    drop(held);
    assert!(owner.fan_tach_snapshot(Instant::now()).await.is_err());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 1);
}

#[tokio::test]
async fn fan_health_remains_live_while_pic_owns_the_management_transaction() {
    let registers = Arc::new(PowerRegisters::default());
    registers.tach.lock().unwrap().extend([0x32; 16]);
    let owner = make_owner(registers.clone());
    let _management = owner.lock_management_until(deadline()).unwrap();
    let until = Instant::now() + Duration::from_millis(100);
    assert_eq!(owner.set_quiet_fans(until).await.unwrap().percent, 30);
    assert_eq!(
        owner.fan_tach_snapshot(until).await.unwrap().samples.len(),
        16
    );
    assert!(!owner.terminal());
    assert_eq!(registers.iic_reads.load(Ordering::SeqCst), 0);
    assert!(registers
        .inner
        .state
        .lock()
        .unwrap()
        .writes
        .iter()
        .all(|(offset, value)| *offset == FAN_PWM && *value == QUIET_PWM));
}

#[test]
fn stalled_fan_owner_closes_work_and_cannot_complete_terminal_drain() {
    let registers = Arc::new(PowerRegisters::default());
    let owner = make_owner(registers.clone());
    let held = owner.lock_fan_until(deadline()).unwrap();
    assert!(owner
        .quiet_fans_locked(Instant::now() + Duration::from_millis(5))
        .is_err());
    assert!(owner.terminal());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    assert!(owner
        .terminal_drain(Instant::now() + Duration::from_millis(5))
        .is_err());
    drop(held);
    owner.terminal_drain(deadline()).unwrap();
}

#[tokio::test]
async fn actual_apw_delay_expiry_stops_before_the_command() {
    let registers = Arc::new(PowerRegisters::default());
    let owner = make_owner(registers.clone());
    let bounded = Instant::now() + Duration::from_millis(10);
    let result = tokio::task::spawn_blocking(move || {
        owner.apw8_with_delay(
            Apw8Setting::new(18.3).unwrap(),
            bounded,
            |ms| owner.power_delay(ms, bounded, false),
            || Ok(()),
        )
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
}
