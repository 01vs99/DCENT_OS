use super::*;
use std::sync::atomic::AtomicUsize;

struct ControlledBus0 {
    inner: Arc<bus0::Backend>,
    opcode: AtomicU8,
    sensor: AtomicU8,
    position: AtomicUsize,
    defect: AtomicU8,
    armed: AtomicBool,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

impl ControlledBus0 {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: bus0::Backend::new(bus0::Fault::None, None),
            opcode: AtomicU8::new(0),
            sensor: AtomicU8::new(0),
            position: AtomicUsize::new(0),
            defect: AtomicU8::new(0),
            armed: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }

    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
}

impl I2cSimBackend for ControlledBus0 {
    fn service_identity(&self) -> Option<usize> {
        self.inner.service_identity()
    }

    fn write(&self, bus: u8, address: u8, bytes: &[u8]) -> crate::Result<usize> {
        let result = self.inner.write(bus, address, bytes)?;
        self.opcode.store(bytes[3], Ordering::SeqCst);
        self.sensor.store(bytes[4], Ordering::SeqCst);
        self.position.store(0, Ordering::SeqCst);
        if bytes[3] == 0x3c && bytes[4] == 0x48 && self.armed.load(Ordering::SeqCst) {
            self.entered.store(true, Ordering::SeqCst);
            let guard = self.released.lock().unwrap();
            let (_guard, result) = self
                .condition
                .wait_timeout_while(guard, Duration::from_secs(6), |released| !*released)
                .unwrap();
            assert!(!result.timed_out(), "bounded bus0 worker gate exhausted");
        }
        Ok(result)
    }

    fn read(&self, bus: u8, address: u8, output: &mut [u8]) -> crate::Result<usize> {
        let count = self.inner.read(bus, address, output)?;
        let position = self.position.fetch_add(1, Ordering::SeqCst);
        match (
            self.defect.load(Ordering::SeqCst),
            self.opcode.load(Ordering::SeqCst),
            position,
        ) {
            (1, 0x17, 2) => output[0] = 0x86,
            (1, 0x17, 4) => output[0] = 0xa2,
            (2, 0x3c, 5) if self.sensor.load(Ordering::SeqCst) == 0x49 => output[0] = 1,
            (2, 0x3c, 6) if self.sensor.load(Ordering::SeqCst) == 0x49 => {
                output[0] = output[0].wrapping_add(1)
            }
            (3, 0x3c, 3) if self.sensor.load(Ordering::SeqCst) == 0x49 => return Ok(0),
            _ => {}
        }
        Ok(count)
    }

    fn write_read(
        &self,
        bus: u8,
        address: u8,
        input: &[u8],
        output: &mut [u8],
    ) -> crate::Result<()> {
        self.inner.write_read(bus, address, input, output)
    }
}

struct RuntimeRelease(Arc<ControlledBus0>, Arc<ControlledApw>);
impl Drop for RuntimeRelease {
    fn drop(&mut self) {
        self.0.release();
        self.1.release();
    }
}

fn owner(a: &Arc<ControlledBus0>, b: &Arc<ControlledApw>) -> BbManagementOwner {
    BbManagementOwner::new(
        spawn_owned_sim_i2c_service(0, a.clone(), (0x50..=0x57).collect()).unwrap(),
        spawn_owned_sim_i2c_service(1, b.clone(), vec![]).unwrap(),
    )
}

async fn prepared(
    a: &Arc<ControlledBus0>,
    b: &Arc<ControlledApw>,
    selected: &[u8],
) -> BbManagementOwner {
    let mut owner = owner(a, b);
    let initial = owner
        .observe_pre_power_once(selected, Instant::now() + Duration::from_secs(12))
        .await;
    assert!(initial.stopped_at.is_none(), "{initial:?}");
    owner.merge_requested_voltage(Some(13.4), None).unwrap();
    owner
}

async fn fenced(handles: &Handles) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !(handles.bus0.terminal_safe_off_is_latched()
            && handles.bus1.terminal_safe_off_is_latched())
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_paired_cycles_use_original_selected_workers_and_no_new_factory_scan() {
    let a = ControlledBus0::new();
    let b = ControlledApw::new();
    let selected = [0x52, 0x50, 0x51];
    let mut owner = prepared(&a, &b, &selected).await;
    let original_trace = a.inner.trace();
    let mut previous = None;
    for sequence in 1..=2 {
        let deadline = Instant::now() + Duration::from_secs(8);
        let snapshot = owner.observe_runtime_once(deadline).await.unwrap();
        assert!(snapshot.stopped_at.is_none(), "{snapshot:?}");
        assert!(!snapshot.voltage_caller_pending && !snapshot.bus0_caller_pending);
        let pair = snapshot.last_complete_pair.unwrap();
        assert_eq!((pair.sequence, pair.deadline), (sequence, deadline));
        assert_eq!(pair.bus0.sequence, pair.voltage.sequence);
        assert_eq!(pair.bus0.deadline, deadline);
        assert_eq!(pair.voltage.deadline, deadline);
        assert_eq!(pair.bus0.selected_addresses, selected);
        assert_eq!((pair.bus0.pics.len(), pair.bus0.bridges.len()), (3, 12));
        assert!(pair
            .bus0
            .pics
            .iter()
            .all(|p| p.accepted_reply.is_some() && p.returned_reads.as_ref().unwrap().len() == 5));
        assert!(pair
            .bus0
            .bridges
            .iter()
            .all(|p| p.decoded.is_some() && p.returned_reads.as_ref().unwrap().len() == 7));
        assert!(
            pair.bus0.pics[2].call_returned_at.unwrap() <= pair.bus0.bridges[0].call_prepared_at
        );
        for (index, request) in pair.bus0.pics.iter().enumerate() {
            assert_eq!(request.factory_address, selected[index]);
            assert_eq!(request.native_slot, usize::from(selected[index] - 0x50));
            assert_eq!(request.pic_address, selected[index] - 0x30);
        }
        for (index, request) in pair.bus0.bridges.iter().enumerate() {
            assert_eq!(request.factory_address, selected[index / 4]);
            assert_eq!(request.sensor_address, 0x48 + (index % 4) as u8);
        }
        let apw = pair.voltage.attempt.as_ref().unwrap();
        assert_eq!(apw.queries.len(), 4);
        assert!(pair.bus0.pics[0].call_prepared_at < apw.queries[3].returned_at);
        assert!(apw.queries[0].prepared_at < pair.bus0.bridges[11].call_returned_at.unwrap());
        assert!(pair.bus0.caller_joined_at.unwrap() <= pair.both_callers_joined_at);
        assert!(pair.voltage.caller_joined_at.unwrap() <= pair.both_callers_joined_at);
        assert!(pair.both_callers_joined_at < deadline);
        assert_eq!(
            pair.voltage
                .preview
                .as_ref()
                .unwrap()
                .first_step
                .unwrap()
                .history
                .repeated_requests,
            0
        );
        if let Some(old) = previous {
            assert!(old < pair.both_callers_joined_at);
        }
        previous = Some(pair.both_callers_joined_at);
    }
    assert_eq!(
        a.inner
            .trace()
            .iter()
            .filter(|e| matches!(e, bus0::Event::Page(_, 256)))
            .count(),
        3
    );
    assert_eq!(
        &a.inner.trace()[..original_trace.len()],
        original_trace.as_slice()
    );
    assert!(a.inner.trace()[original_trace.len()..]
        .iter()
        .all(|e| !matches!(e, bus0::Event::Page(_, _))));
    assert_eq!(b.inner.opcodes(), [2, 1, 6, 3, 2, 1, 6, 3, 2, 1, 6, 3]);
    assert!(spawn_owned_sim_i2c_service(0, a.clone(), vec![]).is_err());
    assert!(spawn_owned_sim_i2c_service(1, b.clone(), vec![]).is_err());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn either_failed_runtime_caller_fences_its_blocked_sibling_before_the_combined_join() {
    for bus0_fails in [true, false] {
        let a = ControlledBus0::new();
        let b = ControlledApw::new();
        let _release = RuntimeRelease(a.clone(), b.clone());
        let mut owner = prepared(&a, &b, &[0x50]).await;
        let handles = owner.handles.clone();
        if bus0_fails {
            a.defect.store(1, Ordering::SeqCst);
            b.armed.store(true, Ordering::SeqCst);
        } else {
            b.foreign_hardware.store(true, Ordering::SeqCst);
            a.armed.store(true, Ordering::SeqCst);
        }
        let snapshot = {
            let observe = owner.observe_runtime_once(Instant::now() + Duration::from_secs(8));
            tokio::pin!(observe);
            if bus0_fails {
                tokio::select! { _=b.wait_entered()=>{}, _=&mut observe=>panic!("sibling not blocked") }
            } else {
                tokio::select! { _=a.wait_entered()=>{}, _=&mut observe=>panic!("sibling not blocked") }
            }
            tokio::select! { _=fenced(&handles)=>{}, _=&mut observe=>panic!("completed with worker still blocked") }
            a.release();
            b.release();
            observe.await.unwrap()
        };
        assert!(snapshot.stopped_at.is_some() && snapshot.last_complete_pair.is_none());
        let sample = snapshot.latest_bus0.unwrap();
        assert!(sample.caller_joined_at.is_some() && sample.accepted_at.is_none());
        assert!(snapshot.latest_voltage.unwrap().preview.is_none());
        if bus0_fails {
            assert_eq!(sample.pics.len(), 1);
            assert!(sample.pics[0].accepted_reply.is_none());
            assert!(sample.bridges.is_empty());
        } else {
            assert_eq!(sample.bridges.len(), 1);
        }
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_both_pending_callers_preserves_cycle_deadline_and_refuses_replacement_work() {
    let a = ControlledBus0::new();
    let b = ControlledApw::new();
    let _release = RuntimeRelease(a.clone(), b.clone());
    let mut owner = prepared(&a, &b, &[0x50]).await;
    a.armed.store(true, Ordering::SeqCst);
    b.armed.store(true, Ordering::SeqCst);
    let original = Instant::now() + Duration::from_secs(8);
    {
        let observe = owner.observe_runtime_once(original);
        tokio::pin!(observe);
        tokio::select! { _=a.wait_entered()=>{}, _=&mut observe=>panic!("premature completion") }
        tokio::select! { _=b.wait_entered()=>{}, _=&mut observe=>panic!("premature completion") }
    }
    let snapshot = owner.snapshot();
    assert!(
        snapshot.stopped_at.is_some()
            && snapshot.bus0_caller_pending
            && snapshot.voltage_caller_pending
    );
    assert!(snapshot.last_complete_pair.is_none());
    assert!(
        !owner
            .join_callers_until(Instant::now() + Duration::from_millis(10))
            .await
    );
    assert!(tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_millis(10))
    )
    .is_err());
    assert!(owner
        .observe_voltage_once(Instant::now() + Duration::from_secs(30))
        .await
        .is_err());
    assert!(owner
        .observe_runtime_once(Instant::now() + Duration::from_secs(30))
        .await
        .is_err());
    assert_eq!(owner.snapshot().latest_bus0.unwrap().deadline, original);
    assert_eq!(owner.snapshot().latest_voltage.unwrap().deadline, original);
    a.release();
    b.release();
    finish(&mut owner).await;
    let snapshot = owner.snapshot();
    assert!(!snapshot.bus0_caller_pending && !snapshot.voltage_caller_pending);
    assert!(snapshot.last_complete_pair.is_none());
    assert!(snapshot.latest_bus0.unwrap().accepted_at.is_none());
    assert!(snapshot.latest_voltage.unwrap().preview.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bus0_caller_timeout_can_join_before_its_original_worker_finishes_a_started_transfer() {
    let a = ControlledBus0::new();
    let b = ControlledApw::new();
    let _release = RuntimeRelease(a.clone(), b.clone());
    let mut owner = prepared(&a, &b, &[0x50]).await;
    a.armed.store(true, Ordering::SeqCst);
    let original = Instant::now() + Duration::from_millis(750);
    {
        let observe = owner.observe_runtime_once(original);
        tokio::pin!(observe);
        tokio::select! { _=a.wait_entered()=>{}, _=&mut observe=>panic!("premature completion") }
        assert!(observe.await.unwrap().stopped_at.is_some());
    }
    assert!(
        owner
            .join_callers_until(Instant::now() + Duration::from_secs(1))
            .await
    );
    let snapshot = owner.snapshot();
    assert!(!snapshot.bus0_caller_pending && !snapshot.voltage_caller_pending);
    let sample = snapshot.latest_bus0.unwrap();
    assert_eq!(sample.deadline, original);
    assert!(sample.accepted_at.is_none());
    assert_eq!(sample.bridges.len(), 1);
    assert!(sample.bridges[0].returned_reads.is_none());
    assert!(!tokio::task::block_in_place(
        || owner.close_services_until(Instant::now() + Duration::from_millis(20))
    )
    .unwrap());
    assert!(owner.close_receipts().0.is_none());
    assert!(spawn_owned_sim_i2c_service(0, a.clone(), vec![]).is_err());
    a.release();
    finish(&mut owner).await;
    assert!(owner.snapshot().last_complete_pair.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renewed_lm75_status_and_short_read_refusals_keep_available_bytes_without_a_complete_pair()
{
    for defect in [2, 3] {
        let a = ControlledBus0::new();
        let b = ControlledApw::new();
        let mut owner = prepared(&a, &b, &[0x51]).await;
        a.defect.store(defect, Ordering::SeqCst);
        let snapshot = owner
            .observe_runtime_once(Instant::now() + Duration::from_secs(8))
            .await
            .unwrap();
        assert!(snapshot.stopped_at.is_some() && snapshot.last_complete_pair.is_none());
        let sample = snapshot.latest_bus0.unwrap();
        assert_eq!(sample.pics[0].pic_address, 0x21);
        assert!(sample.pics[0].accepted_reply.is_some());
        assert_eq!(sample.bridges.len(), 2);
        assert!(sample.bridges[0].decoded.is_some());
        assert!(sample.bridges[1].error.is_some() && sample.bridges[1].decoded.is_none());
        assert_eq!(sample.bridges[1].sensor_address, 0x49);
        if defect == 2 {
            assert_eq!(sample.bridges[1].returned_reads.as_ref().unwrap().len(), 7);
        } else {
            let reads = sample.bridges[1].returned_reads.as_ref().unwrap();
            assert_eq!(reads.len(), 7);
            for (index, read) in reads.iter().enumerate() {
                assert_eq!(read.len(), if index == 3 { 0 } else { 1 });
            }
            assert!(sample.bridges[1]
                .error
                .as_ref()
                .unwrap()
                .contains("ReadShape"));
        }
        assert!(sample.failure.is_some() && sample.accepted_at.is_none());
        finish(&mut owner).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_new_pair_preserves_prior_pair_only_as_its_original_historical_cycle() {
    let a = ControlledBus0::new();
    let b = ControlledApw::new();
    let mut owner = prepared(&a, &b, &[0x50]).await;
    let first = owner
        .observe_runtime_once(Instant::now() + Duration::from_secs(8))
        .await
        .unwrap();
    let historical = first.last_complete_pair.unwrap();
    assert_eq!(historical.sequence, 1);
    b.bad_calibration.store(true, Ordering::SeqCst);
    let second = owner
        .observe_runtime_once(Instant::now() + Duration::from_secs(8))
        .await
        .unwrap();
    assert!(second.stopped_at.is_some());
    assert_eq!(second.latest_bus0.as_ref().unwrap().sequence, 2);
    assert_eq!(second.latest_voltage.as_ref().unwrap().sequence, 2);
    let retained = second.last_complete_pair.unwrap();
    assert_eq!(
        (retained.sequence, retained.deadline),
        (1, historical.deadline)
    );
    assert_eq!(
        retained.both_callers_joined_at,
        historical.both_callers_joined_at
    );
    assert!(second.latest_voltage.unwrap().preview.is_none());
    assert!(owner
        .observe_runtime_once(Instant::now() + Duration::from_secs(30))
        .await
        .is_err());
    finish(&mut owner).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paired_admission_refusals_start_neither_new_caller_or_wire_sequence() {
    for diagnosed in [false, true] {
        let a = ControlledBus0::new();
        let b = ControlledApw::new();
        let mut owner = if diagnosed {
            prepared(&a, &b, &[0x50]).await
        } else {
            owner(&a, &b)
        };
        let (trace0, trace1) = (a.inner.trace(), b.inner.trace());
        let deadline = if diagnosed {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(8)
        };
        assert!(owner.observe_runtime_once(deadline).await.is_err());
        let snapshot = owner.snapshot();
        assert!(snapshot.latest_voltage.is_none() && snapshot.latest_bus0.is_none());
        assert!(!snapshot.voltage_caller_pending && !snapshot.bus0_caller_pending);
        assert_eq!(a.inner.trace(), trace0);
        assert_eq!(b.inner.trace(), trace1);
        finish(&mut owner).await;
    }
}
