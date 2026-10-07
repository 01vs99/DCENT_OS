//! Host-only fixture assembly; sim-hal is forbidden in ARM firmware builds.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
#[path = "bb_pre_power_apw_test_support.rs"]
mod apw;
#[path = "bb_pre_power_bus0_test_support.rs"]
mod bus0;

/// Actual fixed modeled-wire event; readonly data, never worker/phase proof.
#[derive(Clone, Debug)]
pub struct PicEvent {
    pub at: Instant,
    pub address: u8,
    pub opcode: u8,
    pub write: bool,
    pub bytes: Vec<u8>,
}

pub struct Fixture {
    a: Arc<bus0::Backend>,
    b: Arc<apw::Backend>,
    wire: Arc<super::wire_sim::RuntimeWire>,
    opener_calls: Arc<Mutex<Vec<u8>>>,
}
impl Fixture {
    /// Self-authored wire model and held EEPROM fixture, never physical inputs.
    pub fn new(block_apw: bool, bad_factory: bool) -> (BbManagementRuntime, Self) {
        let (mut services, fixture) = Self::workers(block_apw, bad_factory);
        let owner0 = services(0).expect("original fresh fixture bus0");
        let owner1 = services(1).expect("original fresh fixture bus1");
        (BbManagementRuntime::new(owner0, owner1), fixture)
    }

    /// Actual original workers for the retained factory's simulated open seam.
    /// Each bus can be opened once; no snapshot or prepared runtime is injected.
    pub fn factory_services(
        block_apw: bool,
        bad_factory: bool,
    ) -> (crate::platform::beaglebone::BbSimFactoryServices, Self) {
        let (services, fixture) = Self::workers(block_apw, bad_factory);
        (
            crate::platform::beaglebone::BbSimFactoryServices::from_opener(services),
            fixture,
        )
    }
    fn workers(
        block_apw: bool,
        bad_factory: bool,
    ) -> (
        impl FnMut(u8) -> std::io::Result<I2cServiceOwner> + Send + 'static,
        Self,
    ) {
        let a = bus0::Backend::new(
            if bad_factory {
                bus0::Fault::FactoryCrc
            } else {
                bus0::Fault::None
            },
            None,
        );
        let b = apw::Backend::new(0x23, false, block_apw.then_some((2, apw::Phase::Write)));
        let wire = super::wire_sim::RuntimeWire::new(a.clone());
        let source0 = wire.clone();
        let source1 = b.clone();
        let mut opened = [false; 2];
        let opener_calls = Arc::new(Mutex::new(Vec::new()));
        let actual_calls = opener_calls.clone();
        let services = move |bus: u8| {
            actual_calls.lock().unwrap().push(bus);
            if bus > 1 || opened[usize::from(bus)] {
                return Err(std::io::Error::other(
                    "original simulated factory bus is invalid or already opened",
                ));
            }
            opened[usize::from(bus)] = true;
            match bus {
                0 => spawn_owned_sim_i2c_service(0, source0.clone(), (0x50..=0x57).collect()),
                1 => spawn_owned_sim_i2c_service(1, source1.clone(), (0x50..=0x57).collect()),
                _ => unreachable!(),
            }
            .map_err(|error| std::io::Error::other(error.to_string()))
        };
        (
            services,
            Self {
                a,
                b,
                wire,
                opener_calls,
            },
        )
    }
    pub fn opener_calls(&self) -> Vec<u8> {
        self.opener_calls.lock().unwrap().clone()
    }
    pub fn original_service_identities(&self) -> (Option<usize>, Option<usize>) {
        (self.wire.service_identity(), self.b.service_identity())
    }
    pub fn pic_events(&self) -> Vec<PicEvent> {
        self.wire
            .events()
            .into_iter()
            .map(|event| PicEvent {
                at: event.at,
                address: event.address,
                opcode: event.opcode,
                write: event.write,
                bytes: event.bytes,
            })
            .collect()
    }
    pub fn fail_bridge_final_read(&self) {
        self.wire.fail_bridge_final_read();
    }
    pub fn block_bridge_final_read(&self) {
        self.wire.block_bridge_final_read();
    }
    pub fn block_initial_disable_final_read(&self) {
        let _ = self.wire.block_second_disable_read();
    }
    pub async fn wait_bridge_entered(&self) {
        self.wire.wait_bridge_entered().await;
    }
    pub async fn wait_initial_disable_entered(&self) {
        self.wire.wait_disable_entered().await;
    }

    pub fn apw_opcodes(&self) -> Vec<u8> {
        self.b.opcodes()
    }
    pub fn bus0_events(&self) -> usize {
        self.a.trace().len() + self.wire.events().len()
    }
    pub async fn wait_apw_entered(&self) {
        self.b.wait_entered().await;
    }
    pub fn release(&self) {
        self.a.release();
        self.b.release();
        self.wire.release();
    }
    pub fn fail_heartbeat_payload(&self) {
        self.wire.fail_heartbeat();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.release();
    }
}
