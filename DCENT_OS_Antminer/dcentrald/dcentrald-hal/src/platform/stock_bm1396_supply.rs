//! Exact T17e BE088/BDEA8 and S17e BD070/BCE90 readonly supply query.
//! S17e signed-2020 SHA819bd5ee, 5C23C/5C25C independently requires42 and
//! D98DC contains55AA04020600. Both exact profiles use the same wire frame;
//! no controller identity is inferred from a model name or sibling profile.
//! One retained attempt; original nested frame/getter retries are not copied.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyTypeObservation {
    request: [u8; 6],
    transmitted: usize,
    response: Vec<u8>,
    framing_complete: bool,
    admitted_at: Option<Instant>,
}
impl SupplyTypeObservation {
    pub fn request(&self) -> &[u8; 6] {
        &self.request
    }
    pub fn completed_request_bytes(&self) -> usize {
        self.transmitted
    }
    pub fn response(&self) -> &[u8] {
        &self.response
    }
    pub fn framing_complete(&self) -> bool {
        self.framing_complete
    }
    pub fn admitted_at(&self) -> Option<Instant> {
        self.admitted_at
    }
    pub fn admitted_type(&self) -> Option<u8> {
        self.admitted_at.map(|_| self.response[4])
    }
}

impl<H: Hardware> PicApplication<H> {
    pub fn supply_type_observation(&self) -> Result<Option<SupplyTypeObservation>, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "BM1396 PIC state poisoned")?
            .supply_type
            .clone())
    }
    fn supply_update(&self, update: impl FnOnce(&mut SupplyTypeObservation)) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
        update(
            state
                .supply_type
                .as_mut()
                .ok_or("T17e supply-type custody lost")?,
        );
        Ok(())
    }
    pub(super) fn require_supply_type(&self) -> Result<(), String> {
        if self
            .supply_type_observation()?
            .is_some_and(|receipt| receipt.admitted_type() == Some(0x42))
        {
            Ok(())
        } else {
            Err("T17e requires its actual admitted supply-type42 response".into())
        }
    }

    /// Caller retains this application even if the future is cancelled. The
    /// raw attempt is created before the first physical byte and never retried.
    /// A source type is neither a marketing PSU identity nor rail measurement.
    pub async fn observe_supply_type(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<SupplyTypeObservation, String> {
        let app = self.clone();
        self.owner
            .worker(deadline, false, move |owner| {
                let asic = owner.lock(&owner.asic, deadline, false)?;
                let _lane = owner.lock(&owner.management, deadline, false)?;
                owner.query_presence(deadline)?;
                if asic.startup_attempted
                    || !asic.publications.is_empty()
                    || owner.hardware.read(DHASH)? & RUN != 0
                {
                    return Err("T17e supply-type query requires unused cold engine".into());
                }
                let request = [0x55, 0xaa, 0x04, 0x02, 0x06, 0x00];
                {
                    let mut state = app.state.lock().map_err(|_| "BM1396 PIC state poisoned")?;
                    if state.supply_type.is_some() || state.last_voltage.is_some() {
                        return Err(
                            "T17e supply-type query is one-shot before voltage commands".into()
                        );
                    }
                    state.supply_type = Some(SupplyTypeObservation {
                        request,
                        transmitted: 0,
                        response: Vec::with_capacity(8),
                        framing_complete: false,
                        admitted_at: None,
                    });
                }
                let mut fault = FaultGuard::new(&owner.management_fault, &owner.terminal);
                for byte in request {
                    owner.management_byte_locked(0x0520_1100 | u32::from(byte), deadline, false)?;
                    app.supply_update(|receipt| receipt.transmitted += 1)?;
                }
                owner.delay(Duration::from_millis(500), deadline, false)?;
                let mut response = [0; 8];
                for byte in &mut response {
                    *byte = owner.management_byte_locked(0x0620_0000, deadline, false)?;
                    app.supply_update(|receipt| receipt.response.push(*byte))?;
                }
                fault.complete();
                app.supply_update(|receipt| receipt.framing_complete = true)?;
                owner.check(deadline, false)?;
                let checksum = response[2..6]
                    .iter()
                    .map(|&byte| u16::from(byte))
                    .sum::<u16>();
                if response[..4] != [0x55, 0xaa, 6, 2]
                    || u16::from_le_bytes([response[6], response[7]]) != checksum
                    || response[4] != 0x42
                {
                    return Err("T17e supply frame/type rejected by exact source profile".into());
                }
                owner.query_presence(deadline)?;
                owner.check(deadline, false)?;
                app.supply_update(|receipt| receipt.admitted_at = Some(Instant::now()))?;
                app.supply_type_observation()?
                    .ok_or("T17e supply-type custody lost".into())
            })
            .await
    }
}
