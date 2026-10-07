//! Test-only access to real final slots; release builds do not compile this child.
use super::*;

impl<H: Hardware> PicApplication<H> {
    /// A fixture observer is allowed to skip a currently held slot. It cannot
    /// wait inside owner validation, which is called by guarded source checks.
    pub(in crate::platform::stock_bm1396) fn test_final_pll_gate_ready(
        &self,
    ) -> Result<bool, String> {
        match self.prepared_final.try_lock() {
            Err(TryLockError::WouldBlock) => Ok(false),
            Err(TryLockError::Poisoned(_)) => Err("fixture final admission poisoned".into()),
            Ok(admission) => match self.final_pll.try_lock() {
                Err(TryLockError::WouldBlock) => Ok(false),
                Err(TryLockError::Poisoned(_)) => Err("fixture final observation poisoned".into()),
                Ok(retained) => Ok(admission.is_some()
                    && retained.as_ref().is_some_and(|row| {
                        row.completed_at().is_none()
                            && row.stages().len() == 5
                            && row
                                .stages()
                                .iter()
                                .all(|stage| stage.settled_at().is_some())
                            && !row.thermal_snapshots().is_empty()
                    })),
            },
        }
    }

    /// The caller is a real counted ASIC receiver, using the actual owner check.
    /// Exercise both recursive-lock hazards separately without fabricated state.
    pub(in crate::platform::stock_bm1396) fn test_owner_check_with_final_slots_held(
        &self,
        check: impl Fn() -> Result<(), String>,
    ) -> Result<(), String> {
        {
            let _admission = self
                .prepared_final
                .lock()
                .map_err(|_| "fixture admission poisoned")?;
            check()?;
        }
        {
            let _retained = self
                .final_pll
                .lock()
                .map_err(|_| "fixture observation poisoned")?;
            check()?;
        }
        Ok(())
    }
}
