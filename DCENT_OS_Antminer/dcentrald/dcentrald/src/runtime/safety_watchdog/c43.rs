//! C43/BM1393 shutdown uses the retained stock-FPGA IIC owner.
//! Its terminal receipt is not interchangeable with the kernel I2C service.
use super::*;

pub(crate) struct C43WatchdogRouteScope {
    scope: WatchdogRunScope,
}

pub(crate) struct C43WatchdogShutdownManifest {
    route_scope: C43WatchdogRouteScope,
    api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
    api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
    fabric: dcentrald_hal::platform::c43_bm1393::C43TerminalBarrierReceipt,
    safe_off: crate::c43_bm1393_mining::C43SafeOffEvidence,
    teardown: TeardownDisarmAuthority,
}

impl C43WatchdogShutdownManifest {
    pub(crate) fn new(
        route_scope: C43WatchdogRouteScope,
        api_drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
        api_final_commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
        fabric: dcentrald_hal::platform::c43_bm1393::C43TerminalBarrierReceipt,
        safe_off: crate::c43_bm1393_mining::C43SafeOffEvidence,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route_scope,
            api_drain,
            api_final_commit,
            fabric,
            safe_off,
            teardown,
        }
    }

    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        require_mutation_barrier("C43 API drain", &self.api_drain)?;
        require_mutation_barrier("C43 API final commit", &self.api_final_commit)?;
        anyhow::ensure!(
            self.fabric.completed(),
            "C43 retained transport has not reached its terminal barrier"
        );
        anyhow::ensure!(
            self.safe_off.same_owner(&self.fabric),
            "C43 power cutoff and transport barrier belong to different owners"
        );
        validate_c43_safe_off(&self.safe_off, &self.teardown)?;
        Ok((self.route_scope.scope, self.teardown))
    }
}

fn validate_c43_safe_off(
    evidence: &crate::c43_bm1393_mining::C43SafeOffEvidence,
    teardown: &TeardownDisarmAuthority,
) -> Result<()> {
    anyhow::ensure!(
        evidence.completed(),
        "C43 reset/PIC cutoff, transport drain or actor closeout incomplete"
    );
    anyhow::ensure!(
        evidence.same_teardown_budget(teardown),
        "C43 cutoff evidence belongs to another watchdog teardown budget"
    );
    Ok(())
}

impl WatchdogDisarmPermit {
    pub(crate) fn from_c43_manifest(manifest: C43WatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::C43Native,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }
}

impl SafetyWatchdogOwner {
    pub(crate) fn claim_c43_route_scope(&mut self) -> Result<C43WatchdogRouteScope> {
        Ok(C43WatchdogRouteScope {
            scope: self.claim_composition(WatchdogComposition::C43Native)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c43_route_scope_cannot_reuse_another_runtime_owner() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        owner.claim_c43_route_scope().unwrap();
        assert!(owner.claim_c43_route_scope().is_err());
        assert!(owner.claim_s17_route_scope().is_err());
        assert!(owner.claim_bm1398_route_scope().is_err());
        let mut foreign = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        foreign.claim_s17_route_scope().unwrap();
        assert!(foreign.claim_c43_route_scope().is_err());
    }
}
