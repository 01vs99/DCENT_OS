//! Dedicated classic AML watchdog/actor composition. Its PIC, protected
//! identity, GPIO PSU and all UARTs cannot inherit AM2 or NoPic closeout proof.
use super::*;
use crate::runtime::task_guard::RuntimeTaskGuard;
use dcentrald_hal::platform::amlogic::classic_pic::{
    ClassicAmlPowerOwner, ClassicPowerCloseReport,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
pub(crate) enum ClassicAmlActorSlot {
    Health,
    Stratum,
    ApiServer,
    ApiState,
}
impl ClassicAmlActorSlot {
    fn name(self) -> &'static str {
        match self {
            Self::Health => "classic-aml-health",
            Self::Stratum => "classic-aml-stratum",
            Self::ApiServer => "classic-aml-api-server",
            Self::ApiState => "classic-aml-api-state",
        }
    }
}
pub(crate) struct ClassicAmlActors {
    inner: RuntimeTaskGuard,
    scope: WatchdogRunScope,
    issuer: Arc<()>,
    started: [bool; 4],
    closed: bool,
}
pub(crate) struct ClassicAmlActorsClosed {
    scope: WatchdogRunScope,
    issuer: Arc<()>,
    at: Instant,
}
impl ClassicAmlActors {
    pub(crate) fn adopt(
        &mut self,
        slot: ClassicAmlActorSlot,
        task: tokio::task::JoinHandle<()>,
    ) -> std::result::Result<(), tokio::task::JoinHandle<()>> {
        if self.closed || self.started[slot as usize] {
            return Err(task);
        }
        self.inner.adopt(slot.name(), task)?;
        self.started[slot as usize] = true;
        Ok(())
    }
    pub(crate) fn spawn<F>(&mut self, slot: ClassicAmlActorSlot, future: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        anyhow::ensure!(
            !self.closed && !self.started[slot as usize],
            "classic actor slot already started or closed"
        );
        anyhow::ensure!(
            self.inner.spawn(slot.name(), future),
            "classic actor registration refused"
        );
        self.started[slot as usize] = true;
        Ok(())
    }
    pub(crate) fn require_complete(&self) -> Result<()> {
        anyhow::ensure!(
            !self.closed && self.started.iter().all(|s| *s),
            "classic mining requires every registered actor"
        );
        Ok(())
    }
    pub(crate) fn request_stop(&self) {
        self.inner.request_stop();
    }
    pub(crate) fn require_running(&self) -> Result<()> {
        self.require_complete()?;
        anyhow::ensure!(
            self.inner.all_running(),
            "classic runtime actor exited unexpectedly"
        );
        Ok(())
    }
    pub(crate) async fn close_until(
        &mut self,
        deadline: Instant,
    ) -> Result<ClassicAmlActorsClosed> {
        anyhow::ensure!(!self.closed, "classic actor closeout already consumed");
        self.closed = true;
        let result = self.inner.stop_and_join_until(deadline).await;
        anyhow::ensure!(
            !result.any_timed_out() && !result.any_panicked() && Instant::now() < deadline,
            "classic actors failed to quiesce before deadline"
        );
        Ok(ClassicAmlActorsClosed {
            scope: self.scope.clone(),
            issuer: self.issuer.clone(),
            at: Instant::now(),
        })
    }
}
pub(crate) struct ClassicAmlWatchdogRouteScope {
    scope: WatchdogRunScope,
    actors: Arc<()>,
    power: Option<Arc<ClassicAmlPowerOwner>>,
    api: Option<dcentrald_hal::platform::HardwareMutationGateOwner>,
    api_issuer: Arc<()>,
}
pub(crate) struct ClassicAmlApiClosed {
    scope: WatchdogRunScope,
    issuer: Arc<()>,
    drain: dcentrald_hal::platform::HardwareMutationBarrierReceipt,
    commit: dcentrald_hal::platform::HardwareMutationCommitFenceReceipt,
}
impl ClassicAmlApiClosed {
    fn require_route(
        &self,
        route: &ClassicAmlWatchdogRouteScope,
        cutoff_started: Instant,
    ) -> Result<()> {
        anyhow::ensure!(
            self.scope.same_run(&route.scope) && Arc::ptr_eq(&self.issuer, &route.api_issuer),
            "classic API closeout belongs to another route/gate owner"
        );
        require_mutation_barrier("classic API drain", &self.drain)?;
        require_mutation_barrier("classic API commit fence", &self.commit)?;
        anyhow::ensure!(
            self.commit.fenced_at() <= cutoff_started,
            "classic final API commit fence was observed after physical cutoff began"
        );
        Ok(())
    }
}
impl ClassicAmlWatchdogRouteScope {
    pub(crate) fn api_gate(&self) -> Result<dcentrald_hal::platform::HardwareMutationGate> {
        Ok(self
            .api
            .as_ref()
            .context("classic API owner already consumed")?
            .gate())
    }
    pub(crate) async fn close_api_at(&mut self, deadline: Instant) -> Result<ClassicAmlApiClosed> {
        let owner = self
            .api
            .take()
            .context("classic API closeout already consumed")?;
        // Revoke synchronously before awaiting anything. The gate stays pending
        // for this initial native runtime; management never owns its opener.
        let revoked = owner.revoke_commit_fence();
        let commit = crate::hardware_mutation_fence::wait_revoked_hardware_mutation_commit_fence(
            revoked,
            tokio::time::Instant::now(),
            deadline.into(),
            "classic API",
        )
        .await?;
        let drain =
            tokio::task::spawn_blocking(move || owner.close_and_drain_until(deadline)).await??;
        Ok(ClassicAmlApiClosed {
            scope: self.scope.clone(),
            issuer: self.api_issuer.clone(),
            drain,
            commit,
        })
    }

    pub(crate) fn bind_power(&mut self, power: Arc<ClassicAmlPowerOwner>) -> Result<()> {
        anyhow::ensure!(self.power.is_none(), "classic power owner already bound");
        self.power = Some(power);
        Ok(())
    }
    pub(crate) fn serial_scope(&self) -> Result<WatchdogRunScope> {
        anyhow::ensure!(
            self.power.is_some(),
            "classic UART scope requires retained power custody"
        );
        Ok(self.scope.clone())
    }
}
pub(crate) struct ClassicAmlWatchdogShutdownManifest {
    route: ClassicAmlWatchdogRouteScope,
    api: ClassicAmlApiClosed,
    serial: crate::serial_mining::SerialExecutionBarrierReceipt,
    controls: ClassicPowerCloseReport,
    actors: ClassicAmlActorsClosed,
    budget: TeardownBudgetView,
    teardown: TeardownDisarmAuthority,
}
impl ClassicAmlWatchdogShutdownManifest {
    pub(crate) fn new(
        route: ClassicAmlWatchdogRouteScope,
        api: ClassicAmlApiClosed,
        serial: crate::serial_mining::SerialExecutionBarrierReceipt,
        controls: ClassicPowerCloseReport,
        actors: ClassicAmlActorsClosed,
        budget: TeardownBudgetView,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route,
            api,
            serial,
            controls,
            actors,
            budget,
            teardown,
        }
    }
    fn validate(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        let cutoff_started = self
            .controls
            .cutoff_started()
            .context("classic actual GPIO cutoff was not attempted")?;
        self.api.require_route(&self.route, cutoff_started)?;
        // The owner-bound opaque controls report proves both retained I2C
        // workers and the exact raw PSU owner closed. An unrelated generic
        // TerminalSafeOffTransition cannot substitute for those fabrics.
        let serial_at = self.serial.require_classic_scope(&self.route.scope)?;
        anyhow::ensure!(
            self.budget.same_budget(&self.teardown),
            "classic foreign teardown budget"
        );
        let power = self
            .route
            .power
            .as_ref()
            .context("classic closeout has no bound power owner")?;
        anyhow::ensure!(
            self.controls.same_owner(power) && self.controls.software_cleanup_complete(),
            "classic independent cut/retained owner closeout incomplete or foreign"
        );
        anyhow::ensure!(
            self.actors.scope.same_run(&self.route.scope)
                && Arc::ptr_eq(&self.actors.issuer, &self.route.actors),
            "classic actor closeout belongs to another run/roster"
        );
        self.budget
            .require_completed_at(TeardownStage::CutoffStart, cutoff_started)?;
        self.budget.require_completed_at(
            TeardownStage::CutoffComplete,
            self.controls
                .cutoff_observed_at()
                .context("classic raw cutoff observation missing")?,
        )?;
        for at in [
            self.controls.finished_at(),
            self.actors.at,
            serial_at,
            self.api.drain.closed_and_drained_at(),
            self.api.commit.fenced_at(),
        ] {
            self.budget
                .require_completed_at(TeardownStage::CleanupComplete, at)?;
        }
        Ok((self.route.scope, self.teardown))
    }
}
impl SafetyWatchdogOwner {
    pub(crate) async fn enter_classic_aml_mining(
        &mut self,
        route: &ClassicAmlWatchdogRouteScope,
        actors: &ClassicAmlActors,
    ) -> Result<()> {
        anyhow::ensure!(
            self.composition == Some(WatchdogComposition::ClassicAml)
                && self.run_scope.same_run(&route.scope)
                && self.run_scope.same_run(&actors.scope)
                && Arc::ptr_eq(&route.actors, &actors.issuer)
                && route.power.is_some(),
            "classic mining watchdog requires this run's retained route and actor roster"
        );
        actors.require_running()?;
        self.enter_mining_inner().await
    }

    pub(crate) fn claim_classic_aml_route_scope(
        &mut self,
        cancellation: CancellationToken,
    ) -> Result<(ClassicAmlWatchdogRouteScope, ClassicAmlActors)> {
        let scope = self.claim_composition(WatchdogComposition::ClassicAml)?;
        let issuer = Arc::new(());
        Ok((
            ClassicAmlWatchdogRouteScope {
                scope: scope.clone(),
                actors: issuer.clone(),
                power: None,
                api: Some(dcentrald_hal::platform::HardwareMutationGateOwner::new_pending()),
                api_issuer: Arc::new(()),
            },
            ClassicAmlActors {
                inner: RuntimeTaskGuard::new(cancellation),
                scope,
                issuer,
                started: [false; 4],
                closed: false,
            },
        ))
    }
}
impl WatchdogDisarmPermit {
    pub(crate) fn from_classic_aml_manifest(
        manifest: ClassicAmlWatchdogShutdownManifest,
    ) -> Result<Self> {
        let (scope, teardown) = manifest.validate()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::ClassicAml,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn api_closeout_keeps_exact_gate_issuer_and_precedes_cutoff() {
        let mut first = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let mut second = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let (mut route, _) = first
            .claim_classic_aml_route_scope(CancellationToken::new())
            .unwrap();
        let (mut foreign, _) = second
            .claim_classic_aml_route_scope(CancellationToken::new())
            .unwrap();
        // Even same-run/same-generation generic receipts cannot substitute for
        // the retained API gate issuer carried by this private closeout.
        foreign.scope = route.scope.clone();
        let early_cutoff = Instant::now();
        let receipt = route
            .close_api_at(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(receipt.require_route(&route, Instant::now()).is_ok());
        assert!(receipt.require_route(&foreign, Instant::now()).is_err());
        assert!(receipt.require_route(&route, early_cutoff).is_err());
        assert!(route
            .close_api_at(Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
        assert!(route.api_gate().is_err());
    }
    #[tokio::test]
    async fn classic_scope_and_fixed_roster_are_exclusive_and_not_replayable() {
        let mut watchdog = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        let (scope, mut actors) = watchdog
            .claim_classic_aml_route_scope(CancellationToken::new())
            .unwrap();
        assert!(scope.serial_scope().is_err());
        assert!(watchdog
            .claim_classic_aml_route_scope(CancellationToken::new())
            .is_err());
        assert!(watchdog.claim_bm1398_route_scope().is_err());
        assert!(watchdog.claim_s17_route_scope().is_err());
        assert!(actors.require_complete().is_err());
        for slot in [
            ClassicAmlActorSlot::Health,
            ClassicAmlActorSlot::Stratum,
            ClassicAmlActorSlot::ApiServer,
            ClassicAmlActorSlot::ApiState,
        ] {
            actors.spawn(slot, async {}).unwrap();
            assert!(actors.spawn(slot, async {}).is_err());
        }
        actors.require_complete().unwrap();
        let receipt = actors
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(receipt.scope.same_run(&scope.scope));
        assert!(Arc::ptr_eq(&receipt.issuer, &scope.actors));
        assert!(actors.require_complete().is_err());
        assert!(actors
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
    }
}
