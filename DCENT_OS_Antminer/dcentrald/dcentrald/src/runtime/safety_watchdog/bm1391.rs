//! Exact C501/BM1391 watchdog composition and a retained fixed actor roster.
//! GPIO/PIC/engine observations retain their HAL owner and original deadline;
//! source-control observations are not measurements of hashboard rail voltage.
use super::*;
use crate::runtime::task_guard::RuntimeTaskGuard;
use dcentrald_hal::platform::stock_bm1391::{NativeMmio, TerminalControlsReceipt, Transport};
use dcentrald_hal::platform::{
    HardwareMutationBarrierReceipt, HardwareMutationCommitFenceReceipt,
    HardwareMutationCommitFenceTryWait, HardwareMutationGate, HardwareMutationGateOwner,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
pub(crate) enum Bm1391ActorSlot {
    Heartbeats,
    Health,
    Stratum,
    ApiServer,
    ApiState,
}
impl Bm1391ActorSlot {
    fn index(self) -> usize {
        self as usize
    }
    fn name(self) -> &'static str {
        match self {
            Self::Heartbeats => "bm1391-heartbeats",
            Self::Health => "bm1391-health",
            Self::Stratum => "bm1391-stratum",
            Self::ApiServer => "bm1391-api-server",
            Self::ApiState => "bm1391-api-state",
        }
    }
}

pub(crate) struct Bm1391Actors {
    inner: RuntimeTaskGuard,
    scope: WatchdogRunScope,
    issuer: Arc<()>,
    started: [bool; 5],
    closed: bool,
}
pub(crate) struct Bm1391ActorsClosed {
    scope: WatchdogRunScope,
    issuer: Arc<()>,
    finished_at: Instant,
}
impl Bm1391Actors {
    pub(crate) fn require_started_running(&self) -> Result<()> {
        anyhow::ensure!(
            !self.closed && self.started.iter().any(|started| *started) && self.inner.all_running(),
            "BM1391 started actor roster is empty, closed or exited"
        );
        Ok(())
    }
    pub(crate) fn require_running(&self) -> Result<()> {
        anyhow::ensure!(
            !self.closed && self.started.iter().all(|started| *started) && self.inner.all_running(),
            "BM1391 runtime actor roster is incomplete, closed or exited"
        );
        Ok(())
    }
    fn new(scope: WatchdogRunScope, issuer: Arc<()>, cancellation: CancellationToken) -> Self {
        Self {
            inner: RuntimeTaskGuard::new(cancellation),
            scope,
            issuer,
            started: [false; 5],
            closed: false,
        }
    }
    pub(crate) fn spawn<F>(&mut self, slot: Bm1391ActorSlot, future: F) -> Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        anyhow::ensure!(
            !self.closed && !self.started[slot.index()],
            "BM1391 actor slot already started or closed"
        );
        anyhow::ensure!(
            self.inner.spawn(slot.name(), future),
            "BM1391 actor registration rejected"
        );
        self.started[slot.index()] = true;
        Ok(())
    }
    pub(crate) fn request_stop(&self) {
        self.inner.request_stop();
    }
    /// A rejected adoption leaves the actual task handle with its caller.
    pub(crate) fn adopt(
        &mut self,
        slot: Bm1391ActorSlot,
        handle: tokio::task::JoinHandle<()>,
    ) -> std::result::Result<(), tokio::task::JoinHandle<()>> {
        if self.closed || self.started[slot.index()] {
            return Err(handle);
        }
        self.inner.adopt(slot.name(), handle)?;
        self.started[slot.index()] = true;
        Ok(())
    }
    pub(crate) async fn close_until(&mut self, deadline: Instant) -> Result<Bm1391ActorsClosed> {
        anyhow::ensure!(!self.closed, "BM1391 actor closeout is one-shot");
        self.closed = true;
        let summary = self.inner.stop_and_join_until(deadline).await;
        anyhow::ensure!(
            !summary.any_timed_out() && !summary.any_panicked(),
            "BM1391 actor termination was incomplete or panicked"
        );
        let finished_at = Instant::now();
        anyhow::ensure!(
            finished_at < deadline,
            "BM1391 actor closeout completed late"
        );
        Ok(Bm1391ActorsClosed {
            scope: self.scope.clone(),
            issuer: self.issuer.clone(),
            finished_at,
        })
    }
}

pub(crate) struct Bm1391WatchdogRouteScope {
    scope: WatchdogRunScope,
    transport: Arc<Transport<NativeMmio>>,
    actors: Arc<()>,
    api: Arc<HardwareMutationGateOwner>,
    api_issuer: Arc<()>,
    api_closed: std::sync::atomic::AtomicBool,
}
/// Generic HAL API receipts contain no issuer identity. This private wrapper
/// can only be issued by closing the API gate created by this exact route.
pub(crate) struct Bm1391ApiClosed {
    issuer: Arc<()>,
    _owner: Arc<HardwareMutationGateOwner>,
    drain: HardwareMutationBarrierReceipt,
    commit: HardwareMutationCommitFenceReceipt,
}
impl Bm1391ApiClosed {
    fn validate(
        &self,
        issuer: &Arc<()>,
        budget: &TeardownBudgetView,
        cut_attempt: Instant,
    ) -> Result<()> {
        anyhow::ensure!(
            Arc::ptr_eq(&self.issuer, issuer),
            "BM1391 API closeout belongs to another route gate"
        );
        require_mutation_barrier("BM1391 API drain", &self.drain)?;
        require_mutation_barrier("BM1391 API final commit", &self.commit)?;
        anyhow::ensure!(
            self.commit.fenced_at() <= cut_attempt,
            "BM1391 API final commit fence must precede the observed terminal cut attempt"
        );
        budget.require_completed_at(
            TeardownStage::CleanupComplete,
            self.drain.closed_and_drained_at(),
        )?;
        budget.require_completed_at(TeardownStage::CleanupComplete, self.commit.fenced_at())?;
        Ok(())
    }
}
async fn close_api_owner(
    owner: Arc<HardwareMutationGateOwner>,
    issuer: Arc<()>,
    deadline: Instant,
) -> Result<Bm1391ApiClosed> {
    // Revoke synchronously before any await. Final-commit polling never admits
    // new work or makes the caller's original deadline relative again.
    let mut revoked = owner.revoke_commit_fence();
    let commit = loop {
        anyhow::ensure!(Instant::now() < deadline, "BM1391 API commit fence expired");
        match revoked.try_wait() {
            HardwareMutationCommitFenceTryWait::Fenced(receipt) => break receipt,
            HardwareMutationCommitFenceTryWait::Pending(next) => revoked = next,
        }
        tokio::time::sleep_until(tokio::time::Instant::from_std(
            (Instant::now() + Duration::from_millis(1)).min(deadline),
        ))
        .await;
    };
    let task_owner = owner.clone();
    let drain = tokio::task::spawn_blocking(move || task_owner.close_and_drain_until(deadline))
        .await
        .context("BM1391 API drain worker failed")??;
    anyhow::ensure!(Instant::now() < deadline, "BM1391 API drain completed late");
    Ok(Bm1391ApiClosed {
        issuer,
        _owner: owner,
        drain,
        commit,
    })
}
impl Bm1391WatchdogRouteScope {
    pub(crate) fn api_gate(&self) -> HardwareMutationGate {
        self.api.gate()
    }
    /// Close this route's actual API gate. Its initial state remains pending:
    /// no generic API producer can independently admit hardware mutations.
    /// Caller must still attempt prompt independent cutoff when this fails;
    /// delayed API fencing never grants permission to defer that first cut.
    pub(crate) async fn close_api_until(&self, deadline: Instant) -> Result<Bm1391ApiClosed> {
        anyhow::ensure!(
            !self
                .api_closed
                .swap(true, std::sync::atomic::Ordering::SeqCst),
            "BM1391 route API closeout is one-shot"
        );
        close_api_owner(self.api.clone(), self.api_issuer.clone(), deadline).await
    }
}
pub(crate) struct Bm1391WatchdogShutdownManifest {
    route: Bm1391WatchdogRouteScope,
    api: Bm1391ApiClosed,
    controls: TerminalControlsReceipt<NativeMmio>,
    actors: Bm1391ActorsClosed,
    budget: TeardownBudgetView,
    teardown: TeardownDisarmAuthority,
}
impl Bm1391WatchdogShutdownManifest {
    pub(crate) fn new(
        route: Bm1391WatchdogRouteScope,
        api: Bm1391ApiClosed,
        controls: TerminalControlsReceipt<NativeMmio>,
        actors: Bm1391ActorsClosed,
        budget: TeardownBudgetView,
        teardown: TeardownDisarmAuthority,
    ) -> Self {
        Self {
            route,
            api,
            controls,
            actors,
            budget,
            teardown,
        }
    }
    fn into_validated_parts(self) -> Result<(WatchdogRunScope, TeardownDisarmAuthority)> {
        anyhow::ensure!(
            self.budget.same_budget(&self.teardown),
            "BM1391 closeout belongs to another teardown budget"
        );
        anyhow::ensure!(
            self.controls.same_owner(&self.route.transport),
            "BM1391 controls belong to another native transport"
        );
        anyhow::ensure!(
            self.controls.controls_completed(),
            "BM1391 GPIO/PIC/engine/drain observations are incomplete"
        );
        anyhow::ensure!(
            self.actors.scope.same_run(&self.route.scope)
                && Arc::ptr_eq(&self.actors.issuer, &self.route.actors),
            "BM1391 actors belong to another watchdog run or roster"
        );
        let cut_attempt = self
            .controls
            .cutoff_attempted_at()
            .context("BM1391 GPIO worker has no cut-attempt timestamp")?;
        self.api
            .validate(&self.route.api_issuer, &self.budget, cut_attempt)?;
        self.budget
            .require_completed_at(TeardownStage::CutoffStart, cut_attempt)?;
        self.budget.require_completed_at(
            TeardownStage::CutoffComplete,
            self.controls
                .cutoff_observed_at()
                .context("BM1391 independent cutoff has no observation")?,
        )?;
        for at in [self.controls.finished_at(), self.actors.finished_at] {
            self.budget
                .require_completed_at(TeardownStage::CleanupComplete, at)?;
        }
        Ok((self.route.scope, self.teardown))
    }
}
impl WatchdogDisarmPermit {
    pub(crate) fn from_bm1391_manifest(manifest: Bm1391WatchdogShutdownManifest) -> Result<Self> {
        let (scope, teardown) = manifest.into_validated_parts()?;
        Ok(Self {
            scope,
            composition: WatchdogComposition::Bm1391Native,
            teardown: WatchdogTeardownAuthority::Absolute(teardown),
        })
    }
}
impl SafetyWatchdogOwner {
    pub(crate) fn claim_bm1391_route_scope(
        &mut self,
        transport: Arc<Transport<NativeMmio>>,
        cancellation: CancellationToken,
    ) -> Result<(Bm1391WatchdogRouteScope, Bm1391Actors)> {
        let scope = self.claim_composition(WatchdogComposition::Bm1391Native)?;
        let actors = Arc::new(());
        let roster = Bm1391Actors::new(scope.clone(), actors.clone(), cancellation);
        Ok((
            Bm1391WatchdogRouteScope {
                scope,
                transport,
                actors,
                api: Arc::new(HardwareMutationGateOwner::new_pending()),
                api_issuer: Arc::new(()),
                api_closed: std::sync::atomic::AtomicBool::new(false),
            },
            roster,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn actor_liveness_distinguishes_partial_startup_and_full_roster_then_rejects_exit() {
        let stop = CancellationToken::new();
        let mut actors = Bm1391Actors::new(WatchdogRunScope::new(), Arc::new(()), stop.clone());
        assert!(actors.require_started_running().is_err());
        let release = Arc::new(tokio::sync::Notify::new());
        let wake = release.clone();
        actors
            .spawn(Bm1391ActorSlot::Heartbeats, async move {
                wake.notified().await;
            })
            .unwrap();
        actors.require_started_running().unwrap();
        assert!(actors.require_running().is_err());
        for slot in [
            Bm1391ActorSlot::Health,
            Bm1391ActorSlot::Stratum,
            Bm1391ActorSlot::ApiServer,
            Bm1391ActorSlot::ApiState,
        ] {
            let stopped = stop.clone();
            actors
                .spawn(slot, async move {
                    stopped.cancelled().await;
                })
                .unwrap();
        }
        actors.require_running().unwrap();
        release.notify_one();
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(actors.require_started_running().is_err());
        assert!(actors.require_running().is_err());
        actors
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn api_task_adoption_retains_original_handles_and_returns_rejected_custody() {
        let stop = CancellationToken::new();
        let mut actors = Bm1391Actors::new(WatchdogRunScope::new(), Arc::new(()), stop.clone());
        let task_stop = stop.clone();
        let original = tokio::spawn(async move {
            task_stop.cancelled().await;
        });
        actors.adopt(Bm1391ActorSlot::ApiServer, original).unwrap();
        let rejected = tokio::spawn(std::future::pending::<()>());
        let rejected = actors
            .adopt(Bm1391ActorSlot::ApiServer, rejected)
            .unwrap_err();
        assert!(!rejected.is_finished());
        rejected.abort();
        assert!(rejected.await.unwrap_err().is_cancelled());
        actors
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn foreign_same_generation_api_gate_and_post_cut_fence_cannot_authorize() {
        let scope = WatchdogRunScope::new();
        let (mut issuer, _) = issue_teardown_budget_authority(scope);
        let budget = issuer
            .issue_at(Instant::now(), TeardownBudgetPolicy::watchdog_default())
            .unwrap();
        let view = budget.view();
        let actual = Arc::new(HardwareMutationGateOwner::new_pending());
        actual.open().unwrap();
        let actual_issuer = Arc::new(());
        let foreign = Arc::new(HardwareMutationGateOwner::new_pending());
        foreign.open().unwrap();
        let foreign_receipt = close_api_owner(
            foreign,
            Arc::new(()),
            view.deadline(TeardownStage::CutoffStart),
        )
        .await
        .unwrap();
        assert!(actual.gate().try_acquire().is_ok());
        assert!(foreign_receipt
            .validate(&actual_issuer, &view, Instant::now())
            .is_err());
        let receipt = close_api_owner(
            actual.clone(),
            actual_issuer.clone(),
            view.deadline(TeardownStage::CutoffStart),
        )
        .await
        .unwrap();
        assert_eq!(
            foreign_receipt.drain.closed_generation(),
            receipt.drain.closed_generation()
        );
        assert!(actual.gate().try_acquire().is_err());
        let before_fence = receipt.commit.fenced_at() - Duration::from_nanos(1);
        assert!(receipt
            .validate(&actual_issuer, &view, before_fence)
            .is_err());
        receipt
            .validate(&actual_issuer, &view, Instant::now())
            .unwrap();
    }

    #[tokio::test]
    async fn outstanding_api_lease_cannot_produce_a_completed_gate_wrapper() {
        let owner = Arc::new(HardwareMutationGateOwner::new_pending());
        owner.open().unwrap();
        let lease = owner.gate().try_acquire().unwrap();
        assert!(close_api_owner(
            owner.clone(),
            Arc::new(()),
            Instant::now() + Duration::from_millis(20)
        )
        .await
        .is_err());
        assert!(owner.gate().try_acquire().is_err());
        assert!(lease.commit(|| Ok(())).is_err());
        drop(lease);
    }

    #[tokio::test]
    async fn fixed_roster_rejects_duplicates_and_retains_one_run_bound_closeout() {
        let scope = WatchdogRunScope::new();
        let issuer = Arc::new(());
        let cancellation = CancellationToken::new();
        let mut actors = Bm1391Actors::new(scope.clone(), issuer.clone(), cancellation.clone());
        for slot in [
            Bm1391ActorSlot::Heartbeats,
            Bm1391ActorSlot::Health,
            Bm1391ActorSlot::Stratum,
            Bm1391ActorSlot::ApiServer,
            Bm1391ActorSlot::ApiState,
        ] {
            let stop = cancellation.clone();
            actors
                .spawn(slot, async move {
                    stop.cancelled().await;
                })
                .unwrap();
            assert!(actors.spawn(slot, async {}).is_err());
        }
        let receipt = actors
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        assert!(receipt.scope.same_run(&scope));
        assert!(Arc::ptr_eq(&receipt.issuer, &issuer));
        assert!(!receipt.scope.same_run(&WatchdogRunScope::new()));
        assert!(actors
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
        assert!(actors.spawn(Bm1391ActorSlot::Health, async {}).is_err());
    }
    #[tokio::test]
    async fn late_or_panicked_actor_roster_has_no_closeout_receipt() {
        let mut late = Bm1391Actors::new(
            WatchdogRunScope::new(),
            Arc::new(()),
            CancellationToken::new(),
        );
        assert!(late.close_until(Instant::now()).await.is_err());
        let mut panicked = Bm1391Actors::new(
            WatchdogRunScope::new(),
            Arc::new(()),
            CancellationToken::new(),
        );
        panicked
            .spawn(Bm1391ActorSlot::Heartbeats, async {
                panic!("actor fault fixture")
            })
            .unwrap();
        assert!(panicked
            .close_until(Instant::now() + Duration::from_secs(1))
            .await
            .is_err());
    }
    #[test]
    fn bm1391_composition_is_exclusive_with_other_native_routes() {
        let mut owner = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        owner
            .claim_composition(WatchdogComposition::Bm1391Native)
            .unwrap();
        assert!(owner.claim_c43_route_scope().is_err());
        assert!(owner.claim_s17_route_scope().is_err());
        assert!(owner.claim_bm1398_route_scope().is_err());
        let mut foreign = SafetyWatchdogOwner::inert_for_pre_hardware_test();
        foreign.claim_c43_route_scope().unwrap();
        assert!(foreign
            .claim_composition(WatchdogComposition::Bm1391Native)
            .is_err());
    }
}
