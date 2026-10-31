//! Preissued startup claims for exact native/outer workflow operations.
//! No reserve, fake adoption, numeric receipt, retry, or fallback exists here.
use super::*;
use super::super::workflow_transition::RetiredSourceSession;
use crate::execution::retained_resources::Requirements;
use std::time::Instant;

/// Pure source plan; its private StartupPlan is source-derived, not supplied
/// numeric authority. The original claim and actual retired source are needed
/// before any environment/device selection or new runtime construction.
pub(crate) struct WorkflowRuntimePlan {
    plan: core::StartupPlan,
    limits: Limits,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct StartupTiming {
    pub elapsed_ns: u128,
    pub succeeded: bool,
    pub retained_tree_host_bytes: usize,
}

pub(crate) struct PendingWorkflowRuntime<'source, 'context> {
    source: &'source RetiredSourceSession<'context>,
    pending: PendingRuntime,
}

fn same_limits(a: Limits, b: Limits) -> bool {
    a.host_bytes == b.host_bytes && a.device_bytes == b.device_bytes && a.max_rows == b.max_rows
}

fn same_device(a: &lattica_prover_p3::gpu_device::Identity, b: &lattica_prover_p3::gpu_device::Identity) -> bool {
    a.opencl_index == b.opencl_index && a.uuid == b.uuid && a.name == b.name
        && a.pci == b.pci && a.global_bytes == b.global_bytes
        && a.max_allocation_bytes == b.max_allocation_bytes && a.driver == b.driver
}

impl WorkflowRuntimePlan {
    /// Pure source census for closure planning. No source Session, environment
    /// selection or runtime exists here; the typed issuer later matches this
    /// exact requirement against the plan for the actual retired source limits.
    pub(crate) fn outer_host_v1_requirement() -> Result<Requirements, RuntimeError> {
        let plan = core::StartupPlan::outer_host_v1().map_err(|_| RuntimeError::Configuration)?;
        Ok(Requirements::single(Category::PhaseScratch, requested(&plan)?))
    }

    pub(crate) fn device(limits: Limits) -> Result<Self, RuntimeError> {
        Self::new(limits, core::StartupPlan::new().map_err(|_| RuntimeError::Configuration)?)
    }

    pub(crate) fn outer_host_v1(limits: Limits) -> Result<Self, RuntimeError> {
        Self::new(limits, core::StartupPlan::outer_host_v1().map_err(|_| RuntimeError::Configuration)?)
    }

    fn new(limits: Limits, plan: core::StartupPlan) -> Result<Self, RuntimeError> {
        fixed_limits(limits)?;
        if cfg!(debug_assertions) {
            return Err(RuntimeError::Configuration);
        }
        requested(&plan)?;
        Ok(Self { plan, limits })
    }

    pub(crate) fn requirement(&self) -> Result<Requirements, RuntimeError> {
        Ok(Requirements::single(Category::PhaseScratch, requested(&self.plan)?))
    }

    /// Transfer the original startup partition while borrowing the exact
    /// retired source Session. Refusal destroys plan data before returning the
    /// untouched claim; no runtime or selection has been constructed yet.
    pub(crate) fn claim<'source, 'context>(
        self,
        original: Reservation,
        ledger: &Ledger,
        source: &'source RetiredSourceSession<'context>,
    ) -> Result<PendingWorkflowRuntime<'source, 'context>, (RuntimeError, Reservation)> {
        let checked = (|| {
            let allowance = ledger.snapshot().allowance;
            if allowance.host == 0 || allowance.host != self.limits.host_bytes
                || allowance.device != MANAGED_DEVICE
                || !same_limits(self.limits, source.limits())
            {
                return Err(RuntimeError::Configuration);
            }
            if !original.belongs_to(ledger) {
                return Err(RuntimeError::WrongLedger);
            }
            if original.requirements() != self.requirement()? {
                return Err(RuntimeError::Admission);
            }
            Ok(())
        })();
        if let Err(error) = checked {
            drop(self);
            return Err((error, original));
        }
        Ok(PendingWorkflowRuntime {
            source,
            pending: PendingRuntime { selection: None, plan: self.plan, limits: self.limits, reservation: original },
        })
    }
}

impl PendingWorkflowRuntime<'_, '_> {
    pub(crate) fn reservation(&self) -> &Reservation { &self.pending.reservation }

    /// # Safety
    /// The closed typed workflow issuer holds the same serialized immutable
    /// process/environment contract required by PendingRuntime::preflight.
    pub(crate) unsafe fn preflight(&mut self) -> Result<PendingRuntimeGuard<'_>, RuntimeError> {
        // SAFETY: forwards the caller's sealed-process contract.
        unsafe { self.pending.preflight() }
    }

    /// Cancel before startup only. Selection metadata dies before its original
    /// claim is returned. The enclosing operation must fail permanently.
    pub(crate) fn into_unstarted_original(self) -> Reservation {
        let PendingRuntime { selection, plan, limits: _, reservation } = self.pending;
        drop(selection);
        drop(plan);
        reservation
    }

    /// # Safety
    /// Exact typed operation only. Original preparation/backend/output claims
    /// already exist; exclude environment mutation and unrelated GPU work from
    /// preflight through actual Runtime destruction. A refused start is
    /// terminal: the returned original is for restoration, never another try.
    pub(crate) unsafe fn start_preserving(mut self) -> Result<
        (Session, StartupTiming),
        (RuntimeError, StartupTiming, Reservation),
    > {
        let started = Instant::now();
        let tree = self.pending.plan.footprint().retained_tree_host_bytes;
        let fail = |error, pending: Self| {
            let original = pending.into_unstarted_original();
            (error, StartupTiming { elapsed_ns: started.elapsed().as_nanos(), succeeded: false,
                retained_tree_host_bytes: tree }, original)
        };
        // SAFETY: the method's sealed-process contract is forwarded unchanged.
        let checked = unsafe { self.pending.preflight() }.map(|_guard| ());
        if let Err(error) = checked {
            return Err(fail(error, self));
        }
        let active = match ActiveStart::claim() {
            Ok(active) => active,
            Err(error) => return Err(fail(error, self)),
        };
        let selection = self.pending.selection.take().expect("successful original preflight");
        let runtime = match selection.start() {
            Ok(runtime) => runtime,
            // Selection::start destroys any partial owned epoch before Err;
            // uncertain retirement aborts rather than releasing original quota.
            Err(_) => return Err(fail(RuntimeError::Initialization, self)),
        };
        if !same_device(runtime.identity(), self.source.device_identity()) {
            drop(runtime);
            return Err(fail(RuntimeError::Selection, self));
        }
        let device = runtime.identity().clone();
        let max_work_group_size = runtime.maximum_work_group_size();
        let PendingRuntime { selection, plan, limits, reservation } = self.pending;
        drop(selection);
        drop(plan);
        let session = Session {
            limits,
            device,
            max_work_group_size,
            context_bytes: CONTEXT_DEVICE,
            closed: false,
            workflow_transition: super::super::workflow_transition::State::new(),
            _thread: PhantomData,
            runtime_lifetime: Some(RuntimeLifetime { runtime: RefCell::new(runtime), reservation }),
        };
        active.disarm();
        Ok((session, StartupTiming { elapsed_ns: started.elapsed().as_nanos(), succeeded: true,
            retained_tree_host_bytes: tree }))
    }
}

pub(super) fn additional_host_bytes() -> usize {
    4 * size_of::<WorkflowRuntimePlan>()
        + 4 * size_of::<PendingWorkflowRuntime<'static, 'static>>()
        + 8 * size_of::<StartupTiming>()
        + 4 * size_of::<Result<(Session, StartupTiming), (RuntimeError, StartupTiming, Reservation)>>()
        + 4 * size_of::<Result<PendingWorkflowRuntime<'static, 'static>, (RuntimeError, Reservation)>>()
}

#[cfg(all(test, not(debug_assertions)))]
mod tests {
    use super::*;

    #[test]
    fn workflow_startup_is_exact_fixed_source_and_host_tree_delta_is_additive() {
        let limits = Limits { host_bytes: WORKER_HOST, device_bytes: MANAGED_DEVICE, max_rows: MAX_ROWS };
        let device = WorkflowRuntimePlan::device(limits).unwrap().requirement().unwrap();
        let host = WorkflowRuntimePlan::outer_host_v1(limits).unwrap().requirement().unwrap();
        assert_eq!(device.get(Category::PhaseScratch).device, host.get(Category::PhaseScratch).device);
        assert!(host.get(Category::PhaseScratch).host >= device.get(Category::PhaseScratch).host + (8 << 30));
        for category in Category::ALL {
            if category != Category::PhaseScratch {
                assert_eq!(device.get(category), Bytes::ZERO);
                assert_eq!(host.get(category), Bytes::ZERO);
            }
        }
        assert!(WorkflowRuntimePlan::device(Limits { host_bytes: WORKER_HOST - 1, ..limits }).is_err());
        assert!(WorkflowRuntimePlan::device(Limits { device_bytes: MANAGED_DEVICE - 1, ..limits }).is_err());
    }
}
