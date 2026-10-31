//! Two concrete pre-proof source phases on the original workflow capability.
//! Their outputs retain preissued original claims; no caller-owned payload can
//! be attached to this path after allocation, and no generic executor is public.
use super::{
    owners::{SlotClaim, SlotPool},
    planning::WorkflowPlanning,
    types::{combine, SlotId, SlotSpec, WorkflowError, MAX_NATIVE_BYTES},
};
use crate::{
    execution::{
        phase_lifecycle::Status,
        retained_resources::{Bytes, Category, Ledger, Requirements},
        ProvingContext,
    },
    spend_pipeline::full_workflow::{
        PreparedGraphSources, PreparedWorkflowSources, SourceGraphOperation,
        SourceGraphPlan, SourcePreparationError, SourcePreparationOperation,
        SourcePreparationPlan,
    },
};
use std::rc::Rc;

/// Only prepare_graph/prepare_sources construct this owner. There is no mutable
/// borrow, extraction, clone, or public attachment method. The payload dies
/// before its original claim is returned to the pool on every exit.
#[must_use]
pub(crate) struct SourceRetained<T> {
    payload: T,
    source: [u8; 32],
    compiled_source: [u8; 32],
    claim: SlotClaim,
}

impl<T> SourceRetained<T> {
    pub(crate) fn get(&self) -> &T {
        &self.payload
    }

    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.claim.belongs_to(ledger)
    }

    pub(crate) fn source_fingerprint(&self) -> [u8; 32] {
        self.source
    }

    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] {
        self.compiled_source
    }
}

/// If construction succeeded but cleanup failed, the produced payload remains
/// inside this failure owner with its original output claim. Callers can inspect
/// only fixed status codes; failed source data cannot enter shape planning.
#[must_use]
pub(crate) struct SourceFailure<T> {
    pending: Option<SourceRetained<T>>,
    error: Option<SourcePreparationError>,
    status: Option<WorkflowError>,
    claim: SlotClaim,
}

impl<T> SourceFailure<T> {
    pub(crate) fn error(&self) -> Option<&SourcePreparationError> {
        self.error.as_ref()
    }

    pub(crate) fn status(&self) -> Option<&WorkflowError> {
        self.status.as_ref()
    }
}

impl<T> core::fmt::Debug for SourceFailure<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SourceFailure")
            .field("pending_output", &self.pending.is_some())
            .field("error", &self.error)
            .field("status", &self.status)
            .finish()
    }
}

pub(crate) enum SourcePhaseFailure<T> {
    Admission(WorkflowError),
    Retained(SourceFailure<T>),
}

impl<T> core::fmt::Debug for SourcePhaseFailure<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Admission(error) => f.debug_tuple("Admission").field(error).finish(),
            Self::Retained(failure) => f.debug_tuple("Retained").field(failure).finish(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceStage {
    Graph,
    Preparation,
}

#[derive(Clone, Copy)]
struct SourceFacts {
    owner: *const (),
    stage: SourceStage,
    source: [u8; 32],
    compiled_source: [u8; 32],
    output: Requirements,
    failure: Requirements,
    scratch: Requirements,
    backend: Bytes,
}

/// Private construction and an operation-local borrow prevent storing dispatch
/// authority in a source output. A reduced host bound is available only after
/// output, failure, temporary and backend storage have all been admitted.
pub(crate) struct SourcePreparationAccess<'context> {
    context: &'context ProvingContext,
    facts: SourceFacts,
}

/// Only the success arm below can issue this borrowed token, after the actual
/// phase cleanup and this exact pool's retirement both succeed. A failed body
/// or cleanup never exposes it, even if terminal cleanup later retires a pool.
pub(super) struct CompletedSourceCleanup<'pool> {
    pool: &'pool Rc<SlotPool>,
    claim: *const SlotClaim,
    payload: *const (),
}

impl CompletedSourceCleanup<'_> {
    pub(super) fn authorizes(&self, pool: &Rc<SlotPool>, claim: &SlotClaim, payload: *const ()) -> bool {
        Rc::ptr_eq(self.pool, pool) && core::ptr::eq(self.claim, claim) && self.payload == payload
    }
}

impl<'context> SourcePreparationAccess<'context> {
    /// The successful continuation runs after phase scratch has retired, so
    /// its allocation-free token/call frames belong to the output original.
    pub(crate) fn completion_retained_bytes() -> Result<usize, WorkflowError> {
        use core::mem::size_of;
        [size_of::<CompletedSourceCleanup<'static>>(),
            size_of::<&CompletedSourceCleanup<'static>>(), size_of::<&Rc<SlotPool>>(),
            size_of::<Result<(), WorkflowError>>(), size_of::<[usize; 4]>()]
            .into_iter().try_fold(0usize, usize::checked_add).and_then(|n| n.checked_mul(8))
            .ok_or(WorkflowError::Overflow)
    }

    pub(crate) fn graph_retention_frame_bytes() -> Result<usize, WorkflowError> {
        SlotClaim::graph_retention_frame_bytes()
    }

    pub(crate) fn context(&self) -> &'context ProvingContext {
        self.context
    }

    pub(crate) fn preparation_host_bytes(&self) -> Result<u64, WorkflowError> {
        if self.facts.backend.host == 0 || self.facts.backend.host > MAX_NATIVE_BYTES {
            return Err(WorkflowError::BackendAllowance);
        }
        Ok(self.facts.backend.host)
    }

    pub(crate) fn source_fingerprint(&self) -> [u8; 32] {
        self.facts.source
    }

    pub(crate) fn matches_graph(&self, plan: &SourceGraphPlan<'_>) -> bool {
        self.facts.stage == SourceStage::Graph
            && self.facts.owner == plan as *const SourceGraphPlan<'_> as *const ()
    }

    pub(crate) fn matches_preparation(&self, plan: &SourcePreparationPlan<'_>) -> bool {
        self.facts.stage == SourceStage::Preparation
            && self.facts.owner == plan as *const SourcePreparationPlan<'_> as *const ()
    }
}

impl WorkflowPlanning<'_> {
    pub(crate) fn prepare_graph(
        &mut self,
        operation: SourceGraphOperation<'_, '_>,
    ) -> Result<SourceRetained<PreparedGraphSources>, SourcePhaseFailure<PreparedGraphSources>> {
        let plan = operation.plan();
        if !core::ptr::eq(self.context, plan.context()) {
            self.failed = true;
            return Err(SourcePhaseFailure::Admission(WorkflowError::Identity));
        }
        let facts = SourceFacts {
            owner: plan as *const SourceGraphPlan<'_> as *const (),
            stage: SourceStage::Graph,
            source: plan.source_fingerprint(),
            compiled_source: plan.compiled_source_fingerprint(),
            output: plan.output_requirements(),
            failure: plan.failure_requirements(),
            scratch: plan.scratch_requirements(),
            backend: plan.backend_allowance(),
        };
        self.execute_source(facts, |access| operation.execute(access), |output, cleanup| {
            output.claim.retain_completed_graph(&output.payload, cleanup)
        })
    }

    pub(crate) fn prepare_sources<'graph>(
        &mut self,
        operation: SourcePreparationOperation<'_, 'graph>,
    ) -> Result<
        SourceRetained<PreparedWorkflowSources<'graph>>,
        SourcePhaseFailure<PreparedWorkflowSources<'graph>>,
    > {
        let plan = operation.plan();
        if !core::ptr::eq(self.context, plan.context())
            || !plan.belongs_to(self.capability.ledger())
        {
            self.failed = true;
            return Err(SourcePhaseFailure::Admission(WorkflowError::Identity));
        }
        let facts = SourceFacts {
            owner: plan as *const SourcePreparationPlan<'_> as *const (),
            stage: SourceStage::Preparation,
            source: plan.source_fingerprint(),
            compiled_source: plan.compiled_source_fingerprint(),
            output: plan.output_requirements(),
            failure: plan.failure_requirements(),
            scratch: plan.scratch_requirements(),
            backend: plan.backend_allowance(),
        };
        self.execute_source(facts, |access| operation.execute(access), |_, _| Ok(()))
    }

    // This mechanism is private to the two concrete operations above. Numeric
    // requirements and a callback never form a crate-visible execution API.
    fn execute_source<T>(
        &mut self,
        facts: SourceFacts,
        body: impl FnOnce(&SourcePreparationAccess<'_>) -> Result<T, SourcePreparationError>,
        success: impl FnOnce(&mut SourceRetained<T>, &CompletedSourceCleanup<'_>) -> Result<(), WorkflowError>,
    ) -> Result<SourceRetained<T>, SourcePhaseFailure<T>> {
        let requirements = self.source_requirements(facts).map_err(|error| {
            self.failed = true;
            SourcePhaseFailure::Admission(error)
        })?;
        // Fail closed on every early return/unwind from this point. Only full
        // construction and actual cleanup can reenable pure source planning.
        self.failed = true;
        let mut phase = self
            .capability
            .admit(requirements)
            .map_err(|error| SourcePhaseFailure::Admission(error.into()))?;
        let pool = SlotPool::new_borrowed(
            &mut phase,
            &[
                SlotSpec { requirements: facts.output },
                SlotSpec { requirements: facts.failure },
            ],
        )
        .map_err(SourcePhaseFailure::Admission)?;
        self.failed_source_pool = Some(Rc::clone(&pool));
        pool.begin().map_err(SourcePhaseFailure::Admission)?;
        let output = pool.claim(SlotId::new(0)).map_err(SourcePhaseFailure::Admission)?;
        let failure = pool.claim(SlotId::new(1)).map_err(SourcePhaseFailure::Admission)?;
        let access = SourcePreparationAccess { context: self.context, facts };
        let result = body(&access);
        let (pending, error) = match result {
            Ok(payload) => (
                Some(SourceRetained {
                    payload,
                    source: facts.source,
                    compiled_source: facts.compiled_source,
                    claim: output,
                }),
                None,
            ),
            Err(error) => {
                drop(output);
                (None, Some(error))
            }
        };
        let cleanup = phase
            .complete_after_cleanup()
            .map_err(WorkflowError::from)
            .and_then(|()| pool.after_cleanup())
            .and_then(|()| pool.retire());
        if let Err(status) = cleanup {
            pool.poison();
            return Err(SourcePhaseFailure::Retained(SourceFailure {
                pending,
                error,
                status: Some(status),
                claim: failure,
            }));
        }
        match (pending, error) {
            (Some(mut output), None) => {
                // Identity comparisons only; the private callback cannot move
                // or replace this payload/claim before the adapter consumes the
                // borrowed token. No pointer is dereferenced by the token.
                let cleanup = CompletedSourceCleanup { pool: &pool,
                    claim: &output.claim, payload: &output.payload as *const T as *const () };
                if let Err(status) = success(&mut output, &cleanup) {
                    // Every checked refusal precedes any split. Retain the
                    // complete output and failure originals on this path.
                    pool.poison();
                    return Err(SourcePhaseFailure::Retained(SourceFailure {
                        pending: Some(output), error: None, status: Some(status), claim: failure,
                    }));
                }
                drop(failure);
                self.failed_source_pool = None;
                self.failed = false;
                Ok(output)
            }
            (None, Some(error)) => {
                self.failed_source_pool = None;
                Err(SourcePhaseFailure::Retained(SourceFailure {
                    pending: None, error: Some(error), status: None, claim: failure,
                }))
            }
            _ => unreachable!("concrete source result has exactly one branch"),
        }
    }

    fn source_requirements(&self, facts: SourceFacts) -> Result<Requirements, WorkflowError> {
        if self.failed || self.closure_reserved || self.failed_source_pool.is_some() {
            return Err(WorkflowError::Poisoned);
        }
        if facts.source != self.source || facts.compiled_source != self.compiled_source {
            return Err(WorkflowError::Identity);
        }
        if facts.backend.host == 0
            || facts.backend.host > MAX_NATIVE_BYTES
            || self.managed_device != 8 << 30
            || facts.backend.device != self.capability.source_bootstrap_device_bytes()?
        {
            return Err(WorkflowError::BackendAllowance);
        }
        if facts.output.total()? == Bytes::ZERO
            || facts.failure.total()? == Bytes::ZERO
            || facts.output.get(Category::PhaseScratch) != Bytes::ZERO
            || facts.failure.get(Category::PhaseScratch) != Bytes::ZERO
            || facts.output.get(Category::RegisteredMetadata).host
                < super::source_retained_overhead_bytes()?
        {
            return Err(WorkflowError::Planning);
        }
        let mut requirements = combine(combine(facts.output, facts.failure)?, facts.scratch)?;
        requirements = combine(requirements, SlotPool::bookkeeping_requirements(2)?)?;
        requirements.add(Category::PhaseScratch, facts.backend)?;
        Ok(requirements)
    }

    /// A failed preparation cannot resume. This only completes actual cleanup
    /// while the original scratch remains held and permanently retires context.
    pub(crate) fn abort(mut self) -> Result<(), WorkflowError> {
        self.failed = true;
        match self.capability.status() {
            Status::Poisoned => self.capability.retire()?,
            Status::Ready | Status::Retired => {}
            _ => return Err(WorkflowError::Poisoned),
        }
        if let Some(pool) = self.failed_source_pool.take() {
            pool.retire_after_cleanup();
        }
        // A Ready capability already completed its actual cleanup; its Drop
        // retires readiness without a second uncharged backend operation.
        Ok(())
    }
}

#[cfg(test)]
mod tests;
