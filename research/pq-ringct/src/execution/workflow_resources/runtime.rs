use super::{
    owners::{PhaseFailure, Retained, RetainedFailure, SlotClaim, SlotPool},
    planning::WorkflowPlanning,
    types::{
        combine, contains, PhaseBinding, PhaseKind, PhaseStep, WorkflowError, VerificationBinding,
        verification_binding_frame_bytes,
        MAX_DEVICE_BYTES, MAX_HOST_BYTES, MAX_NATIVE_BYTES, REGISTRY_BYTES,
    },
};
use crate::{
    execution::{
        phase_lifecycle::OwnedPhase,
        phase_lifecycle::workflow_transition::RetiredWorkflowContext,
        retained_resources::{Bytes, Category, Requirements, Reservation},
        ProvingContext,
    },
    graph_crypto::{
        PairedCompiled, PairedEndpointOperation, PairedEndpoints, PairedFailure,
        PairedGroupOperation, PairedMergeOperation, PairedNativeOperation, PairedNativeOutput,
    },
    spend_pipeline::full_workflow::ClosedWorkflowPlan,
};
use std::rc::Rc;

mod completion;
pub(crate) use completion::WorkflowCompletionReceipt;
pub(super) use completion::host_bytes as completion_host_bytes;
mod preflight;
mod native_retirement;
pub(super) mod preissue;
pub(crate) use preissue::OuterPreissueAccess;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod graph_source_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use graph_source_owned::{source_native_issuer_scratch_requirements, source_native_packet_metadata_host_bytes, PreissuedSourceNative};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod source_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use source_native_compile_owned::source_native_compile_issuer_scratch_requirements;
mod native_owned;
mod aes_owned;
pub(crate) use aes_owned::{
    aes_native_issuer_scratch_requirements, aes_native_packet_metadata_host_bytes,
    PreissuedAesNative,
};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod parameters_pp_compile;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod equality_compile;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod auxiliary_compile;
mod group_owned;
pub(crate) use group_owned::group_issuer_scratch_requirements;
pub(crate) use native_owned::{
    native_issuer_scratch_requirements, paired_native_packet_metadata_host_bytes,
    PreissuedPairedNative,
};

/// Complete source closure plus the original preissued pool. No numeric-budget
/// constructor, post-dispatch admission, alternate layout, or retry is exposed.
pub(crate) struct WorkflowAdmission<'plan, 'context> {
    phase: Option<OwnedPhase<'context>>,
    pool: Rc<SlotPool>,
    // This exact residual moves to the outer case when admission drops. Caller
    // metadata/runtime frames remain charged while their nested scopes unwind.
    _planning_original: super::planning::GuardedPlanningOriginal<'context>,
    plan: &'plan ClosedWorkflowPlan<'plan>,
    context: &'context ProvingContext,
    retired_context: RetiredWorkflowContext<'context>,
    next_preissue: usize,
    next_native_preissue: usize,
    next: usize,
    failed: bool,
    completed: bool,
}

impl<'plan, 'context> WorkflowAdmission<'plan, 'context> {
    pub(super) fn from_planning(
        planning: WorkflowPlanning<'context>,
        plan: &'plan ClosedWorkflowPlan<'plan>,
    ) -> Result<Self, WorkflowError> {
        if planning.failed || !planning.closure_reserved || planning.failed_source_pool.is_some() {
            return Err(WorkflowError::Poisoned);
        }
        #[cfg(not(debug_assertions))]
        {
            if planning.producer_metadata.is_some() != plan.requires_producer_metadata()
                || planning.producer_metadata.as_ref().is_some_and(|installed| !installed.matches_closed(plan))
                || (plan.requires_producer_metadata() && !planning.original.is_pinned())
            { return Err(WorkflowError::Identity); }
        }
        if !core::ptr::eq(planning.context, plan.context())
            || planning.source != plan.source_fingerprint()
            || planning.compiled_source != plan.compiled_source_fingerprint()
            || planning.enclosing != plan.enclosing_bytes()
            || !plan.belongs_to(planning.capability.ledger())
        {
            return Err(WorkflowError::Identity);
        }
        if !plan.fresh_only() {
            return Err(WorkflowError::Policy);
        }
        if (planning.enclosing.host < REGISTRY_BYTES
                && !(planning.enclosing == Bytes::ZERO && planning.capability.uses_original_generation_ledger()))
            || planning.original.requirements().get(Category::RegisteredMetadata).host
                < super::controller_bytes(plan.slots().len())?
        {
            return Err(WorkflowError::Enclosing);
        }
        let requirements = preflight::check(plan, planning.managed_device)?;
        #[cfg(not(debug_assertions))]
        match (plan.requires_producer_metadata(), plan.admission_projection()) {
            (true, Some(projection)) => projection.validate_for_admission(&planning, plan, requirements)?,
            (false, None) => {},
            _ => return Err(WorkflowError::Identity),
        }
        // Source derivation has returned and all its compiler temporaries have
        // died. This original reusable source scratch is no longer live. The
        // preissued retained metadata splits remain with their source owners.
        drop(planning.scratch);
        let mut phase = planning.capability.admit_owned_with_planning_startup(requirements)?;
        let pool = SlotPool::new(&mut phase, plan.slots())?;
        let retired_context = phase.retire_source_session().map_err(|_| WorkflowError::Planning)?;
        Ok(Self {
            phase: Some(phase),
            pool,
            _planning_original: planning.original,
            plan,
            context: planning.context,
            retired_context,
            next_preissue: 0,
            next_native_preissue: 0,
            next: 0,
            failed: false,
            completed: false,
        })
    }

    pub(crate) fn next_phase(
        &mut self,
        binding: PhaseBinding,
    ) -> Result<WorkflowPhase<'_, 'plan, 'context>, WorkflowError> {
        if self.failed || self.completed || !self.preissue_complete() {
            return Err(WorkflowError::Poisoned);
        }
        let check = (|| {
            let step = *self.plan.steps().get(self.next).ok_or(WorkflowError::Sequence)?;
            if step.binding != binding {
                return Err(WorkflowError::Identity);
            }
            let inputs = preflight::inputs(self.plan, step)?;
            if inputs.iter().any(|slot| !self.pool.is_live(*slot))
                || !self.pool.is_available(step.output)
                || !self.pool.is_available(step.failure)
            {
                return Err(WorkflowError::SlotBusy);
            }
            self.pool.begin()?;
            let output = self.pool.claim(step.output)?;
            let failure = self.pool.claim(step.failure)?;
            Ok((step, output, failure))
        })();
        match check {
            Ok((step, output, failure)) => Ok(WorkflowPhase {
                admission: self,
                step,
                output: Some(output),
                failure: Some(failure),
                completed: false,
            }),
            Err(error) => {
                // Even a fixed binding failure cannot be repaired by silently
                // choosing another phase once this runtime was selected.
                self.failed = true;
                self.pool.poison();
                Err(error)
            }
        }
    }

    pub(crate) fn finish(mut self) -> Result<WorkflowCompletionReceipt<'context>, WorkflowError> {
        if self.failed || self.next != self.plan.steps().len() || !self.preissue_complete()
            || self.plan.steps().last().map(|step| step.binding.kind()) != Some(PhaseKind::FinalVerify) {
            return Err(WorkflowError::Incomplete);
        }
        let phase = self.phase.as_ref().ok_or(WorkflowError::Retired)?;
        if !self._planning_original.belongs_to(phase.ledger()) { return Err(WorkflowError::Identity); }
        let receipt_original = self._planning_original.split(completion::requirements()?)?;
        let result = self
            .phase
            .take()
            .ok_or(WorkflowError::Retired)?
            .complete_after_cleanup();
        match result {
            Ok(()) => {
                self.pool.retire()?;
                self.completed = true;
                WorkflowCompletionReceipt::from_finished(&self, receipt_original)
            }
            Err(error) => {
                self.failed = true;
                self.pool.poison();
                Err(error.into())
            }
        }
    }

    /// Terminal cleanup is permitted after failure. It cannot dispatch, reuse
    /// a source plan, fall back, or make this workflow ready for another proof.
    pub(crate) fn abort(mut self) -> Result<(), WorkflowError> {
        self.failed = true;
        let result = self
            .phase
            .take()
            .ok_or(WorkflowError::Retired)?
            .retire_after_failure();
        match result {
            Ok(()) => {
                self.pool.retire_after_cleanup();
                self.completed = true;
                Ok(())
            }
            Err(error) => {
                self.pool.poison();
                Err(error.into())
            }
        }
    }
}

impl Drop for WorkflowAdmission<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.pool.poison();
        }
    }
}

/// Private construction couples an exact operation with its already-claimed
/// output/failure slots and backend allowance. No ledger/split/attach method is
/// exposed to concrete operation bodies. It cannot be cloned or stored in an
/// output beyond the operation borrow.
pub(crate) struct ExecutionAccess<'context> {
    context: &'context ProvingContext,
    binding: PhaseBinding,
    backend: Bytes,
    pool: &'context Rc<SlotPool>,
}

impl<'context> ExecutionAccess<'context> {
    pub(crate) fn context(&self) -> &'context ProvingContext {
        self.context
    }

    pub(crate) fn binding(&self) -> PhaseBinding {
        self.binding
    }

    /// Read-only provenance check for preproof source owners. Their dedicated
    /// pools differ from execution output pools, but share the original ledger.
    pub(crate) fn owns_source<T>(&self, source: &super::source::SourceRetained<T>) -> bool {
        source.belongs_to(self.pool.ledger())
    }

    pub(crate) fn native_host_bytes(&self) -> Result<u64, WorkflowError> {
        if !self.binding.kind().is_native()
            || self.backend.host == 0
            || self.backend.host > MAX_NATIVE_BYTES
        {
            return Err(WorkflowError::BackendAllowance);
        }
        Ok(self.backend.host)
    }

    pub(crate) fn preparation_host_bytes(&self) -> Result<u64, WorkflowError> {
        if !self.binding.kind().is_preparation()
            || self.backend.host == 0
            || self.backend.host > MAX_NATIVE_BYTES
        {
            return Err(WorkflowError::BackendAllowance);
        }
        Ok(self.backend.host)
    }

    pub(crate) fn registered_host_bytes(&self) -> Result<u64, WorkflowError> {
        if self.binding.kind().is_native()
            || self.binding.kind().is_preparation()
            || self.backend.host == 0
            || self.backend.host > MAX_HOST_BYTES
        {
            return Err(WorkflowError::BackendAllowance);
        }
        Ok(self.backend.host)
    }

    pub(super) fn pool(&self) -> &Rc<SlotPool> {
        self.pool
    }
}

/// The mutable admission borrow serializes all work. Dropping an unfinished
/// phase poisons the original pool; only explicit terminal cleanup can retire it.
#[must_use]
pub(crate) struct WorkflowPhase<'phase, 'plan, 'context> {
    admission: &'phase mut WorkflowAdmission<'plan, 'context>,
    step: PhaseStep,
    output: Option<SlotClaim>,
    failure: Option<SlotClaim>,
    completed: bool,
}

impl WorkflowPhase<'_, '_, '_> {
    // Private generic mechanism: ONLY the concrete source-bound methods below
    // can call it. No caller callback or arbitrary payload can enter this path.
    fn execute<T, E>(
        mut self,
        binding: PhaseBinding,
        body: impl FnOnce(&ExecutionAccess<'_>) -> Result<T, E>,
    ) -> Result<Retained<T>, PhaseFailure<E>> {
        if self.step.binding != binding {
            return Err(PhaseFailure::Admission(WorkflowError::Identity));
        }
        let access = ExecutionAccess {
            context: self.admission.context,
            binding,
            backend: self.step.backend,
            pool: &self.admission.pool,
        };
        let result = body(&access);
        let output_claim = self.output.take().expect("preissued output claim");
        let failure_claim = self.failure.take().expect("preissued failure claim");
        match result {
            Ok(payload) => {
                let output = Retained::produced(payload, output_claim, binding);
                // Keep the failure claim until cleanup and source lifetime
                // checks pass; success never frees it ahead of that barrier.
                match self.cleanup() {
                    Ok(()) => {
                        drop(failure_claim);
                        self.admission.next += 1;
                        self.completed = true;
                        Ok(output)
                    }
                    Err(status) => {
                        drop(output);
                        self.admission.failed = true;
                        self.admission.pool.poison();
                        self.completed = true;
                        Err(PhaseFailure::Retained(RetainedFailure::produced(
                            None,
                            Some(status),
                            failure_claim,
                        )))
                    }
                }
            }
            Err(error) => {
                let mut failure = RetainedFailure::produced(Some(error), None, failure_claim);
                drop(output_claim);
                if let Err(status) = self.cleanup() {
                    failure = failure.with_status(status);
                    self.admission.pool.poison();
                }
                self.admission.failed = true;
                self.completed = true;
                Err(PhaseFailure::Retained(failure))
            }
        }
    }

    fn cleanup(&mut self) -> Result<(), WorkflowError> {
        self.admission
            .phase
            .as_ref()
            .ok_or(WorkflowError::Retired)?
            .cleanup_between_operations()?;
        // Inputs named as consumed must actually have been destroyed. Merely
        // dropping a report, cloning a key or moving a raw proof is insufficient.
        let inputs = preflight::inputs(self.admission.plan, self.step)?;
        if inputs[..self.step.consume_count]
            .iter()
            .any(|slot| self.admission.pool.is_live(*slot))
            || inputs[self.step.consume_count..]
                .iter()
                .any(|slot| !self.admission.pool.is_live(*slot))
        {
            return Err(WorkflowError::Sequence);
        }
        self.admission.pool.after_cleanup()
    }

    pub(crate) fn prepare_endpoints<'request>(
        self,
        operation: PairedEndpointOperation<'_, 'request>,
    ) -> Result<Retained<PairedEndpoints<'request>>, PhaseFailure<PairedFailure>> {
        self.execute(operation.binding(), |access| operation.execute(access))
    }

    pub(crate) fn compile_parent<'request>(
        self,
        operation: PairedMergeOperation<'_, 'request>,
    ) -> Result<Retained<PairedCompiled<'request>>, PhaseFailure<PairedFailure>> {
        self.execute(operation.binding(), |access| operation.execute(access))
    }

}

impl Drop for WorkflowPhase<'_, '_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.admission.failed = true;
            self.admission.pool.poison();
        }
    }
}

mod outer_owned;
pub(crate) use outer_owned::{OwnedOuterScope, OuterOwnedError};
#[cfg(feature = "full-workflow-experiment")]
pub(crate) use outer_owned::PairedIdentityPeers;
pub(crate) use outer_owned::forwarding_host_bytes as owned_outer_forwarding_host_bytes;
impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_fixed_sources<'a>(self,
        operation: crate::spend_pipeline::full_workflow::SourceCompileOperation<'_, 'a>,
    ) -> Result<Retained<crate::spend_pipeline::full_workflow::CompiledFixedSources<'a>>,
        PhaseFailure<crate::spend_pipeline::full_workflow::FixedSourceFailure>> {
        self.execute(operation.binding(), |access| operation.execute(access))
    }
}

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_graph_parent<'graph>(self,
        operation: crate::graph_tree::owned_parent::GraphParentCompileOperation<'_, '_, 'graph>,
    ) -> Result<Retained<crate::graph_tree::owned_parent::OwnedGraphCompiled<'graph>>,
        PhaseFailure<crate::graph_tree::owned_parent::GraphParentFailure>> {
        let inputs = preflight::inputs(self.admission.plan, self.step)
            .map_err(PhaseFailure::Admission)?;
        if self.step.binding != operation.binding() || self.step.backend != Bytes::ZERO
            || self.step.consume_count != 2 || inputs != operation.input_slots()
        { return Err(PhaseFailure::Admission(WorkflowError::Identity)); }
        self.execute(operation.binding(), |access| operation.execute(access))
    }
}

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod uniform_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod transcript_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod sparse_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use uniform_owned::{uniform_native_issuer_scratch_requirements, uniform_native_packet_metadata_host_bytes, PreissuedUniformNative};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use transcript_owned::{transcript_native_issuer_scratch_requirements, transcript_native_packet_metadata_host_bytes, PreissuedTranscriptNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod affine_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use affine_owned::{affine_native_issuer_scratch_requirements, affine_native_packet_metadata_host_bytes, PreissuedAffineNative};
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use sparse_owned::{sparse_native_issuer_scratch_requirements, sparse_native_packet_metadata_host_bytes, PreissuedSparseNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod final_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use final_owned::{final_compile_issuer_requirements, final_verify_issuer_requirements,
    final_outer_forwarding_host_bytes, final_report_transport_host_bytes};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod affine_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use affine_native_compile_owned::affine_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod ntt_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use ntt_owned::{ntt_native_issuer_scratch_requirements, ntt_native_packet_metadata_host_bytes, PreissuedNttNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod ntt_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use ntt_native_compile_owned::ntt_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod mul_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use mul_owned::{mul_native_issuer_scratch_requirements, mul_native_packet_metadata_host_bytes, PreissuedMulNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod mul_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use mul_native_compile_owned::mul_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod g_bound_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use g_bound_owned::{g_bound_native_issuer_scratch_requirements, g_bound_native_packet_metadata_host_bytes, PreissuedGBoundNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod g_bound_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use g_bound_native_compile_owned::g_bound_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod permutation_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use permutation_owned::{permutation_native_issuer_scratch_requirements, permutation_native_packet_metadata_host_bytes, PreissuedPermutationNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod permutation_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use permutation_native_compile_owned::permutation_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod linear_map_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use linear_map_owned::{linear_map_native_issuer_scratch_requirements, linear_map_native_packet_metadata_host_bytes, PreissuedLinearMapNative};

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod linear_map_native_compile_owned;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use linear_map_native_compile_owned::linear_map_native_compile_issuer_scratch_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod driver_guard;
#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
pub(crate) use driver_guard::driver_retained_requirements;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod verification_receipts;
