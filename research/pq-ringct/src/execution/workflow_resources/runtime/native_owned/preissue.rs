//! Every native source is inspected once before the first proof. Only the
//! closed admission can attach a core source packet to this exact plan ordinal.
use super::*;
mod diagnostic;
pub(super) const DIAGNOSTIC_HOST_BYTES: usize = diagnostic::HOST_BYTES;

pub(crate) struct PreissuedPairedNative<'plan, 'request> {
    pub(super) plan: &'plan PairedRequestPlan<'request>,
    pub(super) binding: PhaseBinding,
    pub(super) partition: NativePartitionPlan,
    pub(super) core: PreissuedNativeShakePlan,
    pub(super) preissue_ns: u128,
}

impl PreissuedPairedNative<'_, '_> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn check_before_native(&self) -> Result<(), WorkflowError> {
        if !self.core.uses_outer_host_v1() { return Err(WorkflowError::Policy); }
        self.core.check_execution_selection().map_err(|_| WorkflowError::Planning)
    }
}

/// Retained A packet/collection/caller frames, separate from the core packet's
/// own inventory. B adds both source-derived amounts once per native segment.
pub(crate) fn paired_native_packet_metadata_host_bytes() -> Result<usize, WorkflowError> {
    use core::mem::size_of;
    [size_of::<PreissuedPairedNative<'static, 'static>>(),
        size_of::<Option<PreissuedPairedNative<'static, 'static>>>(),
        size_of::<Vec<Option<PreissuedPairedNative<'static, 'static>>>>(),
        size_of::<Result<PreissuedPairedNative<'static, 'static>, WorkflowError>>(),
        size_of::<NativePartitionPlan>(), size_of::<PhaseBinding>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)
}

impl<'plan, 'context> WorkflowAdmission<'plan, 'context> {
    pub(in crate::execution::workflow_resources::runtime) fn native_preissue_complete(&self) -> bool {
        !self.plan.steps()[self.next_native_preissue..].iter()
            .any(|step| step.binding.kind().is_native())
    }

    pub(crate) fn preissue_paired_native<'source_plan, 'request>(&mut self,
        plan: &'source_plan PairedRequestPlan<'request>, ordinal: usize,
    ) -> Result<PreissuedPairedNative<'source_plan, 'request>, WorkflowError> {
        let preissue_started = Instant::now();
        let report_failure = !self.failed;
        let mut diagnostic = diagnostic::Diagnostic::new(ordinal, self.next_native_preissue);
        let result = (|| {
            if self.failed || self.completed || self.next != 0
                || !self.retired_context.belongs_to(self.context)
            { return Err(WorkflowError::Poisoned); }
            diagnostic.stage = "binding";
            let binding = PhaseBinding::for_paired(plan, ordinal)?;
            diagnostic.stage = "schedule_index";
            let index = self.plan.steps()[self.next_native_preissue..].iter()
                .position(|step| step.binding.kind().is_native())
                .and_then(|index| index.checked_add(self.next_native_preissue))
                .ok_or(WorkflowError::Sequence)?;
            diagnostic.closed_index = Some(index);
            diagnostic.stage = "schedule_identity";
            let step = self.plan.steps()[index];
            if step.binding != binding || binding.kind() != PhaseKind::Native
                || !self.pool.is_available(step.output) || !self.pool.is_available(step.failure)
            { return Err(WorkflowError::Identity); }
            diagnostic.stage = "active_phase";
            let phase = self.phase.as_mut().ok_or(WorkflowError::Retired)?;
            diagnostic.stage = "source_ledger";
            if !plan.belongs_to(phase.ledger()) { return Err(WorkflowError::Identity); }
            diagnostic.stage = "native_source";
            let source = plan.native_source(ordinal).map_err(|error| {
                diagnostic.paired(error); WorkflowError::Source
            })?;
            diagnostic.stage = "source_requirements";
            let (output_requirement, scratch_requirement) = source.source_requirements()
                .map_err(|error| { diagnostic.paired(error); WorkflowError::Planning })?;
            diagnostic.stage = "output_requirement";
            if !contains(binding.facts().output, output_requirement) { return Err(WorkflowError::Planning); }
            diagnostic.stage = "source_scratch";
            if !contains(binding.facts().scratch, scratch_requirement) { return Err(WorkflowError::Planning); }
            diagnostic.stage = "issuer_scratch";
            if !contains(binding.facts().scratch, native_issuer_scratch_requirements()?) { return Err(WorkflowError::Planning); }
            let retired = self.retired_context.source();
            diagnostic.stage = "partition_plan";
            let plan_partition = NativePartitionPlan::new(&source, retired.limits(), step.backend)
                .map_err(|error| { diagnostic.paired(error); WorkflowError::Planning })?;
            diagnostic.geometry(&plan_partition, step.backend);
        diagnostic.stage = "partition_source_subset";
            let source_splits = combine(plan_partition.preparation, plan_partition.verifier)?;
            if !contains(scratch_requirement, source_splits) { return Err(WorkflowError::Planning); }
            diagnostic.stage = "runtime_plan";
            let runtime_plan = plan_partition.runtime()
                .map_err(|error| { diagnostic.paired(error); WorkflowError::Planning })?;
            diagnostic.stage = "partition_originals";
            let mut partition = phase.partition_originals(plan_partition.complete)?;
            let ledger = partition.ledger().clone();
            diagnostic.stage = "split_startup";
            let startup = partition.split(plan_partition.startup)?;
            diagnostic.stage = "split_wrappers";
            let wrappers = partition.split(plan_partition.wrappers)?;
            diagnostic.stage = "split_pcs";
            let pcs = partition.split(plan_partition.pcs)?;
            diagnostic.stage = "split_preparation";
            let preparation = partition.split(plan_partition.preparation)?;
            diagnostic.stage = "split_verifier";
            let verifier = partition.split(plan_partition.verifier)?;
            diagnostic.stage = "runtime_claim";
            let mut pending = match runtime_plan.claim(startup, &ledger, retired) {
                Ok(pending) => pending,
                Err((error, startup)) => {
                    diagnostic.runtime(error);
                    restore::phase(partition, [startup, wrappers, pcs, preparation, verifier])
                        .map_err(|error| { diagnostic.restoration(error); WorkflowError::Planning })?;
                    return Err(WorkflowError::Planning);
                }
            };
            // The guard captures idle physical selection under the existing
            // original startup claim; it never starts an owned runtime.
            let checked = (|| {
                diagnostic.stage = "runtime_preflight";
                let guard = unsafe { pending.preflight() }
                    .map_err(|error| { diagnostic.runtime(error); WorkflowError::Planning })?;
                diagnostic.stage = "core_packet";
                unsafe { plan_partition.native.preissue_from_originals(&preparation,
                    guard.reservation(), &verifier, &wrappers, &pcs, &ledger) }
                    .map_err(|error| { diagnostic.native(error); WorkflowError::Planning })
            })();
            let startup = pending.into_unstarted_original();
            if checked.is_ok() { diagnostic.stage = "restore_originals"; }
            // Keep the original failed stage/cause if restoring originals also
            // fails; report both refusals without moving or replacing any owner.
            restore::phase(partition, [startup, wrappers, pcs, preparation, verifier])
                .map_err(|error| { diagnostic.restoration(error); WorkflowError::Planning })?;
            let core = checked?;
            diagnostic.stage = "core_profile";
            if !core.uses_outer_host_v1() { return Err(WorkflowError::Policy); }
            diagnostic.stage = "advance_native_cursor";
            self.next_native_preissue = index.checked_add(1).ok_or(WorkflowError::Overflow)?;
            Ok(PreissuedPairedNative { plan, binding, partition: plan_partition, core,
                preissue_ns: preissue_started.elapsed().as_nanos() })
        })();
        if let Err(error) = &result {
            self.failed = true;
            self.pool.poison();
            // Failure is already terminal. A failed observation cannot replace the
            // retained original error, release an owner, or trigger another attempt.
            if report_failure { let _ = diagnostic.emit(error); }
        }
        result
    }
}
