//! Every native source is inspected once before the first proof. Only the
//! closed admission can attach a core source packet to this exact plan ordinal.
use super::*;

pub(crate) struct PreissuedAesNative<'plan, 'request> {
    pub(super) plan: &'plan OwnedAesRequestPlan<'request>,
    pub(super) binding: PhaseBinding,
    pub(super) partition: NativePartitionPlan,
    pub(super) core: PreissuedNativeAesPlan,
    pub(super) preissue_ns: u128,
}

impl PreissuedAesNative<'_, '_> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn check_before_native(&self) -> Result<(), WorkflowError> {
        if !self.core.uses_outer_host_v1() { return Err(WorkflowError::Policy); }
        self.core.check_execution_selection().map_err(|_| WorkflowError::Planning)
    }
}

/// Retained A packet/collection/caller frames, separate from the core packet's
/// own inventory. B adds both source-derived amounts once per native segment.
pub(crate) fn aes_native_packet_metadata_host_bytes() -> Result<usize, WorkflowError> {
    use core::mem::size_of;
    [size_of::<PreissuedAesNative<'static, 'static>>(),
        size_of::<Option<PreissuedAesNative<'static, 'static>>>(),
        size_of::<Vec<Option<PreissuedAesNative<'static, 'static>>>>(),
        size_of::<Result<PreissuedAesNative<'static, 'static>, WorkflowError>>(),
        size_of::<NativePartitionPlan>(), size_of::<PhaseBinding>(),
    ].into_iter().try_fold(0usize, |sum, bytes| sum.checked_add(bytes))
        .and_then(|sum| sum.checked_mul(8)).ok_or(WorkflowError::Overflow)
}

impl<'plan, 'context> WorkflowAdmission<'plan, 'context> {
    pub(crate) fn preissue_aes_native<'source_plan, 'request>(&mut self,
        plan: &'source_plan OwnedAesRequestPlan<'request>, ordinal: usize,
    ) -> Result<PreissuedAesNative<'source_plan, 'request>, WorkflowError> {
        let preissue_started = Instant::now();
        let result = (|| {
            if self.failed || self.completed || self.next != 0
                || !self.retired_context.belongs_to(self.context)
            { return Err(WorkflowError::Poisoned); }
            let binding = PhaseBinding::for_aes(plan, ordinal)?;
            let index = self.plan.steps()[self.next_native_preissue..].iter()
                .position(|step| step.binding.kind().is_native())
                .and_then(|index| index.checked_add(self.next_native_preissue))
                .ok_or(WorkflowError::Sequence)?;
            let step = self.plan.steps()[index];
            if step.binding != binding || binding.kind() != PhaseKind::Native
                || !self.pool.is_available(step.output) || !self.pool.is_available(step.failure)
            { return Err(WorkflowError::Identity); }
            let phase = self.phase.as_mut().ok_or(WorkflowError::Retired)?;
            if !plan.belongs_to(phase.ledger()) { return Err(WorkflowError::Identity); }
            let source = plan.native_source(ordinal).map_err(|_| WorkflowError::Source)?;
            let (output_requirement, scratch_requirement) = source.source_requirements()
                .map_err(|_| WorkflowError::Planning)?;
            if !contains(binding.facts().output, output_requirement)
                || !contains(binding.facts().scratch, scratch_requirement)
                || !contains(binding.facts().scratch, aes_native_issuer_scratch_requirements()?)
            { return Err(WorkflowError::Planning); }
            let retired = self.retired_context.source();
            let plan_partition = NativePartitionPlan::new(&source, retired.limits(), step.backend)
                .map_err(|_| WorkflowError::Planning)?;
            let source_splits = combine(plan_partition.preparation, plan_partition.verifier)?;
            if !contains(scratch_requirement, source_splits) { return Err(WorkflowError::Planning); }
            let runtime_plan = plan_partition.runtime().map_err(|_| WorkflowError::Planning)?;
            let mut partition = phase.partition_originals(plan_partition.complete)?;
            let ledger = partition.ledger().clone();
            let startup = partition.split(plan_partition.startup)?;
            let wrappers = partition.split(plan_partition.wrappers)?;
            let pcs = partition.split(plan_partition.pcs)?;
            let preparation = partition.split(plan_partition.preparation)?;
            let verifier = partition.split(plan_partition.verifier)?;
            let mut pending = match runtime_plan.claim(startup, &ledger, retired) {
                Ok(pending) => pending,
                Err((_error, startup)) => {
                    restore::phase(partition, [startup, wrappers, pcs, preparation, verifier])
                        .map_err(|_| WorkflowError::Planning)?;
                    return Err(WorkflowError::Planning);
                }
            };
            // This guard captures idle physical selection under the existing
            // original startup claim; it never starts an owned runtime.
            let checked = (|| {
                let guard = unsafe { pending.preflight() }.map_err(|_| WorkflowError::Planning)?;
                unsafe { plan_partition.native.preissue_from_originals(&preparation,
                    guard.reservation(), &verifier, &wrappers, &pcs, &ledger) }
                    .map_err(|_| WorkflowError::Planning)
            })();
            let startup = pending.into_unstarted_original();
            restore::phase(partition, [startup, wrappers, pcs, preparation, verifier])
                .map_err(|_| WorkflowError::Planning)?;
            let core = checked?;
            if !core.uses_outer_host_v1() { return Err(WorkflowError::Policy); }
            self.next_native_preissue = index.checked_add(1).ok_or(WorkflowError::Overflow)?;
            Ok(PreissuedAesNative { plan, binding, partition: plan_partition, core,
                preissue_ns: preissue_started.elapsed().as_nanos() })
        })();
        if result.is_err() { self.failed = true; self.pool.poison(); }
        result
    }
}
