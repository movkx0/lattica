//! Concrete one-shot preissuance after every source/output/backend claim exists.
//! Packets are created in immutable outer-step order before any proof begins.
use super::*;
use crate::execution::{
    phase_lifecycle::outer_partition::OuterRuntimePartitionPlan,
    retained_resources::Ledger,
};
use crate::graph_crypto::{PairedRequestPlan, PreissuedPairedOuter};
use lattica_prover_p3::block_v2::machine::RegisteredGpuLimits;

/// Only the closed WorkflowAdmission can construct this borrow. Numeric
/// getters carry no standalone authority; B also validates its original source
/// metadata owner, exact plan/ordinal binding and complete preissue census.
pub(crate) struct OuterPreissueAccess<'claims> {
    binding: PhaseBinding,
    context: &'claims ProvingContext,
    ledger: &'claims Ledger,
    held: &'claims Reservation,
    limits: crate::opencl::Limits,
    backend: Bytes,
    operation_host: u64,
}

impl OuterPreissueAccess<'_> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn context(&self) -> &ProvingContext { self.context }
    pub(crate) fn ledger(&self) -> &Ledger { self.ledger }
    /// The complete immutable step backend, including startup and wrappers.
    pub(crate) fn backend_bytes(&self) -> Bytes { self.backend }
    /// The reduced operation budget after the shared partition removes those
    /// actual startup and wrapper owners from the same backend allowance.
    pub(crate) fn pcs_host_bytes(&self) -> u64 { self.operation_host }

    pub(crate) fn require_planning_scratch(&self, request: Requirements) -> Result<(), WorkflowError> {
        if !contains(self.binding.facts().scratch, request)
            || !self.held.belongs_to(self.ledger)
            || !contains(self.held.requirements(), request)
        {
            return Err(WorkflowError::Planning);
        }
        Ok(())
    }

    pub(crate) fn limits(&self) -> Result<RegisteredGpuLimits, WorkflowError> {
        // The original backend/startup and source planning claims already
        // exist. Physical/environment inspection is bounded by those owners.
        RegisteredGpuLimits::new(self.limits.host_bytes, self.limits.device_bytes,
            4 << 30, self.limits.max_rows).map_err(|_| WorkflowError::Planning)
    }
}

fn is_outer(kind: PhaseKind) -> bool {
    matches!(kind, PhaseKind::OuterProve | PhaseKind::GraphProve | PhaseKind::AggregateProve
        | PhaseKind::SourceOuter | PhaseKind::AlgebraOuter | PhaseKind::AesOuter
        | PhaseKind::GraphOuter | PhaseKind::FinalOuter)
}

impl<'plan, 'context> WorkflowAdmission<'plan, 'context> {
    pub(crate) fn preissue_aes_outer<'source_plan, 'request>(
        &mut self,
        plan: &'source_plan crate::graph_crypto::OwnedAesRequestPlan<'request>,
        ordinal: usize,
    ) -> Result<crate::graph_crypto::PreissuedAesOuter<'source_plan, 'request>, WorkflowError> {
        let result = (|| {
            let binding = PhaseBinding::for_aes(plan, ordinal)?;
            let (index, step) = self.next_preissue_step(binding)?;
            let limits = self.retired_context.source().limits();
            let partition_plan = OuterRuntimePartitionPlan::new(limits, step.backend)?;
            let phase = self.phase.as_ref().ok_or(WorkflowError::Retired)?;
            // Borrow original ownership; the source-built packet receives no
            // extraction, new ledger credit or actual backend dispatch handle.
            let held = phase.original_for_preissue()?;
            let access = OuterPreissueAccess { binding, context: self.context,
                ledger: phase.ledger(), held: &held, limits, backend: step.backend,
                operation_host: partition_plan.operation_host() as u64 };
            let packet = crate::graph_crypto::PreissuedAesOuter::new(plan, ordinal, &access)
                .map_err(|_| WorkflowError::Planning)?;
            drop(access);
            drop(held);
            self.next_preissue = index.checked_add(1).ok_or(WorkflowError::Overflow)?;
            Ok(packet)
        })();
        if result.is_err() {
            self.failed = true;
            self.pool.poison();
        }
        result
    }

    pub(super) fn preissue_complete(&self) -> bool {
        self.native_preissue_complete()
            && !self.plan.steps()[self.next_preissue..].iter().any(|step| is_outer(step.binding.kind()))
    }

    // Concrete wrappers for other source families share this check; a caller
    // callback, arbitrary shape or numeric-only packet cannot enter it.
    fn next_preissue_step(&self, binding: PhaseBinding) -> Result<(usize, PhaseStep), WorkflowError> {
        if self.failed || self.completed || self.next != 0
            || !self.retired_context.belongs_to(self.context)
        {
            return Err(WorkflowError::Poisoned);
        }
        let index = self.plan.steps()[self.next_preissue..].iter()
            .position(|step| is_outer(step.binding.kind()))
            .and_then(|index| index.checked_add(self.next_preissue)).ok_or(WorkflowError::Sequence)?;
        let step = self.plan.steps()[index];
        if step.binding != binding || !self.pool.is_available(step.output)
            || !self.pool.is_available(step.failure)
        {
            return Err(WorkflowError::Identity);
        }
        Ok((index, step))
    }

    pub(crate) fn preissue_paired_outer<'source_plan, 'request>(
        &mut self,
        plan: &'source_plan PairedRequestPlan<'request>,
        ordinal: usize,
    ) -> Result<PreissuedPairedOuter<'source_plan, 'request>, WorkflowError> {
        let result = (|| {
            let binding = PhaseBinding::for_paired(plan, ordinal)?;
            let (index, step) = self.next_preissue_step(binding)?;
            let limits = self.retired_context.source().limits();
            let partition_plan = OuterRuntimePartitionPlan::new(limits, step.backend)?;
            let phase = self.phase.as_ref().ok_or(WorkflowError::Retired)?;
            // Borrow original ownership; the source-built packet receives no
            // extraction, new ledger credit or actual backend dispatch handle.
            let held = phase.original_for_preissue()?;
            let access = OuterPreissueAccess { binding, context: self.context,
                ledger: phase.ledger(), held: &held, limits, backend: step.backend,
                operation_host: partition_plan.operation_host() as u64 };
            let packet = PreissuedPairedOuter::new(plan, ordinal, &access)
                .map_err(|_| WorkflowError::Planning)?;
            drop(access);
            drop(held);
            self.next_preissue = index.checked_add(1).ok_or(WorkflowError::Overflow)?;
            Ok(packet)
        })();
        if result.is_err() {
            self.failed = true;
            self.pool.poison();
        }
        result
    }
}

pub(in crate::execution::workflow_resources) fn bookkeeping_bytes() -> usize {
    8 * core::mem::size_of::<OuterPreissueAccess<'static>>()
        + 8 * core::mem::size_of::<Result<RegisteredGpuLimits, WorkflowError>>()
}

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod final_aggregation;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod native_leaves;

#[cfg(all(feature = "full-workflow-experiment", not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod graph_leaves;
