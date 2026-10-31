//! Final outer packets are inspected in the same complete pre-proof sequence.
use super::*;
use crate::ordered_aggregation::owned_final::{FinalPhasePlan, PreissuedFinalOuter};

impl WorkflowAdmission<'_, '_> {
    pub(crate) fn preissue_final_outer<'source_plan, 'source>(&mut self,
        plan: &'source_plan FinalPhasePlan<'source>, ordinal: usize)
        -> Result<PreissuedFinalOuter<'source_plan, 'source>, WorkflowError>
    {
        let result = (|| {
            let binding = PhaseBinding::for_final(plan, ordinal)?;
            let (index, step) = self.next_preissue_step(binding)?;
            if binding.kind() != PhaseKind::FinalOuter { return Err(WorkflowError::Identity); }
            let limits = self.retired_context.source().limits();
            let partition = OuterRuntimePartitionPlan::new(limits, step.backend)?;
            let phase = self.phase.as_ref().ok_or(WorkflowError::Retired)?;
            let held = phase.original_for_preissue()?;
            let access = OuterPreissueAccess { binding, context: self.context,
                ledger: phase.ledger(), held: &held, limits, backend: step.backend,
                operation_host: partition.operation_host() as u64 };
            let packet = PreissuedFinalOuter::new(plan, ordinal, &access)
                .map_err(|_| WorkflowError::Planning)?;
            drop(access); drop(held);
            self.next_preissue = index.checked_add(1).ok_or(WorkflowError::Overflow)?;
            Ok(packet)
        })();
        if result.is_err() { self.failed = true; self.pool.poison(); }
        result
    }
}
