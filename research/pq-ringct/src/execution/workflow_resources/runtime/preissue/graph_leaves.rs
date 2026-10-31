//! Fixed, direct, and parent graph packets, under the immutable outer cursor.
use super::*;
use crate::graph_tree::owned_parent::{
    FixedLeafOuterPlan, PreissuedFixedLeafOuter,
    ParametersPpGraphPlan, PreissuedParametersPpOuter,
    AuxiliaryGraphPlan, PreissuedAuxiliaryOuter,
    EqualityGraphPlan, PreissuedEqualityOuter,
    GraphParentPlan, PreissuedGraphParentOuter,
};

macro_rules! graph_preissue {
    ($method:ident, $plan:ident, $packet:ident $(, $ordinal:expr)?) => {
        pub(crate) fn $method<'source_plan, 'source, 'graph>(&mut self,
            plan: &'source_plan $plan<'source, 'graph>)
            -> Result<$packet<'source_plan, 'source, 'graph>, WorkflowError>
        {
            let result = (|| {
                let binding = plan.binding($($ordinal)?).map_err(|_| WorkflowError::Identity)?;
                let (index, step) = self.next_preissue_step(binding)?;
                if binding.kind() != PhaseKind::GraphOuter { return Err(WorkflowError::Identity); }
                let limits = self.retired_context.source().limits();
                let partition = OuterRuntimePartitionPlan::new(limits, step.backend)?;
                let phase = self.phase.as_ref().ok_or(WorkflowError::Retired)?;
                let held = phase.original_for_preissue()?;
                let access = OuterPreissueAccess { binding, context: self.context,
                    ledger: phase.ledger(), held: &held, limits, backend: step.backend,
                    operation_host: partition.operation_host() as u64 };
                let packet = $packet::new(plan, &access).map_err(|_| WorkflowError::Planning)?;
                drop(access); drop(held);
                self.next_preissue = index.checked_add(1).ok_or(WorkflowError::Overflow)?;
                Ok(packet)
            })();
            if result.is_err() { self.failed = true; self.pool.poison(); }
            result
        }
    };
}
impl WorkflowAdmission<'_, '_> {
    graph_preissue!(preissue_fixed_leaf_outer, FixedLeafOuterPlan, PreissuedFixedLeafOuter);
    graph_preissue!(preissue_parameters_pp_outer, ParametersPpGraphPlan, PreissuedParametersPpOuter, 1);
    graph_preissue!(preissue_auxiliary_outer, AuxiliaryGraphPlan, PreissuedAuxiliaryOuter, 1);
    graph_preissue!(preissue_equality_outer, EqualityGraphPlan, PreissuedEqualityOuter, 1);
    graph_preissue!(preissue_graph_parent_outer, GraphParentPlan, PreissuedGraphParentOuter, 1);
}
