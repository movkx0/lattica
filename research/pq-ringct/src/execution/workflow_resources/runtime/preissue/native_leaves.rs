//! Concrete native and algebra leaf outer packets, before proof zero.
//! The sealed outer-step cursor and original phase scratch authorize each packet.
use super::*;
use crate::graph_tree::owned_parent::{
    NativeLeafOuterPlan, PreissuedNativeLeafOuter,
    AffineLeafOuterPlan, PreissuedAffineLeafOuter,
    NttLeafOuterPlan, PreissuedNttLeafOuter,
    MulLeafOuterPlan, PreissuedMulLeafOuter,
    GBoundLeafOuterPlan, PreissuedGBoundLeafOuter,
    PermutationLeafOuterPlan, PreissuedPermutationLeafOuter,
    LinearMapLeafOuterPlan, PreissuedLinearMapLeafOuter,
};

macro_rules! leaf_preissue {
    ($method:ident, $plan:ident, $packet:ident) => {
        pub(crate) fn $method<'source_plan, 'source, 'graph>(&mut self,
            plan: &'source_plan $plan<'source, 'graph>)
            -> Result<$packet<'source_plan, 'source, 'graph>, WorkflowError>
        {
            let result = (|| {
                let binding = plan.binding().map_err(|_| WorkflowError::Identity)?;
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
    leaf_preissue!(preissue_native_leaf_outer, NativeLeafOuterPlan, PreissuedNativeLeafOuter);
    leaf_preissue!(preissue_affine_leaf_outer, AffineLeafOuterPlan, PreissuedAffineLeafOuter);
    leaf_preissue!(preissue_ntt_leaf_outer, NttLeafOuterPlan, PreissuedNttLeafOuter);
    leaf_preissue!(preissue_mul_leaf_outer, MulLeafOuterPlan, PreissuedMulLeafOuter);
    leaf_preissue!(preissue_g_bound_leaf_outer, GBoundLeafOuterPlan, PreissuedGBoundLeafOuter);
    leaf_preissue!(preissue_permutation_leaf_outer, PermutationLeafOuterPlan, PreissuedPermutationLeafOuter);
    leaf_preissue!(preissue_linear_map_leaf_outer, LinearMapLeafOuterPlan, PreissuedLinearMapLeafOuter);
}
