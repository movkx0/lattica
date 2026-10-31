//! Exact original owner list for the four closed auxiliary graph relations.
use super::*;
use crate::graph_tree::owned_parent::{AuxiliaryCompileOperation, OwnedGraphCompiled, GraphParentFailure};
impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_owned_auxiliary<'a>(self, operation: AuxiliaryCompileOperation<'_, '_, 'a>)
        -> Result<Retained<OwnedGraphCompiled<'a>>, PhaseFailure<GraphParentFailure>> {
        let (slots, count) = operation.input_slots();
        if self.step.input_count != count || self.step.consume_count != count
            || preflight::inputs(self.admission.plan, self.step).map_err(PhaseFailure::Admission)? != &slots[..count]
            || self.step.backend != Bytes::ZERO { return Err(PhaseFailure::Admission(WorkflowError::Sequence)); }
        self.execute(operation.binding(), |access| operation.execute(access))
    }
}
