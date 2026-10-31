use super::*;
use crate::graph_tree::owned_parent::{EqualityCompileOperation, OwnedGraphCompiled, GraphParentFailure};
impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_owned_equality<'a>(self, operation: EqualityCompileOperation<'_, '_, 'a>)
        -> Result<Retained<OwnedGraphCompiled<'a>>, PhaseFailure<GraphParentFailure>> {
        if self.step.input_count != 0 || self.step.consume_count != 0 || self.step.backend != Bytes::ZERO {
            return Err(PhaseFailure::Admission(WorkflowError::Sequence));
        }
        self.execute(operation.binding(), |access| operation.execute(access))
    }
}
