//! Exact two-owner ParametersPp graph compiler. Source facts and operations are
//! concrete; this child adds no generic artifact, proof or source attachment.
use super::*;
use crate::graph_tree::owned_parent::{ParametersPpCompileOperation, OwnedGraphCompiled, GraphParentFailure};
impl WorkflowPhase<'_, '_, '_> {
    pub(crate) fn compile_owned_parameters_pp<'a>(self,
        operation: ParametersPpCompileOperation<'_, '_, 'a>,
    ) -> Result<Retained<OwnedGraphCompiled<'a>>, PhaseFailure<GraphParentFailure>> {
        if self.step.input_count != 2 || self.step.consume_count != 2
            || preflight::inputs(self.admission.plan, self.step)
                .map_err(PhaseFailure::Admission)? != operation.input_slots()
            || self.step.backend != Bytes::ZERO
        { return Err(PhaseFailure::Admission(WorkflowError::Sequence)); }
        self.execute(operation.binding(), |access| operation.execute(access))
    }
}
