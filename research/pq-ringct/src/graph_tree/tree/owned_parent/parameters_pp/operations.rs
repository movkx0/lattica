use super::*;
impl<'source, 'a> ParametersPpGraphPlan<'source, 'a> {
    pub(crate) fn compile_operation<'plan>(&'plan self, request: PairedRequestOutput<'a>)
        -> OwnedResult<ParametersPpCompileOperation<'plan, 'source, 'a>>
    { Ok(ParametersPpCompileOperation { plan: self, request, binding: self.binding(0)? }) }
    pub(crate) fn compile_operation_retaining<'plan>(&'plan self,
        request: PairedRequestOutput<'a>)
        -> core::result::Result<ParametersPpCompileOperation<'plan, 'source, 'a>,
            (GraphParentFailure, PairedRequestOutput<'a>)>
    {
        match self.binding(0) {
            Ok(binding) => Ok(ParametersPpCompileOperation { plan: self, request, binding }),
            Err(error) => Err((error, request)),
        }
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, compiled: Retained<OwnedGraphCompiled<'a>>)
        -> OwnedResult<ParametersPpOuterOperation<'plan, 'source, 'a>>
    { Ok(ParametersPpOuterOperation { plan: self, compiled, binding: self.binding(1)? }) }
    /// Refusal preserves the original compiled owner; the caller must poison.
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self,
        compiled: Retained<OwnedGraphCompiled<'a>>)
        -> core::result::Result<ParametersPpOuterOperation<'plan, 'source, 'a>,
            (GraphParentFailure, Retained<OwnedGraphCompiled<'a>>)>
    {
        match self.binding(1) {
            Ok(binding) => Ok(ParametersPpOuterOperation { plan: self, compiled, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
}
pub(crate) struct ParametersPpCompileOperation<'plan, 'source, 'a> {
    plan: &'plan ParametersPpGraphPlan<'source, 'a>,
    request: PairedRequestOutput<'a>,
    binding: PhaseBinding,
}
impl<'a> ParametersPpCompileOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slots(&self) -> [SlotId; 2] { [self.request.root_slot(), self.request.endpoint_slot()] }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> OwnedResult<OwnedGraphCompiled<'a>> {
        self.plan.check_execution(self.binding, execution)?;
        self.request.check_source(self.plan.request, execution).map_err(|_| GraphParentFailure::Authority)?;
        source::validate_coverage(self.plan.prepared.get(), self.plan.request, self.plan.source.span.first as usize)?;
        let started = Instant::now();
        let artifact = crate::graph_tree::owned_components::shake_artifact(&self.request,
            self.plan.request, self.plan.source.context, execution).map_err(|_| GraphParentFailure::Source)?;
        let mut artifacts = Vec::new();
        artifacts.try_reserve_exact(1).map_err(|_| GraphParentFailure::Capacity)?;
        if artifacts.capacity() > 1 { return Err(GraphParentFailure::Capacity); }
        artifacts.push(crate::graph_tree::LeafArtifact::ParametersPp(artifact));
        let node = crate::graph_tree::owned_components::compile_group(self.plan.source.plan,
            self.plan.prepared.get().graph(), self.plan.source.span.first as usize,
            self.plan.source.context, artifacts, super::super::source::construction(), execution)
            .map_err(|_| GraphParentFailure::Compilation)?;
        // Create the wiping owner before any conformance refusal. Both request
        // proof and endpoint claims stay live through all compiler reads.
        let compiled = OwnedGraphCompiled { report: GraphNodeReport { active_rows: node.program.active_rows(),
            padded_rows: node.program.height(), compile_ns: started.elapsed().as_nanos(),
            ..GraphNodeReport::default() }, node, source: self.plan.source };
        self.plan.source.check_compiled(&compiled.node)?;
        drop(self.request);
        Ok(compiled)
    }
}
pub(crate) struct ParametersPpOuterOperation<'plan, 'source, 'a> {
    plan: &'plan ParametersPpGraphPlan<'source, 'a>,
    compiled: Retained<OwnedGraphCompiled<'a>>,
    binding: PhaseBinding,
}
impl<'a> ParametersPpOuterOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> OwnedResult<OuterSourceShape> { self.plan.source.outer_shape() }
    pub(crate) fn borrowed_parts<'borrow>(&'borrow self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'borrow Arc<Program>, &'borrow Vec<Val>, &'borrow Vec<Val>)>
    {
        self.plan.check_execution(self.binding, execution)?;
        if self.compiled.binding() != self.plan.binding(0)? || !self.compiled.belongs_to(execution)
            || !self.compiled.get().source.same_source(self.plan.source)
        { return Err(GraphParentFailure::Authority); }
        self.plan.source.check_compiled(&self.compiled.get().node)?;
        let node = &self.compiled.get().node;
        Ok((&node.program, &node.public, &node.witness))
    }
    pub(crate) fn compiled_report(&self) -> GraphNodeReport { self.compiled.get().report }
    pub(super) fn prove_registered(&self,
        scope: &mut crate::execution::workflow_resources::OwnedOuterScope<'_, '_>,
        registered: RegisteredProgram,
        backend: &lattica_prover_p3::block_v2::machine::OuterBackendAdmission<'_>,
    ) -> OwnedResult<OwnedGraphNode<'a>> {
        self.borrowed_parts(scope.execution())?;
        super::super::outer::produce(self.compiled.get(), self.plan.cache, scope, registered, backend)
    }
}
