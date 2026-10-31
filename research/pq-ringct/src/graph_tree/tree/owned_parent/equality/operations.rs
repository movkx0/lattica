use super::*;
pub(super) struct WipedInputs(ProofInputs);
impl Drop for WipedInputs {
    fn drop(&mut self) {
        for value in &mut self.0.values { unsafe { core::ptr::write_volatile(value, Val::ZERO); } }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
/// Private, source-specific compiler. Production reaches it only under the
/// concrete EqualityCompileOperation's original source/output/scratch claims.
pub(super) fn compile<'a>(source: GraphNodeSource<'a>, graph: &UnprovedRelationGraph, census: FixedSourceCensus)
    -> OwnedResult<OwnedGraphCompiled<'a>> {
    let operation = source::validate_leaf(source.plan, graph, source.span.first as usize)?;
    let started = Instant::now();
    let spec = Spec { plan: Arc::clone(&source.plan.0), first: source.span.first, count: 1, level: 0 };
    let mut builder = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, census.construction)
        .map_err(|_| GraphParentFailure::Compilation)?;
    let public = public_wires(&mut builder, &spec).map_err(|_| GraphParentFailure::Compilation)?;
    let mut inputs = WipedInputs(ProofInputs::default());
    inputs.0.values.try_reserve_exact(census.construction.max_input_values).map_err(|_| GraphParentFailure::Capacity)?;
    if inputs.0.values.capacity() != census.construction.max_input_values { return Err(GraphParentFailure::Capacity); }
    let mut session = SourceBinding::new(&source.plan.0.shape, graph, &mut builder, &mut inputs.0,
        public[CONTEXT..CONTEXT + 8].try_into().unwrap(), public[STATEMENT..STATEMENT + 4].try_into().unwrap(),
        public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap()).map_err(|_| GraphParentFailure::Source)?;
    session.constrain_equality(operation).map_err(|_| GraphParentFailure::Source)?;
    let leaf = &source.plan.leaves()[source.span.first as usize];
    session.require_exact_coverage(leaf.polynomial_indices(), leaf.byte_indices(), leaf.operation_indices())
        .map_err(|_| GraphParentFailure::Coverage)?;
    if inputs.0.values.len() != census.construction.max_input_values
        || inputs.0.values.capacity() != census.construction.max_input_values { return Err(GraphParentFailure::Capacity); }
    let program = builder.finish(None).map_err(|_| GraphParentFailure::Compilation)?;
    let public = header(&spec, source.context);
    let node = CompiledNode { spec, program: Arc::new(program), public, witness: core::mem::take(&mut inputs.0.values) };
    let compiled = OwnedGraphCompiled { report: GraphNodeReport { active_rows: node.program.active_rows(),
        padded_rows: node.program.height(), compile_ns: started.elapsed().as_nanos(), ..GraphNodeReport::default() },
        node, source };
    source.check_compiled(&compiled.node)?;
    check_concrete(&compiled, census)?;
    Ok(compiled)
}
fn check_concrete(compiled: &OwnedGraphCompiled<'_>, census: FixedSourceCensus) -> OwnedResult<()> {
    let node = &compiled.node;
    if node.program.witness_values() != census.construction.max_input_values
        || node.witness.len() != census.construction.max_input_values
        || node.witness.capacity() != census.construction.max_input_values
        || node.program.construction_host_bytes() > census.construction.max_requested_program_bytes
        || shape::selection_hint_words(&node.program).map_err(|_| GraphParentFailure::Source)? != 0 {
        return Err(GraphParentFailure::Source);
    }
    Ok(())
}
impl<'source, 'a> EqualityGraphPlan<'source, 'a> {
    pub(crate) fn compile_operation<'plan>(&'plan self) -> OwnedResult<EqualityCompileOperation<'plan, 'source, 'a>> {
        Ok(EqualityCompileOperation { plan: self, binding: self.binding(0)? })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, compiled: Retained<OwnedGraphCompiled<'a>>)
        -> OwnedResult<EqualityOuterOperation<'plan, 'source, 'a>> {
        Ok(EqualityOuterOperation { plan: self, compiled, binding: self.binding(1)? })
    }
    /// Refusal preserves the original compiled owner; the caller must poison.
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self,
        compiled: Retained<OwnedGraphCompiled<'a>>)
        -> core::result::Result<EqualityOuterOperation<'plan, 'source, 'a>,
            (GraphParentFailure, Retained<OwnedGraphCompiled<'a>>)>
    {
        match self.binding(1) {
            Ok(binding) => Ok(EqualityOuterOperation { plan: self, compiled, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
}
pub(crate) struct EqualityCompileOperation<'plan, 'source, 'a> {
    plan: &'plan EqualityGraphPlan<'source, 'a>, binding: PhaseBinding,
}
impl<'a> EqualityCompileOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> OwnedResult<OwnedGraphCompiled<'a>> {
        self.plan.check_execution(self.binding, execution)?;
        compile(self.plan.source, self.plan.prepared.get().graph(), self.plan.census)
    }
}
pub(crate) struct EqualityOuterOperation<'plan, 'source, 'a> {
    plan: &'plan EqualityGraphPlan<'source, 'a>, compiled: Retained<OwnedGraphCompiled<'a>>, binding: PhaseBinding,
}
impl<'a> EqualityOuterOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> OwnedResult<OuterSourceShape> { self.plan.source.outer_shape() }
    pub(crate) fn borrowed_parts<'borrow>(&'borrow self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'borrow Arc<Program>, &'borrow Vec<Val>, &'borrow Vec<Val>)> {
        self.plan.check_execution(self.binding, execution)?;
        if self.compiled.binding() != self.plan.binding(0)? || !self.compiled.belongs_to(execution)
            || !self.compiled.get().source.same_source(self.plan.source) { return Err(GraphParentFailure::Authority); }
        self.plan.source.check_compiled(&self.compiled.get().node)?;
        check_concrete(self.compiled.get(), self.plan.census)?;
        let node = &self.compiled.get().node;
        Ok((&node.program, &node.public, &node.witness))
    }
    pub(crate) fn compiled_report(&self) -> GraphNodeReport { self.compiled.get().report }
    pub(super) fn prove_registered(&self, scope: &mut crate::execution::workflow_resources::OwnedOuterScope<'_, '_>,
        registered: RegisteredProgram, backend: &lattica_prover_p3::block_v2::machine::OuterBackendAdmission<'_>)
        -> OwnedResult<OwnedGraphNode<'a>> {
        self.borrowed_parts(scope.execution())?;
        super::super::outer::produce(self.compiled.get(), self.plan.cache, scope, registered, backend)
    }
}
