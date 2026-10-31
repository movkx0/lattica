use super::*;
use lattica_prover_p3::proving::Policy;
fn access(binding: PhaseBinding, execution: &ExecutionAccess<'_>) -> OwnedResult<()> {
    if execution.binding() != binding || execution.context().policy() != Policy::GpuRequired {
        return Err(GraphParentFailure::Authority);
    }
    Ok(())
}
fn owner<T>(owner: &Retained<T>, binding: PhaseBinding, execution: &ExecutionAccess<'_>) -> OwnedResult<()> {
    if owner.binding() != binding || !owner.belongs_to(execution) { return Err(GraphParentFailure::Authority); }
    Ok(())
}
impl<'source, 'graph> GraphParentPlan<'source, 'graph> {
    pub(crate) fn compile_operation<'plan>(&'plan self, children: [Retained<OwnedGraphNode<'graph>>; 2])
        -> OwnedResult<GraphParentCompileOperation<'plan, 'source, 'graph>>
    {
        Ok(GraphParentCompileOperation { plan: self, children, binding: self.binding(0)? })
    }
    pub(crate) fn compile_operation_retaining<'plan>(&'plan self,
        children: [Retained<OwnedGraphNode<'graph>>; 2])
        -> core::result::Result<GraphParentCompileOperation<'plan, 'source, 'graph>,
            (GraphParentFailure, [Retained<OwnedGraphNode<'graph>>; 2])>
    {
        match self.binding(0) {
            Ok(binding) => Ok(GraphParentCompileOperation { plan: self, children, binding }),
            Err(error) => Err((error, children)),
        }
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, compiled: Retained<OwnedGraphCompiled<'graph>>)
        -> OwnedResult<GraphParentOuterOperation<'plan, 'source, 'graph>>
    {
        if self.cache.policy() != ProofCachePolicy::FreshOnly { return Err(GraphParentFailure::Authority); }
        Ok(GraphParentOuterOperation { plan: self, compiled, binding: self.binding(1)? })
    }
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self,
        compiled: Retained<OwnedGraphCompiled<'graph>>)
        -> core::result::Result<GraphParentOuterOperation<'plan, 'source, 'graph>,
            (GraphParentFailure, Retained<OwnedGraphCompiled<'graph>>)>
    {
        if self.cache.policy() != ProofCachePolicy::FreshOnly {
            return Err((GraphParentFailure::Authority, compiled));
        }
        match self.binding(1) {
            Ok(binding) => Ok(GraphParentOuterOperation { plan: self, compiled, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
}
pub(crate) struct GraphParentCompileOperation<'plan, 'source, 'graph> {
    plan: &'plan GraphParentPlan<'source, 'graph>,
    children: [Retained<OwnedGraphNode<'graph>>; 2],
    binding: PhaseBinding,
}
impl<'graph> GraphParentCompileOperation<'_, '_, 'graph> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slots(&self) -> [SlotId; 2] { self.children.each_ref().map(Retained::slot_id) }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> OwnedResult<OwnedGraphCompiled<'graph>> {
        access(self.binding, execution)?;
        if self.plan.cache.policy() != ProofCachePolicy::FreshOnly { return Err(GraphParentFailure::Authority); }
        for (child, expected) in self.children.iter().zip(self.plan.children) {
            owner(child, expected.binding, execution)?;
            let value = child.get();
            if !value.source.same_source(*expected.source)
                || !value.source.plan.matches_final_inner(&value.key.spec.plan)
                || !value.source.span.agrees(&value.key.spec)
                || !value.source.check_public(&value.proof.public)
                || value.key.height > value.source.maximum_padded_rows
            { return Err(GraphParentFailure::Source); }
            outer::check_retained(value, expected.binding.facts().output)?;
        }
        let left = self.children[0].get(); let right = self.children[1].get();
        let spec = Spec::merge(&left.key.spec, &right.key.spec).map_err(|_| GraphParentFailure::Coverage)?;
        if !self.plan.source.span.agrees(&spec) { return Err(GraphParentFailure::Source); }
        let started = Instant::now();
        let mut public = Vec::new();
        public.try_reserve_exact(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Capacity)?;
        if public.capacity() > PUBLIC_VALUES { return Err(GraphParentFailure::Capacity); }
        public.extend_from_slice(&left.proof.public);
        public[FIRST] = Val::from_u32(spec.first);
        public[COUNT] = Val::from_u32(spec.count);
        public[LEVEL] = Val::from_u32(spec.level);
        let mut builder = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, source::construction())
            .map_err(|_| GraphParentFailure::Capacity)?;
        let outer: [Wire; PUBLIC_VALUES] = public_wires(&mut builder, &spec)
            .map_err(|_| GraphParentFailure::Compilation)?.try_into().map_err(|_| GraphParentFailure::Source)?;
        let mut inputs = ProofInputs::default();
        let mut child_wires = [[outer[0]; PUBLIC_VALUES]; 2];
        for (index, child) in [left, right].into_iter().enumerate() {
            let actual = source::registered_shape(child.key.height)?;
            if child.key.cap.len() != actual.preprocessing_cap_roots { return Err(GraphParentFailure::Source); }
            child_wires[index] = inputs.bases(&mut builder, &child.proof.public)
                .map_err(|_| GraphParentFailure::Compilation)?.try_into().map_err(|_| GraphParentFailure::Source)?;
            let mut cap = [[outer[0]; 4]; 64];
            for (target, root) in cap.iter_mut().zip(&child.key.cap) {
                *target = root.map(|value| builder.constant(value));
            }
            verifier::batch::verify_with_bounded_cpu_symbolic(&mut builder, &mut inputs,
                &child.key.air().map_err(|_| GraphParentFailure::Source)?,
                &child_wires[index], &cap[..child.key.cap.len()], &child.proof.proof)
                .map_err(|_| GraphParentFailure::Compilation)?;
        }
        bind_merge(&mut builder, &outer, &child_wires[0], &child_wires[1]);
        let node = CompiledNode { spec, program: Arc::new(builder.finish(None)
            .map_err(|_| GraphParentFailure::Capacity)?), public, witness: inputs.values };
        self.plan.source.check_compiled(&node)?;
        let report = GraphNodeReport { active_rows: node.program.active_rows(), padded_rows: node.program.height(),
            compile_ns: started.elapsed().as_nanos(), ..GraphNodeReport::default() };
        // Both retained children remain live until every parent input has been
        // copied and the bounded compiler output has passed source checks.
        drop(self.children);
        Ok(OwnedGraphCompiled { node, source: self.plan.source, report })
    }
}
pub(crate) struct GraphParentOuterOperation<'plan, 'source, 'graph> {
    plan: &'plan GraphParentPlan<'source, 'graph>,
    compiled: Retained<OwnedGraphCompiled<'graph>>,
    binding: PhaseBinding,
}
impl<'graph> GraphParentOuterOperation<'_, '_, 'graph> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> OwnedResult<OuterSourceShape> { self.plan.source.outer_shape() }
    pub(crate) fn borrowed_parts<'a>(&'a self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'a Arc<Program>, &'a Vec<Val>, &'a Vec<Val>)>
    {
        access(self.binding, execution)?;
        owner(&self.compiled, self.plan.binding(0)?, execution)?;
        if !self.compiled.get().source.same_source(self.plan.source) { return Err(GraphParentFailure::Source); }
        self.plan.source.check_compiled(&self.compiled.get().node)?;
        let node = &self.compiled.get().node;
        Ok((&node.program, &node.public, &node.witness))
    }
    pub(crate) fn compiled_report(&self) -> GraphNodeReport { self.compiled.get().report }
    pub(super) fn prove_registered(&self,
        scope: &mut crate::execution::workflow_resources::OwnedOuterScope<'_, '_>,
        registered: RegisteredProgram,
        backend: &lattica_prover_p3::block_v2::machine::OuterBackendAdmission<'_>)
        -> OwnedResult<OwnedGraphNode<'graph>>
    {
        self.borrowed_parts(scope.execution())?;
        outer::produce(self.compiled.get(), self.plan.cache, scope, registered, backend)
    }
}
