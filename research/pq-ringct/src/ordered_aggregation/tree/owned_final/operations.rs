use super::*;
use lattica_prover_p3::{block_v2::native_gpu::OperationContext, proving::Policy};

/// Only an actual graph producer can create this original-owned graph node.
/// There is no detached key/proof tuple. Index and context are checked
/// against the immutable final source before any numerical verification.
/// The graph owner keeps its original payload lifetime even when the final
/// plan belongs to a deeper scope. Refusals return that exact original owner.
pub(crate) enum FinalChild<'graph, 'source> {
    Graph { index: usize, owner: Retained<OwnedGraphNode<'graph>> },
    Merge(Retained<FinalNode<'source>>),
}
impl FinalChild<'_, '_> {
    fn slot(&self) -> SlotId {
        match self { Self::Graph { owner, .. } => owner.slot_id(), Self::Merge(owner) => owner.slot_id() }
    }
}

pub(crate) struct FinalCompiled<'source> {
    pub(super) node: CompiledNode,
    pub(super) source: &'source FinalAggregationPlan<'source>,
    pub(super) merge: usize,
    pub(super) report: FinalReport,
}
impl Drop for FinalCompiled<'_> {
    fn drop(&mut self) {
        self.node.witness.fill(Val::ZERO);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
impl FinalCompiled<'_> {
    pub(crate) fn report(&self) -> FinalReport { self.report }
}
pub(crate) struct FinalNode<'source> {
    pub(super) node: BatchNode,
    pub(super) source: &'source FinalAggregationPlan<'source>,
    pub(super) merge: usize,
    pub(super) report: FinalReport,
}
impl FinalNode<'_> {
    pub(crate) fn key(&self) -> &BatchKey { &self.node.key }
    pub(crate) fn proof(&self) -> &BatchProof { &self.node.proof }
    pub(crate) fn report(&self) -> FinalReport { self.report }
}

/// Acceptance remains attached to the original final root. It neither moves
/// a raw proof out of its original owner nor creates another proof claim.
pub(crate) struct FinalVerification<'root, 'source> {
    root: &'root Retained<FinalNode<'source>>,
    cpu_verification_ns: u128,
    qualification: FinalQualificationReport,
}
impl FinalVerification<'_, '_> {
    pub(crate) fn key(&self) -> &BatchKey { self.root.get().key() }
    pub(crate) fn proof(&self) -> &BatchProof { self.root.get().proof() }
    pub(crate) fn cpu_verification_ns(&self) -> u128 { self.cpu_verification_ns }
    pub(crate) fn report(&self) -> FinalReport {
        let root = self.root.get().report();
        FinalReport { merge: root.merge, first: root.first, count: root.count,
            active_rows: root.active_rows, padded_rows: root.padded_rows,
            cpu_verification_ns: self.cpu_verification_ns,
            qualification: self.qualification, ..FinalReport::default() }
    }
}

fn access(binding: PhaseBinding, execution: &ExecutionAccess<'_>) -> OwnedResult<()> {
    if execution.binding() != binding || execution.context().policy() != Policy::GpuRequired {
        return Err(FinalFailure::Authority);
    }
    Ok(())
}
fn owner<T>(owner: &Retained<T>, binding: PhaseBinding, execution: &ExecutionAccess<'_>)
    -> OwnedResult<()>
{
    if !owner.belongs_to(execution) || owner.binding() != binding {
        return Err(FinalFailure::Authority);
    }
    Ok(())
}

impl<'source> FinalPhasePlan<'source> {
    pub(crate) fn compile_operation<'plan, 'graph>(&'plan self, ordinal: usize,
        children: [FinalChild<'graph, 'source>; 2]) -> OwnedResult<FinalCompileOperation<'plan, 'graph, 'source>>
    {
        let Some(FinalStepKind::Compile(merge)) = self.step_kind(ordinal)
            else { return Err(FinalFailure::Order); };
        Ok(FinalCompileOperation { plan: self, merge, children,
            binding: self.binding(ordinal, FinalStepKind::Compile(merge))? })
    }
    /// Complete-driver refusal keeps both exact original child owners. The
    /// caller restores their cells and poisons before any further dispatch.
    pub(crate) fn compile_operation_retaining<'plan, 'graph>(&'plan self, ordinal: usize,
        children: [FinalChild<'graph, 'source>; 2])
        -> core::result::Result<FinalCompileOperation<'plan, 'graph, 'source>,
            (FinalFailure, [FinalChild<'graph, 'source>; 2])>
    {
        let Some(FinalStepKind::Compile(merge)) = self.step_kind(ordinal)
            else { return Err((FinalFailure::Order, children)); };
        let binding = match self.binding(ordinal, FinalStepKind::Compile(merge)) {
            Ok(binding) => binding,
            Err(error) => return Err((error, children)),
        };
        Ok(FinalCompileOperation { plan: self, merge, children, binding })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, ordinal: usize,
        compiled: Retained<FinalCompiled<'source>>) -> OwnedResult<FinalOuterOperation<'plan, 'source>>
    {
        let Some(FinalStepKind::Outer(merge)) = self.step_kind(ordinal)
            else { return Err(FinalFailure::Order); };
        if !self.fresh_only() { return Err(FinalFailure::Authority); }
        Ok(FinalOuterOperation { plan: self, merge, compiled,
            binding: self.binding(ordinal, FinalStepKind::Outer(merge))? })
    }
    /// No replacement compiler claim is created on a source or policy refusal.
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self, ordinal: usize,
        compiled: Retained<FinalCompiled<'source>>)
        -> core::result::Result<FinalOuterOperation<'plan, 'source>,
            (FinalFailure, Retained<FinalCompiled<'source>>)>
    {
        let Some(FinalStepKind::Outer(merge)) = self.step_kind(ordinal)
            else { return Err((FinalFailure::Order, compiled)); };
        if !self.fresh_only() { return Err((FinalFailure::Authority, compiled)); }
        let binding = match self.binding(ordinal, FinalStepKind::Outer(merge)) {
            Ok(binding) => binding,
            Err(error) => return Err((error, compiled)),
        };
        Ok(FinalOuterOperation { plan: self, merge, compiled, binding })
    }
    pub(crate) fn verify_operation<'root, 'plan>(&'plan self, ordinal: usize,
        root: &'root Retained<FinalNode<'source>>)
        -> OwnedResult<FinalVerifyOperation<'root, 'plan, 'source>>
    {
        Ok(FinalVerifyOperation { plan: self, root,
            binding: self.binding(ordinal, FinalStepKind::Verify)? })
    }
}

pub(crate) struct FinalCompileOperation<'plan, 'graph, 'source> {
    plan: &'plan FinalPhasePlan<'source>,
    merge: usize,
    children: [FinalChild<'graph, 'source>; 2],
    binding: PhaseBinding,
}
impl<'source> FinalCompileOperation<'_, '_, 'source> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slots(&self) -> [SlotId; 2] { self.children.each_ref().map(FinalChild::slot) }
    pub(crate) fn preparation_requirements(&self) -> OwnedResult<(Requirements, Bytes)> {
        Ok((self.binding.facts().scratch, self.plan.compile_backend(self.binding.ordinal())?))
    }
    pub(crate) fn execute_with_operations(&self, execution: &ExecutionAccess<'_>,
        operations: &OperationContext<'_>) -> OwnedResult<FinalCompiled<'source>>
    {
        access(self.binding, execution)?;
        if !self.plan.fresh_only() { return Err(FinalFailure::Authority); }
        let source = self.plan.source;
        let merge = source.merge(self.merge).ok_or(FinalFailure::Order)?;
        let mut graphs = [None, None];
        // Every ownership, ordering and actual source identity check precedes
        // either the numeric verifier or the GPU leaf/node commitment.
        for (child, expected) in self.children.iter().zip(merge.children()) {
            match (child, expected) {
                (FinalChild::Graph { index, owner: retained }, ChildSource::Graph(expected))
                    if *index == expected =>
                {
                    let binding = self.plan.graph_binding(expected)?;
                    owner(retained, binding, execution)?;
                    let graph = source.graphs().get(expected).ok_or(FinalFailure::Order)?;
                    let node = retained.get();
                    let key = node.key(); let proof = node.proof();
                    let expected_source = self.plan.graph_source(expected)?;
                    if !core::ptr::eq(node.context(), graph.context)
                        || !core::ptr::eq(node.graph_plan(), graph.plan)
                        || node.source().source_fingerprint() != expected_source.source().source_fingerprint()
                        || node.source().compiled_source_fingerprint() != source.compiled_source_fingerprint()
                        || key.source_height() > expected_source.source().maximum_height()
                        || !key.matches_owned_final_input(graph.plan, proof, binding.facts().output)
                        || key.profile_label() != graph.plan.label()
                    { return Err(FinalFailure::Authority); }
                }
                (FinalChild::Merge(retained), ChildSource::Merge(expected)) if expected < self.merge => {
                    owner(retained, self.plan.binding(2 * expected + 1,
                        FinalStepKind::Outer(expected))?, execution)?;
                    memory::check_node(retained.get(), self.plan, expected)?;
                }
                _ => return Err(FinalFailure::Coverage),
            }
        }
        // Finish BOTH children's ownership/coverage checks before numerical
        // verification, compiler allocation or the first GPU root hash.
        let verification_started = Instant::now();
        for (position, child) in self.children.iter().enumerate() {
            match child {
                FinalChild::Graph { index, owner } => {
                    let node = owner.get();
                    graphs[position] = Some(source.scope().graph_child(
                        u32::try_from(*index).map_err(|_| FinalFailure::Overflow)?,
                        node.key(), node.proof(), node.context())
                        .map_err(|_| FinalFailure::Verification)?);
                }
                FinalChild::Merge(owner) => owner.get().node.key.verify(&owner.get().node.proof)
                    .map_err(|_| FinalFailure::Verification)?,
            }
        }
        let cpu_verification_ns = verification_started.elapsed().as_nanos();
        let borrowed = |position: usize| -> OwnedResult<ChildRef<'_>> {
            match &self.children[position] {
                FinalChild::Graph { .. } => Ok(ChildRef::Graph(
                    graphs[position].as_ref().ok_or(FinalFailure::Coverage)?)),
                FinalChild::Merge(retained) => Ok(ChildRef::Batch(&retained.get().node)),
            }
        };
        let children = [borrowed(0)?, borrowed(1)?];
        let started = Instant::now();
        let node = compile_merge_from_source_on_gpu(source, self.merge, children, operations)
            .map_err(|_| FinalFailure::Compile)?;
        memory::check_compiler(merge, &node)?;
        let report = FinalReport { merge: self.merge, first: merge.span().0, count: merge.span().1,
            active_rows: node.program.active_rows(), padded_rows: node.program.height(),
            compile_ns: started.elapsed().as_nanos(), cpu_verification_ns,
            ..FinalReport::default() };
        // The execution issuer keeps this borrowed operation and its exact
        // retained children until actual runtime retirement. Dropping the
        // temporary GraphChild views does not release their original slots.
        drop(graphs);
        Ok(FinalCompiled { node, source, merge: self.merge, report })
    }
}

pub(crate) struct FinalOuterOperation<'plan, 'source> {
    pub(super) plan: &'plan FinalPhasePlan<'source>,
    pub(super) merge: usize,
    pub(super) compiled: Retained<FinalCompiled<'source>>,
    pub(super) binding: PhaseBinding,
}
impl FinalOuterOperation<'_, '_> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn borrowed_parts<'a>(&'a self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'a Arc<Program>, &'a [Val; PUBLIC_VALUES], &'a Vec<Val>)>
    {
        access(self.binding, execution)?;
        owner(&self.compiled, self.plan.binding(2 * self.merge,
            FinalStepKind::Compile(self.merge))?, execution)?;
        let value = self.compiled.get();
        if !core::ptr::eq(value.source, self.plan.source) || value.merge != self.merge
            || !self.plan.fresh_only()
        { return Err(FinalFailure::Authority); }
        memory::check_compiler(self.plan.source.merge(self.merge).ok_or(FinalFailure::Order)?, &value.node)?;
        Ok((&value.node.program, &value.node.public, &value.node.witness))
    }
}

pub(crate) struct FinalVerifyOperation<'root, 'plan, 'source> {
    plan: &'plan FinalPhasePlan<'source>,
    root: &'root Retained<FinalNode<'source>>,
    binding: PhaseBinding,
}
impl<'root, 'source> FinalVerifyOperation<'root, '_, 'source> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.root.slot_id() }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<FinalVerification<'root, 'source>>
    {
        access(self.binding, execution)?;
        let merge = self.plan.source.merge_count() - 1;
        owner(self.root, self.plan.binding(2 * merge + 1, FinalStepKind::Outer(merge))?, execution)?;
        memory::check_node(self.root.get(), self.plan, merge)?;
        if !self.plan.fresh_only()
            || self.root.get().node.key.span() != (0, self.plan.source.scope().total())
        { return Err(FinalFailure::Coverage); }
        let started = Instant::now();
        // This independently recomputes the expected ordered root from the
        // exact original statement slice and performs real CPU proof verification.
        self.root.get().node.key.verify_expected(&self.root.get().node.proof, self.plan.statements)
            .map_err(|_| FinalFailure::Verification)?;
        let original_cpu_verification_ns = started.elapsed().as_nanos();
        let qualification = qualification::run(self.root, self.plan, execution)?;
        let cpu_verification_ns = original_cpu_verification_ns
            .checked_add(qualification.decoded_cpu_verification_ns)
            .and_then(|value| value.checked_add(qualification.mutation_cpu_verification_ns))
            .ok_or(FinalFailure::Overflow)?;
        Ok(FinalVerification { root: self.root, cpu_verification_ns, qualification })
    }
}
