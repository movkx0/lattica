//! Concrete Permutation leaf outer bridge. The compiler owner keeps
//! its exact original claim inside RetainedOriginal until runtime retirement.
//! There is no raw CompiledNode or proof attachment interface.
use super::*;
use crate::{
    execution::workflow_resources::RetainedOriginal,
    graph_tree::permutation_sources::{PermutationLeafCompiler, OwnedCompiledPermutation},
    spend_pipeline::full_workflow::permutation_native_compile::PermutationNativeCompilePlan,
};
use lattica_prover_p3::proving::Policy;

mod source;
mod outer;
pub(crate) use outer::{BoundPermutationLeafOuter, PreissuedPermutationLeafOuter};

pub(crate) struct PermutationLeafOuterPlan<'source, 'a> {
    compiler: &'source PermutationNativeCompilePlan<'a>,
    source: GraphNodeSource<'a>,
    fact: PhaseFacts,
    cache: &'source OuterProofCache,
    original: Reservation,
}
impl<'source, 'a> PermutationLeafOuterPlan<'source, 'a> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        requirement(Category::RegisteredMetadata,
            add(Self::frames()?, PreissuedPermutationLeafOuter::metadata_host_bytes()?)?)
    }
    fn frames() -> OwnedResult<usize> {
        [bytes::<Self>(8)?, bytes::<GraphNodeSource<'static>>(8)?,
            bytes::<GraphChildSource<'static, 'static>>(8)?, bytes::<GraphNodeReport>(8)?,
            bytes::<PermutationLeafOuterOperation<'static, 'static, 'static>>(8)?,
            bytes::<RetainedOriginal<OwnedCompiledPermutation<'static, 'static, 'static>>>(8)?,
            bytes::<core::result::Result<PermutationLeafOuterOperation<'static, 'static, 'static>,
                (GraphParentFailure, RetainedOriginal<OwnedCompiledPermutation<'static, 'static, 'static>>)>>(8)?,
            bytes::<(GraphParentFailure, RetainedOriginal<OwnedCompiledPermutation<'static, 'static, 'static>>)>(8)?,
            bytes::<core::result::Result<PreissuedPermutationLeafOuter<'static, 'static, 'static>,
                crate::execution::workflow_resources::WorkflowError>>(8)?,
            bytes::<Retained<OwnedGraphNode<'static>>>(8)?, bytes::<Sha3_256>(8)?,
            bytes::<PhaseFacts>(8)?, bytes::<PhaseBinding>(8)?, bytes::<Requirements>(16)?,
            bytes::<OwnedResult<Self>>(8)?, bytes::<OwnedResult<OwnedGraphNode<'static>>>(8)?,
            bytes::<[usize; 24]>(8)?,
        ].into_iter().try_fold(64 << 10, add)
    }
    /// A concrete same-owner compiler plan is required; numeric phase facts or
    /// a detached blueprint cannot issue this outer source.
    pub(crate) fn derive_pre_reserved(compiler: &'source PermutationNativeCompilePlan<'a>,
        cache: &'source OuterProofCache, original: Reservation, ledger: &Ledger,
    ) -> OwnedResult<Self> {
        if cache.policy() != ProofCachePolicy::FreshOnly || !original.belongs_to(ledger)
            || original.requirements() != Self::planning_requirements()?
            || !compiler.belongs_to(ledger)
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
            || ledger.snapshot().allowance.device > 8 << 30
        { return Err(GraphParentFailure::Authority); }
        let compiled = compiler.source_compile_plan();
        let binding = compiler.binding().map_err(|_| GraphParentFailure::Authority)?;
        if binding.facts().output != compiled.blueprint().compiler_requirements().0 {
            return Err(GraphParentFailure::Authority);
        }
        let source = GraphNodeSource::from_permutation_compile(compiled)?;
        let (output, verifier) = source.output_requirements()?;
        let fact = PhaseFacts { kind: PhaseKind::GraphOuter,
            source_fingerprint: source.source_fingerprint,
            compiled_source_fingerprint: source.compiled_source_fingerprint,
            output, failure: super::memory::failure_requirements()?,
            scratch: combine(&[verifier, super::outer::caller_requirements()?,
                requirement(Category::PhaseScratch, Self::frames()?)?,
                PreissuedPermutationLeafOuter::planning_scratch_requirement()?])? };
        Ok(Self { compiler, source, fact, cache, original })
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> {
        (ordinal == 0).then_some(self.fact)
    }
    pub(crate) fn binding(&self) -> OwnedResult<PhaseBinding> {
        PhaseBinding::for_permutation_leaf_outer(self, 0).map_err(|_| GraphParentFailure::Authority)
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger) && self.compiler.belongs_to(ledger)
    }
    pub(crate) fn source(&self) -> &GraphNodeSource<'a> { &self.source }
    pub(crate) fn compiler_plan(&self) -> &'source PermutationNativeCompilePlan<'a> { self.compiler }
    pub(crate) fn child_source(&self) -> OwnedResult<GraphChildSource<'_, 'a>> {
        Ok(GraphChildSource { source: &self.source, binding: self.binding()? })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self,
        compiled: RetainedOriginal<OwnedCompiledPermutation<'a, 'a, 'a>>,
    ) -> OwnedResult<PermutationLeafOuterOperation<'plan, 'source, 'a>> {
        if self.cache.policy() != ProofCachePolicy::FreshOnly {
            return Err(GraphParentFailure::Authority);
        }
        Ok(PermutationLeafOuterOperation { plan: self, compiled, binding: self.binding()? })
    }
    /// Preserve the exact compiled owner when pre-dispatch validation refuses.
    /// The driver restores a refused owner into its original stable input cell.
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self,
        compiled: RetainedOriginal<OwnedCompiledPermutation<'a, 'a, 'a>>,
    ) -> core::result::Result<PermutationLeafOuterOperation<'plan, 'source, 'a>,
        (GraphParentFailure, RetainedOriginal<OwnedCompiledPermutation<'a, 'a, 'a>>)>
    {
        let checked = (|| {
            if self.cache.policy() != ProofCachePolicy::FreshOnly {
                return Err(GraphParentFailure::Authority);
            }
            self.binding()
        })();
        match checked {
            Ok(binding) => Ok(PermutationLeafOuterOperation { plan: self, compiled, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
    fn check_compiled(&self, compiled: &OwnedCompiledPermutation<'a, 'a, 'a>) -> OwnedResult<()> {
        let expected = self.compiler.source_compile_plan();
        let facts = expected.facts();
        let node = compiled.node();
        if !core::ptr::eq(compiled.blueprint(), expected.blueprint())
            || compiled.facts() != facts
            || compiled.reservation().requirements() != expected.blueprint().compiler_requirements().0
            || node.program.witness_values() != facts.input_values
            || node.witness.len() != facts.input_values
            || shape::selection_hint_words(&node.program).map_err(|_| GraphParentFailure::Source)?
                != facts.selection_hint_words
        { return Err(GraphParentFailure::Source); }
        self.source.check_compiled(node)
    }
}

pub(crate) struct PermutationLeafOuterOperation<'plan, 'source, 'a> {
    plan: &'plan PermutationLeafOuterPlan<'source, 'a>,
    compiled: RetainedOriginal<OwnedCompiledPermutation<'a, 'a, 'a>>,
    binding: PhaseBinding,
}
impl<'a> PermutationLeafOuterOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> OwnedResult<OuterSourceShape> { self.plan.source.outer_shape() }
    pub(crate) fn borrowed_parts<'borrow>(&'borrow self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'borrow Arc<Program>, &'borrow Vec<Val>, &'borrow Vec<Val>)>
    {
        if execution.binding() != self.binding || execution.context().policy() != Policy::GpuRequired
            || self.plan.cache.policy() != ProofCachePolicy::FreshOnly
            || self.compiled.binding() != self.plan.compiler.binding().map_err(|_| GraphParentFailure::Authority)?
            || !self.compiled.belongs_to(execution)
        { return Err(GraphParentFailure::Authority); }
        self.plan.check_compiled(self.compiled.get())?;
        let node = self.compiled.get().node();
        Ok((&node.program, &node.public, &node.witness))
    }
    pub(crate) fn compiled_report(&self) -> GraphNodeReport {
        let compiled = self.compiled.get();
        GraphNodeReport { active_rows: compiled.node().program.active_rows(),
            padded_rows: compiled.node().program.height(), compile_ns: compiled.compile_ns(),
            ..GraphNodeReport::default() }
    }
    fn prove_registered(&self,
        scope: &mut crate::execution::workflow_resources::OwnedOuterScope<'_, '_>,
        registered: RegisteredProgram,
        backend: &lattica_prover_p3::block_v2::machine::OuterBackendAdmission<'_>,
    ) -> OwnedResult<OwnedGraphNode<'a>> {
        self.borrowed_parts(scope.execution())?;
        super::outer::produce_borrowed(self.compiled.get().node(), self.plan.source,
            self.compiled_report(), self.plan.cache, scope, registered, backend)
    }
}
