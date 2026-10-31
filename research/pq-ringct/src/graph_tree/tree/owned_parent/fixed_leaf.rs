//! Concrete fixed-source graph outer bridge; the existing source compiler's
//! retained payload remains borrowed through proving, verification and retirement.
use super::*;
use crate::{
    graph_tree::fixed_sources::{FixedSourceCensus, FixedSourceCompilePlan},
    spend_pipeline::full_workflow::{SourceOperationPlan, CompiledFixedSources},
};
use lattica_prover_p3::proving::Policy;
mod source;
mod outer;
pub(crate) use outer::{PreissuedFixedLeafOuter, BoundFixedLeafOuter};

pub(crate) struct FixedLeafOuterPlan<'source, 'a> {
    compiler: &'source SourceOperationPlan<'a>,
    source: GraphNodeSource<'a>,
    census: FixedSourceCensus,
    fact: PhaseFacts,
    cache: &'source OuterProofCache,
    original: Reservation,
}
impl<'source, 'a> FixedLeafOuterPlan<'source, 'a> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        requirement(Category::RegisteredMetadata,
            add(source::frames()?, PreissuedFixedLeafOuter::metadata_host_bytes()?)?)
    }
    pub(crate) fn derive_pre_reserved(compiler: &'source SourceOperationPlan<'a>,
        cache: &'source OuterProofCache, original: Reservation, ledger: &Ledger,
    ) -> OwnedResult<Self> {
        if compiler.context().policy() != Policy::GpuRequired || cache.policy() != ProofCachePolicy::FreshOnly
            || !original.belongs_to(ledger) || !compiler.sources().belongs_to(ledger)
            || original.requirements() != Self::planning_requirements()?
            || compiler.sources().source_fingerprint() != compiler.workflow_source_fingerprint()
            || compiler.sources().compiled_source_fingerprint() != compiler.compiled_source_fingerprint()
            || compiler.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint()
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
            || ledger.snapshot().allowance.device > 8 << 30
        { return Err(GraphParentFailure::Authority); }
        let prepared = compiler.sources().get();
        let fixed = FixedSourceCompilePlan::new(prepared.plan(), prepared.graph(), prepared.context())
            .map_err(|_| GraphParentFailure::Coverage)?;
        let census = fixed.census();
        let source = source::derive(prepared.plan(), prepared.graph(), prepared.context(), census,
            compiler.source_fingerprint(), compiler.compiled_source_fingerprint())?;
        let (output, verifier) = source.output_requirements()?;
        let fact = PhaseFacts { kind: PhaseKind::GraphOuter,
            source_fingerprint: source.source_fingerprint,
            compiled_source_fingerprint: source.compiled_source_fingerprint,
            output, failure: super::memory::failure_requirements()?,
            scratch: combine(&[verifier, super::outer::caller_requirements()?,
                requirement(Category::PhaseScratch, source::frames()?)?,
                PreissuedFixedLeafOuter::planning_scratch_requirement()?])? };
        Ok(Self { compiler, source, census, fact, cache, original })
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { (ordinal == 0).then_some(self.fact) }
    pub(crate) fn binding(&self) -> OwnedResult<PhaseBinding> {
        PhaseBinding::for_fixed_leaf_outer(self, 0).map_err(|_| GraphParentFailure::Authority)
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger) && self.compiler.sources().belongs_to(ledger)
    }
    pub(crate) fn compiler_plan(&self) -> &'source SourceOperationPlan<'a> { self.compiler }
    pub(crate) fn source(&self) -> &GraphNodeSource<'a> { &self.source }
    pub(crate) fn child_source(&self) -> OwnedResult<GraphChildSource<'_, 'a>> {
        Ok(GraphChildSource { source: &self.source, binding: self.binding()? })
    }
    pub(crate) fn outer_operation<'plan>(&'plan self, compiled: Retained<CompiledFixedSources<'a>>)
        -> OwnedResult<FixedLeafOuterOperation<'plan, 'source, 'a>>
    { Ok(FixedLeafOuterOperation { plan: self, compiled, binding: self.binding()? }) }
    /// A refusal returns the same compiler owner for restoration in its cell.
    pub(crate) fn outer_operation_retaining<'plan>(&'plan self,
        compiled: Retained<CompiledFixedSources<'a>>)
        -> core::result::Result<FixedLeafOuterOperation<'plan, 'source, 'a>,
            (GraphParentFailure, Retained<CompiledFixedSources<'a>>)>
    {
        match self.binding() {
            Ok(binding) => Ok(FixedLeafOuterOperation { plan: self, compiled, binding }),
            Err(error) => Err((error, compiled)),
        }
    }
    fn check_compiled(&self, compiled: &CompiledFixedSources<'a>) -> OwnedResult<()> {
        if !compiled.belongs_to_plan(self.compiler)
            || !core::ptr::eq(compiled.sources(), self.compiler.sources())
            || compiled.node().program.witness_values() != self.census.construction.max_input_values
            || compiled.node().witness.len() != self.census.construction.max_input_values
            || compiled.node().witness.capacity() != self.census.construction.max_input_values
            || compiled.node().program.construction_host_bytes() > self.census.construction.max_requested_program_bytes
            || shape::selection_hint_words(&compiled.node().program).map_err(|_| GraphParentFailure::Source)? != 0
        { return Err(GraphParentFailure::Source); }
        self.source.check_compiled(compiled.node())
    }
}
pub(crate) struct FixedLeafOuterOperation<'plan, 'source, 'a> {
    plan: &'plan FixedLeafOuterPlan<'source, 'a>,
    compiled: Retained<CompiledFixedSources<'a>>,
    binding: PhaseBinding,
}
impl<'a> FixedLeafOuterOperation<'_, '_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn input_slot(&self) -> SlotId { self.compiled.slot_id() }
    pub(crate) fn source_shape(&self) -> OwnedResult<OuterSourceShape> { self.plan.source.outer_shape() }
    pub(crate) fn borrowed_parts<'borrow>(&'borrow self, execution: &ExecutionAccess<'_>)
        -> OwnedResult<(&'borrow Arc<Program>, &'borrow Vec<Val>, &'borrow Vec<Val>)>
    {
        let expected = PhaseBinding::for_source(self.plan.compiler, 0).map_err(|_| GraphParentFailure::Authority)?;
        if execution.binding() != self.binding || execution.context().policy() != Policy::GpuRequired
            || !core::ptr::eq(execution.context(), self.plan.compiler.context())
            || !execution.owns_source(self.plan.compiler.sources())
            || self.plan.cache.policy() != ProofCachePolicy::FreshOnly
            || self.compiled.binding() != expected || self.compiled.get().binding() != expected
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
