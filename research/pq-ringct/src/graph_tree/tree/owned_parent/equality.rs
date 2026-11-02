//! Direct unchanged EqualBytes/EqualSigned leaves with original source claims.
//! The private compiler emits SourceBinding's exact relation; no raw artifact
//! or detached CompiledNode can be attached to an execution output.
use super::*;
use crate::{execution::{ProvingContext, workflow_resources::SourceRetained},
    graph_tree::fixed_sources::FixedSourceCensus,
    rust_verify::committed_backend::{Operation, Source, source_binding::SourceBinding},
    spend_pipeline::full_workflow::{PreparedWorkflowSources, SourcePlanningPlan}};
use lattica_prover_p3::{proving::Policy, block_v2::machine::verifier::ProofInputs};
mod source;
mod operations;
mod outer;
pub(crate) use operations::{EqualityCompileOperation, EqualityOuterOperation};
pub(crate) use outer::{PreissuedEqualityOuter, BoundEqualityOuter};

pub(crate) struct EqualityDependencies {
    pub(crate) bindings: [Option<PhaseBinding>; 1],
    pub(crate) count: usize,
    pub(crate) consume: usize,
}
pub(crate) struct EqualityGraphPlan<'source, 'a> {
    context: &'a ProvingContext,
    prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    source: GraphNodeSource<'a>,
    census: FixedSourceCensus,
    workflow_source: [u8; 32],
    facts: [PhaseFacts; 2],
    cache: &'source OuterProofCache,
    original: Reservation,
}
impl<'source, 'a> EqualityGraphPlan<'source, 'a> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        requirement(Category::RegisteredMetadata,
            add(source::frames()?, PreissuedEqualityOuter::metadata_host_bytes()?)?)
    }
    pub(crate) fn planning_scratch_requirements() -> OwnedResult<Requirements> {
        requirement(Category::PhaseScratch, source::frames()?)
    }
    pub(crate) fn derive_pre_reserved(scope: &SourcePlanningPlan<'a>,
        prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize,
        cache: &'source OuterProofCache, original: Reservation,
        scratch: &Reservation, ledger: &Ledger) -> OwnedResult<Self> {
        scope.validate_initial_source(prepared.get().native_source()).map_err(|_| GraphParentFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired || cache.policy() != ProofCachePolicy::FreshOnly
            || !original.belongs_to(ledger) || !scratch.belongs_to(ledger) || !prepared.belongs_to(ledger)
            || original.requirements() != Self::planning_requirements()?
            || !contains(scratch.requirements(), Self::planning_scratch_requirements()?)
            || prepared.source_fingerprint() != scope.source_fingerprint()
            || prepared.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
            || scope.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint()
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host) || ledger.snapshot().allowance.device > 8 << 30
        { return Err(GraphParentFailure::Authority); }
        let prepared_value = prepared.get();
        let census = FixedSourceCensus::from_graph(prepared_value.graph()).map_err(|_| GraphParentFailure::Source)?;
        let source = source::derive(prepared_value.plan(), prepared_value.graph(), prepared_value.context(), ordinal,
            prepared.source_fingerprint(), prepared.compiled_source_fingerprint())?;
        let (compiled, compiler_scratch) = source::compiler_requirements(census)?;
        let (compiled, compiler_scratch) = super::memory::packed_compiler_requirements(source, (compiled, compiler_scratch), census.construction.max_requested_program_bytes)?;
        let (output, verifier) = source.output_requirements()?;
        let failure = super::memory::failure_requirements()?;
        let fact = |kind, output, scratch| PhaseFacts { kind, output, scratch, failure,
            source_fingerprint: source.source_fingerprint,
            compiled_source_fingerprint: source.compiled_source_fingerprint };
        Ok(Self { context: scope.context(), prepared, source, census,
            workflow_source: scope.source_fingerprint(), facts: [
                fact(PhaseKind::GraphLeafCompile, compiled, compiler_scratch),
                fact(PhaseKind::GraphOuter, output, combine(&[verifier,
                    super::outer::caller_requirements()?, requirement(Category::PhaseScratch, source::frames()?)?,
                    PreissuedEqualityOuter::planning_scratch_requirement()?])?),
            ], cache, original })
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { self.facts.get(ordinal).copied() }
    pub(crate) fn binding(&self, ordinal: usize) -> OwnedResult<PhaseBinding> {
        PhaseBinding::for_equality_graph(self, ordinal).map_err(|_| GraphParentFailure::Authority)
    }
    pub(crate) fn dependencies(&self, ordinal: usize) -> OwnedResult<EqualityDependencies> {
        match ordinal {
            0 => Ok(EqualityDependencies { bindings: [None], count: 0, consume: 0 }),
            1 => Ok(EqualityDependencies { bindings: [Some(self.binding(0)?)], count: 1, consume: 1 }),
            _ => Err(GraphParentFailure::Order),
        }
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger) && self.prepared.belongs_to(ledger)
    }
    pub(crate) fn source(&self) -> &GraphNodeSource<'a> { &self.source }
    pub(crate) fn prepared(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.prepared }
    pub(crate) fn child_source(&self) -> OwnedResult<GraphChildSource<'_, 'a>> {
        Ok(GraphChildSource { source: &self.source, binding: self.binding(1)? })
    }
    fn check_execution(&self, binding: PhaseBinding, execution: &ExecutionAccess<'_>) -> OwnedResult<()> {
        if execution.binding() != binding || execution.context().policy() != Policy::GpuRequired
            || !core::ptr::eq(execution.context(), self.context) || !execution.owns_source(self.prepared)
            || self.cache.policy() != ProofCachePolicy::FreshOnly
            || self.prepared.source_fingerprint() != self.workflow_source
            || self.prepared.compiled_source_fingerprint() != self.source.compiled_source_fingerprint
        { return Err(GraphParentFailure::Authority); }
        Ok(())
    }
}
