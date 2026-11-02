//! Concrete ParametersPp graph leaf. All other crypto consumers still require
//! their separately sealed auxiliary proof owners; there is no raw artifact route.
use super::*;
use crate::{
    execution::{ProvingContext, workflow_resources::SourceRetained},
    graph_crypto::{PairedRequestPlan, PairedRequestOutput, RequestDescriptor},
    graph_tree::fixed_sources::FixedSourceCensus,
    rust_verify::committed_backend::{Operation, Source},
    spend_pipeline::full_workflow::{PreparedWorkflowSources, SourcePlanningPlan},
};
use lattica_prover_p3::proving::Policy;
mod source;
mod operations;
mod outer;
pub(crate) use operations::{ParametersPpCompileOperation, ParametersPpOuterOperation};
pub(crate) use outer::{PreissuedParametersPpOuter, BoundParametersPpOuter};

pub(crate) struct ParametersPpGraphPlan<'source, 'a> {
    context: &'a ProvingContext,
    prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    request: &'source PairedRequestPlan<'a>,
    source: GraphNodeSource<'a>,
    workflow_source: [u8; 32],
    facts: [PhaseFacts; 2],
    cache: &'source OuterProofCache,
    original: Reservation,
}
impl<'source, 'a> ParametersPpGraphPlan<'source, 'a> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        requirement(Category::RegisteredMetadata,
            add(source::frames()?, PreissuedParametersPpOuter::metadata_host_bytes()?)?)
    }
    pub(crate) fn planning_scratch_requirements() -> OwnedResult<Requirements> {
        source::planning_scratch_requirements()
    }
    pub(crate) fn derive_pre_reserved(scope: &SourcePlanningPlan<'a>,
        prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
        request: &'source PairedRequestPlan<'a>, ordinal: usize,
        cache: &'source OuterProofCache, original: Reservation,
        scratch: &Reservation, ledger: &Ledger,
    ) -> OwnedResult<Self> {
        scope.validate_initial_source(prepared.get().native_source())
            .map_err(|_| GraphParentFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired || cache.policy() != ProofCachePolicy::FreshOnly
            || !original.belongs_to(ledger) || !scratch.belongs_to(ledger)
            || !prepared.belongs_to(ledger) || !request.belongs_to(ledger)
            || original.requirements() != Self::planning_requirements()?
            || !contains(scratch.requirements(), Self::planning_scratch_requirements()?)
            || prepared.source_fingerprint() != scope.source_fingerprint()
            || prepared.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
            || request.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
            || scope.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint()
            || request.graph_context() != prepared.get().context()
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
            || ledger.snapshot().allowance.device > 8 << 30
        { return Err(GraphParentFailure::Authority); }
        source::validate_coverage(prepared.get(), request, ordinal)?;
        let source = source::derive(prepared, request, ordinal)?;
        let (compiled, compiler_scratch) = source::compiler_requirements(
            prepared.get(), request.root_source().maximum_padded_rows)?;
        let (compiled, compiler_scratch) = super::memory::packed_compiler_requirements(source, (compiled, compiler_scratch), super::source::PROGRAM_BYTES)?;
        let (output, verifier) = source.output_requirements()?;
        let failure = super::memory::failure_requirements()?;
        let fact = |kind, output, scratch| PhaseFacts { kind, output, scratch, failure,
            source_fingerprint: source.source_fingerprint,
            compiled_source_fingerprint: source.compiled_source_fingerprint };
        Ok(Self { context: scope.context(), prepared, request, source,
            workflow_source: scope.source_fingerprint(), facts: [
                fact(PhaseKind::GraphLeafCompile, compiled, compiler_scratch),
                fact(PhaseKind::GraphOuter, output, combine(&[verifier,
                    super::outer::caller_requirements()?,
                    requirement(Category::PhaseScratch, source::frames()?)?,
                    PreissuedParametersPpOuter::planning_scratch_requirement()?])?),
            ], cache, original })
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { self.facts.get(ordinal).copied() }
    pub(crate) fn binding(&self, ordinal: usize) -> OwnedResult<PhaseBinding> {
        PhaseBinding::for_parameters_pp_graph(self, ordinal).map_err(|_| GraphParentFailure::Authority)
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger) && self.prepared.belongs_to(ledger) && self.request.belongs_to(ledger)
    }
    pub(crate) fn source(&self) -> &GraphNodeSource<'a> { &self.source }
    pub(crate) fn prepared(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.prepared }
    pub(crate) fn request_plan(&self) -> &'source PairedRequestPlan<'a> { self.request }
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
