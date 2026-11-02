//! Four closed auxiliary graph relations. Source plans borrow the original
//! request/native plans; operations consume their original retained outputs.
//! No caller-selected AIR, naked artifact, budget, or proof retry enters here.
use super::*;
use crate::{
    execution::{ProvingContext, workflow_resources::{SourceRetained, RetainedNative}},
    graph_auxiliary::Role,
    graph_crypto::{OwnedAesRequestPlan, OwnedAesRequestOutput, PairedRequestPlan,
        PairedRequestOutput, RequestDescriptor},
    graph_tree::fixed_sources::FixedSourceCensus,
    rust_verify::committed_backend::{Operation, Source},
    spend_pipeline::full_workflow::{PreparedWorkflowSources, SourcePlanningPlan,
        uniform_native::{UniformNativeOperationPlan, OwnedUniformOutput},
        sparse_native::{SparseNativeOperationPlan, OwnedSparseOutput},
        transcript_native::{TranscriptNativeOperationPlan, OwnedTranscriptOutput}},
};
use lattica_prover_p3::proving::Policy;
mod sources;
mod bounds;
mod operations;
mod outer;
mod dependencies;
mod prepared_inventory;
pub(crate) use prepared_inventory::AuxiliaryPreparedInventory;
pub(crate) use dependencies::AuxiliaryDependencies;
pub(crate) use operations::{AuxiliaryCompileOperation, AuxiliaryOuterOperation};
pub(crate) use outer::{PreissuedAuxiliaryOuter, BoundAuxiliaryOuter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuxiliaryGraphKind { SampleG, ExpandAlpha, HashAlpha, HashX }
#[derive(Clone, Copy)]
pub(crate) enum AuxiliaryGraphSources<'source, 'a> {
    SampleG { aes: &'source OwnedAesRequestPlan<'a>, uniform: &'source UniformNativeOperationPlan<'a> },
    ExpandAlpha { uniform_aes: &'source OwnedAesRequestPlan<'a>, uniform: &'source UniformNativeOperationPlan<'a>,
        sparse_aes: &'source OwnedAesRequestPlan<'a>, sparse: &'source SparseNativeOperationPlan<'a> },
    HashAlpha { shake: &'source PairedRequestPlan<'a>, transcript: &'source TranscriptNativeOperationPlan<'a> },
    HashX { shake: &'source PairedRequestPlan<'a>, transcript: &'source TranscriptNativeOperationPlan<'a>,
        sparse: &'source SparseNativeOperationPlan<'a> },
}
pub(crate) enum AuxiliaryGraphOutputs<'a> {
    SampleG { aes: OwnedAesRequestOutput<'a>, uniform: RetainedNative<OwnedUniformOutput<'a>> },
    ExpandAlpha { uniform_aes: OwnedAesRequestOutput<'a>, uniform: RetainedNative<OwnedUniformOutput<'a>>,
        sparse_aes: OwnedAesRequestOutput<'a>, sparse: RetainedNative<OwnedSparseOutput<'a>> },
    HashAlpha { shake: PairedRequestOutput<'a>, transcript: RetainedNative<OwnedTranscriptOutput<'a>> },
    HashX { shake: PairedRequestOutput<'a>, transcript: RetainedNative<OwnedTranscriptOutput<'a>>,
        sparse: RetainedNative<OwnedSparseOutput<'a>> },
}
pub(crate) struct AuxiliaryGraphPlan<'source, 'a> {
    context: &'a ProvingContext,
    prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    sources: AuxiliaryGraphSources<'source, 'a>,
    source: GraphNodeSource<'a>,
    workflow_source: [u8; 32],
    facts: [PhaseFacts; 2],
    cache: &'source OuterProofCache,
    original: Reservation,
}
impl<'source, 'a> AuxiliaryGraphPlan<'source, 'a> {
    pub(crate) fn planning_requirements() -> OwnedResult<Requirements> {
        requirement(Category::RegisteredMetadata,
            add(bounds::frames()?, PreissuedAuxiliaryOuter::metadata_host_bytes()?)?)
    }
    pub(crate) fn planning_scratch_requirements(sources: AuxiliaryGraphSources<'_, '_>) -> OwnedResult<Requirements> {
        bounds::planning_scratch_requirements(sources)
    }
    pub(crate) fn derive_pre_reserved(scope: &SourcePlanningPlan<'a>,
        prepared: &'a SourceRetained<PreparedWorkflowSources<'a>>,
        sources: AuxiliaryGraphSources<'source, 'a>, ordinal: usize,
        cache: &'source OuterProofCache, original: Reservation,
        scratch: &Reservation, ledger: &Ledger,
    ) -> OwnedResult<Self> {
        scope.validate_initial_source(prepared.get().native_source()).map_err(|_| GraphParentFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired || cache.policy() != ProofCachePolicy::FreshOnly
            || !original.belongs_to(ledger) || !scratch.belongs_to(ledger) || !prepared.belongs_to(ledger)
            || !sources.belongs_to(ledger)
            || original.requirements() != Self::planning_requirements()?
            || !contains(scratch.requirements(), Self::planning_scratch_requirements(sources)?)
            || prepared.source_fingerprint() != scope.source_fingerprint()
            || prepared.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
            || scope.compiled_source_fingerprint() != crate::graph_proofs::compiled_source_fingerprint()
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host) || ledger.snapshot().allowance.device > 8 << 30
        { return Err(GraphParentFailure::Authority); }
        AuxiliaryPreparedInventory::new(prepared, ordinal)?.validate_plans(sources, scope.context())?;
        // Pure source census and complete scratch checks precede all native or
        // recursive template construction. Planning never observes proof rows.
        let (compiled, compiler_scratch) = bounds::compiler_requirements(prepared.get(), sources)?;
        let source = bounds::derive(prepared, sources, ordinal)?;
        let (compiled, compiler_scratch) = super::memory::packed_compiler_requirements(source, (compiled, compiler_scratch), super::source::PROGRAM_BYTES)?;
        let (output, verifier) = source.output_requirements()?;
        let failure = super::memory::failure_requirements()?;
        let fact = |kind, output, scratch| PhaseFacts { kind, output, scratch, failure,
            source_fingerprint: source.source_fingerprint,
            compiled_source_fingerprint: source.compiled_source_fingerprint };
        let plan = Self { context: scope.context(), prepared, sources, source,
            workflow_source: scope.source_fingerprint(), facts: [
                fact(PhaseKind::GraphLeafCompile, compiled, compiler_scratch),
                fact(PhaseKind::GraphOuter, output, combine(&[verifier,
                    super::outer::caller_requirements()?, requirement(Category::PhaseScratch, bounds::frames()?)?,
                    PreissuedAuxiliaryOuter::planning_scratch_requirement()?])?),
            ], cache, original };
        plan.dependencies(0)?;
        Ok(plan)
    }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { self.facts.get(ordinal).copied() }
    pub(crate) fn binding(&self, ordinal: usize) -> OwnedResult<PhaseBinding> {
        PhaseBinding::for_auxiliary_graph(self, ordinal).map_err(|_| GraphParentFailure::Authority)
    }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.original.belongs_to(ledger) && self.prepared.belongs_to(ledger) && self.sources.belongs_to(ledger)
    }
    pub(crate) fn source(&self) -> &GraphNodeSource<'a> { &self.source }
    pub(crate) fn prepared(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.prepared }
    pub(crate) fn sources(&self) -> AuxiliaryGraphSources<'source, 'a> { self.sources }
    pub(crate) fn kind(&self) -> AuxiliaryGraphKind { self.sources.kind() }
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
