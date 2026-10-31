//! Concrete FixedSources compile phase. Unsupported native source families have
//! no variants, phase facts, constructor, runtime, or refusal dispatcher here.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Requirements},
        workflow_resources::{
            ExecutionAccess, PhaseBinding, PhaseFacts, PhaseFailure, PhaseKind,
            Retained, RetainedFailure, SourceRetained,
        },
        ProvingContext,
    },
    graph_tree::{
        self, fixed_sources::{self, FixedSourceCompilePlan, FixedSourceFailure},
        CompiledNode, GraphContext,
    },
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{program::Val, Program};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

type Result<T> = core::result::Result<T, FixedSourceFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(FixedSourceFailure::Resource)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(FixedSourceFailure::Resource)
}
fn host(bytes: usize) -> Result<Bytes> {
    Ok(Bytes { host: u64::try_from(bytes).map_err(|_| FixedSourceFailure::Resource)?, device: 0 })
}

/// This concrete subset has exactly one CPU compilation phase. It cannot stand
/// in for a complete transaction plan: native/outer/merge closure is separate.
/// ClosedWorkflowPlan must retain this exact owner by immutable reference.
pub(crate) struct SourceOperationPlan<'a> {
    context: &'a ProvingContext,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    fixed: FixedSourceCompilePlan<'a>,
    workflow_source: [u8; 32],
    facts: PhaseFacts,
}

impl<'a> SourceOperationPlan<'a> {
    pub(crate) fn fixed_sources(
        scope: &SourcePlanningPlan<'a>,
        sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    ) -> Result<Self> {
        scope.validate_initial_source(sources.get().native_source())
            .map_err(|_| FixedSourceFailure::Authority)?;
        if scope.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired
            || sources.source_fingerprint() != scope.source_fingerprint()
            || sources.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
        {
            return Err(FixedSourceFailure::Authority);
        }
        let prepared = sources.get();
        let fixed = FixedSourceCompilePlan::new(prepared.plan(), prepared.graph(), prepared.context())?;
        let census = fixed.census();
        let mut output = Requirements::single(Category::SymbolicCompiler,
            host(census.construction.max_requested_program_bytes)?);
        output.add(Category::CompilerInputs, host(add(census.input_bytes,
            mul(graph_tree::PUBLIC_VALUES, size_of::<Val>())?)?)?)
            .map_err(|_| FixedSourceFailure::Resource)?;
        output.add(Category::RegisteredMetadata, host(add(
            size_of::<Retained<CompiledFixedSources<'a>>>(),
            add(size_of::<Program>(), 2 * size_of::<usize>())?,
        )?)?).map_err(|_| FixedSourceFailure::Resource)?;
        let failure = Requirements::single(Category::Report, host(add(
            size_of::<PhaseFailure<FixedSourceFailure>>(),
            size_of::<RetainedFailure<FixedSourceFailure>>(),
        )?)?);
        // Builder construction, exact-shape matching and source bridges remain
        // charged in addition to the complete output slot throughout execution.
        let mut scratch = Requirements::single(Category::SymbolicCompiler, host(add(
            census.construction.max_requested_program_bytes, census.source_scratch_bytes,
        )?)?);
        scratch.add(Category::CompilerInputs, host(census.input_bytes)?)
            .map_err(|_| FixedSourceFailure::Resource)?;
        let wrapper_frames = mul(4, [
            size_of::<Self>(), size_of::<Result<Self>>(),
            size_of::<SourceCompileOperation<'static, 'static>>(),
            size_of::<Result<SourceCompileOperation<'static, 'static>>>(),
            size_of::<CompiledFixedSources<'static>>(), size_of::<Result<CompiledFixedSources<'static>>>(),
            size_of::<ExecutionAccess<'static>>(), size_of::<PhaseFacts>(),
            size_of::<PhaseBinding>(), size_of::<Sha3_256>(),
            size_of::<std::time::Instant>(), size_of::<u128>(),
            4 * size_of::<Requirements>(), 4 * size_of::<Bytes>(),
        ].into_iter().try_fold(0, add)?)?;
        scratch.add(Category::PhaseScratch, host(add(census.frame_bytes, wrapper_frames)?)?)
            .map_err(|_| FixedSourceFailure::Resource)?;
        let mut source = Sha3_256::new();
        source.update(b"lattica/full-workflow/fixed-sources-compile/v1");
        source.update(scope.source_fingerprint());
        source.update(scope.compiled_source_fingerprint());
        source.update(prepared.native_identity());
        source.update(prepared.plan().label());
        source.update(prepared.context().context);
        for word in prepared.context().statement.iter().chain(&prepared.context().node_manifest) {
            source.update(word.as_canonical_u64().to_le_bytes());
        }
        for limit in [census.construction.max_requested_program_bytes,
            census.construction.max_wires, census.construction.max_input_values]
        {
            source.update(u64::try_from(limit).map_err(|_| FixedSourceFailure::Resource)?.to_le_bytes());
        }
        Ok(Self {
            context: scope.context(), sources, fixed, workflow_source: scope.source_fingerprint(),
            facts: PhaseFacts { kind: PhaseKind::SourceCompile,
                compiled_source_fingerprint: scope.compiled_source_fingerprint(),
                source_fingerprint: source.finalize().into(), output, failure, scratch },
        })
    }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.context }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn workflow_source_fingerprint(&self) -> [u8; 32] { self.workflow_source }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.facts.source_fingerprint }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.facts.compiled_source_fingerprint }
    pub(crate) fn phase_count(&self) -> usize { 1 }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> {
        (ordinal == 0).then_some(self.facts)
    }
    pub(crate) fn backend_allowance(&self) -> Bytes { Bytes::ZERO }
    pub(crate) fn compile(&self) -> Result<SourceCompileOperation<'_, 'a>> {
        Ok(SourceCompileOperation { plan: self,
            binding: PhaseBinding::for_source(self, 0).map_err(|_| FixedSourceFailure::Authority)? })
    }
}

pub(crate) struct SourceCompileOperation<'plan, 'a> {
    plan: &'plan SourceOperationPlan<'a>,
    binding: PhaseBinding,
}
impl<'a> SourceCompileOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn execute(self, execution: &ExecutionAccess<'_>) -> Result<CompiledFixedSources<'a>> {
        if self.binding != execution.binding()
            || !core::ptr::eq(self.plan.context, execution.context())
            || !execution.owns_source(self.plan.sources)
            || self.plan.sources.source_fingerprint() != self.plan.workflow_source
            || self.plan.sources.compiled_source_fingerprint() != self.plan.compiled_source_fingerprint()
        {
            return Err(FixedSourceFailure::Authority);
        }
        let started = std::time::Instant::now();
        let node = self.plan.fixed.compile()?;
        let compile_ns = started.elapsed().as_nanos();
        Ok(CompiledFixedSources { sources: self.plan.sources, node, compile_ns, binding: self.binding,
            operation_source: self.plan.source_fingerprint(), compiled_source: self.plan.compiled_source_fingerprint() })
    }
}

/// Keeps the exact admitted graph/source owners borrowed until compilation's
/// output is destroyed or consumed by the coordinator's concrete outer adapter.
pub(crate) struct CompiledFixedSources<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    node: CompiledNode,
    compile_ns: u128,
    binding: PhaseBinding,
    operation_source: [u8; 32],
    compiled_source: [u8; 32],
}
impl<'a> CompiledFixedSources<'a> {
    pub(crate) fn program(&self) -> &Arc<Program> { fixed_sources::compiled_program(&self.node) }
    pub(crate) fn public_values(&self) -> &[Val] { self.node.public_values() }
    pub(crate) fn witness_values(&self) -> &[Val] { fixed_sources::compiled_witness(&self.node) }
    pub(crate) fn node(&self) -> &CompiledNode { &self.node }
    pub(crate) fn compile_ns(&self) -> u128 { self.compile_ns }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn context(&self) -> &GraphContext { self.sources.get().context() }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.operation_source }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.compiled_source }
    pub(crate) fn belongs_to_plan(&self, plan: &SourceOperationPlan<'a>) -> bool {
        core::ptr::eq(self.sources, plan.sources)
            && PhaseBinding::for_source(plan, 0).ok() == Some(self.binding)
            && self.operation_source == plan.source_fingerprint()
            && self.compiled_source == plan.compiled_source_fingerprint()
    }
}
