//! Concrete unchanged Permutation graph leaves with exact algebra-batch membership.
//!
//! The blueprint describes the exact registered source leaf. Workflow queries
//! reuse bounded numerical analysis held by the admitted prepared source.
//! Its bounded template inspection runs under an original planning claim, and
//! compilation borrows an independently verified child and original compiler
//! claims. Neither operation is native/outer dispatch or a graph-root proof.
use super::*;
use super::fixed_sources::FixedSourceCensus;
use crate::{
    component_tree::native_shape::{
        framing, NativeCoreBound, NativePlanningStorage,
        unchanged::{other_native_core_bound, OtherNativeDescriptor},
    },
    graph_proofs::owned_permutation::{PermutationSource, VerifiedPermutationProof},
    rust_verify::committed_backend::{source_binding::SourceBinding, Operation, Source},
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        machine::{
            pq_bytes::Byte,
            program::{ConstructionLimits, ProofInputs, MAX_WIRES},
            verifier::batch::shape::{selection_hint_words, OperationCounts},
            Program,
        },
        native_gpu::permutation_preparation::PermutationDescriptor,
    },
    ringct_research_quota::{Bytes, Category, Ledger, Requirements, Reservation},
};

const PROGRAM_BYTES: usize = 2 << 30;
const INPUT_VALUES: usize = 1 << 20;
const AUXILIARY_BYTES: usize = 512 << 20;
const MAX_ROWS: usize = 1 << 20;
const ROOT_INPUTS: usize = 4 * (1770 + 8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermutationLeafFailure {
    Source, Coverage, Resource, Authority, SourceDrift, Compile, Rows,
}
type PermutationResult<T> = core::result::Result<T, PermutationLeafFailure>;
fn add(a: usize, b: usize) -> PermutationResult<usize> {
    a.checked_add(b).ok_or(PermutationLeafFailure::Resource)
}
fn mul(a: usize, b: usize) -> PermutationResult<usize> {
    a.checked_mul(b).filter(|n| *n <= isize::MAX as usize)
        .ok_or(PermutationLeafFailure::Resource)
}
fn sum(parts: impl IntoIterator<Item = usize>) -> PermutationResult<usize> {
    parts.into_iter().try_fold(0, add)
}
fn bytes<T>(count: usize) -> PermutationResult<usize> { mul(size_of::<T>(), count) }
fn requirement(category: Category, bytes: usize) -> PermutationResult<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(bytes).map_err(|_| PermutationLeafFailure::Resource)?, device: 0,
    }))
}
fn construction() -> ConstructionLimits {
    ConstructionLimits { max_requested_program_bytes: PROGRAM_BYTES,
        max_wires: MAX_WIRES, max_input_values: INPUT_VALUES }
}

// Witness bytes are observable secret material even on a compiler refusal.
// Volatile stores cannot be removed as dead writes before Vec destruction.
fn wipe(values: &mut [Val]) {
    for value in values { unsafe { core::ptr::write_volatile(value, Val::ZERO) }; }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}
struct WipedInputs(ProofInputs);
impl Drop for WipedInputs {
    fn drop(&mut self) {
        wipe(&mut self.0.values);
    }
}
fn admitted(original: &Reservation, ledger: &Ledger, wanted: Requirements) -> PermutationResult<()> {
    let allowance = ledger.snapshot().allowance;
    let have = original.requirements();
    if !original.belongs_to(ledger) || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
        || allowance.device > 8u64 << 30 || Category::ALL.into_iter().any(|category| {
            let a = have.get(category); let b = wanted.get(category);
            a.host < b.host || a.device < b.device
        }) {
        return Err(PermutationLeafFailure::Authority);
    }
    Ok(())
}

/// No artifact fields or observed compiled height enter these facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PermutationLeafFacts {
    pub(crate) operations: OperationCounts,
    pub(crate) maximum_active_rows: usize,
    pub(crate) maximum_padded_rows: usize,
    pub(crate) maximum_wires: usize,
    pub(crate) input_values: usize,
    pub(crate) selection_hint_words: usize,
}
impl PermutationLeafFacts {
    fn from_core(core: NativeCoreBound, kind: PermutationDescriptor) -> PermutationResult<Self> {
        let source = framing::native_root_join(mul(kind.count(), 8)?)
            .map_err(|_| PermutationLeafFailure::Resource)?;
        let overhead = framing::source_binding_initialization(1770, 8)
            .and_then(|value| value.with_overhead(framing::GRAPH_HEADER))
            .and_then(|value| value.with_overhead(source))
            .map_err(|_| PermutationLeafFailure::Resource)?;
        if overhead.cubic != 0 || core.counts.quotient_chunks != 16 {
            return Err(PermutationLeafFailure::SourceDrift);
        }
        let operations = core.counts.operations.with_overhead(overhead)
            .map_err(|_| PermutationLeafFailure::Resource)?;
        let maximum_active_rows = operations.active_rows(PUBLIC_VALUES)
            .map_err(|_| PermutationLeafFailure::Resource)?;
        let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES)
            .map_err(|_| PermutationLeafFailure::Resource)?;
        let maximum_wires = add(core.counts.wires,
            sum([PUBLIC_VALUES, overhead.scalar, mul(8, overhead.poseidon)?])?)?;
        let input_values = add(core.counts.input_values, ROOT_INPUTS)?;
        if maximum_padded_rows > MAX_ROWS || maximum_wires > MAX_WIRES
            || input_values > INPUT_VALUES {
            return Err(PermutationLeafFailure::Rows);
        }
        Ok(Self { operations, maximum_active_rows, maximum_padded_rows,
            maximum_wires, input_values, selection_hint_words: core.counts.selection_hint_words })
    }

    fn check(&self, node: &CompiledNode) -> PermutationResult<()> {
        let p = &node.program;
        let operations = OperationCounts::from_program(p);
        let hints = selection_hint_words(p).map_err(|_| PermutationLeafFailure::Resource)?;
        if p.public_values() != PUBLIC_VALUES || node.public.len() != PUBLIC_VALUES
            || p.active_rows() > self.maximum_active_rows || p.height() > self.maximum_padded_rows
            || p.wire_count() > self.maximum_wires || p.witness_values() != self.input_values
            || node.witness.len() != self.input_values || hints != self.selection_hint_words
            || operations.scalar > self.operations.scalar || operations.cubic > self.operations.cubic
            || operations.poseidon > self.operations.poseidon
            || p.construction_host_bytes() > PROGRAM_BYTES {
            return Err(PermutationLeafFailure::SourceDrift);
        }
        Ok(())
    }
}

/// References come from one immutable PreparedWorkflowSources owner. The
/// closed operation issuer must preserve that provenance and same ledger.
pub(crate) struct PermutationLeafBlueprint<'a, 'graph> {
    plan: &'a Plan,
    graph: &'a UnprovedRelationGraph,
    context: &'a GraphContext,
    source: PermutationSource<'graph>,
    kind: PermutationDescriptor,
    descriptor: OtherNativeDescriptor<'graph>,
    storage: NativePlanningStorage,
    ordinal: usize,
    planning: Requirements,
    output: Requirements,
    scratch: Requirements,
}
impl<'a, 'graph> PermutationLeafBlueprint<'a, 'graph> {
    pub(crate) fn new(plan: &'a Plan, graph: &'a UnprovedRelationGraph,
        context: &'a GraphContext, source: PermutationSource<'graph>) -> PermutationResult<Self>
    {
        let prepared = source.sources().get();
        if !core::ptr::eq(plan, prepared.plan()) || !core::ptr::eq(graph, prepared.graph())
            || !core::ptr::eq(context, prepared.context())
        { return Err(PermutationLeafFailure::Source); }
        let metadata = prepared.metadata().map_err(|_| PermutationLeafFailure::Source)?;
        let fixed = metadata.fixed();
        let kind = source.kind();
        let crate::graph_proofs::ComponentKind::Permutation { .. } = source.batch().kind()
            else { return Err(PermutationLeafFailure::Source); };
        let expected = OperationFamily::Permutation;
        let (ordinal, leaf) = metadata.leaf(plan, &expected, source.operation_indices())
            .map_err(|_| PermutationLeafFailure::Coverage)?;
        if leaf.byte_indices() != metadata.common_bytes()
            || leaf.polynomial_indices().len() != kind.count()
            || !leaf.operation_indices().iter().copied().eq(source.operation_indices().iter().copied())
        { return Err(PermutationLeafFailure::Coverage); }
        // Every expected polynomial is the exact derived output of one of the
        // selected operations; source planning already rejects duplicates.
        if !metadata.derived_matches(source.operation_indices(), leaf.polynomial_indices())
        { return Err(PermutationLeafFailure::Coverage); }
        let descriptor = OtherNativeDescriptor::Algebra { kind: source.batch().kind(), count: kind.count() };
        let storage = descriptor.storage(construction()).map_err(|_| PermutationLeafFailure::Resource)?;
        let key = crate::component_tree::native_shape::cohort::Descriptor::Other(descriptor).key();
        let (planning, output, scratch) = metadata.footprint(5, key, storage,
            || Self::source_requirements(kind, &storage, &fixed))?;
        Ok(Self { plan, graph, context, source, kind, descriptor, storage, ordinal,
            planning, output, scratch })
    }
    fn source_requirements(kind: PermutationDescriptor, storage: &NativePlanningStorage, fixed: &FixedSourceCensus)
        -> PermutationResult<(Requirements, Requirements, Requirements)>
    {
        let wrapper_heap = sum([
            bytes::<crate::permutation_air::PendingPermutation>(kind.count())?, bytes::<usize>(kind.count())?,
            size_of::<Vec<crate::permutation_air::PendingPermutation>>(), size_of::<Vec<usize>>(),
            // Two serial-word bridges bound either source family. Include
            // each 32-bit decomposition independently and growth replacement.
            bytes::<Byte>(2 * 4 * 32)?, bytes::<Wire>(2 * 8 * 4 * 32)?,
            bytes::<Wire>(2 * 4 * 16)?, bytes::<Wire>(4 * 16)?,
            // Conservative source-binding commitment temporary backing;
            // the permutation join itself only equates existing public roots.
            bytes::<Val>(2 * (4 * 8 + 4 * 8 + 22))?, bytes::<Vec<Val>>(2 * 3)?,
            8 * 512,
        ])?;
        let wrapper_frames = mul(8, sum([
            size_of::<Self>(), size_of::<PermutationResult<Self>>(), size_of::<NativeCoreBound>(),
            size_of::<Option<crate::component_tree::native_shape::cohort::ResolvedBound>>(),
            size_of::<PermutationLeafCompiler<'static, 'static, 'static>>(),
            size_of::<PermutationResult<PermutationLeafCompiler<'static, 'static, 'static>>>(),
            size_of::<PermutationLeafFacts>(), size_of::<PermutationResult<PermutationLeafFacts>>(),
            size_of::<Spec>(), size_of::<CompiledNode>(), size_of::<PermutationResult<CompiledNode>>(),
            size_of::<OwnedCompiledPermutation<'static, 'static, 'static>>(),
            size_of::<PermutationCompileOutcome<'static, 'static, 'static>>(),
            size_of::<Reservation>(), size_of::<(PermutationLeafFailure, Reservation)>(),
            size_of::<ProgramBuilder>(), size_of::<ProofInputs>(),
            size_of::<WipedInputs>(), size_of::<std::time::Instant>(),
            size_of::<SourceBinding<'static, 'static, 'static>>(),
            size_of::<[[Wire; 4]; crate::statement_air::POLYNOMIALS]>(),
            size_of::<[[Wire; 4]; crate::proof_air::POLYNOMIALS]>(),
            size_of::<[Byte; 32]>(), size_of::<[Wire; 32]>(), size_of::<[Wire; 16]>(),
            size_of::<[Val; 8]>(), size_of::<[Val; PUBLIC_VALUES]>(),
            size_of::<[Wire; PUBLIC_VALUES]>(), size_of::<[Requirements; 4]>(),
            16 * size_of::<Vec<Wire>>(), 16 * size_of::<usize>(),
        ])?)?;
        let wrapper_frames = add(wrapper_frames, crate::graph_tree::metadata::GraphMetadata::construction_bytes())?;
        let auxiliary = sum([storage.auxiliary_peak_bytes, fixed.source_scratch_bytes,
            fixed.frame_bytes, wrapper_heap, wrapper_frames])?;
        if auxiliary > AUXILIARY_BYTES || fixed.construction.max_input_values != ROOT_INPUTS {
            return Err(PermutationLeafFailure::Resource);
        }
        let planning = requirement(Category::PhaseScratch,
            add(storage.total_requested_bytes, wrapper_frames)?)?;
        let mut output = requirement(Category::SymbolicCompiler, PROGRAM_BYTES)?;
        output.add(Category::CompilerInputs,
            requirement(Category::CompilerInputs, add(storage.input_backing_bytes,
                bytes::<Val>(2 * PUBLIC_VALUES)?)?)?.get(Category::CompilerInputs))
            .map_err(|_| PermutationLeafFailure::Resource)?;
        output.add(Category::RegisteredMetadata,
            requirement(Category::RegisteredMetadata,
                sum([size_of::<Program>(), 2 * size_of::<usize>(),
                    size_of::<OwnedCompiledPermutation<'static, 'static, 'static>>(),
                    // The full typed slot owner survives the compiler phase.
                    size_of::<crate::execution::workflow_resources::RetainedOriginal<
                        OwnedCompiledPermutation<'static, 'static, 'static>>>()])?)?
                .get(Category::RegisteredMetadata)).map_err(|_| PermutationLeafFailure::Resource)?;
        let scratch = requirement(Category::PhaseScratch, auxiliary)?;
        Ok((planning, output, scratch))
    }

    pub(crate) fn kind(&self) -> PermutationDescriptor { self.kind }
    pub(crate) fn ordinal(&self) -> usize { self.ordinal }
    pub(crate) fn graph_plan(&self) -> &'a Plan { self.plan }
    pub(crate) fn relation_graph(&self) -> &'a UnprovedRelationGraph { self.graph }
    pub(crate) fn context(&self) -> &'a GraphContext { self.context }
    pub(crate) fn source(&self) -> PermutationSource<'graph> { self.source }
    /// Numeric-only request; normal inspection still authenticates originals.
    pub(crate) fn metadata_request(&self) -> crate::component_tree::native_shape::cohort::Request<'_> {
        crate::component_tree::native_shape::cohort::Request {
            descriptor: crate::component_tree::native_shape::cohort::Descriptor::Other(self.descriptor),
            auxiliary: self.storage.auxiliary_peak_bytes,
        }
    }
    pub(crate) fn planning_requirements(&self) -> Requirements { self.planning }
    pub(crate) fn compiler_requirements(&self) -> (Requirements, Requirements) { (self.output, self.scratch) }

    /// Run during complete closure, before native proof zero. The exact
    /// original claim covers bounded recorder/template/builder allocations.
    pub(crate) fn inspect<'plan>(&'plan self, original: &Reservation, ledger: &Ledger)
        -> PermutationResult<PermutationLeafCompiler<'plan, 'a, 'graph>>
    { self.inspect_inner(original, ledger, None) }
    pub(crate) fn inspect_resolved<'plan>(&'plan self, original: &Reservation, ledger: &Ledger,
        resolved: crate::component_tree::native_shape::cohort::ResolvedBound)
        -> PermutationResult<PermutationLeafCompiler<'plan, 'a, 'graph>>
    { self.inspect_inner(original, ledger, Some(resolved)) }
    fn inspect_inner<'plan>(&'plan self, original: &Reservation, ledger: &Ledger,
        resolved: Option<crate::component_tree::native_shape::cohort::ResolvedBound>)
        -> PermutationResult<PermutationLeafCompiler<'plan, 'a, 'graph>>
    {
        admitted(original, ledger, self.planning)?;
        let core = match resolved {
            Some(bound) => bound.for_request(self.metadata_request(), construction()),
            None => other_native_core_bound(self.descriptor, construction(), self.storage.auxiliary_peak_bytes),
        }.map_err(|_| PermutationLeafFailure::Compile)?;
        if core.storage != self.storage { return Err(PermutationLeafFailure::SourceDrift); }
        Ok(PermutationLeafCompiler { blueprint: self, facts: PermutationLeafFacts::from_core(core, self.kind)? })
    }
}

pub(crate) struct PermutationLeafCompiler<'plan, 'a, 'graph> {
    blueprint: &'plan PermutationLeafBlueprint<'a, 'graph>,
    facts: PermutationLeafFacts,
}
impl<'plan, 'a, 'graph> PermutationLeafCompiler<'plan, 'a, 'graph> {
    pub(crate) fn facts(&self) -> PermutationLeafFacts { self.facts }
    pub(crate) fn blueprint(&self) -> &PermutationLeafBlueprint<'a, 'graph> { self.blueprint }

    fn compile_borrowed(&self, child: &VerifiedPermutationProof<'graph>,
        output: &Reservation, scratch: &Reservation, ledger: &Ledger)
        -> PermutationResult<CompiledNode>
    {
        let source = self.blueprint;
        admitted(output, ledger, source.output)?;
        admitted(scratch, ledger, source.scratch)?;
        if core::ptr::eq(output, scratch) || !child.source().same_source(source.source)
            || !child.owned().belongs_to(ledger) || child.owned().geometry().kind() != source.kind {
            return Err(PermutationLeafFailure::Authority);
        }
        let spec = Spec { plan: Arc::clone(&source.plan.0), first: source.ordinal as u32, count: 1, level: 0 };
        let mut builder = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, construction())
            .map_err(|_| PermutationLeafFailure::Compile)?;
        let public = public_wires(&mut builder, &spec).map_err(|_| PermutationLeafFailure::Compile)?;
        let mut inputs = WipedInputs(ProofInputs::default());
        let mut binding = SourceBinding::new(&source.plan.0.shape, source.graph, &mut builder, &mut inputs.0,
            public[CONTEXT..CONTEXT + 8].try_into().unwrap(),
            public[STATEMENT..STATEMENT + 4].try_into().unwrap(),
            public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap())
            .map_err(|_| PermutationLeafFailure::Source)?;
        binding.verify_permutation_batch_owned(source.source.operation_indices(), child.artifact())
            .map_err(|_| PermutationLeafFailure::Compile)?;
        let leaf = &source.plan.leaves()[source.ordinal];
        binding.require_exact_coverage(leaf.polynomial_indices(), leaf.byte_indices(), leaf.operation_indices())
            .map_err(|_| PermutationLeafFailure::Coverage)?;
        let program = builder.finish(None).map_err(|_| PermutationLeafFailure::Compile)?;
        let mut node = CompiledNode { spec: spec.clone(), program: Arc::new(program),
            public: header(&spec, source.context), witness: core::mem::take(&mut inputs.0.values) };
        if let Err(error) = self.facts.check(&node) {
            wipe(&mut node.witness);
            return Err(error);
        }
        Ok(node)
    }

    /// All compiler temporaries die before either outcome is returned. The
    /// child stays with its original owner throughout its final read; every
    /// proof value copied into the compiler then follows the output claim.
    /// The exact original output is returned on refusal, never readmitted.
    pub(crate) fn compile_retaining(&self,
        child: &VerifiedPermutationProof<'graph>, output: Reservation,
        scratch: &Reservation, ledger: &Ledger)
        -> PermutationCompileOutcome<'plan, 'a, 'graph>
    {
        let started = std::time::Instant::now();
        match self.compile_borrowed(child, &output, scratch, ledger) {
            Ok(node) => Ok(OwnedCompiledPermutation { node: Some(node), blueprint: self.blueprint,
                facts: self.facts, compile_ns: started.elapsed().as_nanos(), output: Some(output) }),
            Err(failure) => Err((failure, output)),
        }
    }
}

pub(crate) type PermutationCompileOutcome<'plan, 'a, 'graph> = core::result::Result<
    OwnedCompiledPermutation<'plan, 'a, 'graph>, (PermutationLeafFailure, Reservation)>;

/// The original compiler output claim follows the complete program, public
/// fields and copied child inputs through every move. The immutable blueprint
/// keeps the source plan/graph/algebra-batch owner borrowed. Drop order is deliberate.
pub(crate) struct OwnedCompiledPermutation<'plan, 'a, 'graph> {
    node: Option<CompiledNode>,
    blueprint: &'plan PermutationLeafBlueprint<'a, 'graph>,
    facts: PermutationLeafFacts,
    compile_ns: u128,
    output: Option<Reservation>,
}
impl<'a, 'graph> OwnedCompiledPermutation<'_, 'a, 'graph> {
    pub(crate) fn node(&self) -> &CompiledNode { self.node.as_ref().expect("owned source node") }
    pub(crate) fn blueprint(&self) -> &PermutationLeafBlueprint<'a, 'graph> { self.blueprint }
    pub(crate) fn facts(&self) -> PermutationLeafFacts { self.facts }
    pub(crate) fn compile_ns(&self) -> u128 { self.compile_ns }
    pub(crate) fn reservation(&self) -> &Reservation { self.output.as_ref().expect("owned source original") }
    pub(crate) fn witness(&self) -> &[Val] { &self.node().witness }
    fn destroy_payload(&mut self) {
        if let Some(mut node) = self.node.take() {
            wipe(&mut node.witness);
            drop(node);
        }
    }
    pub(crate) fn destroy_into_original(mut self) -> Reservation {
        self.destroy_payload();
        self.output.take().expect("same source compiler original")
    }
}
impl Drop for OwnedCompiledPermutation<'_, '_, '_> {
    fn drop(&mut self) { self.destroy_payload(); }
}
