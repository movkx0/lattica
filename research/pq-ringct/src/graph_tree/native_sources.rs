//! Concrete unchanged Statement/PrivateProof graph leaves.
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
    graph_sources::{SourceFactory, owned_native::VerifiedSourceProof},
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
        native_gpu::graph_source_preparation::GraphSourceKind,
        native_graph_source_proof::NativeGraphSourceProof,
    },
    ringct_research_quota::{Bytes, Category, Ledger, Requirements, Reservation},
};

const PROGRAM_BYTES: usize = 2 << 30;
const INPUT_VALUES: usize = 1 << 20;
const AUXILIARY_BYTES: usize = 512 << 20;
const MAX_ROWS: usize = 1 << 20;
const ROOT_INPUTS: usize = 4 * (1770 + 8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSourceFailure {
    Source, Coverage, Resource, Authority, SourceDrift, Compile, Rows,
}
type NativeResult<T> = core::result::Result<T, NativeSourceFailure>;
fn add(a: usize, b: usize) -> NativeResult<usize> {
    a.checked_add(b).ok_or(NativeSourceFailure::Resource)
}
fn mul(a: usize, b: usize) -> NativeResult<usize> {
    a.checked_mul(b).filter(|n| *n <= isize::MAX as usize)
        .ok_or(NativeSourceFailure::Resource)
}
fn sum(parts: impl IntoIterator<Item = usize>) -> NativeResult<usize> {
    parts.into_iter().try_fold(0, add)
}
fn bytes<T>(count: usize) -> NativeResult<usize> { mul(size_of::<T>(), count) }
fn requirement(category: Category, bytes: usize) -> NativeResult<Requirements> {
    Ok(Requirements::single(category, Bytes {
        host: u64::try_from(bytes).map_err(|_| NativeSourceFailure::Resource)?, device: 0,
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
fn admitted(original: &Reservation, ledger: &Ledger, wanted: Requirements) -> NativeResult<()> {
    let allowance = ledger.snapshot().allowance;
    let have = original.requirements();
    if !original.belongs_to(ledger) || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host)
        || allowance.device > 8u64 << 30 || Category::ALL.into_iter().any(|category| {
            let a = have.get(category); let b = wanted.get(category);
            a.host < b.host || a.device < b.device
        }) {
        return Err(NativeSourceFailure::Authority);
    }
    Ok(())
}

/// No artifact fields or observed compiled height enter these facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSourceFacts {
    pub(crate) operations: OperationCounts,
    pub(crate) maximum_active_rows: usize,
    pub(crate) maximum_padded_rows: usize,
    pub(crate) maximum_wires: usize,
    pub(crate) input_values: usize,
    pub(crate) selection_hint_words: usize,
}
impl NativeSourceFacts {
    fn from_core(core: NativeCoreBound, kind: GraphSourceKind) -> NativeResult<Self> {
        let source = match kind {
            GraphSourceKind::Statement => framing::STATEMENT_SOURCE,
            GraphSourceKind::PrivateProof => framing::PRIVATE_SOURCE,
        };
        let overhead = framing::source_binding_initialization(1770, 8)
            .and_then(|value| value.with_overhead(framing::GRAPH_HEADER))
            .and_then(|value| value.with_overhead(source))
            .map_err(|_| NativeSourceFailure::Resource)?;
        if overhead.cubic != 0 || core.counts.quotient_chunks != 16 {
            return Err(NativeSourceFailure::SourceDrift);
        }
        let operations = core.counts.operations.with_overhead(overhead)
            .map_err(|_| NativeSourceFailure::Resource)?;
        let maximum_active_rows = operations.active_rows(PUBLIC_VALUES)
            .map_err(|_| NativeSourceFailure::Resource)?;
        let maximum_padded_rows = operations.padded_rows(PUBLIC_VALUES)
            .map_err(|_| NativeSourceFailure::Resource)?;
        let maximum_wires = add(core.counts.wires,
            sum([PUBLIC_VALUES, overhead.scalar, mul(8, overhead.poseidon)?])?)?;
        let source_words = match kind { GraphSourceKind::Statement => 16,
            GraphSourceKind::PrivateProof => 8 };
        let input_values = sum([core.counts.input_values, ROOT_INPUTS, source_words])?;
        if maximum_padded_rows > MAX_ROWS || maximum_wires > MAX_WIRES
            || input_values > INPUT_VALUES {
            return Err(NativeSourceFailure::Rows);
        }
        Ok(Self { operations, maximum_active_rows, maximum_padded_rows,
            maximum_wires, input_values, selection_hint_words: core.counts.selection_hint_words })
    }

    fn check(&self, node: &CompiledNode) -> NativeResult<()> {
        let p = &node.program;
        let operations = OperationCounts::from_program(p);
        let hints = selection_hint_words(p).map_err(|_| NativeSourceFailure::Resource)?;
        if p.public_values() != PUBLIC_VALUES || node.public.len() != PUBLIC_VALUES
            || p.active_rows() > self.maximum_active_rows || p.height() > self.maximum_padded_rows
            || p.wire_count() > self.maximum_wires || p.witness_values() != self.input_values
            || node.witness.len() != self.input_values || hints != self.selection_hint_words
            || operations.scalar > self.operations.scalar || operations.cubic > self.operations.cubic
            || operations.poseidon > self.operations.poseidon
            || p.construction_host_bytes() > PROGRAM_BYTES {
            return Err(NativeSourceFailure::SourceDrift);
        }
        Ok(())
    }
}

/// References come from one immutable PreparedWorkflowSources owner. The
/// closed operation issuer must preserve that provenance and same ledger.
pub(crate) struct NativeSourceBlueprint<'a, 'graph> {
    plan: &'a Plan,
    graph: &'a UnprovedRelationGraph,
    context: &'a GraphContext,
    factory: &'a SourceFactory<'graph>,
    kind: GraphSourceKind,
    descriptor: OtherNativeDescriptor<'static>,
    storage: NativePlanningStorage,
    ordinal: usize,
    planning: Requirements,
    output: Requirements,
    scratch: Requirements,
}
impl<'a, 'graph> NativeSourceBlueprint<'a, 'graph> {
    pub(crate) fn new(
        plan: &'a Plan,
        graph: &'a UnprovedRelationGraph,
        context: &'a GraphContext,
        factory: &'a SourceFactory<'graph>,
        kind: GraphSourceKind,
    ) -> NativeResult<Self> {
        Self::new_inner(plan, graph, context, factory, kind, None)
    }
    pub(crate) fn new_for_prepared(
        prepared: &'a crate::spend_pipeline::full_workflow::PreparedWorkflowSources<'graph>,
        kind: GraphSourceKind,
    ) -> NativeResult<Self> {
        let metadata = prepared
            .metadata()
            .map_err(|_| NativeSourceFailure::Source)?;
        Self::new_inner(
            prepared.plan(),
            prepared.graph(),
            prepared.context(),
            prepared.source_factory(),
            kind,
            Some(metadata),
        )
    }
    fn new_inner(
        plan: &'a Plan,
        graph: &'a UnprovedRelationGraph,
        context: &'a GraphContext,
        factory: &'a SourceFactory<'graph>,
        kind: GraphSourceKind,
        metadata: Option<&super::metadata::GraphMetadata>,
    ) -> NativeResult<Self> {
        let fixed = match metadata {
            Some(m) => m.fixed(),
            None => {
                FixedSourceCensus::from_graph(graph).map_err(|_| NativeSourceFailure::Source)?
            }
        };
        let (ordinal, expected, descriptor) = match kind {
            GraphSourceKind::Statement => (
                1,
                LeafKind::Statement,
                OtherNativeDescriptor::Statement {
                    setup_seed: graph.setup_seed(),
                },
            ),
            GraphSourceKind::PrivateProof => (
                2,
                LeafKind::PrivateProof,
                OtherNativeDescriptor::PrivateProof,
            ),
        };
        let leaf = plan
            .leaves()
            .get(ordinal)
            .ok_or(NativeSourceFailure::Coverage)?;
        if let Some(metadata) = metadata {
            if !metadata.native_coverage(kind == GraphSourceKind::PrivateProof) {
                return Err(NativeSourceFailure::Coverage);
            }
        } else {
            let polynomial = |source: &Source| match kind {
                GraphSourceKind::Statement => matches!(source, Source::StatementPolynomial { .. }),
                GraphSourceKind::PrivateProof => matches!(source, Source::ProofPolynomial { .. }),
            };
            let byte = |source: &Source| {
                matches!(source, Source::Context | Source::StatementSeed)
                    || match kind {
                        GraphSourceKind::Statement => {
                            matches!(source, Source::StatementSerial { .. })
                        }
                        GraphSourceKind::PrivateProof => matches!(source, Source::ProofAlpha),
                    }
            };
            if leaf.kind() != &expected
                || !leaf.polynomial_indices().iter().copied().eq(graph
                    .polynomials()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, node)| polynomial(&node.source).then_some(i)))
                || !leaf.byte_indices().iter().copied().eq(graph
                    .bytes()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, node)| byte(&node.source).then_some(i)))
                || !leaf.operation_indices().iter().copied().eq(graph
                    .operations()
                    .iter()
                    .enumerate()
                    .filter_map(|(i, operation)| {
                        (kind == GraphSourceKind::PrivateProof
                            && matches!(operation, Operation::Norm { .. }))
                        .then_some(i)
                    }))
                || (kind == GraphSourceKind::PrivateProof && leaf.operation_indices().len() != 6)
            {
                return Err(NativeSourceFailure::Coverage);
            }
        }
        let storage = descriptor
            .storage(construction())
            .map_err(|_| NativeSourceFailure::Resource)?;
        let key = crate::component_tree::native_shape::cohort::Descriptor::Other(descriptor).key();
        let (planning, output, scratch) = match metadata {
            Some(metadata) => metadata.footprint(0, key, storage, || {
                Self::source_requirements(&storage, &fixed)
            })?,
            None => Self::source_requirements(&storage, &fixed)?,
        };
        Ok(Self {
            plan,
            graph,
            context,
            factory,
            kind,
            descriptor,
            storage,
            ordinal,
            planning,
            output,
            scratch,
        })
    }
    fn source_requirements(
        storage: &NativePlanningStorage,
        fixed: &FixedSourceCensus,
    ) -> NativeResult<(Requirements, Requirements, Requirements)> {
        let wrapper_heap = sum([
            // Two serial-word bridges bound either source family. Include
            // each 32-bit decomposition independently and growth replacement.
            bytes::<Byte>(2 * 4 * 32)?,
            bytes::<Wire>(2 * 8 * 4 * 32)?,
            bytes::<Wire>(2 * 4 * 16)?,
            bytes::<Wire>(4 * 16)?,
            // The statement bundle join calls initial a second time outside
            // the AIR callback accounted in native storage.
            bytes::<Val>(2 * (4 * 8 + 4 * 8 + 22))?,
            bytes::<Vec<Val>>(2 * 3)?,
            8 * 512,
        ])?;
        let wrapper_frames = mul(
            8,
            sum([
                size_of::<Self>(),
                size_of::<NativeResult<Self>>(),
                size_of::<NativeCoreBound>(),
                size_of::<Option<crate::component_tree::native_shape::cohort::ResolvedBound>>(),
                size_of::<NativeSourceCompilePlan<'static, 'static, 'static>>(),
                size_of::<NativeResult<NativeSourceCompilePlan<'static, 'static, 'static>>>(),
                size_of::<NativeSourceFacts>(),
                size_of::<NativeResult<NativeSourceFacts>>(),
                size_of::<Spec>(),
                size_of::<CompiledNode>(),
                size_of::<NativeResult<CompiledNode>>(),
                size_of::<OwnedCompiledSource<'static, 'static, 'static>>(),
                size_of::<CompileOutcome<'static, 'static, 'static>>(),
                size_of::<Reservation>(),
                size_of::<(NativeSourceFailure, Reservation)>(),
                size_of::<ProgramBuilder>(),
                size_of::<ProofInputs>(),
                size_of::<WipedInputs>(),
                size_of::<std::time::Instant>(),
                size_of::<SourceBinding<'static, 'static, 'static>>(),
                size_of::<[[Wire; 4]; crate::statement_air::POLYNOMIALS]>(),
                size_of::<[[Wire; 4]; crate::proof_air::POLYNOMIALS]>(),
                size_of::<[Byte; 32]>(),
                size_of::<[Wire; 32]>(),
                size_of::<[Wire; 16]>(),
                size_of::<[Val; 8]>(),
                size_of::<[Val; PUBLIC_VALUES]>(),
                size_of::<[Wire; PUBLIC_VALUES]>(),
                size_of::<[Requirements; 4]>(),
                16 * size_of::<Vec<Wire>>(),
                16 * size_of::<usize>(),
            ])?,
        )?;
        let wrapper_frames = add(
            wrapper_frames,
            crate::graph_tree::metadata::GraphMetadata::construction_bytes(),
        )?;
        let auxiliary = sum([
            storage.auxiliary_peak_bytes,
            fixed.source_scratch_bytes,
            fixed.frame_bytes,
            wrapper_heap,
            wrapper_frames,
        ])?;
        if auxiliary > AUXILIARY_BYTES || fixed.construction.max_input_values != ROOT_INPUTS {
            return Err(NativeSourceFailure::Resource);
        }
        let planning = requirement(
            Category::PhaseScratch,
            add(storage.total_requested_bytes, wrapper_frames)?,
        )?;
        let mut output = requirement(Category::SymbolicCompiler, PROGRAM_BYTES)?;
        output
            .add(
                Category::CompilerInputs,
                requirement(
                    Category::CompilerInputs,
                    add(
                        storage.input_backing_bytes,
                        bytes::<Val>(2 * PUBLIC_VALUES)?,
                    )?,
                )?
                .get(Category::CompilerInputs),
            )
            .map_err(|_| NativeSourceFailure::Resource)?;
        output
            .add(
                Category::RegisteredMetadata,
                requirement(
                    Category::RegisteredMetadata,
                    sum([
                        size_of::<Program>(),
                        2 * size_of::<usize>(),
                        size_of::<OwnedCompiledSource<'static, 'static, 'static>>(),
                        // The full typed slot owner survives the compiler phase.
                        size_of::<
                            crate::execution::workflow_resources::RetainedOriginal<
                                OwnedCompiledSource<'static, 'static, 'static>,
                            >,
                        >(),
                    ])?,
                )?
                .get(Category::RegisteredMetadata),
            )
            .map_err(|_| NativeSourceFailure::Resource)?;
        let scratch = requirement(Category::PhaseScratch, auxiliary)?;
        Ok((planning, output, scratch))
    }

    pub(crate) fn kind(&self) -> GraphSourceKind {
        self.kind
    }
    pub(crate) fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub(crate) fn graph_plan(&self) -> &'a Plan {
        self.plan
    }
    pub(crate) fn relation_graph(&self) -> &'a UnprovedRelationGraph {
        self.graph
    }
    pub(crate) fn context(&self) -> &'a GraphContext {
        self.context
    }
    pub(crate) fn source_factory(&self) -> &'a SourceFactory<'graph> {
        self.factory
    }
    /// Numeric-only request; normal inspection still authenticates originals.
    pub(crate) fn metadata_request(
        &self,
    ) -> crate::component_tree::native_shape::cohort::Request<'_> {
        crate::component_tree::native_shape::cohort::Request {
            descriptor: crate::component_tree::native_shape::cohort::Descriptor::Other(
                self.descriptor,
            ),
            auxiliary: self.storage.auxiliary_peak_bytes,
        }
    }
    pub(crate) fn planning_requirements(&self) -> Requirements {
        self.planning
    }
    pub(crate) fn compiler_requirements(&self) -> (Requirements, Requirements) {
        (self.output, self.scratch)
    }

    /// Run during complete closure, before native proof zero. The exact
    /// original claim covers bounded recorder/template/builder allocations.
    pub(crate) fn inspect<'plan>(
        &'plan self,
        original: &Reservation,
        ledger: &Ledger,
    ) -> NativeResult<NativeSourceCompilePlan<'plan, 'a, 'graph>> {
        self.inspect_inner(original, ledger, None)
    }
    pub(crate) fn inspect_resolved<'plan>(
        &'plan self,
        original: &Reservation,
        ledger: &Ledger,
        resolved: crate::component_tree::native_shape::cohort::ResolvedBound,
    ) -> NativeResult<NativeSourceCompilePlan<'plan, 'a, 'graph>> {
        self.inspect_inner(original, ledger, Some(resolved))
    }
    fn inspect_inner<'plan>(
        &'plan self,
        original: &Reservation,
        ledger: &Ledger,
        resolved: Option<crate::component_tree::native_shape::cohort::ResolvedBound>,
    ) -> NativeResult<NativeSourceCompilePlan<'plan, 'a, 'graph>> {
        admitted(original, ledger, self.planning)?;
        let core = match resolved {
            Some(bound) => bound.for_request(self.metadata_request(), construction()),
            None => other_native_core_bound(
                self.descriptor,
                construction(),
                self.storage.auxiliary_peak_bytes,
            ),
        }
        .map_err(|_| NativeSourceFailure::Compile)?;
        if core.storage != self.storage {
            return Err(NativeSourceFailure::SourceDrift);
        }
        Ok(NativeSourceCompilePlan {
            blueprint: self,
            facts: NativeSourceFacts::from_core(core, self.kind)?,
        })
    }
}

pub(crate) struct NativeSourceCompilePlan<'plan, 'a, 'graph> {
    blueprint: &'plan NativeSourceBlueprint<'a, 'graph>,
    facts: NativeSourceFacts,
}
impl<'plan, 'a, 'graph> NativeSourceCompilePlan<'plan, 'a, 'graph> {
    pub(crate) fn facts(&self) -> NativeSourceFacts { self.facts }
    pub(crate) fn blueprint(&self) -> &NativeSourceBlueprint<'a, 'graph> { self.blueprint }

    fn compile_borrowed(&self, child: &VerifiedSourceProof<'_, 'graph>,
        output: &Reservation, scratch: &Reservation, ledger: &Ledger)
        -> NativeResult<CompiledNode>
    {
        let source = self.blueprint;
        admitted(output, ledger, source.output)?;
        admitted(scratch, ledger, source.scratch)?;
        if core::ptr::eq(output, scratch) || !core::ptr::eq(child.source(), source.factory)
            || !child.owned().belongs_to(ledger) || child.owned().geometry().kind() != source.kind {
            return Err(NativeSourceFailure::Authority);
        }
        let spec = Spec { plan: Arc::clone(&source.plan.0), first: source.ordinal as u32, count: 1, level: 0 };
        let mut builder = ProgramBuilder::new_with_construction_limits(PUBLIC_VALUES, construction())
            .map_err(|_| NativeSourceFailure::Compile)?;
        let public = public_wires(&mut builder, &spec).map_err(|_| NativeSourceFailure::Compile)?;
        let mut inputs = WipedInputs(ProofInputs::default());
        let mut binding = SourceBinding::new(&source.plan.0.shape, source.graph, &mut builder, &mut inputs.0,
            public[CONTEXT..CONTEXT + 8].try_into().unwrap(),
            public[STATEMENT..STATEMENT + 4].try_into().unwrap(),
            public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap())
            .map_err(|_| NativeSourceFailure::Source)?;
        match child.artifact() {
            NativeGraphSourceProof::Statement(proof) if source.kind == GraphSourceKind::Statement =>
                binding.verify_statement_owned(proof).map_err(|_| NativeSourceFailure::Compile)?,
            NativeGraphSourceProof::PrivateProof(proof) if source.kind == GraphSourceKind::PrivateProof =>
                binding.verify_private_owned(proof).map_err(|_| NativeSourceFailure::Compile)?,
            _ => return Err(NativeSourceFailure::Source),
        }
        let leaf = &source.plan.leaves()[source.ordinal];
        binding.require_exact_coverage(leaf.polynomial_indices(), leaf.byte_indices(), leaf.operation_indices())
            .map_err(|_| NativeSourceFailure::Coverage)?;
        let program = builder.finish(None).map_err(|_| NativeSourceFailure::Compile)?;
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
        child: &VerifiedSourceProof<'_, 'graph>, output: Reservation,
        scratch: &Reservation, ledger: &Ledger)
        -> CompileOutcome<'plan, 'a, 'graph>
    {
        let started = std::time::Instant::now();
        match self.compile_borrowed(child, &output, scratch, ledger) {
            Ok(node) => Ok(OwnedCompiledSource { node: Some(node), blueprint: self.blueprint,
                facts: self.facts, compile_ns: started.elapsed().as_nanos(), output: Some(output) }),
            Err(failure) => Err((failure, output)),
        }
    }
}

pub(crate) type CompileOutcome<'plan, 'a, 'graph> = core::result::Result<
    OwnedCompiledSource<'plan, 'a, 'graph>, (NativeSourceFailure, Reservation)>;

/// The original compiler output claim follows the complete program, public
/// fields and copied child inputs through every move. The immutable blueprint
/// keeps the source plan/graph/factory owner borrowed. Drop order is deliberate.
pub(crate) struct OwnedCompiledSource<'plan, 'a, 'graph> {
    node: Option<CompiledNode>,
    blueprint: &'plan NativeSourceBlueprint<'a, 'graph>,
    facts: NativeSourceFacts,
    compile_ns: u128,
    output: Option<Reservation>,
}
impl<'a, 'graph> OwnedCompiledSource<'_, 'a, 'graph> {
    pub(crate) fn node(&self) -> &CompiledNode { self.node.as_ref().expect("owned source node") }
    pub(crate) fn blueprint(&self) -> &NativeSourceBlueprint<'a, 'graph> { self.blueprint }
    pub(crate) fn facts(&self) -> NativeSourceFacts { self.facts }
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
impl Drop for OwnedCompiledSource<'_, '_, '_> {
    fn drop(&mut self) { self.destroy_payload(); }
}

#[cfg(all(test, feature = "native-matrict", feature = "recursive-wide"))]
mod tests;
