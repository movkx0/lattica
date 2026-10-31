//! The single FixedSources leaf, with a constructor census before allocation.
//! This does not plan an outer proof, a native source, or complete graph closure.
use super::*;
use crate::{
    obligation_manifest::ContextWires as ManifestContextWires,
    rust_verify::committed_backend::{source_binding::SourceBinding, Operation, Source},
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::machine::{
    pq_bytes::Byte,
    program::{ConstructionLimits, ProofInputs},
    Program,
};

const POLYNOMIALS: usize = 1770;
const BYTE_NODES: usize = 8;
const OPERATIONS: usize = 1311;
const D: usize = 256;
const PROGRAM_BYTES: usize = 64 << 20;
const MAX_WIRES: usize = 1 << 20;
const MAX_ROWS: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixedSourceFailure {
    Unsupported,
    Resource,
    Authority,
    Source,
    Compile,
    Coverage,
    Rows,
}
type FixedResult<T> = core::result::Result<T, FixedSourceFailure>;
fn add(a: usize, b: usize) -> FixedResult<usize> {
    a.checked_add(b).ok_or(FixedSourceFailure::Resource)
}
fn mul(a: usize, b: usize) -> FixedResult<usize> {
    a.checked_mul(b).ok_or(FixedSourceFailure::Resource)
}
fn sum(parts: &[usize]) -> FixedResult<usize> {
    parts.iter().try_fold(0, |total, &part| add(total, part))
}
// Maintained Rust Vec push/extend/collect growth: charge all replaced backing
// plus the final allocation, without borrowing reuse or move-elision credit.
fn vector<T>(elements: usize) -> FixedResult<usize> {
    mul(mul(elements.max(4), 4)?, size_of::<T>())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FixedSourceCensus {
    pub(crate) construction: ConstructionLimits,
    pub(crate) input_bytes: usize,
    pub(crate) source_scratch_bytes: usize,
    pub(crate) frame_bytes: usize,
}

impl FixedSourceCensus {
    pub(super) fn from_graph(graph: &UnprovedRelationGraph) -> FixedResult<Self> {
        if size_of::<usize>() != 8 || PUBLIC_VALUES != 28
            || graph.polynomials().len() != POLYNOMIALS
            || graph.bytes().len() != BYTE_NODES
            || graph.operations().len() != OPERATIONS
        {
            return Err(FixedSourceFailure::Unsupported);
        }
        let nodes = add(POLYNOMIALS, BYTE_NODES)?;
        let input_values = mul(nodes, 4)?;
        // inventory::exact_shape: version/header, polynomial records including
        // fixed coefficients/roots, byte records, expression and operation records.
        let mut shape_words = sum(&[
            47, mul(POLYNOMIALS, 14 + D)?, mul(BYTE_NODES, 11)?,
            mul(graph.expressions().len(), 9)?,
        ])?;
        let mut record_words = D + 5;
        let mut record_roots = 1;
        for operation in graph.operations() {
            let (words, roots) = match operation {
                Operation::CanonicalMap { inputs, expressions, .. }
                | Operation::SignedMap { inputs, expressions, .. } => (
                    add(add(4, inputs.len())?, expressions.len())?, add(inputs.len(), 1)?,
                ),
                Operation::Norm { inputs, .. } => (add(2, inputs.len())?, inputs.len()),
                Operation::HashAlpha { parts, .. } | Operation::HashX { parts, .. } => (
                    add(2, mul(2, parts.len())?)?, add(parts.len(), 1)?,
                ),
                Operation::ParametersPp { .. } => (35, 2),
                Operation::SampleG { .. } | Operation::ExpandAlpha { .. } => (8, 5),
                Operation::ByteMap { .. } => return Err(FixedSourceFailure::Unsupported),
                Operation::Add { .. } | Operation::Sub { .. }
                | Operation::AutomorphismQ { .. } | Operation::SignedToCanonical { .. }
                | Operation::Ntt { .. } | Operation::Mul { .. }
                | Operation::GBound { .. } | Operation::EqualBytes { .. }
                | Operation::EqualSigned { .. } => (8, 3),
            };
            shape_words = add(shape_words, add(6, words)?)?;
            record_words = record_words.max(words);
            record_roots = record_roots.max(roots);
        }
        let manifest_words = add(12, mul(6, nodes)?)?;
        let source_scratch_bytes = sum(&[
            // SourceBinding::new performs one exact-shape comparison. Include
            // the collector, current Record and expression/header backing.
            vector::<u64>(shape_words)?, vector::<u64>(record_words.max(41))?,
            vector::<[Val; 4]>(record_roots)?, vector::<u64>(9)?,
            // SourceBinding public root arrays and all three coverage flags.
            mul(nodes, size_of::<[Wire; 4]>())?, POLYNOMIALS + BYTE_NODES + OPERATIONS,
            // Header and root-manifest inputs are outside ProgramBuilder.
            vector::<u64>(12)?, vector::<Wire>(manifest_words)?,
            // Exact-sized four-root ProofInputs::bases return and public wires.
            vector::<Wire>(4)?, vector::<Wire>(PUBLIC_VALUES)?,
            // The context bridge uses one 32-byte owner, one bit decomposition
            // at a time, and a 16-field byte commitment. Charge both context
            // and seed commitment fields additively, without overlap credit.
            vector::<Byte>(32)?, vector::<Wire>(32)?, mul(2, vector::<Wire>(16)?)?,
            // Static Debug/refusal paths in these maintained constructors.
            // No child artifact or caller diagnostic is formatted here.
            4 * 512,
        ])?;
        let frame_bytes = mul(4, sum(&[
            size_of::<Self>(), size_of::<FixedResult<Self>>(),
            size_of::<FixedSourceCompilePlan<'static>>(),
            size_of::<FixedResult<FixedSourceCompilePlan<'static>>>(),
            size_of::<CompiledNode>(), size_of::<FixedResult<CompiledNode>>(),
            size_of::<Program>(), size_of::<core::result::Result<Program, lattica_prover_p3::block_v2::machine::program::ExecutionError>>(),
            size_of::<ProgramBuilder>(), size_of::<ProofInputs>(),
            size_of::<SourceBinding<'static, 'static, 'static>>(),
            size_of::<Spec>(), size_of::<GraphContext>(), size_of::<ManifestContextWires>(),
            size_of::<[Byte; 32]>(), size_of::<[Wire; 32]>(),
            size_of::<[[Wire; 4]; 3]>(), size_of::<[Wire; PUBLIC_VALUES]>(),
            size_of::<[Val; PUBLIC_VALUES]>(), size_of::<String>(),
            size_of::<sha3::Sha3_256>(), 32 * size_of::<usize>(),
            12 * size_of::<Vec<Wire>>(),
        ])?)?;
        Ok(Self {
            construction: ConstructionLimits {
                max_requested_program_bytes: PROGRAM_BYTES,
                max_wires: MAX_WIRES,
                max_input_values: input_values,
            },
            input_bytes: mul(input_values, size_of::<Val>())?,
            source_scratch_bytes,
            frame_bytes,
        })
    }
}

/// Immutable references originate in the admitted PreparedWorkflowSources owner.
/// The plan is allocation-free and supplies no reservation or GPU authority.
pub(crate) struct FixedSourceCompilePlan<'a> {
    plan: &'a Plan,
    graph: &'a UnprovedRelationGraph,
    context: &'a GraphContext,
    census: FixedSourceCensus,
}
impl<'a> FixedSourceCompilePlan<'a> {
    pub(crate) fn new(
        plan: &'a Plan, graph: &'a UnprovedRelationGraph, context: &'a GraphContext,
    ) -> FixedResult<Self> {
        let leaf = plan.leaves().first().ok_or(FixedSourceFailure::Source)?;
        if leaf.kind() != &LeafKind::FixedSources || !leaf.operation_indices().is_empty()
            || !leaf.polynomial_indices().iter().copied().eq(graph.polynomials().iter()
                .enumerate().filter_map(|(index, node)| (node.source == Source::Fixed).then_some(index)))
            || !leaf.byte_indices().iter().copied().eq(graph.bytes().iter()
                .enumerate().filter_map(|(index, node)| matches!(node.source,
                    Source::Fixed | Source::Context | Source::StatementSeed).then_some(index)))
        {
            return Err(FixedSourceFailure::Coverage);
        }
        Ok(Self { plan, graph, context, census: FixedSourceCensus::from_graph(graph)? })
    }
    pub(crate) fn census(&self) -> FixedSourceCensus { self.census }

    // Called only by SourceCompileOperation after its original workflow access
    // validates binding/context/retained-source provenance. No native dispatch.
    pub(crate) fn compile(&self) -> FixedResult<CompiledNode> {
        let spec = Spec { plan: Arc::clone(&self.plan.0), first: 0, count: 1, level: 0 };
        let mut builder = ProgramBuilder::new_with_construction_limits(
            PUBLIC_VALUES, self.census.construction,
        ).map_err(|_| FixedSourceFailure::Compile)?;
        let public = public_wires(&mut builder, &spec).map_err(|_| FixedSourceFailure::Compile)?;
        let mut inputs = ProofInputs {
            values: Vec::with_capacity(self.census.construction.max_input_values),
        };
        let mut session = SourceBinding::new(
            &self.plan.0.shape, self.graph, &mut builder, &mut inputs,
            public[CONTEXT..CONTEXT + 8].try_into().unwrap(),
            public[STATEMENT..STATEMENT + 4].try_into().unwrap(),
            public[NODE_MANIFEST..NODE_MANIFEST + 4].try_into().unwrap(),
        ).map_err(|_| FixedSourceFailure::Source)?;
        session.constrain_fixed_sources().map_err(|_| FixedSourceFailure::Source)?;
        let leaf = &self.plan.leaves()[0];
        session.require_exact_coverage(
            leaf.polynomial_indices(), leaf.byte_indices(), leaf.operation_indices(),
        ).map_err(|_| FixedSourceFailure::Coverage)?;
        if inputs.values.len() != self.census.construction.max_input_values
            || inputs.values.capacity() > self.census.construction.max_input_values
        {
            return Err(FixedSourceFailure::Resource);
        }
        let program = builder.finish(None).map_err(|_| FixedSourceFailure::Compile)?;
        if program.height() > MAX_ROWS || program.wire_count() > MAX_WIRES
            || program.construction_host_bytes() > PROGRAM_BYTES
        {
            return Err(FixedSourceFailure::Rows);
        }
        let public = header(&spec, self.context);
        Ok(CompiledNode { spec, program: Arc::new(program), public, witness: inputs.values })
    }
}

/// Exact views for the separate owned outer adapter; no prepared key or proof.
pub(crate) fn compiled_program(node: &CompiledNode) -> &Arc<Program> { &node.program }
pub(crate) fn compiled_witness(node: &CompiledNode) -> &[Val] { &node.witness }

#[cfg(all(test, feature = "native-matrict"))]
mod tests;
