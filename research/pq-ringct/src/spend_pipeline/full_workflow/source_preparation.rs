//! Second admitted source phase. Its plans borrow the original graph owner;
//! no plan owns a graph from which one of its own fields borrows.
//!
//! The census below describes requested Rust allocation backing for the pinned
//! Rust 1.96 source and the maintained constructors. It is not a process RSS,
//! allocator-overhead, or compiled-stack claim: those retain the external
//! worker/process guards. All arithmetic and graph scans finish before any
//! allocating constructor or raw GPU operation is entered.
use super::{InitialNativeSource, PreparedGraphSources, SourcePlanningPlan, SourcePreparationError};
use crate::{
    aes_lane_air::AesLaneAir,
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements},
        workflow_resources::{
            source_retained_overhead_bytes, SourceFailure, SourcePhaseFailure,
            SourcePreparationAccess, SourceRetained,
        },
        ProvingContext,
    },
    graph_auxiliary::{AuxiliaryFactory, AuxiliaryRequest},
    graph_crypto::{self, Request, SegmentInfo},
    graph_proofs::{ComponentKind, GraphProofPlan, PlannedBatch, ResourceLimits},
    graph_sources::SourceFactory,
    graph_tree::{self, GraphContext, LeafPlan},
    producer_branch,
    recursive_aggregation::LeafStatement,
    rust_verify::{
        committed_backend::{
            source_binding::RegisteredGraphShape, Expression, Operation, PolyId,
            PolynomialKind, Source, TranscriptPart, UnprovedRelationGraph,
        },
        D,
    },
    shake_air::lane::batch::ShakeSegmentAir,
    spend_pipeline::Budgets,
    transcript_air::{PartKind, PartValues, TranscriptAir},
};
use core::mem::{align_of, size_of};
use lattica_prover_p3::{
    block_v2::machine::program::Val,
    proving::{operation_storage::RawPreparationReportStorage, Policy},
};
use p3_field::PrimeCharacteristicRing;
use std::collections::BTreeMap;

type Result<T> = core::result::Result<T, SourcePreparationError>;
const FULL_KINDS: [usize; 18] = [6, 2, 409, 201, 2, 95, 95, 474, 6, 12, 2, 1, 0, 1, 2, 1, 1, 1];
const MAX_EXPRESSION_DEPTH: usize = 64;
const MAX_EXPRESSION_VISITS: usize = 1 << 20;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(SourcePreparationError::Resource)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(SourcePreparationError::Resource)
}
fn sum(values: impl IntoIterator<Item = usize>) -> Result<usize> {
    values.into_iter().try_fold(0, add)
}
fn host(bytes: usize) -> Result<Bytes> {
    Ok(Bytes { host: u64::try_from(bytes).map_err(|_| SourcePreparationError::Resource)?, device: 0 })
}

// Rust 1.96 push/collect/exact-sized construction, including old/new backing.
// The factor three also covers doubling from a non-power-of-two initial Vec.
// A retained owner keeps this conservative growth allowance until destruction.
fn vector<T>(count: usize) -> Result<usize> {
    if count == 0 || size_of::<T>() == 0 { return Ok(0); }
    mul(mul(3, count.checked_next_power_of_two().ok_or(SourcePreparationError::Resource)?.max(4))?, size_of::<T>())
}

// Independent small vectors each have their own minimum capacity. Summing
// logical element counts and rounding once would undercount leaf assignments.
fn vectors<T>(elements: usize, owners: usize) -> Result<usize> {
    mul(mul(3, add(mul(2, elements)?, mul(4, owners)?)?)?, size_of::<T>())
}

// alloc/collections/btree/node.rs in the pinned Rust 1.96 source uses B=6:
// eleven keys/values, a parent pointer/two u16 fields, and twelve child edges.
// Bound every node as internal, with separate alignment slack for all fields.
// At most one occupied node per key plus an empty root exists; doubling and
// two extra nodes cover a split/root-growth overlap and consuming iterators.
fn btree<K, V>(entries: usize) -> Result<usize> {
    let alignment = align_of::<K>().max(align_of::<V>()).max(align_of::<usize>());
    let node = sum([
        size_of::<usize>(), 2 * size_of::<u16>(),
        mul(11, add(size_of::<K>(), size_of::<V>())?)?,
        12 * size_of::<usize>(), mul(5, alignment)?,
    ])?;
    mul(add(mul(2, entries)?, 2)?, node)
}

fn operation_kind(operation: &Operation) -> usize {
    match operation {
        Operation::CanonicalMap { .. } => 0, Operation::SignedMap { .. } => 1,
        Operation::Add { .. } => 2, Operation::Sub { .. } => 3,
        Operation::AutomorphismQ { .. } => 4, Operation::SignedToCanonical { .. } => 5,
        Operation::Ntt { .. } => 6, Operation::Mul { .. } => 7,
        Operation::Norm { .. } => 8, Operation::GBound { .. } => 9,
        Operation::EqualBytes { .. } => 10, Operation::EqualSigned { .. } => 11,
        Operation::ByteMap { .. } => 12, Operation::ParametersPp { .. } => 13,
        Operation::SampleG { .. } => 14, Operation::ExpandAlpha { .. } => 15,
        Operation::HashAlpha { .. } => 16, Operation::HashX { .. } => 17,
    }
}

// Only equality of group keys matters for this census; the constructor still
// validates the original algebra descriptors and uses its unchanged R4 limits.
fn group_key(operation: &Operation) -> Option<(u8, u64, u32)> {
    match *operation {
        Operation::Add { modulus, .. } => Some((0, modulus, 0)),
        Operation::Sub { modulus, .. } => Some((1, modulus, 0)),
        Operation::SignedToCanonical { modulus, bound, .. } => Some((2, modulus, bound)),
        Operation::Ntt { modulus, .. } => Some((3, modulus, 0)),
        Operation::Mul { modulus, .. } => Some((4, modulus, 0)),
        _ => None,
    }
}

// Before linear_map_air's recursive BTreeMap constructor can run, prove that
// every coefficient tree is acyclic, shallow, and contains only this map's
// <=16 declared inputs. Otherwise a small declared input list could conceal an
// arbitrarily large temporary expression map before descriptor rejection.
fn expression_depth(
    graph: &UnprovedRelationGraph, id: usize, coefficient: usize,
    inputs: &[PolyId], depth: usize, visits: &mut usize,
) -> Result<usize> {
    *visits = add(*visits, 1)?;
    if depth > MAX_EXPRESSION_DEPTH || *visits > MAX_EXPRESSION_VISITS {
        return Err(SourcePreparationError::Geometry);
    }
    let node = graph.expressions().get(id).ok_or(SourcePreparationError::Geometry)?;
    let child = |next: usize, visits: &mut usize| -> Result<usize> {
        if next >= id { return Err(SourcePreparationError::Geometry); }
        expression_depth(graph, next, coefficient, inputs, depth + 1, visits)
    };
    match *node {
        Expression::CanonicalInput { polynomial, index }
        | Expression::SignedInput { polynomial, index } => {
            if index != coefficient || !inputs.contains(&polynomial) {
                return Err(SourcePreparationError::Geometry);
            }
            Ok(depth)
        }
        Expression::CanonicalConstant { .. } => Ok(depth),
        Expression::Add { left, right, .. } | Expression::Sub { left, right, .. }
        | Expression::SignedSub { left, right, .. } => {
            Ok(child(left, visits)?.max(child(right, visits)?))
        }
        Expression::Scale { input, .. } | Expression::SignedNeg { input, .. } => child(input, visits),
        // This is also unsupported by the maintained linear descriptor. It is
        // refused here, before any registration/descriptor allocation.
        Expression::ConvertCoefficient { .. } => Err(SourcePreparationError::Geometry),
    }
}

fn descriptor_heap(inputs: usize) -> Result<usize> {
    sum([
        vector::<PolynomialKind>(inputs)?, vector::<[i64; D]>(inputs)?,
        vector::<u32>(add(inputs, 2)?)?,
    ])
}

fn transcript_heap(parts: usize) -> Result<usize> {
    // TranscriptAir's Event consists of three usize values. There is at most
    // one event per part; PartValues owns its entire coefficient array inline.
    sum([vector::<PartKind>(parts)?, vector::<[usize; 3]>(parts)?, vector::<PartValues>(parts)?])
}

fn raw_crypto(input: usize, output: usize) -> Result<usize> {
    // Exact maintained operations_crypto::host_bytes staging bound.
    sum([mul(add(output, 1)?, 16)?, input, 80 << 10])
}

#[derive(Clone, Copy)]
struct Census {
    retained: usize,
    temporary: usize,
    packing: usize,
    backend_host: usize,
}

impl Census {
    fn from_source(graph: &UnprovedRelationGraph, native: &InitialNativeSource<'_>) -> Result<Self> {
        if size_of::<usize>() != 8 || D != 256 || graph.polynomials().len() != 1770
            || graph.bytes().len() != 8 || graph.operations().len() != 1311
        { return Err(SourcePreparationError::Geometry); }
        let mut kinds = [0usize; 18];
        for operation in graph.operations() { kinds[operation_kind(operation)] += 1; }
        if kinds != FULL_KINDS { return Err(SourcePreparationError::Geometry); }

        let polynomials = graph.polynomials().len();
        let bytes = graph.bytes().len();
        let operations = graph.operations().len();
        let batches = operations - kinds[8];
        let leaves = add(batches, 3)?;
        let mut shape_words = sum([
            47, mul(polynomials, 14 + D)?, mul(bytes, 11)?, mul(graph.expressions().len(), 9)?,
        ])?;
        let mut record_words = D + 5;
        let mut record_roots = 1usize;
        let mut descriptor_retained = 0usize;
        let mut descriptor_temporary = 0usize;
        let mut map_inputs = 0usize;
        let mut map_depth = 0usize;
        let mut expression_visits = 0usize;
        let mut public_values = 0usize;
        let mut groups = 0usize;
        let mut grouped_indices = 0usize;
        let mut request_count = 0usize;
        let mut crypto_payloads = 0usize;
        let mut crypto_partitions = 0usize;
        let mut largest_partition = 0usize;
        let mut auxiliary_count = 0usize;
        let mut auxiliary_payloads = 0usize;
        let mut largest_transcript = 0usize;
        let mut largest_transcript_scratch = 0usize;
        let mut raw_host = raw_crypto(49, 32)?;
        let manifest_words = add(12, mul(6, add(polynomials, bytes)?)?)?;
        let statement_words = add(1, native.statement_bytes().len().div_ceil(4))?;
        let source_statement_words = add(24, mul(4, crate::statement_air::POLYNOMIALS)?)?;
        let source_proof_words = add(8, mul(4, crate::proof_air::POLYNOMIALS)?)?;
        let mut field_words = manifest_words.max(statement_words)
            .max(source_statement_words).max(source_proof_words).max(4 + 12 * 64);

        for (index, operation) in graph.operations().iter().enumerate() {
            if let Some(key) = group_key(operation) {
                grouped_indices = add(grouped_indices, 1)?;
                if !graph.operations()[..index].iter().any(|old| group_key(old) == Some(key)) {
                    groups = add(groups, 1)?;
                }
            }
            let (body_words, roots) = match operation {
                Operation::CanonicalMap { inputs, expressions, .. }
                | Operation::SignedMap { inputs, expressions, .. } => {
                    if inputs.is_empty() || inputs.len() > 16 {
                        return Err(SourcePreparationError::Geometry);
                    }
                    // The maintained permutation recognizer is allocation-free.
                    if crate::permutation_air::graph::graph_operation(graph, index).is_err() {
                        for (coefficient, &id) in expressions.iter().enumerate() {
                            map_depth = map_depth.max(expression_depth(
                                graph, id, coefficient, inputs, 1, &mut expression_visits,
                            )?);
                        }
                        map_inputs = map_inputs.max(inputs.len());
                        let heap = descriptor_heap(inputs.len())?;
                        descriptor_retained = add(descriptor_retained, heap)?;
                        descriptor_temporary = descriptor_temporary.max(add(heap, vector::<PolyId>(inputs.len())?)?);
                    }
                    public_values = add(public_values, mul(4, add(inputs.len(), 1)?)?.max(8))?;
                    (add(add(4, inputs.len())?, expressions.len())?, add(inputs.len(), 1)?)
                }
                Operation::Norm { inputs, .. } => (add(2, inputs.len())?, inputs.len()),
                Operation::HashAlpha { parts, .. } | Operation::HashX { parts, .. } => {
                    if parts.is_empty() || parts.len() > 256 { return Err(SourcePreparationError::Geometry); }
                    let mut input = 0usize;
                    for part in parts {
                        input = add(input, match part { TranscriptPart::Bytes(_) => 32, TranscriptPart::Polynomial(_) => 4 * D })?;
                    }
                    let output = if matches!(operation, Operation::HashAlpha { .. }) { 32 } else { 137 };
                    let units = crate::shake_air::Descriptor { input_len: input, output_len: output }
                        .permutations().map_err(|_| SourcePreparationError::Geometry)?;
                    let partition = add(vector::<ShakeSegmentAir>(units)?, vector::<SegmentInfo>(units)?)?;
                    request_count = add(request_count, 1)?;
                    crypto_payloads = add(crypto_payloads, vector::<u8>(input)?)?;
                    crypto_partitions = add(crypto_partitions, partition)?;
                    largest_partition = largest_partition.max(partition);
                    let heap = transcript_heap(parts.len())?;
                    largest_transcript = largest_transcript.max(heap);
                    largest_transcript_scratch = largest_transcript_scratch.max(sum([
                        size_of::<TranscriptAir>(), heap, vector::<[Val; 4]>(parts.len())?,
                        vector::<u8>(input)?, vector::<u32>(D)?,
                    ])?);
                    auxiliary_payloads = add(auxiliary_payloads, heap)?;
                    auxiliary_count = add(auxiliary_count, 1)?;
                    if matches!(operation, Operation::HashX { .. }) {
                        auxiliary_payloads = add(auxiliary_payloads, vector::<u8>(output)?)?;
                        auxiliary_count = add(auxiliary_count, 1)?;
                    }
                    raw_host = raw_host.max(raw_crypto(input, output)?);
                    field_words = field_words.max(input.div_ceil(2)).max(output.div_ceil(2)).max(mul(8, parts.len())?);
                    (add(2, mul(2, parts.len())?)?, add(parts.len(), 1)?)
                }
                Operation::ParametersPp { .. } => {
                    let input = add(b"lattica/pq-ringct/matrict-plus-n10/fixture-v1".len(), 64)?;
                    let units = crate::shake_air::Descriptor { input_len: input, output_len: 32 }
                        .permutations().map_err(|_| SourcePreparationError::Geometry)?;
                    let partition = add(vector::<ShakeSegmentAir>(units)?, vector::<SegmentInfo>(units)?)?;
                    request_count = add(request_count, 1)?;
                    crypto_payloads = add(crypto_payloads, vector::<u8>(input)?)?;
                    crypto_partitions = add(crypto_partitions, partition)?;
                    largest_partition = largest_partition.max(partition);
                    raw_host = raw_host.max(raw_crypto(input, 32)?);
                    field_words = field_words.max(input.div_ceil(2));
                    (35, 2)
                }
                Operation::SampleG { .. } | Operation::ExpandAlpha { .. } => {
                    let outputs = if matches!(operation, Operation::SampleG { .. }) {
                        [mul(crate::uniform_air::Kind::SampleG4.draws(), 4)?, 0]
                    } else {
                        [mul(crate::uniform_air::Kind::ExpandAlpha2.draws(), 4)?, 127]
                    };
                    for output in outputs.into_iter().filter(|&n| n != 0) {
                        let units = output.div_ceil(16);
                        let partition = add(vector::<AesLaneAir>(units)?, vector::<SegmentInfo>(units)?)?;
                        request_count = add(request_count, 1)?;
                        crypto_partitions = add(crypto_partitions, partition)?;
                        largest_partition = largest_partition.max(partition);
                        auxiliary_count = add(auxiliary_count, 1)?;
                        auxiliary_payloads = add(auxiliary_payloads, vector::<u8>(output)?)?;
                        raw_host = raw_host.max(raw_crypto(32, output)?);
                        field_words = field_words.max(output.div_ceil(2));
                    }
                    (8, 5)
                }
                Operation::ByteMap { .. } => return Err(SourcePreparationError::Geometry),
                _ => {
                    // Affine roots are bundled into four publics per batch;
                    // charging twelve per operation also bounds Mul and Ntt.
                    public_values = add(public_values, 12)?;
                    (8, 3)
                }
            };
            shape_words = add(shape_words, add(6, body_words)?)?;
            record_words = record_words.max(body_words);
            record_roots = record_roots.max(roots);
        }
        if request_count != 7 || auxiliary_count != 7 || field_words > 1 << 20 {
            return Err(SourcePreparationError::Geometry);
        }
        raw_host = raw_host.max(mul(add(field_words.max(1), 9)?, size_of::<u64>())?);
        let fixed_polynomials = graph.polynomials().iter().filter(|node| node.source == Source::Fixed).count();
        let fixed_bytes = graph.bytes().iter().filter(|node| node.source == Source::Fixed).count();
        let registered_heap = sum([
            vector::<u64>(shape_words)?, vector::<(usize, [Val; 4])>(fixed_polynomials)?,
            vector::<(usize, [Val; 4])>(fixed_bytes)?,
        ])?;
        // Arc<PlanInner>: two reference counts, RegisteredGraphShape, label,
        // leaves Vec and field-alignment slack; the shape's inline source
        // arrays are included by size_of rather than reconstructed manually.
        let tree_owner = sum([
            2 * size_of::<usize>(), size_of::<RegisteredGraphShape>(), 32,
            size_of::<Vec<LeafPlan>>(), 5 * align_of::<RegisteredGraphShape>(),
        ])?;
        let tree_heap = sum([
            tree_owner, registered_heap, vector::<LeafPlan>(leaves)?,
            vectors::<usize>(polynomials, leaves)?, vectors::<usize>(operations, leaves)?,
            vectors::<usize>(add(bytes, mul(2, leaves)?)?, leaves)?,
        ])?;
        let algebra_heap = sum([
            vector::<PlannedBatch>(batches)?, vectors::<usize>(batches, batches)?,
            vectors::<Val>(public_values, batches)?, descriptor_retained,
        ])?;
        let crypto_heap = sum([
            vector::<Request>(request_count)?, crypto_payloads, crypto_partitions,
        ])?;
        let auxiliary_heap = add(vector::<AuxiliaryRequest>(auxiliary_count)?, auxiliary_payloads)?;
        let source_heap = vector::<[i64; D]>(crate::proof_air::POLYNOMIALS)?;
        let retained = sum([tree_heap, algebra_heap, crypto_heap, auxiliary_heap, source_heap,
            crate::graph_tree::metadata::GraphMetadata::retained_bytes()])?;

        let registration_temporary = sum([
            // The initial RegisteredGraphShape is dropped before tree creation;
            // nevertheless reserve two complete copies plus match/inventory
            // scratch so no exact-shape reallocation overlaps an unclaimed one.
            mul(2, add(size_of::<RegisteredGraphShape>(), registered_heap)?)?,
            vector::<u64>(record_words.max(41))?, vector::<[Val; 4]>(record_roots)?,
            vector::<usize>(crate::statement_air::POLYNOMIALS)?,
            vector::<usize>(crate::proof_air::POLYNOMIALS)?,
            mul(2, add(crate::statement_air::POLYNOMIALS, crate::proof_air::POLYNOMIALS)?)?
                .checked_mul(size_of::<Option<usize>>()).ok_or(SourcePreparationError::Resource)?,
        ])?;
        let group_temporary = sum([
            btree::<(u8, u64, u32), (ComponentKind, Vec<usize>)>(groups)?,
            vectors::<usize>(grouped_indices, groups)?,
            // Stable batch sorting and the operation_batches vector coexist
            // with the algebra plan, then transfer indices into the tree.
            vector::<PlannedBatch>(batches)?, vector::<Vec<usize>>(batches)?,
            vectors::<usize>(batches, batches)?, vector::<Option<usize>>(operations)?,
            vector::<crate::affine_air::AffineRoots>(64)?,
        ])?;
        let expression_temporary = sum([
            mul(add(map_depth, 2)?, btree::<PolyId, i128>(map_inputs)?)?,
            btree::<u32, ()>(add(map_inputs, 2)?)?, mul(2, descriptor_temporary)?,
            // Named recursive Form/operand/index temporaries; process stack
            // limits still guard compiler frame materialization.
            mul(add(map_depth, 2)?, sum([
                2 * size_of::<BTreeMap<PolyId, i128>>(), 2 * size_of::<i128>(),
                2 * size_of::<Option<u32>>(), 8 * size_of::<usize>(), 2 * size_of::<Expression>(),
            ])?)?,
        ])?;
        let crypto_temporary = sum([
            // AuxiliaryFactory deliberately builds another complete crypto
            // plan using its maintained defaults. Neither that plan nor the
            // old partition during subdivision may consume the output claim.
            size_of::<graph_crypto::Plan>(), crypto_heap, mul(2, largest_partition)?,
            largest_transcript_scratch, largest_transcript,
            vector::<u8>(49)?, vector::<u8>(32)?,
        ])?;
        let source_temporary = sum([
            // One decoded Proof coexists with converted ProofValues. The
            // original validated native census includes its decoded backing,
            // inline proof and encoded storage; twice it bounds decode moves.
            mul(2, native.retained_bytes())?,
            mul(add(crate::statement_air::POLYNOMIALS, crate::proof_air::POLYNOMIALS)?, size_of::<Option<[Val; 4]>>())?,
            2 * size_of::<[i64; D]>(),
        ])?;
        // Count each distinct source packing buffer and one independent
        // manifest/affine/transcript packing Vec. This additive ceiling also
        // covers failure destruction; operation-internal staging is separate.
        let packing = sum([
            vector::<u64>(statement_words)?, vector::<u64>(source_statement_words)?,
            vector::<u64>(source_proof_words)?, vector::<u64>(field_words)?,
        ])?;
        Ok(Self { retained, temporary: sum([
            registration_temporary, group_temporary, expression_temporary,
            crypto_temporary, source_temporary,
        ])?, packing, backend_host: raw_host })
    }
}

pub(crate) struct SourcePreparationPlan<'graph> {
    context: &'graph ProvingContext,
    source_fingerprint: [u8; 32],
    compiled_source_fingerprint: [u8; 32],
    native_identity: [u8; 32],
    budgets: Budgets,
    algebra_limits: ResourceLimits,
    graph: &'graph SourceRetained<PreparedGraphSources>,
    native: &'graph InitialNativeSource<'graph>,
    output: Requirements,
    failure: Requirements,
    scratch: Requirements,
    backend: Bytes,
}

impl<'graph> SourcePreparationPlan<'graph> {
    pub(crate) fn new(
        scope: &SourcePlanningPlan<'graph>,
        graph: &'graph SourceRetained<PreparedGraphSources>,
        native: &'graph InitialNativeSource<'graph>,
    ) -> Result<Self> {
        scope.validate_initial_source(native)?;
        if !cfg!(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64"))
            || scope.context().policy() != Policy::GpuRequired
            || graph.get().native_identity() != native.identity()
            || graph.source_fingerprint() != scope.source_fingerprint()
            || graph.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
            || graph.get().graph().setup_seed() != native.setup_seed()
        { return Err(SourcePreparationError::Identity); }
        let census = Census::from_source(graph.get().graph(), native)?;
        let report = RawPreparationReportStorage::new().map_err(|_| SourcePreparationError::Resource)?;
        let backend = Bytes { host: host(census.backend_host)?.host, device: scope.source_backend_allowance().device };
        if backend.host == 0 || backend.host > 24 << 30 || backend.device == 0 || backend.device > 8 << 30 {
            return Err(SourcePreparationError::Resource);
        }
        let mut output = Requirements::single(Category::SymbolicCompiler, host(census.retained)?);
        output.add(Category::RegisteredMetadata, host(add(
            usize::try_from(source_retained_overhead_bytes().map_err(|_| SourcePreparationError::Resource)?)
                .map_err(|_| SourcePreparationError::Resource)?,
            add(size_of::<PreparedWorkflowSources<'graph>>(),
                SourcePreparationAccess::completion_retained_bytes().map_err(|_| SourcePreparationError::Resource)?)?,
        )?)?).map_err(|_| SourcePreparationError::Resource)?;
        let failure = Requirements::single(Category::Report, host(add(
            size_of::<SourceFailure<PreparedWorkflowSources<'graph>>>(),
            size_of::<SourcePhaseFailure<PreparedWorkflowSources<'graph>>>(),
        )?)?);
        let mut scratch = Requirements::single(Category::SymbolicCompiler, host(census.temporary)?);
        scratch.add(Category::CompilerInputs, host(census.packing)?)
            .map_err(|_| SourcePreparationError::Resource)?;
        let frames = mul(4, sum([
            size_of::<Self>(), size_of::<SourcePreparationOperation<'_, 'graph>>(),
            size_of::<PreparedWorkflowSources<'graph>>(),
            size_of::<SourceRetained<PreparedWorkflowSources<'graph>>>(),
            size_of::<SourcePreparationAccess<'_>>(),
            size_of::<Result<PreparedWorkflowSources<'graph>>>(),
            size_of::<core::result::Result<PreparedWorkflowSources<'graph>, String>>(),
            size_of::<Census>(), size_of::<LeafStatement>(), size_of::<sha3::Sha3_256>(),
        ])?)?;
        scratch.add(Category::PhaseScratch, host(add(frames, report.required_host_bytes)?)?)
            .map_err(|_| SourcePreparationError::Resource)?;
        // Copy only facts derived by the immutable original bootstrap. The
        // constructor has no caller budget/fingerprint override, and validates
        // exact initial-source pointer membership before copying these facts.
        // Neither bootstrap nor this descriptor must outlive its operation.
        Ok(Self {
            context: scope.context(), source_fingerprint: scope.source_fingerprint(),
            compiled_source_fingerprint: scope.compiled_source_fingerprint(),
            native_identity: native.identity(), budgets: scope.budgets(),
            algebra_limits: scope.algebra_limits(), graph, native,
            output, failure, scratch, backend,
        })
    }
    pub(crate) fn context(&self) -> &'graph ProvingContext { self.context }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.source_fingerprint }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.compiled_source_fingerprint }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.graph.belongs_to(ledger) }
    pub(crate) fn output_requirements(&self) -> Requirements { self.output }
    pub(crate) fn failure_requirements(&self) -> Requirements { self.failure }
    pub(crate) fn scratch_requirements(&self) -> Requirements { self.scratch }
    pub(crate) fn backend_allowance(&self) -> Bytes { self.backend }
    pub(crate) fn operation(&self) -> SourcePreparationOperation<'_, 'graph> {
        SourcePreparationOperation { plan: self }
    }
}

pub(crate) struct SourcePreparationOperation<'plan, 'graph> {
    plan: &'plan SourcePreparationPlan<'graph>,
}
impl<'graph> SourcePreparationOperation<'_, 'graph> {
    pub(crate) fn plan(&self) -> &SourcePreparationPlan<'graph> { self.plan }
    pub(crate) fn execute(self, access: &SourcePreparationAccess<'_>) -> Result<PreparedWorkflowSources<'graph>> {
        if !access.matches_preparation(self.plan)
            || !core::ptr::eq(access.context(), self.plan.context())
            || access.source_fingerprint() != self.plan.source_fingerprint()
        { return Err(SourcePreparationError::Identity); }
        if self.plan.native.identity() != self.plan.native_identity
            || self.plan.graph.get().native_identity() != self.plan.native_identity
            || self.plan.graph.source_fingerprint() != self.plan.source_fingerprint
            || self.plan.graph.compiled_source_fingerprint() != self.plan.compiled_source_fingerprint
        { return Err(SourcePreparationError::Identity); }
        if access.preparation_host_bytes().map_err(|_| SourcePreparationError::Resource)? != self.plan.backend.host {
            return Err(SourcePreparationError::Resource);
        }
        #[cfg(not(feature = "opencl"))]
        { Err(SourcePreparationError::Preparation) }
        #[cfg(feature = "opencl")]
        {
            let graph: &'graph UnprovedRelationGraph = self.plan.graph.get().graph();
            let native = self.plan.native;
            let execution = self.plan.context();
            let budgets = self.plan.budgets;
            let host = usize::try_from(self.plan.backend.host).map_err(|_| SourcePreparationError::Resource)?;
            let (prepared, report) = execution.with_witness_preparation(host, |operations| {
                // Fixed static errors prevent graph-dependent diagnostic
                // expansion across the raw-operation/report boundary.
                let registered = RegisteredGraphShape::from_trusted_graph(graph)
                    .map_err(|_| "source registration failed".to_owned())?;
                let algebra = GraphProofPlan::new_with_operations(
                    &registered, graph, self.plan.algebra_limits, operations,
                ).map_err(|_| "algebra source preparation failed".to_owned())?;
                drop(registered);
                let tree = graph_tree::Plan::from_trusted_graph(graph, algebra.operation_batches())
                    .map_err(|_| "graph tree preparation failed".to_owned())?;
                let statement = LeafStatement::from_bytes_on_gpu(
                    tree.label(), *native.context(), native.statement_bytes(), operations,
                ).map_err(|_| "statement source preparation failed".to_owned())?;
                let context = GraphContext {
                    context: *native.context(), statement: statement.digest.map(Val::from_u64),
                    node_manifest: tree.node_manifest_hint_on_gpu(graph, operations)
                        .map_err(|_| "graph manifest preparation failed".to_owned())?,
                };
                let source = SourceFactory::new_on_gpu(
                    &tree, graph, &context, native.statement_bytes(), native.proof_bytes(),
                    budgets.native_bytes, operations,
                ).map_err(|_| "native source preparation failed".to_owned())?;
                let crypto = graph_crypto::Plan::new_with_operations(&tree, graph, budgets.crypto_policy, operations)
                    .map_err(|_| "crypto source preparation failed".to_owned())?;
                let auxiliary = AuxiliaryFactory::new_on_gpu(&tree, graph, &context, budgets.native_bytes, operations)
                    .map_err(|_| "auxiliary source preparation failed".to_owned())?;
                let branch = producer_branch::Factory::new_with_operations(&tree, graph, &context, execution, operations)
                    .map_err(|_| "producer source preparation failed".to_owned())?;
                Ok(PreparedWorkflowSources {
                    graph: self.plan.graph, native, tree, context, algebra, crypto, source, auxiliary, branch,
                    metadata: std::sync::OnceLock::new(),
                })
            }).map_err(|_| SourcePreparationError::Preparation)?;
            // The report's complete backing stays under the source phase's
            // scratch claim until it has been destroyed; A then drains it.
            drop(report);
            Ok(prepared)
        }
    }
}

/// Immutable source plans only. None of these getters authorize compilation,
/// proving, or acceptance; the original retained owner remains borrowed and
/// the subsequent closure planner must admit each producer/consumer phase.
pub(crate) struct PreparedWorkflowSources<'graph> {
    graph: &'graph SourceRetained<PreparedGraphSources>,
    native: &'graph InitialNativeSource<'graph>,
    tree: graph_tree::Plan,
    context: GraphContext,
    algebra: GraphProofPlan<'graph>,
    crypto: graph_crypto::Plan,
    source: SourceFactory<'graph>,
    auxiliary: AuxiliaryFactory,
    branch: producer_branch::Factory<'graph>,
    metadata: std::sync::OnceLock<Box<core::result::Result<crate::graph_tree::metadata::GraphMetadata, crate::graph_tree::fixed_sources::FixedSourceFailure>>>,
}
impl<'graph> PreparedWorkflowSources<'graph> {
    /// The box and every fixed cache slot are funded by this owner's original
    /// source-preparation retained claim, before any lazy analysis can run.
    pub(crate) fn metadata(&self) -> core::result::Result<&crate::graph_tree::metadata::GraphMetadata, crate::graph_tree::fixed_sources::FixedSourceFailure> {
        self.metadata.get_or_init(|| Box::new(crate::graph_tree::metadata::GraphMetadata::new(self.plan(), self.graph())))
            .as_ref().as_ref().map_err(|error| *error)
    }
    pub(crate) fn plan(&self) -> &graph_tree::Plan { &self.tree }
    pub(crate) fn context(&self) -> &GraphContext { &self.context }
    pub(crate) fn crypto(&self) -> &graph_crypto::Plan { &self.crypto }
    pub(crate) fn algebra(&self) -> &GraphProofPlan<'graph> { &self.algebra }
    pub(crate) fn native_identity(&self) -> [u8; 32] { self.native.identity() }
    pub(crate) fn native_source(&self) -> &'graph InitialNativeSource<'graph> { self.native }
    pub(crate) fn graph(&self) -> &'graph UnprovedRelationGraph { self.graph.get().graph() }
    pub(crate) fn source_factory(&self) -> &SourceFactory<'graph> { &self.source }
    pub(crate) fn auxiliary_factory(&self) -> &AuxiliaryFactory { &self.auxiliary }
    pub(crate) fn branch_factory(&self) -> &producer_branch::Factory<'graph> { &self.branch }
}
