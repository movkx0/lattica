//! Cumulative requested payloads for one fixed P3 0.6.1 CPU note proof.
//! Every source request is charged until the encoded owner is destroyed.
//! See SOURCE_BOUNDS.md: these are source bounds, never observed RSS.
use super::*;
use p3_air::{SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};
use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView, RowMajorMatrixViewMut},
    Dimensions,
};
use p3_uni_stark::Domain;

type Packed = <Val as Field>::Packing;
type PackedExt = <Challenge as ExtensionField<Val>>::ExtensionPacking;
type InputData = <crate::note_gpu::ValMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
type FriData =
    <crate::note_gpu::ChallengeMmcs as Mmcs<Challenge>>::ProverData<RowMajorMatrix<Challenge>>;
const CONSTRAINTS: usize = 128;
const EXPRESSION_OPERATIONS: usize = 1024;
const TREE_LOG: usize = 17;
const LDE_ROWS: usize = 1 << TREE_LOG;
const MATRICES: usize = 18;
const FRI_LAYERS: usize = TREE_LOG - 4;

#[repr(C)]
struct ArcPayload<T> {
    strong: std::sync::atomic::AtomicUsize,
    weak: std::sync::atomic::AtomicUsize,
    payload: T,
}

// Rust 1.96 B=6 BTree nodes: 11 keys,11 values,12 child edges. Both
// actual keys (usize or (usize,Val)) and values (thin/fat Arc) fit two words.
// Three words cover the parent pointer, index/length and alignment padding.
#[repr(C)]
struct CacheNodeUpper {
    header: [usize; 3],
    keys: [[usize; 2]; 11],
    values: [[usize; 2]; 11],
    edges: [usize; 12],
}

#[derive(Clone, Copy, Default)]
struct Ledger(usize);
impl Ledger {
    fn bytes(&mut self, bytes: usize) -> Result<(), Error> {
        self.0 = add(self.0, bytes)?;
        Ok(())
    }
    fn exact<T>(&mut self, count: usize) -> Result<(), Error> {
        self.bytes(mul(count, size_of::<T>())?)
    }
    fn growing<T>(&mut self, count: usize) -> Result<(), Error> {
        if count != 0 && size_of::<T>() != 0 {
            // All old/new buffers under Rust 1.96's audited exact-sized,
            // truthful iterator or amortized doubling paths. No caller Vecs.
            self.exact::<T>(mul(4, count.max(8))?)?;
        }
        Ok(())
    }
    fn repeat(&mut self, other: Self, count: usize) -> Result<(), Error> {
        self.bytes(mul(other.0, count)?)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(in crate::note_gpu) struct CpuPlan {
    pub trace_bytes: usize,
    pub configuration_bytes: usize,
    pub symbolic_bytes: usize,
    pub quotient_bytes: usize,
    pub transforms_bytes: usize,
    pub commitment_bytes: usize,
    pub opening_bytes: usize,
    pub fri_bytes: usize,
    pub encoded_output_bytes: usize,
    pub inline_bytes: usize,
    pub operation_bytes: usize,
    pub decoder_bytes: usize,
    pub verifier_bytes: usize,
    pub handoff_inline_bytes: usize,
    pub total_bytes: usize,
}

impl CpuPlan {
    pub(super) fn new() -> Result<Self, Error> {
        let g = Geometry::pinned()?;
        if cfg!(debug_assertions)
            || !cfg!(all(target_os = "linux", target_arch = "x86_64"))
            || (1 << (g.degree_bits + g.log_blowup)) != LDE_ROWS
            || g.quotient_chunks + 2 != MATRICES
            || size_of::<Packed>() > 64
            || size_of::<PackedExt>() > 128
        {
            return Err(Error::Geometry);
        }
        let trace_bytes = trace()?;
        let configuration_bytes = configuration()?;
        let symbolic_bytes = symbolic(g)?;
        let quotient_bytes = quotient(g)?;
        let transforms_bytes = transforms(g)?;
        let commitment_bytes = commitments(g)?;
        let opening_bytes = opening(g)?;
        let fri_bytes = fri(g)?;
        let encoded_output_bytes = MAX_PROOF_BYTES;
        let inline_bytes = [
            size_of::<MyConfig>(),
            size_of::<lattica_prover_p3::config::Challenger>(),
            size_of::<Proof>(),
            size_of::<RowMajorMatrix<Val>>(),
            size_of::<lattica_prover_p3::joinsplit_air::Witness>(),
            size_of::<CpuPlan>(),
            size_of::<CpuPrepared<'static>>(),
            size_of::<CpuProduced>(),
            size_of::<CpuTimes>(),
            8 * size_of::<Instant>(),
            4 * size_of::<Reservation>(),
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        let operation_bytes = [
            trace_bytes,
            configuration_bytes,
            symbolic_bytes,
            quotient_bytes,
            transforms_bytes,
            commitment_bytes,
            opening_bytes,
            fri_bytes,
            encoded_output_bytes,
            inline_bytes,
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        if operation_bytes > super::super::super::NATIVE_HOST_BYTES {
            return Err(Error::ResourceLimit);
        }
        let decoder_bytes = codec::requirements_for(
            MAX_PROOF_BYTES,
            add(ARTIFACT_HEADER_BYTES, MAX_PROOF_BYTES)?,
            26,
            g,
        )?
        .reserved_bytes;
        let verifier_bytes = VerificationPlan::new()
            .map_err(|_| Error::Geometry)?
            .required_temporary_bytes();
        let handoff_inline_bytes = [
            size_of::<RetainedCpuProducer>(),
            size_of::<codec::PreAdmittedScratch>(),
            size_of::<codec::ScratchGuard<'static>>(),
            2 * size_of::<[Val; 26]>(),
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        let total_bytes = [
            operation_bytes,
            decoder_bytes,
            verifier_bytes,
            handoff_inline_bytes,
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        if total_bytes > WORKER_HOST_BYTES {
            return Err(Error::ResourceLimit);
        }
        Ok(Self {
            trace_bytes,
            configuration_bytes,
            symbolic_bytes,
            quotient_bytes,
            transforms_bytes,
            commitment_bytes,
            opening_bytes,
            fri_bytes,
            encoded_output_bytes,
            inline_bytes,
            operation_bytes,
            decoder_bytes,
            verifier_bytes,
            handoff_inline_bytes,
            total_bytes,
        })
    }
}

fn trace() -> Result<usize, Error> {
    // build_trace: exact trace and i128 delta; two growing 32-entry links;
    // 74 scalar Poseidon calls, each constructs two4x8 +22 field vectors.
    let mut h = Ledger::default();
    h.exact::<Val>(4096 * 19)?;
    h.exact::<i128>(4096)?;
    for _ in 0..2 {
        h.growing::<(usize, u64)>(32)?;
    }
    h.exact::<Val>(74 * (2 * 4 * 8 + 22))?;
    Ok(h.0)
}

fn configuration() -> Result<usize, Error> {
    // Five permutations in fresh_config, plus initialise_challenger's clone.
    // Two DFTs: PCS and periodic evaluation; each has three empty Arc roots.
    #[repr(C)]
    struct Cache {
        lock: std::sync::atomic::AtomicUsize,
        map: std::collections::BTreeMap<usize, usize>,
    }
    let mut h = Ledger::default();
    h.exact::<Val>(6 * (2 * 4 * 8 + 22))?;
    h.exact::<ArcPayload<Cache>>(6)?;
    Ok(h.0)
}

fn symbolic(g: Geometry) -> Result<usize, Error> {
    let mut h = Ledger::default();
    h.exact::<SymbolicAirBuilder<Val>>(1)?;
    // Builder construction and main()'s owned two-row clone.
    h.growing::<SymbolicVariable<Val>>(4 * g.trace_columns + 26 + g.periodic_columns)?;
    h.growing::<SymbolicExpression<Val>>(CONSTRAINTS)?;
    h.growing::<u8>(CONSTRAINTS)?; // private ConstraintType enum
    h.growing::<usize>(CONSTRAINTS)?; // emitted-order index stream
                                      // Every arithmetic operation creates at most two Arc expression nodes.
    h.exact::<ArcPayload<SymbolicExpression<Val>>>(2 * EXPRESSION_OPERATIONS)?;
    h.growing::<Challenge>(CONSTRAINTS)?; // alpha powers
    h.growing::<Vec<Val>>(2)?;
    h.growing::<Val>(2 * CONSTRAINTS)?;
    Ok(h.0)
}

fn quotient(g: Geometry) -> Result<usize, Error> {
    let mut h = Ledger::default();
    // Coset/vanishing inputs, two denominator/inverse/result triples,
    // transition and vanishing selectors, with two spare full vectors.
    h.exact::<Val>(12 * LDE_ROWS)?;
    // Original periodic columns and all index-list construction from C011's
    // reviewed verifier census; borrowing its full sum overcounts evaluation.
    h.bytes(
        VerificationPlan::new()
            .map_err(|_| Error::Geometry)?
            .required_temporary_bytes(),
    )?;
    // Periodic DFT columns and rectangular table; packed table has the same
    // scalar backing plus one Vec descriptor per possible scalar row group.
    h.exact::<Val>(3 * g.periodic_columns * LDE_ROWS)?;
    h.growing::<Vec<Packed>>(LDE_ROWS)?;
    // Even charging every node of the indexed binary split tree permits less
    // than2*LDE_ROWS initializations, not merely the eight worker threads.
    h.exact::<Packed>(2 * LDE_ROWS * (2 * g.trace_columns + CONSTRAINTS))?;
    h.exact::<[Vec<Packed>; 4]>(2 * LDE_ROWS)?;
    // Quotient output, flatten_to_base copy and split-evals copy. Domains,
    // chunk wrappers and the hiding reduction's coefficient arrays.
    h.exact::<Challenge>(3 * LDE_ROWS)?;
    h.growing::<Domain<MyConfig>>(2 * g.quotient_chunks)?;
    h.growing::<RowMajorMatrix<Val>>(2 * g.quotient_chunks)?;
    h.growing::<(Domain<MyConfig>, RowMajorMatrix<Val>)>(g.quotient_chunks + 2)?;
    h.growing::<Val>(3 * g.quotient_chunks)?;
    Ok(h.0)
}

fn transforms(g: Geometry) -> Result<usize, Error> {
    let mut h = Ledger::default();
    // Main, random and16 quotient LDE matrices (widths23,6,16x6).
    let columns = g.trace_columns
        + g.random_codewords
        + (g.quotient_chunks + 1) * (g.challenge_degree + g.random_codewords);
    // Input/hiding construction, old/new reserve_exact overlap and an owned
    // materialization; no move or cache-sharing credit is assumed.
    h.exact::<Val>(4 * columns * LDE_ROWS)?;
    // Quotient random-values slab, vanishing coefficients and forward FFT
    // output. Each chunk width is6 and its final height is LDE_ROWS.
    h.exact::<Val>(3 * g.quotient_chunks * 6 * LDE_ROWS)?;
    let transforms = 2 + 2 * g.quotient_chunks + g.periodic_columns;
    let mut one = Ledger::default();
    // Forward/inverse pairs and all coset twiddle vectors. Every transform
    // has <=32 cosets and their total length <=its final height. Charging
    // eight final-height vectors covers both representations and all calls.
    one.exact::<Val>(8 * LDE_ROWS)?;
    one.growing::<RowMajorMatrixViewMut<'static, Val>>(32)?;
    // At most34 cache insertions per transform (32 cosets + two pairs).
    // At most two nodes per insertion over the complete append-only tree.
    one.exact::<CacheNodeUpper>(2 * 34)?;
    one.exact::<ArcPayload<[Vec<Val>; 2]>>(2)?;
    // A Vec<Vec<Val>> and its independently allocated Arc<[Vec<Val>]>.
    one.growing::<Vec<Val>>(32 * TREE_LOG)?;
    one.exact::<Vec<Val>>(32 * TREE_LOG)?;
    one.exact::<[std::sync::atomic::AtomicUsize; 2]>(32)?;
    h.repeat(one, transforms)?;
    Ok(h.0)
}

fn tree(h: &mut Ledger, matrices: usize, height: usize) -> Result<(), Error> {
    h.exact::<Val>(4 * matrices * height)?; // independent hiding salts
    h.exact::<[Val; 4]>(2 * height + TREE_LOG * 2)?;
    // Stable-sort collection, clone for every arity decision, sorting scratch
    // and matrix-injection descriptors. No deduplication or alias credit.
    for _ in 0..TREE_LOG + 4 {
        h.growing::<usize>(matrices)?;
    }
    h.growing::<Vec<[Val; 4]>>(TREE_LOG + 1)?;
    h.growing::<usize>(TREE_LOG)?;
    h.growing::<Dimensions>(matrices)?;
    h.growing::<(RowMajorMatrix<Val>, RowMajorMatrix<Val>)>(matrices)?;
    h.growing::<[Val; 4]>(3 * (1 << 6))?; // cap construction/transcript/owner
    Ok(())
}

fn commitments(g: Geometry) -> Result<usize, Error> {
    let mut h = Ledger::default();
    for matrices in [1, g.quotient_chunks, 1] {
        tree(&mut h, matrices, LDE_ROWS)?;
    }
    h.exact::<InputData>(3)?;
    Ok(h.0)
}

fn opening(g: Geometry) -> Result<usize, Error> {
    let mut h = Ledger::default();
    h.exact::<Val>(LDE_ROWS)?; // common bit-reversed coset
    h.exact::<Challenge>(6 * LDE_ROWS)?; //2points: difference/inverse/adjusted
    h.exact::<Challenge>((MATRICES + 1) * LDE_ROWS)?; // compressed+reduced
    let mut widths = [6usize; MATRICES];
    widths[1] = 23;
    for (i, width) in widths.into_iter().enumerate() {
        let points = if i == 1 { 2 } else { 1 };
        // Each indexed fold/reduce has <=two identities per scalar input row.
        // round up the scalar width to the largest supported eight lanes.
        h.exact::<Challenge>(points * 2 * (1 << g.degree_bits) * width.next_multiple_of(8))?;
        h.growing::<Challenge>(points * width)?;
        h.growing::<Challenge>(points * 4)?; // separately drained hiding tail
        h.growing::<Vec<Challenge>>(2 * points)?;
        h.growing::<Challenge>(points)?;
    }
    h.growing::<PackedExt>(23)?;
    h.growing::<Vec<Vec<Vec<Challenge>>>>(6)?;
    h.growing::<Vec<Vec<Challenge>>>(2 * MATRICES)?;
    h.growing::<(Challenge, Vec<Challenge>)>(4)?;
    h.growing::<(Challenge, usize)>(2)?;
    h.growing::<RowMajorMatrixView<'static, Val>>(2 * MATRICES)?;
    h.growing::<(
        Vec<RowMajorMatrixView<'static, Val>>,
        &'static Vec<Vec<Challenge>>,
    )>(3)?;
    h.growing::<usize>(2 * MATRICES)?;
    h.growing::<Vec<Challenge>>(32)?;
    // Returned uni-stark field clones and their descriptors are bounded by the
    // same exact quadratic proof-shape census used by the canonical decoder.
    h.bytes(g.decoded_backing_ceiling_bytes()?)?;
    Ok(h.0)
}

fn query_tree(h: &mut Ledger, matrices: usize, fields: usize) -> Result<(), Error> {
    // Source salted row, split owned row/salts, sibling path, and all wrappers.
    h.growing::<Val>(2 * (fields + 4 * matrices))?;
    h.growing::<Vec<Val>>(3 * matrices)?;
    h.growing::<[Val; 4]>(TREE_LOG)?;
    Ok(())
}

fn fri(g: Geometry) -> Result<usize, Error> {
    let mut h = Ledger::default();
    let mut layer = Ledger::default();
    // Binary progress gives at most13 layers. Charge each at the full initial
    // height even though the actual arity16 chain has only four rounds.
    tree(&mut layer, 1, LDE_ROWS)?;
    layer.exact::<Challenge>(2 * LDE_ROWS)?; // fold materialization+output
    layer.exact::<Val>(LDE_ROWS)?; // inverse twiddle powers
    layer.growing::<usize>(2)?;
    h.repeat(layer, FRI_LAYERS)?;
    h.growing::<super::super::super::Cap>(FRI_LAYERS)?;
    h.growing::<FriData>(FRI_LAYERS)?;
    h.growing::<usize>(FRI_LAYERS)?;
    h.growing::<Val>(FRI_LAYERS)?;
    h.growing::<Challenge>(16)?; // final-poly backing (before truncate)
    let mut query = Ledger::default();
    query_tree(&mut query, 1, 6)?;
    query_tree(&mut query, 1, 23)?;
    query_tree(&mut query, g.quotient_chunks, 16 * 6)?;
    query.growing::<super::super::super::Opening>(3)?;
    let mut step = Ledger::default();
    query_tree(&mut step, 1, 16 * 2)?;
    step.growing::<Challenge>(2 * 16)?; // extension row and sibling copies
    step.growing::<Vec<Challenge>>(1)?;
    query.repeat(step, FRI_LAYERS)?;
    query.growing::<super::super::super::Step>(FRI_LAYERS)?;
    h.repeat(query, g.queries)?;
    h.growing::<super::super::super::Query>(g.queries)?;
    // POW uses DuplexChallenger's packed find_map_any implementation: no
    // per-candidate challenger clone/Vec. Rayon scheduling and native stacks
    // remain under the external worker guard, never called payload bytes.
    Ok(h.0)
}
