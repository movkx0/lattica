//! Pre-dispatch transport geometry for the fixed 25-public final ordered aggregate.
//!
//! This calculation allocates no proof, template, vector, key or runtime. Its
//! report is not admission, source authentication or permission to dispatch.
//! See `qualification/BOUNDS.md` for the pinned schema and lookup derivation.
use core::mem::size_of;
use lattica_prover_p3::block_v2::{
    codec,
    machine::{program, WIDTH},
    profile::{self, Challenge, Config},
};
use p3_batch_stark::BatchProof;

mod layout;
use layout::Layout;

type Proof = BatchProof<Config>;
type Val = program::Val;
type Result<T> = core::result::Result<T, Refusal>;

const PUBLICS: usize = 25;
const HEIGHTS: usize = 18;
const MIN_LOG_ROWS: usize = 3;
const MAX_LOG_ROWS: usize = 20;
const MAIN_WIDTH: usize = 94;
const PREPROCESSED_WIDTH: usize = 200;
const QUOTIENT_CHUNKS: usize = 16;
// At most ceil(4 * 23 / 6) lane groups plus one public group. Each group
// contributes one cubic extension column, plus the running-sum column.
const LOOKUP_BASE_WIDTH: usize = 54;
const INNER_LIMIT: usize = 2 << 20;
const DECODE_LIMIT: usize = 64 << 20;
const MAX_SEQUENCE: usize = 256;
const MAX_DEPTH: usize = 32;
const MAX_ITEMS: usize = 1 << 20;
const MAGIC_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    Profile,
    Height,
    Overflow,
    Sequence,
    Depth,
    Items,
    InnerEncoding,
    DecodeStorage,
}

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(Refusal::Overflow)
}

fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(Refusal::Overflow)
}

/// Never called: the selector measures the real nested Vec element layout
/// without constructing a zero-filled proof or naming transitive dependency
/// types. Headers embedded in these elements are counted exactly once.
fn element_size<T>(_: for<'a> fn(&'a Proof) -> &'a Vec<T>) -> usize {
    size_of::<T>()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinnedProfile {
    lanes: usize,
    extension_lanes: usize,
    opcode_bits: usize,
    main_width: usize,
    publics: usize,
    max_rows: usize,
    log_blowup: usize,
    cap_height: usize,
    queries: usize,
    random_codewords: usize,
    query_pow_bits: usize,
    challenge_bits: usize,
    collision_bits: usize,
    codec_revision: u64,
    magic: [u8; MAGIC_BYTES],
    inner_limit: usize,
    decode_limit: usize,
    scalar_size: usize,
    challenge_size: usize,
    pointer_size: usize,
}

impl PinnedProfile {
    fn current() -> Self {
        Self {
            lanes: program::LANES,
            extension_lanes: program::EXT_LANES,
            opcode_bits: program::OPCODE_BITS,
            main_width: WIDTH,
            publics: crate::ordered_aggregation::PUBLIC_VALUES,
            max_rows: crate::ordered_aggregation::source::ROW_LIMIT,
            log_blowup: profile::LOG_BLOWUP,
            cap_height: profile::CAP_HEIGHT,
            queries: profile::NUM_QUERIES,
            random_codewords: profile::NUM_RANDOM_CODEWORDS,
            query_pow_bits: profile::QUERY_POW_BITS,
            challenge_bits: profile::CHALLENGE_FIELD_BITS,
            collision_bits: profile::HASH_COLLISION_BITS,
            codec_revision: profile::NODE_CODEC_REVISION,
            magic: *codec::REGISTERED_PROOF_MAGIC,
            inner_limit: profile::MAX_PROOF_BYTES,
            decode_limit: codec::REGISTERED_PROOF_STORAGE_LIMIT_BYTES,
            scalar_size: size_of::<Val>(),
            challenge_size: size_of::<Challenge>(),
            pointer_size: size_of::<usize>(),
        }
    }

    fn check(self) -> Result<()> {
        let expected = Self {
            lanes: 23,
            extension_lanes: 7,
            opcode_bits: 3,
            main_width: MAIN_WIDTH,
            publics: PUBLICS,
            max_rows: 1 << MAX_LOG_ROWS,
            log_blowup: 4,
            cap_height: 6,
            queries: 128,
            random_codewords: 4,
            query_pow_bits: 16,
            challenge_bits: 191,
            collision_bits: 127,
            codec_revision: 2,
            magic: *b"LBV2RP02",
            inner_limit: INNER_LIMIT,
            decode_limit: DECODE_LIMIT,
            scalar_size: 8,
            challenge_size: 24,
            pointer_size: 8,
        };
        if self != expected {
            return Err(Refusal::Profile);
        }
        Ok(())
    }
}

/// Upper bounds for one admitted height, not a proof or transport receipt.
/// `decoded_cumulative_bytes` is the decoder's requested backing only. The
/// original retained proof, encoded packet, fixed decoded Proof, enclosing
/// header, caller frames, verifier and allocator overhead remain additive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct HeightShape {
    pub(super) rows: usize,
    pub(super) encoded_inner_bytes: usize,
    pub(super) decoded_vector_bytes: usize,
    pub(super) canonical_bytes: usize,
    pub(super) decoded_cumulative_bytes: usize,
    pub(super) decoded_fixed_proof_bytes: usize,
    pub(super) decoder_allocations: usize,
    pub(super) logical_items: usize,
    pub(super) max_sequence: usize,
    pub(super) compound_depth: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TransportEnvelope {
    pub(super) cases: [HeightShape; HEIGHTS],
    pub(super) encoded_inner_bytes: usize,
    pub(super) decoded_cumulative_bytes: usize,
}

impl TransportEnvelope {
    /// Fixed local profile only: callers cannot choose lower security, a
    /// smaller public statement, an unreviewed shape, or a different cap.
    /// Every supported height must fit before a future caller may reserve a
    /// transport phase. This function itself grants no such reservation.
    pub(super) fn for_root() -> Result<Self> {
        PinnedProfile::current().check()?;
        let mut result = Self {
            cases: [HeightShape::default(); HEIGHTS],
            encoded_inner_bytes: 0,
            decoded_cumulative_bytes: 0,
        };
        for (index, case) in result.cases.iter_mut().enumerate() {
            let log_rows = add(MIN_LOG_ROWS, index)?;
            let rows = 1usize
                .checked_shl(u32::try_from(log_rows).map_err(|_| Refusal::Overflow)?)
                .ok_or(Refusal::Overflow)?;
            *case = for_height(rows)?;
            result.encoded_inner_bytes = result.encoded_inner_bytes.max(case.encoded_inner_bytes);
            result.decoded_cumulative_bytes = result
                .decoded_cumulative_bytes
                .max(case.decoded_cumulative_bytes);
        }
        Ok(result)
    }
}

/// Fixed planner and layout-algebra forwarding, charged before construction.
/// Every nested helper is at most sixteen calls deep; all state is inline.
pub(super) fn planning_host_bytes() -> Result<usize> {
    let parts = [size_of::<TransportEnvelope>(), size_of::<Result<TransportEnvelope>>(),
        size_of::<[HeightShape; HEIGHTS]>(), size_of::<HeightShape>(), size_of::<Result<HeightShape>>(),
        size_of::<PinnedProfile>(), size_of::<Layout>(), size_of::<Result<Layout>>(),
        size_of::<[Layout; 8]>(), size_of::<[usize; 5]>(), size_of::<[usize; 16]>(),
        size_of::<std::slice::Iter<'static, Layout>>(),
        size_of::<std::iter::Enumerate<std::slice::IterMut<'static, HeightShape>>>(),
        size_of::<std::ops::Range<usize>>(), size_of::<Result<usize>>(), size_of::<Refusal>()];
    mul(16, parts.into_iter().try_fold(core::mem::size_of_val(&parts), add)?)
}

fn scalar() -> Layout {
    // The trusted wide codec serializes every Goldilocks/u64 word as eight
    // raw bytes. The decoder treats those bytes as one scalar, not a tuple.
    Layout::scalar(8)
}

fn extension() -> Result<Layout> {
    // The concrete decoder uses a stack-only ExtField { value: [Val; 3],
    // _phantom: () } seed; it does not allocate an upstream temporary Vec.
    Layout::structure(&[scalar().array(3)?, Layout::scalar(0)])
}

fn cap(log_domain: usize) -> Result<Layout> {
    let roots = 1usize
        .checked_shl(u32::try_from(log_domain.min(6)).map_err(|_| Refusal::Overflow)?)
        .ok_or(Refusal::Overflow)?;
    Layout::structure(&[
        scalar().array(4)?.vector(roots, size_of::<[Val; 4]>())?,
        Layout::scalar(0),
    ])
}

fn authentication(matrices: usize, path: usize) -> Result<Layout> {
    Layout::structure(&[
        scalar()
            .vector(4, size_of::<Val>())?
            .vector(matrices, size_of::<Vec<Val>>())?,
        scalar().array(4)?.vector(path, size_of::<[Val; 4]>())?,
    ])
}

fn for_height(rows: usize) -> Result<HeightShape> {
    if !(1 << MIN_LOG_ROWS..=1 << MAX_LOG_ROWS).contains(&rows) || !rows.is_power_of_two() {
        return Err(Refusal::Height);
    }
    let degree = add(rows.ilog2() as usize, 1)?;
    let log_lde = add(degree, 4)?;
    let ext = extension()?;
    let commits = Layout::structure(&[
        cap(log_lde)?,
        cap(log_lde)?.some()?,
        cap(log_lde)?,
        cap(log_lde)?.some()?,
    ])?;
    let base_values = Layout::structure(&[
        ext.vector(MAIN_WIDTH, size_of::<Challenge>())?,
        Layout::none(),
        ext.vector(PREPROCESSED_WIDTH, size_of::<Challenge>())?.some()?,
        Layout::none(),
        ext.vector(3, size_of::<Challenge>())?
            .vector(QUOTIENT_CHUNKS, size_of::<Vec<Challenge>>())?,
        ext.vector(3, size_of::<Challenge>())?.some()?,
    ])?;
    let lookup_values = Layout::structure(&[
        base_values,
        ext.vector(LOOKUP_BASE_WIDTH, size_of::<Challenge>())?,
        ext.vector(LOOKUP_BASE_WIDTH, size_of::<Challenge>())?,
    ])?;
    let opened_values = Layout::structure(&[
        lookup_values.vector(1, element_size(|p| &p.opened_values.instances))?,
    ])?;

    let matrix_counts = [1, 1, QUOTIENT_CHUNKS, 1, 1];
    let point_counts = [1, 1, 1, 1, 2];
    let widths = [3, MAIN_WIDTH, 3, PREPROCESSED_WIDTH, LOOKUP_BASE_WIDTH];
    let mut random_rounds = Layout::EMPTY;
    let mut input_rounds = Layout::EMPTY;
    for round in 0..5 {
        let random_columns = if round == 3 { 0 } else { 4 };
        let random = ext
            .vector(random_columns, size_of::<Challenge>())?
            .vector(point_counts[round], size_of::<Vec<Challenge>>())?
            .vector(matrix_counts[round], size_of::<Vec<Vec<Challenge>>>())?;
        random_rounds = random_rounds.merge(random)?;
        let opened = scalar()
            .vector(add(widths[round], random_columns)?, size_of::<Val>())?
            .vector(matrix_counts[round], size_of::<Vec<Val>>())?;
        let batch_opening = Layout::structure(&[
            opened,
            authentication(matrix_counts[round], log_lde.saturating_sub(6))?,
        ])?;
        input_rounds = input_rounds.merge(batch_opening)?;
    }
    let random = random_rounds.vector_body(5, size_of::<Vec<Vec<Vec<Challenge>>>>())?;
    let input_proof = input_rounds.vector_body(
        5,
        element_size(|p| &p.opening_proof.1.query_proofs[0].input_proof),
    )?;
    let mut fri_caps = Layout::EMPTY;
    let mut fri_steps = Layout::EMPTY;
    for layer in 0..degree {
        let log_layer = log_lde.checked_sub(add(layer, 1)?).ok_or(Refusal::Overflow)?;
        fri_caps = fri_caps.merge(cap(log_layer)?)?;
        let step = Layout::structure(&[
            Layout::scalar(1), // CommitPhaseProofStep.log_arity is u8.
            ext.vector(1, size_of::<Challenge>())?,
            authentication(1, log_layer.saturating_sub(6))?,
        ])?;
        fri_steps = fri_steps.merge(step)?;
    }
    let query = Layout::structure(&[
        input_proof,
        fri_steps.vector_body(
            degree,
            element_size(|p| &p.opening_proof.1.query_proofs[0].commit_phase_openings),
        )?,
    ])?;
    let fri = Layout::structure(&[
        fri_caps.vector_body(
            degree,
            element_size(|p| &p.opening_proof.1.commit_phase_commits),
        )?,
        scalar().vector(degree, size_of::<Val>())?,
        query.vector(128, element_size(|p| &p.opening_proof.1.query_proofs))?,
        ext.vector(1, size_of::<Challenge>())?,
        scalar(),
    ])?;
    let proof = Layout::structure(&[
        commits,
        opened_values,
        Layout::structure(&[random, fri])?,
        ext.some()?.vector(1, element_size(|p| &p.lookup_terminals))?,
        scalar().vector(1, size_of::<usize>())?,
    ])?;
    finish(rows, proof)
}

fn finish(rows: usize, proof: Layout) -> Result<HeightShape> {
    if proof.max_sequence > MAX_SEQUENCE {
        return Err(Refusal::Sequence);
    }
    if proof.depth > MAX_DEPTH {
        return Err(Refusal::Depth);
    }
    if proof.items > MAX_ITEMS {
        return Err(Refusal::Items);
    }
    let encoded = add(proof.encoded, MAGIC_BYTES)?;
    if encoded > INNER_LIMIT {
        return Err(Refusal::InnerEncoding);
    }
    // Storage::registered strips the magic before canonical re-encoding.
    // Both decoded vectors and this additional exact encoded buffer stay
    // charged cumulatively, including after canonical-buffer destruction.
    let decoded = add(proof.backing, proof.encoded)?;
    if decoded > DECODE_LIMIT {
        return Err(Refusal::DecodeStorage);
    }
    Ok(HeightShape {
        rows,
        encoded_inner_bytes: encoded,
        decoded_vector_bytes: proof.backing,
        canonical_bytes: proof.encoded,
        decoded_cumulative_bytes: decoded,
        decoded_fixed_proof_bytes: size_of::<Proof>(),
        decoder_allocations: add(proof.allocations, usize::from(proof.encoded != 0))?,
        logical_items: proof.items,
        max_sequence: proof.max_sequence,
        compound_depth: proof.depth,
    })
}

#[cfg(test)]
mod tests;
