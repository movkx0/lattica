//! Producer-side host census for the fixed quadratic note opening graph.
//! Raw producer capacities are distinct from decoded lengths: hiding drain
//! retains full rows, and removing a FRI value retains full arity backing.
//! This pure phase census does not grant dispatch or a shared quota lease.
use super::{add, mul, Error, Geometry};
use crate::block_v2::{
    gpu_hash::{
        device::{self, DeviceMatrix, DeviceOpening, ReplaySalts},
        CandidateMmcs, FriData, FriExtensionMmcs, ProverData,
    },
    gpu_quotient_prover::opened_value_descriptor_host_bound,
    pcs_field::ProvingConfig,
};
use crate::config::{Challenge, Val};
use core::mem::size_of;
use p3_commit::{BatchOpening, Mmcs};
use p3_fri::{CommitPhaseProofStep, QueryProof};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

type Input = BatchOpening<Val, CandidateMmcs>;
type Step = CommitPhaseProofStep<Challenge, FriExtensionMmcs<Challenge>>;
type Query = QueryProof<Challenge, FriExtensionMmcs<Challenge>, Vec<Input>>;
type Cap = <CandidateMmcs as Mmcs<Val>>::Commitment;
type Proof = p3_uni_stark::Proof<ProvingConfig<Challenge>>;

// Existing source-owned component ceilings. These are checked obligations,
// never new operation allowances or an alternative to the worker quota.
const PCS_QUERY_METADATA: usize = 1 << 20;
const FRI_QUERY_LIMIT: usize = 1 << 30;
const FRI_ROW_QUERY_LIMIT: usize = 1 << 20;
const ROUNDS: usize = 3;
const MATRICES: usize = 18;
const ROUND_MATRICES: [usize; ROUNDS] = [1, 1, 16];
const ROUND_COLUMNS: [usize; ROUNDS] = [6, 23, 16 * 6];

fn bytes<T>(count: usize) -> Result<usize, Error> {
    mul(count, size_of::<T>())
}
fn sum(parts: &[usize]) -> Result<usize, Error> {
    parts.iter().try_fold(0, |n, &part| add(n, part))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct OpeningHostResources {
    round_point_backing_bytes: usize,
    full_opened_value_backing_bytes: usize,
    hidden_tail_backing_bytes: usize,
    opening_construction_bytes: usize,
    initial_query_bytes: usize,
    fri_query_bytes: usize,
    fri_assembly_bytes: usize,
    retained_metadata_bytes: usize,
    opened_value_descriptor_bytes: usize,
    raw_proof_inline_bytes: usize,
    opening_and_query_host_bytes: usize,
    raw_proof_capacity_ceiling_bytes: usize,
    maximum_fri_layer_count: usize,
    maximum_fri_row_capacity: usize,
    requires_device_only_trees_and_randomness: bool,
}

impl OpeningHostResources {
    /// Allocation-free and independent of environment or device initialization.
    /// Exact normalized quotient_chunks=16 must be checked before this model
    /// can participate in an enclosing producer's admission token.
    pub fn new() -> Result<Self, Error> {
        let g = Geometry::pinned()?;
        let log_height = g.rows.ilog2() as usize + 1 + g.log_blowup;
        let layers = log_height
            .checked_sub(g.log_blowup)
            .ok_or(Error::Geometry)?;
        let queries = g.queries;
        let arity = 1usize
            .checked_shl(g.max_log_arity as u32)
            .ok_or(Error::Overflow)?;
        if log_height != 17 || layers != 13 || arity != 16 || g.quotient_chunks != 16 {
            return Err(Error::Geometry);
        }
        let mut widths = [6usize; MATRICES];
        widths[1] = 23;
        let mut points = [1usize; MATRICES];
        points[1] = 2;
        let matrix_capacity = ROUND_MATRICES
            .into_iter()
            .try_fold(0, |n, m| add(n, (2 * m).max(4)))?;
        let point_count = points.into_iter().try_fold(0, add)?;
        let value_count = widths
            .iter()
            .zip(points)
            .try_fold(0, |n, (&w, p)| add(n, mul(w, p)?))?;

        // uni::prove uses three rounds; allow the minimum Vec push capacity of
        // four and twice each logical matrix count even though vec! is exact.
        let round_point_backing_bytes = sum(&[
            bytes::<(usize, Vec<Vec<Challenge>>)>(4)?,
            bytes::<Vec<Challenge>>(matrix_capacity)?,
            bytes::<Challenge>(point_count)?,
        ])?;
        let full_opened_value_backing_bytes = sum(&[
            bytes::<Vec<Vec<Vec<Challenge>>>>(ROUNDS)?,
            bytes::<Vec<Vec<Challenge>>>(MATRICES)?,
            bytes::<Vec<Challenge>>(point_count)?,
            bytes::<Challenge>(value_count)?,
        ])?;
        let hidden_tail_backing_bytes = sum(&[
            bytes::<Vec<Vec<Vec<Challenge>>>>(ROUNDS)?,
            bytes::<Vec<Vec<Challenge>>>(MATRICES)?,
            bytes::<Vec<Challenge>>(point_count)?,
            bytes::<Challenge>(mul(point_count, g.random_codewords)?)?,
        ])?;
        let readback = widths.iter().zip(points).try_fold(0usize, |n, (&w, p)| {
            Ok::<_, Error>(n.max(bytes::<Challenge>(mul(w, p)?)?))
        })?;
        let opening_construction_bytes = sum(&[
            bytes::<(u32, DeviceOpening)>(MATRICES)?,
            readback,
            // The one-height FRI bridge and source round-height bookkeeping.
            size_of::<DeviceMatrix>(),
            bytes::<usize>(ROUNDS)?,
        ])?;

        // Same preflight formula as CandidateMmcs::owned_query_host_bytes.
        // Charge all round batches together, including raw/converted gathers
        // and paths, so returned outputs cannot recycle a live owner's charge.
        let path = mul(log_height.saturating_sub(g.cap_height), 32)?;
        let mut initial_query_bytes = 0;
        for (columns, matrices) in ROUND_COLUMNS.into_iter().zip(ROUND_MATRICES) {
            let fields = add(columns, mul(matrices, 4)?)?;
            initial_query_bytes = add(
                initial_query_bytes,
                sum(&[
                    mul(mul(2, queries)?, add(mul(fields, 8)?, path)?)?,
                    bytes::<Vec<[Val; 4]>>(queries)?,
                    PCS_QUERY_METADATA,
                ])?,
            )?;
        }

        // Overcount every possible post-fold height at the maximum full arity.
        // This covers the unchanged adaptive arity schedule without assuming
        // sibling len == backing capacity or borrowing binary-only coverage.
        let mut fri_query_bytes = 0;
        let mut cap_bytes = 0;
        for log in g.log_blowup..log_height {
            let query = FriData::query_host_bytes::<Challenge>(log, arity, queries)
                .map_err(|_| Error::Geometry)?;
            if query > FRI_ROW_QUERY_LIMIT {
                return Err(Error::ResourceLimit);
            }
            fri_query_bytes = add(fri_query_bytes, query)?;
            cap_bytes = add(
                cap_bytes,
                mul(3, bytes::<[Val; 4]>(1 << log.min(g.cap_height))?)?,
            )?;
        }
        let fri_assembly_bytes = sum(&[
            cap_bytes,
            mul(
                layers,
                sum(&[
                    size_of::<Cap>(),
                    size_of::<(FriData, usize)>(),
                    size_of::<Val>(),
                ])?,
            )?,
            mul(bytes::<usize>(queries)?, add(add(1, ROUNDS)?, layers)?)?,
            mul(
                queries,
                add(size_of::<Vec<Input>>(), bytes::<Input>(ROUNDS)?)?,
            )?,
            mul(
                queries,
                add(size_of::<Vec<Step>>(), bytes::<Step>(layers)?)?,
            )?,
            bytes::<Query>(queries)?,
            bytes::<Challenge>(2)?,
        ])?;
        if sum(&[initial_query_bytes, fri_query_bytes, fri_assembly_bytes])? > FRI_QUERY_LIMIT {
            return Err(Error::ResourceLimit);
        }

        // RetainedTree's device Allocation is inline in ProverData/FriData.
        // Only its cap is heap-owned in the admitted Device tree mode. Prefix
        // allocations/scrub owners and salt streams have separate Arc backing.
        // Count shared wrappers per occurrence, deliberately granting no alias
        // credit. The engine/config/session and compiler envelopes are separate.
        let retained_metadata_bytes = sum(&[
            bytes::<ProverData<RowMajorMatrix<Val>>>(ROUNDS)?,
            mul(
                matrix_capacity,
                sum(&[
                    size_of::<Dimensions>(),
                    size_of::<DeviceMatrix>(),
                    size_of::<ReplaySalts>(),
                ])?,
            )?,
            mul(
                add(add(MATRICES, layers)?, 5)?,
                device::matrix_host_backing(false),
            )?,
            device::matrix_host_backing(true),
            mul(
                add(MATRICES, layers)?,
                add(
                    size_of::<ReplaySalts>(),
                    device::retained_stream_host_backing(),
                )?,
            )?,
            mul(3 * ROUNDS, bytes::<[Val; 4]>(1 << g.cap_height)?)?,
            bytes::<u64>(g.extension_degree)?,
            // Both old/new backing in the two temporary opening planners.
            bytes::<usize>(4 + 8 + 7 + 14)?,
        ])?;
        let opened_value_descriptor_bytes =
            opened_value_descriptor_host_bound::<Challenge>(1, 0, 16)
                .map_err(|_| Error::ResourceLimit)?;
        let raw_proof_inline_bytes = size_of::<Proof>();
        // Summation instead of a phase maximum deliberately keeps all source
        // owners charged across moves, including scratch no longer live when
        // the final proof returns. This also bounds the producer's raw proof.
        let opening_and_query_host_bytes = sum(&[
            round_point_backing_bytes,
            full_opened_value_backing_bytes,
            hidden_tail_backing_bytes,
            opening_construction_bytes,
            initial_query_bytes,
            fri_query_bytes,
            fri_assembly_bytes,
            retained_metadata_bytes,
            opened_value_descriptor_bytes,
            raw_proof_inline_bytes,
        ])?;
        let raw_proof_capacity_ceiling_bytes = opening_and_query_host_bytes;
        Ok(Self {
            round_point_backing_bytes,
            full_opened_value_backing_bytes,
            hidden_tail_backing_bytes,
            opening_construction_bytes,
            initial_query_bytes,
            fri_query_bytes,
            fri_assembly_bytes,
            retained_metadata_bytes,
            opened_value_descriptor_bytes,
            raw_proof_inline_bytes,
            opening_and_query_host_bytes,
            raw_proof_capacity_ceiling_bytes,
            maximum_fri_layer_count: layers,
            maximum_fri_row_capacity: arity,
            requires_device_only_trees_and_randomness: true,
        })
    }

    pub fn required_host_bytes(self) -> usize {
        self.opening_and_query_host_bytes
    }
    pub fn raw_proof_capacity_ceiling_bytes(self) -> usize {
        self.raw_proof_capacity_ceiling_bytes
    }
}
