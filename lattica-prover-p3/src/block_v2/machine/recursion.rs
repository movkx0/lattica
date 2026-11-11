//! Version-separated recursion architecture prototype.
//!
//! The caller supplies a trusted verifier program, never a program selected by
//! a proof. Witnesses cannot change instructions, wire addresses, multiplicities
//! or child keys. This is an execution backend, not a RingCT acceptance API.
//! Production promotion requires the complete recursive verifier and GPU gates.

mod air;
mod geometry;
#[cfg(feature = "gpu")]
mod gpu;
mod layout;
mod parent;
mod prepared;
mod swaps;
mod typed;
pub use typed::{TypedVerifierPlan, TypedVerifierStats};
#[cfg(test)]
mod tests;

use super::{
    program::{Op, Val},
    ExecutionError, Program,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use sha3::{Digest, Sha3_256};
use std::sync::Arc;

pub use geometry::{ArchitectureGeometry, TableGeometry};
#[cfg(feature = "gpu")]
pub use gpu::{
    CachedGpuRecursionTemplate, GpuProofMeasurement, GpuRecursionCache, GpuRecursionCacheStats,
    GpuTemplateLimits, PreparedGpuRecursionTemplate,
};
pub use parent::{CompiledRecursionVerifier, RecursionVerifier};
pub use prepared::{PreparedRecursionTemplate, RecursionExecutionProof};

pub const VERSION: u64 = 5;
const PADDING: u32 = u32::MAX;

/// One immutable circuit. Preparation is independent of all proof witnesses.
/// The identity includes the trusted registry, exact program and backend
/// version. Equal geometry alone never authorizes a cache hit.
#[derive(Clone, Debug)]
pub struct RecursionTemplate {
    program: Arc<Program>,
    rows: [Arc<[u32]>; 3],
    id: [u8; 32],
    typed: TypedVerifierPlan,
    tables: Arc<[layout::TableSpan]>,
}

impl RecursionTemplate {
    /// Lowering has a 2 GiB admission bound. Its operation bound also limits
    /// row indices to 128 MiB; reserve 256 MiB for those and layout scratch.
    /// The source program and returned proof inputs are charged separately.
    pub const CONSTRUCTION_WORKSPACE_BYTES: usize = typed::PLANNING_BYTES + (256 << 20);

    pub fn new(program: Arc<Program>, trusted_registry: [u8; 32]) -> Result<Self, String> {
        let typed = TypedVerifierPlan::compile(&program)?;
        let mut hasher = Sha3_256::new();
        hasher.update(b"lattica-recursion-multi-table-prototype-v5");
        hasher.update(b"typed-pcs-reduction-transition-v3");
        hasher.update(b"authenticated-merkle-swap-poseidon-v1");
        hasher.update(b"hash-resident-private-input-providers-v1");
        hasher.update(b"direct-sbox-two-lane-hash-v1");
        hasher.update(b"global-quotient-budget-layout-v1");
        hasher.update(VERSION.to_le_bytes());
        hasher.update(trusted_registry);
        hasher.update(crate::block_v2::profile::CANDIDATE_PROFILE_ID);
        for v in [
            air::SCALAR_LANES,
            air::CUBIC_LANES,
            air::HASH_LANES,
            typed::TERMS_PER_ROW,
            air::HASH_TABLE_MAX_ROWS,
            air::SCALAR_TABLE_MAX_ROWS,
            crate::block_v2::profile::LOG_BLOWUP,
            crate::block_v2::profile::NUM_QUERIES,
            crate::block_v2::profile::CAP_HEIGHT,
            crate::block_v2::profile::NUM_RANDOM_CODEWORDS,
            crate::block_v2::profile::QUERY_POW_BITS,
        ] {
            hasher.update((v as u64).to_le_bytes());
        }
        program.visit_manifest_fields(&mut |v| {
            hasher.update(v.to_le_bytes());
            Ok(())
        })?;
        let mut counts = [0usize; 3];
        let mut scalar_counts = [0usize; 8];
        for (index, op) in program.operations.iter().enumerate() {
            if typed.removed[index] {
                continue;
            }
            counts[table(op)] += 1;
            if table(op) == 0 {
                scalar_counts[op.code()] += 1;
            }
        }
        // One opcode per arithmetic row; lane activity remains authenticated.
        // Padding is an explicit sentinel, never an input/witness instruction.
        counts[0] = scalar_counts
            .iter()
            .map(|n| n.div_ceil(air::SCALAR_LANES) * air::SCALAR_LANES)
            .sum();
        let mut rows: [Vec<u32>; 3] = Default::default();
        for (rows, count) in rows.iter_mut().zip(counts) {
            rows.try_reserve_exact(count)
                .map_err(|_| "template index allocation")?;
        }
        rows[0].resize(counts[0], PADDING);
        let mut next = [0usize; 8];
        for code in 1..8 {
            next[code] = next[code - 1]
                + scalar_counts[code - 1].div_ceil(air::SCALAR_LANES) * air::SCALAR_LANES;
        }
        for (i, op) in program.operations.iter().enumerate() {
            if typed.removed[i] {
                continue;
            }
            let index = u32::try_from(i).map_err(|_| "template operation index")?;
            if index == PADDING {
                return Err("template operation index collision".into());
            }
            if table(op) == 0 {
                rows[0][next[op.code()]] = index;
                next[op.code()] += 1;
            } else {
                rows[table(op)].push(index);
            }
        }
        let mut template = Self {
            program,
            rows: rows.map(Arc::from),
            id: hasher.finalize().into(),
            typed,
            tables: Arc::from([]),
        };
        template.tables = Arc::from(layout::plan(&template)?);
        Ok(template)
    }

    pub fn typed_plan(&self) -> &TypedVerifierPlan {
        &self.typed
    }

    pub fn identity(&self) -> [u8; 32] {
        self.id
    }

    /// A prepared CPU job must carry the very source used to build its template.
    pub fn matches_program(&self, program: &Arc<Program>) -> bool {
        Arc::ptr_eq(&self.program, program)
    }

    pub fn geometry(&self) -> Result<ArchitectureGeometry, String> {
        geometry::analyze(self)
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn preprocessing_table(&self, index: usize) -> Result<RowMajorMatrix<Val>, String> {
        use p3_air::BaseAir;
        self.airs()
            .get(index)
            .ok_or("recursion preprocessing table index")?
            .preprocessed_trace()
            .ok_or_else(|| "recursion preprocessing table".into())
    }

    /// Separate witness filling from immutable circuit construction. Each call
    /// allocates fresh values; no private input or randomizer enters a cache.
    fn traces(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<Vec<RowMajorMatrix<Val>>, ExecutionError> {
        let values = self.program.evaluate(public, witness)?;
        Ok(self
            .airs()
            .iter()
            .map(|air| air::trace(air, &values))
            .collect())
    }

    fn active_rows(&self, kind: usize) -> usize {
        let (count, lanes) = match kind {
            0 => (self.rows[0].len(), air::SCALAR_LANES),
            1 => (self.rows[1].len(), air::CUBIC_LANES),
            2 => (self.rows[2].len(), air::HASH_LANES),
            3 => (1, 1),
            4 => (self.typed.groups.len(), 1),
            _ => unreachable!(),
        };
        count.div_ceil(lanes)
    }

    fn airs(&self) -> Vec<air::TableAir> {
        let shared = Arc::new(self.clone());
        self.tables
            .iter()
            .map(|span| air::TableAir {
                template: Arc::clone(&shared),
                kind: span.kind,
                first_row: span.first_row,
                active_rows: span.active_rows,
                height: span.height,
            })
            .collect()
    }
}

/// At most two tables per kind. Split only when the exact power-of-two
/// prefix plus a padded tail removes rows; never pad a tiny overflow to a
/// second full-height table. The trusted template fixes both spans.
fn partition_rows(rows: usize) -> Vec<(usize, usize, usize)> {
    let height = rows.max(8).next_power_of_two();
    let prefix = height / 2;
    let tail = rows.saturating_sub(prefix);
    let tail_height = tail.max(8).next_power_of_two();
    if rows > prefix && prefix >= 8 && prefix + tail_height < height {
        vec![(0, prefix, prefix), (prefix, tail, tail_height)]
    } else {
        vec![(0, rows, height)]
    }
}

fn table(op: &Op) -> usize {
    match op {
        Op::Poseidon { .. } => 2,
        Op::CubicMul { .. } | Op::CubicInverse { .. } => 1,
        _ => 0,
    }
}
