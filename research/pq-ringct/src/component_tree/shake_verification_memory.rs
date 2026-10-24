//! Admission for the independent CPU verifier of a native serial SHAKE child.
//!
//! This is an opt-in prerequisite; existing factory verification and paired
//! orchestration are unchanged. The caller must reserve proof backing before
//! producing it and use the shared ledger accounting for every other live
//! owner. This module reserves a separate 64 MiB component
//! before configuration construction or numerical verification. Borrowed inputs
//! cannot change while admitted, and the reservation is released on every exit.
//!
//! The ledger follows pinned p3 0.6.1 / Rust 1.96 allocation sites, as in
//! `block_v2/wallet_verification/scratch.rs`. It sums allocation requests,
//! including replacement buffers and every Rayon interpolation accumulator.
//! It is not RSS: thread pools/stacks, allocator overhead, OS entropy internals,
//! callbacks, caller reports and the enclosing worker lifetimes are separate.

use crate::execution::retained_resources::{
    Bytes, Category, Ledger as ResourceLedger, Requirements, Reservation,
};
use crate::shake_air::{self, lane::batch::ShakeSegmentAir};
use core::mem::size_of;
use lattica_prover_p3::block_v2::profile::{self, Config, CpuVerificationConfigPlan};
use p3_air::BaseAir;
use p3_field::{BasedVectorSpace, ExtensionField, TwoAdicField};
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::Dimensions;
use p3_symmetric::MerkleCap;
use p3_uni_stark::{Domain, Proof};

type Ext = profile::Challenge;
type Packed = <Ext as ExtensionField<Val>>::ExtensionPacking;
type Cap = MerkleCap<Val, [Val; 4]>;
type Point = (Ext, Vec<Ext>);
type Matrix = (Domain<Config>, Vec<Point>);
type Round = (Cap, Vec<Matrix>);
type SortedDimension = (usize, &'static Dimensions);

pub const COMPONENT_BYTES: usize = 64 << 20;
pub const PROOF_BACKING_CEILING: usize = 64 << 20;
const MAX_HEIGHT: usize = 1 << 24;
const QUOTIENT: usize = 16;
const PERIOD: usize = 128;
const PERIODIC: usize = 42;
const PUBLIC: usize = 216;
const GEOMETRY: &str = "native SHAKE verification unsupported geometry";
const OVERFLOW: &str = "native SHAKE verification size overflow";
const ENVELOPE: &str = "native SHAKE verification proof envelope";
const CAPACITY: &str = "native SHAKE verification proof capacity";
const BUDGET: &str = "native SHAKE verification component allowance";
type Result<T> = core::result::Result<T, &'static str>;

fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(OVERFLOW)
}
fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(OVERFLOW)
}
fn require(ok: bool, message: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}

#[derive(Clone, Copy, Default)]
struct Ledger(usize);
impl Ledger {
    fn bytes(&mut self, bytes: usize) -> Result<()> {
        self.0 = add(self.0, bytes)?;
        Ok(())
    }
    fn exact<T>(&mut self, count: usize) -> Result<()> {
        self.bytes(mul(count, size_of::<T>())?)
    }
    // Rust 1.96 RawVec growth, including replaced allocations and minimum
    // capacities. This also covers Result/collect without a useful lower hint.
    fn growing<T>(&mut self, count: usize) -> Result<()> {
        if count != 0 {
            self.exact::<T>(mul(4, count.max(8))?)?;
        }
        Ok(())
    }
    fn repeat(&mut self, other: Self, count: usize) -> Result<()> {
        self.bytes(mul(other.0, count)?)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Shape {
    width: usize,
    height: usize,
    degree: usize,
    log_lde: usize,
}
impl Shape {
    fn new(air: &ShakeSegmentAir) -> Result<Self> {
        require(
            cfg!(all(not(debug_assertions), target_arch = "x86_64")),
            GEOMETRY,
        )?;
        require(
            size_of::<usize>() == 8
                && size_of::<Val>() == 8
                && size_of::<Ext>() == 24
                // The pinned coset stores shift, cached shift_inverse and log_size.
                && size_of::<Domain<Config>>() == 24
                && size_of::<Cap>() == 24
                && size_of::<Point>() == 48
                && size_of::<Matrix>() == 48
                && size_of::<Round>() == 48
                && size_of::<SortedDimension>() == 16
                && size_of::<Packed>() <= 192,
            GEOMETRY,
        )?;
        let fri = profile::fri(());
        require(
            profile::LOG_BLOWUP == 4
                && profile::NUM_QUERIES == 128
                && profile::CAP_HEIGHT == 6
                && profile::NUM_RANDOM_CODEWORDS == 4
                && profile::QUERY_POW_BITS == 16
                && <Ext as BasedVectorSpace<Val>>::DIMENSION == 3
                && fri.log_blowup == 4
                && fri.num_queries == 128
                && fri.max_log_arity == 1
                && fri.log_final_poly_len == 0
                && fri.commit_proof_of_work_bits == 0
                && fri.query_proof_of_work_bits == 16,
            GEOMETRY,
        )?;
        require(
            shake_air::lane::HEIGHT == 4096
                && shake_air::lane::WIDTH == 517
                && shake_air::lane::batch::WIDTH == 518
                && shake_air::lane::SCHEDULE_PERIOD == PERIOD
                && shake_air::lane::PERIODIC_COLUMNS == PERIODIC
                && shake_air::PUBLIC_VALUES == PUBLIC
                && air.num_periodic_columns() == PERIODIC
                && air.num_public_values() == PUBLIC
                && air.max_constraint_degree() == Some(7)
                && air.preprocessed_width() == 0,
            GEOMETRY,
        )?;
        // Single AIR fields are public, so recheck its constructor invariants.
        // Batch fields are private and available only through checked constructors.
        if let ShakeSegmentAir::Single(single) = air {
            shake_air::lane::LaneShakeAir::new(single.descriptor, single.permutation)
                .map_err(|_| GEOMETRY)?;
        }
        let height = air.height();
        let count = air.permutations();
        require(
            count.is_power_of_two()
                && height == mul(4096, count)?
                && height <= MAX_HEIGHT
                && height.is_power_of_two()
                && matches!(air.width(), 517 | 518),
            GEOMETRY,
        )?;
        let degree = add(height.ilog2() as usize, 1)?;
        let log_lde = add(degree, 4)?;
        require(degree <= 25 && log_lde <= Val::TWO_ADICITY, GEOMETRY)?;
        Ok(Self {
            width: air.width(),
            height,
            degree,
            log_lde,
        })
    }
    fn roots(self, log: usize) -> usize {
        1usize << log.min(6)
    }
    fn path(self, log: usize) -> usize {
        log.saturating_sub(6)
    }
}

/// All fields are source-derived allocation-request bounds, never observed RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds {
    pub configuration_bytes: usize,
    pub uni_bytes: usize,
    pub transcript_bytes: usize,
    pub air_bytes: usize,
    pub fri_bytes: usize,
    pub periodic_construction_bytes: usize,
    pub periodic_evaluation_bytes: usize,
    pub diagnostic_bytes: usize,
    pub cumulative_requested_bytes: usize,
    pub component_reservation_bytes: usize,
}

// Each native MMCS batch has one height. Charge both stable sorts and their
// scratch. Remaining-height iterators are empty before the arity walk clones.
fn tree(heap: &mut Ledger, matrices: usize, log_height: usize) -> Result<()> {
    for _ in 0..2 {
        heap.growing::<SortedDimension>(matrices)?;
        heap.exact::<SortedDimension>(matrices)?;
    }
    heap.growing::<usize>(log_height)
}
fn hiding_tree(heap: &mut Ledger, matrices: usize, width: usize, log: usize) -> Result<()> {
    heap.growing::<Vec<Val>>(matrices)?;
    let mut row = Ledger::default();
    row.growing::<Val>(add(width, 4)?)?;
    heap.repeat(row, matrices)?;
    heap.growing::<Dimensions>(matrices)?;
    tree(heap, matrices, log)
}

fn periodic_evaluation() -> Result<usize> {
    let mut heap = Ledger::default();
    heap.exact::<Val>(PERIOD)?; // Domain::evaluate_polynomial_at column clone.
    heap.growing::<Val>(PERIOD)?; // Materialized coset.
    for _ in 0..3 {
        heap.exact::<Ext>(PERIOD)?;
    } // differences/inverses/weights
      // Dense width-one rows borrow storage. Pinned Rayon fold(identity).reduce
      // has at most two identities per nonempty indexed leaf, at most 128 leaves.
    heap.exact::<Packed>(mul(2, PERIOD)?)?;
    heap.growing::<Ext>(1)?; // Result, also covers on-coset early return.
    Ok(heap.0)
}

impl Bounds {
    fn new(shape: Shape, configuration_bytes: usize) -> Result<Self> {
        let matrices = [1, 1, QUOTIENT];
        let widths = [3, shape.width, 3];
        let mut uni = Ledger::default();
        for _ in 0..2 {
            uni.growing::<Domain<Config>>(QUOTIENT)?;
        }
        uni.growing::<usize>(shape.width)?; // default main_next_row_columns
        uni.growing::<Round>(3)?; // random round, temporary vec, extension
        for (round, points) in [1, 2, 1].into_iter().enumerate() {
            uni.growing::<Matrix>(matrices[round])?;
            let mut matrix = Ledger::default();
            matrix.growing::<Point>(points)?; // local then push(next)
            for _ in 0..points {
                matrix.exact::<Ext>(widths[round])?;
                // Hiding appends four values; count old and replacement buffers.
                matrix.exact::<Ext>(mul(2, add(widths[round], 4)?)?)?;
            }
            uni.repeat(matrix, matrices[round])?;
        }
        uni.exact::<[Val; 4]>(mul(6, shape.roots(shape.log_lde))?)?;
        uni.growing::<Ext>(QUOTIENT)?; // quotient recomposition coefficients
        uni.growing::<Ext>(PERIODIC)?;
        let mut transcript = Ledger::default();
        transcript.exact::<[Val; 8]>(8)?;
        transcript.exact::<Val>(22)?;
        transcript.growing::<Val>(4)?;
        transcript.growing::<Val>(4)?;
        let mut air = Ledger::default();
        air.exact::<Val>(PUBLIC)?;
        air.growing::<Ext>(PERIODIC)?;
        air.growing::<Ext>(5)?;
        air.growing::<(Ext, Ext, Ext, Ext)>(4)?;
        // SHAKE local/next rows and Poseidon2 round constants are borrowed/inline.
        let mut fri = Ledger::default();
        let mut arities = Ledger::default();
        arities.growing::<usize>(shape.degree)?;
        fri.repeat(arities, 128)?;
        fri.growing::<Ext>(shape.degree)?;
        for layer in 0..shape.degree {
            fri.exact::<[Val; 4]>(shape.roots(shape.log_lde - layer - 1))?;
        }
        let mut query = Ledger::default();
        // All three rounds have 2^degree domains after quotient hiding. One
        // reduced-opening BTree leaf: 11 slots plus a conservative 8-word header.
        query.bytes(add(
            8 * size_of::<usize>(),
            mul(11, add(size_of::<usize>(), size_of::<(Ext, Ext)>())?)?,
        )?)?;
        query.growing::<(usize, Ext)>(1)?;
        for round in 0..3 {
            query.growing::<usize>(matrices[round])?;
            query.growing::<Dimensions>(matrices[round])?;
            hiding_tree(
                &mut query,
                matrices[round],
                add(widths[round], 4)?,
                shape.log_lde,
            )?;
        }
        for layer in 0..shape.degree {
            let log = shape.log_lde - layer - 1;
            for _ in 0..3 {
                query.exact::<Ext>(2)?;
            } // reconstructed row+two clones
            query.growing::<Val>(6)?; // Extension-MMCS flattening
            query.growing::<Vec<Val>>(1)?;
            query.growing::<Dimensions>(1)?;
            hiding_tree(&mut query, 1, 6, log)?;
            query.growing::<Ext>(2)?; // fold-row evaluations
            query.growing::<Val>(2)?; // binary coset
            query.growing::<Ext>(2)?; // Lagrange denominators
            query.exact::<Ext>(2)?; // single-chunk inverse output
        }
        fri.repeat(query, 128)?;
        let mut periodic = Ledger::default();
        periodic.exact::<Val>(mul(PERIODIC, PERIOD)?)?;
        periodic.growing::<Vec<Val>>(PERIODIC)?;
        let periodic_evaluation_bytes = periodic_evaluation()?;
        // Formatting writes into an inline fixed-size result. It allocates no
        // heap and cannot leave a String alive after temporary admission ends.
        // Caller result/stack storage is outside this requested-heap ledger.
        let diagnostic = Ledger::default();
        let mut total = Ledger::default();
        for bytes in [
            configuration_bytes,
            uni.0,
            transcript.0,
            air.0,
            fri.0,
            periodic.0,
            diagnostic.0,
        ] {
            total.bytes(bytes)?;
        }
        // Sequential columns: summing all requests is deliberately stronger
        // than a peak-lifetime estimate, including every Rayon worker request.
        total.bytes(mul(PERIODIC, periodic_evaluation_bytes)?)?;
        require(total.0 <= COMPONENT_BYTES, BUDGET)?;
        Ok(Self {
            configuration_bytes,
            uni_bytes: uni.0,
            transcript_bytes: transcript.0,
            air_bytes: air.0,
            fri_bytes: fri.0,
            periodic_construction_bytes: periodic.0,
            periodic_evaluation_bytes,
            diagnostic_bytes: diagnostic.0,
            cumulative_requested_bytes: total.0,
            component_reservation_bytes: COMPONENT_BYTES,
        })
    }
}

/// Public-shape planner; construction allocates nothing and starts no proof.
#[derive(Clone, Copy, Debug)]
pub struct Plan {
    shape: Shape,
    configuration: CpuVerificationConfigPlan,
    bounds: Bounds,
}
impl Plan {
    pub fn new(air: &ShakeSegmentAir) -> Result<Self> {
        let shape = Shape::new(air)?;
        let configuration = CpuVerificationConfigPlan::new()?;
        let bounds = Bounds::new(shape, configuration.requested_bytes())?;
        Ok(Self {
            shape,
            configuration,
            bounds,
        })
    }
    pub fn bounds(self) -> Bounds {
        self.bounds
    }

    /// Inspect already-owned input capacities without allocating. This is not
    /// a retroactive proof reservation: the producer must have admitted backing
    /// before generation/decoding, using its own ownership-following budget.
    pub fn proof_backing_bytes(
        self,
        proof: &Proof<Config>,
        public: &Vec<Val>,
        already_reserved: usize,
    ) -> Result<usize> {
        require(already_reserved <= PROOF_BACKING_CEILING, CAPACITY)?;
        self.shape.audit(proof, public, already_reserved)
    }

    /// The enclosing producer must bind the NativeProof reservation to this
    /// proof's storage from its creation through destruction. The shared
    /// ledger's generic category token proves capacity and ledger identity;
    /// this verifier alone cannot establish that producer ownership mapping.
    pub fn admit<'p>(
        self,
        air: &'p ShakeSegmentAir,
        proof: &'p Proof<Config>,
        public: &'p Vec<Val>,
        proof_reservation: &'p Reservation,
        ledger: &ResourceLedger,
    ) -> Result<AdmittedVerification<'p>> {
        let proof_backing_bytes =
            self.audit_inputs(air, proof, public, proof_reservation, ledger)?;
        let reservation = ledger
            .admit_phase(Self::component_requirement())
            .map_err(|_| BUDGET)?;
        Ok(AdmittedVerification {
            plan: self,
            air,
            proof,
            public,
            proof_backing_bytes,
            _proof_reservation: proof_reservation,
            _reservation: reservation,
        })
    }

    pub fn component_requirement() -> Requirements {
        Requirements::single(
            Category::IndependentVerifier,
            Bytes {
                host: COMPONENT_BYTES as u64,
                device: 0,
            },
        )
    }

    /// Consume exactly the verifier component split from a whole-phase
    /// admission. This does not reserve again or confer native dispatch rights.
    /// Wrong-ledger, mixed-category and incorrect-size tokens are refused.
    pub fn admit_pre_reserved<'p>(
        self,
        air: &'p ShakeSegmentAir,
        proof: &'p Proof<Config>,
        public: &'p Vec<Val>,
        proof_reservation: &'p Reservation,
        reservation: Reservation,
        ledger: &ResourceLedger,
    ) -> Result<AdmittedVerification<'p>> {
        require(reservation.belongs_to(ledger), BUDGET)?;
        require(
            reservation.requirements() == Self::component_requirement(),
            BUDGET,
        )?;
        let proof_backing_bytes =
            self.audit_inputs(air, proof, public, proof_reservation, ledger)?;
        Ok(AdmittedVerification {
            plan: self,
            air,
            proof,
            public,
            proof_backing_bytes,
            _proof_reservation: proof_reservation,
            _reservation: reservation,
        })
    }

    fn audit_inputs(
        self,
        air: &ShakeSegmentAir,
        proof: &Proof<Config>,
        public: &Vec<Val>,
        proof_reservation: &Reservation,
        ledger: &ResourceLedger,
    ) -> Result<usize> {
        require(Shape::new(air)? == self.shape, GEOMETRY)?;
        let allowance = ledger.snapshot().allowance;
        require(
            allowance.host <= 32u64 << 30 && allowance.device <= 8u64 << 30,
            BUDGET,
        )?;
        require(proof_reservation.belongs_to(ledger), BUDGET)?;
        let already_reserved_proof_bytes = usize::try_from(
            proof_reservation
                .requirements()
                .get(Category::NativeProof)
                .host
                .min(PROOF_BACKING_CEILING as u64),
        )
        .map_err(|_| OVERFLOW)?;
        self.proof_backing_bytes(proof, public, already_reserved_proof_bytes)
    }
}

/// Only Plan's checked admission methods can issue this token. Its borrows pin
/// every audited input;
/// its non-clone reservation follows moves and releases on success/error/drop.
pub struct AdmittedVerification<'p> {
    plan: Plan,
    air: &'p ShakeSegmentAir,
    proof: &'p Proof<Config>,
    public: &'p Vec<Val>,
    proof_backing_bytes: usize,
    _proof_reservation: &'p Reservation,
    // Last field: every owned payload must be destroyed before releasing it.
    _reservation: Reservation,
}
#[derive(Debug)]
pub enum VerificationFailure {
    Configuration(&'static str),
    InvalidProof(Diagnostic),
}

/// Bounded inline diagnostic; no heap owner escapes the temporary reservation.
pub struct Diagnostic {
    bytes: [u8; 1024],
    len: usize,
}
impl Diagnostic {
    fn from_error(error: impl core::fmt::Debug) -> Self {
        use core::fmt::Write;
        let mut result = Self {
            bytes: [0; 1024],
            len: 0,
        };
        if write!(&mut result, "{error:?}").is_err() {
            result.len = 0;
            result
                .write_str("native SHAKE verifier diagnostic exceeded fixed capacity")
                .expect("fixed diagnostic fits");
        }
        result
    }
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).expect("whole UTF-8 write invariant")
    }
}
impl core::fmt::Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> core::fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(core::fmt::Error)?;
        if end > self.bytes.len() {
            return Err(core::fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
impl core::fmt::Debug for Diagnostic {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationReceipt {
    pub proof_backing_bytes: usize,
    pub bounds: Bounds,
}
impl AdmittedVerification<'_> {
    pub fn verify(self) -> core::result::Result<VerificationReceipt, VerificationFailure> {
        let config = self
            .plan
            .configuration
            .make_config(self.plan.bounds.configuration_bytes)
            .map_err(VerificationFailure::Configuration)?;
        p3_uni_stark::verify(&config, self.air, self.proof, self.public)
            .map_err(|error| VerificationFailure::InvalidProof(Diagnostic::from_error(error)))?;
        Ok(VerificationReceipt {
            proof_backing_bytes: self.proof_backing_bytes,
            bounds: self.plan.bounds,
        })
    }
}

struct Backing {
    bytes: usize,
    limit: usize,
}
impl Backing {
    #[cfg_attr(test, track_caller)]
    fn capacity<T>(&mut self, actual: usize, maximum: usize) -> Result<()> {
        let cap = if maximum == 0 {
            0
        } else {
            mul(maximum, 2)?.max(4)
        };
        #[cfg(test)]
        if actual > cap {
            eprintln!(
                "native_verifier_capacity site={} element={} actual={} producer_length={} capacity_limit={}",
                core::panic::Location::caller(), core::any::type_name::<T>(), actual, maximum, cap
            );
        }
        require(actual <= cap, CAPACITY)?;
        self.bytes = add(self.bytes, mul(actual, size_of::<T>())?)?;
        #[cfg(test)]
        if self.bytes > self.limit {
            eprintln!(
                "native_verifier_backing site={} requested={} limit={}",
                core::panic::Location::caller(),
                self.bytes,
                self.limit
            );
        }
        require(self.bytes <= self.limit, CAPACITY)
    }
    #[cfg_attr(test, track_caller)]
    fn vector<T>(&mut self, values: &Vec<T>, expected: usize) -> Result<()> {
        self.vector_after_shrink(values, expected, expected)
    }
    /// `drain`/`truncate` preserve the producer's original backing. Keep the
    /// logical envelope exact while bounding that particular source allocation.
    #[cfg_attr(test, track_caller)]
    fn vector_after_shrink<T>(
        &mut self,
        values: &Vec<T>,
        expected: usize,
        producer_length: usize,
    ) -> Result<()> {
        require(values.len() == expected, ENVELOPE)?;
        require(producer_length >= expected, GEOMETRY)?;
        self.capacity::<T>(values.capacity(), producer_length)
    }
    #[cfg_attr(test, track_caller)]
    fn cap(&mut self, cap: &Cap, roots: usize) -> Result<()> {
        require(cap.roots().len() == roots, ENVELOPE)?;
        self.capacity::<[Val; 4]>(cap.root_capacity(), roots)
    }
    #[cfg_attr(test, track_caller)]
    fn rows<T>(&mut self, rows: &Vec<Vec<T>>, count: usize, width: usize) -> Result<()> {
        self.vector(rows, count)?;
        for row in rows {
            self.vector(row, width)?;
        }
        Ok(())
    }
    #[cfg_attr(test, track_caller)]
    fn authentication(
        &mut self,
        auth: &(Vec<Vec<Val>>, Vec<[Val; 4]>),
        matrices: usize,
        siblings: usize,
    ) -> Result<()> {
        self.rows(&auth.0, matrices, 4)?;
        self.vector(&auth.1, siblings)
    }
}
impl Shape {
    fn audit(self, proof: &Proof<Config>, public: &Vec<Val>, limit: usize) -> Result<usize> {
        require(proof.degree_bits == self.degree, ENVELOPE)?;
        let mut heap = Backing {
            bytes: add(size_of::<Proof<Config>>(), size_of::<Vec<Val>>())?,
            limit,
        };
        heap.vector(public, PUBLIC)?;
        heap.cap(&proof.commitments.trace, self.roots(self.log_lde))?;
        heap.cap(&proof.commitments.quotient_chunks, self.roots(self.log_lde))?;
        heap.cap(
            proof.commitments.random.as_ref().ok_or(ENVELOPE)?,
            self.roots(self.log_lde),
        )?;
        let opened = &proof.opened_values;
        heap.vector(&opened.trace_local, self.width)?;
        heap.vector(opened.trace_next.as_ref().ok_or(ENVELOPE)?, self.width)?;
        require(
            opened.preprocessed_local.is_none() && opened.preprocessed_next.is_none(),
            ENVELOPE,
        )?;
        // HidingPcs::open drains four hiding values from these seven-element
        // openings, retaining their original allocation with logical length 3.
        heap.vector_after_shrink(opened.random.as_ref().ok_or(ENVELOPE)?, 3, 7)?;
        heap.vector(&opened.quotient_chunks, QUOTIENT)?;
        for chunk in &opened.quotient_chunks {
            heap.vector_after_shrink(chunk, 3, 7)?;
        }
        let (hiding, fri) = &proof.opening_proof;
        let matrices = [1, 1, QUOTIENT];
        let widths = [7, add(self.width, 4)?, 7];
        heap.vector(hiding, 3)?;
        for (round, values) in hiding.iter().enumerate() {
            heap.vector(values, matrices[round])?;
            for points in values {
                heap.rows(points, if round == 1 { 2 } else { 1 }, 4)?;
            }
        }
        heap.vector(&fri.commit_phase_commits, self.degree)?;
        for (layer, cap) in fri.commit_phase_commits.iter().enumerate() {
            heap.cap(cap, self.roots(self.log_lde - layer - 1))?;
        }
        heap.vector(&fri.commit_pow_witnesses, self.degree)?;
        // FRI truncates its final blowup-sized evaluation vector before IDFT;
        // the pinned degree-zero polynomial can retain all 16 element slots.
        heap.vector_after_shrink(&fri.final_poly, 1, 1 << profile::LOG_BLOWUP)?;
        heap.vector(&fri.query_proofs, 128)?;
        for query in &fri.query_proofs {
            heap.vector(&query.input_proof, 3)?;
            for (round, opening) in query.input_proof.iter().enumerate() {
                heap.rows(&opening.opened_values, matrices[round], widths[round])?;
                heap.authentication(
                    &opening.opening_proof,
                    matrices[round],
                    self.path(self.log_lde),
                )?;
            }
            heap.vector(&query.commit_phase_openings, self.degree)?;
            for (layer, opening) in query.commit_phase_openings.iter().enumerate() {
                require(opening.log_arity == 1, ENVELOPE)?;
                heap.vector(&opening.sibling_values, 1)?;
                heap.authentication(
                    &opening.opening_proof,
                    1,
                    self.path(self.log_lde - layer - 1),
                )?;
            }
        }
        Ok(heap.bytes)
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    struct TestBudget {
        ledger: ResourceLedger,
        proof: Reservation,
    }
    impl TestBudget {
        fn new(temporary: usize) -> Result<Self> {
            use crate::execution::retained_resources::WorkerAllowance;
            let ledger = ResourceLedger::new(WorkerAllowance {
                host: (PROOF_BACKING_CEILING + temporary) as u64,
                device: 0,
            });
            let proof = ledger
                .reserve(
                    Category::NativeProof,
                    Bytes {
                        host: PROOF_BACKING_CEILING as u64,
                        device: 0,
                    },
                )
                .map_err(|_| BUDGET)?;
            Ok(Self { ledger, proof })
        }
        fn reserved_bytes(&self) -> usize {
            self.ledger.snapshot().categories[Category::IndependentVerifier as usize]
                .current
                .host as usize
        }
    }

    fn single() -> ShakeSegmentAir {
        ShakeSegmentAir::Single(
            shake_air::lane::LaneShakeAir::new(
                shake_air::Descriptor {
                    input_len: 0,
                    output_len: 32,
                },
                0,
            )
            .unwrap(),
        )
    }
    fn batch(count: usize) -> ShakeSegmentAir {
        ShakeSegmentAir::Batch(
            shake_air::lane::batch::BatchShakeAir::full_absorb(
                shake_air::Descriptor {
                    input_len: count * shake_air::RATE,
                    output_len: 32,
                },
                0,
                count,
            )
            .unwrap(),
        )
    }
    fn fixture(air: &ShakeSegmentAir) -> (Proof<Config>, Vec<Val>) {
        // Deliberately invalid cryptographic data, exact verifier geometry only.
        let proof =
            crate::component_tree::shape_diagnostic::invalid_native_template(air, air.height());
        (proof, vec![Val::ZERO; PUBLIC])
    }

    struct OversizedDiagnostic;
    impl core::fmt::Debug for OversizedDiagnostic {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            for _ in 0..1025 {
                formatter.write_str("é")?;
            }
            Ok(())
        }
    }

    fn check_inline_diagnostic_boundaries() {
        let normal = Diagnostic::from_error("native α");
        assert_eq!(normal.as_str(), "\"native α\"");
        let overflow = Diagnostic::from_error(OversizedDiagnostic);
        assert_eq!(
            overflow.as_str(),
            "native SHAKE verifier diagnostic exceeded fixed capacity"
        );
        assert!(normal.len <= normal.bytes.len());
        assert!(overflow.len <= overflow.bytes.len());
    }

    #[test]
    fn inline_diagnostics_preserve_utf8_and_bound_overflow() {
        check_inline_diagnostic_boundaries();
    }

    #[test]
    fn shape_plans_fit_the_fixed_component_and_reject_changed_air_metadata() {
        assert_eq!(
            [
                size_of::<Domain<Config>>(),
                size_of::<Cap>(),
                size_of::<Point>(),
                size_of::<Matrix>(),
                size_of::<Round>(),
                size_of::<SortedDimension>(),
            ],
            [24, 24, 48, 48, 48, 16],
            "pinned native verification layouts"
        );
        for air in core::iter::once(single()).chain((0..=12).map(|log| batch(1 << log))) {
            let plan = Plan::new(&air).unwrap();
            assert!(plan.bounds.cumulative_requested_bytes < COMPONENT_BYTES);
            assert_eq!(plan.bounds.component_reservation_bytes, COMPONENT_BYTES);
            assert_eq!(
                plan.bounds.configuration_bytes,
                CpuVerificationConfigPlan::new().unwrap().requested_bytes()
            );
            assert_eq!(plan.bounds.periodic_construction_bytes, 47_040);
            assert!(plan.bounds.periodic_evaluation_bytes <= 64_256);
        }
        let mut air = single();
        if let ShakeSegmentAir::Single(a) = &mut air {
            a.permutation = 1;
        }
        assert!(Plan::new(&air).is_err());
        assert_eq!(add(usize::MAX, 1), Err(OVERFLOW));
        assert_eq!(mul(usize::MAX, 2), Err(OVERFLOW));
        assert!(Ledger::default().growing::<Ext>(usize::MAX).is_err());
    }

    #[test]
    fn proof_backing_and_component_admission_have_independent_exact_boundaries() {
        let air = single();
        let plan = Plan::new(&air).unwrap();
        let (proof, public) = fixture(&air);
        let backing = plan
            .proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING)
            .unwrap();
        assert!(backing > size_of::<Proof<Config>>());
        assert_eq!(
            plan.proof_backing_bytes(&proof, &public, backing).unwrap(),
            backing
        );
        assert!(plan
            .proof_backing_bytes(&proof, &public, backing - 1)
            .is_err());
        let short = TestBudget::new(COMPONENT_BYTES - 1).unwrap();
        assert!(plan
            .admit(&air, &proof, &public, &short.proof, &short.ledger)
            .is_err());
        assert_eq!(short.reserved_bytes(), 0);
        let allowance = TestBudget::new(COMPONENT_BYTES).unwrap();
        let token = plan
            .admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
            .unwrap();
        assert_eq!(allowance.reserved_bytes(), COMPONENT_BYTES);
        assert!(plan
            .admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
            .is_err());
        let moved = token;
        drop(moved);
        assert_eq!(allowance.reserved_bytes(), 0);
        // Numeric failure must also release the reservation and never retain
        // configuration state. This fixture is not claimed as a real proof.
        let token = plan
            .admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
            .unwrap();
        assert!(matches!(
            token.verify(),
            Err(VerificationFailure::InvalidProof(_))
        ));
        assert_eq!(allowance.reserved_bytes(), 0);
    }

    #[test]
    fn pre_reserved_verifier_transfer_preserves_charge_through_failure_and_drop() {
        use crate::execution::retained_resources::WorkerAllowance;
        let ledger = ResourceLedger::new(WorkerAllowance {
            host: (PROOF_BACKING_CEILING + COMPONENT_BYTES) as u64,
            device: 0,
        });
        let native_requirement = Requirements::single(
            Category::NativeProof,
            Bytes {
                host: PROOF_BACKING_CEILING as u64,
                device: 0,
            },
        );
        let mut requirements = Plan::component_requirement();
        requirements
            .add(
                Category::NativeProof,
                native_requirement.get(Category::NativeProof),
            )
            .unwrap();
        let mut phase = ledger.admit_phase(requirements).unwrap();
        let proof_reservation = phase.split(native_requirement).unwrap();
        let verifier_reservation = phase.split(Plan::component_requirement()).unwrap();
        let before = ledger.snapshot();
        assert_eq!(ledger.remaining(), Bytes::ZERO);
        let air = single();
        let plan = Plan::new(&air).unwrap();
        let (proof, public) = fixture(&air);
        let token = plan
            .admit_pre_reserved(
                &air,
                &proof,
                &public,
                &proof_reservation,
                verifier_reservation,
                &ledger,
            )
            .unwrap();
        assert_eq!(ledger.snapshot(), before);
        let moved = token;
        drop(moved);
        assert_eq!(
            ledger.snapshot().current,
            native_requirement.get(Category::NativeProof)
        );
        let verifier_reservation = ledger.admit_phase(Plan::component_requirement()).unwrap();
        assert!(matches!(
            plan.admit_pre_reserved(
                &air,
                &proof,
                &public,
                &proof_reservation,
                verifier_reservation,
                &ledger,
            )
            .unwrap()
            .verify(),
            Err(VerificationFailure::InvalidProof(_))
        ));
        assert_eq!(
            ledger.snapshot().current,
            native_requirement.get(Category::NativeProof)
        );
        drop(proof);
        drop(public);
        drop(proof_reservation);
        drop(phase);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn pre_reserved_transfer_refuses_foreign_mixed_and_inexact_components() {
        let allowance = TestBudget::new(COMPONENT_BYTES + 1).unwrap();
        let foreign = TestBudget::new(COMPONENT_BYTES).unwrap();
        let air = single();
        let plan = Plan::new(&air).unwrap();
        let (mut proof, public) = fixture(&air);
        let foreign_component = foreign
            .ledger
            .admit_phase(Plan::component_requirement())
            .unwrap();
        assert_eq!(
            plan.admit_pre_reserved(
                &air,
                &proof,
                &public,
                &allowance.proof,
                foreign_component,
                &allowance.ledger
            )
            .err(),
            Some(BUDGET)
        );
        assert_eq!(foreign.reserved_bytes(), 0);
        assert_eq!(allowance.reserved_bytes(), 0);
        for bytes in [COMPONENT_BYTES - 1, COMPONENT_BYTES + 1] {
            let component = allowance
                .ledger
                .reserve(
                    Category::IndependentVerifier,
                    Bytes {
                        host: bytes as u64,
                        device: 0,
                    },
                )
                .unwrap();
            assert_eq!(
                plan.admit_pre_reserved(
                    &air,
                    &proof,
                    &public,
                    &allowance.proof,
                    component,
                    &allowance.ledger
                )
                .err(),
                Some(BUDGET)
            );
            assert_eq!(allowance.reserved_bytes(), 0);
        }
        let mut mixed = Plan::component_requirement();
        mixed
            .add(Category::Report, Bytes { host: 1, device: 0 })
            .unwrap();
        let component = allowance.ledger.admit_phase(mixed).unwrap();
        assert_eq!(
            plan.admit_pre_reserved(
                &air,
                &proof,
                &public,
                &allowance.proof,
                component,
                &allowance.ledger
            )
            .err(),
            Some(BUDGET)
        );
        assert_eq!(allowance.reserved_bytes(), 0);
        assert_eq!(
            allowance.ledger.snapshot().categories[Category::Report as usize].current,
            Bytes::ZERO
        );
        proof.degree_bits += 1;
        let component = allowance
            .ledger
            .admit_phase(Plan::component_requirement())
            .unwrap();
        assert_eq!(
            plan.admit_pre_reserved(
                &air,
                &proof,
                &public,
                &allowance.proof,
                component,
                &allowance.ledger
            )
            .err(),
            Some(ENVELOPE)
        );
        assert_eq!(allowance.reserved_bytes(), 0);
    }

    #[test]
    fn producer_drain_and_truncation_capacity_is_charged_without_relaxing_lengths() {
        fn with_capacity<T: Clone>(values: &[T], capacity: usize) -> Vec<T> {
            let mut retained = Vec::with_capacity(capacity);
            retained.extend_from_slice(values);
            retained
        }
        let air = single();
        let plan = Plan::new(&air).unwrap();
        let (mut proof, public) = fixture(&air);
        let original = plan
            .proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING)
            .unwrap();
        let random = proof.opened_values.random.as_mut().unwrap();
        *random = with_capacity(random, 7);
        for chunk in &mut proof.opened_values.quotient_chunks {
            *chunk = with_capacity(chunk, 7);
        }
        proof.opening_proof.1.final_poly = with_capacity(&proof.opening_proof.1.final_poly, 16);
        let retained = plan
            .proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING)
            .unwrap();
        assert!(retained > original);
        assert_eq!(
            plan.proof_backing_bytes(&proof, &public, retained - 1),
            Err(CAPACITY)
        );
        proof.opened_values.random.as_mut().unwrap().push(Ext::ZERO);
        assert_eq!(
            plan.proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING),
            Err(ENVELOPE)
        );
        proof.opened_values.random.as_mut().unwrap().pop();
        let random = proof.opened_values.random.as_mut().unwrap();
        *random = with_capacity(random, 15);
        assert_eq!(
            plan.proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING),
            Err(CAPACITY)
        );
        *proof.opened_values.random.as_mut().unwrap() = vec![Ext::ZERO; 3];
        proof.opening_proof.1.final_poly = with_capacity(&proof.opening_proof.1.final_poly, 33);
        assert_eq!(
            plan.proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING),
            Err(CAPACITY)
        );
    }

    #[test]
    fn malformed_or_overcapacity_proofs_are_refused_before_reserving() {
        let air = single();
        let plan = Plan::new(&air).unwrap();
        let (proof, public) = fixture(&air);
        let allowance = TestBudget::new(COMPONENT_BYTES).unwrap();
        let other_ledger = TestBudget::new(COMPONENT_BYTES).unwrap();
        assert_eq!(
            plan.admit(
                &air,
                &proof,
                &public,
                &other_ledger.proof,
                &allowance.ledger
            )
            .err(),
            Some(BUDGET)
        );
        let zero_native = allowance
            .ledger
            .reserve(Category::NativeProof, Bytes::ZERO)
            .unwrap();
        assert_eq!(
            plan.admit(&air, &proof, &public, &zero_native, &allowance.ledger)
                .err(),
            Some(CAPACITY)
        );
        let wrong_category = allowance
            .ledger
            .reserve(Category::Report, Bytes::ZERO)
            .unwrap();
        assert_eq!(
            plan.admit(&air, &proof, &public, &wrong_category, &allowance.ledger)
                .err(),
            Some(CAPACITY)
        );
        let mutations: [fn(&mut Proof<Config>); 7] = [
            |p| p.degree_bits += 1,
            |p| {
                p.opening_proof.1.query_proofs.pop();
            },
            |p| {
                p.opening_proof.1.query_proofs[0].input_proof[0]
                    .opening_proof
                    .0[0]
                    .push(Val::ZERO);
            },
            |p| p.opening_proof.1.query_proofs[0].commit_phase_openings[0].log_arity = 2,
            |p| {
                p.opened_values.trace_next = None;
            },
            |p| {
                p.commitments.random = None;
            },
            |p| {
                p.commitments.trace = Cap::new(vec![[Val::ZERO; 4]; 32]);
            },
        ];
        for mutate in mutations {
            let (mut invalid, _) = fixture(&air);
            mutate(&mut invalid);
            assert!(plan
                .admit(&air, &invalid, &public, &allowance.proof, &allowance.ledger)
                .is_err());
            assert_eq!(allowance.reserved_bytes(), 0);
        }
        let mut excess_public = Vec::with_capacity(2 * PUBLIC + 1);
        excess_public.extend_from_slice(&public);
        assert!(plan
            .admit(
                &air,
                &proof,
                &excess_public,
                &allowance.proof,
                &allowance.ledger
            )
            .is_err());
        let other = batch(1);
        assert!(plan
            .admit(&other, &proof, &public, &allowance.proof, &allowance.ledger)
            .is_err());
        assert_eq!(allowance.reserved_bytes(), 0);
    }

    #[test]
    #[ignore = "fresh CPU native SHAKE proof; requires coordinator serialized resource slot"]
    fn fresh_native_proof_verifies_and_statement_mutation_releases_reservation() {
        let air = single();
        // The proof-production token precedes all witness/proof construction;
        // the test's enclosing guard separately admits proving/trace scratch.
        let allowance = TestBudget::new(COMPONENT_BYTES).unwrap();
        let witness = air.generate(&[]).unwrap();
        let config = profile::make_cpu_config();
        let mut proof = p3_uni_stark::prove(&config, &air, witness.trace, &witness.public_values);
        drop(config);
        let mut public = witness.public_values.to_vec();
        let plan = Plan::new(&air).unwrap();
        let backing = plan
            .proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING)
            .unwrap();
        #[cfg(feature = "native-verification-allocation-audit")]
        let receipt = observation::measure_checked(plan.bounds.cumulative_requested_bytes, || {
            plan.admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
                .unwrap()
                .verify()
                .unwrap()
        });
        #[cfg(not(feature = "native-verification-allocation-audit"))]
        let receipt = plan
            .admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
            .unwrap()
            .verify()
            .unwrap();
        assert_eq!(receipt.proof_backing_bytes, backing);
        assert_eq!(receipt.bounds, plan.bounds());
        assert_eq!(allowance.reserved_bytes(), 0);
        let component = allowance
            .ledger
            .admit_phase(Plan::component_requirement())
            .unwrap();
        let pre_reserved = || {
            plan.admit_pre_reserved(
                &air,
                &proof,
                &public,
                &allowance.proof,
                component,
                &allowance.ledger,
            )
            .unwrap()
            .verify()
            .unwrap()
        };
        #[cfg(feature = "native-verification-allocation-audit")]
        let transferred =
            observation::measure_checked(plan.bounds.cumulative_requested_bytes, pre_reserved);
        #[cfg(not(feature = "native-verification-allocation-audit"))]
        let transferred = pre_reserved();
        assert_eq!(transferred, receipt);
        assert_eq!(allowance.reserved_bytes(), 0);
        public[0] += Val::ONE;
        assert!(matches!(
            plan.admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
                .unwrap()
                .verify(),
            Err(VerificationFailure::InvalidProof(_))
        ));
        assert_eq!(allowance.reserved_bytes(), 0);
        public[0] -= Val::ONE;
        proof.opened_values.trace_local[0] += Ext::ONE;
        assert!(matches!(
            plan.admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
                .unwrap()
                .verify(),
            Err(VerificationFailure::InvalidProof(_))
        ));
        assert_eq!(allowance.reserved_bytes(), 0);
    }

    // Opt-in only: this audit feature must be built without core's `stream`
    // feature, which owns a different global allocator. The coordinator runs
    // these ignored process-wide observations serially, with bounded threads.
    #[cfg(feature = "native-verification-allocation-audit")]
    mod observation {
        use super::*;
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        struct Observer;
        #[global_allocator]
        static ALLOCATOR: Observer = Observer;
        static ENABLED: AtomicBool = AtomicBool::new(false);
        static BYTES: AtomicUsize = AtomicUsize::new(0);
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        static OVERFLOWED: AtomicBool = AtomicBool::new(false);
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        fn observe(bytes: usize) {
            if ENABLED.load(Ordering::Acquire) {
                if BYTES
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                        n.checked_add(bytes)
                    })
                    .is_err()
                {
                    OVERFLOWED.store(true, Ordering::Relaxed);
                }
                CALLS.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe impl GlobalAlloc for Observer {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                observe(layout.size());
                unsafe { System.alloc(layout) }
            }
            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                observe(layout.size());
                unsafe { System.alloc_zeroed(layout) }
            }
            unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
                observe(size);
                unsafe { System.realloc(pointer, layout, size) }
            }
            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                unsafe { System.dealloc(pointer, layout) }
            }
        }
        struct Disable;
        impl Drop for Disable {
            fn drop(&mut self) {
                ENABLED.store(false, Ordering::Release);
            }
        }
        pub(super) fn measure_checked<T>(bound: usize, work: impl FnOnce() -> T) -> T {
            let _guard = LOCK.lock().unwrap();
            BYTES.store(0, Ordering::Relaxed);
            CALLS.store(0, Ordering::Relaxed);
            OVERFLOWED.store(false, Ordering::Relaxed);
            ENABLED.store(true, Ordering::Release);
            let disable = Disable;
            let result = work();
            drop(disable);
            let bytes = BYTES.load(Ordering::Relaxed);
            let calls = CALLS.load(Ordering::Relaxed);
            assert!(!OVERFLOWED.load(Ordering::Relaxed));
            assert!(
                bytes <= bound,
                "requested={bytes} bound={bound} calls={calls}"
            );
            eprintln!("native_shake_verification_requests bytes={bytes} calls={calls} source_bound={bound}");
            result
        }

        #[test]
        #[ignore = "serial process-wide allocation observation; no core stream allocator"]
        fn bounded_diagnostics_allocate_nothing() {
            measure_checked(0, check_inline_diagnostic_boundaries);
        }

        #[test]
        #[ignore = "serial process-wide allocation observation; no core stream allocator"]
        fn plans_preflight_and_refusal_allocate_nothing() {
            let air = single();
            let (proof, public) = fixture(&air);
            let allowance = TestBudget::new(COMPONENT_BYTES - 1).unwrap();
            measure_checked(0, || {
                let plan = Plan::new(&air).unwrap();
                plan.proof_backing_bytes(&proof, &public, PROOF_BACKING_CEILING)
                    .unwrap();
                assert!(plan
                    .admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
                    .is_err());
            });
            let admitted = TestBudget::new(COMPONENT_BYTES).unwrap();
            let component = admitted
                .ledger
                .admit_phase(Plan::component_requirement())
                .unwrap();
            measure_checked(0, || {
                let token = Plan::new(&air)
                    .unwrap()
                    .admit_pre_reserved(
                        &air,
                        &proof,
                        &public,
                        &admitted.proof,
                        component,
                        &admitted.ledger,
                    )
                    .unwrap();
                assert_eq!(admitted.reserved_bytes(), COMPONENT_BYTES);
                drop(token);
                assert_eq!(admitted.reserved_bytes(), 0);
            });
        }

        #[test]
        #[ignore = "serial process-wide allocation observation; warmed bounded Rayon runtime"]
        fn config_periodic_and_numeric_air_requests_fit_source_components() {
            use p3_commit::PolynomialSpace;
            use p3_field::coset::TwoAdicMultiplicativeCoset;
            for air in [single(), batch(8)] {
                let plan = Plan::new(&air).unwrap();
                // Force the exact caller's runtime/Rayon paths before measuring.
                let domain =
                    TwoAdicMultiplicativeCoset::<Val>::new(Val::ONE, air.height().ilog2() as usize)
                        .unwrap();
                let point = Ext::from_u64(19);
                let warm = air.periodic_columns();
                domain.evaluate_periodic_column_at(&warm[0], point);
                let config_plan = CpuVerificationConfigPlan::new().unwrap();
                measure_checked(0, || {
                    assert!(config_plan
                        .make_config(config_plan.requested_bytes() - 1)
                        .is_err())
                });
                let config = measure_checked(plan.bounds.configuration_bytes, || {
                    config_plan
                        .make_config(config_plan.requested_bytes())
                        .unwrap()
                });
                drop(config);
                let columns = measure_checked(plan.bounds.periodic_construction_bytes, || {
                    air.periodic_columns()
                });
                for column in &columns {
                    for point in [Ext::ONE, point] {
                        measure_checked(plan.bounds.periodic_evaluation_bytes, || {
                            domain.evaluate_periodic_column_at(column, point)
                        });
                    }
                }
                let local = vec![Ext::ZERO; air.width()];
                let next = local.clone();
                let periodic = vec![Ext::ZERO; PERIODIC];
                let public = vec![Val::ZERO; PUBLIC];
                measure_checked(plan.bounds.air_bytes, || {
                    let _ = p3_uni_stark::verify_constraints::<Config, _, ()>(
                        &air,
                        &local,
                        &next,
                        None,
                        None,
                        &periodic,
                        &public,
                        domain,
                        point,
                        Ext::ONE,
                        Ext::ZERO,
                    );
                });
                let (proof, public) = fixture(&air);
                let allowance = TestBudget::new(COMPONENT_BYTES).unwrap();
                measure_checked(plan.bounds.cumulative_requested_bytes, || {
                    assert!(plan
                        .admit(&air, &proof, &public, &allowance.proof, &allowance.ledger)
                        .unwrap()
                        .verify()
                        .is_err());
                });
                assert_eq!(allowance.reserved_bytes(), 0);
            }
        }
    }
}
