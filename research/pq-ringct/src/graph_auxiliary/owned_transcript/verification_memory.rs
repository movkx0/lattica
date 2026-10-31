//! Admission for the independent CPU verifier of a bounded native transcript source.
//!
//! This is an opt-in prerequisite; production factory verification remains unchanged. The caller must reserve proof backing before
//! producing it and use the shared ledger accounting for every other live
//! owner. This module consumes an original preissued64 MiB component
//! before configuration construction or numerical verification. Borrowed inputs
//! cannot change while admitted. The default verifier releases its reservation
//! on every exit. The preserving path returns the exact original token
//! after verification temporaries die; a failure returns cleanup ownership only.
//!
//! The ledger follows pinned p3 0.6.1 / Rust 1.96 allocation sites, as in
//! `block_v2/wallet_verification/scratch.rs`. It sums allocation requests,
//! including replacement buffers and every Rayon interpolation accumulator.
//! It is not RSS: thread pools/stacks, allocator overhead, OS entropy internals,
//! callbacks, caller reports and the enclosing worker lifetimes are separate.

use crate::execution::retained_resources::{
    Bytes, Category, Ledger as ResourceLedger, Requirements, Reservation,
};
use crate::transcript_air::{self, TranscriptAir};
use lattica_prover_p3::block_v2::native_gpu::{
    transcript_preparation::{TranscriptLayout, TranscriptPartKind, TranscriptPreparationPlan, MAX_PARTS},
    transcript_recording::TranscriptSymbolicReplay,
};
use core::mem::size_of;
use lattica_prover_p3::block_v2::profile::{self, Config, CpuVerificationConfigPlan};
use p3_air::{Air, AirBuilder, BaseAir};
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
const QUOTIENT: usize = 16;
const GEOMETRY: &str = "native transcript verification unsupported geometry";
const OVERFLOW: &str = "native transcript verification size overflow";
const ENVELOPE: &str = "native transcript verification proof envelope";
const CAPACITY: &str = "native transcript verification proof capacity";
const BUDGET: &str = "native transcript verification component allowance";
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

/// Closed maintained AIRs only; no caller callback or replacement degree hint.
pub(crate) struct SourceAir<'a>(&'a TranscriptAir, TranscriptLayout);
impl<'a> SourceAir<'a> {
    pub(crate) fn new(air: &'a TranscriptAir, kind: TranscriptLayout) -> Self { Self(air, kind) }
    fn kind(&self) -> TranscriptLayout { self.1 }
    fn height(&self) -> usize { self.0.height() }
}
impl BaseAir<Val> for SourceAir<'_> {
    fn width(&self) -> usize { self.0.width() }
    fn num_public_values(&self) -> usize { self.0.num_public_values() }
    fn num_periodic_columns(&self) -> usize { self.0.num_periodic_columns() }
    fn periodic_columns(&self) -> Vec<Vec<Val>> { self.0.periodic_columns() }
    fn max_constraint_degree(&self) -> Option<usize> { self.0.max_constraint_degree() }
    fn num_constraints(&self) -> Option<usize> { self.0.num_constraints() }
    fn preprocessed_width(&self) -> usize { self.0.preprocessed_width() }
    fn main_next_row_columns(&self) -> Vec<usize> { self.0.main_next_row_columns() }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for SourceAir<'_> {
    fn eval(&self, builder: &mut AB) { self.0.eval(builder) }
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
    kind: TranscriptLayout,
    public: usize,
    periodic: usize,
    width: usize,
    height: usize,
    degree: usize,
    log_lde: usize,
}
impl Shape {
    fn new(air: &SourceAir) -> Result<Self> {
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
        let layout = super::layout_for_air(air.0).map_err(|_| GEOMETRY)?;
        require(layout == air.kind(), GEOMETRY)?;
        let (height, width, public, periodic) =
            (layout.part_count().next_power_of_two() * 128, 383 + 2 * layout.event_count(), 8, 4);
        require((air.height(), air.width(), air.num_public_values(), air.num_periodic_columns())
            == (height, width, public, periodic) && air.max_constraint_degree().is_none()
            && air.num_constraints().is_none() && air.preprocessed_width() == 0,
            GEOMETRY)?;
        let degree = add(height.ilog2() as usize, 1)?;
        let log_lde = add(degree, 4)?;
        require(degree <= 25 && log_lde <= Val::TWO_ADICITY, GEOMETRY)?;
        Ok(Self {
            kind: air.kind(), public, periodic,
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

/// Source-derived requested-heap and entry-frame bounds, never observed RSS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds {
    pub symbolic_replay_bytes: usize,
    pub configuration_bytes: usize,
    pub uni_bytes: usize,
    pub transcript_bytes: usize,
    pub air_bytes: usize,
    pub fri_bytes: usize,
    pub periodic_construction_bytes: usize,
    pub periodic_evaluation_bytes: usize,
    pub diagnostic_bytes: usize,
    pub cumulative_requested_bytes: usize,
    /// Inline owners in the shared entry/helper, separate from requested heap.
    pub entry_frame_bytes: usize,
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

fn periodic_evaluation(period: usize) -> Result<usize> {
    let mut heap = Ledger::default();
    heap.exact::<Val>(period)?; // Domain::evaluate_polynomial_at column clone.
    heap.growing::<Val>(period)?; // Materialized coset.
    for _ in 0..3 {
        heap.exact::<Ext>(period)?;
    } // differences/inverses/weights
      // Dense width-one rows borrow storage. Pinned Rayon fold(identity).reduce
      // has at most two identities per nonempty indexed leaf, bounded by period.
    heap.exact::<Packed>(mul(2, period)?)?;
    heap.growing::<Ext>(1)?; // Result, also covers on-coset early return.
    Ok(heap.0)
}

impl Bounds {
    fn new(shape: Shape, configuration_bytes: usize, symbolic_replay_bytes: usize) -> Result<Self> {
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
        uni.growing::<Ext>(shape.periodic)?;
        let mut transcript = Ledger::default();
        transcript.exact::<[Val; 8]>(8)?;
        transcript.exact::<Val>(22)?;
        transcript.growing::<Val>(4)?;
        transcript.growing::<Val>(4)?;
        let mut air = Ledger::default();
        // Same concrete AIR callback vectors as the accepted recorder. Its
        // expression/public representations bound the numeric folder's values.
        // This is separate from callback storage in symbolic_replay_bytes.
        let source = TranscriptPreparationPlan::new(shape.kind).map_err(|_| GEOMETRY)?;
        air.bytes(source.host().air_callback_heap_bytes)?;
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
        // Reference schedule first allocates four 128-value columns, then
        // replaces parity with a two-value column: count the replaced payload.
        periodic.exact::<Val>(4 * 128 + 2)?;
        periodic.growing::<Vec<Val>>(shape.periodic)?;
        // All actual periods are <=128; the row count may be much larger.
        let periodic_evaluation_bytes = periodic_evaluation(128)?;
        // Formatting writes into an inline fixed-size result. It allocates no
        // heap and cannot leave a String alive after temporary admission ends.
        // Caller result/stack storage is outside this requested-heap ledger.
        let diagnostic = Ledger::default();
        let mut total = Ledger::default();
        for bytes in [
            symbolic_replay_bytes,
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
        total.bytes(mul(shape.periodic, periodic_evaluation_bytes)?)?;
        let entry_frame_bytes = verifier_entry_frame_bytes()?;
        require(add(total.0, entry_frame_bytes)? <= COMPONENT_BYTES, BUDGET)?;
        Ok(Self {
            symbolic_replay_bytes,
            configuration_bytes,
            uni_bytes: uni.0,
            transcript_bytes: transcript.0,
            air_bytes: air.0,
            fri_bytes: fri.0,
            periodic_construction_bytes: periodic.0,
            periodic_evaluation_bytes,
            diagnostic_bytes: diagnostic.0,
            cumulative_requested_bytes: total.0,
            entry_frame_bytes,
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
    pub(super) fn for_recorded(air: &SourceAir, replay: TranscriptSymbolicReplay) -> Result<Self> {
        let shape = Shape::new(air)?;
        let configuration = CpuVerificationConfigPlan::new()?;
        let geometry = replay.geometry();
        require((geometry.kind(), geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            == (shape.kind, shape.height, shape.width, shape.public, shape.periodic), GEOMETRY)?;
        let bounds = Bounds::new(shape, configuration.requested_bytes(), replay.required_host_bytes())?;
        Ok(Self {
            shape,
            configuration,
            bounds,
        })
    }
    pub(crate) fn bounds(self) -> Bounds {
        self.bounds
    }

    /// Resource-census comparison only. The concrete issuer separately binds
    /// both recordings to its same immutable source factory and plan owner.
    pub(crate) fn same_census(self, other: Self) -> bool {
        self.shape == other.shape && self.bounds == other.bounds
            && self.configuration.requested_bytes() == other.configuration.requested_bytes()
    }

    /// Additional inline ownership for the retaining call and its immediate
    /// caller. Reserve this before source/PCS construction, inside the enclosing
    /// worker allowance, and keep it through destruction of the returned value.
    /// It grants no verification or retry authority and excludes the caller's
    /// own enclosing request/workspace structures and any further forwarding.
    pub(crate) fn retaining_original_caller_host_bytes() -> Result<usize> {
        type Retained = core::result::Result<
            (VerificationReceipt, Reservation),
            (VerificationFailure, Reservation),
        >;
        let mut frames = Ledger::default();
        // Consuming caller and callee self slots, full return/match/forwarded
        // Result slots, both branch tuples, and separately materialized fields.
        // Count the complete variants; the bounded diagnostic is inline.
        frames.exact::<AdmittedVerification<'static>>(2)?;
        frames.exact::<Retained>(4)?;
        frames.exact::<(VerificationReceipt, Reservation)>(2)?;
        frames.exact::<(VerificationFailure, Reservation)>(2)?;
        frames.exact::<VerificationReceipt>(2)?;
        frames.exact::<VerificationFailure>(2)?;
        frames.exact::<Reservation>(2)?;
        frames.exact::<usize>(8)?;
        Ok(frames.0)
    }

    /// Inspect already-owned input capacities without allocating. This is not
    /// a retroactive proof reservation: the producer must have admitted backing
    /// before generation/decoding, using its own ownership-following budget.
    pub(crate) fn proof_backing_bytes(
        self,
        proof: &Proof<Config>,
        public: &[Val],
        already_reserved: usize,
    ) -> Result<usize> {
        require(already_reserved <= PROOF_BACKING_CEILING, CAPACITY)?;
        self.shape.audit(proof, public, already_reserved)
    }

    pub(crate) fn component_requirement() -> Requirements {
        Requirements::single(
            Category::IndependentVerifier,
            Bytes {
                host: COMPONENT_BYTES as u64,
                device: 0,
            },
        )
    }

    /// Refusal keeps the same original verifier claim for terminal cleanup.
    /// The complete source issuer must never replace it with fresh credit.
    pub(crate) fn admit_pre_reserved_preserving<'p>(
        self,
        air: &'p SourceAir<'p>,
        proof: &'p Proof<Config>,
        public: &'p [Val],
        proof_reservation: &'p Reservation,
        reservation: Reservation,
        ledger: &ResourceLedger,
    ) -> core::result::Result<AdmittedVerification<'p>, (&'static str, Reservation)> {
        let checked = (|| -> Result<usize> {
            require(reservation.belongs_to(ledger), BUDGET)?;
            require(reservation.requirements() == Self::component_requirement(), BUDGET)?;
            self.audit_inputs(air, proof, public, proof_reservation, ledger)
        })();
        let proof_backing_bytes = match checked {
            Ok(bytes) => bytes,
            Err(error) => return Err((error, reservation)),
        };
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
        air: &SourceAir,
        proof: &Proof<Config>,
        public: &[Val],
        proof_reservation: &Reservation,
        ledger: &ResourceLedger,
    ) -> Result<usize> {
        require(Shape::new(air)? == self.shape, GEOMETRY)?;
        let allowance = ledger.snapshot().allowance;
        require(
            crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host) && allowance.device <= 8u64 << 30,
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
    air: &'p SourceAir<'p>,
    proof: &'p Proof<Config>,
    public: &'p [Val],
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
                .write_str("native transcript verifier diagnostic exceeded fixed capacity")
                .expect("fixed diagnostic fits");
        }
        result
    }
    pub(crate) fn as_str(&self) -> &str {
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

fn verifier_entry_frame_bytes() -> Result<usize> {
    type NativeOutcome =
        core::result::Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<Config>>>;
    type Outcome = core::result::Result<VerificationReceipt, VerificationFailure>;
    let mut frames = Ledger::default();
    // Four full slots cover local values, returns, residual/error conversion,
    // and forwarding at this entry and its borrowed helper. Downstream verifier
    // execution still uses the enclosing guarded stacks. These inline owners
    // are additive to all requested heap and fit the original 64 MiB component.
    frames.exact::<AdmittedVerification<'static>>(4)?;
    frames.exact::<Config>(4)?;
    frames.exact::<core::result::Result<Config, &'static str>>(4)?;
    frames.exact::<NativeOutcome>(4)?;
    frames.exact::<Outcome>(4)?;
    frames.exact::<VerificationReceipt>(4)?;
    frames.exact::<VerificationFailure>(4)?;
    frames.exact::<Diagnostic>(4)?;
    frames.exact::<core::fmt::Arguments<'static>>(4)?;
    frames.exact::<usize>(16)?;
    frames.exact::<[TranscriptPartKind; MAX_PARTS]>(8)?;
    frames.exact::<TranscriptLayout>(8)?;
    frames.exact::<SourceAir<'static>>(8)?;
    Ok(frames.0)
}

impl AdmittedVerification<'_> {
    pub(crate) fn verify(self) -> core::result::Result<VerificationReceipt, VerificationFailure> {
        self.verify_borrowed()
    }

    /// Return the exact admitted component after all configuration, verifier,
    /// and diagnostic-formatting temporaries are destroyed. The token is never
    /// dropped/recreated or readmitted. On failure it permits terminal cleanup
    /// only; a request workspace must retire instead of dispatching a retry.
    /// The caller must precharge `Plan::retaining_original_caller_host_bytes`.
    pub(crate) fn verify_retaining_original(
        self,
    ) -> core::result::Result<(VerificationReceipt, Reservation), (VerificationFailure, Reservation)>
    {
        // The helper's borrow ends only after its configuration and native
        // verification temporaries have dropped on success or ordinary error.
        let outcome = self.verify_borrowed();
        let original = self._reservation;
        match outcome {
            Ok(receipt) => Ok((receipt, original)),
            Err(failure) => Err((failure, original)),
        }
    }

    fn verify_borrowed(&self) -> core::result::Result<VerificationReceipt, VerificationFailure> {
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
    fn audit(self, proof: &Proof<Config>, public: &[Val], limit: usize) -> Result<usize> {
        require(proof.degree_bits == self.degree, ENVELOPE)?;
        let mut heap = Backing {
            bytes: add(size_of::<Proof<Config>>(), size_of::<[Val; 8]>())?,
            limit,
        };
        require(public.len() == self.public, ENVELOPE)?;
        // The closed output contains a fixed public array, never an unbounded
        // caller vector. Charge the largest variant without overlap credit.
        heap.bytes = add(heap.bytes, 8 * size_of::<Val>())?;
        require(heap.bytes <= limit, CAPACITY)?;
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
mod tests;
