//! Cumulative requested heap storage for the registered numerical verifier.
//!
//! The model follows p3 0.6.1 and Rust 1.96 allocation sites, using trusted AIR
//! geometry after the length envelope. Summing every allocation request (also
//! replacements) bounds simultaneous payload storage without guessing lifetimes.
//! It covers `verify_batch` with a fresh CPU challenger and the reference PCS.
//! Configuration construction, the public-value copy, caller-owned proof and
//! metadata capacities, debug symbolic inference, tracing subscribers, error
//! formatting, stacks and allocator overhead need enclosing reservations.
//!
//! Qualification is release x86_64 only. Dependency/toolchain changes require
//! a renewed source audit; allocation observations test, but do not define, bounds.

use super::{profile, verification_envelope::Envelope, Config, MachineAir, Val};
use p3_air::BaseAir;
use p3_batch_stark::{Commitment, CommonData, Domain};
use p3_lookup::Kind;
use p3_matrix::Dimensions;

type Ext = profile::Challenge;
type Point = (Ext, Vec<Ext>);
type Matrix = (Domain<Config>, Vec<Point>);
type Round = (Commitment<Config>, Vec<Matrix>);
type SortedDimension = (usize, &'static Dimensions);

// Component ceiling, not a measured peak or a complete worker reservation.
pub(super) const LIMIT_BYTES: usize = 64 << 20;
const ERROR: &str = "native verifier numerical scratch exceeds allowance";
const GEOMETRY: &str = "native verifier numerical scratch geometry";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Plan {
    pub(super) batch_bytes: usize,
    pub(super) transcript_bytes: usize,
    pub(super) lookup_bytes: usize,
    pub(super) fri_bytes: usize,
    pub(super) requested_bytes: usize,
}

#[derive(Clone, Copy, Default)]
struct Ledger(usize);

fn add(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_add(b).ok_or(ERROR)
}
fn mul(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_mul(b).ok_or(ERROR)
}

impl Ledger {
    fn bytes(&mut self, bytes: usize) -> Result<(), &'static str> {
        self.0 = add(self.0, bytes)?;
        Ok(())
    }
    fn exact<T>(&mut self, count: usize) -> Result<(), &'static str> {
        self.bytes(mul(count, core::mem::size_of::<T>())?)
    }
    // Pinned RawVec doubles capacity, with minimum 8 for bytes, 4 for other
    // small elements and 1 for large elements. A final capacity below 2*n,
    // plus its geometric predecessors, requests less than 4*max(n, 8) slots.
    // This also covers Result/collect iterators without a useful lower hint.
    // Explicit into_boxed_slice shrinking is charged separately at its site.
    fn growing<T>(&mut self, count: usize) -> Result<(), &'static str> {
        if count == 0 {
            return Ok(());
        }
        self.exact::<T>(mul(4, count.max(8))?)
    }
    fn repeat(&mut self, other: Self, count: usize) -> Result<(), &'static str> {
        self.bytes(mul(other.0, count)?)
    }
}

// The registered PCS gives all matrices within an MMCS batch the same height.
// Both sorted vectors are charged, including stable-sort scratch. The schedule
// consumes all matrices before walking heights; its cloned remaining iterators
// are empty, so there is no per-height matrix-vector clone allocation.
fn tree(ledger: &mut Ledger, matrices: usize, log_height: usize) -> Result<(), &'static str> {
    for _ in 0..2 {
        ledger.growing::<SortedDimension>(matrices)?;
        ledger.exact::<SortedDimension>(matrices)?;
    }
    ledger.growing::<usize>(log_height)
}

fn hiding_tree(
    ledger: &mut Ledger,
    matrices: usize,
    width: usize,
    log_height: usize,
) -> Result<(), &'static str> {
    ledger.growing::<Vec<Val>>(matrices)?;
    let mut row = Ledger::default();
    row.growing::<Val>(add(width, 4)?)?; // Four salt elements per row.
    ledger.repeat(row, matrices)?;
    ledger.growing::<Dimensions>(matrices)?;
    tree(ledger, matrices, log_height)
}

impl Plan {
    pub(super) fn new(
        air: &MachineAir,
        common: &CommonData<Config>,
        quotient_chunks: usize,
    ) -> Result<Self, &'static str> {
        let shape = Envelope::new(air, common, quotient_chunks)?;
        let global = common.preprocessed.as_ref().ok_or(GEOMETRY)?;
        let meta = global
            .instances
            .first()
            .and_then(Option::as_ref)
            .ok_or(GEOMETRY)?;
        // These conditions justify one AIR and one MMCS height. Never silently
        // reuse the model for another shape.
        if global.instances.len() != 1
            || global.matrix_to_instance != [0]
            || meta.matrix_index != 0
            || meta.width != shape.widths[3]
            || meta.degree_bits != shape.degree
            || !quotient_chunks.is_power_of_two()
            || air.num_periodic_columns() != 0
            || common.lookups[0].is_empty()
        {
            return Err(GEOMETRY);
        }
        let lookups = &common.lookups[0];
        let mut global_bus = None;
        for lookup in lookups.iter() {
            if let Kind::Global(name) = &lookup.kind {
                if global_bus.is_some_and(|bus| bus != name.as_str()) {
                    return Err(GEOMETRY);
                }
                global_bus = Some(name.as_str());
            }
        }
        let cap_roots = 1usize
            .checked_shl(shape.log_lde.min(profile::CAP_HEIGHT) as u32)
            .ok_or(ERROR)?;

        let mut batch = Ledger::default();
        // check_multiplicity_height_bound converts a u128 sum and the u64 field
        // order to BigUint. Its error branch can also compute F::bits() from
        // another order value. Charging u64 limbs also covers u32-digit builds.
        for _ in 0..3 {
            batch.growing::<u64>(2)?;
        }
        batch.exact::<usize>(6)?; // Five per-AIR vectors plus trace_heights.
        for _ in 0..2 {
            batch.growing::<Domain<Config>>(1)?; // Trace and extended trace domains.
            batch.growing::<Vec<Domain<Config>>>(1)?;
            batch.growing::<Domain<Config>>(quotient_chunks)?; // Quotient partitions.
        }
        batch.growing::<Round>(5)?;
        for (round, points) in [1, 1, 1, 1, 2].into_iter().enumerate() {
            let matrices = shape.matrices[round];
            let width = shape.widths[round];
            batch.growing::<Matrix>(matrices)?;
            let mut matrix = Ledger::default();
            matrix.exact::<Point>(points)?; // vec! point descriptors.
            for _ in 0..points {
                matrix.exact::<Ext>(width)?; // Clone public opening row.
                if round != 3 {
                    // HidingPcs::verify extends that clone with codewords. Old
                    // and replacement allocations both enter the cumulative sum.
                    matrix.exact::<Ext>(mul(2, add(width, profile::NUM_RANDOM_CODEWORDS)?)?)?;
                }
            }
            batch.repeat(matrix, matrices)?;
        }
        // Five PCS commitment clones and five transcript-observation clones.
        batch.exact::<[Val; 4]>(mul(10, cap_roots)?)?;
        batch.growing::<Ext>(quotient_chunks)?; // Recomposition coefficients.
        for _ in 0..2 {
            batch.growing::<Ext>(add(lookups.len(), 1)?)?; // Permutation rows.
        }
        batch.exact::<Ext>(shape.widths[1])?; // Absent main-next zero row.
        batch.exact::<Ext>(shape.widths[3])?; // Absent preprocessing-next zero row.
        batch.growing::<Ext>(1)?; // Single lookup terminal.

        let mut transcript = Ledger::default();
        // initialise_challenger clones the scalar Poseidon2 permutation: two
        // four-round external vectors, each width 8, and 22 internal constants.
        transcript.exact::<[Val; 8]>(8)?;
        transcript.exact::<Val>(22)?;
        transcript.growing::<Val>(4)?; // CPU duplex input buffer.
        transcript.growing::<Val>(4)?; // CPU duplex output buffer.
        transcript.growing::<Vec<usize>>(1)?;
        transcript.exact::<u8>(1)?; // Cold foldhash global seed's boxed byte.
        if global_bus.is_some() {
            // The one named wire bus adds one hashbrown entry (&str, usize).
            // Its initial table has four buckets; allow eight plus two SIMD
            // control groups and alignment padding. Repeated names do not grow.
            transcript.bytes(add(mul(8, core::mem::size_of::<(&str, usize)>())?, 64)?)?;
        }
        transcript.growing::<usize>(lookups.len())?; // Per-instance bus IDs.
        transcript.growing::<Ext>(lookups.len())?; // Challenges::bus_prefix.
        transcript.exact::<Ext>(lookups.len())?; // Boxed-slice shrink, if needed.
        transcript.growing::<Vec<Ext>>(1)?;
        transcript.growing::<Ext>(mul(2, lookups.len())?)?;

        let mut lookup = Ledger::default();
        for entry in lookups.iter() {
            let terms = entry.elements.len();
            if terms != entry.multiplicities.len() {
                return Err(GEOMETRY);
            }
            lookup.exact::<usize>(terms)?; // Lookup constraint-degree inference.
            lookup.growing::<Vec<Ext>>(terms)?; // Resolved element descriptors.
            for tuple in &entry.elements {
                lookup.growing::<Ext>(tuple.len())?;
            }
            lookup.growing::<Ext>(terms)?; // Resolved multiplicities.
            lookup.growing::<Ext>(terms)?; // Combined denominator terms.
            if terms != 0 {
                lookup.exact::<Ext>(mul(2, add(terms, 1)?)?)?; // Prefix/suffix products.
            }
        }

        let layers = shape.degree; // Binary folds to the blowup-only final domain.
        let mut fri = Ledger::default();
        let mut arities = Ledger::default();
        arities.growing::<usize>(layers)?;
        fri.repeat(arities, profile::NUM_QUERIES)?; // First plus every comparison.
        fri.growing::<Ext>(layers)?; // Commit-phase betas.
        for layer in 0..layers {
            let roots = 1usize << (shape.log_lde - layer - 1).min(profile::CAP_HEIGHT);
            fri.exact::<[Val; 4]>(roots)?; // Observed FRI cap clone.
        }
        let mut query = Ledger::default();
        // All initial domains have the same extended height, hence the reduced
        // opening BTreeMap contains one entry. Rust 1.96 uses an 11-slot leaf:
        // key/value arrays plus a conservative eight-word header/padding bound.
        query.bytes(add(
            mul(8, core::mem::size_of::<usize>())?,
            mul(
                11,
                add(
                    core::mem::size_of::<usize>(),
                    core::mem::size_of::<(Ext, Ext)>(),
                )?,
            )?,
        )?)?;
        query.growing::<(usize, Ext)>(1)?; // Descending reduced openings.
        for round in 0..5 {
            let matrices = shape.matrices[round];
            let hiding = if round == 3 {
                0
            } else {
                profile::NUM_RANDOM_CODEWORDS
            };
            query.growing::<usize>(matrices)?; // Input batch heights.
            query.growing::<Dimensions>(matrices)?;
            hiding_tree(
                &mut query,
                matrices,
                add(shape.widths[round], hiding)?,
                shape.log_lde,
            )?;
        }
        for layer in 0..layers {
            let log_height = shape.log_lde - layer - 1;
            query.exact::<Ext>(2)?; // Reconstructed binary evaluation row.
            query.exact::<Ext>(2)?; // MMCS input row clone.
            query.exact::<Ext>(2)?; // Extension-MMCS clone before flattening.
            query.growing::<Val>(6)?; // Flattened row (may reuse the previous Vec).
            query.growing::<Vec<Val>>(1)?;
            query.growing::<Dimensions>(1)?;
            hiding_tree(&mut query, 1, 6, log_height)?;
            query.growing::<Ext>(2)?; // fold_row collect (may reuse evaluations).
            query.growing::<Val>(2)?; // Binary coset points.
            query.growing::<Ext>(2)?; // Lagrange differences.
            query.exact::<Ext>(2)?; // Single-chunk inverse output; no Rayon.
        }
        fri.repeat(query, profile::NUM_QUERIES)?;
        let requested_bytes = add(add(batch.0, transcript.0)?, add(lookup.0, fri.0)?)?;
        Ok(Self {
            batch_bytes: batch.0,
            transcript_bytes: transcript.0,
            lookup_bytes: lookup.0,
            fri_bytes: fri.0,
            requested_bytes,
        })
    }

    pub(super) fn admit(self, limit: usize) -> Result<(), &'static str> {
        if self.requested_bytes > limit {
            return Err(ERROR);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
