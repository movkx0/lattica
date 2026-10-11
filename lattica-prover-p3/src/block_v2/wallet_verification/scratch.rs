//! Release x86_64 payload bounds for the fixed wallet Uni-STARK verifier.
//!
//! The pinned p3 0.6.1 / Rust 1.96 allocation sites define these bounds. The
//! proof is already caller-owned and separately admitted; no proving operation
//! or upstream numerical verifier is changed. Configuration, domain/transcript,
//! AIR and PCS/FRI requests are summed conservatively. Periodic interpolation
//! calls are sequential and join their Rayon jobs before returning a scalar,
//! so only one column workspace coexists with the retained periodic table.
//!
//! This is a component payload plan, not RSS or a complete physical reservation.
//! Thread pools/stacks, allocator overhead, OS entropy internals, callbacks and
//! enclosing worker/coordinator lifetimes still need their own composition.

use super::{air, profile, Envelope, Val};
use p3_matrix::Dimensions;
use p3_uni_stark::Domain;

#[path = "scratch/ledger.rs"]
mod ledger;
#[path = "scratch/periodic.rs"]
mod periodic;
use ledger::{add, mul, Ledger};

type Ext = profile::Challenge;
type Config = profile::Config;
type Point = (Ext, Vec<Ext>);
type Matrix = (Domain<Config>, Vec<Point>);
type Round = (p3_symmetric::MerkleCap<Val, [Val; 4]>, Vec<Matrix>);
type SortedDimension = (usize, &'static Dimensions);

pub(crate) const TEMPORARY_LIMIT_BYTES: usize = 64 << 20;
const ERROR: &str = "wallet verifier temporary payload allowance";
const DIAGNOSTIC_BYTES: usize = 1024 + core::mem::size_of::<String>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Plan {
    pub(crate) configuration_bytes: usize,
    pub(crate) uni_bytes: usize,
    pub(crate) transcript_bytes: usize,
    pub(crate) air_bytes: usize,
    pub(crate) fri_bytes: usize,
    pub(crate) periodic_construction_bytes: usize,
    pub(crate) periodic_retained_bytes: usize,
    pub(crate) periodic_evaluation_peak_bytes: usize,
    pub(crate) periodic_evaluation_cumulative_bytes: usize,
    pub(crate) temporary_peak_bytes: usize,
    pub(crate) cumulative_requested_bytes: usize,
}

// Each MMCS batch here contains one height. The two stable dimension sorts
// include their scratch; the remaining-height iterator is empty before the
// arity walk clones it. Salt reconstruction is charged separately below.
fn tree(heap: &mut Ledger, matrices: usize, log_height: usize) -> Result<(), &'static str> {
    for _ in 0..2 {
        heap.growing::<SortedDimension>(matrices)?;
        heap.exact::<SortedDimension>(matrices)?;
    }
    heap.growing::<usize>(log_height)
}
fn hiding_tree(
    heap: &mut Ledger,
    matrices: usize,
    width: usize,
    log_height: usize,
) -> Result<(), &'static str> {
    heap.growing::<Vec<Val>>(matrices)?;
    let mut row = Ledger::default();
    row.growing::<Val>(add(width, 4)?)?;
    heap.repeat(row, matrices)?;
    heap.growing::<Dimensions>(matrices)?;
    tree(heap, matrices, log_height)
}

impl Plan {
    pub(crate) fn new(degree: usize, htlc: bool) -> Result<Self, &'static str> {
        let shape = Envelope::new(degree, htlc)?;
        // Hiding: 2 * next_power_of_two(degree_hint + 1 - 1). The numerical
        // verifier checks this exact quotient count before building PCS rounds.
        let quotient = mul(2, air::CONSTRAINT_DEGREE.next_power_of_two())?;
        if quotient > profile::MAX_QUOTIENT_CHUNKS {
            return Err(ERROR);
        }
        let matrices = [1, 1, quotient];
        let roots = 1usize << shape.log_lde.min(profile::CAP_HEIGHT);
        let periodic = periodic::Storage::new(htlc)?;
        let mut uni = Ledger::default();
        for _ in 0..2 {
            uni.growing::<Domain<Config>>(quotient)?;
        }
        uni.growing::<usize>(shape.widths[1])?; // main_next_row_columns
        uni.growing::<Round>(3)?; // initial random round, temporary vec, extension
        for (round, points) in [1, 2, 1].into_iter().enumerate() {
            uni.growing::<Matrix>(matrices[round])?;
            let mut matrix = Ledger::default();
            // Trace starts with vec![local] then pushes next: count both buffers.
            matrix.growing::<Point>(points)?;
            for _ in 0..points {
                let width = shape.widths[round];
                matrix.exact::<Ext>(width)?;
                matrix.exact::<Ext>(mul(2, add(width, profile::NUM_RANDOM_CODEWORDS)?)?)?;
            }
            uni.repeat(matrix, matrices[round])?;
        }
        uni.exact::<[Val; 4]>(mul(6, roots)?)?; // PCS and transcript cap clones
        uni.growing::<Ext>(quotient)?; // quotient recomposition coefficients
        uni.growing::<Ext>(periodic.columns)?; // retained periodic values

        let mut transcript = Ledger::default();
        transcript.exact::<[Val; 8]>(8)?;
        transcript.exact::<Val>(22)?; // cloned challenger permutation
        transcript.growing::<Val>(4)?; // duplex input/output buffers
        transcript.growing::<Val>(4)?;

        let mut air = Ledger::default();
        // Original AIR eval clones public, local, next, periodic and rc rows.
        let public = if htlc {
            crate::htlc_air::N_PUBLIC
        } else {
            crate::joinsplit_air::N_PUBLIC
        };
        for count in [
            add(public, 16)?,
            shape.widths[1],
            shape.widths[1],
            periodic.columns,
            8,
        ] {
            air.growing::<Ext>(count)?;
        }

        let mut fri = Ledger::default();
        let mut arities = Ledger::default();
        arities.growing::<usize>(degree)?;
        fri.repeat(arities, profile::NUM_QUERIES)?;
        fri.growing::<Ext>(degree)?; // commit-phase betas
        for layer in 0..degree {
            fri.exact::<[Val; 4]>(1usize << (shape.log_lde - layer - 1).min(profile::CAP_HEIGHT))?;
        }
        let mut query = Ledger::default();
        // Random/trace domains have 2^degree rows. Quotient chunks have
        // 2^(degree-1) rows, then hiding doubles them. Thus all three rounds
        // have one extended height: the reduced-opening BTree has one entry.
        query.bytes(add(
            8 * core::mem::size_of::<usize>(),
            mul(
                11,
                add(
                    core::mem::size_of::<usize>(),
                    core::mem::size_of::<(Ext, Ext)>(),
                )?,
            )?,
        )?)?;
        query.growing::<(usize, Ext)>(1)?;
        for round in 0..3 {
            query.growing::<usize>(matrices[round])?;
            query.growing::<Dimensions>(matrices[round])?;
            hiding_tree(
                &mut query,
                matrices[round],
                add(shape.widths[round], profile::NUM_RANDOM_CODEWORDS)?,
                shape.log_lde,
            )?;
        }
        for layer in 0..degree {
            let log_height = shape.log_lde - layer - 1;
            for _ in 0..3 {
                query.exact::<Ext>(2)?;
            } // reconstructed row and two clones
            query.growing::<Val>(6)?; // extension-MMCS flattening
            query.growing::<Vec<Val>>(1)?;
            query.growing::<Dimensions>(1)?;
            hiding_tree(&mut query, 1, 6, log_height)?;
            query.growing::<Ext>(2)?; // fold-row evaluations
            query.growing::<Val>(2)?; // binary coset
            query.growing::<Ext>(2)?; // denominators
            query.exact::<Ext>(2)?; // batch inverses
        }
        fri.repeat(query, profile::NUM_QUERIES)?;

        let configuration_bytes = profile::verification::requested_bytes();
        // Reserve these requests throughout all phases, even if some owners
        // are constructed later or dropped sooner. Caller proof is separate.
        let persistent = add(
            configuration_bytes,
            add(add(uni.0, transcript.0)?, add(air.0, DIAGNOSTIC_BYTES)?)?,
        )?;
        let periodic_or_pcs = add(periodic.retained, periodic.evaluation_peak.max(fri.0))?;
        let temporary_peak_bytes = add(persistent, periodic.construction.max(periodic_or_pcs))?;
        let cumulative_requested_bytes = add(
            persistent,
            add(
                periodic.construction,
                add(periodic.evaluation_cumulative, fri.0)?,
            )?,
        )?;
        Ok(Self {
            configuration_bytes,
            uni_bytes: uni.0,
            transcript_bytes: transcript.0,
            air_bytes: air.0,
            fri_bytes: fri.0,
            periodic_construction_bytes: periodic.construction,
            periodic_retained_bytes: periodic.retained,
            periodic_evaluation_peak_bytes: periodic.evaluation_peak,
            periodic_evaluation_cumulative_bytes: periodic.evaluation_cumulative,
            temporary_peak_bytes,
            cumulative_requested_bytes,
        })
    }
    pub(crate) fn admit(self, bytes: usize) -> Result<(), &'static str> {
        if self.temporary_peak_bytes > bytes {
            return Err(ERROR);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "stream"))]
#[path = "scratch/tests.rs"]
pub(super) mod tests;
