//! Fixed wallet periodic-column construction and one interpolation workspace.
//! The actual path is p3-commit's two-adic domain -> p3-matrix interpolation,
//! not p3-fri's scalar PeriodicEvaluator helper. All Rayon fold/reduce leaf
//! accumulators are charged, independently of which threads execute them.

use super::ledger::{add, mul, Ledger};
use super::{Ext, Val};
use crate::{htlc_air as htlc, joinsplit_air as js};
use p3_field::ExtensionField;

type Packed = <Ext as ExtensionField<Val>>::ExtensionPacking;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Storage {
    pub(super) columns: usize,
    pub(super) height: usize,
    pub(super) construction: usize,
    pub(super) retained: usize,
    pub(super) evaluation_peak: usize,
    pub(super) evaluation_cumulative: usize,
}

impl Storage {
    pub(super) fn new(is_htlc: bool) -> Result<Self, &'static str> {
        let (columns, height) = if is_htlc {
            (htlc::N_PERIODIC, htlc::HEIGHT)
        } else {
            (js::N_PERIODIC, js::HEIGHT)
        };
        // periodic_table: eleven length-32 columns; all additional one-hot
        // columns and pos_coeff have wallet HEIGHT entries, each exact-sized.
        let long = columns.checked_sub(11).ok_or(super::ERROR)?;
        let values = add(11 * 32, mul(long, height)?)?;
        let mut construction = Ledger::default();
        construction.exact::<Val>(values)?;
        construction.exact::<Vec<Val>>(8)?; // temporary rc vector in periodic_table
        construction.growing::<Vec<Val>>(columns)?;

        let n = js::N_IN;
        let m = js::M_OUT;
        let seeds = add(add(n, m)?, 2)?;
        let windows = if is_htlc {
            add(seeds, add(mul(2, n)?, 1)?)?
        } else {
            seeds
        };
        // own_in, recip, commit_a_in, chain_link, commit_b, mem, root,
        // null_in, out_a_in, region_last, seeds, range_active, range_close.
        for count in [
            n,
            n,
            n,
            add(n, m)?,
            add(n, m)?,
            mul(n, js::DEPTH)?,
            n,
            n,
            m,
            seeds,
            seeds,
            mul(windows, js::BITS)?,
            windows,
        ] {
            construction.growing::<usize>(count)?;
        }
        if is_htlc {
            // to_seeds, diff_seeds, in_commit_b, htlc_in0, htlc_link,
            // htlc_in3, htlc_root_out, htlc_in1, htlc_in2.
            // Pinned htlc_air::HTLC_BLOCKS is four, hence three links per input.
            for count in [n, n, n, n, mul(n, 3)?, n, n, n, n] {
                construction.growing::<usize>(count)?;
            }
        }
        let mut retained = Ledger::default();
        retained.exact::<Val>(values)?;
        retained.exact::<Vec<Val>>(mul(2, columns.max(8))?)?;
        let small = evaluation(32)?;
        let large = evaluation(height)?;
        Ok(Self {
            columns,
            height,
            construction: construction.0,
            retained: retained.0,
            evaluation_peak: small.max(large),
            evaluation_cumulative: add(mul(11, small)?, mul(long, large)?)?,
        })
    }
}

pub(super) fn evaluation(period: usize) -> Result<usize, &'static str> {
    let mut heap = Ledger::default();
    heap.exact::<Val>(period)?; // domain.evaluate_polynomial_at's column clone
    heap.growing::<Val>(period)?; // interpolation coset collection
    for _ in 0..3 {
        // Indexed Rayon collect for differences and adjusted weights, and the
        // exact zero_vec for batch inverses. Inversion writes into that output;
        // packed and tail inverse helpers use fixed stack arrays.
        heap.exact::<Ext>(period)?;
    }
    // Width-one DenseMatrix uses packed rows without allocating row copies.
    // par_fold_reduce = fold(identity).reduce(identity): at most two identity
    // accumulators per nonempty indexed leaf, and at most period leaves.
    // Sum all leaf allocations, not just the calling thread's observations.
    heap.exact::<Packed>(mul(2, period)?)?;
    // Result collection also covers the on-coset early return's one-element row.
    heap.growing::<Ext>(1)?;
    Ok(heap.0)
}
