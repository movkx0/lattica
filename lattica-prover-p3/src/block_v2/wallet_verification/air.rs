//! Verifier-only degree metadata for the three fixed wallet AIRs.
//!
//! P3 0.6.1 skips symbolic graph construction for degree inference in release
//! when this hint is present. Constraints and all other metadata delegate to
//! the original AIR. Proving continues to use that original AIR unchanged.
//! Independent symbolic tests require exact equality with the inferred degree;
//! the hint is not an allowance to change quotient geometry or proof parameters.
//! Debug builds retain upstream's symbolic cross-check and need a separate bound.

use crate::block_v2::{leaf::ContextJoinSplitAir, typed_leaf::ContextAir};
use crate::{config::Val, htlc_air::HtlcAir, joinsplit_air::JoinSplitAir};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;

pub(super) const CONSTRAINT_DEGREE: usize = 8;

// The field is private: only the three constructors below may attach this hint.
pub(crate) struct DegreeAir<A>(A);

pub(crate) fn join_split() -> DegreeAir<ContextJoinSplitAir> {
    DegreeAir(ContextJoinSplitAir)
}
pub(crate) fn htlc() -> DegreeAir<ContextAir<HtlcAir>> {
    DegreeAir(ContextAir(HtlcAir))
}
pub(crate) fn issuance() -> DegreeAir<ContextAir<JoinSplitAir>> {
    DegreeAir(ContextAir(JoinSplitAir))
}

impl<A: BaseAir<Val>> BaseAir<Val> for DegreeAir<A> {
    fn width(&self) -> usize {
        self.0.width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        self.0.preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        self.0.preprocessed_width()
    }
    fn num_periodic_columns(&self) -> usize {
        self.0.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.0.periodic_columns()
    }
    fn periodic_values(&self, row_index: usize) -> Vec<Val> {
        self.0.periodic_values(row_index)
    }
    fn periodic_columns_matrix(&self) -> Option<RowMajorMatrix<Val>> {
        self.0.periodic_columns_matrix()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.0.preprocessed_next_row_columns()
    }
    fn num_constraints(&self) -> Option<usize> {
        self.0.num_constraints()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(CONSTRAINT_DEGREE)
    }
    fn num_public_values(&self) -> usize {
        self.0.num_public_values()
    }
}

impl<AB: AirBuilder<F = Val>, A: Air<AB>> Air<AB> for DegreeAir<A> {
    fn eval(&self, builder: &mut AB) {
        self.0.eval(builder);
    }
}

#[cfg(all(test, feature = "stream"))]
#[path = "air/tests.rs"]
mod tests;
