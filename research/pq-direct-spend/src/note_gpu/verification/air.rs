//! Metadata-only degree hint; every constraint and other AIR method delegates.
//! The exact degree is checked against independent reference symbolic inference.
use super::Val;
use lattica_prover_p3::joinsplit_air::JoinSplitAir;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_matrix::dense::RowMajorMatrix;

pub(super) const DEGREE: usize = 8;
pub(in crate::note_gpu) struct VerifierAir;

impl BaseAir<Val> for VerifierAir {
    fn width(&self) -> usize {
        JoinSplitAir.width()
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val>> {
        JoinSplitAir.preprocessed_trace()
    }
    fn preprocessed_width(&self) -> usize {
        JoinSplitAir.preprocessed_width()
    }
    fn num_periodic_columns(&self) -> usize {
        JoinSplitAir.num_periodic_columns()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        JoinSplitAir.periodic_columns()
    }
    fn periodic_values(&self, row: usize) -> Vec<Val> {
        JoinSplitAir.periodic_values(row)
    }
    fn periodic_columns_matrix(&self) -> Option<RowMajorMatrix<Val>> {
        JoinSplitAir.periodic_columns_matrix()
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        JoinSplitAir.main_next_row_columns()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        JoinSplitAir.preprocessed_next_row_columns()
    }
    fn num_constraints(&self) -> Option<usize> {
        JoinSplitAir.num_constraints()
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(DEGREE)
    }
    fn num_public_values(&self) -> usize {
        JoinSplitAir.num_public_values()
    }
}
impl<AB: AirBuilder<F = Val>> Air<AB> for VerifierAir {
    fn eval(&self, builder: &mut AB) {
        JoinSplitAir.eval(builder);
    }
}
