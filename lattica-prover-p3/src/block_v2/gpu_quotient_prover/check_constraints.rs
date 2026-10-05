//! Adapted from p3-batch-stark 0.6.1 (Plonky3 contributors), Apache-2.0.
//! See LICENSE-APACHE in this directory. Original source SHA-256:
//! 199c6dedd321597e060aa295da397dfffc6fd52dff806f68695c09498033b561
//! Changes: upstream public types/helpers; quotient evaluations go to a
//! commitment callback; debug checks retained. Transcript and proof assembly
//! are unchanged. Only the explicit GPU quotient research switch selects this.
use p3_air::{Air, DebugConstraintBuilder};
use p3_field::{ExtensionField, Field};
use p3_lookup::{Lookup, LookupProtocol};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
use p3_matrix::stack::VerticalPair;
use p3_matrix::Matrix;
use tracing::instrument;

/// Type alias for the inputs to lookup constraint checking.
/// - The first element is a slice of [`Lookup`] values (generic over a field `F`) representing the symbolic lookups to be performed.
/// - The second element is a reference to the [`LookupProtocol`] implementation.
#[allow(unused)]
type LookupConstraintsInputs<'a, F, LG> = (&'a [Lookup<F>], &'a LG);

/// Runs constraint checks using a given [AIR](`p3_air::Air`) implementation and trace matrix.
///
/// Iterates over every row in `main`, providing both the current and next row
/// (with wraparound) to the [AIR](`p3_air::Air`) logic. Also injects public values into the builder
/// for first/last row assertions.
///
/// Collects all constraint failures for the first failing row, then panics with
/// a summary listing every violated constraint (index with optional label).
///
/// # Arguments
/// - `air`: The [AIR](`p3_air::Air`) logic to run.
/// - `main`: The [`RowMajorMatrix`] containing rows of witness values.
/// - `permutation`: The permutation [`RowMajorMatrix`] (rows of permutation values).
/// - `permutation_challenges`: The challenges used for the permutation argument.
/// - `public_values`: Public values provided to the builder.
/// - `lookup_constraints_inputs`: Inputs necessary to check lookup constraints:
///     - the symbolic representation of the [`Lookup`] values,
///     - the [`LookupProtocol`] implementation.
#[instrument(name = "check constraints", skip_all)]
#[allow(unused)] // Do not remove, or this will trigger warnings in release mode.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_constraints<'b, F, EF, A, LG>(
    air: &A,
    main: &RowMajorMatrix<F>,
    preprocessed: &Option<RowMajorMatrix<F>>,
    permutation: &RowMajorMatrix<EF>,
    permutation_challenges: &[EF],
    permutation_values: &[EF],
    public_values: &[F],
    lookup_constraints_inputs: LookupConstraintsInputs<'b, F, LG>,
) where
    F: Field,
    EF: ExtensionField<F>,
    A: for<'a> Air<DebugConstraintBuilder<'a, F, EF>>,
    LG: LookupProtocol,
{
    let height = main.height();
    if let Some(prep) = preprocessed.as_ref() {
        assert_eq!(
            prep.height(),
            height,
            "debug constraint check requires preprocessed trace height ({}) to match main trace height ({})",
            prep.height(),
            height
        );
    }
    assert_eq!(
        permutation.height(),
        height,
        "debug constraint check requires permutation trace height ({}) to match main trace height ({})",
        permutation.height(),
        height
    );

    let (lookups, lookup_gadget) = lookup_constraints_inputs;

    for row_index in 0..height {
        let row_index_next = (row_index + 1) % height;

        // Safety:
        // - row_index < height so we can use unchecked indexing.
        // - row_index_next < height so we can use unchecked indexing.
        let (local, next, prep_local, prep_next, perm_local, perm_next) = unsafe {
            (
                main.row_slice_unchecked(row_index),
                main.row_slice_unchecked(row_index_next),
                preprocessed
                    .as_ref()
                    .map(|p| p.row_slice_unchecked(row_index)),
                preprocessed
                    .as_ref()
                    .map(|p| p.row_slice_unchecked(row_index_next)),
                permutation.row_slice_unchecked(row_index),
                permutation.row_slice_unchecked(row_index_next),
            )
        };
        let main = VerticalPair::new(
            RowMajorMatrixView::new_row(&*local),
            RowMajorMatrixView::new_row(&*next),
        );

        let preprocessed = match (prep_local.as_ref(), prep_next.as_ref()) {
            (Some(l), Some(n)) => VerticalPair::new(
                RowMajorMatrixView::new_row(&**l),
                RowMajorMatrixView::new_row(&**n),
            ),
            _ => VerticalPair::new(
                RowMajorMatrixView::new(&[], 0),
                RowMajorMatrixView::new(&[], 0),
            ),
        };

        let permutation = VerticalPair::new(
            RowMajorMatrixView::new_row(&*perm_local),
            RowMajorMatrixView::new_row(&*perm_next),
        );

        let periodic_row = air.periodic_values(row_index);
        let mut builder = DebugConstraintBuilder::new_with_permutation(
            row_index,
            main,
            preprocessed,
            public_values,
            F::from_bool(row_index == 0),
            F::from_bool(row_index == height - 1),
            F::from_bool(row_index != height - 1),
            permutation,
            permutation_challenges,
            permutation_values,
            &periodic_row,
        );

        lookup_gadget.eval_air_and_lookups(air, &mut builder, lookups);

        // Stop at the first failing row and report all violations at once.
        if builder.has_failures() {
            let rendered = builder.formatted_failures();
            panic!(
                "constraints not satisfied on row {row_index}: \
                 failed constraints = {rendered}"
            );
        }
    }
}
