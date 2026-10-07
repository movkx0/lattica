//! Candidate-only opening adapter, derived from Plonky3 p3-fri 0.6.1
//! two_adic_pcs.rs (MIT OR Apache-2.0). Evaluation/challenger order and the
//! upstream FRI prover are preserved; only matrix quotient reduction changes.
//! Not production-qualified. The CPU verifier and serialized proof are unchanged.
use super::batched_fri as prover;
use super::gpu_hash::{reduce_openings, CandidateMmcs, OpeningMatrix, OpeningTerm};
use super::profile::{Challenge, ChallengeMmcs};
use super::resident_pcs::ResidentInner;
use crate::config::{Challenger, Val};
use p3_challenger::FieldChallenger;
use p3_commit::{Mmcs, OpenedValues, Pcs};
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{
    batch_multiplicative_inverse, dot_product, ExtensionField, Field, PrimeCharacteristicRing,
    TwoAdicField,
};
use p3_fri::{FriParameters, TwoAdicFriFolding, TwoAdicFriFoldingForMmcs};
use p3_matrix::interpolation::{compute_adjusted_weights, Interpolate};
use p3_matrix::{
    dense::{RowMajorMatrix, RowMajorMatrixView},
    Matrix,
};
use p3_util::{linear_map::LinearMap, log2_strict_usize, reverse_slice_index_bits};
use std::marker::PhantomData;
use tracing::debug_span;

type ProverData = <CandidateMmcs as Mmcs<Val>>::ProverData<RowMajorMatrix<Val>>;
type HidingProof = <ResidentInner as Pcs<Challenge, Challenger>>::Proof;
type InnerPcs = p3_fri::TwoAdicFriPcs<Val, crate::config::Dft, CandidateMmcs, ChallengeMmcs>;
type InnerProof = <InnerPcs as Pcs<Challenge, Challenger>>::Proof;

/// A stored prefix and its independent committed height. This deliberately
/// does not implement Matrix with a fictitious full row range.
#[derive(Clone)]
struct PrefixView<'a, F> {
    matrix: RowMajorMatrixView<'a, F>,
    height: usize,
}
impl<'a, F> std::ops::Deref for PrefixView<'a, F> {
    type Target = RowMajorMatrixView<'a, F>;
    fn deref(&self) -> &Self::Target {
        &self.matrix
    }
}
impl<F> PrefixView<'_, F> {
    fn height(&self) -> usize {
        self.height
    }
}

/// This FRI-MMCS belongs to one shared proof attempt. Never clone it per call:
/// the salt stream must advance across active PCS clones.
#[tracing::instrument(target = "lattica_block_v2_perf", name = "GPU opening proof", skip_all)]
pub(super) fn open_hiding(
    mmcs: &CandidateMmcs,
    fri: &FriParameters<ChallengeMmcs>,
    rounds: Vec<(&ProverData, Vec<Vec<Challenge>>)>,
    challenger: &mut Challenger,
    is_preprocessing: bool,
    random_columns: usize,
) -> (OpenedValues<Challenge>, HidingProof) {
    let (mut values, proof) = open(mmcs, fri, rounds, challenger);
    let random_values = values
        .iter_mut()
        .enumerate()
        .map(|(round, matrices)| {
            matrices
                .iter_mut()
                .map(|points| {
                    points
                        .iter_mut()
                        .map(|values| {
                            let count = if is_preprocessing &&
                    round == <ResidentInner as Pcs<Challenge, Challenger>>::PREPROCESSED_TRACE_IDX {
                    0
                } else { random_columns };
                            let split = values
                                .len()
                                .checked_sub(count)
                                .expect("hiding opening width");
                            values.drain(split..).collect()
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    (values, (random_values, proof))
}

fn validate_shapes(
    matrices: &[(Vec<PrefixView<'_, Val>>, &Vec<Vec<Challenge>>)],
) -> Result<(), &'static str> {
    let mut max_height = 0usize;
    let mut point_heights = Vec::<(Challenge, usize)>::new();
    let mut heights = std::collections::BTreeSet::new();
    let mut count = 0usize;
    let mut opened_elements = 0usize;
    for (mats, points) in matrices {
        if mats.len() != points.len() || mats.is_empty() {
            return Err("opening matrix/point count");
        }
        for (mat, points) in mats.iter().zip(points.iter()) {
            count += 1;
            if count > 256
                || mat.width() == 0
                || mat.width() > 4096
                || mat.matrix.height() < (mat.height() >> super::profile::LOG_BLOWUP)
                || mat.height() < (1 << super::profile::LOG_BLOWUP)
                || !mat.height().is_power_of_two()
                || mat.height() > (1 << 25)
                || points.is_empty()
                || points.len() > 32
            {
                return Err("opening matrix/point dimensions");
            }
            max_height = max_height.max(mat.height());
            opened_elements += mat.width() * points.len();
            heights.insert(mat.height());
            for point in points {
                if *point == Challenge::ZERO {
                    return Err("zero opening point");
                }
                if let Some((_, height)) = point_heights.iter_mut().find(|(p, _)| p == point) {
                    *height = (*height).max(mat.height());
                } else {
                    if point_heights.len() == 32 {
                        return Err("opening distinct point bound");
                    }
                    point_heights.push((*point, mat.height()));
                }
            }
        }
    }
    if count == 0 {
        return Err("empty opening");
    }
    // Vector payloads: coset + inverse/adjusted weights + conservative
    // batch-inverse scratch + FRI inputs + every opened value (including repeated
    // points). Bounded GPU tile staging is admitted separately; this is not RSS.
    let bytes = host_vector_bytes(
        max_height,
        point_heights.iter().map(|(_, h)| *h).sum(),
        heights.iter().sum(),
        opened_elements,
    )
    // Bound cache planning metadata and allocation handles as well as vectors.
    .and_then(|bytes| bytes.checked_add(64 << 10))
    .ok_or("opening host workspace overflow")?;
    if bytes > (4usize << 30) {
        return Err("opening host workspace allowance");
    }
    Ok(())
}

fn host_vector_bytes(
    max_height: usize,
    point_rows: usize,
    fri_rows: usize,
    opened_elements: usize,
) -> Option<usize> {
    max_height
        .checked_mul(56)?
        .checked_add(point_rows.checked_mul(48)?)?
        .checked_add(fri_rows.checked_mul(24)?)?
        .checked_add(opened_elements.checked_mul(24)?)
}

fn open(
    mmcs: &CandidateMmcs,
    fri: &FriParameters<ChallengeMmcs>,
    commitment_data_with_opening_points: Vec<(&ProverData, Vec<Vec<Challenge>>)>,
    challenger: &mut Challenger,
) -> (OpenedValues<Challenge>, InnerProof) {
    /*

    A quick rundown of the optimizations in this function:
    We are trying to compute sum_i alpha^i * (p(X) - y)/(X - z),
    for each z an opening point, y = p(z). Each p(X) is given as evaluations in bit-reversed order
    in the columns of the matrices. y is computed by barycentric interpolation.
    X and p(X) are in the base field; alpha, y and z are in the extension.
    The primary goal is to minimize extension multiplications.

    - Instead of computing all alpha^i, we just compute alpha^i for i up to the largest width
    of a matrix, then multiply by an "alpha offset" when accumulating.
          a^0 x0 + a^1 x1 + a^2 x2 + a^3 x3 + ...
        = ( a^0 x0 + a^1 x1 ) + a^2 ( a^0 x2 + a^1 x3 ) + ...
        (see `alpha_pows`, `alpha_pow_offset`, `num_reduced`)

    - For each unique point z, we precompute 1/(X-z) for the largest subgroup opened at this point.
    Since we compute it in bit-reversed order, smaller subgroups can simply truncate the vector.
        (see `inv_denoms`)

    - Then, for each matrix (with columns p_i) and opening point z, we want:
        for each row (corresponding to subgroup element X):
            reduced[X] += alpha_offset * sum_i [ alpha^i * inv_denom[X] * (p_i[X] - y[i]) ]

        We can factor out inv_denom, and expand what's left:
            reduced[X] += alpha_offset * inv_denom[X] * sum_i [ alpha^i * p_i[X] - alpha^i * y[i] ]

        And separate the sum:
            reduced[X] += alpha_offset * inv_denom[X] * [ sum_i [ alpha^i * p_i[X] ] - sum_i [ alpha^i * y[i] ] ]

        And now the last sum doesn't depend on X, so we can precompute that for the matrix, too.
        So the hot loop (that depends on both X and i) is just:
            sum_i [ alpha^i * p_i[X] ]

        with alpha^i an extension, p_i[X] a base

    */

    // Contained in each `Self::ProverData` is a list of matrices which have been committed to.
    // We extract those matrices to be able to refer to them directly.
    let mats_and_points = commitment_data_with_opening_points
        .iter()
        .map(|(data, points)| {
            let mats = mmcs
                .prefix_matrices(data)
                .into_iter()
                .map(|(m, height)| PrefixView { matrix: m, height })
                .collect::<Vec<_>>();
            debug_assert_eq!(
                mats.len(),
                points.len(),
                "each matrix should have a corresponding set of evaluation points"
            );
            (mats, points)
        })
        .collect::<Vec<_>>();

    // Find the maximum height and the maximum width of matrices in the batch.
    // These do not need to correspond to the same matrix.
    let (global_max_height, _global_max_width) = mats_and_points
        .iter()
        .flat_map(|(mats, _)| mats.iter().map(|m| (m.height(), m.width())))
        .reduce(|(hmax, wmax), (h, w)| (hmax.max(h), wmax.max(w)))
        .expect("No Matrices Supplied?");
    validate_shapes(&mats_and_points).expect("candidate opening dimensions/admission");
    let log_global_max_height = log2_strict_usize(global_max_height);

    // Get all values of the coset `gH` for the largest necessary subgroup `H`.
    // We also bit reverse which means that coset has the nice property that
    // `coset[..2^i]` contains the values of `gK` for `|K| = 2^i`.
    let coset = {
        let coset = TwoAdicMultiplicativeCoset::new(Val::GENERATOR, log_global_max_height).unwrap();
        let mut coset_points = coset.iter().collect();
        reverse_slice_index_bits(&mut coset_points);
        coset_points
    };

    // For each unique opening point z, we will find the largest degree bound
    // for that point, and precompute 1/(z - X) for the largest subgroup (in bitrev order).
    let inv_denoms = compute_inverse_denominators(&mats_and_points, &coset);

    // Precompute adjusted barycentric weights once per opening point.
    // adjusted[i] = 1/(z - x_i) - 1/z, reused across all matrices opened at z.
    let adjusted_weights: LinearMap<Challenge, Vec<Challenge>> = inv_denoms
        .iter()
        .map(|(point, denoms)| (*point, compute_adjusted_weights(*point, denoms)))
        .collect();

    // Evaluate coset representations and write openings to the challenger
    let all_opened_values = mats_and_points
        .iter()
        .map(|(mats, points)| {
            // For each collection of matrices
            mats.iter()
                .zip(points.iter())
                .map(|(mat, points_for_mat)| {
                    // Every committed matrix is assumed to be an LDE at `fri.log_blowup`;
                    // `commit`/`commit_ldes` enforce `height >= 1 << log_blowup`. A larger actual
                    // blowup is still sound, just slightly slower.
                    // Ideally, polynomials would be passed in with their blow-up factors known.

                    // The point of this correction is that each column of the matrix corresponds to a low degree polynomial.
                    // Hence we can save time by restricting the height of the matrix to be the minimal height which
                    // uniquely identifies the polynomial.
                    let h = mat.height() >> fri.log_blowup;

                    // `subgroup` and `mat` are both in bit-reversed order, so we can truncate.
                    let (low_coset, _) = mat.split_rows(h);

                    points_for_mat
                        .iter()
                        .map(|&point| {
                            let _guard =
                                debug_span!("evaluate matrix", dims = %mat.dimensions()).entered();

                            // Use Barycentric interpolation to evaluate each column of the matrix at the given point.
                            let ys =
                                debug_span!("compute opened values with Lagrange interpolation")
                                    .in_scope(|| {
                                        // Slice the precomputed adjusted weights to match this matrix's height.
                                        // Zero-allocation hot path: straight to the SIMD dot product.
                                        let adj = &adjusted_weights.get(&point).unwrap()[..h];
                                        low_coset.interpolate_coset_with_precomputation(
                                            Val::GENERATOR,
                                            point,
                                            adj,
                                        )
                                    });

                            challenger.observe_algebra_slice(&ys);
                            ys
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // Batch combination challenge

    // Soundness Error:
    // See the discussion in the doc comment of [`prove_fri`]. Essentially, the soundness error
    // for this sample is tightly tied to the soundness error of the FRI protocol.
    // Roughly speaking, at a minimum is it k/|EF| where `k` is the sum of, for each function, the number of
    // points it needs to be opened at. This comes from the fact that we are taking a large linear combination
    // of `(f(zeta) - f(x))/(zeta - x)` for each function `f` and all of `f`'s opening points.
    // In our setup, k is two times the trace width plus the number of quotient polynomials.
    let alpha: Challenge = challenger.sample_algebra_element();

    // Preserve upstream per-height alpha offsets and matrix/point ordering.
    // Wide compression and all point reductions share one tiled GPU input.
    let mut num_reduced = [0usize; 32];
    let mut requests = Vec::new();
    for ((mats, points), opened_round) in mats_and_points.iter().zip(&all_opened_values) {
        for ((mat, points_for_mat), opened_mat) in mats.iter().zip(points.iter()).zip(opened_round)
        {
            let log_height = log2_strict_usize(mat.height());
            let mut terms = Vec::with_capacity(points_for_mat.len());
            for (&point, openings) in points_for_mat.iter().zip(opened_mat) {
                terms.push(OpeningTerm {
                    inverse_denominators: inv_denoms.get(&point).unwrap(),
                    alpha_offset: alpha.exp_u64(num_reduced[log_height] as u64),
                    opened: dot_product(alpha.powers(), openings.iter().copied()),
                });
                num_reduced[log_height] += mat.width();
            }
            requests.push(OpeningMatrix {
                values: mat.values,
                width: mat.width(),
                height: mat.height(),
                terms,
            });
        }
    }
    // All matrices were committed as degree-bounded LDEs, including hiding
    // columns. Compact reconstruction is allowed only AFTER this alpha sample.
    let fri_input = reduce_openings(&requests, alpha, fri.log_blowup)
        .expect("candidate GPU opening reduction failed; no silent fallback");

    let folding: TwoAdicFriFoldingForMmcs<Val, CandidateMmcs> = TwoAdicFriFolding(PhantomData);

    // Produce the FRI proof.
    let fri_proof = prover::prove_fri(
        &folding,
        fri,
        fri_input,
        challenger,
        log_global_max_height,
        &commitment_data_with_opening_points,
        mmcs,
        |indices| {
            for (data, _) in &commitment_data_with_opening_points {
                let shift = log_global_max_height - log2_strict_usize(mmcs.get_max_height(data));
                let local: Vec<_> = indices.iter().map(|i| i >> shift).collect();
                mmcs.prepare_queries(data, &local)
                    .expect("compact query reconstruction failed");
            }
        },
    );

    (all_opened_values, fri_proof)
}

fn compute_inverse_denominators<F: TwoAdicField, EF: ExtensionField<F>>(
    mats_and_points: &[(Vec<PrefixView<'_, F>>, &Vec<Vec<EF>>)],
    coset: &[F],
) -> LinearMap<EF, Vec<EF>> {
    // For each `z`, find the maximal height of any matrix which we need to
    // open at `z`.
    let mut max_log_height_for_point: LinearMap<EF, usize> = LinearMap::new();
    for (mats, points) in mats_and_points {
        for (mat, points_for_mat) in mats.iter().zip(points.iter()) {
            let log_height = log2_strict_usize(mat.height());
            for &z in points_for_mat {
                if let Some(lh) = max_log_height_for_point.get_mut(&z) {
                    *lh = core::cmp::max(*lh, log_height);
                } else {
                    max_log_height_for_point.insert(z, log_height);
                }
            }
        }
    }

    // Compute the inverse denominators for each point `z`.
    max_log_height_for_point
        .into_iter()
        .map(|(z, log_height)| {
            (
                z,
                batch_multiplicative_inverse(
                    // As coset is stored in bit-reversed order,
                    // we can just take the first `2^log_height` elements.
                    &coset[..(1 << log_height)]
                        .iter()
                        .map(|&x| z - x)
                        .collect::<Vec<_>>(),
                ),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opening_host_budget_includes_opened_values_and_rejects_overflow() {
        let h = 1 << 25;
        assert_eq!(host_vector_bytes(h, h, h, 0), Some(4usize << 30));
        assert!(host_vector_bytes(h, h, h, 1).unwrap() > (4usize << 30));
        assert_eq!(host_vector_bytes(usize::MAX, 1, 1, 1), None);
        assert_eq!(host_vector_bytes(16, 32, 16, usize::MAX), None);
    }
    #[test]
    fn opening_adapter_rejects_mismatched_or_unbounded_inputs() {
        let matrix = RowMajorMatrix::new(vec![Val::ONE; 64 * 3], 3);
        let points = vec![vec![Challenge::from_u64(11)]];
        assert!(validate_shapes(&[(
            vec![PrefixView {
                matrix: matrix.as_view(),
                height: matrix.height()
            }],
            &points
        )])
        .is_ok());
        assert!(validate_shapes(&[]).is_err());
        let missing = vec![];
        assert!(validate_shapes(&[(
            vec![PrefixView {
                matrix: matrix.as_view(),
                height: matrix.height()
            }],
            &missing
        )])
        .is_err());
        let zero = vec![vec![Challenge::ZERO]];
        assert!(validate_shapes(&[(
            vec![PrefixView {
                matrix: matrix.as_view(),
                height: matrix.height()
            }],
            &zero
        )])
        .is_err());
        let too_many = vec![vec![Challenge::ONE; 33]];
        assert!(validate_shapes(&[(
            vec![PrefixView {
                matrix: matrix.as_view(),
                height: matrix.height()
            }],
            &too_many
        )])
        .is_err());
        let small = RowMajorMatrix::new(vec![Val::ONE; 8 * 3], 3);
        assert!(validate_shapes(&[(
            vec![PrefixView {
                matrix: small.as_view(),
                height: small.height()
            }],
            &points
        )])
        .is_err());
        let odd = RowMajorMatrix::new(vec![Val::ONE; 63 * 3], 3);
        assert!(validate_shapes(&[(
            vec![PrefixView {
                matrix: odd.as_view(),
                height: odd.height()
            }],
            &points
        )])
        .is_err());
    }
}
