//! Research streaming candidate: build retained LDEs with bounded heap FFTs.
//! Used beneath HeapNormalizedDft; this component initially writes retained LDEs
//! through the spill allocator. Later normalization may change their residency.
use p3_dft::{Layout, Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::bitrev::BitReversibleMatrix;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_matrix::util::reverse_matrix_index_bits;
use p3_matrix::Matrix;

const MIN_INPUT_BYTES: usize = 64 << 20;
const MAX_INPUT_BYTES: usize = 1 << 30;
const MAX_INPUT_HEIGHT: usize = 1 << 21;
const MAX_ADDED_BITS: usize = 4;

#[derive(Clone, Default)]
pub struct BoundedCosetDft {
    forward: super::heap_dft::BoundedHeapDft,
    inner: Radix2DitParallel<Val>,
}

impl BoundedCosetDft {
    fn eligible(mat: &RowMajorMatrix<Val>, added_bits: usize) -> bool {
        mat.values
            .len()
            .checked_mul(core::mem::size_of::<Val>())
            .is_some_and(|bytes| (MIN_INPUT_BYTES..=MAX_INPUT_BYTES).contains(&bytes))
            && mat.height() <= MAX_INPUT_HEIGHT
            && added_bits <= MAX_ADDED_BITS
    }

    fn workspace_lde<T>(
        &self,
        mat: RowMajorMatrix<Val>,
        added_bits: usize,
        shift: Val,
        transform: T,
    ) -> <Self as TwoAdicSubgroupDft<Val>>::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, Val>, Layout),
    {
        let width = mat.width;
        let height = mat.height();
        assert!(height.is_power_of_two() && height <= MAX_INPUT_HEIGHT);
        assert!(added_bits <= MAX_ADDED_BITS);
        let cosets = 1usize << added_bits;
        let input_len = mat.values.len();
        let output_len = input_len.checked_mul(cosets).expect("LDE length overflow");
        let report = std::env::var("LATTICA_FFT_TRACE").is_ok_and(|v| v == "1");
        let started = report.then(std::time::Instant::now);
        if report {
            eprintln!("bounded_coset_lde_start input_bytes={} output_bytes={} width={width} added_bits={added_bits}", input_len * 8, output_len * 8);
        }
        let values = crate::spill_alloc::copy_to_heap(&mat.values, MAX_INPUT_BYTES)
            .expect("bounded coefficient workspace");
        drop(mat);
        let mut coefficients = self.inner.idft_batch(RowMajorMatrix::new(values, width));

        // Preserve upstream's callback layout, invocation count and RNG draw
        // ordering. The normal-order inverse is reordered only around this call.
        reverse_matrix_index_bits(&mut coefficients);
        transform(&mut coefficients.as_view_mut(), Layout::BitReversed);
        reverse_matrix_index_bits(&mut coefficients);

        // The retained LDE uses the ordinary allocator (mmap when spill is armed).
        // Only coefficients and one coset (<=1 GiB each) are explicit heap Vecs.
        // Twiddle caches and all other allocations remain subject to the process
        // limit; the workspace bound is not a claim about total prover memory.
        let mut output = RowMajorMatrix::new(Val::zero_vec(output_len), width);
        let generator = Val::two_adic_generator(height.ilog2() as usize + added_bits);
        for coset_index in 0..cosets {
            let values = crate::spill_alloc::copy_to_heap(&coefficients.values, MAX_INPUT_BYTES)
                .expect("bounded coset workspace");
            let evaluated = self.inner.coset_dft_batch(
                RowMajorMatrix::new(values, width),
                shift * generator.exp_u64(coset_index as u64),
            );
            // This removes the view, exposing its already bit-reversed storage;
            // it does not normalize the coset or allocate a retained heap LDE.
            let raw = evaluated.bit_reverse_rows().to_row_major_matrix();
            let start = p3_util::reverse_bits_len(coset_index, added_bits) * input_len;
            output.values[start..start + input_len].copy_from_slice(&raw.values);
        }
        if let Some(started) = started {
            eprintln!(
                "bounded_coset_lde_done elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
        output.bit_reverse_rows()
    }
}

impl TwoAdicSubgroupDft<Val> for BoundedCosetDft {
    type Evaluations = <Radix2DitParallel<Val> as TwoAdicSubgroupDft<Val>>::Evaluations;

    fn dft_batch(&self, mat: RowMajorMatrix<Val>) -> Self::Evaluations {
        self.forward.dft_batch(mat)
    }

    fn coset_lde_batch(
        &self,
        mat: RowMajorMatrix<Val>,
        added_bits: usize,
        shift: Val,
    ) -> Self::Evaluations {
        self.coset_lde_batch_with_transform(mat, added_bits, shift, |_, _| {})
    }

    fn coset_lde_batch_with_transform<T>(
        &self,
        mat: RowMajorMatrix<Val>,
        added_bits: usize,
        shift: Val,
        transform: T,
    ) -> Self::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, Val>, Layout),
    {
        if Self::eligible(&mat, added_bits) {
            self.workspace_lde(mat, added_bits, shift, transform)
        } else {
            self.inner
                .coset_lde_batch_with_transform(mat, added_bits, shift, transform)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeField64;

    fn input(height: usize, width: usize) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(
            (0..height * width)
                .map(|i| Val::from_u64((i as u64).wrapping_mul(0x9e3779b97f4a7c15).rotate_left(19)))
                .collect(),
            width,
        )
    }

    fn perturb(matrix: &mut RowMajorMatrixViewMut<'_, Val>, layout: Layout) {
        assert!(matches!(layout, Layout::BitReversed));
        for (i, v) in matrix.values.iter_mut().enumerate() {
            *v += Val::from_usize(i * 17 + 29);
        }
    }

    #[test]
    fn workspace_layout_callback_and_values_match_upstream() {
        for height in [1, 2, 16, 128] {
            for width in [1, 3, 7, 8, 94] {
                for added in 0..=4 {
                    let matrix = input(height, width);
                    let shift = Val::from_u64(17);
                    let expected = Radix2DitParallel::default()
                        .coset_lde_batch_with_transform(matrix.clone(), added, shift, perturb)
                        .to_row_major_matrix();
                    let mut calls = 0;
                    let actual = BoundedCosetDft::default()
                        .workspace_lde(matrix, added, shift, |m, layout| {
                            calls += 1;
                            perturb(m, layout);
                        })
                        .to_row_major_matrix();
                    assert_eq!(calls, 1);
                    assert_eq!(actual.width, expected.width);
                    assert_eq!(actual.values, expected.values);
                    for (a, b) in actual.values.iter().zip(&expected.values) {
                        assert_eq!(
                            a.as_canonical_u64().to_le_bytes(),
                            b.as_canonical_u64().to_le_bytes()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn retained_large_lde_stays_spilled_and_matches_upstream() {
        check_large(1 << 21, 7, true);
    }

    #[test]
    #[ignore = "wide spill test: run alone under 3 GiB RAM and 3 GiB mapped-spill caps"]
    fn wide_common_preprocessing_input_matches_upstream() {
        check_large(1 << 20, 70, true);
    }

    #[test]
    #[ignore = "wide reference test: run alone under a 3 GiB RAM cap with disk-backed scratch"]
    fn wide_disk_workspace_matches_resident_reference() {
        check_large(1 << 20, 70, false);
    }

    fn check_large(height: usize, width: usize, spill_reference: bool) {
        let _reference_scope = spill_reference.then(crate::spill_alloc::SpillScope::arm);
        let matrix = input(height, width);
        assert!(BoundedCosetDft::eligible(&matrix, 1));
        let shift = Val::from_u64(31);
        let started = std::time::Instant::now();
        let expected = Radix2DitParallel::default()
            .coset_lde_batch_with_transform(matrix.clone(), 1, shift, perturb)
            .bit_reverse_rows()
            .to_row_major_matrix();
        eprintln!(
            "reference_lde_ms={} height={height} width={width}",
            started.elapsed().as_millis()
        );
        let _candidate_scope = crate::spill_alloc::SpillScope::arm();
        let started = std::time::Instant::now();
        let actual = BoundedCosetDft::default()
            .coset_lde_batch_with_transform(matrix, 1, shift, perturb)
            .bit_reverse_rows()
            .to_row_major_matrix();
        eprintln!(
            "workspace_lde_ms={} height={height} width={width}",
            started.elapsed().as_millis()
        );
        assert_eq!(actual.width, expected.width);
        assert_eq!(actual.values.len(), expected.values.len());
        for (i, (a, b)) in actual.values.iter().zip(&expected.values).enumerate() {
            assert_eq!(a, b, "field at {i}");
            assert_eq!(
                a.as_canonical_u64().to_le_bytes(),
                b.as_canonical_u64().to_le_bytes(),
                "canonical bytes at {i}",
            );
        }
        // The candidate retained result is mapped; optionally the reference is
        // too. The resident-reference case avoids an intentionally slow mmap FFT.
        let mapped_results = if spill_reference { 2 } else { 1 };
        assert!(
            crate::spill_alloc::spill_stats().1
                >= mapped_results * (actual.values.len() * 8) as u64
        );
    }
}
