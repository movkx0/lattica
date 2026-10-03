//! Bounded heap workspace for temporary FFTs in the streaming candidate profile.
//! This component leaves coset LDE allocation unchanged; outer candidate wrappers
//! may choose different retention policies. No global allocator mode or
//! cryptographic parameter changes. This does not enable production recursion.
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};

const MIN_WORKSPACE: usize = 64 << 20;
const MAX_WORKSPACE: usize = 2 << 30;

#[derive(Clone, Default)]
pub struct BoundedHeapDft {
    inner: Radix2DitParallel<Val>,
}

impl TwoAdicSubgroupDft<Val> for BoundedHeapDft {
    type Evaluations = <Radix2DitParallel<Val> as TwoAdicSubgroupDft<Val>>::Evaluations;

    fn dft_batch(&self, mat: RowMajorMatrix<Val>) -> Self::Evaluations {
        let bytes = mat.values.len().checked_mul(core::mem::size_of::<Val>());
        let use_workspace = bytes.is_some_and(|n| (MIN_WORKSPACE..=MAX_WORKSPACE).contains(&n));
        // Opt-in diagnostics contain geometry/timing only, never field values.
        let report =
            use_workspace && std::env::var("LATTICA_FFT_TRACE").is_ok_and(|value| value == "1");
        let started = report.then(std::time::Instant::now);
        if report {
            eprintln!(
                "bounded_heap_fft_start bytes={} width={}",
                bytes.unwrap(),
                mat.width
            );
        }
        let mat = if use_workspace {
            let values = crate::spill_alloc::copy_to_heap(&mat.values, MAX_WORKSPACE)
                .expect("validated bounded FFT workspace");
            let width = mat.width;
            drop(mat);
            RowMajorMatrix::new(values, width)
        } else {
            mat
        };
        // The upstream transform and owned bit-reversal conversion are in-place:
        // the same bounded heap Vec remains owned by the temporary evaluation.
        let output = self.inner.dft_batch(mat);
        if let Some(started) = started {
            eprintln!(
                "bounded_heap_fft_done elapsed_ms={}",
                started.elapsed().as_millis()
            );
        }
        output
    }

    fn coset_lde_batch(
        &self,
        mat: RowMajorMatrix<Val>,
        added_bits: usize,
        shift: Val,
    ) -> Self::Evaluations {
        self.inner.coset_lde_batch(mat, added_bits, shift)
    }

    fn coset_lde_batch_with_transform<T>(
        &self,
        mat: RowMajorMatrix<Val>,
        added_bits: usize,
        shift: Val,
        transform: T,
    ) -> Self::Evaluations
    where
        T: FnOnce(&mut RowMajorMatrixViewMut<'_, Val>, p3_dft::Layout),
    {
        self.inner
            .coset_lde_batch_with_transform(mat, added_bits, shift, transform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spill_alloc::SpillScope;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::Matrix;

    #[test]
    fn bounded_large_fft_matches_upstream_with_spilling_armed() {
        // Both packed width 8 and the actual quotient-blinding width 7, with
        // inputs above the spill threshold and full-range field values.
        for (height, width) in [(1 << 20, 8), (1 << 21, 7)] {
            let values: Vec<_> = (0..height * width)
                .map(|i| Val::from_u64((i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)))
                .collect();
            let expected = Radix2DitParallel::<Val>::default()
                .dft_batch(RowMajorMatrix::new(values.clone(), width))
                .to_row_major_matrix();
            let _scope = SpillScope::arm();
            let mapped = values.clone();
            drop(values);
            let actual = BoundedHeapDft::default()
                .dft_batch(RowMajorMatrix::new(mapped, width))
                .to_row_major_matrix();
            assert_eq!(actual.width(), expected.width());
            assert_eq!(actual.values, expected.values);
            for (actual, expected) in actual.values.iter().zip(&expected.values) {
                assert_eq!(
                    actual.as_canonical_u64().to_le_bytes(),
                    expected.as_canonical_u64().to_le_bytes()
                );
            }
        }
    }

    #[test]
    fn delegated_coset_and_transform_match_upstream() {
        let input = RowMajorMatrix::new((0..96).map(Val::from_usize).collect(), 3);
        let shift = Val::from_u64(17);
        let expected = Radix2DitParallel::<Val>::default()
            .coset_lde_batch_with_transform(input.clone(), 2, shift, |m, _| {
                m.values[0] += Val::ONE;
            })
            .to_row_major_matrix();
        let actual = BoundedHeapDft::default()
            .coset_lde_batch_with_transform(input, 2, shift, |m, _| {
                m.values[0] += Val::ONE;
            })
            .to_row_major_matrix();
        assert_eq!(actual.values, expected.values);
    }
}
