//! Research streaming candidate for quotient-LDE normalization.
//!
//! Large main/preprocessing LDEs stay mapped. Explicitly normalizing a coset LDE
//! of 64 MiB..2 GiB moves it to the heap before the upstream in-place permutation.
//! That Vec remains heap-backed through later upstream reordering/retention.
//! This is NOT merely a 2 GiB temporary workspace: the common candidate shape
//! retains sixteen 896 MiB quotient LDEs (14 GiB total). The existing job-wide
//! RAM cap and a real end-to-end measurement remain mandatory. Selecting this
//! research profile does not establish a passed feasibility gate or activation.
use p3_dft::{Layout, TwoAdicSubgroupDft};
use p3_goldilocks::Goldilocks as Val;
use p3_matrix::bitrev::{BitReversedMatrixView, BitReversibleMatrix};
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_matrix::Matrix;

const MIN_NORMALIZATION: usize = 64 << 20;
const MAX_NORMALIZATION: usize = 2 << 30;

pub struct NormalizationEvaluations {
    inner: BitReversedMatrixView<RowMajorMatrix<Val>>,
    heap_normalization: bool,
}

impl Matrix<Val> for NormalizationEvaluations {
    fn width(&self) -> usize {
        self.inner.width()
    }
    fn height(&self) -> usize {
        self.inner.height()
    }

    unsafe fn row_subseq_unchecked(
        &self,
        row: usize,
        start: usize,
        end: usize,
    ) -> impl IntoIterator<Item = Val, IntoIter = impl Iterator<Item = Val> + Send + Sync> {
        // SAFETY: this wrapper preserves dimensions and row semantics exactly;
        // the caller's Matrix contract is the underlying view's contract.
        unsafe { self.inner.row_subseq_unchecked(row, start, end) }
    }

    fn to_row_major_matrix(self) -> RowMajorMatrix<Val> {
        let bytes = self
            .inner
            .inner
            .values
            .len()
            .checked_mul(core::mem::size_of::<Val>());
        if self.heap_normalization
            && bytes.is_some_and(|n| (MIN_NORMALIZATION..=MAX_NORMALIZATION).contains(&n))
        {
            let report = std::env::var("LATTICA_FFT_TRACE").is_ok_and(|v| v == "1");
            let started = report.then(std::time::Instant::now);
            if report {
                eprintln!("heap_lde_normalize_start bytes={}", bytes.unwrap());
            }
            // Cancelling the view exposes physical bit-reversed storage without
            // permuting it. Copy that storage, then delegate the exact upstream
            // permutation on its new heap allocation. No global spill suspension.
            let raw = self.inner.bit_reverse_rows();
            let values = crate::spill_alloc::copy_to_heap(&raw.values, MAX_NORMALIZATION)
                .expect("bounded normalization allocation");
            let width = raw.width;
            drop(raw);
            let output = RowMajorMatrix::new(values, width)
                .bit_reverse_rows()
                .to_row_major_matrix();
            if let Some(started) = started {
                eprintln!(
                    "heap_lde_normalize_done elapsed_ms={}",
                    started.elapsed().as_millis()
                );
            }
            output
        } else {
            self.inner.to_row_major_matrix()
        }
    }
}

impl BitReversibleMatrix<Val> for NormalizationEvaluations {
    type BitRev = RowMajorMatrix<Val>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        // PCS commitment asks for already bit-reversed storage. Do not move
        // retained main/preprocessing LDEs to the heap for this operation.
        self.inner.bit_reverse_rows()
    }
}

#[derive(Clone, Default)]
pub struct HeapNormalizedDft {
    inner: super::coset_workspace::BoundedCosetDft,
}

impl TwoAdicSubgroupDft<Val> for HeapNormalizedDft {
    type Evaluations = NormalizationEvaluations;

    fn dft_batch(&self, mat: RowMajorMatrix<Val>) -> Self::Evaluations {
        // BoundedCosetDft already uses BoundedHeapDft for large temporary DFTs.
        NormalizationEvaluations {
            inner: self.inner.dft_batch(mat),
            heap_normalization: false,
        }
    }

    fn coset_lde_batch(
        &self,
        mat: RowMajorMatrix<Val>,
        added_bits: usize,
        shift: Val,
    ) -> Self::Evaluations {
        NormalizationEvaluations {
            inner: self.inner.coset_lde_batch(mat, added_bits, shift),
            heap_normalization: true,
        }
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
        NormalizationEvaluations {
            inner: self
                .inner
                .coset_lde_batch_with_transform(mat, added_bits, shift, transform),
            heap_normalization: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_dft::Radix2DitParallel;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};

    type TestPcs<D> = p3_fri::HidingFriPcs<
        Val,
        D,
        crate::config::ValMmcs,
        p3_commit::ExtensionMmcs<Val, super::super::profile::Challenge, crate::config::ValMmcs>,
        rand_chacha::ChaCha20Rng,
    >;
    type TestConfig<D> = p3_uni_stark::StarkConfig<
        TestPcs<D>,
        super::super::profile::Challenge,
        crate::config::Challenger,
    >;

    // Fixed seeds exist ONLY in this test module. Candidate proof parameters are
    // reused verbatim; no reduced query count, grinding, or non-hiding fallback.
    fn seeded_config<D: TwoAdicSubgroupDft<Val>>(dft: D) -> TestConfig<D> {
        use super::super::profile;
        use crate::config::{Challenger, MyCompress, MyHash, ValMmcs};
        use rand::SeedableRng;
        let permutation = p3_goldilocks::default_goldilocks_poseidon2_8();
        let mmcs = ValMmcs::new(
            MyHash::new(permutation.clone()),
            MyCompress::new(permutation.clone()),
            profile::CAP_HEIGHT,
            rand_chacha::ChaCha20Rng::from_seed([37; 32]),
        );
        let extension_mmcs = p3_commit::ExtensionMmcs::new(mmcs.clone());
        TestConfig::<D>::new(
            TestPcs::<D>::new(
                dft,
                mmcs,
                profile::fri(extension_mmcs),
                profile::NUM_RANDOM_CODEWORDS,
                rand_chacha::ChaCha20Rng::from_seed([53; 32]),
            ),
            Challenger::new(permutation),
        )
    }

    struct RecurrenceAir;
    impl p3_air::BaseAir<Val> for RecurrenceAir {
        fn width(&self) -> usize {
            2
        }
        fn num_public_values(&self) -> usize {
            3
        }
    }
    impl<AB: p3_air::AirBuilder<F = Val>> p3_air::Air<AB> for RecurrenceAir {
        fn eval(&self, builder: &mut AB) {
            use p3_air::{AirBuilder, WindowAccess};
            let main = builder.main();
            let local = main.current_slice();
            let next = main.next_slice();
            let public = builder.public_values();
            let (a, b, last) = (public[0], public[1], public[2]);
            builder.when_first_row().assert_eq(local[0], a);
            builder.when_first_row().assert_eq(local[1], b);
            builder.when_transition().assert_eq(next[0], local[1]);
            builder
                .when_transition()
                .assert_eq(next[1], local[0] + local[1]);
            builder.when_last_row().assert_eq(local[0], last);
        }
    }

    #[test]
    fn full_strength_hiding_proofs_cross_verify_with_identical_commitments() {
        use super::super::{heap_dft::BoundedHeapDft, profile};
        let height = 1 << 16;
        let mut values = Vec::with_capacity(2 * height);
        let (mut a, mut b) = (Val::from_u64(3), Val::from_u64(5));
        for _ in 0..height {
            values.extend([a, b]);
            (a, b) = (b, a + b);
        }
        let public = [values[0], values[1], values[values.len() - 2]];
        let trace = RowMajorMatrix::new(values, 2);
        let baseline = seeded_config(BoundedHeapDft::default());
        let candidate = seeded_config(HeapNormalizedDft::default());
        let _scope = crate::spill_alloc::SpillScope::arm();
        let baseline_proof = p3_uni_stark::prove(&baseline, &RecurrenceAir, trace.clone(), &public);
        let candidate_proof = p3_uni_stark::prove(&candidate, &RecurrenceAir, trace, &public);
        let lde_bytes = (1usize << candidate_proof.degree_bits)
            * (1 << profile::LOG_BLOWUP)
            * (3 + profile::NUM_RANDOM_CODEWORDS)
            * 8;
        assert!((MIN_NORMALIZATION..=MAX_NORMALIZATION).contains(&lde_bytes));
        // Grinding may choose different valid nonces across Rayon schedules;
        // commitments precede query grinding and must match exactly.
        assert_eq!(
            postcard::to_allocvec(&baseline_proof.commitments).unwrap(),
            postcard::to_allocvec(&candidate_proof.commitments).unwrap()
        );
        let as_baseline: p3_uni_stark::Proof<TestConfig<BoundedHeapDft>> =
            postcard::from_bytes(&postcard::to_allocvec(&candidate_proof).unwrap()).unwrap();
        let as_candidate: p3_uni_stark::Proof<TestConfig<HeapNormalizedDft>> =
            postcard::from_bytes(&postcard::to_allocvec(&baseline_proof).unwrap()).unwrap();
        p3_uni_stark::verify(&baseline, &RecurrenceAir, &as_baseline, &public).unwrap();
        p3_uni_stark::verify(&candidate, &RecurrenceAir, &as_candidate, &public).unwrap();
        let mut wrong = public;
        wrong[2] += Val::ONE;
        assert!(p3_uni_stark::verify(&baseline, &RecurrenceAir, &as_baseline, &wrong).is_err());
        assert!(p3_uni_stark::verify(&candidate, &RecurrenceAir, &as_candidate, &wrong).is_err());
    }

    fn input(height: usize, width: usize) -> RowMajorMatrix<Val> {
        RowMajorMatrix::new(
            (0..height * width)
                .map(|i| {
                    Val::from_u64(match i % 8 {
                        0 => 0,
                        1 => 1,
                        2 => super::super::commitment::MODULUS - 1,
                        3 => u64::MAX,
                        _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15).rotate_left(23),
                    })
                })
                .collect(),
            width,
        )
    }

    fn equal(a: &RowMajorMatrix<Val>, b: &RowMajorMatrix<Val>) {
        assert_eq!(a.dimensions(), b.dimensions());
        for (i, (a, b)) in a.values.iter().zip(&b.values).enumerate() {
            assert_eq!(a, b, "field {i}");
            assert_eq!(
                a.as_canonical_u64().to_le_bytes(),
                b.as_canonical_u64().to_le_bytes(),
                "encoding {i}"
            );
        }
    }

    #[test]
    fn views_normalization_callbacks_and_commit_layout_match_upstream() {
        for height in [1, 2, 16, 128] {
            for width in [1, 7, 94] {
                for added in 0..=4 {
                    let matrix = input(height, width);
                    let shift = Val::from_u64(13);
                    let transform = |m: &mut RowMajorMatrixViewMut<'_, Val>, layout| {
                        assert!(matches!(layout, Layout::BitReversed));
                        m.values[0] += Val::ONE;
                    };
                    let expected = Radix2DitParallel::default().coset_lde_batch_with_transform(
                        matrix.clone(),
                        added,
                        shift,
                        transform,
                    );
                    let actual = HeapNormalizedDft::default().coset_lde_batch_with_transform(
                        matrix.clone(),
                        added,
                        shift,
                        transform,
                    );
                    assert_eq!(actual.dimensions(), expected.dimensions());
                    for r in 0..actual.height() {
                        for c in 0..width {
                            assert_eq!(actual.get(r, c), expected.get(r, c));
                        }
                    }
                    equal(
                        &actual.to_row_major_matrix(),
                        &expected.to_row_major_matrix(),
                    );
                    let expected = Radix2DitParallel::default()
                        .coset_lde_batch(matrix.clone(), added, shift)
                        .bit_reverse_rows()
                        .to_row_major_matrix();
                    let actual = HeapNormalizedDft::default()
                        .coset_lde_batch(matrix, added, shift)
                        .bit_reverse_rows()
                        .to_row_major_matrix();
                    equal(&actual, &expected);
                }
            }
        }
    }

    #[test]
    fn large_normalization_and_later_reordering_preserve_owned_values() {
        let matrix = input(1 << 17, 7);
        let shift = Val::from_u64(19);
        let expected = Radix2DitParallel::default()
            .coset_lde_batch(matrix.clone(), 4, shift)
            .to_row_major_matrix();
        let scope = crate::spill_alloc::SpillScope::arm();
        let actual = HeapNormalizedDft::default()
            .coset_lde_batch(matrix, 4, shift)
            .to_row_major_matrix();
        assert!((MIN_NORMALIZATION..=MAX_NORMALIZATION).contains(&(actual.values.len() * 8)));
        equal(&actual, &expected);
        let pointer = actual.values.as_ptr();
        drop(scope);
        let actual = actual.bit_reverse_rows().to_row_major_matrix();
        assert_eq!(
            pointer,
            actual.values.as_ptr(),
            "owned reordering must be in-place"
        );
        equal(&actual, &expected.bit_reverse_rows().to_row_major_matrix());
    }

    #[test]
    fn extracting_commit_layout_does_not_copy_or_permute() {
        let raw = input(16, 7);
        let pointer = raw.values.as_ptr();
        let expected = raw.clone();
        let view = NormalizationEvaluations {
            inner: raw.bit_reverse_rows(),
            heap_normalization: true,
        };
        let extracted = view.bit_reverse_rows();
        assert_eq!(pointer, extracted.values.as_ptr());
        equal(&extracted, &expected);
    }
}
