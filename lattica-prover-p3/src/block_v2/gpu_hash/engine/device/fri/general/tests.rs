use super::*;
use crate::block_v2::gpu_hash::{self, FriExtension};
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_matrix::dense::RowMajorMatrix;
use p3_util::reverse_slice_index_bits;

fn words<F: FriExtension>(values: &[F]) -> Vec<u64> {
    values
        .iter()
        .flat_map(|v| v.as_basis_coefficients_slice())
        .map(|v| v.as_canonical_u64())
        .collect()
}
fn value<F: FriExtension>(row: usize) -> F {
    F::from_basis_coefficients_fn(|c| {
        if (row + c) % 17 == 0 {
            -Val::ONE
        } else {
            Val::from_u64((row * 37 + c * 19 + 1) as u64)
        }
    })
}

fn arithmetic<F: FriExtension>(session: &DeviceSession) {
    let foreign = DeviceSession::new().unwrap();
    for log in [1u32, 4, 5, 9, 14] {
        let values: Vec<F> = (0..1 << log).map(value).collect();
        let spec = MatrixSpec::new(log, 1, F::DEVICE_EXTENSION, RowOrder::BitReversed, 1).unwrap();
        let input = session.upload(spec, &words(&values)).unwrap();
        for arity in 1..=4usize.min(log as usize) {
            let leaves = session.fri_leaves_with_arity(&input, arity).unwrap();
            assert_eq!(leaves.spec().columns(), 1 << arity);
            assert_eq!(leaves.spec().bytes(), input.spec().bytes());
            for beta in [
                F::ZERO,
                F::ONE,
                value::<F>(9),
                F::from_basis_coefficients_fn(|c| {
                    Val::from_u64(0xfedc_ba98_7654_3210u64.rotate_left(c as u32 * 17))
                }),
            ] {
                let encoding = words(&[beta]);
                let before = session.stats();
                let folded = session.fold_fri(&input, arity, &encoding).unwrap();
                let mixed = session
                    .mix_fri_with_arity(&folded, &folded, arity, &encoding)
                    .unwrap();
                assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
                assert_eq!(session.stats().downloaded_bytes, before.downloaded_bytes);
                let folding = TwoAdicFriFolding::<(), ()>(core::marker::PhantomData);
                let expected = <_ as FriFoldingStrategy<Val, F>>::fold_matrix(
                    &folding,
                    beta,
                    arity,
                    RowMajorMatrix::new(values.clone(), 1 << arity),
                );
                assert_eq!(session.read(&folded, 4 << 20).unwrap(), words(&expected));
                let expected: Vec<_> = expected
                    .into_iter()
                    .map(|v| v + beta.exp_power_of_2(arity) * v)
                    .collect();
                assert_eq!(session.read(&mixed, 4 << 20).unwrap(), words(&expected));
            }
        }
        let beta = words(&[value::<F>(2)]);
        let before = session.stats();
        assert!(session.fold_fri(&input, 0, &beta).is_err());
        assert!(session.fold_fri(&input, 5, &beta).is_err());
        assert!(session.fold_fri(&input, 1, &beta[..1]).is_err());
        let mut malformed = beta.clone();
        malformed[0] = GOLDILOCKS_MODULUS;
        assert!(session.fold_fri(&input, 1, &malformed).is_err());
        assert!(session.fri_leaves_with_arity(&input, 0).is_err());
        assert!(session.fri_leaves_with_arity(&input, 5).is_err());
        assert!(foreign.fold_fri(&input, 1, &beta).is_err());
        assert!(foreign.fri_leaves_with_arity(&input, 1).is_err());
        assert_eq!(before, session.stats());
        assert_eq!(session.read(&input, 4 << 20).unwrap(), words(&values));
    }
}

fn coefficients<F: FriExtension>(session: &DeviceSession) {
    let foreign = DeviceSession::new().unwrap();
    for log_len in [0usize, 1, 3, 7, 12] {
        let expected: Vec<F> = (0..1 << log_len).map(value).collect();
        let mut padded = expected.clone();
        padded.resize(1 << (log_len + 4), F::ZERO);
        let mut evals = Radix2DFTSmallBatch::<Val>::default().dft_algebra(padded);
        reverse_slice_index_bits(&mut evals);
        let spec = MatrixSpec::new(
            (log_len + 4) as u32,
            1,
            F::DEVICE_EXTENSION,
            RowOrder::BitReversed,
            1,
        )
        .unwrap();
        let input = session.upload(spec, &words(&evals)).unwrap();
        let bytes = expected.len() * F::DIMENSION * 8;
        let before = session.stats();
        assert!(session
            .final_polynomial_with_len(&input, 4, log_len, bytes - 1)
            .is_err());
        assert!(session
            .final_polynomial_with_len(&input, usize::MAX, log_len, bytes)
            .is_err());
        assert!(session
            .final_polynomial_with_len(&input, 4, 17, usize::MAX)
            .is_err());
        assert!(foreign
            .final_polynomial_with_len(&input, 4, log_len, bytes)
            .is_err());
        assert_eq!(before, session.stats());
        let actual = session
            .final_polynomial_with_len(&input, 4, log_len, bytes)
            .unwrap();
        assert_eq!(actual, words(&expected));
        assert_eq!(
            session.stats().downloaded_bytes - before.downloaded_bytes,
            bytes as u64
        );
        assert_eq!(
            session.stats().uploaded_bytes - before.uploaded_bytes,
            (if log_len == 0 { 8 } else { log_len * 8 }) as u64
        );
        assert_eq!(session.read(&input, 4 << 20).unwrap(), words(&evals));
    }
}

#[test]
#[ignore = "requires OpenCL GPU in a <=3 GiB zero-swap service"]
fn gpu_general_fri_arithmetic_matches_cpu_for_both_extensions_and_all_arities() {
    let _shutdown = gpu_hash::TestShutdownGuard;
    gpu_hash::initialize_from_env().unwrap();
    let session = DeviceSession::new().unwrap();
    arithmetic::<crate::config::Challenge>(&session);
    arithmetic::<crate::block_v2::profile::Challenge>(&session);
    coefficients::<crate::config::Challenge>(&session);
    coefficients::<crate::block_v2::profile::Challenge>(&session);
    assert!(session.stats().general_fri_folds > 0);
    assert!(session.stats().fold_device_ns > 0);
}
