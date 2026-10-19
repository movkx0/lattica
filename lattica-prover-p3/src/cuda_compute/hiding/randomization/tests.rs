use super::*;
use crate::{
    config::{self, Challenger, Dft, MyCompress, MyHash, Val, ValMmcs},
    cuda_compute::{Commitments, FriField, Limits, Randoms},
};
use p3_commit::{ExtensionMmcs, Mmcs, Pcs};
use p3_field::{
    coset::TwoAdicMultiplicativeCoset as Domain, PrimeCharacteristicRing, PrimeField64,
    TwoAdicField,
};
use p3_fri::HidingFriPcs;
use p3_matrix::Matrix as _;
use p3_merkle_tree::MerkleCap;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 32 << 20,
            max_allocation_bytes: 8 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}

fn rng(seed: u8) -> ChaCha20Rng {
    let mut result = ChaCha20Rng::from_seed([seed; 32]);
    result.set_word_pos((1 << 36) - 1);
    result
}

fn mmcs() -> ValMmcs {
    let p = p3_goldilocks::default_goldilocks_poseidon2_8();
    ValMmcs::new(MyHash::new(p.clone()), MyCompress::new(p), 6, rng(71))
}

fn compare<F: FriField + TwoAdicField>(runtime: &Runtime) {
    type Cpu<F> = HidingFriPcs<Val, Dft, ValMmcs, ExtensionMmcs<Val, F, ValMmcs>, ChaCha20Rng>;
    let hiding = Hiding::new(runtime).unwrap();
    let commitments = Commitments::new(runtime).unwrap();
    let randoms = Randoms::new(runtime).unwrap();
    let private = randoms.import(rng(31)).unwrap();
    let salts = randoms.import(rng(71)).unwrap();
    let cpu = Cpu::<F>::new(
        Dft::default(),
        mmcs(),
        p3_fri::FriParameters {
            log_blowup: 4,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 128,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 16,
            mmcs: ExtensionMmcs::new(mmcs()),
        },
        config::NUM_RANDOM_CODEWORDS,
        rng(31),
    );
    // Repeated batches also compare continued sampling and salt cursor order.
    for _ in 0..2 {
        let before = runtime.snapshot();
        {
            let mut prepared = Vec::new();
            let mut domains = Vec::new();
            for (log, shift) in [(1, 1), (3, 7), (8, 13)] {
                prepared.push(
                    hiding
                        .prepare_randomization(log, shift, F::EXTENSION, &private, log + 4, 2)
                        .unwrap(),
                );
                domains.push(Domain::new(Val::from_u64(shift), log as usize).unwrap());
            }
            let (cap, data) =
                <Cpu<F> as Pcs<F, Challenger>>::get_opt_randomization_poly_commitment(
                    &cpu, domains,
                )
                .unwrap();
            let expected = mmcs().get_matrices(&data);
            for (input, matrix) in prepared.iter().zip(&expected) {
                for first in (0..input.plan.width).step_by(2) {
                    let columns = (input.plan.width - first).min(2);
                    let values = hiding
                        .with_randomization_lde(
                            input,
                            first,
                            columns,
                            RowOrder::BitReversed,
                            |tile| tile.read(1 << 20),
                        )
                        .unwrap();
                    let want: Vec<_> = matrix
                        .values
                        .chunks_exact(matrix.width)
                        .flat_map(|row| {
                            row[first..first + columns]
                                .iter()
                                .map(PrimeField64::as_canonical_u64)
                        })
                        .collect();
                    assert_eq!(values, want);
                }
            }
            let inputs: Vec<_> = prepared.iter().map(HidingInput::Randomization).collect();
            let native = hiding
                .commit_batch(&commitments, &inputs, &salts, 6)
                .unwrap();
            let raw = native.cap(1 << 20).unwrap();
            let digests: Vec<[Val; 4]> = raw
                .chunks_exact(4)
                .map(|words| std::array::from_fn(|i| Val::from_u64(words[i])))
                .collect();
            assert_eq!(MerkleCap::new(digests), cap);
            for (index, input) in prepared.iter().enumerate() {
                let shape = native.opening_shape(index).unwrap();
                assert_eq!(shape.prefix.log_rows, input.samples.spec.log_rows);
                assert_eq!(shape.lde.rows(), expected[index].height());
                assert_eq!(shape.random_columns, 4);
                assert_eq!(shape.lde.columns, 4 + F::DIMENSION);
            }
        }
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        private.check_live().unwrap();
        salts.check_live().unwrap();
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_randomization_commitments_match_upstream_for_extensions_and_cosets() {
    let runtime = runtime();
    compare::<config::Challenge>(&runtime);
    compare::<p3_field::extension::CubicTrinomialExtensionField<Val>>(&runtime);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_randomization_admission_and_consumer_failures_preserve_ownership() {
    let runtime = runtime();
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let private = randoms.import(rng(31)).unwrap();
    let before = runtime.snapshot();
    for (log, shift, extension, output, columns) in [
        (0, 1, Extension::Quadratic, 4, 2),
        (26, 1, Extension::Quadratic, 30, 2),
        (3, 0, Extension::Quadratic, 7, 2),
        (3, 1, Extension::Base, 7, 2),
        (3, 1, Extension::Quadratic, 2, 2),
        (3, 1, Extension::Quadratic, 26, 2),
        (3, 1, Extension::Quadratic, 7, 0),
        (3, 1, Extension::Quadratic, 7, 7),
    ] {
        assert!(hiding
            .prepare_randomization(log, shift, extension, &private, output, columns)
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
    let mut pressure = Vec::new();
    while runtime.snapshot().live_bytes + 1024 < 32 << 20 {
        let bytes = ((32 << 20) - runtime.snapshot().live_bytes - 1024).min(8 << 20);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    let pressured = runtime.snapshot();
    assert!(hiding
        .prepare_randomization(5, 1, Extension::Quadratic, &private, 9, 2)
        .is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    private.check_live().unwrap();
    let mut cpu_rng = rng(31);
    let expected: Vec<_> = (0..16)
        .map(|_| cpu_rng.random::<Val>().as_canonical_u64())
        .collect();
    assert_eq!(
        private
            .sample_fields(16)
            .unwrap()
            .read_for_test(128)
            .unwrap(),
        expected
    );

    for panic in [false, true] {
        let private = randoms.import(rng(32)).unwrap();
        let prepared = hiding
            .prepare_randomization(4, 13, Extension::Cubic, &private, 8, 2)
            .unwrap();
        let before = runtime.snapshot();
        assert!(hiding
            .with_randomization_lde(&prepared, usize::MAX, 1, RowOrder::Natural, |_| Ok(()))
            .is_err());
        assert_eq!(runtime.snapshot(), before);
        private.check_live().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hiding.with_randomization_lde::<()>(&prepared, 0, 2, RowOrder::Natural, |_| {
                if panic {
                    panic!("injected randomization consumer unwind");
                }
                Err("injected randomization consumer failure".into())
            })
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert!(private.check_live().is_err());
        let before = runtime.snapshot();
        assert!(hiding
            .with_randomization_lde(&prepared, 0, 2, RowOrder::Natural, |_| Ok(()))
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
}
