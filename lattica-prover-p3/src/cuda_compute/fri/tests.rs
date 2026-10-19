use super::*;
use crate::{
    config::{Challenger, Val},
    cuda_compute::{Limits, Transcripts},
};
use p3_challenger::{CanSample, FieldChallenger};
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding};
use p3_matrix::dense::RowMajorMatrix;

pub(super) fn runtime(managed: usize, allocation: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: allocation,
            ..Limits::default()
        },
    )
    .unwrap()
}
pub(super) fn words<F: ExtensionField<Val>>(values: &[F]) -> Vec<u64> {
    values
        .iter()
        .flat_map(|v| {
            v.as_basis_coefficients_slice()
                .iter()
                .map(PrimeField64::as_canonical_u64)
        })
        .collect()
}
pub(super) fn value<F: ExtensionField<Val>>(i: usize) -> F {
    F::from_basis_coefficients_fn(|j| {
        Val::from_u64(
            (i as u64)
                .wrapping_mul(0x9e3779b97f4a7c15)
                .wrapping_add((j * 19 + 1) as u64),
        )
    })
}
pub(super) fn upload<F: ExtensionField<Val>>(
    runtime: &Runtime,
    extension: Extension,
    log: u32,
    shift: u64,
    values: &[F],
) -> Matrix {
    runtime
        .upload_matrix(
            MatrixSpec::new(log, 1, extension, RowOrder::BitReversed, shift).unwrap(),
            &words(values),
        )
        .unwrap()
}

fn arithmetic<F: ExtensionField<Val>>(extension: Extension) {
    let runtime = runtime(16 << 20, 8 << 20);
    let fri = Fri::new(&runtime).unwrap();
    for log in [1, 4, 5, 9, 14] {
        let values: Vec<F> = (0..1 << log).map(value).collect();
        let original = upload(&runtime, extension, log, 7, &values);
        let before = runtime.snapshot();
        let vector = fri.rescale(&original).unwrap();
        assert_eq!(runtime.snapshot(), before);
        assert_eq!(original.spec.shift, 7);
        assert_eq!(vector.matrix.spec.shift, 1);
        for log_arity in 1..=4usize.min(log as usize) {
            let leaves = fri.leaves(&vector, log_arity).unwrap();
            assert_eq!(leaves.spec.columns, 1 << log_arity);
            assert_eq!(leaves.buffer.pointer(), original.buffer.pointer());
            for beta in [F::ZERO, F::ONE, value::<F>(9), value::<F>(137)] {
                let storage = runtime.allocate(extension.degree() + 4).unwrap();
                storage.write(2, &words(&[beta])).unwrap();
                let round = fri
                    .round(
                        extension,
                        log_arity,
                        FieldSpan {
                            buffer: &storage,
                            first: 2,
                        },
                    )
                    .unwrap();
                storage.write(2, &vec![0; extension.degree()]).unwrap();
                let before = runtime.snapshot();
                let folded = round.fold(&vector).unwrap();
                let mixed = round.mix(&folded, &folded).unwrap();
                assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
                assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
                let oracle = TwoAdicFriFolding::<(), ()>(core::marker::PhantomData);
                let expected = <_ as FriFoldingStrategy<Val, F>>::fold_matrix(
                    &oracle,
                    beta,
                    log_arity,
                    RowMajorMatrix::new(values.clone(), 1 << log_arity),
                );
                assert_eq!(folded.matrix.read(1 << 20).unwrap(), words(&expected));
                let expected: Vec<_> = expected
                    .iter()
                    .map(|&v| v + beta.exp_power_of_2(log_arity) * v)
                    .collect();
                assert_eq!(mixed.matrix.read(1 << 20).unwrap(), words(&expected));
            }
        }
        assert_eq!(original.read(1 << 20).unwrap(), words(&values));
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_quadratic_fri_folds_and_mixes_match_upstream_all_arities() {
    arithmetic::<crate::config::Challenge>(Extension::Quadratic);
}
#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_cubic_fri_folds_and_mixes_match_upstream_all_arities() {
    arithmetic::<p3_field::extension::CubicTrinomialExtensionField<Val>>(Extension::Cubic);
}

fn final_coefficients<F: ExtensionField<Val>>(extension: Extension) {
    let runtime = runtime(16 << 20, 8 << 20);
    let fri = Fri::new(&runtime).unwrap();
    let transcripts = Transcripts::new(&runtime).unwrap();
    for (log_final, log_blowup) in [(0, 4), (1, 4), (4, 4), (8, 4), (16, 0)] {
        let log = log_final + log_blowup;
        // FRI tests f(13*X); its final coefficients must contain the coset
        // rescaling, even though FRI folds use the unit subgroup's roots.
        let expected: Vec<F> = (0..1 << log_final)
            .map(|i| value::<F>(i) * Val::from_u64(13).exp_u64(i as u64))
            .collect();
        let mut padded = expected.clone();
        padded.resize(1 << log, F::ZERO);
        let natural = Radix2DFTSmallBatch::<Val>::default().dft_algebra(padded);
        let values: Vec<F> = (0usize..1 << log)
            .map(|i| natural[i.reverse_bits() >> (usize::BITS - log)])
            .collect();
        let original = upload(&runtime, extension, log, 13, &values);
        let vector = fri.rescale(&original).unwrap();
        let before = runtime.snapshot();
        let result = fri
            .final_polynomial(
                &vector,
                log_blowup as usize,
                log_final as usize,
                expected.len() * extension.degree() * 8,
            )
            .unwrap();
        assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
        assert_eq!(
            runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
            log_final as u64 * 8
        );
        assert_eq!(
            runtime.snapshot().live_bytes - before.live_bytes,
            expected.len() * extension.degree() * 8
        );
        let after = runtime.snapshot();
        assert!(result.read(result.words() * 8 - 1).is_err());
        assert_eq!(runtime.snapshot(), after);
        let mut transcript = transcripts.start().unwrap();
        let before_observe = runtime.snapshot();
        for first in (0..result.words()).step_by(crate::transcript_limits::BATCH_WORDS) {
            transcript
                .observe_resident(
                    result.span().buffer,
                    first,
                    (result.words() - first).min(crate::transcript_limits::BATCH_WORDS),
                )
                .unwrap();
        }
        assert_eq!(
            runtime.snapshot().downloaded_bytes,
            before_observe.downloaded_bytes
        );
        assert_eq!(
            runtime.snapshot().uploaded_bytes,
            before_observe.uploaded_bytes
        );
        let mut cpu = Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8());
        cpu.observe_algebra_slice(&expected);
        let expected_samples: Vec<_> = (0..7)
            .map(|_| {
                let v: Val = cpu.sample();
                v.as_canonical_u64()
            })
            .collect();
        assert_eq!(transcript.sample_fields(7).unwrap(), expected_samples);
        assert_eq!(result.read(result.words() * 8).unwrap(), words(&expected));
        assert_eq!(
            original.read(original.spec.bytes()).unwrap(),
            words(&values)
        );
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_final_polynomials_match_rescaled_cpu_coefficients_and_transcripts() {
    final_coefficients::<crate::config::Challenge>(Extension::Quadratic);
    final_coefficients::<p3_field::extension::CubicTrinomialExtensionField<Val>>(Extension::Cubic);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_queries_preserve_order_duplicates_and_aggregate_host_limits() {
    let runtime = runtime(1 << 20, 1 << 19);
    let fri = Fri::new(&runtime).unwrap();
    let spec = MatrixSpec::new(5, 8, Extension::Cubic, RowOrder::BitReversed, 1).unwrap();
    let raw: Vec<_> = (0..spec.words()).map(|i| (i * 137 + 17) as u64).collect();
    let input = runtime.upload_matrix(spec, &raw).unwrap();
    for count in [1, 33, 4096] {
        let indices: Vec<_> = (0..count).map(|i| [31, 0, 17, 31][i % 4]).collect();
        let output_bytes = count * 24 * 8;
        let host_bytes = output_bytes + count * 8;
        let before = runtime.snapshot();
        assert!(fri.gather(&input, &indices, host_bytes - 1).is_err());
        assert_eq!(runtime.snapshot(), before);
        // The largest batch exceeds the intentionally small per-allocation cap.
        if output_bytes > 1 << 19 {
            assert!(fri.gather(&input, &indices, host_bytes).is_err());
            assert_eq!(runtime.snapshot(), before);
            continue;
        }
        let actual = fri.gather(&input, &indices, host_bytes).unwrap();
        let expected: Vec<_> = indices
            .iter()
            .flat_map(|&i| raw[i * 24..(i + 1) * 24].iter().copied())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            output_bytes as u64
        );
        assert_eq!(
            runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
            (count * 8) as u64
        );
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    }
    let before = runtime.snapshot();
    for indices in [vec![], vec![32], vec![0; 4097]] {
        assert!(fri.gather(&input, &indices, 2 << 20).is_err());
    }
    assert_eq!(runtime.snapshot(), before);
    let narrow_spec = MatrixSpec::new(5, 1, Extension::Cubic, RowOrder::BitReversed, 1).unwrap();
    let narrow = runtime
        .upload_matrix(narrow_spec, &raw[..narrow_spec.words()])
        .unwrap();
    let indices: Vec<_> = (0..4096).map(|i| [31, 0, 17, 31][i % 4]).collect();
    let before = runtime.snapshot();
    let result = fri.gather(&narrow, &indices, 4096 * 4 * 8).unwrap();
    let expected: Vec<_> = indices
        .iter()
        .flat_map(|&i| raw[i * 3..(i + 1) * 3].iter().copied())
        .collect();
    assert_eq!(result, expected);
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        4096 * 3 * 8
    );
    assert_eq!(
        runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
        4096 * 8
    );
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_fri_rejects_geometry_and_storage_before_work() {
    let runtime = runtime(64 << 10, 32 << 10);
    let fri = Fri::new(&runtime).unwrap();
    let values: Vec<crate::config::Challenge> = (0..16).map(value).collect();
    let source = upload(&runtime, Extension::Quadratic, 4, 7, &values);
    let vector = fri.rescale(&source).unwrap();
    let beta = runtime.allocate(2).unwrap();
    beta.write(0, &[17, 19]).unwrap();
    let span = FieldSpan {
        buffer: &beta,
        first: 0,
    };
    let before = runtime.snapshot();
    for arity in [0, 5, usize::MAX] {
        assert!(fri.leaves(&vector, arity).is_err());
        assert!(fri.round(Extension::Quadratic, arity, span).is_err());
    }
    assert!(fri.round(Extension::Base, 1, span).is_err());
    assert!(fri
        .round(
            Extension::Quadratic,
            1,
            FieldSpan {
                first: usize::MAX,
                ..span
            }
        )
        .is_err());
    for (blowup, final_len, allowance) in [
        (4, 1, 1024),
        (3, 1, 31),
        (usize::MAX, 0, 1024),
        (0, 17, usize::MAX),
    ] {
        assert!(fri
            .final_polynomial(&vector, blowup, final_len, allowance)
            .is_err());
    }
    assert_eq!(runtime.snapshot(), before);
    let round = fri.round(Extension::Quadratic, 2, span).unwrap();
    let mut pressure = Vec::new();
    while runtime.snapshot().live_bytes + 8 <= 64 << 10 {
        let bytes = ((64 << 10) - runtime.snapshot().live_bytes).min(32 << 10);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    let pressured = runtime.snapshot();
    assert!(round.fold(&vector).is_err());
    assert!(fri.final_polynomial(&vector, 3, 1, 32).is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    round.fold(&vector).unwrap();
    fri.final_polynomial(&vector, 3, 1, 32).unwrap();
}

#[test]
#[ignore = "requires NVRTC"]
fn cuda_fri_source_compiles_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
