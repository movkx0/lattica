use super::*;
use crate::{
    config::{self, Challenge, Challenger, Dft, MyCompress, MyHash, MyPcs, Val, ValMmcs},
    cuda_compute::{Commitments, Limits, Randoms, Snapshot},
    gpu_matrix::GOLDILOCKS_MODULUS as P,
};
use p3_commit::{Mmcs, Pcs, PolynomialSpace};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{
    coset::TwoAdicMultiplicativeCoset as Domain, Field, PrimeCharacteristicRing, PrimeField64,
};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn runtime(managed: usize, allocation: usize) -> Runtime {
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
fn spec(log: u32, columns: usize, extension: Extension, shift: u64) -> MatrixSpec {
    MatrixSpec::new(log, columns, extension, RowOrder::Natural, shift).unwrap()
}
fn words(n: usize) -> Vec<u64> {
    (0..n)
        .map(|i| match i % 7 {
            0 => 0,
            1 => P,
            2 => u64::MAX,
            3 => P - 1,
            _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15),
        })
        .collect()
}
fn matrix(raw: &[u64], width: usize) -> RowMajorMatrix<Val> {
    RowMajorMatrix::new(raw.iter().map(|&v| Val::from_u64(v)).collect(), width)
}
fn canonical(values: &[Val]) -> Vec<u64> {
    values.iter().map(PrimeField64::as_canonical_u64).collect()
}
fn rng() -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed([87; 32]);
    rng.set_stream(13);
    rng.set_word_pos((1 << 36) - 1);
    rng
}
fn pcs(rng: ChaCha20Rng) -> (MyPcs, ValMmcs) {
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    let mmcs = ValMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm),
        config::CAP_HEIGHT,
        ChaCha20Rng::from_seed([17; 32]),
    );
    let pcs = MyPcs::new(
        Dft::default(),
        mmcs.clone(),
        config::production_fri(config::ChallengeMmcs::new(mmcs.clone())),
        config::NUM_RANDOM_CODEWORDS,
        rng,
    );
    (pcs, mmcs)
}
fn physical(row: usize, log: u32, order: RowOrder) -> usize {
    if order == RowOrder::Natural {
        row
    } else {
        row.reverse_bits() >> (usize::BITS - log)
    }
}
fn tile(
    reference: &RowMajorMatrix<Val>,
    first: usize,
    columns: usize,
    reference_order: RowOrder,
    order: RowOrder,
) -> Vec<u64> {
    let log = reference.height().ilog2();
    (0..reference.height())
        .flat_map(|row| {
            let natural = physical(row, log, order);
            let source = physical(natural, log, reference_order);
            canonical(
                &reference.values
                    [source * reference.width + first..source * reference.width + first + columns],
            )
        })
        .collect()
}
fn next_samples(random: &DeviceRandom, cpu: &mut ChaCha20Rng) {
    let expected: Vec<_> = (0..37)
        .map(|_| cpu.random::<Val>().as_canonical_u64())
        .collect();
    assert_eq!(
        random
            .sample_fields(37)
            .unwrap()
            .read_for_test(37 * 8)
            .unwrap(),
        expected
    );
}

#[test]
fn hiding_plans_reject_geometry_overflow_and_charge_both_stage_peaks() {
    let p = TilePlan::new(8, 19, 13, 3, false).unwrap();
    let scratch = p.scratch().unwrap();
    let bytes = scratch.iter().sum::<usize>() * 8;
    let state = Snapshot {
        live_bytes: 71,
        allocations: 2,
        ..Snapshot::default()
    };
    let limits = Limits {
        managed_bytes: bytes + 71,
        max_allocation_bytes: scratch[0] * 8,
        max_allocations: 7,
        ..Limits::default()
    };
    plan::admit(scratch, state, limits).unwrap();
    assert!(plan::admit(
        scratch,
        state,
        Limits {
            managed_bytes: bytes + 70,
            ..limits
        }
    )
    .is_err());
    assert!(plan::admit(
        scratch,
        state,
        Limits {
            max_allocations: 6,
            ..limits
        }
    )
    .is_err());
    assert!(plan::admit(
        scratch,
        state,
        Limits {
            max_allocation_bytes: scratch[0] * 8 - 1,
            ..limits
        }
    )
    .is_err());
    assert!(plan::admit([usize::MAX], state, limits).is_err());
    for (input, width, output, columns, quotient) in [
        (0, 1, 1, 1, false),
        (32, 1, 32, 1, true),
        (u32::MAX, 1, 1, 1, true),
        (8, 19, 8, 3, true),
        (8, 19, 7, 3, false),
        (8, 19, 32, 3, false),
        (8, 19, 10, 0, false),
        (8, 19, 10, 20, false),
        (8, usize::MAX, 10, 1, false),
    ] {
        assert!(TilePlan::new(input, width, output, columns, quotient).is_err());
    }
    for (first, columns) in [(19, 1), (18, 2), (0, 4), (usize::MAX, 1), (0, 0)] {
        assert!(p.tile(first, columns).is_err());
    }
    assert_eq!(GENERATOR, Val::GENERATOR.as_canonical_u64());
    assert_eq!(
        config::NUM_RANDOM_CODEWORDS,
        crate::block_v2::profile::NUM_RANDOM_CODEWORDS
    );
    assert_eq!(config::LOG_BLOWUP, crate::block_v2::profile::LOG_BLOWUP);
}

#[test]
#[ignore = "requires pinned NVRTC but no GPU context"]
fn cuda_hiding_kernels_compile_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_trace_hiding_and_preprocessing_match_upstream_pcs() {
    let runtime = runtime(64 << 20, 32 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    for input_spec in [
        spec(0, 1, Extension::Base, 1),
        spec(3, 3, Extension::Quadratic, 1),
        spec(5, 17, Extension::Cubic, 1),
    ] {
        let raw = words(input_spec.words());
        let width = input_spec.columns * input_spec.extension.degree();
        let trace = runtime.upload_matrix(input_spec, &raw).unwrap();
        let mut cpu = rng();
        let random = randoms.import(cpu.clone()).unwrap();
        let (pcs, mmcs) = pcs(cpu.clone());
        let log = input_spec.log_rows + 1 + config::LOG_BLOWUP as u32;
        let (_, data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(
            &pcs,
            [(
                Domain::new(Val::ONE, input_spec.log_rows as usize + 1).unwrap(),
                matrix(&raw, width),
            )],
        );
        let reference = mmcs.get_matrices(&data)[0].clone();
        let before = runtime.snapshot();
        let input = hiding
            .prepare_trace(&trace, &random, log, 17.min(reference.width))
            .unwrap();
        assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
            8
        );
        for _ in 0..input.shape.random_words {
            let _: Val = cpu.random();
        }
        next_samples(&random, &mut cpu);
        for order in [RowOrder::Natural, RowOrder::BitReversed] {
            for first in (0..reference.width).step_by(input.plan.columns) {
                let columns = input.plan.columns.min(reference.width - first);
                let before = runtime.snapshot();
                let output = hiding
                    .with_trace_lde(&input, first, columns, order, |m| Ok(m.clone()))
                    .unwrap();
                assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
                assert_eq!(
                    runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
                    ((input.plan.input_log + log) * 8) as u64
                );
                assert_eq!(
                    output.spec,
                    MatrixSpec::new(log, columns, Extension::Base, order, GENERATOR).unwrap()
                );
                assert_eq!(
                    output.read(output.spec.bytes()).unwrap(),
                    tile(&reference, first, columns, RowOrder::BitReversed, order)
                );
            }
        }
        next_samples(&random, &mut cpu); // LDE regeneration never advances the stream.
    }
    for input_spec in [
        spec(0, 1, Extension::Base, 1),
        spec(4, 17, Extension::Base, 1),
    ] {
        let raw = words(input_spec.words());
        let trace = runtime.upload_matrix(input_spec, &raw).unwrap();
        let (pcs, mmcs) = pcs(rng());
        let (_, data) = <MyPcs as Pcs<Challenge, Challenger>>::commit_preprocessing(
            &pcs,
            [(
                Domain::new(Val::ONE, input_spec.log_rows as usize + 1).unwrap(),
                matrix(&raw, input_spec.columns),
            )],
        );
        let reference = mmcs.get_matrices(&data)[0].clone();
        let before = runtime.snapshot();
        let input = hiding
            .prepare_preprocessing(
                &trace,
                reference.height().ilog2(),
                3.min(input_spec.columns),
            )
            .unwrap();
        assert_eq!(runtime.snapshot(), before);
        for order in [RowOrder::Natural, RowOrder::BitReversed] {
            for first in (0..reference.width).step_by(input.plan.columns) {
                let columns = input.plan.columns.min(reference.width - first);
                hiding
                    .with_trace_lde(&input, first, columns, order, |m| {
                        assert_eq!(
                            m.read(m.spec.bytes())?,
                            tile(&reference, first, columns, RowOrder::BitReversed, order)
                        );
                        Ok(())
                    })
                    .unwrap();
            }
        }
    }
}

fn horner(coefficients: &RowMajorMatrix<Val>, column: usize, point: Val) -> Val {
    (0..coefficients.height())
        .rev()
        .fold(Val::ZERO, |acc, row| {
            acc * point + coefficients.values[row * coefficients.width + column]
        })
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_quotient_hiding_matches_upstream_and_recomposes_all_chunks() {
    let runtime = runtime(64 << 20, 32 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        for (chunks, log_height, shift) in [(2usize, 1u32, 1), (4, 4, 7), (16, 2, 13), (32, 1, 13)]
        {
            let input_spec = spec(chunks.ilog2() + log_height, 1, extension, shift);
            let raw = words(input_spec.words());
            let quotient = runtime.upload_matrix(input_spec, &raw).unwrap();
            let domain = Domain::new(Val::from_u64(shift), input_spec.log_rows as usize).unwrap();
            let domains = domain.split_domains(chunks);
            let evaluations: Vec<_> = (0..chunks)
                .map(|chunk| {
                    let values = (0..(1 << log_height))
                        .flat_map(|row| {
                            let first = (row * chunks + chunk) * extension.degree();
                            raw[first..first + extension.degree()].iter().copied()
                        })
                        .collect::<Vec<_>>();
                    (domains[chunk], matrix(&values, extension.degree()))
                })
                .collect();
            let mut cpu = rng();
            let random = randoms.import(cpu.clone()).unwrap();
            let (pcs, _) = pcs(cpu.clone());
            let reference =
                <MyPcs as Pcs<Challenge, Challenger>>::get_quotient_ldes(&pcs, evaluations, chunks);
            let log = log_height + 1 + config::LOG_BLOWUP as u32;
            let before = runtime.snapshot();
            let input = hiding
                .prepare_quotient(&quotient, chunks, &random, log, 3)
                .unwrap();
            assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
            assert_eq!(
                runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                16
            );
            for _ in 0..input.shape.random_words + input.shape.mask_words {
                let _: Val = cpu.random();
            }
            next_samples(&random, &mut cpu);
            let mut hidden_coefficients = Vec::new();
            for (chunk, reference) in reference.iter().enumerate() {
                let mut natural = vec![Val::ZERO; reference.values.len()];
                for order in [RowOrder::Natural, RowOrder::BitReversed] {
                    for first in (0..reference.width).step_by(3) {
                        let columns = 3.min(reference.width - first);
                        let before = runtime.snapshot();
                        let output = hiding
                            .with_quotient_lde(&input, chunk, first, columns, order, |m| {
                                Ok(m.clone())
                            })
                            .unwrap();
                        assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
                        assert_eq!(
                            runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
                            ((log_height + log) * 8) as u64
                        );
                        let got = output.read(output.spec.bytes()).unwrap();
                        assert_eq!(
                            got,
                            tile(reference, first, columns, RowOrder::BitReversed, order)
                        );
                        if order == RowOrder::Natural {
                            for row in 0..reference.height() {
                                for c in 0..columns {
                                    natural[row * reference.width + first + c] =
                                        Val::from_u64(got[row * columns + c]);
                                }
                            }
                        }
                    }
                }
                hidden_coefficients.push(Dft::default().coset_idft_batch(
                    RowMajorMatrix::new(natural, reference.width),
                    Val::GENERATOR,
                ));
            }
            // Independent off-domain recomposition: normalized vanishing
            // weights cancel the masks, recovering the original quotient.
            let original = Dft::default()
                .coset_idft_batch(matrix(&raw, extension.degree()), Val::from_u64(shift));
            for point in [Val::from_u64(19), Val::from_u64(29)] {
                for column in 0..extension.degree() {
                    let recomposed: Val = domains
                        .iter()
                        .enumerate()
                        .map(|(i, part)| {
                            let weight: Val = domains
                                .iter()
                                .enumerate()
                                .filter(|(j, _)| *j != i)
                                .map(|(_, other)| {
                                    other.vanishing_poly_at_point(point)
                                        / other.vanishing_poly_at_point(part.first_point())
                                })
                                .product();
                            weight * horner(&hidden_coefficients[i], column, point)
                        })
                        .sum();
                    assert_eq!(recomposed, horner(&original, column, point));
                }
            }
            next_samples(&random, &mut cpu);
        }
    }
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_hiding_tiles_fit_when_full_lde_exceeds_managed_and_allocation_limits() {
    let runtime = runtime(4 << 20, 1 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let input_spec = spec(10, 17, Extension::Cubic, 1);
    let raw = words(input_spec.words());
    let trace = runtime.upload_matrix(input_spec, &raw).unwrap();
    let random = randoms.import(rng()).unwrap();
    let log = input_spec.log_rows + 1 + config::LOG_BLOWUP as u32;
    let before = runtime.snapshot();
    assert!(hiding.prepare_trace(&trace, &random, log, 55).is_err());
    assert_eq!(runtime.snapshot(), before);
    let input = hiding.prepare_trace(&trace, &random, log, 2).unwrap();
    let mut cpu = rng();
    let mut padded = matrix(&raw, 51).with_random_cols(51 + 8, &mut cpu);
    padded.width = 55;
    for (first, columns) in [(0, 2), (49, 2), (51, 2), (54, 1)] {
        let selected = matrix(
            &tile(
                &padded,
                first,
                columns,
                RowOrder::Natural,
                RowOrder::Natural,
            ),
            columns,
        );
        let expected = Dft::default()
            .coset_lde_batch(selected, config::LOG_BLOWUP, Val::GENERATOR)
            .to_row_major_matrix();
        hiding
            .with_trace_lde(&input, first, columns, RowOrder::BitReversed, |m| {
                assert_eq!(
                    m.read(m.spec.bytes())?,
                    tile(
                        &expected,
                        0,
                        columns,
                        RowOrder::Natural,
                        RowOrder::BitReversed
                    )
                );
                Ok(())
            })
            .unwrap();
    }
    assert!(runtime.snapshot().peak_bytes <= 4 << 20);
    next_samples(&random, &mut cpu);
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_hiding_consumers_retire_random_family_on_failure_and_unwind() {
    let runtime = runtime(4 << 20, 2 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let input_spec = spec(3, 1, Extension::Cubic, 1);
    let trace = runtime
        .upload_matrix(input_spec, &words(input_spec.words()))
        .unwrap();
    for quotient in [false, true] {
        for panic in [false, true] {
            let random = randoms.import(rng()).unwrap();
            let alias = random.snapshot().unwrap();
            let consumer = |_: &Matrix| -> Result<()> {
                if panic {
                    panic!("injected hiding consumer panic");
                }
                Err("injected hiding consumer failure".into())
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if quotient {
                    let input = hiding.prepare_quotient(&trace, 2, &random, 5, 2).unwrap();
                    let before = runtime.snapshot();
                    assert!(hiding
                        .with_quotient_lde(&input, 2, 0, 2, RowOrder::Natural, |_| Ok(()))
                        .is_err());
                    assert_eq!(runtime.snapshot(), before);
                    random.check_live().unwrap();
                    hiding.with_quotient_lde(&input, 1, 0, 2, RowOrder::Natural, consumer)
                } else {
                    let input = hiding.prepare_trace(&trace, &random, 5, 2).unwrap();
                    let before = runtime.snapshot();
                    assert!(hiding
                        .with_trace_lde(&input, usize::MAX, 2, RowOrder::Natural, |_| Ok(()))
                        .is_err());
                    assert_eq!(runtime.snapshot(), before);
                    random.check_live().unwrap();
                    hiding.with_trace_lde(&input, 0, 2, RowOrder::Natural, consumer)
                }
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert!(result.unwrap().is_err());
            }
            assert!(random.check_live().is_err());
            assert!(alias.sample_fields(1).is_err());
            drop(alias);
            drop(random);
            assert_eq!(runtime.snapshot().live_bytes, trace.spec.bytes());
        }
    }
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_hidden_lde_and_replayed_salts_feed_cpu_audited_commitment() {
    let runtime = runtime(8 << 20, 4 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let input_spec = spec(3, 1, Extension::Cubic, 1);
    let raw = words(input_spec.words());
    let trace = runtime.upload_matrix(input_spec, &raw).unwrap();
    let mut cpu = rng();
    let random = randoms.import(cpu.clone()).unwrap();
    let log = 5;
    let input = hiding.prepare_trace(&trace, &random, log, 7).unwrap();
    let mut padded = matrix(&raw, 3).with_random_cols(3 + 8, &mut cpu);
    padded.width = 7;
    let expected = Dft::default()
        .coset_lde_batch(padded, 1, Val::GENERATOR)
        .to_row_major_matrix();
    let salts_spec = MatrixSpec::new(log, 4, Extension::Base, RowOrder::BitReversed, 1).unwrap();
    let salts = random
        .prepare_salt_replay(salts_spec, 1)
        .unwrap()
        .pop()
        .unwrap();
    let expected_salts: Vec<Val> = (0..salts_spec.words()).map(|_| cpu.random()).collect();
    let before = runtime.snapshot();
    let tree = hiding
        .with_trace_lde(&input, 0, 7, RowOrder::BitReversed, |m| {
            commitments.commit_replayed(m, &salts, 0)
        })
        .unwrap();
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        8
    ); // replay status only
    assert_eq!(
        runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
        (4 + log) as u64 * 8
    ); // public roots only
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm);
    let mut layer: Vec<[Val; 4]> = (0..salts_spec.rows())
        .map(|row| {
            let source = physical(row, log, RowOrder::BitReversed);
            hash.hash_iter(
                expected.values[source * 7..source * 7 + 7]
                    .iter()
                    .copied()
                    .chain(expected_salts[row * 4..row * 4 + 4].iter().copied()),
            )
        })
        .collect();
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|c| compress.compress([c[0], c[1]]))
            .collect();
    }
    assert_eq!(tree.cap(32).unwrap(), canonical(&layer[0]));
    next_samples(&random, &mut cpu);
}

#[test]
#[ignore = "requires CUDA; run serially with an explicit device UUID"]
fn cuda_hiding_rejects_resource_pressure_before_private_work() {
    let runtime = runtime(2 << 20, 1 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let input_spec = spec(6, 1, Extension::Cubic, 7);
    let quotient = runtime
        .upload_matrix(input_spec, &words(input_spec.words()))
        .unwrap();
    let mut cpu = rng();
    let random = randoms.import(cpu.clone()).unwrap();
    let before = runtime.snapshot();
    // Sampling fits, but the requested LDE tile does not. Reject before either
    // the random columns or the subsequent mask sequence consumes the cursor.
    assert!(hiding
        .prepare_quotient(&quotient, 4, &random, 18, 3)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    next_samples(&random, &mut cpu);
    let input = hiding
        .prepare_quotient(&quotient, 4, &random, 9, 3)
        .unwrap();
    for _ in 0..input.shape.random_words + input.shape.mask_words {
        let _: Val = cpu.random();
    }
    let mut pressure = Vec::new();
    while (2 << 20) - runtime.snapshot().live_bytes > 8 {
        let bytes = ((2 << 20) - runtime.snapshot().live_bytes - 8).min(1 << 20);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    let before = runtime.snapshot();
    assert!(hiding
        .with_quotient_lde(&input, 0, 0, 3, RowOrder::Natural, |_| Ok(()))
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    random.check_live().unwrap();
    drop(pressure);
    hiding
        .with_quotient_lde(&input, 0, 0, 3, RowOrder::Natural, |_| Ok(()))
        .unwrap();
    next_samples(&random, &mut cpu);
}
