mod benchmark;
mod opening;

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_randomization_commitment_failures_retire_samples_and_salts() {
    let runtime = runtime(32 << 20, 8 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    for fault in [Fault::AfterTile, Fault::PanicAfterTile] {
        let private = randoms.import(rng(31)).unwrap();
        let salts = randoms.import(rng(71)).unwrap();
        let prepared = hiding
            .prepare_randomization(4, 13, Extension::Cubic, &private, 8, 2)
            .unwrap();
        let inputs = [HidingInput::Randomization(&prepared)];
        let before = runtime.snapshot();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            hiding.commit_batch_impl(&commitments, &inputs, &salts, 6, fault)
        }));
        assert!(result.is_err() || result.unwrap().is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert_eq!(runtime.snapshot().allocations, before.allocations);
        assert!(private.check_live().is_err());
        assert!(salts.check_live().is_err());
        let before = runtime.snapshot();
        assert!(hiding
            .with_randomization_lde(&prepared, 0, 2, RowOrder::Natural, |_| Ok(()))
            .is_err());
        assert_eq!(runtime.snapshot(), before);
    }
}

use super::*;
use crate::{
    config::{self, Challenge, Challenger, Dft, MyCompress, MyHash, MyPcs, Val, ValMmcs},
    cuda_compute::{Limits, Randoms},
};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs, Pcs, PolynomialSpace};
use p3_field::{
    coset::TwoAdicMultiplicativeCoset as Domain, PrimeCharacteristicRing, PrimeField64,
};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
use p3_merkle_tree::MerkleCap;
use rand::{RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn rng(seed: u8) -> ChaCha20Rng {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    rng.set_word_pos((1 << 36) - 1);
    rng
}
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
fn mmcs(salt_rng: ChaCha20Rng, cap: usize) -> ValMmcs {
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    ValMmcs::new(
        MyHash::new(perm.clone()),
        MyCompress::new(perm),
        cap,
        salt_rng,
    )
}
fn pcs(hiding_rng: ChaCha20Rng, mmcs: ValMmcs) -> MyPcs {
    MyPcs::new(
        Dft::default(),
        mmcs.clone(),
        config::production_fri(config::ChallengeMmcs::new(mmcs)),
        config::NUM_RANDOM_CODEWORDS,
        hiding_rng,
    )
}
fn upload(
    runtime: &Runtime,
    log: u32,
    columns: usize,
    extension: Extension,
    shift: u64,
    seed: usize,
) -> (Matrix, RowMajorMatrix<Val>) {
    let spec = MatrixSpec::new(log, columns, extension, RowOrder::Natural, shift).unwrap();
    let raw: Vec<_> = (0..spec.words())
        .map(|i| {
            if i % 9 == 0 {
                u64::MAX
            } else {
                (seed + i * 137) as u64
            }
        })
        .collect();
    let cpu = RowMajorMatrix::new(
        raw.iter().map(|&v| Val::from_u64(v)).collect(),
        columns * extension.degree(),
    );
    (runtime.upload_matrix(spec, &raw).unwrap(), cpu)
}
fn digests(words: &[u64]) -> Vec<[Val; 4]> {
    words
        .chunks_exact(4)
        .map(|c| std::array::from_fn(|i| Val::from_u64(c[i])))
        .collect()
}
fn opening(result: &HiddenOpenings, query: usize) -> BatchOpening<Val, ValMmcs> {
    let values = result
        .matrices
        .iter()
        .map(|m| {
            m.values[query * m.spec.columns..(query + 1) * m.spec.columns]
                .iter()
                .map(|&v| Val::from_u64(v))
                .collect()
        })
        .collect();
    let salts = result
        .matrices
        .iter()
        .map(|m| {
            m.salts[query * 4..(query + 1) * 4]
                .iter()
                .map(|&v| Val::from_u64(v))
                .collect()
        })
        .collect();
    let path =
        digests(&result.paths[query * result.path_len * 4..(query + 1) * result.path_len * 4]);
    BatchOpening::new(values, (salts, path))
}
fn next_samples(device: &DeviceRandom, cpu: &mut ChaCha20Rng) {
    let expected: Vec<_> = (0..19)
        .map(|_| cpu.random::<Val>().as_canonical_u64())
        .collect();
    assert_eq!(
        device
            .sample_fields(19)
            .unwrap()
            .read_for_test(152)
            .unwrap(),
        expected
    );
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_hidden_mixed_batches_match_cpu_caps_queries_and_wire_encoding() {
    let runtime = runtime(64 << 20, 32 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let (short, short_cpu) = upload(&runtime, 0, 1, Extension::Base, 1, 5);
        let (tall, tall_cpu) = upload(&runtime, 4, 17, extension, 1, 9);
        let (prep, prep_cpu) = upload(&runtime, 2, 3, Extension::Base, 1, 17);
        let (quotient, quotient_cpu) = upload(&runtime, 5, 1, extension, 13, 99);
        let mut cpu_random = rng(21);
        let random = randoms.import(cpu_random.clone()).unwrap();
        let short_input = hiding.prepare_trace(&short, &random, 5, 2).unwrap();
        let tall_input = hiding.prepare_trace(&tall, &random, 9, 17).unwrap();
        let prep_input = hiding.prepare_preprocessing(&prep, 7, 2).unwrap();
        let quotient_input = hiding
            .prepare_quotient(&quotient, 4, &random, 8, 2)
            .unwrap();
        for _ in 0..short_input.shape.random_words
            + tall_input.shape.random_words
            + quotient_input.shape.random_words
            + quotient_input.shape.mask_words
        {
            let _: Val = cpu_random.random();
        }

        // Generate the independent oracle through the unchanged CPU hiding PCS,
        // in the same hiding-stream order. Final MMCS salts use another stream.
        let oracle_mmcs = mmcs(rng(61), 0);
        let oracle_pcs = pcs(rng(21), oracle_mmcs.clone());
        let (_, trace_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(
            &oracle_pcs,
            [
                (Domain::new(Val::ONE, 1).unwrap(), short_cpu),
                (Domain::new(Val::ONE, 5).unwrap(), tall_cpu),
            ],
        );
        let traces: Vec<_> = oracle_mmcs
            .get_matrices(&trace_data)
            .into_iter()
            .cloned()
            .collect();
        let (_, prep_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit_preprocessing(
            &oracle_pcs,
            [(Domain::new(Val::ONE, 3).unwrap(), prep_cpu)],
        );
        let prepared_cpu = oracle_mmcs.get_matrices(&prep_data)[0].clone();
        let quotient_domain = Domain::new(Val::from_u64(13), 5).unwrap();
        let quotient_ldes = <MyPcs as Pcs<Challenge, Challenger>>::get_quotient_ldes(
            &oracle_pcs,
            quotient_domain
                .split_domains(4)
                .into_iter()
                .zip(quotient_domain.split_evals(4, quotient_cpu)),
            4,
        );
        let mut expected_matrices = vec![prepared_cpu, traces[0].clone()];
        expected_matrices.extend(quotient_ldes);
        expected_matrices.extend([traces[1].clone(), traces[0].clone()]);
        let dimensions: Vec<_> = expected_matrices.iter().map(|m| m.dimensions()).collect();
        let inputs = [
            HidingInput::Trace(&prep_input),
            HidingInput::Trace(&short_input),
            HidingInput::Quotient(&quotient_input),
            HidingInput::Trace(&tall_input),
            HidingInput::Trace(&short_input),
        ];
        for cap_height in [0, 1, 6] {
            let mut cpu_salts = rng(73);
            let salt_random = randoms.import(cpu_salts.clone()).unwrap();
            let oracle = mmcs(cpu_salts.clone(), cap_height);
            let (expected_cap, expected_data) = oracle.commit(expected_matrices.clone());
            let before = runtime.snapshot();
            let actual = hiding
                .commit_batch(&commitments, &inputs, &salt_random, cap_height)
                .unwrap();
            let after = runtime.snapshot();
            let roots_words =
                |p: TilePlan| (p.input_log + p.output_log) as usize * p.width.div_ceil(p.columns);
            let public_roots = roots_words(prep_input.plan)
                + 2 * roots_words(short_input.plan)
                + roots_words(tall_input.plan)
                + 4 * roots_words(quotient_input.plan);
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                (public_roots * 8) as u64
            );
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 2 * 8 * 8); // draw + replay status per matrix
            let prefix_bytes: usize = actual.matrices.iter().map(|m| m.prefix.spec.bytes()).sum();
            assert_eq!(
                after.live_bytes - before.live_bytes,
                prefix_bytes + (2 * 512 - 1) * 4 * 8
            );
            let cap = MerkleCap::new(digests(&actual.cap(8 << 20).unwrap()));
            assert_eq!(cap, expected_cap);
            assert_eq!(
                actual
                    .specs()
                    .map(|s| (s.rows(), s.columns))
                    .collect::<Vec<_>>(),
                expected_matrices
                    .iter()
                    .map(|m| (m.height(), m.width))
                    .collect::<Vec<_>>()
            );
            assert_eq!(actual.matrices[0].random_columns, 0);
            assert!(actual.matrices[1..].iter().all(|m| m.random_columns == 4));
            for _ in 0..expected_matrices
                .iter()
                .map(|m| m.height() * 4)
                .sum::<usize>()
            {
                let _: Val = cpu_salts.random();
            }
            for count in [1, 4, 33, 256] {
                let indices: Vec<_> = (0..count).map(|q| [511, 0, 17, 511][q % 4]).collect();
                let before = runtime.snapshot();
                if count == 256 {
                    // This allowance fits each individual result, but not the
                    // aggregate retained rows, salts, paths and staging.
                    assert!(actual
                        .open(&commitments, &hiding.transforms, &indices, 256 << 10)
                        .is_err());
                    assert_eq!(runtime.snapshot(), before);
                }
                let opened = actual
                    .open(&commitments, &hiding.transforms, &indices, 8 << 20)
                    .unwrap();
                let output_words: usize = opened
                    .matrices
                    .iter()
                    .map(|m| m.values.len() + m.salts.len())
                    .sum::<usize>()
                    + opened.paths.len();
                assert_eq!(
                    runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
                    (output_words * 8 + 8 * 8) as u64
                );
                assert_eq!(opened.queries, count);
                for (q, &index) in indices.iter().enumerate() {
                    let result = opening(&opened, q);
                    assert_eq!(
                        postcard::to_allocvec(&result).unwrap(),
                        postcard::to_allocvec(&oracle.open_batch(index, &expected_data)).unwrap()
                    );
                    oracle
                        .verify_batch(&cap, &dimensions, index, BatchOpeningRef::from(&result))
                        .unwrap();
                    if cap_height == 0 && q == 0 {
                        let (values, proof) = result.unpack();
                        for matrix in 0..values.len() {
                            let mut altered = values.clone();
                            altered[matrix][0] += Val::ONE;
                            assert!(oracle
                                .verify_batch(
                                    &cap,
                                    &dimensions,
                                    index,
                                    BatchOpeningRef::new(&altered, &proof)
                                )
                                .is_err());
                            let mut changed_salts = proof.clone();
                            changed_salts.0[matrix][0] += Val::ONE;
                            assert!(oracle
                                .verify_batch(
                                    &cap,
                                    &dimensions,
                                    index,
                                    BatchOpeningRef::new(&values, &changed_salts)
                                )
                                .is_err());
                        }
                        let mut changed_path = proof.clone();
                        changed_path.1[0][0] += Val::ONE;
                        assert!(oracle
                            .verify_batch(
                                &cap,
                                &dimensions,
                                index,
                                BatchOpeningRef::new(&values, &changed_path)
                            )
                            .is_err());
                    }
                }
            }
            next_samples(&salt_random, &mut cpu_salts);
            drop(actual);
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        }
        next_samples(&random, &mut cpu_random);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_streamed_hidden_commitment_and_queries_fit_below_full_lde_size() {
    let runtime = runtime(8 << 20, 2 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let (trace, cpu_trace) = upload(&runtime, 10, 17, Extension::Cubic, 1, 17);
    let random = randoms.import(rng(29)).unwrap();
    let salts = randoms.import(rng(43)).unwrap();
    let prepared = hiding.prepare_trace(&trace, &random, 15, 2).unwrap();
    let before = runtime.snapshot();
    assert!(runtime.allocate((1 << 15) * 55).is_err());
    assert_eq!(runtime.snapshot(), before);
    let data = hiding
        .commit_batch(&commitments, &[HidingInput::Trace(&prepared)], &salts, 0)
        .unwrap();
    let oracle = mmcs(rng(43), 0);
    let oracle_pcs = pcs(rng(29), oracle.clone());
    let (expected_cap, expected_data) = <MyPcs as Pcs<Challenge, Challenger>>::commit(
        &oracle_pcs,
        [(Domain::new(Val::ONE, 11).unwrap(), cpu_trace)],
    );
    let cap = MerkleCap::new(digests(&data.cap(32).unwrap()));
    assert_eq!(cap, expected_cap);
    let indices = [32767, 0, 12345, 12345];
    let actual = data
        .open(&commitments, &hiding.transforms, &indices, 1 << 20)
        .unwrap();
    let dimensions: Vec<_> = oracle
        .get_matrices(&expected_data)
        .iter()
        .map(|m| m.dimensions())
        .collect();
    for (q, index) in indices.into_iter().enumerate() {
        let opened = opening(&actual, q);
        assert_eq!(
            postcard::to_allocvec(&opened).unwrap(),
            postcard::to_allocvec(&oracle.open_batch(index, &expected_data)).unwrap()
        );
        oracle
            .verify_batch(&cap, &dimensions, index, BatchOpeningRef::from(&opened))
            .unwrap();
    }
    assert_eq!(data.matrices[0].prefix.spec.rows(), 2048);
    assert!(runtime.snapshot().peak_bytes <= 8 << 20);
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_hidden_batch_preflight_rejections_preserve_streams_and_queries() {
    let runtime = runtime(4 << 20, 2 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let (trace, _) = upload(&runtime, 3, 1, Extension::Base, 1, 7);
    let random = randoms.import(rng(33)).unwrap();
    let salts = randoms.import(rng(77)).unwrap();
    let prepared = hiding.prepare_trace(&trace, &random, 8, 2).unwrap();
    let before = runtime.snapshot();
    assert!(hiding.commit_batch(&commitments, &[], &salts, 0).is_err());
    let too_many: Vec<_> = (0..257).map(|_| HidingInput::Trace(&prepared)).collect();
    assert!(hiding
        .commit_batch(&commitments, &too_many, &salts, 0)
        .is_err());
    assert_eq!(runtime.snapshot(), before);
    let pressure = fill_budget(&runtime, 4 << 20, 2 << 20);
    let pressured = runtime.snapshot();
    assert!(hiding
        .commit_batch(&commitments, &[HidingInput::Trace(&prepared)], &salts, 0)
        .is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    next_samples(&salts, &mut rng(77));
    let data = hiding
        .commit_batch(&commitments, &[HidingInput::Trace(&prepared)], &salts, 0)
        .unwrap();
    let before = runtime.snapshot();
    for queries in [vec![], vec![256], vec![0; 257]] {
        assert!(data
            .open(&commitments, &hiding.transforms, &queries, 1 << 20)
            .is_err());
    }
    assert!(data
        .open(&commitments, &hiding.transforms, &[0], 0)
        .is_err());
    assert!(data.cap(31).is_err());
    assert_eq!(runtime.snapshot(), before);
    random.check_live().unwrap();
    salts.check_live().unwrap();
    let pressure = fill_budget(&runtime, 4 << 20, 2 << 20);
    let pressured = runtime.snapshot();
    assert!(data
        .open(&commitments, &hiding.transforms, &[0, 255], 1 << 20)
        .is_err());
    assert_eq!(runtime.snapshot(), pressured);
    drop(pressure);
    data.open(&commitments, &hiding.transforms, &[1, 1, 0], 1 << 20)
        .unwrap();
}

fn fill_budget(runtime: &Runtime, limit: usize, allocation: usize) -> Vec<Buffer> {
    let mut pressure = Vec::new();
    while limit - runtime.snapshot().live_bytes > 8 {
        let bytes = (limit - runtime.snapshot().live_bytes - 8).min(allocation);
        pressure.push(runtime.allocate(bytes / 8).unwrap());
    }
    pressure
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_hidden_batch_failures_retire_every_participating_family() {
    let runtime = runtime(8 << 20, 4 << 20);
    let hiding = Hiding::new(&runtime).unwrap();
    let commitments = Commitments::new(&runtime).unwrap();
    let randoms = Randoms::new(&runtime).unwrap();
    let (trace, _) = upload(&runtime, 3, 1, Extension::Base, 1, 7);
    for fault in [Fault::AfterTile, Fault::PanicAfterTile, Fault::AfterQuery] {
        let a = randoms.import(rng(1)).unwrap();
        let b = randoms.import(rng(2)).unwrap();
        let salts = randoms.import(rng(3)).unwrap();
        let aliases = [
            a.snapshot().unwrap(),
            b.snapshot().unwrap(),
            salts.snapshot().unwrap(),
        ];
        let first = hiding.prepare_trace(&trace, &a, 8, 2).unwrap();
        let second = hiding.prepare_trace(&trace, &b, 8, 2).unwrap();
        let baseline = runtime.snapshot().live_bytes;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            let inputs = [HidingInput::Trace(&first), HidingInput::Trace(&second)];
            if matches!(fault, Fault::AfterQuery) {
                let data = hiding.commit_batch(&commitments, &inputs, &salts, 0)?;
                data.open_impl(
                    &commitments,
                    &hiding.transforms,
                    &[255, 0, 255],
                    1 << 20,
                    fault,
                )?;
            } else {
                hiding.commit_batch_impl(&commitments, &inputs, &salts, 0, fault)?;
            }
            Ok(())
        }));
        if matches!(fault, Fault::PanicAfterTile) {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_err());
        }
        for alias in &aliases {
            assert!(alias.check_live().is_err());
        }
        assert_eq!(runtime.snapshot().live_bytes, baseline);
    }
}
