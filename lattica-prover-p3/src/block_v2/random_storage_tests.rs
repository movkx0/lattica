//! Test-only deterministic streams for device randomization polynomials and
//! salt ownership. No production randomness policy is selected here.
use super::*;
use crate::block_v2::gpu_hash::device::{
    DeviceRandom, DeviceSession, Extension, MatrixSpec, QuotientCommitShape, RowOrder,
    TraceCommitShape,
};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{BasedVectorSpace, PrimeField64};
use p3_matrix::bitrev::BitReversibleMatrix;
use rand::RngExt;

fn device_mmcs() -> CandidateMmcs {
    let mut result = mmcs(true);
    result.device_only = true;
    result
}

fn salt_spec(height: usize) -> MatrixSpec {
    MatrixSpec::new(height.ilog2(), 4, Extension::Base, RowOrder::BitReversed, 1).unwrap()
}

fn salts(
    stream: &DeviceRandom,
    height: usize,
    count: usize,
) -> Vec<super::super::device::ReplaySalts> {
    stream
        .prepare_salt_replay(salt_spec(height), count)
        .unwrap()
}

fn compare_owned(
    cpu: &ValMmcs,
    gpu: &CandidateMmcs,
    session: &DeviceSession,
    expected: (Commitment, CpuData),
    actual: (Commitment, ProverData<RowMajorMatrix<Val>>),
) {
    assert_eq!(expected.0, actual.0);
    assert!(matches!(
        actual.1,
        ProverData::DeviceOnly {
            salts: super::super::SaltStore::Replay(_),
            ..
        }
    ));
    let matrices = cpu.get_matrices(&expected.1);
    let height = matrices[0].height();
    for (index, matrix) in matrices.iter().enumerate() {
        let prefix = actual.1.owned_matrix(session, index).unwrap();
        assert_eq!(prefix.spec().rows(), height >> profile::LOG_BLOWUP);
        assert_eq!(
            session.read(&prefix, prefix.spec().bytes()).unwrap(),
            matrix.values[..prefix.spec().words()]
                .iter()
                .map(|v| v.as_canonical_u64())
                .collect::<Vec<_>>()
        );
    }
    let indices = [0, height - 1, height / 3, height / 3];
    let budget = gpu
        .owned_query_host_bytes(&actual.1, indices.len())
        .unwrap();
    let before = session.stats();
    assert!(gpu
        .open_owned_queries(session, &actual.1, &indices, budget - 1)
        .is_err());
    assert_eq!(session.stats(), before);
    let queries = gpu
        .open_owned_queries(session, &actual.1, &indices, budget)
        .unwrap();
    assert_eq!(
        session.stats().gathered_value_bytes - before.gathered_value_bytes,
        (indices.len() * matrices.len() * 4 * 8) as u64
    );
    let dimensions: Vec<_> = matrices.iter().map(|m| m.dimensions()).collect();
    for (index, query) in indices.into_iter().zip(queries) {
        assert_eq!(
            postcard::to_allocvec(&cpu.open_batch(index, &expected.1)).unwrap(),
            postcard::to_allocvec(&query).unwrap()
        );
        cpu.verify_batch(
            &actual.0,
            &dimensions,
            index,
            BatchOpeningRef::new(&query.opened_values, &query.opening_proof),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_device_evaluations_and_salts_match_cpu_cosets_and_tiles() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    for (height, widths, shift) in [
        (2usize, vec![1], 1u64),
        (32, vec![3, 7, 33], 7),
        (256, vec![35], 11),
        (4096, vec![65], 0xffff_ffff_0000_0000),
    ] {
        let session = DeviceSession::new().unwrap();
        let gpu = device_mmcs();
        let cpu = (*mmcs(false).cpu).clone();
        let mut reference = ChaCha20Rng::from_seed([81; 32]);
        let random = session.import_random_stream(reference.clone()).unwrap();
        let salt_stream = session
            .import_random_stream(ChaCha20Rng::from_seed([41; 32]))
            .unwrap();
        let baseline = engine::report("device evaluation seeded").unwrap();
        let mut inputs = Vec::new();
        let mut expected = Vec::new();
        let before = session.stats();
        for width in &widths {
            let spec = MatrixSpec::new(
                height.ilog2(),
                *width,
                Extension::Base,
                RowOrder::Natural,
                shift,
            )
            .unwrap();
            let samples = random.sample_matrix(spec).unwrap();
            inputs.push(session.prepare_evaluations(&samples).unwrap());
            // The prepared input must retain the private samples after this drop.
            drop(samples);
            let values = RowMajorMatrix::rand(&mut reference, height, *width);
            expected.push(
                crate::config::Dft::default()
                    .coset_lde_batch(
                        values,
                        profile::LOG_BLOWUP,
                        Val::GENERATOR / Val::from_u64(shift),
                    )
                    .bit_reverse_rows()
                    .to_row_major_matrix(),
            );
        }
        let salt_matrices = salts(&salt_stream, height << profile::LOG_BLOWUP, widths.len());
        let before_commit = engine::report("device evaluation before commit").unwrap();
        let actual = gpu
            .commit_evaluations_with_device_salts(
                &inputs,
                profile::LOG_BLOWUP,
                salt_matrices,
                &session,
                64 << 20,
            )
            .unwrap();
        let after_commit = engine::report("device evaluation after commit").unwrap();
        // Existing LDE setup uploads two public root tables. Neither private
        // evaluation fields nor salt fields pass through that setup transfer.
        assert_eq!(
            after_commit.uploaded_bytes - before_commit.uploaded_bytes,
            16 * (height << profile::LOG_BLOWUP).ilog2() as u64
        );
        assert_eq!(
            after_commit.lde_host_output_bytes,
            before_commit.lde_host_output_bytes
        );
        let after = session.stats();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            after.random_status_bytes - before.random_status_bytes
        );
        compare_owned(&cpu, &gpu, &session, cpu.commit(expected), actual);
        drop(inputs);
        assert_eq!(
            engine::report("device evaluation released")
                .unwrap()
                .device_matrix_live_bytes,
            baseline.device_matrix_live_bytes
        );
    }
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_device_salts_preserve_shared_trace_and_randomization_streams() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    for extension in [Extension::Base, Extension::Cubic] {
        for height in [1usize, 8, 256, 8192] {
            let session = DeviceSession::new().unwrap();
            let gpu = device_mmcs();
            let (cpu, cpu_mmcs) = reference();
            let random = session
                .import_random_stream(ChaCha20Rng::from_seed([43; 32]))
                .unwrap();
            let random_clone = random.clone();
            let salt_stream = session
                .import_random_stream(ChaCha20Rng::from_seed([41; 32]))
                .unwrap();
            let salt_clone = salt_stream.clone();
            let domain = Domain::new(Val::ONE, (2 * height).ilog2() as usize).unwrap();
            let host = matrix(height, 3 * extension.degree(), 19);
            let spec = MatrixSpec::new(height.ilog2(), 3, extension, RowOrder::Natural, 1).unwrap();
            let trace = session
                .upload(
                    spec,
                    &host
                        .values
                        .iter()
                        .map(|v| v.as_canonical_u64())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
            let shape = TraceCommitShape::new(spec, profile::NUM_RANDOM_CODEWORDS).unwrap();
            let baseline = engine::report("device salt trace baseline").unwrap();
            for (random, salt_stream) in [(&random, &salt_clone), (&random_clone, &salt_stream)] {
                let prepared = session
                    .prepare_trace_commit_with_random(
                        &trace,
                        profile::NUM_RANDOM_CODEWORDS,
                        random.sample_fields(shape.random_words).unwrap(),
                    )
                    .unwrap();
                let actual = gpu
                    .commit_traces_with_device_salts(
                        &[prepared],
                        salts(salt_stream, (2 * height) << profile::LOG_BLOWUP, 1),
                        &session,
                        64 << 20,
                    )
                    .unwrap();
                compare_owned(
                    &cpu_mmcs,
                    &gpu,
                    &session,
                    <CpuPcs as Pcs<Challenge, Challenger>>::commit(&cpu, [(domain, host.clone())]),
                    actual,
                );
                // The randomization polynomial consumes the very same active
                // witness stream; there is no independent reseed at this boundary.
                let random_spec = MatrixSpec::new(
                    domain.size().ilog2(),
                    profile::NUM_RANDOM_CODEWORDS + <Challenge as BasedVectorSpace<Val>>::DIMENSION,
                    Extension::Base,
                    RowOrder::Natural,
                    1,
                )
                .unwrap();
                let inputs: Vec<_> = (0..2)
                    .map(|_| {
                        let matrix = random.sample_matrix(random_spec).unwrap();
                        session.prepare_evaluations(&matrix).unwrap()
                    })
                    .collect();
                let actual = gpu
                    .commit_evaluations_with_device_salts(
                        &inputs,
                        profile::LOG_BLOWUP,
                        salts(salt_stream, domain.size() << profile::LOG_BLOWUP, 2),
                        &session,
                        64 << 20,
                    )
                    .unwrap();
                compare_owned(
                    &cpu_mmcs,
                    &gpu,
                    &session,
                    <CpuPcs as Pcs<Challenge, Challenger>>::get_opt_randomization_poly_commitment(
                        &cpu,
                        [domain, domain],
                    )
                    .unwrap(),
                    actual,
                );
                drop(inputs);
                assert_eq!(
                    engine::report("device salt trace released")
                        .unwrap()
                        .device_matrix_live_bytes,
                    baseline.device_matrix_live_bytes
                );
            }
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_device_quotient_salts_match_cpu_chunks_and_successive_draws() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    for (height, chunks, shift) in [(8usize, 2, 7u64), (32, 4, 11), (64, 16, 7), (8192, 2, 11)] {
        let session = DeviceSession::new().unwrap();
        let (cpu, _) = candidate(true);
        let cpu_mmcs = (*mmcs(false).cpu).clone();
        let gpu = device_mmcs();
        let domain = Domain::new(Val::from_u64(shift), height.ilog2() as usize).unwrap();
        let host = matrix(height, 3, 31);
        let domains = domain.split_domains(chunks);
        let matrices = domain.split_evals(chunks, host.clone());
        let spec = MatrixSpec::new(
            height.ilog2(),
            1,
            Extension::Cubic,
            RowOrder::Natural,
            shift,
        )
        .unwrap();
        let quotient = session
            .upload(
                spec,
                &host
                    .values
                    .iter()
                    .map(|v| v.as_canonical_u64())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let shape = QuotientCommitShape::new(spec, chunks, profile::NUM_RANDOM_CODEWORDS).unwrap();
        let random = session
            .import_random_stream(ChaCha20Rng::from_seed([47; 32]))
            .unwrap();
        let salt_stream = session
            .import_random_stream(ChaCha20Rng::from_seed([41; 32]))
            .unwrap();
        let baseline = engine::report("device quotient salts baseline").unwrap();
        for _ in 0..2 {
            let prepared = session
                .prepare_quotient_commit_with_random(
                    &quotient,
                    chunks,
                    profile::NUM_RANDOM_CODEWORDS,
                    random.sample_fields(shape.random_words).unwrap(),
                    random.sample_fields(shape.mask_words).unwrap(),
                )
                .unwrap();
            let actual = gpu
                .commit_quotient_with_device_salts(
                    &prepared,
                    salts(
                        &salt_stream,
                        (height / chunks) << (profile::LOG_BLOWUP + 1),
                        chunks,
                    ),
                    &session,
                    64 << 20,
                )
                .unwrap();
            let expected =
                cpu.get_quotient_ldes(domains.iter().copied().zip(matrices.clone()), chunks);
            compare_owned(&cpu_mmcs, &gpu, &session, cpu_mmcs.commit(expected), actual);
            drop(prepared);
            assert_eq!(
                engine::report("device quotient salts released")
                    .unwrap()
                    .device_matrix_live_bytes,
                baseline.device_matrix_live_bytes
            );
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_device_fri_salts_match_cpu_caps_and_queried_rows() {
    check_fri_salts(false);
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_fri_salt_replay_matches_cpu_without_retaining_sample_matrices() {
    check_fri_salts(true);
}

fn check_fri_salts(replay: bool) {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let gpu = device_mmcs();
    let cpu = CpuExtensionMmcs::new((*mmcs(false).cpu).clone());
    let failure = crate::block_v2::randomness::Failure::default();
    if replay {
        gpu.activate_private_randomness(&session, &failure).unwrap();
    }
    let salt_stream = session
        .import_random_stream(ChaCha20Rng::from_seed([41; 32]))
        .unwrap();
    let mut values_rng = ChaCha20Rng::from_seed([87; 32]);
    for height in [2usize, 8, 256, 8192] {
        let values: Vec<_> = (0..height)
            .map(|_| values_rng.random::<Challenge>())
            .collect();
        let words: Vec<_> = values
            .iter()
            .flat_map(<Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice)
            .map(|v| v.as_canonical_u64())
            .collect();
        let vector = session
            .upload(
                MatrixSpec::new(
                    height.ilog2(),
                    1,
                    Extension::Cubic,
                    RowOrder::BitReversed,
                    1,
                )
                .unwrap(),
                &words,
            )
            .unwrap();
        let baseline = engine::report("device FRI salts baseline").unwrap();
        let expected = cpu.commit(vec![RowMajorMatrix::new(values, 2)]);
        let before = session.stats();
        let (cap, data) = if replay {
            gpu.commit_fri_device(&session, &vector, 0)
        } else {
            gpu.commit_fri_with_device_salts(
                &session,
                &vector,
                salt_stream.sample_matrix(salt_spec(height / 2)).unwrap(),
            )
        }
        .unwrap();
        assert_eq!(cap, expected.0);
        assert_eq!(session.stats().uploaded_bytes, before.uploaded_bytes);
        // Each commitment consumes exactly one original salt draw. The
        // replay route retains none of its sample bytes beyond that commit.
        assert_eq!(
            session.stats().random_fields - before.random_fields,
            (height / 2 * 4) as u64
        );
        let retained = engine::report("FRI salts committed")
            .unwrap()
            .device_matrix_live_bytes;
        assert_eq!(
            retained - baseline.device_matrix_live_bytes,
            if replay { 0 } else { height / 2 * 32 }
        );
        let indices = [0, height / 2 - 1, 0];
        let before_queries = session.stats();
        let queries = data.open_rows(&session, &indices).unwrap();
        assert_eq!(
            session.stats().gathered_value_bytes - before_queries.gathered_value_bytes,
            (indices.len() * (6 + 4) * 8) as u64
        );
        for (index, query) in indices.into_iter().zip(queries) {
            assert_eq!(
                postcard::to_allocvec(&cpu.open_batch(index, &expected.1)).unwrap(),
                postcard::to_allocvec(&query).unwrap()
            );
            cpu.verify_batch(
                &cap,
                &[p3_matrix::Dimensions {
                    width: 2,
                    height: height / 2,
                }],
                index,
                BatchOpeningRef::new(&query.opened_values, &query.opening_proof),
            )
            .unwrap();
        }
        drop(data);
        assert_eq!(
            engine::report("device FRI salts released")
                .unwrap()
                .device_matrix_live_bytes,
            baseline.device_matrix_live_bytes
        );
    }
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_device_random_storage_rejects_domains_sessions_and_budgets() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let foreign = DeviceSession::new().unwrap();
    let gpu = device_mmcs();
    let stream = session
        .import_random_stream(ChaCha20Rng::from_seed([89; 32]))
        .unwrap();
    let foreign_stream = foreign
        .import_random_stream(ChaCha20Rng::from_seed([91; 32]))
        .unwrap();
    for spec in [
        MatrixSpec::new(0, 1, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(3, 1, Extension::Base, RowOrder::BitReversed, 1).unwrap(),
    ] {
        let values = stream.sample_matrix(spec).unwrap();
        let before = engine::report("invalid evaluation before").unwrap();
        assert!(session.prepare_evaluations(&values).is_err());
        let after = engine::report("invalid evaluation after").unwrap();
        assert_eq!(after.allocations, before.allocations);
    }
    let values = stream
        .sample_matrix(MatrixSpec::new(3, 7, Extension::Base, RowOrder::Natural, 1).unwrap())
        .unwrap();
    let input = session.prepare_evaluations(&values).unwrap();
    let height = 8usize << profile::LOG_BLOWUP;
    let before = session.stats();
    for spec in [
        MatrixSpec::new(height.ilog2(), 4, Extension::Base, RowOrder::Natural, 1).unwrap(),
        MatrixSpec::new(height.ilog2(), 4, Extension::Base, RowOrder::BitReversed, 7).unwrap(),
        MatrixSpec::new(height.ilog2(), 3, Extension::Base, RowOrder::BitReversed, 1).unwrap(),
    ] {
        assert!(stream.prepare_salt_replay(spec, 1).is_err());
    }
    assert_eq!(session.stats(), before);
    let rejected_salts = [
        stream
            .prepare_salt_replay(salt_spec(height / 2), 1)
            .unwrap(),
        vec![],
        foreign_stream
            .prepare_salt_replay(salt_spec(height), 1)
            .unwrap(),
        stream.prepare_salt_replay(salt_spec(height), 2).unwrap(),
    ];
    let mut good_salts: Vec<_> = (0..4)
        .map(|_| stream.prepare_salt_replay(salt_spec(height), 1).unwrap())
        .collect();
    let baseline = engine::report("device salt admission before").unwrap();
    for salts in rejected_salts {
        assert!(gpu
            .commit_evaluations_with_device_salts(
                core::slice::from_ref(&input),
                profile::LOG_BLOWUP,
                salts,
                &session,
                64 << 20
            )
            .is_err());
    }
    assert!(gpu
        .commit_evaluations_with_device_salts(
            core::slice::from_ref(&input),
            0,
            good_salts.pop().unwrap(),
            &session,
            64 << 20
        )
        .is_err());
    assert!(foreign.prepare_evaluations(&values).is_err());
    assert!(gpu
        .commit_evaluations_with_device_salts(
            core::slice::from_ref(&input),
            profile::LOG_BLOWUP,
            good_salts.pop().unwrap(),
            &foreign,
            64 << 20
        )
        .is_err());
    assert!(mmcs(true)
        .commit_evaluations_with_device_salts(
            core::slice::from_ref(&input),
            profile::LOG_BLOWUP,
            good_salts.pop().unwrap(),
            &session,
            64 << 20
        )
        .is_err());
    let after = engine::report("device salt admission after").unwrap();
    assert_eq!(after.allocations, baseline.allocations);
    assert_eq!(after.uploaded_bytes, baseline.uploaded_bytes);
    assert_eq!(after.downloaded_bytes, baseline.downloaded_bytes);

    // The LDE value-output allowance excludes the bounded public cap and
    // metadata. Device-only storage must work with zero host polynomial bytes.
    let (_, data) = gpu
        .commit_evaluations_with_device_salts(
            core::slice::from_ref(&input),
            profile::LOG_BLOWUP,
            good_salts.pop().unwrap(),
            &session,
            0,
        )
        .unwrap();
    let before_query = session.stats();
    assert!(gpu.open_owned_queries(&session, &data, &[0], 0).is_err());
    assert_eq!(session.stats(), before_query);
    drop(data);

    // Private salts must never enter the reusable public preprocessing route.
    use crate::block_v2::machine::{gpu_program::WitnessProgram, ProgramBuilder};
    let mut builder = ProgramBuilder::new(0).unwrap();
    let x = builder.input();
    builder.mul(x, x);
    let program = builder.finish(None).unwrap();
    let witness = session
        .prepare_witness(std::sync::Arc::new(
            WitnessProgram::compile(&program, 64 << 20).unwrap(),
        ))
        .unwrap();
    let preprocessing = witness.preprocessing_trace(&session).unwrap();
    let preprocessing = session
        .prepare_preprocessing_commit(&preprocessing)
        .unwrap();
    let private_salts = salts(
        &stream,
        preprocessing.shape.height << profile::LOG_BLOWUP,
        1,
    );
    let before = engine::report("private preprocessing salt rejection before").unwrap();
    let error = gpu
        .commit_traces_with_device_salts(&[preprocessing], private_salts, &session, 64 << 20)
        .err()
        .unwrap();
    assert!(error.contains("private device salts"));
    let after = engine::report("private preprocessing salt rejection after").unwrap();
    assert_eq!(after.allocations, before.allocations);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
}
