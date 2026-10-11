//! Deterministic test-only streams exercise device samples as real hiding
//! commitment inputs. The salt stream remains the existing host reference.
use super::*;
use crate::block_v2::gpu_hash::device::{
    DeviceSession, Extension, MatrixSpec, QuotientCommitShape, RowOrder, TraceCommitShape,
};
use p3_field::PrimeField64;

#[test]
#[ignore = "requires OpenCL GPU, retained trees and a <=3 GiB zero-swap service"]
fn gpu_generated_trace_samples_match_cpu_commitments_without_sample_transfers() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    for extension in [Extension::Base, Extension::Cubic] {
        for (height, width) in [(1usize, 1usize), (8, 7), (256, 33), (8192, 2)] {
            let width = width * extension.degree();
            let domain = Domain::new(Val::ONE, (height * 2).ilog2() as usize).unwrap();
            let (cpu, cpu_mmcs) = reference();
            let gpu_mmcs = mmcs(true);
            let session = DeviceSession::new().unwrap();
            let rng = session
                .import_random_stream(ChaCha20Rng::from_seed([43; 32]))
                .unwrap();
            let shared = rng.clone();
            let trace = matrix(height, width, 19);
            let spec = MatrixSpec::new(
                height.ilog2(),
                width / extension.degree(),
                extension,
                RowOrder::Natural,
                1,
            )
            .unwrap();
            let words: Vec<_> = trace.values.iter().map(|v| v.as_canonical_u64()).collect();
            let device_trace = session.upload(spec, &words).unwrap();
            let shape = TraceCommitShape::new(spec, profile::NUM_RANDOM_CODEWORDS).unwrap();
            let baseline = engine::report("random trace baseline").unwrap();
            for stream in [&rng, &shared] {
                gpu_mmcs
                    .preflight_owned_traces(&[shape], 64 << 20, true)
                    .unwrap();
                let before = session.stats();
                let random = stream.sample_fields(shape.random_words).unwrap();
                let prepared = session
                    .prepare_trace_commit_with_random(
                        &device_trace,
                        profile::NUM_RANDOM_CODEWORDS,
                        random,
                    )
                    .unwrap();
                let after = session.stats();
                assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                assert_eq!(
                    after.downloaded_bytes - before.downloaded_bytes,
                    after.random_status_bytes - before.random_status_bytes
                );
                let expected = <CpuPcs as Pcs<Challenge, Challenger>>::commit(
                    &cpu,
                    vec![(domain, trace.clone())],
                );
                let actual = gpu_mmcs
                    .commit_owned_traces(core::slice::from_ref(&prepared), &session, 64 << 20)
                    .unwrap();
                compare(&cpu_mmcs, &gpu_mmcs, expected, actual);
                drop(prepared);
                assert_eq!(
                    engine::report("random trace released")
                        .unwrap()
                        .device_matrix_live_bytes,
                    baseline.device_matrix_live_bytes
                );
            }
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU, owned quotient flags and a <=3 GiB zero-swap service"]
fn gpu_generated_quotient_samples_match_cpu_masks_caps_and_paths() {
    crate::block_v2::quotient_pcs::initialize_gpu_quotient_from_env(true, true).unwrap();
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    for (height, chunks, shift) in [
        (8usize, 2usize, 7u64),
        (32, 4, 11),
        (64, 16, 7),
        (8192, 2, 11),
    ] {
        let domain = Domain::new(Val::from_u64(shift), (height * chunks).ilog2() as usize).unwrap();
        let values = matrix(height * chunks, 3, 31);
        let domains = domain.split_domains(chunks);
        let matrices = domain.split_evals(chunks, values.clone());
        let (cpu, _) = candidate(true);
        let cpu_mmcs = (*mmcs(false).cpu).clone();
        let gpu_mmcs = mmcs(true);
        let session = DeviceSession::new().unwrap();
        let rng = session
            .import_random_stream(ChaCha20Rng::from_seed([47; 32]))
            .unwrap();
        let shared = rng.clone();
        let spec = MatrixSpec::new(
            (height * chunks).ilog2(),
            1,
            Extension::Cubic,
            RowOrder::Natural,
            shift,
        )
        .unwrap();
        let words: Vec<_> = values.values.iter().map(|v| v.as_canonical_u64()).collect();
        let quotient = session.upload(spec, &words).unwrap();
        let shape = QuotientCommitShape::new(spec, chunks, profile::NUM_RANDOM_CODEWORDS).unwrap();
        let baseline = engine::report("random quotient baseline").unwrap();
        for stream in [&rng, &shared] {
            gpu_mmcs
                .preflight_owned_quotient(shape, 64 << 20, true)
                .unwrap();
            let before = session.stats();
            let random = stream.sample_fields(shape.random_words).unwrap();
            let masks = stream.sample_fields(shape.mask_words).unwrap();
            let prepared = session
                .prepare_quotient_commit_with_random(
                    &quotient,
                    chunks,
                    profile::NUM_RANDOM_CODEWORDS,
                    random,
                    masks,
                )
                .unwrap();
            let after = session.stats();
            assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
            assert_eq!(
                after.downloaded_bytes - before.downloaded_bytes,
                after.random_status_bytes - before.random_status_bytes
            );
            let ldes =
                cpu.get_quotient_ldes(domains.clone().into_iter().zip(matrices.clone()), chunks);
            let actual = gpu_mmcs
                .commit_owned_quotient(&prepared, 64 << 20, Some(&session))
                .unwrap();
            compare(&cpu_mmcs, &gpu_mmcs, cpu_mmcs.commit(ldes), actual);
            drop(prepared);
            assert_eq!(
                engine::report("random quotient released")
                    .unwrap()
                    .device_matrix_live_bytes,
                baseline.device_matrix_live_bytes
            );
        }
    }
}

#[test]
#[ignore = "requires OpenCL GPU and a <=3 GiB zero-swap service"]
fn gpu_generated_samples_reject_wrong_commitment_counts_and_sessions() {
    let _shutdown = engine::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let foreign = DeviceSession::new().unwrap();
    let stream = session
        .import_random_stream(ChaCha20Rng::from_seed([77; 32]))
        .unwrap();
    let foreign_stream = foreign
        .import_random_stream(ChaCha20Rng::from_seed([78; 32]))
        .unwrap();
    let spec = MatrixSpec::new(3, 1, Extension::Base, RowOrder::Natural, 1).unwrap();
    let trace = session.upload(spec, &[1; 8]).unwrap();
    let shape = TraceCommitShape::new(spec, profile::NUM_RANDOM_CODEWORDS).unwrap();
    let base = engine::report("random input rejection baseline").unwrap();
    for words in [
        stream.sample_fields(shape.random_words - 1).unwrap(),
        foreign_stream.sample_fields(shape.random_words).unwrap(),
    ] {
        let before = engine::report("random trace before rejection").unwrap();
        assert!(session
            .prepare_trace_commit_with_random(&trace, profile::NUM_RANDOM_CODEWORDS, words)
            .is_err());
        let after = engine::report("random trace rejection").unwrap();
        assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
        assert_eq!(before.allocations, after.allocations);
    }
    assert_eq!(
        engine::report("random trace rejection released")
            .unwrap()
            .device_matrix_live_bytes,
        base.device_matrix_live_bytes
    );
    let spec = MatrixSpec::new(4, 1, Extension::Cubic, RowOrder::Natural, 7).unwrap();
    let quotient = session.upload(spec, &[1; 48]).unwrap();
    let shape = QuotientCommitShape::new(spec, 2, profile::NUM_RANDOM_CODEWORDS).unwrap();
    let base = engine::report("random quotient rejection baseline").unwrap();
    for case in 0..3 {
        let random = if case == 2 { &foreign_stream } else { &stream }
            .sample_fields(shape.random_words - usize::from(case == 0))
            .unwrap();
        let masks = stream
            .sample_fields(shape.mask_words - usize::from(case == 1))
            .unwrap();
        let before = engine::report("random quotient before rejection").unwrap();
        assert!(session
            .prepare_quotient_commit_with_random(
                &quotient,
                2,
                profile::NUM_RANDOM_CODEWORDS,
                random,
                masks
            )
            .is_err());
        let after = engine::report("random quotient rejection").unwrap();
        assert_eq!(before.uploaded_bytes, after.uploaded_bytes);
        assert_eq!(before.allocations, after.allocations);
        assert_eq!(
            after.device_matrix_live_bytes,
            base.device_matrix_live_bytes
        );
    }
}
