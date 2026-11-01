use super::*;

#[test]
fn batch_census_and_canonical_validation_precede_execution() {
    assert!(Footprint::for_streams::<std::iter::Empty<Result<u64, String>>>(0).is_err());
    assert!(Footprint::for_streams::<std::iter::Empty<Result<u64, String>>>(MAX_STREAMS + 1).is_err());
    for n in 1..=MAX_STREAMS {
        let p = Footprint::for_streams::<std::iter::Empty<Result<u64, String>>>(n).unwrap();
        assert_eq!(p.device_bytes, n as u64 * (4096 + 8) * 8);
        assert!(p.host_bytes > p.device_bytes);
    }
    for (domain, total, count, values, ok) in [
        (1, 4, 4, vec![0, 1, GOLDILOCKS_MODULUS - 1, 3], true),
        (GOLDILOCKS_MODULUS, 4, 4, vec![0; 4], false),
        (1, 3, 4, vec![0; 4], false),
        (1, 4, 4, vec![GOLDILOCKS_MODULUS; 4], false),
        (1, 4, 4, vec![0; 3], false),
        (1, 4, 4, vec![0; 5], false),
    ] {
        let job = Job { domain, total_fields: total, count,
            fields: values.iter().copied().map(Ok), state: None };
        assert_eq!(validate(&[job]).is_ok(), ok);
    }
}

fn run() -> Run {
    use crate::proving::{Capabilities, CoverageScope, Policy, Request};
    let mut caps = Capabilities::cpu(crate::proving::Profile::BlockV2Cubic, true, false)
        .scoped(CoverageScope::Operation, &[Stage::Preprocessing]);
    caps.set(Stage::Preprocessing, Backend::OpenCl);
    Run::new("public_hash_batch_differential", Request { policy: Policy::GpuRequired, emit_report: false }, caps).unwrap()
}

#[test]
#[ignore = "requires isolated OpenCL GPU and guarded zero-swap execution"]
fn gpu_identity_prefix_batches_match_exact_serial_hash_and_release_buffers() {
    let _shutdown = super::super::super::super::TestShutdownGuard;
    super::super::tests::initialize();
    let session = DeviceSession::new().unwrap();
    let live = super::super::tests::live(&session);
    for n in 1..=MAX_STREAMS {
        let inputs: Vec<Vec<u64>> = (0..n).map(|i| {
            let lengths = [0, 1, 3, 4, 63, 64, 65, 4095, 4096, 4097, 8191, 8192, 8193, 16, 8, 7];
            let length = lengths[i % lengths.len()];
            (0..length).map(|j| [0, 1, GOLDILOCKS_MODULUS - 1, (j + i) as u64][j % 4]).collect()
        }).collect();
        for split in [0usize, 4, 64, 4096, usize::MAX] {
            let batch: Vec<_> = inputs.iter().enumerate().map(|(i, fields)| {
                let prefix_fields = split.min(fields.len()) / 4 * 4;
                Input { domain: (i + 1) as u64, total_fields: fields.len(), prefix_fields,
                    fields: fields[..prefix_fields].iter().copied().map(Ok) }
            }).collect();
            let run = run();
            let prefixes = session.hash_public_prefix_batch(batch, &run, 2 << 20).unwrap();
            assert_eq!(super::super::tests::live(&session), live);
            for (i, (prefix, fields)) in prefixes.into_iter().zip(&inputs).enumerate() {
                let remaining = &fields[split.min(fields.len()) / 4 * 4..];
                let actual = session.finish_public_prefix(prefix, remaining, &run, 2 << 20).unwrap();
                assert_eq!(actual, commitment::hash_fields((i + 1) as u64, fields).unwrap());
                assert_eq!(super::super::tests::live(&session), live);
            }
            let report = run.finish(true).unwrap();
            assert!(report.stage_coverage_complete);
        }
    }
    println!("PUBLIC_HASH_EXECUTION {}", serde_json::to_string(
        &crate::block_v2::gpu_hash::engine::public_hash_execution().unwrap().unwrap()).unwrap());
}

#[test]
#[ignore = "requires isolated OpenCL GPU and guarded zero-swap execution"]
fn gpu_identity_batch_rejects_invalid_inputs_without_dispatch_or_retained_buffers() {
    let _shutdown = super::super::super::super::TestShutdownGuard;
    super::super::tests::initialize();
    let session = DeviceSession::new().unwrap();
    let live = super::super::tests::live(&session);
    let before = session.stats();
    let run = run();
    for (prefix_fields, allowance, fields) in [
        (3, 2 << 20, [0u64; 4]), (4, 0, [0; 4]),
        (4, 2 << 20, [GOLDILOCKS_MODULUS; 4]),
    ] {
        assert!(session.hash_public_prefix_batch(vec![Input { domain: 1, total_fields: 4,
            prefix_fields, fields: fields.iter().copied().map(Ok) }], &run, allowance).is_err());
    }
    assert_eq!(session.stats().public_hash_device_ns, before.public_hash_device_ns);
    assert_eq!(super::super::tests::live(&session), live);
}

#[test]
#[ignore = "requires isolated OpenCL GPU and guarded zero-swap execution"]
fn gpu_identity_batch_replay_failure_drains_queued_work_before_releasing_buffers() {
    // Fault injection: the census clone succeeds, while the execution iterator
    // fails either after a queued upload or after a completed first chunk.
    struct ReplayFailure { offset: usize, fail_at: Option<usize> }
    impl Clone for ReplayFailure {
        fn clone(&self) -> Self { Self { offset: self.offset, fail_at: None } }
    }
    impl Iterator for ReplayFailure {
        type Item = Result<u64, String>;
        fn next(&mut self) -> Option<Self::Item> {
            let at = self.offset;
            self.offset += 1;
            if at == 8192 { None }
            else if self.fail_at == Some(at) { Some(Err("injected execution stream failure".into())) }
            else { Some(Ok(at as u64)) }
        }
    }
    let _shutdown = super::super::super::super::TestShutdownGuard;
    super::super::tests::initialize();
    let session = DeviceSession::new().unwrap();
    let live = super::super::tests::live(&session);
    for fail_at in [0, 4097] {
        let before = session.stats();
        assert!(session.hash_public_prefix_batch(vec![Input { domain: 9, total_fields: 8192,
            prefix_fields: 8192, fields: ReplayFailure { offset: 0, fail_at: Some(fail_at) } }],
            &run(), 2 << 20).is_err());
        assert_eq!(super::super::tests::live(&session), live);
        assert_eq!(session.stats().public_hash_batches - before.public_hash_batches,
            u64::from(fail_at != 0));
    }
    println!("PUBLIC_HASH_EXECUTION {}", serde_json::to_string(
        &crate::block_v2::gpu_hash::engine::public_hash_execution().unwrap().unwrap()).unwrap());
    drop(session);
    crate::block_v2::gpu_hash::shutdown().unwrap();
}
