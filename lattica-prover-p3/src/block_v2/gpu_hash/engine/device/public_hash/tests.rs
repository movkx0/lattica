use super::*;
use crate::block_v2::commitment;

#[test]
fn public_hash_stream_batches_validate_lengths_fields_and_failures_without_a_device() {
    for length in [0, 1, 3, 4, 5, 4095, 4096, 4097, 8195] {
        let mut producer = |emit: &mut FieldSink<'_>| {
            for i in 0..length {
                emit(i as u64)?;
            }
            Ok(())
        };
        assert_eq!(stream_length(7, &mut producer).unwrap(), length);
        let mut actual = Vec::new();
        let mut calls = 0;
        batches(length, &mut producer, |fields, first| {
            assert_eq!(first, calls == 0);
            assert!(fields.len() <= BATCH_WORDS);
            actual.extend_from_slice(fields);
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(actual, (0..length as u64).collect::<Vec<_>>());
        assert_eq!(calls, length.div_ceil(BATCH_WORDS).max(1));
    }
    for (expected, actual, invalid) in [
        (5, 4, None),
        (4, 5, None),
        (4097, 4097, Some(4096)),
        (0, 1, None),
    ] {
        assert!(batches(
            expected,
            &mut |emit| {
                for i in 0..actual {
                    emit(if invalid == Some(i) {
                        GOLDILOCKS_MODULUS
                    } else {
                        1
                    })?;
                }
                Ok(())
            },
            |_, _| Ok(())
        )
        .is_err());
    }
    // A buggy producer may swallow the callback's error. Rejection is sticky.
    assert!(stream_length(0, &mut |emit| {
        let _ = emit(u64::MAX);
        Ok(())
    })
    .is_err());
    assert!(batches(
        1,
        &mut |emit| {
            let _ = emit(u64::MAX);
            let _ = emit(1);
            Ok(())
        },
        |_, _| Ok(())
    )
    .is_err());
    assert!(batches(
        0,
        &mut |emit| {
            let _ = emit(1);
            Ok(())
        },
        |_, _| Ok(())
    )
    .is_err());
    let mut calls = 0;
    assert!(batches(
        BATCH_WORDS * 2,
        &mut |emit| {
            for _ in 0..BATCH_WORDS * 2 {
                let _ = emit(1);
            }
            Ok(())
        },
        |_, _| {
            calls += 1;
            Err("consumer failed".into())
        }
    )
    .is_err());
    assert_eq!(calls, 1);
    assert!(stream_length(GOLDILOCKS_MODULUS, &mut |_| panic!("invalid domain")).is_err());
    assert!(stream_length(0, &mut |_| Err("source failed".into())).is_err());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_public_hash_stream_rejects_changed_replays_and_reports_completed_batches() {
    use crate::proving::{Backend, Capabilities, Policy, Profile, Request, Run, Stage};
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    for mode in 0..4 {
        let mut pass = 0;
        let before = session.stats();
        let run = Run::new(
            "changed stream",
            Request::compatible(),
            Capabilities::cpu(Profile::BlockV2Cubic, true, true),
        )
        .unwrap();
        let result = session.hash_public_stream_reported(
            7,
            |emit| {
                pass += 1;
                let length = if pass == 2 {
                    match mode {
                        0 => BATCH_WORDS,
                        1 => BATCH_WORDS + 2,
                        _ => BATCH_WORDS + 1,
                    }
                } else {
                    BATCH_WORDS + 1
                };
                for i in 0..length {
                    if pass == 2 && mode == 3 && i == BATCH_WORDS {
                        return Err("source failed".into());
                    }
                    emit(if pass == 2 && mode == 2 && i == BATCH_WORDS {
                        GOLDILOCKS_MODULUS
                    } else {
                        1
                    })?;
                }
                Ok(())
            },
            &run,
            Stage::Preprocessing,
        );
        assert!(result.is_err());
        let report = run.finish(false).unwrap();
        assert_eq!(report.observations.len(), 1);
        assert_eq!(report.observations[0].backend, Backend::OpenCl);
        assert_eq!(report.observations[0].completed_calls, 1);
        assert!(report.observations[0].device_ns > 0);
        let after = session.stats();
        assert_eq!(after.public_hash_calls, before.public_hash_calls);
        assert_eq!(after.public_hash_batches - before.public_hash_batches, 1);
        assert_eq!(
            after.uploaded_bytes - before.uploaded_bytes,
            BATCH_WORDS as u64 * 8
        );
        assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
        assert_eq!(live(&session), baseline);
    }
    let before = session.stats();
    assert!(session
        .hash_public_stream_inner(
            7,
            |emit| {
                for _ in 0..BATCH_WORDS {
                    emit(1)?;
                }
                emit(GOLDILOCKS_MODULUS)
            },
            |_| Ok(())
        )
        .is_err());
    assert_eq!(session.stats(), before);
    let rejected = Run::new(
        "stream policy",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        Capabilities::cpu(Profile::BlockV2Cubic, true, true),
    )
    .unwrap();
    assert!(session
        .hash_public_stream_reported(
            7,
            |_| panic!("rejected before source"),
            &rejected,
            Stage::Preprocessing
        )
        .is_err());
    assert_eq!(session.stats(), before);
    assert!(rejected.finish(false).unwrap().observations.is_empty());
    // A failed replay leaves no state behind that can affect the next digest.
    let fields = vec![GOLDILOCKS_MODULUS - 1; BATCH_WORDS + 1];
    assert_eq!(
        session
            .hash_public_stream_inner(
                7,
                |emit| {
                    for &field in &fields {
                        emit(field)?;
                    }
                    Ok(())
                },
                |_| Ok(())
            )
            .unwrap(),
        commitment::hash_fields(7, &fields).unwrap()
    );
    assert_eq!(live(&session), baseline);
}

#[cfg(feature = "gpu")]
fn initialize() {
    super::super::super::initialize_mode(
        super::super::super::Limits {
            managed_bytes: 1 << 20,
            tile_bytes: 1 << 18,
            staging_bytes: 1 << 16,
        },
        super::super::super::TransferMode::Serial,
    )
    .unwrap();
}
fn live(session: &DeviceSession) -> usize {
    session
        .with_engine(|engine| Ok(engine.accounting.lock().unwrap().device_live))
        .unwrap()
}

#[test]
fn public_hash_fields_and_fixed_workspace_are_checked_without_a_device() {
    assert_eq!(BATCH_WORDS % 4, 0);
    assert_eq!(WORKSPACE_BYTES, 32800);
    assert_eq!(MAX_ALLOCATION_BYTES, 32768);
    assert_eq!(HOST_BYTES, 65536);
    assert_eq!(validate(GOLDILOCKS_MODULUS - 1, &[]).unwrap(), 0);
    assert_eq!(validate(0, &[0, GOLDILOCKS_MODULUS - 1]).unwrap(), 2);
    assert!(validate(GOLDILOCKS_MODULUS, &[]).is_err());
    assert!(validate(0, &[GOLDILOCKS_MODULUS]).is_err());
    assert!(validate(0, &[u64::MAX]).is_err());
    assert!((programs::PUBLIC_VALUES as u64 + 1) * 8 <= WORKSPACE_BYTES);
    assert!(programs::PUBLIC_VALUES as u64 * 8 <= MAX_ALLOCATION_BYTES);
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_summary_validation_checks_raw_words_and_policy_with_fixed_memory() {
    use crate::proving::{Backend, Capabilities, Policy, Profile, Request, Run, Stage};
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    let caps = || Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    let mut valid = [0; programs::PUBLIC_VALUES];
    valid[..16].fill(u32::MAX as u64);
    valid[programs::MODE] = 12;
    valid[programs::LEVEL] = u64::from(commitment::DEPTH);
    valid[programs::COUNT] = 64;
    valid[programs::ROOT..programs::ROOT + 4].fill(GOLDILOCKS_MODULUS - 1);
    let rejected = Run::new(
        "summary policy",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        caps(),
    )
    .unwrap();
    let before = session.stats();
    assert!(session
        .validate_public_summary_reported(&valid, 12, &rejected, Stage::PublicValues)
        .is_err());
    assert_eq!(session.stats(), before);
    assert!(rejected.finish(false).unwrap().observations.is_empty());

    let mut cases = vec![(valid, 12, None), (valid, 0, Some("node metadata range"))];
    for index in 0..16 {
        let mut words = valid;
        words[index] = 1 << 32;
        cases.push((words, 12, Some("noncanonical context limb")));
    }
    for index in programs::ROOT..programs::ROOT + 4 {
        for value in [GOLDILOCKS_MODULUS, u64::MAX] {
            let mut words = valid;
            words[index] = value;
            cases.push((words, 12, Some("noncanonical Goldilocks field element")));
        }
    }
    for (index, value) in [
        (programs::MODE, 0),
        (programs::MODE, 13),
        (programs::LEVEL, 7),
        (programs::LEVEL, 64),
        (programs::LEVEL, u64::MAX),
        (programs::COUNT, 65),
        (programs::COUNT, u64::MAX),
    ] {
        let mut words = valid;
        words[index] = value;
        cases.push((words, 12, Some("node metadata range")));
    }
    for (words, modes, error) in cases {
        let run = Run::new("summary words", Request::compatible(), caps()).unwrap();
        let before = session.stats();
        let result =
            session.validate_public_summary_reported(&words, modes, &run, Stage::PublicValues);
        assert_eq!(result.err().as_deref(), error);
        let report = run.finish(error.is_none()).unwrap();
        assert_eq!(report.observations.len(), 1);
        let observation = &report.observations[0];
        assert_eq!(observation.stage, Stage::PublicValues);
        assert_eq!(observation.backend, Backend::OpenCl);
        assert_eq!(observation.calls, 1);
        assert_eq!(observation.completed_calls, 1);
        assert!(observation.device_ns > 0);
        let after = session.stats();
        assert_eq!(after.public_hash_calls, before.public_hash_calls);
        assert_eq!(
            after.uploaded_bytes - before.uploaded_bytes,
            std::mem::size_of_val(&words) as u64
        );
        assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 8);
        assert_eq!(live(&session), baseline);
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_public_hash_matches_protocol_at_chunk_boundaries_with_fixed_memory() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    for domain in [0, 0x4c42563210, GOLDILOCKS_MODULUS - 1] {
        for length in [0usize, 1, 3, 4, 5, 4095, 4096, 4097, 8195, 65537] {
            let fields: Vec<_> = (0..length)
                .map(|i| {
                    if i % 2 == 0 {
                        i as u64
                    } else {
                        GOLDILOCKS_MODULUS - i as u64
                    }
                })
                .collect();
            let before = session.stats();
            assert_eq!(
                session.hash_public_fields(domain, &fields).unwrap(),
                commitment::hash_fields(domain, &fields).unwrap()
            );
            let after = session.stats();
            assert_eq!(after.public_hash_calls - before.public_hash_calls, 1);
            assert_eq!(
                after.public_hash_batches - before.public_hash_batches,
                length.div_ceil(BATCH_WORDS).max(1) as u64
            );
            assert_eq!(
                after.public_hash_fields - before.public_hash_fields,
                length as u64
            );
            assert_eq!(
                after.public_hash_permutations - before.public_hash_permutations,
                length.div_ceil(4) as u64
            );
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                length as u64 * 8
            );
            assert_eq!(after.downloaded_bytes - before.downloaded_bytes, 32);
            assert!(after.public_hash_device_ns > before.public_hash_device_ns);
            assert_eq!(live(&session), baseline);
        }
    }
    // The message itself cannot fit in the 1 MiB managed allowance.
    let fields = vec![GOLDILOCKS_MODULUS - 1; (1 << 17) + 1];
    assert_eq!(
        session.hash_public_fields(7, &fields).unwrap(),
        commitment::hash_fields(7, &fields).unwrap()
    );
    assert_ne!(
        session.hash_public_fields(7, &[1]).unwrap(),
        session.hash_public_fields(7, &[1, 0]).unwrap()
    );
    assert_eq!(live(&session), baseline);
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_public_hash_rejects_before_upload_and_discards_failed_state() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    let before = session.stats();
    let mut invalid = vec![1; BATCH_WORDS + 1];
    invalid[BATCH_WORDS] = GOLDILOCKS_MODULUS;
    assert!(session.hash_public_fields(7, &invalid).is_err());
    assert!(session.hash_public_fields(GOLDILOCKS_MODULUS, &[]).is_err());
    assert_eq!(session.stats(), before);
    let limits = session
        .with_engine(|engine| {
            let old = (engine.limits.managed_bytes, engine.max_alloc);
            engine.limits.managed_bytes =
                engine.accounting.lock().unwrap().live + WORKSPACE_BYTES as usize - 1;
            Ok(old)
        })
        .unwrap();
    assert!(session.hash_public_fields(7, &[1]).is_err());
    assert_eq!(session.stats(), before);
    session
        .with_engine(|engine| {
            engine.limits.managed_bytes = limits.0;
            engine.max_alloc = MAX_ALLOCATION_BYTES as usize - 1;
            Ok(())
        })
        .unwrap();
    assert!(session.hash_public_fields(7, &[1]).is_err());
    assert_eq!(session.stats(), before);
    session
        .with_engine(|engine| {
            engine.max_alloc = limits.1;
            Ok(())
        })
        .unwrap();
    let fields = vec![17; BATCH_WORDS + 1];
    assert!(session
        .hash_public_fields_inner(7, &fields, |_| Err("injected after GPU batch".into()))
        .is_err());
    let failed = session.stats();
    assert_eq!(failed.public_hash_batches - before.public_hash_batches, 1);
    assert_eq!(failed.public_hash_calls, before.public_hash_calls);
    assert_eq!(failed.downloaded_bytes, before.downloaded_bytes);
    assert_eq!(live(&session), baseline);
    assert_eq!(
        session.hash_public_fields(7, &fields).unwrap(),
        commitment::hash_fields(7, &fields).unwrap()
    );
    assert_eq!(live(&session), baseline);
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_public_hash_reports_real_batches_and_rejects_cpu_policy_before_work() {
    use crate::proving::{Backend, Capabilities, Policy, Profile, Request, Run, Stage};
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let caps = || Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    let rejected = Run::new(
        "public hash",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        caps(),
    )
    .unwrap();
    let before = session.stats();
    assert!(session
        .hash_public_fields_reported(7, &[1], &rejected, Stage::PublicValues)
        .is_err());
    assert_eq!(session.stats(), before);
    assert!(rejected.finish(false).unwrap().observations.is_empty());
    let run = Run::new("public hash", Request::compatible(), caps()).unwrap();
    assert!(session
        .hash_public_fields_reported(GOLDILOCKS_MODULUS, &[], &run, Stage::PublicValues)
        .is_err());
    assert!(run.finish(false).unwrap().observations.is_empty());
    let run = Run::new("public hash", Request::compatible(), caps()).unwrap();
    let fields = vec![17; BATCH_WORDS + 3];
    assert_eq!(
        session
            .hash_public_fields_reported(7, &fields, &run, Stage::PublicValues)
            .unwrap(),
        commitment::hash_fields(7, &fields).unwrap()
    );
    let report = run.finish(true).unwrap();
    assert_eq!(report.observations.len(), 1);
    let observation = &report.observations[0];
    assert_eq!(observation.stage, Stage::PublicValues);
    assert_eq!(observation.backend, Backend::OpenCl);
    assert_eq!(observation.calls, 2);
    assert_eq!(observation.completed_calls, 2);
    assert_eq!(observation.inclusive_ns, 0);
    assert_eq!(
        observation.device_ns,
        session.stats().public_hash_device_ns - before.public_hash_device_ns
    );
    assert!(!report.stage_coverage_complete);
}
