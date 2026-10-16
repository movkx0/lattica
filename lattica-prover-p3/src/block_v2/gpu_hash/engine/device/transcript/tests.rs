use super::*;
use crate::config::Challenger;
use p3_challenger::{CanObserve, CanSample, CanSampleBits, GrindingChallenger};
use p3_field::{BasedVectorSpace, PrimeField64};

fn cpu() -> Challenger {
    Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8())
}
fn observe(cpu: &mut Challenger, gpu: &mut DeviceTranscript, words: &[u64]) {
    cpu.observe_slice(&words.iter().map(|&n| Val::new(n)).collect::<Vec<_>>());
    gpu.observe(words).unwrap();
}
fn compare(cpu: &mut Challenger, gpu: &mut DeviceTranscript, count: usize) {
    let expected: Vec<u64> = (0..count)
        .map(|_| {
            let value: Val = cpu.sample();
            value.as_canonical_u64()
        })
        .collect();
    assert_eq!(gpu.sample_fields(count).unwrap(), expected);
}
#[cfg(feature = "gpu")]
fn initialize() {
    super::super::super::initialize_mode(
        super::super::super::Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 8 << 20,
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
fn transcript_memory_plan_rejects_overflow_and_accounts_for_simultaneous_buffers() {
    for words in [
        vec![STATE_WORDS],
        vec![MAX_TRANSCRIPT_WORDS],
        vec![GRIND_BATCH, GRIND_BATCH.div_ceil(GRIND_TILE), 2],
    ] {
        let expected = 1024 + words.iter().sum::<usize>() * 8;
        assert_eq!(
            memory_plan(&words, 1024, expected, usize::MAX).unwrap(),
            expected
        );
        assert!(memory_plan(&words, 1024, expected - 1, usize::MAX).is_err());
        assert!(memory_plan(&words, 1024, expected, words.iter().max().unwrap() * 8 - 1).is_err());
    }
    for words in [vec![], vec![0], vec![usize::MAX], vec![1, 1, 1, 1]] {
        assert!(memory_plan(&words, 0, usize::MAX, usize::MAX).is_err());
    }
    assert!(memory_plan(&[1], usize::MAX - 7, usize::MAX, usize::MAX).is_err());
    assert!(memory_plan(&[1], 9, 8, 8).is_err());
}

#[test]
fn transcript_bit_masks_match_upstream_bounds_including_zero() {
    for bits in 0..usize::BITS.min(64) as usize {
        assert_eq!(bit_mask(bits).unwrap(), (1u64 << bits) - 1);
    }
    for bits in [usize::BITS as usize, 64, 65, usize::MAX] {
        assert!(bit_mask(bits).is_err());
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_bounded_transcript_slots_reject_before_copy_and_return_after_scrubbing() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    assert!(session.new_transcript_bounded(0).is_err());
    let root = session.new_transcript_bounded(2).unwrap();
    let mut a = root.snapshot().unwrap();
    let before = session.stats();
    assert!(root.snapshot().is_err());
    assert_eq!(before, session.stats());
    assert_eq!(live(&session), baseline + 2 * STATE_WORDS * 8);
    assert!(a.sample_fields(3).is_ok());
    drop(a);
    assert_eq!(live(&session), baseline + STATE_WORDS * 8);
    let b = root.snapshot().unwrap();
    drop(root);
    let c = b.snapshot().unwrap();
    assert!(b.snapshot().is_err());
    drop(c);
    drop(b);
    assert_eq!(live(&session), baseline);
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_transcript_host_quota_owns_states_and_concurrent_operations() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let baseline = live(&session);
    let state_bytes = state_host_backing().unwrap();
    // The research constructor has no state-count ceiling; host ownership must
    // still reject a future state before its device allocation or copy.
    let mut root = session.new_transcript().unwrap();
    assert_eq!(session.transcript_host_reserved_bytes(), state_bytes);
    let snapshot = root.snapshot().unwrap();
    assert_eq!(session.transcript_host_reserved_bytes(), 2 * state_bytes);
    drop(snapshot);
    assert_eq!(session.transcript_host_reserved_bytes(), state_bytes);

    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        let holder = threads.spawn(|| {
            let _scope = session
                .reserve_transcript_host(host_storage_plan::Plan {
                    bytes: limits::HOST_BYTES - 2 * state_bytes + 1,
                })
                .unwrap();
            barrier.wait();
            barrier.wait();
        });
        barrier.wait();
        let before = session.stats();
        let rejected = [
            root.snapshot().is_err(),
            session.new_transcript().is_err(),
            root.observe(&[1]).is_err(),
            root.sample_fields(1).is_err(),
            session.next_points([1; 3], &[5]).is_err(),
        ];
        let after = session.stats();
        barrier.wait();
        holder.join().unwrap();
        assert!(rejected.into_iter().all(|rejected| rejected));
        assert_eq!(before, after);
    });
    assert_eq!(session.transcript_host_reserved_bytes(), state_bytes);
    let mut reference = cpu();
    compare(&mut reference, &mut root, 3);

    let other = DeviceSession::new().unwrap();
    let mut foreign = other
        .reserve_transcript_host(host_storage_plan::Plan::observation().unwrap())
        .unwrap();
    let before = session.stats();
    assert!(root.observe_scoped(&[1], &mut foreign).is_err());
    assert_eq!(before, session.stats());
    drop(foreign);
    assert_eq!(other.transcript_host_reserved_bytes(), 0);

    let mut failed = session.new_transcript().unwrap();
    failed.fault = Some(Fault::Unwind);
    let retained = session.transcript_host_reserved_bytes();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = failed.sample_fields(3);
    }))
    .is_err());
    assert_eq!(session.transcript_host_reserved_bytes(), retained);
    drop(failed);
    compare(&mut reference, &mut root, 1);
    drop(root);
    assert_eq!(session.transcript_host_reserved_bytes(), 0);
    assert_eq!(live(&session), baseline);
    eprintln!("gpu_transcript_host_ownership state_bytes={state_bytes} states_retained=true simultaneous_rejection_before_work=true nested_owner_checked=true failure_and_unwind_release=true zero_live_bytes_after_drop=true");
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_transcript_matches_duplex_absorption_extensions_and_query_bits() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    for len in 0..=12 {
        let mut cpu = cpu();
        let mut gpu = session.new_transcript().unwrap();
        let words: Vec<_> = (0..len)
            .map(|i| {
                if i % 2 == 0 {
                    0
                } else {
                    GOLDILOCKS_MODULUS - i as u64
                }
            })
            .collect();
        observe(&mut cpu, &mut gpu, &words);
        for count in [1, 3, 4, 5, 9] {
            compare(&mut cpu, &mut gpu, count);
            observe(&mut cpu, &mut gpu, &[GOLDILOCKS_MODULUS - 1, 1, 0]);
        }
        let quad: crate::config::Challenge = cpu.sample();
        assert_eq!(
            gpu.sample_fields(2).unwrap(),
            quad.as_basis_coefficients_slice()
                .iter()
                .map(|n: &Val| n.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        let cubic: crate::block_v2::profile::Challenge = cpu.sample();
        assert_eq!(
            gpu.sample_fields(3).unwrap(),
            cubic
                .as_basis_coefficients_slice()
                .iter()
                .map(|n: &Val| n.as_canonical_u64())
                .collect::<Vec<_>>()
        );
        for bits in [0, 1, 16, 25, 32, 63] {
            let expected: Vec<_> = (0..17).map(|_| cpu.sample_bits(bits) as u64).collect();
            assert_eq!(gpu.sample_bits(bits, 17).unwrap(), expected);
            compare(&mut cpu, &mut gpu, 3);
        }
    }
    // Different length tags must distinguish zero padding.
    let mut a = session.new_transcript().unwrap();
    let mut b = session.new_transcript().unwrap();
    a.observe(&[7]).unwrap();
    b.observe(&[7, 0]).unwrap();
    assert_ne!(a.sample_fields(4).unwrap(), b.sample_fields(4).unwrap());
    let mut cpu = cpu();
    let mut gpu = session.new_transcript().unwrap();
    let words: Vec<_> = (0..MAX_TRANSCRIPT_WORDS as u64).collect();
    observe(&mut cpu, &mut gpu, &words);
    compare(&mut cpu, &mut gpu, MAX_TRANSCRIPT_WORDS);
    let stats = session.stats();
    assert_eq!(stats.downloaded_bytes, stats.transcript_public_bytes);
    assert_eq!(stats.downloaded_bytes, stats.transcript_sampled_fields * 8);
    assert_eq!(stats.uploaded_bytes, stats.transcript_observed_fields * 8);
    assert!(stats.transcript_device_ns > 0);
    eprintln!("gpu_transcript_conformance stats={stats:?}");
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_transcript_snapshots_are_independent_device_copies_and_scrub_on_drop() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let initial = live(&session);
    for pending in 0..=7 {
        let mut original = session.new_transcript().unwrap();
        let mut reference = cpu();
        observe(&mut reference, &mut original, &[17, 19, 23, 29, 31]);
        compare(&mut reference, &mut original, (pending % 4) + 1);
        observe(&mut reference, &mut original, &vec![41; pending]);
        let before = session.stats();
        let mut snapshot = original.snapshot().unwrap();
        let mut snapshot_cpu = reference.clone();
        let after = session.stats();
        assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(after.transcript_snapshots, before.transcript_snapshots + 1);
        assert_eq!(live(&session), initial + STATE_WORDS * 16);
        observe(&mut reference, &mut original, &[53]);
        compare(&mut reference, &mut original, 11);
        drop(original);
        observe(&mut snapshot_cpu, &mut snapshot, &[61, 67]);
        compare(&mut snapshot_cpu, &mut snapshot, 19);
        let raw = snapshot.state.buffer().clone();
        drop(snapshot);
        assert_eq!(live(&session), initial);
        // Test-only raw handle observes the scrub after typed ownership is gone.
        session
            .with_engine(|engine| {
                let mut words = vec![1u64; STATE_WORDS];
                let fence = engine.fence();
                raw.read(&mut words[..]).enq().map_err(|e| e.to_string())?;
                fence.finish()?;
                assert!(words.iter().all(|&n| n == 0));
                Ok(())
            })
            .unwrap();
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_grinding_matches_single_thread_cpu_and_advances_the_transcript() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    for len in 0..=7 {
        for bits in [0, 1, 8, 16] {
            let mut cpu = cpu();
            let mut gpu = session.new_transcript().unwrap();
            compare(&mut cpu, &mut gpu, len % 4 + 1);
            observe(
                &mut cpu,
                &mut gpu,
                &(0..len).map(|n| n as u64 * 17).collect::<Vec<_>>(),
            );
            let mut verifier = cpu.clone();
            let before = session.stats();
            let expected = pool.install(|| cpu.grind(bits));
            let actual = gpu.grind(bits).unwrap();
            assert_eq!(actual, expected.as_canonical_u64(), "len={len} bits={bits}");
            assert!(verifier.check_witness(bits, Val::new(actual)));
            if bits == 0 {
                assert_eq!(session.stats(), before);
            } else {
                assert_eq!(session.stats().grinding_calls, before.grinding_calls + 1);
                let public: Val = cpu.sample();
                let verified: Val = verifier.sample();
                assert_eq!(public, verified);
                assert_eq!(
                    gpu.sample_fields(1).unwrap(),
                    vec![public.as_canonical_u64()]
                );
            }
            compare(&mut cpu, &mut gpu, 19);
            observe(&mut cpu, &mut gpu, &[GOLDILOCKS_MODULUS - 1, 0]);
            compare(&mut cpu, &mut gpu, 7);
        }
    }
    // Small, non-tile-aligned batches exercise minimum reduction, an uneven
    // final tile and continuation through batches with no accepted witness.
    let mut cpu = cpu();
    let mut gpu = session.new_transcript().unwrap();
    observe(&mut cpu, &mut gpu, &[109, 113, 127]);
    let expected = pool.install(|| cpu.grind(12));
    assert!(expected.as_canonical_u64() > 37);
    assert_eq!(
        gpu.grind_bounded(12, 37, 1 << 20).unwrap(),
        expected.as_canonical_u64()
    );
    compare(&mut cpu, &mut gpu, 29);
    let stats = session.stats();
    assert_eq!(stats.grinding_status_bytes, stats.grinding_batches * 16);
    assert_eq!(
        stats.downloaded_bytes,
        stats.transcript_public_bytes + stats.grinding_status_bytes
    );
    assert!(stats.grinding_device_ns > 0);
    eprintln!("gpu_grinding_conformance stats={stats:?}");
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_transcript_admission_rejects_before_mutation_and_releases_scratch() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let mut gpu = session.new_transcript().unwrap();
    let mut cpu = cpu();
    observe(&mut cpu, &mut gpu, &[101, 103, 107]);
    let before = session.stats();
    for count in [0, MAX_TRANSCRIPT_WORDS + 1, usize::MAX] {
        assert!(gpu.sample_fields(count).is_err());
    }
    assert!(gpu.observe(&vec![0; MAX_TRANSCRIPT_WORDS + 1]).is_err());
    for value in [GOLDILOCKS_MODULUS, u64::MAX] {
        assert!(gpu.observe(&[value]).is_err());
    }
    for bits in [64, usize::MAX] {
        assert!(gpu.sample_bits(bits, 1).is_err());
    }
    for bits in [MAX_GRIND_BITS + 1, 63, usize::MAX] {
        assert!(gpu.grind(bits).is_err());
    }
    assert_eq!(session.stats(), before);
    for allocation_limit in [false, true] {
        let saved = session
            .with_engine(|engine| {
                let saved = (engine.limits.managed_bytes, engine.max_alloc);
                if allocation_limit {
                    engine.max_alloc = 7;
                } else {
                    engine.limits.managed_bytes = engine.accounting.lock().unwrap().live;
                }
                Ok(saved)
            })
            .unwrap();
        let rejected = [
            session.new_transcript().is_err(),
            gpu.snapshot().is_err(),
            gpu.observe(&[1]).is_err(),
            gpu.sample_fields(1).is_err(),
            gpu.grind(16).is_err(),
        ];
        session
            .with_engine(|engine| {
                engine.limits.managed_bytes = saved.0;
                engine.max_alloc = saved.1;
                Ok(())
            })
            .unwrap();
        assert!(rejected.into_iter().all(|rejected| rejected));
        assert_eq!(session.stats(), before);
    }
    let initial = live(&session);
    compare(&mut cpu, &mut gpu, 37);
    assert_eq!(live(&session), initial);
    let mut snapshot = gpu.snapshot().unwrap();
    compare(&mut cpu, &mut snapshot, 37);
    drop(snapshot);
    assert_eq!(live(&session), initial);
    assert!(super::super::super::shutdown().is_err());
    assert!(gpu.sample_fields(1).is_ok());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_transcript_execution_failure_retires_snapshots_without_affecting_other_attempts() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    for fault in [
        Fault::Observe,
        Fault::Sample,
        Fault::Snapshot,
        Fault::Grind,
        Fault::Unwind,
    ] {
        let initial = live(&session);
        let mut gpu = session.new_transcript().unwrap();
        gpu.observe(&[139, 149, 151]).unwrap();
        let mut related = gpu.snapshot().unwrap();
        let mut unrelated = session.new_transcript().unwrap();
        gpu.fault = Some(fault);
        match fault {
            Fault::Observe => assert!(gpu.observe(&[157]).is_err()),
            Fault::Sample => assert!(gpu.sample_fields(3).is_err()),
            Fault::Snapshot => assert!(gpu.snapshot().is_err()),
            Fault::Grind => assert!(gpu.grind(8).is_err()),
            Fault::Unwind => {
                assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = gpu.sample_fields(3);
                }))
                .is_err())
            }
        }
        assert_eq!(live(&session), initial + 3 * STATE_WORDS * 8);
        let before = session.stats();
        for retired in [&mut gpu, &mut related] {
            assert!(retired.observe(&[]).is_err());
            assert!(retired.sample_fields(1).is_err());
            assert!(retired.grind(0).is_err());
            assert!(retired.snapshot().is_err());
        }
        assert_eq!(session.stats(), before);
        compare(&mut cpu(), &mut unrelated, 11);
        drop((gpu, related, unrelated));
        assert_eq!(live(&session), initial);
    }
    // Exhaustion is an execution failure even though no witness was applied.
    let mut gpu = session.new_transcript().unwrap();
    let mut cpu = cpu();
    observe(&mut cpu, &mut gpu, &[163, 167, 173]);
    assert!(!cpu.check_witness(20, Val::new(0)));
    let mut snapshot = gpu.snapshot().unwrap();
    assert!(gpu
        .grind_bounded(20, 1, 1)
        .unwrap_err()
        .contains("budget exhausted"));
    assert!(snapshot.sample_fields(1).is_err());
}
