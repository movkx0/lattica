use super::*;
use crate::{
    config::{Challenger, Val},
    cuda_compute::{Commitments, Matrix},
    gpu_matrix::{Extension, MatrixSpec, RowOrder},
};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, GrindingChallenger};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_symmetric::Permutation;

mod benchmark;

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
fn cpu() -> Challenger {
    Challenger::new(p3_goldilocks::default_goldilocks_poseidon2_8())
}
fn sample(cpu: &mut Challenger, count: usize) -> Vec<u64> {
    (0..count)
        .map(|_| <Challenger as CanSample<Val>>::sample(cpu).as_canonical_u64())
        .collect()
}

#[test]
fn transcript_preflight_checks_whole_operation_and_bit_boundaries() {
    let limits = Limits {
        managed_bytes: 184,
        max_allocation_bytes: 128,
        max_allocations: 5,
        ..Limits::default()
    };
    assert_eq!(admission(&[16, 1, 2], 32, 2, limits).unwrap(), 184);
    assert!(admission(
        &[16, 1, 2],
        32,
        2,
        Limits {
            managed_bytes: 183,
            ..limits
        }
    )
    .is_err());
    assert!(admission(
        &[16, 1, 2],
        32,
        2,
        Limits {
            max_allocation_bytes: 127,
            ..limits
        }
    )
    .is_err());
    assert!(admission(
        &[16, 1, 2],
        32,
        2,
        Limits {
            max_allocations: 4,
            ..limits
        }
    )
    .is_err());
    for words in [&[0][..], &[usize::MAX][..], &[1, 1, 1, 1][..]] {
        assert!(admission(words, 0, 0, limits).is_err());
    }
    assert!(admission(&[1], usize::MAX, 0, limits).is_err());
    assert!(admission(&[1], 0, usize::MAX, limits).is_err());
    assert_eq!(bit_mask(0).unwrap(), 0);
    assert_eq!(bit_mask(63).unwrap(), (1u64 << 63) - 1);
    for bits in [64, 65, usize::MAX] {
        assert!(bit_mask(bits).is_err());
    }
    assert!(limits::STATE_WORDS * 8 + 2 * limits::BATCH_WORDS * 8 < limits::HOST_BYTES);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_transcripts_match_cpu_across_absorb_squeeze_snapshot_and_mask_boundaries() {
    let runtime = runtime(2 << 20, 1 << 20);
    let engine = Transcripts::new(&runtime).unwrap();
    let mut actual = engine.start().unwrap();
    let mut reference = cpu();
    assert_eq!(actual.sample_fields(9).unwrap(), sample(&mut reference, 9));
    for length in [0, 1, 2, 3, 4, 5, 31, 4096] {
        let words: Vec<_> = (0..length)
            .map(|i| {
                if i % 7 == 0 {
                    GOLDILOCKS_MODULUS - 1
                } else {
                    (i * 193 + 7) as u64
                }
            })
            .collect();
        reference.observe_slice(&words.iter().copied().map(Val::new).collect::<Vec<_>>());
        let before = runtime.snapshot();
        actual.observe(&words).unwrap();
        assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
        assert_eq!(
            runtime.snapshot().uploaded_bytes - before.uploaded_bytes,
            length as u64 * 8
        );
        if length == 0 {
            assert_eq!(runtime.snapshot(), before);
        }
        for count in [1, 2, 3, 4, 5, 129] {
            assert_eq!(
                actual.sample_fields(count).unwrap(),
                sample(&mut reference, count)
            );
        }
        for bits in [0, 1, 16, 25, 63] {
            let expected: Vec<_> = (0..17)
                .map(|_| reference.sample_bits(bits) as u64)
                .collect();
            assert_eq!(actual.sample_bits(bits, 17).unwrap(), expected);
        }
    }
    actual.observe(&[17, 19, 23]).unwrap();
    reference.observe([Val::new(17), Val::new(19), Val::new(23)]);
    let before = runtime.snapshot();
    let mut fork = actual.snapshot().unwrap();
    let mut expected_fork = reference.clone();
    let after = runtime.snapshot();
    assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    assert_eq!(
        after.copied_bytes - before.copied_bytes,
        (limits::STATE_WORDS * 8) as u64
    );
    assert!(actual.snapshot().is_err());
    assert_eq!(runtime.snapshot(), after);
    actual.observe(&[29]).unwrap();
    reference.observe(Val::new(29));
    fork.observe(&[31]).unwrap();
    expected_fork.observe(Val::new(31));
    assert_eq!(
        actual.sample_fields(19).unwrap(),
        sample(&mut reference, 19)
    );
    assert_eq!(
        fork.sample_fields(19).unwrap(),
        sample(&mut expected_fork, 19)
    );
    drop(fork);
    assert!(actual.snapshot().is_ok());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_transcript_resident_observations_and_samples_feed_native_hashing() {
    let runtime = runtime(2 << 20, 1 << 20);
    let engine = Transcripts::new(&runtime).unwrap();
    let commits = Commitments::new(&runtime).unwrap();
    let mut actual = engine.start().unwrap();
    let mut reference = cpu();
    let words = [
        0,
        7,
        u64::MAX,
        GOLDILOCKS_MODULUS,
        GOLDILOCKS_MODULUS + 1,
        19,
        23,
        0,
    ];
    let input = runtime.allocate(words.len()).unwrap();
    input.write(0, &words).unwrap();
    reference.observe_slice(
        &words[2..7]
            .iter()
            .copied()
            .map(Val::from_u64)
            .collect::<Vec<_>>(),
    );
    let before = runtime.snapshot();
    actual.observe_resident(&input, 2, 5).unwrap();
    let sampled = actual.sample_resident(8).unwrap();
    let matrix = Matrix {
        spec: MatrixSpec::new(0, 8, Extension::Base, RowOrder::Natural, 1).unwrap(),
        buffer: sampled,
    };
    let output = commits.permute(&matrix).unwrap();
    let after = runtime.snapshot();
    assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
    assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
    let mut expected: [Val; 8] = sample(&mut reference, 8)
        .into_iter()
        .map(Val::new)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut expected);
    assert_eq!(
        output.read(64).unwrap(),
        expected.map(|value| value.as_canonical_u64())
    );
    assert_eq!(actual.sample_fields(5).unwrap(), sample(&mut reference, 5));
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_grinding_matches_cpu_minimum_and_post_witness_state() {
    let runtime = runtime(2 << 20, 1 << 20);
    let engine = Transcripts::new(&runtime).unwrap();
    let mut actual = engine.start().unwrap();
    let mut reference = cpu();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    let before = runtime.snapshot();
    assert_eq!(actual.grind(0).unwrap(), 0);
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(pool.install(|| reference.grind(0)), Val::ZERO);
    for pending in 0..4 {
        let input: Vec<_> = (0..pending).map(|i| 17 + i as u64).collect();
        reference.observe_slice(&input.iter().copied().map(Val::new).collect::<Vec<_>>());
        actual.observe(&input).unwrap();
        let expected = pool.install(|| reference.grind(8)).as_canonical_u64();
        let before = runtime.snapshot();
        // Non-power-of-two batches exercise partial tiles and multi-batch search.
        assert_eq!(actual.grind_bounded(8, 257, 1 << 16).unwrap(), expected);
        let after = runtime.snapshot();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(
            after.downloaded_bytes - before.downloaded_bytes,
            ((expected as usize / 257 + 1) * 16) as u64
        );
        assert_eq!(after.live_bytes, before.live_bytes);
        assert_eq!(
            actual.sample_fields(13).unwrap(),
            sample(&mut reference, 13)
        );
    }
    let expected = pool.install(|| reference.grind(16)).as_canonical_u64();
    assert_eq!(actual.grind(16).unwrap(), expected);
    assert_eq!(actual.sample_fields(9).unwrap(), sample(&mut reference, 9));
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_transcript_rejections_preserve_state_and_attempt_retirement_is_shared() {
    let runtime = runtime(64 << 10, 32 << 10);
    let engine = Transcripts::new(&runtime).unwrap();
    let mut actual = engine.start().unwrap();
    let input = runtime.allocate(8).unwrap();
    let before = runtime.snapshot();
    assert!(actual.observe(&[GOLDILOCKS_MODULUS]).is_err());
    assert!(actual.observe(&vec![0; limits::BATCH_WORDS + 1]).is_err());
    for count in [0, limits::BATCH_WORDS + 1, usize::MAX] {
        assert!(actual.sample_fields(count).is_err());
    }
    for bits in [64, usize::MAX] {
        assert!(actual.sample_bits(bits, 1).is_err());
    }
    assert!(actual.observe_resident(&input, usize::MAX, 1).is_err());
    assert!(actual.observe_resident(&input, 7, 2).is_err());
    let alias = actual.state.clone();
    assert!(actual.observe_resident(&alias, 0, 1).is_err());
    drop(alias);
    assert!(actual.grind(limits::GRIND_BITS + 1).is_err());
    assert!(actual.grind_bounded(4, 0, 17).is_err());
    assert!(actual.grind_bounded(4, 1, 0).is_err());
    assert!(actual
        .grind_bounded(4, limits::GRIND_BATCH + 1, 17)
        .is_err());
    assert!(actual
        .grind_bounded(4, 1, limits::GRIND_CANDIDATES + 1)
        .is_err());
    // The normal grinding workspace is larger than this runtime's allocation
    // ceiling; rejection must happen before any candidate work or state change.
    assert!(actual.grind(8).is_err());
    assert_eq!(runtime.snapshot(), before);
    let mut reference = cpu();
    assert_eq!(actual.sample_fields(9).unwrap(), sample(&mut reference, 9));
    let mut filler = Vec::new();
    while runtime.snapshot().live_bytes < 64 << 10 {
        let remaining = (64 * 1024 - runtime.snapshot().live_bytes) / 8;
        filler.push(runtime.allocate(remaining.min(4096)).unwrap());
    }
    let before = runtime.snapshot();
    assert!(actual.snapshot().is_err());
    assert!(actual.sample_fields(1).is_err());
    assert!(actual.observe(&[17]).is_err());
    assert_eq!(runtime.snapshot(), before);
    assert!(actual.check_live().is_ok());
    drop(filler);
    assert_eq!(actual.sample_fields(5).unwrap(), sample(&mut reference, 5));
    actual.begin_attempt().unwrap().complete();
    let mut fork = actual.snapshot().unwrap();
    drop(actual.begin_attempt().unwrap());
    let before = runtime.snapshot();
    assert!(actual.observe(&[]).is_err());
    assert!(fork.sample_fields(1).is_err());
    assert!(fork.grind(0).is_err());
    assert!(fork.snapshot().is_err());
    assert_eq!(runtime.snapshot(), before);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_transcript_partial_failures_and_exhaustion_retire_snapshots() {
    let runtime = runtime(2 << 20, 1 << 20);
    let engine = Transcripts::new(&runtime).unwrap();
    for fault in [Fault::Snapshot, Fault::Observe, Fault::Sample, Fault::Grind] {
        let mut actual = engine.start().unwrap();
        let mut fork = Some(actual.snapshot().unwrap());
        actual.fault = Some(fault);
        if fault == Fault::Snapshot {
            drop(fork.take());
        }
        let before = runtime.snapshot();
        let failed = match fault {
            Fault::Snapshot => actual.snapshot().map(|_| ()),
            Fault::Observe => actual.observe(&[17, 19, 23]),
            Fault::Sample => actual.sample_fields(7).map(|_| ()),
            Fault::Grind => actual.grind_bounded(4, 257, 1 << 12).map(|_| ()),
            Fault::PanicSample => unreachable!(),
        };
        assert!(failed.is_err());
        assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
        assert!(actual.observe(&[]).is_err());
        // Snapshot fault has retired its temporary state and returned the slot.
        if let Some(fork) = &mut fork {
            assert!(fork.sample_fields(1).is_err());
        }
    }
    let mut actual = engine.start().unwrap();
    let mut reference = cpu();
    let seed = (0u64..)
        .find(|&seed| {
            let mut candidate = cpu();
            candidate.observe(Val::new(seed));
            !candidate.check_witness(8, Val::ZERO)
        })
        .unwrap();
    actual.observe(&[seed]).unwrap();
    reference.observe(Val::new(seed));
    let mut fork = actual.snapshot().unwrap();
    let before = runtime.snapshot();
    assert!(actual.grind_bounded(8, 1, 1).is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert_eq!(
        runtime.snapshot().downloaded_bytes - before.downloaded_bytes,
        16
    );
    assert!(fork.sample_fields(1).is_err());
    assert!(!reference.check_witness(8, Val::ZERO));
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_transcript_unwind_and_runtime_failure_are_fail_closed() {
    let runtime = runtime(2 << 20, 1 << 20);
    let engine = Transcripts::new(&runtime).unwrap();
    let mut actual = engine.start().unwrap();
    let mut fork = actual.snapshot().unwrap();
    actual.fault = Some(Fault::PanicSample);
    let before = runtime.snapshot();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| actual.sample_fields(3)));
    assert!(result.is_err());
    assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
    assert!(fork.observe(&[]).is_err());
    drop(fork);
    drop(actual);
    // A retired family does not poison independent, freshly created attempts.
    let mut fresh = engine.start().unwrap();
    assert_eq!(fresh.sample_fields(7).unwrap(), sample(&mut cpu(), 7));
    runtime.state.fail();
    let before = runtime.snapshot();
    assert!(fresh.observe(&[]).is_err());
    assert!(fresh.sample_fields(1).is_err());
    assert!(fresh.snapshot().is_err());
    assert!(fresh.grind(0).is_err());
    assert_eq!(runtime.snapshot(), before);
}

#[test]
#[ignore = "requires pinned NVRTC but no GPU context"]
fn cuda_transcript_kernels_compile_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
