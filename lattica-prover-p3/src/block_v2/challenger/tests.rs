use super::*;
use p3_field::PrimeCharacteristicRing;

fn cpu() -> CpuChallenger {
    CpuChallenger::new(p3_goldilocks::default_goldilocks_poseidon2_8())
}
fn adapter() -> CandidateChallenger {
    CandidateChallenger::new(p3_goldilocks::default_goldilocks_poseidon2_8())
}

fn exercise(mut reference: CpuChallenger, mut actual: CandidateChallenger) {
    let values: Vec<_> = (0..8203).map(|i| Val::from_usize(i * 19)).collect();
    reference.observe_slice(&values);
    actual.observe_slice(&values);
    let hash = Hash::<Val, Val, 4>::from([Val::new(9); 4]);
    reference.observe(hash);
    actual.observe(hash);
    let cap = MerkleCap::<Val, [Val; 4]>::new(vec![[Val::new(13); 4]; 64]);
    reference.observe(&cap);
    actual.observe(&cap);
    reference.observe(cap.clone());
    actual.observe(cap);
    let nested = vec![vec![Val::new(7); 9], vec![Val::ZERO, Val::NEG_ONE]];
    reference.observe(nested.clone());
    actual.observe(nested);
    let extension =
        crate::config::Challenge::from_basis_coefficients_fn(|i| Val::from_usize(i + 71));
    reference.observe_algebra_element(extension);
    actual.observe_algebra_element(extension);
    let cubics: Vec<_> = (0..1370)
        .map(|i| {
            super::super::profile::Challenge::from_basis_coefficients_fn(|j| Val::from_usize(i + j))
        })
        .collect();
    reference.observe_algebra_slice(&cubics);
    actual.observe_algebra_slice(&cubics);
    for _ in 0..9 {
        assert_eq!(
            <CpuChallenger as CanSample<Val>>::sample(&mut reference),
            <CandidateChallenger as CanSample<Val>>::sample(&mut actual)
        );
        assert_eq!(
            reference.sample_algebra_element::<crate::config::Challenge>(),
            actual.sample_algebra_element::<crate::config::Challenge>()
        );
        assert_eq!(
            reference.sample_algebra_element::<super::super::profile::Challenge>(),
            actual.sample_algebra_element::<super::super::profile::Challenge>()
        );
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap();
    for bits in [0, 4, 16] {
        let expected = pool.install(|| reference.grind(bits));
        assert_eq!(pool.install(|| actual.grind(bits)), expected);
        for bits in [0, 1, 16, 25, 63] {
            let expected: Vec<_> = (0..128).map(|_| reference.sample_bits(bits)).collect();
            let sampled = actual.sample_bits_vec(bits, 128);
            assert_eq!(sampled.capacity(), 128);
            assert_eq!(sampled, expected);
        }
    }
    let mut fork = actual.clone();
    let mut reference_fork = reference.clone();
    actual.observe(Val::new(97));
    reference.observe(Val::new(97));
    fork.observe(Val::new(101));
    reference_fork.observe(Val::new(101));
    for (mut actual, mut reference) in [(actual, reference), (fork, reference_fork)] {
        assert!(actual.check_witness(0, Val::NEG_ONE));
        assert!(reference.check_witness(0, Val::NEG_ONE));
        assert_eq!(
            actual.check_witness(16, Val::new(1)),
            reference.check_witness(16, Val::new(1))
        );
        assert_eq!(
            actual.sample_algebra_element::<super::super::profile::Challenge>(),
            reference.sample_algebra_element::<super::super::profile::Challenge>()
        );
    }
}

#[test]
fn cpu_adapter_preserves_upstream_observations_sampling_and_grinding() {
    assert!(!adapter().is_gpu());
    exercise(cpu(), adapter());
}

#[test]
fn cpu_adapter_conversion_preserves_pending_state() {
    let mut reference = cpu();
    reference.observe([Val::new(37), Val::NEG_ONE, Val::ZERO]);
    let actual = reference.clone().into();
    exercise(reference, actual);
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
#[test]
fn cpu_adapter_does_not_initialize_a_device_or_require_an_attempt() {
    let challenger = adapter();
    assert!(challenger.begin_attempt().unwrap().is_none());
    assert_eq!(challenger.backend_name(), "cpu");
    let run = crate::proving::Run::new(
        "cpu transcript",
        crate::proving::Request::compatible(),
        crate::proving::legacy_cpu(),
    )
    .unwrap();
    assert!(challenger.observe_execution(&run).unwrap().is_none());
    assert!(run.finish(true).unwrap().observations.is_empty());
}

#[cfg(feature = "gpu")]
fn initialize() {
    super::super::gpu_hash::initialize_quotient_test_engine(super::super::gpu_hash::Limits {
        managed_bytes: 256 << 20,
        tile_bytes: 32 << 20,
        staging_bytes: 8 << 20,
    })
    .unwrap();
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_adapter_preserves_all_upstream_traits_and_independent_clones() {
    let _shutdown = super::super::gpu_hash::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let challenger = CandidateChallenger::new_gpu(&session).unwrap();
    assert!(challenger.is_gpu());
    exercise(cpu(), challenger);
    assert!(session.stats().transcript_samples > 0);
    assert_eq!(session.stats().grinding_calls, 2);
    assert!(session.stats().transcript_snapshots > 0);
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_adapter_retires_whole_attempts_and_rejects_other_sessions() {
    let _shutdown = super::super::gpu_hash::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let mut challenger = CandidateChallenger::new_gpu(&session).unwrap();
    let mut related = challenger.clone();
    assert!(challenger.check_session(&session).is_ok());
    assert!(challenger
        .check_session(&DeviceSession::new().unwrap())
        .is_err());
    let before = session.stats();
    let attempt = challenger.begin_attempt().unwrap().unwrap();
    attempt.complete();
    assert_eq!(before, session.stats());
    let attempt = related.begin_attempt().unwrap().unwrap();
    drop(attempt);
    for retired in [&mut challenger, &mut related] {
        assert!(retired.begin_attempt().is_err());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| retired.sample_bits(1)))
                .is_err()
        );
    }
    let mut fresh = CandidateChallenger::new_gpu(&session).unwrap();
    let mut fresh_clone = fresh.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || fresh.sample_bits_vec(16, 4097)
    ))
    .is_err());
    assert!(fresh_clone.begin_attempt().is_err());
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fresh_clone.clone())).is_err()
    );
    let mut fresh = CandidateChallenger::new_gpu(&session).unwrap();
    assert_eq!(fresh.sample_bits(25), cpu().sample_bits(25));
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn registered_gpu_adapter_clone_exhaustion_retires_family_without_copying() {
    let _shutdown = super::super::gpu_hash::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let root = CandidateChallenger::new_gpu_registered(&session).unwrap();
    let related = root.clone();
    let before = session.stats();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.clone())).is_err());
    assert_eq!(session.stats(), before);
    assert!(root.begin_attempt().is_err());
    assert!(related.begin_attempt().is_err());
    drop(related);
    // Releasing a slot must not revive a retired family.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| root.clone())).is_err());
    drop(root);
    let mut fresh = CandidateChallenger::new_gpu_registered(&session).unwrap();
    assert_eq!(fresh.sample_bits(25), cpu().sample_bits(25));
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_transcript_reports_actual_device_work_including_before_failure() {
    use super::super::{gpu_hash::device::DomainSpec, profile::Challenge};
    use crate::proving::{
        Backend as ProvingBackend, Capabilities, Policy, Profile, Request, Run, Stage,
    };
    let _shutdown = super::super::gpu_hash::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let mut challenger = CandidateChallenger::new_gpu_registered(&session).unwrap();
    let caps = || Capabilities::cpu(Profile::BlockV2Cubic, true, true);
    let cpu_run = Run::new(
        "rejected GPU transcript",
        Request {
            policy: Policy::CpuRequired,
            emit_report: false,
        },
        caps(),
    )
    .unwrap();
    let before = session.stats();
    assert!(challenger.observe_execution(&cpu_run).is_err());
    assert_eq!(before, session.stats());
    assert!(cpu_run.finish(false).unwrap().observations.is_empty());

    let empty = Run::new("unused GPU transcript", Request::compatible(), caps()).unwrap();
    drop(challenger.observe_execution(&empty).unwrap());
    assert!(empty.finish(true).unwrap().observations.is_empty());
    for succeeds in [true, false] {
        let run = Run::new("GPU transcript reporting", Request::compatible(), caps()).unwrap();
        let before = session.stats();
        let work = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _observation = challenger.observe_execution(&run).unwrap();
            challenger.observe(Val::new(37));
            let point: Challenge = challenger.sample();
            drop(challenger.clone());
            challenger.next_points(point, &[DomainSpec::new(1, 4).unwrap()]);
            challenger.grind(4);
            if !succeeds {
                // This failed admission adds no device work and retires the family.
                challenger.sample_bits_vec(1, resources::BATCH_WORDS + 1);
            }
        }));
        assert_eq!(work.is_ok(), succeeds);
        let after = session.stats();
        let report = run.finish(succeeds).unwrap();
        assert_eq!(report.succeeded, succeeds);
        assert!(!report.stage_coverage_complete);
        assert_eq!(report.observations.len(), 3);
        for (stage, calls, ns) in [
            (
                Stage::Transcript,
                after.transcript_observations
                    + after.transcript_samples
                    + after.transcript_snapshots
                    - before.transcript_observations
                    - before.transcript_samples
                    - before.transcript_snapshots,
                after.transcript_device_ns - before.transcript_device_ns,
            ),
            (
                Stage::Grinding,
                after.grinding_calls - before.grinding_calls,
                after.grinding_device_ns - before.grinding_device_ns,
            ),
            (
                Stage::Scalar,
                after.scalar_calls - before.scalar_calls,
                after.scalar_device_ns - before.scalar_device_ns,
            ),
        ] {
            let actual = report
                .observations
                .iter()
                .find(|entry| entry.stage == stage)
                .unwrap();
            assert_eq!(actual.backend, ProvingBackend::OpenCl);
            assert_eq!(actual.calls, calls);
            assert_eq!(actual.completed_calls, calls);
            assert_eq!(actual.device_ns, ns);
            assert_eq!(actual.inclusive_ns, 0);
            assert!(calls > 0 && ns > 0);
        }
    }
    assert!(challenger.begin_attempt().is_err());
}
