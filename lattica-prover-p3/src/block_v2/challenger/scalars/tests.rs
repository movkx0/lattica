use super::*;
use crate::block_v2::profile::Config;
use p3_batch_stark::BatchTranscript;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::LogUpGadget;

fn adapter() -> CandidateChallenger {
    CandidateChallenger::new(p3_goldilocks::default_goldilocks_poseidon2_8())
}
#[cfg(feature = "gpu")]
fn initialize() {
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(crate::block_v2::gpu_hash::Limits {
        managed_bytes: 256 << 20,
        tile_bytes: 32 << 20,
        staging_bytes: 8 << 20,
    })
    .unwrap();
}
fn lookup(kind: Kind, widths: &[usize]) -> Lookup<Val> {
    Lookup {
        kind,
        elements: widths.iter().map(|&n| vec![Val::ONE.into(); n]).collect(),
        multiplicities: vec![Val::ONE.into(); widths.len()],
        count_weight: 1,
        column: 0,
    }
}
fn fixture() -> Vec<Vec<Lookup<Val>>> {
    vec![
        vec![
            lookup(Kind::Global("a".into()), &[1]),
            lookup(Kind::Local, &[2, 4]),
        ],
        vec![],
        vec![
            lookup(Kind::Global("a".into()), &[7]),
            lookup(Kind::Global("b".into()), &[0]),
            lookup(Kind::Local, &[]),
            lookup(Kind::Global("a".into()), &[3]),
        ],
    ]
}
#[test]
fn lookup_bus_metadata_preserves_global_names_local_identity_and_empty_instances() {
    let fixture = fixture();
    let refs: Vec<_> = fixture.iter().map(Vec::as_slice).collect();
    assert_eq!(
        bus_layout(&refs).unwrap(),
        (vec![vec![0, 1], vec![], vec![0, 2, 3, 0]], 7, 4)
    );
    assert_eq!(
        bus_layout(&[&[], &[]]).unwrap(),
        (vec![vec![], vec![]], 1, 0)
    );
    assert_eq!(bus_layout(&[&[lookup(Kind::Local, &[0])]]).unwrap().1, 1);
    let excess = vec![lookup(Kind::Global("a".into()), &[1]); 4097];
    assert!(bus_layout(&[&excess]).is_err());
}

#[cfg(feature = "stream")]
#[test]
fn lookup_host_metadata_is_exact_and_bounded_for_sparse_and_shared_names() {
    use crate::spill_alloc::allocation_requests::measure;
    for count in [1, resources::SCALAR_OUTPUTS] {
        let rows = (0..count)
            .map(|index| {
                vec![lookup(
                    if index % 3 == 0 {
                        Kind::Local
                    } else {
                        Kind::Global(format!("bus-{}", (count - index) % 7))
                    },
                    &[1],
                )]
            })
            .collect::<Vec<_>>();
        let refs = rows.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let ((ids, width, buses), requests) = measure(|| bus_layout(&refs).unwrap());
        assert_eq!(ids.len(), count);
        assert_eq!(ids.capacity(), count);
        assert_eq!(width, 1);
        assert!(buses <= count);
        assert!(ids.iter().all(|row| row.len() == 1 && row.capacity() == 1));
        let independent = count
            * (core::mem::size_of::<Vec<usize>>()
                + core::mem::size_of::<usize>()
                + core::mem::size_of::<(&str, usize)>());
        assert_eq!(requests.bytes, independent);
        assert_eq!(requests.calls, count + 2);
        assert!(!requests.overflow);
        assert!(requests.bytes <= storage::Plan::lookup(count, count).unwrap().bytes);
        // A direct encounter-order oracle, separate from the sorted-name table.
        let mut names = std::collections::HashMap::new();
        let mut next = 0;
        for (row, actual) in rows.iter().zip(&ids) {
            let expected = match &row[0].kind {
                Kind::Local => {
                    let id = next;
                    next += 1;
                    id
                }
                Kind::Global(name) => *names.entry(name).or_insert_with(|| {
                    let id = next;
                    next += 1;
                    id
                }),
            };
            assert_eq!(actual, &[expected]);
        }
        assert_eq!(buses, next);
        eprintln!("lookup_host_metadata count={count} allocated_bytes={} independent_bytes={independent} exact_capacities=true", requests.bytes);
    }
    let refs = vec![&[][..]; resources::SCALAR_OUTPUTS];
    let ((ids, _, buses), requests) = measure(|| bus_layout(&refs).unwrap());
    assert_eq!(buses, 0);
    assert!(ids.iter().all(|row| row.is_empty() && row.capacity() == 0));
    assert_eq!(
        requests.bytes,
        refs.len() * core::mem::size_of::<Vec<usize>>()
    );
    assert_eq!(requests.calls, 1);
}

#[cfg(feature = "stream")]
#[test]
fn lookup_rejects_excess_empty_instances_before_metadata_allocation() {
    use crate::spill_alloc::allocation_requests::measure;
    let refs = vec![&[][..]; resources::SCALAR_OUTPUTS + 1];
    let (error, requests) = measure(|| bus_layout(&refs).unwrap_err());
    assert!(error.contains("lookup host metadata"));
    // Only the returned diagnostic String is allocated, not the outer ID table.
    assert_eq!(requests.calls, 1);
    assert_eq!(requests.bytes, error.capacity());
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_lookup_mapping_and_next_points_preserve_upstream_transcript_state() {
    let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    for fixture in [
        fixture(),
        vec![vec![], vec![]],
        vec![vec![lookup(Kind::Local, &[0])]],
    ] {
        let refs: Vec<_> = fixture.iter().map(Vec::as_slice).collect();
        let mut cpu = BatchTranscript::<Config>::new(adapter());
        let mut gpu = CandidateChallenger::new_gpu(&session).unwrap();
        for pending in 0..5 {
            let observations: Vec<_> = (0..pending).map(|i| Val::new(i + 11)).collect();
            cpu.challenger.observe_slice(&observations);
            gpu.observe_slice(&observations);
            let before = session.stats();
            assert_eq!(
                gpu.gpu_lookup_challenges(&refs),
                cpu.sample_perm_challenges(&refs, &LogUpGadget::new())
            );
            if refs.iter().all(|v| v.is_empty()) {
                assert_eq!(before, session.stats());
            }
            let point: Challenge = cpu.challenger.sample();
            assert_eq!(point, gpu.sample());
            let domains: Vec<_> = [0, 1, 8, 19, 32]
                .into_iter()
                .map(|n| DomainSpec::new(7, n).unwrap())
                .collect();
            assert_eq!(
                gpu.next_points(point, &domains),
                cpu.challenger.next_points(point, &domains)
            );
            assert_eq!(gpu.next_points(point, &[]), Vec::<Challenge>::new());
            let quadratic =
                crate::config::Challenge::from_basis_coefficients_fn(|i| Val::new(41 + i as u64));
            assert_eq!(
                gpu.next_points(quadratic, &domains),
                cpu.challenger.next_points(quadratic, &domains)
            );
            assert_eq!(
                gpu.next_points(quadratic, &[]),
                Vec::<crate::config::Challenge>::new()
            );
            assert_eq!(
                <CandidateChallenger as CanSample<Challenge>>::sample(&mut gpu),
                cpu.challenger.sample()
            );
        }
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_scalar_failure_retires_challenger_family_without_poisoning_new_attempts() {
    let _shutdown = crate::block_v2::gpu_hash::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let mut gpu = CandidateChallenger::new_gpu(&session).unwrap();
    let related = gpu.clone();
    let before = session.stats();
    let excess = vec![lookup(Kind::Local, &[1]); 4097];
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || gpu.gpu_lookup_challenges(&[&excess])
    ))
    .is_err());
    assert_eq!(before, session.stats());
    assert!(related.begin_attempt().is_err());
    let mut empty_excess = CandidateChallenger::new_gpu(&session).unwrap();
    let related = empty_excess.clone();
    let refs = vec![&[][..]; resources::SCALAR_OUTPUTS + 1];
    let before = session.stats();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || empty_excess.gpu_lookup_challenges(&refs)
    ))
    .is_err());
    assert_eq!(before, session.stats());
    assert!(related.begin_attempt().is_err());
    let mut fresh = CandidateChallenger::new_gpu(&session).unwrap();
    let related = fresh.clone();
    let Backend::Gpu(transcript) = &mut fresh.inner else {
        unreachable!()
    };
    assert!(transcript
        .derive_scalars(|s| s.lookup_prefixes([0; 3], [1; 3], 0, 1))
        .is_err());
    assert!(related.begin_attempt().is_err());
    let mut executing = CandidateChallenger::new_gpu(&session).unwrap();
    let executing_clone = executing.clone();
    let before = session.stats();
    let Backend::Gpu(transcript) = &mut executing.inner else {
        unreachable!()
    };
    let failed: Result<(), String> = transcript.derive_scalars(|s| {
        s.lookup_prefixes([0; 3], [1; 3], 2, 4)?;
        Err("injected error after GPU scalar execution".into())
    });
    assert!(failed.is_err());
    assert_eq!(session.stats().scalar_calls, before.scalar_calls + 1);
    assert!(executing_clone.begin_attempt().is_err());
    let mut independent = CandidateChallenger::new_gpu(&session).unwrap();
    assert!(independent.gpu_lookup_challenges(&[&[]])[0].is_empty());
    assert_eq!(
        <CandidateChallenger as CanSample<Challenge>>::sample(&mut independent),
        adapter().sample()
    );

    let shared = CandidateChallenger::new_gpu(&session).unwrap();
    let sibling = shared.clone();
    let retained = session.transcript_host_reserved_bytes();
    let plan = storage::Plan::next_points(resources::SCALAR_OUTPUTS, 3).unwrap();
    let held = session
        .reserve_transcript_host(storage::Plan {
            bytes: resources::HOST_BYTES - retained - plan.bytes + 1,
        })
        .unwrap();
    let domains = vec![DomainSpec::new(7, 8).unwrap(); resources::SCALAR_OUTPUTS];
    let point = Challenge::from_basis_coefficients_fn(|i| Val::new(i as u64 + 1));
    let before = session.stats();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = shared.next_points(point, &domains);
    }))
    .is_err());
    assert_eq!(before, session.stats());
    assert!(sibling.begin_attempt().is_err());
    drop(held);
    assert_eq!(session.transcript_host_reserved_bytes(), retained);
}
