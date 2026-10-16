use super::*;
use crate::block_v2::profile::Challenge;
use p3_commit::PolynomialSpace;
use p3_field::BasedVectorSpace;
use p3_lookup::Challenges;

fn ext(c: [u64; 3]) -> Challenge {
    Challenge::from_basis_coefficients_fn(|i| Val::new(c[i]))
}
fn words(value: Challenge) -> [u64; 3] {
    let c: &[Val] = value.as_basis_coefficients_slice();
    [
        c[0].as_canonical_u64(),
        c[1].as_canonical_u64(),
        c[2].as_canonical_u64(),
    ]
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

#[test]
fn scalar_domain_metadata_and_lookup_bounds_are_checked_without_a_device() {
    for log in 0..=32 {
        for shift in [1, 7, GOLDILOCKS_MODULUS - 1] {
            let actual = DomainSpec::new(shift, log).unwrap();
            let reference = TwoAdicMultiplicativeCoset::new(Val::new(shift), log).unwrap();
            assert_eq!(actual, reference.into());
            assert_eq!(actual.size(), reference.size());
        }
    }
    for (shift, log) in [(0, 0), (GOLDILOCKS_MODULUS, 0), (1, 33), (1, usize::MAX)] {
        assert!(DomainSpec::new(shift, log).is_err());
    }
    assert!(validate_lookup(1, MAX_SCALARS).is_ok());
    assert!(validate_lookup(u32::MAX as usize, 1).is_ok());
    for (width, buses) in [(0, 1), (1, 0), (1, MAX_SCALARS + 1), (usize::MAX, 1)] {
        assert!(validate_lookup(width, buses).is_err());
    }
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_scalar_arithmetic_matches_upstream_at_field_and_geometry_boundaries() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let p = GOLDILOCKS_MODULUS;
    for (alpha, beta) in [
        ([0; 3], [0; 3]),
        ([p - 1, 0, 1], [1, 0, 0]),
        ([p - 2, p - 1, 3], [p - 1, p - 3, p - 7]),
        ([13, 29, 37], [11, 19, 31]),
    ] {
        for width in [1, 2, 7, 33, u32::MAX as usize] {
            let count = if width == 33 { MAX_SCALARS } else { 17 };
            let expected = Challenges::new(ext(alpha), ext(beta), width, count);
            assert_eq!(
                session.lookup_prefixes(alpha, beta, width, count).unwrap(),
                expected
                    .bus_prefix
                    .iter()
                    .copied()
                    .map(words)
                    .collect::<Vec<_>>()
            );
        }
    }
    let logs: Vec<_> = (0..=32).collect();
    let maximum_logs: Vec<_> = (0..MAX_SCALARS).map(|i| i % 33).collect();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        let point = [7u64, 13, 29];
        let actual = session
            .next_points_extension(extension, &point[..extension.degree()], &maximum_logs)
            .unwrap();
        assert_eq!(actual.len(), MAX_SCALARS * extension.degree());
        assert_eq!(actual.capacity(), actual.len());
        for (row, &log) in actual.chunks_exact(extension.degree()).zip(&maximum_logs) {
            for (&word, &coefficient) in row.iter().zip(&point) {
                assert_eq!(
                    Val::new(word),
                    Val::new(coefficient) * Val::TWO_ADIC_GENERATORS[log]
                );
            }
        }
    }
    eprintln!("gpu_scalar_host_capacity max_outputs={MAX_SCALARS} degrees=2,3 exact_capacities=true cpu_reference_checked=true");
    for point in [[0; 2], [p - 1, p - 2], [7, 13]] {
        type Quadratic = crate::config::Challenge;
        let value = Quadratic::from_basis_coefficients_fn(|i| Val::new(point[i]));
        let before = session.stats();
        let actual = session
            .next_points_extension(Extension::Quadratic, &point, &logs)
            .unwrap();
        assert_eq!(actual.len(), 2 * logs.len());
        for (log, actual) in logs.iter().zip(actual.chunks_exact(2)) {
            let reference = TwoAdicMultiplicativeCoset::new(Val::new(11), *log)
                .unwrap()
                .next_point(value)
                .unwrap();
            assert_eq!(
                actual,
                <Quadratic as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&reference)
                    .iter()
                    .map(PrimeField64::as_canonical_u64)
                    .collect::<Vec<_>>()
            );
        }
        assert_eq!(
            session.stats().scalar_input_bytes - before.scalar_input_bytes,
            ((2 + logs.len()) * 8) as u64
        );
        assert_eq!(
            session.stats().scalar_output_bytes - before.scalar_output_bytes,
            (2 * logs.len() * 8) as u64
        );
    }
    for point in [[0; 3], [p - 1, p - 2, p - 3], [7, 13, 29]] {
        let actual = session.next_points(point, &logs).unwrap();
        for (log, actual) in logs.iter().zip(actual) {
            let reference = TwoAdicMultiplicativeCoset::new(Val::new(11), *log).unwrap();
            assert_eq!(actual, words(reference.next_point(ext(point)).unwrap()));
        }
    }
    for shift in [1, 7, 11, p - 1] {
        for log in [0, 1, 5, 13, 25, 32] {
            let domain = DomainSpec::new(shift, log).unwrap();
            let reference = TwoAdicMultiplicativeCoset::new(Val::new(shift), log).unwrap();
            for log_chunks in [0, 1, 4, 8].into_iter().filter(|&n| n <= log) {
                let chunks = 1usize << log_chunks;
                assert_eq!(
                    session.split_domains(domain, chunks).unwrap(),
                    reference
                        .split_domains(chunks)
                        .into_iter()
                        .map(Into::into)
                        .collect::<Vec<DomainSpec>>()
                );
            }
            for new_log in [log, 32] {
                assert_eq!(
                    session.disjoint_domain(domain, new_log).unwrap(),
                    reference.create_disjoint_domain(1usize << new_log).into()
                );
            }
        }
    }
    let stats = session.stats();
    assert_eq!(stats.downloaded_bytes, stats.scalar_output_bytes);
    assert_eq!(stats.uploaded_bytes, stats.scalar_input_bytes);
    assert!(stats.scalar_device_ns > 0);
    assert!(stats.scalar_lookup_prefixes > 0 && stats.scalar_next_points > 0);
    assert!(stats.scalar_cosets > 0 && stats.scalar_disjoint_domains > 0);
    assert_eq!(
        session
            .with_engine(|engine| Ok(engine.accounting.lock().unwrap().device_live))
            .unwrap(),
        0
    );
    eprintln!("gpu_scalar_conformance stats={stats:?}");
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn gpu_scalars_reject_invalid_inputs_and_memory_before_execution() {
    let _shutdown = super::super::super::TestShutdownGuard;
    initialize();
    let session = DeviceSession::new().unwrap();
    let domain = DomainSpec::new(7, 8).unwrap();
    let before = session.stats();
    for (extension, point) in [
        (Extension::Base, vec![1]),
        (Extension::Quadratic, vec![1]),
        (Extension::Quadratic, vec![1; 3]),
        (Extension::Cubic, vec![1; 2]),
        (Extension::Quadratic, vec![GOLDILOCKS_MODULUS; 2]),
    ] {
        assert!(session
            .next_points_extension(extension, &point, &[0, 32])
            .is_err());
    }
    assert!(session
        .lookup_prefixes([GOLDILOCKS_MODULUS; 3], [0; 3], 1, 1)
        .is_err());
    assert!(session.lookup_prefixes([0; 3], [0; 3], 0, 1).is_err());
    assert!(session
        .lookup_prefixes([0; 3], [0; 3], 1, MAX_SCALARS + 1)
        .is_err());
    for logs in [vec![], vec![33], vec![1; MAX_SCALARS + 1]] {
        assert!(session.next_points([1; 3], &logs).is_err());
    }
    for chunks in [0, 3, 512, usize::MAX] {
        assert!(session.split_domains(domain, chunks).is_err());
    }
    assert!(session.disjoint_domain(domain, 33).is_err());
    assert_eq!(before, session.stats());
    let other = DeviceSession::new().unwrap();
    let plan = host_storage::Plan::next_points(1, 3).unwrap();
    let mut foreign = other.reserve_transcript_host(plan).unwrap();
    assert!(session
        .next_points_extension_scoped(Extension::Cubic, &[1; 3], &[5], &mut foreign)
        .is_err());
    let mut small = session
        .reserve_transcript_host(host_storage::Plan { bytes: 1 })
        .unwrap();
    assert!(session
        .next_points_extension_scoped(Extension::Cubic, &[1; 3], &[5], &mut small)
        .is_err());
    assert_eq!(before, session.stats());
    drop((foreign, small));
    assert_eq!(session.transcript_host_reserved_bytes(), 0);
    assert_eq!(other.transcript_host_reserved_bytes(), 0);
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
            session.lookup_prefixes([0; 3], [1; 3], 2, 4).is_err(),
            session.next_points([1; 3], &[5]).is_err(),
            session.split_domains(domain, 16).is_err(),
            session.disjoint_domain(domain, 9).is_err(),
        ];
        session
            .with_engine(|engine| {
                engine.limits.managed_bytes = saved.0;
                engine.max_alloc = saved.1;
                Ok(())
            })
            .unwrap();
        assert!(rejected.into_iter().all(|rejected| rejected));
        assert_eq!(before, session.stats());
    }
    assert!(session.next_points([1; 3], &[5]).is_ok());
    assert_eq!(
        session
            .with_engine(|engine| Ok(engine.accounting.lock().unwrap().device_live))
            .unwrap(),
        0
    );
}
