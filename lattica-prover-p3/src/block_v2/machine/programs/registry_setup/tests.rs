use super::*;

fn family<const N: usize>() {
    use crate::spill_alloc::allocation_requests::measure;
    let caps: Caps<N> = core::array::from_fn(|key| {
        (0..1 << profile::CAP_HEIGHT)
            .map(|root| {
                core::array::from_fn(|lane| Val::from_u64((1 + 256 * key + 4 * root + lane) as u64))
            })
            .collect()
    });
    let mut maximum_requests = 0;
    for log_height in 3..=21 {
        let height = 1 << log_height;
        let (bounded, requested) = measure(|| profile_id(height, &caps));
        assert_eq!(
            bounded.unwrap(),
            super::super::profile_id(height, &caps).unwrap()
        );
        assert!(!requested.overflow);
        maximum_requests = maximum_requests.max(requested.bytes);
        #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
        assert!(requested.bytes <= Plan::new().unwrap().cumulative_requested_bytes);
    }
    for (limits, fingerprint_bytes) in [
        (
            Limits {
                recording: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (
            Limits {
                normalization: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (
            Limits {
                packing: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (
            Limits {
                retained: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (LIMITS, 0),
    ] {
        assert!(profile_id_with_limits(64, &caps, limits, fingerprint_bytes).is_err());
        assert_eq!(
            profile_id(64, &caps).unwrap(),
            super::super::profile_id(64, &caps).unwrap()
        );
    }
    let mut malformed = caps;
    malformed[N - 1].pop();
    let (bad, requested) = measure(|| profile_id(64, &malformed));
    assert!(bad.is_err());
    assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    eprintln!("bounded_registry_family keys={N} matched_heights=19 quota_rejections=5 successful_retries=5 malformed_rejections=1 malformed_allocations=0 maximum_requested_bytes={maximum_requests}");
}

#[test]
fn bounded_families_preserve_reference_identities_and_quota_failures() {
    family::<3>();
    family::<5>();
    family::<6>();
    family::<12>();
}

#[test]
fn unsupported_families_reject_before_symbolic_allocation() {
    fn reject<const N: usize>() {
        let caps: Caps<N> =
            core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]);
        let (bad, requested) =
            crate::spill_alloc::allocation_requests::measure(|| profile_id(64, &caps));
        assert!(bad.is_err());
        assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    }
    reject::<0>();
    reject::<4>();
    reject::<13>();
    eprintln!("bounded_registry_unsupported rejected_families=3 allocations=0");
}

fn caps() -> Caps<12> {
    core::array::from_fn(|key| {
        (0..1 << profile::CAP_HEIGHT)
            .map(|root| {
                core::array::from_fn(|word| Val::from_u64((1 + 256 * key + 4 * root + word) as u64))
            })
            .collect()
    })
}

#[test]
fn bounded_identity_matches_reference_at_every_admitted_height() {
    let caps = caps();
    for degree in 3..=21 {
        let height = 1 << degree;
        assert_eq!(
            profile_id(height, &caps).unwrap(),
            super::super::profile_id(height, &caps).unwrap(),
            "height={height}"
        );
    }
    eprintln!("bounded_registry_identity matched_heights=19 keys=12");
}

#[test]
fn quotas_reject_each_setup_phase_and_leave_recorder_reusable() {
    let caps = caps();
    for (limits, fingerprint_bytes) in [
        (
            Limits {
                recording: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (
            Limits {
                normalization: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (
            Limits {
                packing: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (
            Limits {
                retained: 0,
                ..LIMITS
            },
            fingerprint::bounded::HOST_BYTES,
        ),
        (LIMITS, 0),
    ] {
        assert!(profile_id_with_limits(64, &caps, limits, fingerprint_bytes).is_err());
        assert_eq!(
            profile_id(64, &caps).unwrap(),
            super::super::profile_id(64, &caps).unwrap()
        );
    }
    eprintln!("bounded_registry_quota rejections=5 successful_retries=5");
}

#[test]
fn invalid_registry_geometry_rejects_before_heap_requests() {
    let caps = caps();
    for height in [0, 1, 4, 7, 63, (1 << 21) + 1, 1 << 22, usize::MAX] {
        let (result, requested) =
            crate::spill_alloc::allocation_requests::measure(|| profile_id(height, &caps));
        assert!(result.is_err());
        assert!(!requested.overflow);
        assert_eq!(requested.bytes, 0);
        assert_eq!(requested.calls, 0);
    }
    let mut malformed = caps;
    malformed[11].pop();
    let (result, requested) =
        crate::spill_alloc::allocation_requests::measure(|| profile_id(64, &malformed));
    assert!(result.is_err());
    assert!(!requested.overflow);
    assert_eq!(requested.bytes, 0);
    assert_eq!(requested.calls, 0);
    eprintln!("bounded_registry_geometry rejections=9 allocations=0");
}

#[test]
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
fn plan_is_allocation_free_and_observations_use_cumulative_bound() {
    let (plan, requested) = crate::spill_alloc::allocation_requests::measure(Plan::new);
    let plan = plan.unwrap();
    assert!(!requested.overflow);
    assert_eq!(requested.bytes, 0);
    assert_eq!(requested.calls, 0);
    assert!(add(usize::MAX, 1).is_err());
    assert!(plan.peak_bytes < plan.cumulative_requested_bytes);
    let caps = caps();
    // Test-only stderr diagnostics are initialized before observing requests.
    let _ = profile_id(64, &caps).unwrap();
    for height in [8, 64, 1 << 21] {
        let (identity, requested) =
            crate::spill_alloc::allocation_requests::measure(|| profile_id(height, &caps));
        assert_eq!(
            identity.unwrap(),
            super::super::profile_id(height, &caps).unwrap()
        );
        assert!(!requested.overflow);
        assert!(requested.bytes <= plan.cumulative_requested_bytes);
        eprintln!("bounded_registry_setup height={height} requested_bytes={} calls={} shape_retained_bytes={} graph_workspace_bytes={} fingerprint_peak_bytes={} peak_bytes={} cumulative_bound={}", requested.bytes, requested.calls, plan.shape_retained_bytes, plan.graph_workspace_bytes, plan.fingerprint_peak_bytes, plan.peak_bytes, plan.cumulative_requested_bytes);
    }
}

#[test]
fn registry_field_prefix_cannot_grow_beyond_its_fixed_reservation() {
    let air = shape(64).unwrap();
    let prepared = verifier::prepare_registry(&air, LIMITS).unwrap();
    let analysis = analysis::analyze_prepared(&air, &prepared).unwrap();
    for keys in [3, 5, 6, 12] {
        let mut fields = registry_fields(64, &air, &analysis, [0; 4]);
        extend_registry_kind(&mut fields, keys);
        assert!(fields.len() <= PREFIX_WORDS);
        assert_eq!(fields.capacity(), PREFIX_WORDS);
    }
}

#[test]
fn startup_shape_ceiling_covers_exact_qualified_plan() {
    assert!(SHAPE_REQUEST_UPPER <= SHAPE_STORAGE_BYTES);
    assert!(INITIAL_STORAGE_BYTES < 41 << 20);
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    assert!(Plan::new().unwrap().peak_bytes <= INITIAL_STORAGE_BYTES);
    eprintln!("registry_startup_payload shape_upper={SHAPE_REQUEST_UPPER} shape_allowance={SHAPE_STORAGE_BYTES} payload_bytes={INITIAL_STORAGE_BYTES}");
}
