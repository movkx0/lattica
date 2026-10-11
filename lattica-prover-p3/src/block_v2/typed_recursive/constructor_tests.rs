use super::*;
use crate::spill_alloc::allocation_requests::measure;

fn registry<const N: usize>() -> Registry<N> {
    Registry {
        height: 2048,
        caps: core::array::from_fn(|key| {
            (0..1 << profile::CAP_HEIGHT)
                .map(|root| {
                    core::array::from_fn(|lane| {
                        Val::from_u64((1 + 256 * key + 4 * root + lane) as u64)
                    })
                })
                .collect()
        }),
    }
}

fn family<const N: usize>() {
    let registry = registry::<N>();
    let identity = registry.id().unwrap();
    let floor = storage::SESSION_STARTUP_HOST_BYTES;
    assert_eq!(
        floor,
        storage::SESSION_HOST_BYTES + programs::registry_setup::INITIAL_STORAGE_BYTES as u64
    );
    for budget in [0, storage::SESSION_HOST_BYTES, floor - 1] {
        let owned = registry.clone();
        let (bad, requested) = measure(|| Session::new(owned, identity, budget));
        assert!(bad.is_err());
        assert!(!requested.overflow && requested.bytes <= 1024 + core::mem::size_of::<String>());
    }
    let (bounded, setup) =
        measure(|| programs::registry_setup::profile_id(registry.height, &registry.caps));
    assert_eq!(bounded.unwrap(), identity);
    let owned = registry.clone();
    let (session, requested) = measure(|| Session::new(owned, identity, floor));
    let session = session.unwrap();
    assert_eq!(session.expected_profile, identity);
    assert_eq!(session.worker_memory_bytes, floor);
    assert_eq!(session.registry.height, registry.height);
    assert_eq!(session.registry.caps, registry.caps);
    assert!(!setup.overflow && !requested.overflow);
    assert_eq!(setup.bytes, requested.bytes);
    assert_eq!(setup.calls, requested.calls);
    assert!(storage::admit_session(&session.registry).unwrap() <= storage::SESSION_HOST_BYTES);
    let mut wrong_profile = identity;
    wrong_profile[0] ^= 1;
    assert!(Session::new(registry.clone(), wrong_profile, floor).is_err());
    let mut changed = registry.clone();
    changed.caps[0][0][0] += Val::ONE;
    assert!(Session::new(changed, identity, floor).is_err());
    let mut invalid_height = registry;
    invalid_height.height = 7;
    let (bad, rejected) = measure(|| Session::new(invalid_height, identity, floor));
    assert!(bad.is_err());
    assert!(!rejected.overflow && rejected.bytes <= 1024 + core::mem::size_of::<String>());
    eprintln!("bounded_session_constructor keys={N} startup_bytes={floor} exact_floor=true short_rejections=3 profile_rejected=true caps_rejected=true height_rejected=true setup_bytes={} constructor_bytes={} setup_calls={} constructor_calls={}", setup.bytes, requested.bytes, setup.calls, requested.calls);
}

#[test]
fn generic_sessions_reserve_setup_before_identity_and_use_one_bounded_builder() {
    family::<5>();
    family::<6>();
    family::<12>();
}

#[test]
fn unsupported_session_families_reject_before_symbolic_allocation() {
    fn reject<const N: usize>() {
        let owned = registry::<N>();
        let (bad, requested) =
            measure(|| Session::new(owned, [0; 32], storage::SESSION_STARTUP_HOST_BYTES));
        assert!(bad.is_err());
        assert!(!requested.overflow && requested.bytes <= 1024 + core::mem::size_of::<String>());
    }
    reject::<3>();
    reject::<4>();
    reject::<13>();
    eprintln!("bounded_session_unsupported rejected_families=3 symbolic_allocations=0");
}
