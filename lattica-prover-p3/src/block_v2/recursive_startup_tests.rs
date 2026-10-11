use super::*;
use crate::spill_alloc::allocation_requests::measure;

fn registry() -> Registry {
    Registry {
        height: 1024,
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

#[test]
fn legacy_constructor_reserves_setup_and_reuses_the_bounded_identity_builder() {
    let registry = registry();
    let pin = registry.id().unwrap();
    let floor = storage::STARTUP_HOST_BYTES;
    for budget in [0, storage::SESSION_HOST_BYTES, floor - 1] {
        let owned = registry.clone();
        let (bad, requested) =
            measure(|| ProverSession::new_with_memory_budget(owned, pin, budget));
        assert!(bad.is_err());
        assert!(!requested.overflow && requested.bytes <= 1024 + core::mem::size_of::<String>());
    }
    let (bounded, setup) = measure(|| registry.bounded_id());
    assert_eq!(bounded.unwrap(), pin);
    let owned = registry.clone();
    let (session, requested) = measure(|| ProverSession::new_with_memory_budget(owned, pin, floor));
    let session = session.unwrap();
    assert_eq!(session.memory_budget_bytes(), floor);
    assert_eq!(session.expected_profile, pin);
    assert_eq!(session.registry.caps, registry.caps);
    assert!(!setup.overflow && !requested.overflow);
    assert_eq!(setup.bytes, requested.bytes);
    assert_eq!(setup.calls, requested.calls);
    assert!(
        storage::admit_session(&session.registry).unwrap() as u64 <= storage::SESSION_HOST_BYTES
    );
    for construction in [
        WrapperConstruction::SingleWallet,
        WrapperConstruction::GroupedPair,
    ] {
        let session =
            ConstructionSession::new_with_memory_budget(construction, registry.clone(), pin, floor)
                .unwrap();
        assert_eq!(session.construction(), construction);
        assert_eq!(session.memory_budget_bytes(), floor);
    }
    assert_eq!(
        ProverSession::new(registry.clone(), pin)
            .unwrap()
            .memory_budget_bytes(),
        super::super::feasibility::RAM_BUDGET_BYTES
    );
    let mut wrong = pin;
    wrong[0] ^= 1;
    assert!(ProverSession::new_with_memory_budget(registry.clone(), wrong, floor).is_err());
    let mut changed = registry.clone();
    changed.caps[0][0][0] += Val::ONE;
    assert!(ProverSession::new_with_memory_budget(changed, pin, floor).is_err());
    let mut invalid = registry;
    invalid.height = 7;
    let (bad, requested_bad) =
        measure(|| ProverSession::new_with_memory_budget(invalid, pin, floor));
    assert!(bad.is_err());
    assert!(
        !requested_bad.overflow && requested_bad.bytes <= 1024 + core::mem::size_of::<String>()
    );
    eprintln!("legacy_session_constructor startup_bytes={floor} exact_floor=true short_rejections=3 wrappers=2 default_preserved=true profile_rejected=true caps_rejected=true height_rejected=true setup_bytes={} constructor_bytes={} setup_calls={} constructor_calls={}", setup.bytes, requested.bytes, setup.calls, requested.calls);
}

#[test]
fn legacy_registry_capacity_rejects_the_first_root_beyond_its_ceiling() {
    let mut registry = registry();
    let pin = registry.id().unwrap();
    let word = core::mem::size_of::<[Val; 4]>();
    let other = core::mem::size_of::<Registry>()
        + registry.caps[1..]
            .iter()
            .map(|cap| cap.capacity() * word)
            .sum::<usize>();
    let roots = (Registry::STORAGE_LIMIT_BYTES - other) / word;
    let mut cap = Vec::with_capacity(roots);
    cap.extend_from_slice(&registry.caps[0]);
    registry.caps[0] = cap;
    assert_eq!(registry.bounded_id().unwrap(), pin);
    let retained = core::mem::size_of::<Registry>() + registry.storage_bytes().unwrap();
    assert!(
        retained <= Registry::STORAGE_LIMIT_BYTES
            && retained + word > Registry::STORAGE_LIMIT_BYTES
    );
    let mut cap = Vec::with_capacity(roots + 1);
    cap.extend_from_slice(&registry.caps[0]);
    registry.caps[0] = cap;
    assert_eq!(registry.id().unwrap(), pin); // Reference identity ignores spare capacity.
    let (bad, requested) = measure(|| registry.bounded_id());
    assert!(bad.is_err());
    assert!(!requested.overflow && requested.bytes <= 1024 + core::mem::size_of::<String>());
    let (bad, requested) = measure(|| {
        ProverSession::new_with_memory_budget(registry, pin, storage::STARTUP_HOST_BYTES)
    });
    assert!(bad.is_err());
    assert!(!requested.overflow && requested.bytes <= 1024 + core::mem::size_of::<String>());
    eprintln!("legacy_registry_capacity retained_bytes={retained} limit_bytes={} first_excess_root_rejected=true reference_identity_unchanged=true symbolic_allocations=0", Registry::STORAGE_LIMIT_BYTES);
}

#[test]
fn legacy_setup_workspace_is_released_before_active_proof_budget() {
    let (admitted, requested) = measure(|| storage::admit_startup(storage::STARTUP_HOST_BYTES));
    admitted.unwrap();
    assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
    assert_eq!(
        storage::active_memory_bytes(storage::STARTUP_HOST_BYTES).unwrap(),
        programs::registry_setup::INITIAL_STORAGE_BYTES as u64
    );
    for budget in [
        0,
        storage::SESSION_HOST_BYTES - 1,
        storage::SESSION_HOST_BYTES,
    ] {
        assert!(storage::active_memory_bytes(budget).is_err());
    }
    assert_eq!(
        storage::active_memory_bytes(u64::MAX).unwrap(),
        u64::MAX - storage::SESSION_HOST_BYTES
    );
    eprintln!(
        "legacy_session_budget startup_bytes={} retained_bytes={} active_at_floor={} allocations=0",
        storage::STARTUP_HOST_BYTES,
        storage::SESSION_HOST_BYTES,
        storage::active_memory_bytes(storage::STARTUP_HOST_BYTES).unwrap()
    );
}
