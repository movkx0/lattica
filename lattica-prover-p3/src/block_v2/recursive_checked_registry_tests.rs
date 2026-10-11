use super::*;
use crate::spill_alloc::allocation_requests::measure;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
use crate::spill_alloc::allocation_requests::measure_all;

fn registry(height: usize) -> Registry {
    Registry {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    }
}

#[test]
fn borrowed_session_admits_one_identity_and_preserves_owned_authority() {
    for height in [8, 1024, 1 << 21] {
        let mut registry = registry(height);
        let (_, identity) = measure(|| CheckedRegistryRef::new(&registry).unwrap());
        let (_, copying) = measure(|| registry.clone());
        let (mut session, requested) = measure(|| {
            ProverSession::from_borrowed_registry(&registry, storage::STARTUP_HOST_BYTES).unwrap()
        });
        assert!(!identity.overflow && !copying.overflow && !requested.overflow);
        assert_eq!(requested.bytes, identity.bytes + copying.bytes);
        assert_eq!(requested.calls, identity.calls + copying.calls);
        assert_eq!(copying.calls, 3);
        let profile = registry.id().unwrap();
        assert_eq!(session.registry_approval().profile(), profile);
        assert_eq!(session.memory_budget_bytes(), storage::STARTUP_HOST_BYTES);
        assert_eq!(session.stats(), CacheStats::default());
        assert_ne!(registry.caps[0].as_ptr(), session.registry.caps[0].as_ptr());
        let (_, reuse) = measure(|| {
            for _ in 0..1024 {
                let approved = session.registry_approval();
                assert_eq!(approved.profile(), profile);
                assert!(core::ptr::eq(approved.as_registry(), &session.registry));
            }
        });
        assert!(!reuse.overflow && reuse.calls == 0 && reuse.bytes == 0);
        registry.caps[0][0][0] += Val::ONE;
        assert_ne!(registry.bounded_id().unwrap(), profile);
        assert_eq!(session.registry_approval().profile(), profile);
        session.clear();
        assert_eq!(session.registry_approval().profile(), profile);
        assert_eq!(session.registry.caps[0][0][0], Val::ZERO);
    }
    eprintln!("legacy_session_approval_copy heights=3 identity_builds_per_copy=1 cap_buffers=3 profile_reads=3072 reuse_allocations=0 source_mutation_and_eviction_preserve_owned_authority=true");
}

#[test]
fn borrowed_session_rejects_budget_and_backing_before_copying_or_setup() {
    let mut registry = registry(1024);
    for budget in [
        0,
        storage::SESSION_HOST_BYTES,
        storage::STARTUP_HOST_BYTES - 1,
    ] {
        let (result, requested) =
            measure(|| ProverSession::from_borrowed_registry(&registry, budget));
        assert!(result.is_err());
        assert!(!requested.overflow && requested.bytes <= 1048);
    }
    registry.caps[0]
        .reserve_exact(Registry::STORAGE_LIMIT_BYTES / core::mem::size_of::<[Val; 4]>());
    let (result, requested) =
        measure(|| ProverSession::from_borrowed_registry(&registry, storage::STARTUP_HOST_BYTES));
    assert!(result.is_err());
    assert!(!requested.overflow && requested.bytes <= 1048);
    eprintln!("legacy_session_approval_rejection early_rejections=4 allocation_request_limit=1048 cap_copy_and_symbolic_setup_not_started=true");
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[ignore = "fresh CPU child proof checks both session merge-verification positions"]
fn fresh_session_child_verification_reuses_identity_and_rejects_both_bad_children() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(fresh_session_child_verification_serial);
}

#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
fn fresh_session_child_verification_serial() {
    use crate::block_v2::codec;
    let mut registry = registry(1024);
    let budget = 512 << 20;
    let compiled = programs::empty(registry.height, &registry.caps).unwrap();
    let registered = RegisteredProgram::new_with_memory_budget(
        MachineAir::new(compiled.program.pad_to(registry.height).unwrap()),
        budget - storage::SESSION_HOST_BYTES,
    )
    .unwrap();
    registry.caps[1] = registered.preprocessing_cap().roots().to_vec();
    drop(registered);
    let mut session = ProverSession::from_borrowed_registry(&registry, budget).unwrap();
    let profile = session.expected_profile;
    let node = session.empty(DEMO_CHAIN, 0).unwrap();
    let approved = session.registry_approval();
    let (_, identity) = measure_all(|| registry.id().unwrap());
    let (_, direct) = measure_all(|| {
        for _ in 0..2 {
            registry.verify(profile, &node, &node.public).unwrap();
        }
    });
    let (_, reused) = measure_all(|| {
        for _ in 0..2 {
            approved.verify(&node, &node.public).unwrap();
        }
    });
    assert!(!identity.overflow && !direct.overflow && !reused.overflow);
    assert_eq!(direct.bytes - reused.bytes, 2 * identity.bytes);
    assert_eq!(direct.calls - reused.calls, 2 * identity.calls);

    let mut bad = codec::decode_node(&codec::encode_node(&node).unwrap()).unwrap();
    bad.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    let before = session.stats();
    assert!(session.merge(&bad, &node).is_err());
    assert!(session.merge(&node, &bad).is_err());
    assert_eq!(session.stats(), before);
    let mut changed = node.public;
    changed[programs::ROOT] += Val::ONE;
    assert!(session.registry_approval().verify(&node, &changed).is_err());
    session.clear();
    session
        .registry_approval()
        .verify(&node, &node.public)
        .unwrap();
    eprintln!("legacy_session_approval_fresh cpu_proofs=1 child_checks=2 avoided_reference_identities=2 both_bad_child_positions_reject=true public_mutation_rejects=true eviction_preserves_acceptance=true identity_bytes={} identity_calls={} direct_bytes={} direct_calls={} reused_bytes={} reused_calls={}", identity.bytes, identity.calls, direct.bytes, direct.calls, reused.bytes, reused.calls);
}
