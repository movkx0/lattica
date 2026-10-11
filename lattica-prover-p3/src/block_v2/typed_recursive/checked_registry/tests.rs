use super::*;
use crate::spill_alloc::allocation_requests::measure;

fn registry(height: usize) -> Registry<12> {
    Registry {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ONE; 4]; 1 << profile::CAP_HEIGHT]),
    }
}

#[test]
fn owned_identity_preserves_backing_and_reuses_without_heap_requests() {
    for height in [8, 64, 1 << 21] {
        let registry = registry(height);
        let expected = registry.id().unwrap();
        let address = registry.caps[0].as_ptr();
        let checked = CheckedRegistry::new(registry).unwrap();
        assert_eq!(checked.registry.caps[0].as_ptr(), address);
        assert_eq!(checked.profile(), expected);
        let (_, requested) = measure(|| {
            for _ in 0..1024 {
                assert_eq!(checked.profile(), expected);
            }
        });
        assert!(!requested.overflow && requested.bytes == 0 && requested.calls == 0);
        assert!(checked.storage_bytes().unwrap() < Registry::<12>::STORAGE_LIMIT_BYTES);
    }
    eprintln!(
        "checked_registry_identity heights=3 profile_reads=3072 allocations=0 moved_caps=true"
    );
}

#[test]
fn malformed_and_oversized_registry_rejects_before_symbolic_setup() {
    for height in [0, 7, 63, 1 << 22, usize::MAX] {
        let input = registry(height);
        let (result, requests) = measure(|| CheckedRegistry::new(input));
        assert!(result.is_err());
        assert!(!requests.overflow && requests.bytes <= 1048);
    }
    let mut input = registry(64);
    input.caps[0].pop();
    let (result, requests) = measure(|| CheckedRegistry::new(input));
    assert!(result.is_err());
    assert!(!requests.overflow && requests.bytes <= 1048);
    let mut input = registry(64);
    input.caps[0]
        .reserve_exact(Registry::<12>::STORAGE_LIMIT_BYTES / core::mem::size_of::<[Val; 4]>());
    let (result, requests) = measure(|| CheckedRegistry::new(input));
    assert!(result.is_err());
    assert!(!requests.overflow && requests.bytes <= 1048);
    eprintln!("checked_registry_admission early_rejections=7 request_limit=1048");
}

#[test]
fn borrowed_approval_clones_only_caps_and_session_transfer_allocates_nothing() {
    let mut raw = registry(64);
    let expected = raw.id().unwrap();
    let approval = CheckedRegistryRef::new(&raw).unwrap();
    assert!(core::ptr::eq(approval.as_registry(), &raw));
    let (owned, copied) = measure(|| approval.to_owned());
    assert!(!copied.overflow);
    assert_eq!(copied.calls, 12);
    assert_eq!(
        copied.bytes,
        12 * (1 << profile::CAP_HEIGHT) * core::mem::size_of::<[Val; 4]>()
    );
    raw.caps[0][0][0] += Val::ONE;
    assert_ne!(raw.id().unwrap(), expected);
    assert_eq!(owned.profile(), expected);
    let address = owned.as_registry().caps[0].as_ptr();
    let (session, transferred) =
        measure(|| Session::from_checked(owned, storage::SESSION_HOST_BYTES + 1));
    let session = session.unwrap();
    assert!(!transferred.overflow && transferred.bytes == 0 && transferred.calls == 0);
    let borrowed = session.registry_approval().unwrap();
    assert_eq!(borrowed.profile(), expected);
    assert_eq!(borrowed.as_registry().caps[0].as_ptr(), address);
    eprintln!("checked_registry_handoff copied_bytes={} copied_calls={} transfer_allocations=0 original_mutation_isolated=true", copied.bytes, copied.calls);
}

#[test]
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
#[ignore = "fresh CPU registered proof and serial all-thread verification observations"]
fn fresh_empty_node_uses_the_original_verifier_and_rejects_mutations() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(fresh_empty_node_serial);
}

fn fresh_empty_node_serial() {
    use crate::block_v2::{
        codec,
        execution::job::{Job, RegistryPin, VerifiedNode},
    };
    use crate::spill_alloc::allocation_requests::measure_all;
    let height = 2048;
    let budget = 512 << 20;
    let mut registry = registry(height);
    let compiled = typed_pairs::compile_registration(height, programs::EMPTY, None).unwrap();
    registry.caps[1] = register_compiled(height, compiled, budget).unwrap();
    let profile = registry.id().unwrap();
    let pin = RegistryPin::new_typed(&registry, profile).unwrap();
    let checked = CheckedRegistry::new(registry.clone()).unwrap();
    let chain = [47; 32];
    let mut session = Session::new(registry.clone(), profile, budget).unwrap();
    let mut node = session.empty(chain, commitment::DEPTH).unwrap();
    let job = Job::empty(pin, chain, 0, commitment::DEPTH).unwrap();
    let expected = job.expected_public();
    registry.verify(profile, &node, &expected).unwrap();
    checked.verify(&node, &expected).unwrap();
    let bytes = codec::encode_node(&node).unwrap();
    let reference = VerifiedNode::verify_typed(&job, &registry, &bytes).unwrap();
    assert_eq!(
        reference,
        VerifiedNode::verify_typed_checked(&job, &checked, &bytes).unwrap()
    );
    let (_, identity) = measure_all(|| CheckedRegistryRef::new(&registry).unwrap());
    let (direct, direct_requests) =
        measure_all(|| VerifiedNode::verify_typed(&job, &registry, &bytes));
    let (reused, reused_requests) =
        measure_all(|| VerifiedNode::verify_typed_checked(&job, &checked, &bytes));
    assert_eq!(direct.unwrap(), reused.unwrap());
    assert!(!identity.overflow && !direct_requests.overflow && !reused_requests.overflow);
    assert_eq!(
        direct_requests.bytes - reused_requests.bytes,
        identity.bytes
    );
    assert_eq!(
        direct_requests.calls - reused_requests.calls,
        identity.calls
    );
    let mut changed_public = expected;
    changed_public[0] += Val::ONE;
    assert!(registry.verify(profile, &node, &changed_public).is_err());
    assert!(checked.verify(&node, &changed_public).is_err());
    let mut changed_registry = registry.clone();
    changed_registry.caps[0][0][0] += Val::ONE;
    let changed_registry = CheckedRegistry::new(changed_registry).unwrap();
    assert!(VerifiedNode::verify_typed_checked(&job, &changed_registry, &bytes).is_err());
    node.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    assert!(registry.verify(profile, &node, &expected).is_err());
    assert!(checked.verify(&node, &expected).is_err());
    let altered = codec::encode_node(&node).unwrap();
    assert!(VerifiedNode::verify_typed_checked(&job, &checked, &altered).is_err());
    eprintln!("checked_registry_fresh cpu_proofs=1 unchanged_verifier=true public_mutation_rejected=true registry_mutation_rejected=true opening_mutation_rejected=true direct_bytes={} reused_bytes={} identity_bytes={} direct_calls={} reused_calls={} identity_calls={}", direct_requests.bytes, reused_requests.bytes, identity.bytes, direct_requests.calls, reused_requests.calls, identity.calls);
}
