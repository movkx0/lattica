use super::*;
use crate::spill_alloc::allocation_requests::{measure, measure_all};

fn fresh_registry_family<const N: usize>() {
    let height = 2048;
    let budget = 512 << 20;
    let mut registry = Registry::<N> {
        height,
        caps: core::array::from_fn(|_| vec![[Val::ZERO; 4]; 1 << profile::CAP_HEIGHT]),
    };
    registry.caps[1] = match N {
        5 => register(height, programs::EMPTY, None, budget).unwrap(),
        6 => register_finalized(height, programs::EMPTY, None, budget).unwrap(),
        12 => {
            let compiled =
                typed_pairs::compile_registration(height, programs::EMPTY, None).unwrap();
            register_compiled(height, compiled, budget).unwrap()
        }
        _ => unreachable!(),
    };
    let expected_profile = registry.id().unwrap();
    let mut session = Session::new(registry.clone(), expected_profile, budget).unwrap();
    let mut node = session.empty([47; 32], commitment::DEPTH).unwrap();
    let expected = node.public;
    registry.verify(expected_profile, &node, &expected).unwrap();
    session.verify_registered(&node, &expected).unwrap();

    let (_, identity) = measure(|| registry.id().unwrap());
    let (direct, direct_requests) =
        measure_all(|| registry.verify(expected_profile, &node, &expected));
    let (reused, reused_requests) = measure_all(|| session.verify_registered(&node, &expected));
    direct.unwrap();
    reused.unwrap();
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
    assert!(registry
        .verify(expected_profile, &node, &changed_public)
        .is_err());
    assert!(session.verify_registered(&node, &changed_public).is_err());
    node.public[programs::ROOT] += Val::ONE;
    assert!(session.verify_registered(&node, &expected).is_err());
    node.public = expected;
    for mode in [0, N as u64 + 1, u64::MAX] {
        let mut invalid = expected;
        invalid[programs::MODE] = Val::from_u64(mode);
        assert!(registry.verify(expected_profile, &node, &invalid).is_err());
        assert!(session.verify_registered(&node, &invalid).is_err());
    }
    let mut changed_registry = registry.clone();
    changed_registry.caps[0][0][0] += Val::ONE;
    let other_profile = changed_registry.id().unwrap();
    let other = Session::new(changed_registry, other_profile, budget).unwrap();
    assert!(other.verify_registered(&node, &expected).is_err());

    node.proof.opened_values.instances[0].permutation_local[0] += profile::Challenge::ONE;
    assert!(registry.verify(expected_profile, &node, &expected).is_err());
    assert!(session.verify_registered(&node, &expected).is_err());
    assert!(session.merge(&node, &node).is_err());
    assert!(session.finalize(&node).is_err());
    eprintln!("session_registry_fresh keys={N} cpu_proofs=1 height={height} unchanged_verifier=true public_mutation_rejected=true node_statement_rejected=true invalid_modes_rejected=3 registry_mutation_rejected=true opening_mutation_rejected=true invalid_children_rejected=true direct_bytes={} reused_bytes={} identity_bytes={} direct_calls={} reused_calls={} identity_calls={}", direct_requests.bytes, reused_requests.bytes, identity.bytes, direct_requests.calls, reused_requests.calls, identity.calls);
}

#[test]
#[ignore = "fresh CPU proofs for all supported typed session registry families"]
fn fresh_sessions_reuse_identity_and_keep_complete_numerical_verification() {
    fresh_registry_family::<5>();
    fresh_registry_family::<6>();
    fresh_registry_family::<12>();
}
