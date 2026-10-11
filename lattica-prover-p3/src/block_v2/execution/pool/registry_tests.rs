use super::*;
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn submission_reuses_identity_and_still_rejects_a_different_registry() {
    let temp = Temp::new();
    let (mut pool, selection, context, _) = fixture(&temp);
    let raw = Registry::<12> {
        height: 8,
        caps: core::array::from_fn(|_| {
            vec![[crate::config::Val::ZERO; 4]; 1 << crate::block_v2::profile::CAP_HEIGHT]
        }),
    };
    let (_, identity) = measure(|| raw.id().unwrap());
    assert!(!identity.overflow);
    let jobs = selection.jobs().len();
    let (submitted, requests) =
        measure(|| pool.submit(&selection, context.clone(), [3; 32], 1000, 0));
    let candidate = submitted.unwrap();
    assert!(!requests.overflow && requests.bytes < jobs * identity.bytes);
    assert_eq!(pool.candidates[&candidate].jobs.len(), jobs);
    let mut other = raw;
    other.caps[0][0][0] += crate::config::Val::ONE;
    let pin = RegistryPin::new_typed(&other, other.id().unwrap()).unwrap();
    let wallet = typed_wallet_for(pin, 1, 1, &[1]);
    let changed =
        Selection::new(pin, [9; 32], &[PublicInput::new(wallet, vec![1]).unwrap()]).unwrap();
    assert!(pool.submit(&changed, context, [3; 32], 1000, 0).is_err());
    assert_eq!(pool.candidates.len(), 1);
    eprintln!("pool_registry_submission jobs={jobs} requested_bytes={} reference_identity_bytes={} substitution_rejected=true", requests.bytes, identity.bytes);
}

#[test]
fn replacement_checks_cached_profile_without_registry_compilation() {
    let temp = Temp::new();
    let (mut pool, _, _, state) = fixture(&temp);
    pool.slots[0].closed = true;
    let cap = pool.slots[0].endpoint.capabilities();
    let mut wrong = cap.clone();
    wrong.profile[0] ^= 1;
    assert!(pool
        .replace_worker(cap.worker, |_| Ok(Box::new(SimulatedEndpoint {
            cap: wrong,
            state: state.clone()
        })))
        .is_err());
    assert!(pool.slots[0].closed);
    let (result, requests) = measure(|| {
        pool.replace_worker(cap.worker, |_| {
            Ok(Box::new(SimulatedEndpoint { cap, state }))
        })
    });
    result.unwrap();
    assert!(!requests.overflow && requests.bytes < 64 << 10);
    assert!(!pool.slots[0].closed);
    eprintln!(
        "pool_registry_replacement requested_bytes={} wrong_profile_rejected=true",
        requests.bytes
    );
}
