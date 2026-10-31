use super::*;
use crate::block_v2::legacy_wallet::note_admission::PreparationPlan;
use crate::spill_alloc::allocation_requests::measure;
use crate::{
    joinsplit_air as js,
    note_research_quota::{Quota, LEDGER_BYTES},
};
use sha3::{Digest, Sha3_256};

#[test]
fn complete_note_startup_charge_is_pure_and_refuses_short_original_tokens() {
    let (resources, requests) = measure(|| Resources::new().unwrap());
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
    assert_eq!(
        resources.total,
        resources.startup
            + resources.selection
            + resources.device_plan
            + resources.configuration
            + resources.operation
    );
    let quota = Quota::new(LEDGER_BYTES + resources.total).unwrap();
    let short = quota.reserve(resources.total - 1).unwrap();
    let (refusal, requests) = measure(|| resources.check(&short));
    assert_eq!(refusal, Err(Error::ResourceLimit));
    assert_eq!(
        (requests.calls, requests.bytes, requests.overflow),
        (0, 0, false)
    );
    drop(short);
    let exact = quota.reserve(resources.total).unwrap();
    resources.check(&exact).unwrap();
    drop(exact);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
#[ignore = "dedicated env-clear immutable worker, 47 GiB process/zero swap, 8 GiB GPU plus 4 GiB context; coordinator only"]
fn gpu_fixed_note_original_owners_prove_fresh_and_retire_exact_runtime() {
    // Public deterministic correctness fixture and CPU oracle only. Fixture
    // generation is outside this test's proof measurement; this is not a
    // complete direct-spend or RingCT throughput result.
    let mut witness = js::demo_witness();
    witness.outputs[1].value += witness.fee;
    witness.fee = 0;
    let expected = js::public_values(&witness).try_into().unwrap();
    let quota = Quota::new(32 << 30).unwrap();
    let preparation = PreparationPlan::new(24 << 30).unwrap();
    let resources = Resources::new().unwrap();
    let mut digests = [[0u8; 32]; 2];
    for digest in &mut digests {
        let prepared = preparation
            .prepare(
                &witness,
                expected,
                quota.reserve(preparation.required_host_bytes()).unwrap(),
            )
            .unwrap();
        let runtime_reservation = quota.reserve(resources.total).unwrap();
        // SAFETY: ignored qualification test is launched as the sole selected
        // test by the reviewed env-clear parent guard. It never mutates env;
        // the process must not run any other tests or mutation concurrently.
        let runtime = unsafe { NoteRuntime::prove(prepared, runtime_reservation) }.unwrap();
        let completion = runtime.completion().unwrap();
        assert_eq!(completion.public().unwrap(), &expected);
        let encoded = completion.encoded().unwrap();
        assert!(!encoded.is_empty() && encoded.len() <= 64 << 20);
        *digest = Sha3_256::digest(encoded).into();
        let encoded_bytes = encoded.len();
        let retirement = runtime.finish().unwrap();
        assert_eq!(retirement.managed_live_bytes, 0);
        assert_eq!(retirement.host_tree_live_bytes, 0);
        assert!(retirement.lease_released);
        assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
        println!("fixed_note_owned_proof encoded_bytes={encoded_bytes} managed_live_bytes=0 host_tree_live_bytes=0 lease_released=true public_dispatch=false independent_verification=false");
    }
    assert_ne!(
        digests[0], digests[1],
        "fresh hiding cannot replay proof bytes"
    );
}
