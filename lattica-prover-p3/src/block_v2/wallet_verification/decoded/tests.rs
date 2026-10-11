use super::super::{inputs, storage, tests::template};
use super::*;
use crate::block_v2::codec::proofs;
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn every_admitted_geometry_decodes_with_exact_backing_and_quota_boundaries() {
    let mut maximum_backing = 0;
    let mut maximum_requested = 0;
    for htlc in [false, true] {
        for degree in 1..=MAX_DEGREE_BITS {
            let wallet = template(degree, htlc);
            let bytes = postcard::to_allocvec(&wallet).unwrap();
            assert!(bytes.len() <= profile::MAX_PROOF_BYTES);
            let limit = storage_limit().unwrap();
            let quota = proofs::Storage::new(limit);
            let (decoded, observed) = measure(|| quota.wallet(&bytes));
            let decoded = decoded.unwrap();
            inputs(&decoded, htlc).unwrap();
            let backing = storage::proof_bytes(&decoded).unwrap();
            let bound = backing_bytes(degree, htlc).unwrap();
            assert_eq!(backing, bound);
            assert!(!observed.overflow);
            assert_eq!(observed.bytes, backing + bytes.len());
            assert!(observed.bytes <= limit);
            assert!(proofs::Storage::new(observed.bytes).wallet(&bytes).is_ok());
            assert!(proofs::Storage::new(observed.bytes - 1)
                .wallet(&bytes)
                .is_err());
            maximum_backing = maximum_backing.max(backing);
            maximum_requested = maximum_requested.max(observed.bytes);
        }
    }
    eprintln!("wallet_decoded_geometry cases=56 attempts=168 maximum_backing_bytes={maximum_backing} maximum_requested_bytes={maximum_requested} limit_bytes={STORAGE_LIMIT} exact_capacity=true");
}

#[test]
fn malformed_nested_shape_stops_at_the_smaller_quota_before_verification() {
    let mut wallet = template(MAX_DEGREE_BITS, true);
    // Each sequence fits the generic codec's 256-element guard, but these
    // empty point rows exceed the wallet envelope and amplify backing bytes.
    wallet.proof.opening_proof.0 = vec![vec![vec![Vec::<Ext>::new(); 256]; 256]; 4];
    let bytes = postcard::to_allocvec(&wallet).unwrap();
    assert!(bytes.len() <= profile::MAX_PROOF_BYTES);
    let loose = proofs::Storage::new(proofs::INPUT_STORAGE_LIMIT);
    let decoded = loose.wallet(&bytes).unwrap();
    assert!(storage::proof_bytes(&decoded).unwrap() > STORAGE_LIMIT);
    assert!(inputs(&decoded, true).is_err());
    let quota = proofs::Storage::new(storage_limit().unwrap());
    let (result, observed) = measure(|| quota.wallet(&bytes));
    assert!(result.is_err() && !observed.overflow);
    assert!(observed.bytes <= STORAGE_LIMIT);
    assert!(observed.bytes > STORAGE_LIMIT / 2);
    eprintln!("wallet_decoded_malformed wire_bytes={} rejected_requested_bytes={} limit_bytes={STORAGE_LIMIT} legacy_decoded_backing_bytes={} envelope_rejected=true", bytes.len(), observed.bytes, storage::proof_bytes(&decoded).unwrap());
}

#[test]
fn source_model_checks_arithmetic_without_allocating() {
    let (_, observed) = measure(|| {
        for htlc in [false, true] {
            let mut previous = 0;
            for degree in 1..=MAX_DEGREE_BITS {
                let bytes = backing_bytes(degree, htlc).unwrap();
                assert!(bytes >= previous);
                assert!(add(bytes, profile::MAX_PROOF_BYTES).unwrap() <= storage_limit().unwrap());
                previous = bytes;
            }
        }
        for degree in [0, MAX_DEGREE_BITS + 1, usize::MAX] {
            assert!(backing_bytes(degree, false).is_err());
        }
        assert!(add(usize::MAX, 1).is_err());
        assert!(mul(usize::MAX, 2).is_err());
        assert!(Bytes::default().exact::<Val>(usize::MAX).is_err());
        assert!(Bytes::default().repeat(Bytes(2), usize::MAX).is_err());
    });
    assert_eq!(observed.bytes, 0);
    assert_eq!(observed.calls, 0);
    eprintln!("wallet_decoded_model cases=56 invalid_degrees=3 overflow_cases=4 allocations=0");
}

#[test]
#[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
fn intake_phases_fit_the_maximum_without_counting_canonical_scratch_twice() {
    use super::super::intake::Plan;
    let (maximum, observed) = measure(Plan::maximum);
    let maximum = maximum.unwrap();
    assert_eq!(observed.calls, 0);
    for htlc in [false, true] {
        for degree in 1..=MAX_DEGREE_BITS {
            let plan = Plan::new(degree, htlc).unwrap();
            assert!(plan.peak_bytes <= maximum.peak_bytes);
            assert!(plan.cumulative_requested_bytes <= maximum.cumulative_requested_bytes);
            assert!(plan.valid_decode_requested_bytes <= plan.decoder_allowance_bytes);
            assert!(plan.peak_bytes > plan.decoded_backing_bytes + plan.numerical_peak_bytes);
        }
    }
    eprintln!("wallet_intake_model cases=56 decoded_backing_bytes={} valid_decode_requested_bytes={} decoder_allowance_bytes={} numerical_peak_bytes={} summary_requested_bytes={} peak_bytes={} cumulative_requested_bytes={} allocations=0", maximum.decoded_backing_bytes, maximum.valid_decode_requested_bytes, maximum.decoder_allowance_bytes, maximum.numerical_peak_bytes, maximum.summary_requested_bytes, maximum.peak_bytes, maximum.cumulative_requested_bytes);
}
