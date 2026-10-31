use super::*;
use crate::note_research_quota::{Quota, LEDGER_BYTES};
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn output_readback_requires_exact_statement_canonical_words_and_transfer_count() {
    let expected = core::array::from_fn(|i| Val::from_usize(i + 1));
    let words = expected.map(|value| value.as_canonical_u64());
    validate_readback(&words, 208, &expected).unwrap();
    for bytes in [0, 200, 216] {
        assert_eq!(
            validate_readback(&words, bytes, &expected),
            Err(Error::Statement)
        );
    }
    assert_eq!(
        validate_readback(&words[..25], 208, &expected),
        Err(Error::Statement)
    );
    let mut reordered = words;
    reordered.swap(0, 1);
    assert_eq!(
        validate_readback(&reordered, 208, &expected),
        Err(Error::Statement)
    );
    let mut noncanonical = words;
    noncanonical[0] += Val::ORDER_U64;
    assert_eq!(
        validate_readback(&noncanonical, 208, &expected),
        Err(Error::Statement)
    );
}

#[test]
fn phase_reservation_requires_original_ledger_and_full_preceding_output_charge() {
    let resources = OperationResources::new().unwrap();
    let required = resources.required_host_bytes();
    assert!(required < 24 << 30);
    assert_eq!(resources.encoded_proof_bytes, 64 << 20);
    let quota = Quota::new(LEDGER_BYTES + required).unwrap();
    let other = Quota::new(LEDGER_BYTES + required).unwrap();
    let anchor = quota.reserve(0).unwrap();
    let wrong = other.reserve(required).unwrap();
    let short = quota.reserve(required - 1).unwrap();
    let (refusals, allocations) = measure(|| {
        (
            resources.check_reservation(&wrong, &anchor),
            resources.check_reservation(&short, &anchor),
        )
    });
    assert_eq!(
        refusals,
        (Err(Error::ResourceLimit), Err(Error::ResourceLimit))
    );
    assert_eq!(
        (allocations.calls, allocations.bytes, allocations.overflow),
        (0, 0, false)
    );
    drop(short);
    let exact = quota.reserve(required).unwrap();
    resources.check_reservation(&exact, &anchor).unwrap();
    drop(quota);
    let moved = exact;
    assert!(anchor.reserve_related(1).is_err());
    drop(moved);
    let reclaimed = anchor.reserve_related(required).unwrap();
    drop(reclaimed);
    drop(wrong);
    assert_eq!(other.snapshot().live_reserved_bytes, LEDGER_BYTES);
}
