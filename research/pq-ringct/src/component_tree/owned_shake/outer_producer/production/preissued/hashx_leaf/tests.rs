use super::*;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn first_hashx_leaf_bridge_claim_refuses_short_or_foreign_storage_and_releases() {
    let required = bridge_requirement().unwrap();
    let bytes = required.total().unwrap();
    assert_eq!(required.get(Category::PhaseScratch), bytes);
    assert_eq!(bytes.device, 0);
    assert!(bytes.host > (8 * size_of::<PreparedHashxLeaf<'_, '_, '_, '_>>()) as u64);
    for (host, admitted) in [(bytes.host, true), (bytes.host - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let result = ledger.admit_phase(required);
        assert_eq!(result.is_ok(), admitted);
        if let Ok(original) = result {
            check_bridge(&original, &ledger).unwrap();
            let foreign = Ledger::new(WorkerAllowance { host, device: 0 });
            assert_eq!(check_bridge(&original, &foreign), Err(Error::Authority));
            for category in Category::ALL {
                assert!(ledger
                    .reserve(category, Bytes { host: 1, device: 0 })
                    .is_err());
            }
            drop(original);
        }
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        for category in ledger.snapshot().categories {
            assert_eq!(category.current, Bytes::ZERO);
        }
    }
    // Only original quota claims are exercised. No fake native/outer attempt,
    // compiler, output, retirement, captured cap or accepted leaf is fabricated.
}
