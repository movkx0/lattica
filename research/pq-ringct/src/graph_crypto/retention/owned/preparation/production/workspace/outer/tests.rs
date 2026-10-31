use super::*;
use crate::execution::retained_resources::WorkerAllowance;

#[test]
fn bridge_entry_requires_the_live_ticket_and_never_falls_back() {
    for enabled in [false, true] {
        for bound in [false, true] {
            for pending in [false, true] {
                for ticket in [false, true] {
                    assert_eq!(
                        native_entry(enabled, bound, pending, ticket),
                        (!enabled && !bound && !pending && !ticket)
                            || (enabled && bound && !pending && ticket)
                    );
                }
            }
        }
    }
    // An enabled/unbound claim and a dropped ticket both refuse before native0.
    assert!(!native_entry(true, false, true, false));
    assert!(!native_entry(true, true, false, false));
}

#[test]
fn all_ten_original_children_and_attachments_must_have_moved() {
    assert!(children_moved(10, 0, 0));
    for next in [0, 1, 8, 9, 11, usize::MAX] {
        assert!(!children_moved(next, 0, 0));
    }
    for remaining in 1..=10 {
        assert!(!children_moved(10, remaining, 0));
        assert!(!children_moved(10, 0, remaining));
        assert!(!children_moved(10, remaining, remaining));
    }
}

#[test]
fn bridge_claim_is_additive_exact_and_releases_on_terminal_drop() {
    let required = bridge_requirement().unwrap();
    let bytes = required.total().unwrap();
    assert_eq!(bytes.device, 0);
    assert_eq!(required.get(Category::PhaseScratch), bytes);
    assert!(bytes.host > (8 * size_of::<ActiveHashxOuter<'_, '_>>()) as u64);
    for (host, admitted) in [(bytes.host, true), (bytes.host - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let result = ledger.admit_phase(required);
        assert_eq!(result.is_ok(), admitted);
        if let Ok(original) = result {
            check_bridge(&original, &ledger).unwrap();
            let other = Ledger::new(WorkerAllowance { host, device: 0 });
            assert_eq!(check_bridge(&original, &other), Err(Error::Authority));
            drop(original);
        }
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    // Pure claim checks mint no native/outer attempt, proof or retirement owner.
}
