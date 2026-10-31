use super::*;
use crate::note_research_quota::{Quota, LEDGER_BYTES};
use crate::spill_alloc::allocation_requests::measure;

#[test]
fn insufficient_token_is_refused_before_input_or_metadata_work() {
    let plan = PreparationPlan::new(24 << 30).unwrap();
    let quota = Quota::new(LEDGER_BYTES + plan.required_host_bytes()).unwrap();
    let witness = js::demo_witness();
    let short = quota.reserve(plan.required_host_bytes() - 1).unwrap();
    let (result, requests) = measure(|| plan.prepare(&witness, [Val::ZERO; 26], short));
    assert!(matches!(result, Err(Error::ResourceLimit)));
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
}

#[test]
fn malformed_statement_releases_exact_core_charge_without_allocation() {
    let plan = PreparationPlan::new(24 << 30).unwrap();
    let quota = Quota::new(LEDGER_BYTES + plan.required_host_bytes()).unwrap();
    let witness = js::demo_witness();
    let exact = quota.reserve(plan.required_host_bytes()).unwrap();
    let (result, requests) = measure(|| plan.prepare(&witness, [Val::ZERO; 26], exact));
    assert!(matches!(result, Err(Error::Statement)));
    assert_eq!(requests.calls, 0);
    assert!(!requests.overflow);
    assert_eq!(quota.snapshot().live_reserved_bytes, LEDGER_BYTES);
}
