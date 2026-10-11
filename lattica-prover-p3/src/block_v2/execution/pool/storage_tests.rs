use super::*;

#[test]
fn pool_storage_survives_submission_cancellation_and_failure_collection() {
    let temp = Temp::new();
    let (mut pool, selection, context, state) = fixture(&temp);
    let plan = pool.storage_plan().unwrap();
    assert_eq!(plan.registry_bytes, Registry::<12>::STORAGE_LIMIT_BYTES);
    assert!(pool.registry.storage_bytes().unwrap() <= plan.registry_bytes);
    let total = plan.total_bytes().unwrap();
    plan.admit(total).unwrap();
    assert!(plan.admit(total - 1).is_err());
    let empty = pool.bookkeeping_storage_bytes().unwrap();
    let candidate = pool.submit(&selection, context, [3; 32], 1000, 0).unwrap();
    pool.seal(candidate, [3; 32], 0).unwrap();
    pool.step(1).unwrap();
    let live = pool.bookkeeping_storage_bytes().unwrap();
    assert!(live > empty);
    assert_eq!(pool.slots.capacity(), 1);
    assert_eq!(
        pool.candidates[&candidate].jobs.capacity(),
        selection.jobs().len()
    );
    // Reproduce an endpoint failure while a lease is active. The existing stop
    // path must run before its failure message becomes caller-owned.
    state.borrow_mut().fail_result = true;
    pool.step(2).unwrap();
    assert!(pool.idle());
    assert_eq!(state.borrow().cancelled, 1);
    assert!(pool.bookkeeping_storage_bytes().unwrap() <= plan.bookkeeping.retained_bytes);
    let failures = pool.take_failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].1, "simulated broken transport");
    assert_eq!(failures[0].1.capacity(), 4 * MAX_FAILURE_CHARS);
    let output = PoolOutputStorage::new().unwrap();
    assert!(PoolOutputStorage::failure_storage_bytes(&failures).unwrap() <= output.failure_bytes);
    assert!(pool.failures.is_empty());
    pool.retire(candidate, 3).unwrap();
    let retired = pool.bookkeeping_storage_bytes().unwrap();
    assert!(retired <= plan.bookkeeping.retained_bytes);
    assert!(pool.jobs.is_empty() && pool.candidates.is_empty() && pool.failures.is_empty());
    eprintln!(
        "bounded_pool_bookkeeping retained_bytes={} transition_bytes={} scheduler_retained_bytes={} scheduler_selection_bytes={} total_bytes={}",
        plan.bookkeeping.retained_bytes,
        plan.bookkeeping.transition_bytes,
        plan.bookkeeping.scheduler.retained_bytes,
        plan.bookkeeping.scheduler.selection_bytes,
        plan.bookkeeping.total_bytes().unwrap()
    );
    eprintln!("bounded_pool_census empty_bytes={empty} live_bytes={live} retired_bytes={retired}");
}

#[test]
fn failure_messages_bound_multibyte_and_fragmented_display_without_a_full_string() {
    struct Fragments;
    impl std::fmt::Display for Fragments {
        fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for _ in 0..3000 {
                output.write_str("\u{1f680}")?;
            }
            Ok(())
        }
    }
    let message = failure_message(&Fragments);
    assert_eq!(message, "\u{1f680}".repeat(MAX_FAILURE_CHARS));
    assert_eq!(message.len(), 4 * MAX_FAILURE_CHARS);
    assert_eq!(message.capacity(), 4 * MAX_FAILURE_CHARS);
    assert_eq!(
        failure_message(&"short ASCII failure"),
        "short ASCII failure"
    );
    let mixed = "a\u{1f680}\u{e9}".repeat(1000);
    assert_eq!(
        failure_message(&mixed),
        mixed.chars().take(MAX_FAILURE_CHARS).collect::<String>()
    );
    eprintln!("bounded_pool_failure characters={MAX_FAILURE_CHARS} maximum_bytes={} full_message_allocated=false", message.capacity());
}
