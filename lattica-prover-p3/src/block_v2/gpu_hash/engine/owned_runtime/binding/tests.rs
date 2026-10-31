use super::*;

fn lease() -> Arc<JobLease> {
    Arc::new(JobLease {
        _global: std::fs::File::open("/dev/null").unwrap(),
        _device: None,
        _slot: None,
    })
}

#[test]
fn weak_identity_is_exact_and_does_not_change_last_strong_owner_rule() {
    let original = lease();
    let engine = Arc::clone(&original);
    let first = Arc::downgrade(&original);
    let same = Arc::downgrade(&engine);
    let foreign_owner = lease();
    let foreign = Arc::downgrade(&foreign_owner);
    // Test the exact private equality helper without fabricating a real
    // OpenCL device handle or an externally constructible runtime binding.
    assert!(same_epoch_and_device(&first, &7u8, &same, &7u8));
    assert!(!same_epoch_and_device(&first, &7u8, &foreign, &7u8));
    assert!(!same_epoch_and_device(&first, &7u8, &same, &8u8));
    assert_ne!(first.strong_count(), 0);
    assert_eq!(Arc::strong_count(&original), 2);
    exact_last_owner(&original, &engine).unwrap();
    let active_session = Arc::clone(&original);
    assert!(exact_last_owner(&original, &engine).is_err());
    drop(active_session);
    exact_last_owner(&original, &engine).unwrap();
    drop(engine);
    assert_ne!(first.strong_count(), 0);
    drop(original);
    assert_eq!(first.strong_count(), 0);
    assert_eq!(same.strong_count(), 0);
    // Another allocation cannot reuse the original backing while Weak lives.
    let later_owner = lease();
    let later = Arc::downgrade(&later_owner);
    assert!(!same_epoch_and_device(&first, &7u8, &later, &7u8));
    assert!(same_epoch_and_device(&first, &7u8, &same, &7u8));
    assert!(RuntimeBinding::retained_allocation_bytes() > core::mem::size_of::<JobLease>());
}

#[test]
fn sole_binding_fact_requires_a_live_epoch_and_no_other_phase_binding() {
    let original = lease();
    let runtime = Arc::downgrade(&original);
    assert!(sole_live_binding(&runtime));
    let phase = Arc::downgrade(&original);
    assert!(!sole_live_binding(&runtime));
    assert!(!sole_live_binding(&phase));
    drop(phase);
    assert!(sole_live_binding(&runtime));
    let captured_before_retirement = sole_live_binding(&runtime);
    drop(original);
    assert!(captured_before_retirement);
    assert!(!sole_live_binding(&runtime));
    assert_eq!(runtime.strong_count(), 0);
}

#[test]
fn retiring_with_another_phase_binding_never_gains_the_sole_binding_fact() {
    let original = lease();
    let runtime = Arc::downgrade(&original);
    let phase = Arc::downgrade(&original);
    let captured_before_retirement = sole_live_binding(&runtime);
    drop(original);
    drop(phase);
    assert!(!captured_before_retirement);
    // Dropping the phase later does not revise the captured refusal fact.
    assert!(!sole_live_binding(&runtime));
}
