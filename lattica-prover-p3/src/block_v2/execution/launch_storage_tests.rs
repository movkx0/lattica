use super::*;

#[test]
fn launch_inventory_refresh_counts_overlap_and_keeps_old_state_on_overflow() {
    let temp = Temp::new();
    let mut store = LaunchStore::create(&temp.launches(), LaunchLimits { records: 16 }).unwrap();
    let plan = store.storage_plan().unwrap();
    let empty = store.retained_storage_bytes().unwrap();
    for index in 0..16 {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.launches().join(format!("{index:064x}.worker")))
            .unwrap();
    }
    store.refresh().unwrap();
    let full = store.retained_storage_bytes().unwrap();
    assert!(empty < full && full <= plan.retained_bytes().unwrap());
    let excess = temp.launches().join(format!("{:064x}.worker", 16));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&excess)
        .unwrap();
    assert!(store.refresh().is_err());
    assert_eq!(store.records.len(), 16);
    assert_eq!(store.retained_storage_bytes().unwrap(), full);
    fs::remove_file(excess).unwrap();
    for index in 0..16 {
        fs::remove_file(temp.launches().join(format!("{index:064x}.worker"))).unwrap();
    }
    store.refresh().unwrap();
    assert!(store.records.is_empty());
    assert_eq!(store.retained_storage_bytes().unwrap(), empty);
    eprintln!("bounded_launch_census empty_bytes={empty} full_bytes={full} records=16 rejected_records=17");
}

#[test]
fn launch_component_checks_hard_limit_and_exact_allowance() {
    for (name, records) in [("cli", 256), ("pool", 16384)] {
        let plan = LaunchLimits { records }.storage_plan().unwrap();
        let total = plan.total_bytes().unwrap();
        plan.admit(total).unwrap();
        assert!(plan.admit(total - 1).is_err());
        eprintln!("bounded_launch_storage profile={name} owner_bytes={} retained_records_bytes={} refresh_records_bytes={} control_bytes={} total_bytes={total}",
            plan.owner_bytes, plan.retained_records_bytes, plan.refresh_records_bytes, plan.control_bytes);
    }
    assert!(LaunchLimits { records: 0 }.storage_plan().is_err());
    assert!(LaunchLimits { records: 16385 }.storage_plan().is_err());
}
