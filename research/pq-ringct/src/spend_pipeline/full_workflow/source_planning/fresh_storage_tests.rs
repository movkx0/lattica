use super::*;
use crate::execution::retained_resources::{Ledger, WorkerAllowance};
#[test]
fn selected_profile_bounds_retained_owners_without_fabricating_release_credit() {
    for profile in crate::host_memory_profile::HostMemoryProfile::ALL {
        let limit = profile.worker_bytes();
        assert_eq!(fresh_owned_host_with_limit(host(64), Bytes { host: 128, device: 8 },
            Bytes { host: limit, device: 8 }, limit).unwrap(), limit);
        assert!(fresh_owned_host_with_limit(host(64), Bytes { host: 128, device: 8 },
            Bytes { host: limit + 1, device: 8 }, limit).is_err());
        assert!(fresh_owned_host_with_limit(host(64), Bytes { host: 128, device: 8 },
            Bytes { host: limit, device: 9 }, limit).is_err());
    }
    assert!(fresh_owned_host_with_limit(host(64), Bytes { host: 128, device: 8 },
        Bytes { host: 256, device: 8 }, (32 << 30) + 1).is_err());
}

#[test]
fn fresh_source_census_includes_same_ledger_case_originals_without_credit() {
    let ledger = Ledger::new(WorkerAllowance { host: 1024, device: 128 });
    let generation = ledger.reserve(Category::NativeProof, host(64)).unwrap();
    let startup = ledger.reserve(Category::PhaseScratch, Bytes { host: 128, device: 128 }).unwrap();
    let case = ledger.reserve(Category::RegisteredMetadata, host(32)).unwrap();
    let before = ledger.snapshot().current;
    assert_eq!(fresh_owned_host(generation.requirements().total().unwrap(),
        startup.requirements().total().unwrap(), before).unwrap(), 224);
    assert_eq!(ledger.snapshot().current, before);
    drop(case);
    assert_eq!(fresh_owned_host(host(64), Bytes { host: 128, device: 128 },
        ledger.snapshot().current).unwrap(), 192);
}

#[test]
fn fresh_source_census_refuses_missing_originals_extra_device_and_overflow() {
    let generation = host(64);
    let startup = Bytes { host: 128, device: 128 };
    for current in [Bytes { host: 191, device: 128 }, Bytes { host: 224, device: 127 },
        Bytes { host: 224, device: 129 }, Bytes { host: WORKER_HOST + 1, device: 128 }]
    { assert!(fresh_owned_host(generation, startup, current).is_err()); }
    assert!(fresh_owned_host(Bytes { host: 64, device: 1 }, startup,
        Bytes { host: 224, device: 129 }).is_err());
    assert!(fresh_owned_host(host(u64::MAX), startup,
        Bytes { host: u64::MAX, device: 128 }).is_err());
}
