use super::*;

#[test]
fn failed_release_poisoning_cannot_lend_capacity_to_new_requests() {
    let budget = Budget::new();
    budget.install(64).unwrap();
    assert!(budget.reserve(32));
    budget.invalidate();
    assert_eq!(budget.snapshot().reserved_request_bytes, 32);
    assert!(!budget.snapshot().accounting_valid);
    assert!(!budget.reserve(1));
    assert!(budget.install(128).is_err());
}

#[test]
fn observation_does_not_allocate() {
    let (sample, requests) = crate::spill_alloc::allocation_requests::measure(snapshot);
    assert!(sample.accounting_valid);
    assert_eq!((requests.calls, requests.bytes), (0, 0));
    assert!(!requests.overflow);
}

#[test]
#[cfg(target_os = "linux")]
fn actual_heap_and_spill_requests_share_capacity_and_roll_back_failures() {
    use crate::spill_alloc::{
        reserve_heap, spill_stats, system_budget, SpillAlloc, SpillScope, PAGE, THRESHOLD,
    };
    use std::alloc::{GlobalAlloc, Layout};
    const CHILD: &str = "LATTICA_HOST_BUDGET_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for backing in ["file", "memory"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "spill_alloc::host_budget::tests::actual_heap_and_spill_requests_share_capacity_and_roll_back_failures",
                    "--test-threads=1",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("LATTICA_SPILL_BACKING", backing)
                .env("LATTICA_SPILL_DIR", "/tmp")
                .env("LATTICA_SPILL_MAX_BYTES", (3 * (THRESHOLD + PAGE)).to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{backing}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            print!("{}", String::from_utf8_lossy(&output.stdout));
            eprint!("{}", String::from_utf8_lossy(&output.stderr));
        }
        return;
    }
    drop(SpillScope::arm());
    let initial = snapshot().reserved_request_bytes;
    let system_initial = system_budget::snapshot().reserved_request_bytes;
    let backing = THRESHOLD + PAGE;
    let capacity = backing + PAGE;
    HOST.install(initial + capacity).unwrap();
    let allocator = SpillAlloc;
    unsafe {
        let large = Layout::from_size_align(THRESHOLD, 8).unwrap();
        let small = Layout::from_size_align(PAGE, 8).unwrap();
        let one = Layout::from_size_align(1, 1).unwrap();
        // A real System failure and real mmap failure must release both their
        // combined reservations and their separate System/spill reservations.
        let mut original: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_AS, &mut original), 0);
        let tight = libc::rlimit {
            rlim_cur: 0,
            ..original
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_AS, &tight), 0);
        let failed_heap = allocator.alloc(large);
        let scope = SpillScope::arm();
        let failed_spill = allocator.alloc(large);
        drop(scope);
        let restored = libc::setrlimit(libc::RLIMIT_AS, &original);
        assert_eq!(restored, 0);
        assert!(failed_heap.is_null() && failed_spill.is_null());
        assert_eq!(snapshot().reserved_request_bytes, initial);
        assert_eq!(
            system_budget::snapshot().reserved_request_bytes,
            system_initial
        );
        assert_eq!(spill_stats(), (0, 0));
        assert_eq!(snapshot().rejected_requests, 0);

        let heap = allocator.alloc(small);
        assert!(!heap.is_null());
        let scope = SpillScope::arm();
        let spilled = allocator.alloc(large);
        assert!(!spilled.is_null());
        spilled.write(91);
        assert_eq!(spill_stats(), (1, backing as u64));
        assert_eq!(snapshot().reserved_request_bytes, initial + capacity);
        assert_eq!(
            system_budget::snapshot().reserved_request_bytes,
            system_initial + PAGE
        );
        assert!(allocator.alloc(one).is_null());
        assert!(allocator.alloc_zeroed(one).is_null());
        assert!(reserve_heap::<u8>(THRESHOLD, backing).is_none());
        // The old mapping remains live throughout replacement allocation.
        assert!(allocator.realloc(spilled, large, THRESHOLD + 1).is_null());
        assert_eq!(*spilled, 91);
        assert_eq!(spill_stats(), (1, backing as u64));
        assert_eq!(snapshot().reserved_request_bytes, initial + capacity);
        allocator.dealloc(spilled, large);
        assert_eq!(spill_stats(), (0, 0));
        assert_eq!(snapshot().reserved_request_bytes, initial + PAGE);
        drop(scope);

        // Test the other direction: a live large heap request prevents a spill
        // despite the separate spill ledger having its entire capacity free.
        let large_heap = allocator.alloc(large);
        assert!(!large_heap.is_null());
        let scope = SpillScope::arm();
        assert!(allocator.alloc(large).is_null());
        assert_eq!(spill_stats(), (0, 0));
        assert_eq!(snapshot().reserved_request_bytes, initial + capacity);
        drop(scope);
        allocator.dealloc(large_heap, large);
        allocator.dealloc(heap, small);
    }
    assert_eq!(snapshot().reserved_request_bytes, initial);
    assert_eq!(snapshot().peak_reserved_request_bytes, initial + capacity);
    assert_eq!(snapshot().rejected_requests, 5);
    assert!(snapshot().accounting_valid);
    assert!(HOST.install(initial + capacity + 1).is_err());
    eprintln!("combined_host_budget_verified rejections=5 system_and_mmap_rollback=true old_buffer_preserved=true full_spill_charged=true immutable=true");
}

#[test]
#[cfg(target_os = "linux")]
fn optional_spill_failure_falls_back_without_double_charging() {
    use crate::spill_alloc::{spill_stats, system_budget, SpillAlloc, SpillScope, PAGE, THRESHOLD};
    use std::alloc::{GlobalAlloc, Layout};
    const CHILD: &str = "LATTICA_HOST_FALLBACK_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "spill_alloc::host_budget::tests::optional_spill_failure_falls_back_without_double_charging",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("LATTICA_SPILL_BACKING", "file")
            .env("LATTICA_SPILL_DIR", "/dev/null/not-a-directory")
            .env_remove("LATTICA_SPILL_MAX_BYTES")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        return;
    }
    let scope = SpillScope::arm();
    let initial = snapshot().reserved_request_bytes;
    let system_initial = system_budget::snapshot().reserved_request_bytes;
    let backing = THRESHOLD + PAGE;
    HOST.install(initial + backing).unwrap();
    unsafe {
        let layout = Layout::from_size_align(THRESHOLD, 8).unwrap();
        let ptr = SpillAlloc.alloc(layout);
        assert!(!ptr.is_null());
        ptr.write(53);
        assert_eq!(spill_stats(), (0, 0));
        assert_eq!(snapshot().reserved_request_bytes, initial + backing);
        assert_eq!(
            system_budget::snapshot().reserved_request_bytes,
            system_initial + backing
        );
        assert_eq!(*ptr, 53);
        SpillAlloc.dealloc(ptr, layout);
    }
    drop(scope);
    assert_eq!(snapshot().reserved_request_bytes, initial);
    assert_eq!(snapshot().rejected_requests, 0);
    assert!(snapshot().accounting_valid);
    eprintln!(
        "combined_host_budget_fallback_verified rollback_before_system=true single_charge=true"
    );
}
