//! Isolate real allocator ownership from the test harness and other test cases.
use super::super::*;
use super::snapshot;

fn live() -> usize {
    let sample = snapshot();
    assert!(sample.accounting_valid);
    assert!(sample.peak_requested_bytes >= sample.live_requested_bytes);
    sample.live_requested_bytes
}

#[test]
fn real_system_spill_reallocation_and_explicit_heap_ownership() {
    const FLAG: &str = "LATTICA_SYSTEM_REQUEST_OWNERSHIP_TEST";
    if std::env::var_os(FLAG).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "spill_alloc::system_requests::allocator_tests::real_system_spill_reallocation_and_explicit_heap_ownership",
                "--test-threads=1",
            ])
            .env(FLAG, "1")
            .env("LATTICA_SPILL_BACKING", "memory")
            .env("LATTICA_SPILL_MAX_BYTES", (THRESHOLD + PAGE).to_string())
            .status().unwrap();
        assert!(status.success());
        return;
    }
    // Resolve the spill configuration before comparing live System ownership.
    drop(SpillScope::arm());
    let initial = live();
    let allocator = SpillAlloc;
    unsafe {
        let small = Layout::from_size_align(37, 8).unwrap();
        let ptr = allocator.alloc_zeroed(small);
        assert!(!ptr.is_null());
        assert_eq!(live(), initial + 37);
        assert!(std::slice::from_raw_parts(ptr, 37).iter().all(|b| *b == 0));
        *ptr = 91;
        let large = allocator.realloc(ptr, small, THRESHOLD);
        assert!(!large.is_null());
        assert_eq!(*large, 91);
        assert_eq!(live(), initial + THRESHOLD + PAGE);
        let large_layout = Layout::from_size_align(THRESHOLD, 8).unwrap();
        let ptr = allocator.realloc(large, large_layout, 73);
        assert!(!ptr.is_null());
        assert_eq!(*ptr, 91);
        assert_eq!(live(), initial + 73);
        allocator.dealloc(ptr, Layout::from_size_align(73, 8).unwrap());
        assert_eq!(live(), initial);

        let aligned = Layout::from_size_align(THRESHOLD + 8, 2 * PAGE).unwrap();
        let ptr = allocator.alloc(aligned);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % (2 * PAGE), 0);
        assert_eq!(live(), initial + THRESHOLD + 8);
        allocator.dealloc(ptr, aligned);
        assert_eq!(live(), initial);

        let zeroed = allocator.alloc_zeroed(large_layout);
        assert!(!zeroed.is_null());
        assert_eq!(live(), initial + THRESHOLD + PAGE);
        assert!(std::slice::from_raw_parts(zeroed, THRESHOLD)
            .iter()
            .all(|b| *b == 0));
        allocator.dealloc(zeroed, large_layout);
        assert_eq!(live(), initial);

        let scope = SpillScope::arm();
        let mapped = allocator.alloc(large_layout);
        assert!(!mapped.is_null());
        assert_eq!(live(), initial);
        assert_eq!(spill_stats(), (1, (THRESHOLD + PAGE) as u64));
        let refused = allocator.alloc(large_layout);
        assert!(refused.is_null());
        assert_eq!(live(), initial);
        // Explicit retained heap storage must still be visible while spill is armed.
        let heap = reserve_heap::<u8>(THRESHOLD + 1, THRESHOLD + 2 * PAGE).unwrap();
        assert_eq!(live(), initial + THRESHOLD + 2 * PAGE);
        drop(heap);
        assert_eq!(live(), initial);
        drop(scope);
        allocator.dealloc(mapped, large_layout);
        assert_eq!(spill_stats(), (0, 0));
        assert_eq!(live(), initial);

        // A valid caller layout can fail when its allocator header is added.
        let impossible = Layout::from_size_align(isize::MAX as usize - PAGE + 1, 1).unwrap();
        assert!(allocator.alloc(impossible).is_null());
        assert_eq!(live(), initial);
        assert!(snapshot().peak_requested_bytes >= initial + THRESHOLD + 2 * PAGE);
    }
}
