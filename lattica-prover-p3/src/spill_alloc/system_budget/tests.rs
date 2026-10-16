use super::*;

#[test]
fn installation_includes_existing_requests_and_cannot_be_widened() {
    let budget = Budget::new();
    assert!(budget.reserve(17));
    budget.install(20).unwrap();
    assert!(budget.reserve(3));
    assert!(!budget.reserve(1));
    assert!(budget.install(40).is_err());
    assert_eq!(budget.snapshot().limit_bytes, Some(20));
    assert_eq!(budget.snapshot().reserved_request_bytes, 20);
    budget.release(17);
    assert!(budget.reserve(17));
    budget.release(20);
    let sample = budget.snapshot();
    assert_eq!(sample.reserved_request_bytes, 0);
    assert_eq!(sample.peak_reserved_request_bytes, 20);
    assert_eq!(sample.rejected_requests, 1);
    assert!(sample.accounting_valid);
    for limit in [0, ACTIVE, usize::MAX] {
        assert!(Budget::new().install(limit).is_err());
    }
    let cold = Budget::new();
    assert!(cold.reserve(21));
    assert!(cold.install(20).is_err());
    assert!(cold.install(40).is_err());
    assert_eq!(cold.snapshot().limit_bytes, None);
    cold.release(21);
}

#[test]
fn overflow_and_unmatched_release_never_wrap_into_headroom() {
    let budget = Budget::new();
    assert!(budget.reserve(MAX_BYTES));
    assert!(!budget.reserve(1));
    assert!(!budget.reserve(usize::MAX));
    assert_eq!(budget.snapshot().reserved_request_bytes, MAX_BYTES);
    budget.release(MAX_BYTES);
    budget.install(7).unwrap();
    budget.release(1);
    assert!(!budget.snapshot().accounting_valid);
    assert!(!budget.reserve(1));
    assert_eq!(budget.snapshot().reserved_request_bytes, 0);
}

#[test]
fn concurrent_requests_hold_one_shared_limit_until_release() {
    let budget = Budget::new();
    budget.install(4096).unwrap();
    let held = std::sync::Barrier::new(5);
    let release = std::sync::Barrier::new(5);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                assert!(budget.reserve(1024));
                held.wait();
                release.wait();
                budget.release(1024);
            });
        }
        held.wait();
        assert_eq!(budget.snapshot().reserved_request_bytes, 4096);
        assert!(!budget.reserve(1));
        release.wait();
    });
    assert_eq!(budget.snapshot().reserved_request_bytes, 0);
    assert_eq!(budget.snapshot().peak_reserved_request_bytes, 4096);
}

#[test]
fn activation_races_are_resolved_before_allocation_can_start() {
    // Repeatedly overlap activation with requests that predate the cap.
    // Activation may reject if one is still held; success must honor the cap.
    for _ in 0..128 {
        let budget = Budget::new();
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let allocator = scope.spawn(|| {
                start.wait();
                if budget.reserve(32) {
                    if budget.snapshot().limit_bytes.is_some() {
                        panic!("oversized request survived successful activation");
                    }
                    budget.release(32);
                }
            });
            start.wait();
            let admitted = budget.install(16).is_ok();
            allocator.join().unwrap();
            if admitted {
                assert!(!budget.reserve(17));
                assert!(budget.reserve(16));
                budget.release(16);
            }
            assert_eq!(budget.snapshot().reserved_request_bytes, 0);
            assert!(budget.snapshot().accounting_valid);
        });
    }
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
fn real_allocations_reject_growth_preserve_old_buffers_and_release_failed_requests() {
    use crate::spill_alloc::{reserve_heap, spill_stats, SpillAlloc, SpillScope, PAGE, THRESHOLD};
    use std::alloc::{GlobalAlloc, Layout};
    const CHILD: &str = "LATTICA_SYSTEM_BUDGET_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "spill_alloc::system_budget::tests::real_allocations_reject_growth_preserve_old_buffers_and_release_failed_requests",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("LATTICA_SPILL_BACKING", "memory")
            .env("LATTICA_SPILL_MAX_BYTES", (THRESHOLD + PAGE).to_string())
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
    // Resolve lazy configuration before fixing the process-wide baseline.
    drop(SpillScope::arm());
    let initial = snapshot().reserved_request_bytes;
    let capacity = THRESHOLD + 2 * PAGE;
    SYSTEM.install(initial + capacity).unwrap();
    let allocator = SpillAlloc;
    unsafe {
        let large_layout = Layout::from_size_align(THRESHOLD, 8).unwrap();
        // Force System itself to fail after reservation, without attempting a
        // huge allocation or changing the hard limit. Restore before reporting.
        let mut original: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_AS, &mut original), 0);
        let tight = libc::rlimit {
            rlim_cur: 0,
            ..original
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_AS, &tight), 0);
        let failed = allocator.alloc(large_layout);
        let restored = libc::setrlimit(libc::RLIMIT_AS, &original);
        assert_eq!(restored, 0);
        assert!(failed.is_null());
        assert_eq!(snapshot().reserved_request_bytes, initial);
        assert_eq!(snapshot().rejected_requests, 0);

        // Fill the exact cap, including the large allocation's header/rounding.
        let mut heap = reserve_heap::<u8>(THRESHOLD + 1, capacity).unwrap();
        heap.push(91);
        assert_eq!(snapshot().reserved_request_bytes, initial + capacity);
        for layout in [
            Layout::from_size_align(1, 1).unwrap(),
            Layout::from_size_align(1, 2 * PAGE).unwrap(),
        ] {
            assert!(allocator.alloc(layout).is_null());
            assert!(allocator.alloc_zeroed(layout).is_null());
        }
        assert!(reserve_heap::<u8>(THRESHOLD, THRESHOLD + PAGE).is_none());
        // Reallocation must reserve old+new until copy/free, and refusal must
        // retain both the original bytes and its original reservation.
        let old = Layout::from_size_align(heap.capacity(), 1).unwrap();
        assert!(allocator
            .realloc(heap.as_mut_ptr(), old, THRESHOLD + 2)
            .is_null());
        assert_eq!(heap[0], 91);
        assert_eq!(snapshot().reserved_request_bytes, initial + capacity);
        // Direct spills remain in their separate mapping reservation. They do
        // not consume System capacity or borrow from the exhausted heap limit.
        let scope = SpillScope::arm();
        let mapped = allocator.alloc(large_layout);
        assert!(!mapped.is_null());
        assert_eq!(spill_stats(), (1, (THRESHOLD + PAGE) as u64));
        assert_eq!(snapshot().reserved_request_bytes, initial + capacity);
        drop(scope);
        allocator.dealloc(mapped, large_layout);
        assert_eq!(spill_stats(), (0, 0));
        drop(heap);
        assert_eq!(snapshot().reserved_request_bytes, initial);
        let zeroed = allocator.alloc_zeroed(large_layout);
        assert!(!zeroed.is_null());
        assert_eq!(*zeroed, 0);
        allocator.dealloc(zeroed, large_layout);
        assert_eq!(snapshot().reserved_request_bytes, initial);
    }
    let sample = snapshot();
    assert!(sample.accounting_valid);
    assert_eq!(sample.rejected_requests, 6);
    assert_eq!(sample.peak_reserved_request_bytes, initial + capacity);
    assert!(SYSTEM.install(initial + capacity + 1).is_err());
    eprintln!("system_request_budget_verified rejections=6 failed_system_rolled_back=true old_buffer_preserved=true spill_separate=true immutable=true");
}
