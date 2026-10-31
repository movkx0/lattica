//! Opt-in test observer, built without the core stream allocator. Every Rayon
//! allocation during a measured call contributes; the source census remains
//! the admission authority. Run these ignored observations in a serial process.
#[cfg(any(feature = "gpu-proving", feature = "note-gpu-preparation"))]
compile_error!("note-verification-allocation-audit requires a CPU-only test binary");

use super::*;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct Observer;
#[global_allocator]
static ALLOCATOR: Observer = Observer;
static ENABLED: AtomicBool = AtomicBool::new(false);
static BYTES: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicUsize = AtomicUsize::new(0);
static OVERFLOW: AtomicBool = AtomicBool::new(false);
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn observe(bytes: usize) {
    if ENABLED.load(Ordering::Acquire) {
        for (counter, amount) in [(&BYTES, bytes), (&CALLS, 1)] {
            if counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                    n.checked_add(amount)
                })
                .is_err()
            {
                OVERFLOW.store(true, Ordering::Relaxed);
            }
        }
    }
}
unsafe impl GlobalAlloc for Observer {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
struct Disable;
impl Drop for Disable {
    fn drop(&mut self) {
        ENABLED.store(false, Ordering::Release);
    }
}

pub(super) fn measure_checked<T>(bound: usize, work: impl FnOnce() -> T) -> T {
    let _lock = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    BYTES.store(0, Ordering::Relaxed);
    CALLS.store(0, Ordering::Relaxed);
    OVERFLOW.store(false, Ordering::Relaxed);
    let disable = Disable;
    ENABLED.store(true, Ordering::Release);
    let result = work();
    drop(disable);
    let bytes = BYTES.load(Ordering::Acquire);
    let calls = CALLS.load(Ordering::Acquire);
    assert!(!OVERFLOW.load(Ordering::Acquire));
    assert!(
        bytes <= bound,
        "requested={bytes} source_bound={bound} allocations={calls}"
    );
    eprintln!("private_note_verifier_allocation_requests bytes={bytes} allocations={calls} source_bound={bound} all_threads=true");
    result
}

#[test]
#[ignore = "release-only serial process-wide allocation observation"]
fn admission_and_insufficient_quota_rejection_allocate_nothing() {
    let plan = measure_checked(0, VerificationPlan::new).unwrap();
    let expected = crate::note_gpu::tests::statement();
    let packet =
        crate::note_gpu::tests::packet(&crate::note_gpu::tests::fixture(&[4, 4, 4, 1]), &expected);
    let required = decode_required_bytes(&packet, &expected).unwrap();
    let session = DecodeSession::new(required + plan.required_temporary_bytes() - 1).unwrap();
    let artifact = session.decode(packet, &expected, expected.context).unwrap();
    let result = measure_checked(0, || plan.verify(&artifact));
    assert!(matches!(result, Err(VerificationError::ResourceLimit)));
    drop(artifact);
    assert_eq!(
        session.snapshot().live_reserved_bytes,
        session.snapshot().ledger_bytes
    );
}

#[test]
#[ignore = "release-only serial process-wide allocation observation with bounded Rayon runtime"]
fn fresh_configuration_periodic_and_numeric_air_fit_their_source_components() {
    use p3_commit::PolynomialSpace;
    let plan = VerificationPlan::new().unwrap();
    for _ in 0..3 {
        measure_checked(plan.configuration_bytes, fresh_config).unwrap();
    }
    let domain = p3_uni_stark::Domain::<MyConfig>::new(Val::ONE, 12).unwrap();
    let warm = js::periodic();
    // The first interpolation initializes the external Rayon pool. It is
    // outside the numerical payload model; every subsequent worker request is
    // measured globally until the joined interpolation has returned.
    std::hint::black_box(domain.evaluate_periodic_column_at(&warm[11], Challenge::from_u64(19)));
    drop(warm);
    let columns = measure_checked(plan.periodic_construction_bytes, js::periodic);
    let retained = columns.capacity() * core::mem::size_of::<Vec<Val>>()
        + columns
            .iter()
            .map(|v| v.capacity() * core::mem::size_of::<Val>())
            .sum::<usize>();
    assert!(retained <= plan.periodic_retained_bytes);
    for index in [0, 11] {
        for point in [Challenge::ONE, Challenge::from_u64(19)] {
            measure_checked(plan.periodic_evaluation_peak_bytes, || {
                domain.evaluate_periodic_column_at(&columns[index], point)
            });
        }
    }
    let row = vec![Challenge::ZERO; js::WIDTH];
    let public = vec![Val::ZERO; js::N_PUBLIC];
    let periodic = vec![Challenge::ZERO; js::N_PERIODIC];
    let _result = measure_checked(plan.air_bytes, || {
        p3_uni_stark::verify_constraints::<MyConfig, _, ()>(
            &air::VerifierAir,
            &row,
            &row,
            None,
            None,
            &periodic,
            &public,
            domain,
            Challenge::from_u64(13),
            Challenge::from_u64(17),
            Challenge::ZERO,
        )
    });
}
