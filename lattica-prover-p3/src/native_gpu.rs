//! Process-local native lifecycle for the explicitly selected owned GPU prover.

#[cfg(any(
    test,
    all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda"))
))]
use std::sync::Mutex;

#[cfg(any(
    test,
    all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda"))
))]
const OK: i32 = 0;
const REJECTED: i32 = 1;
pub(crate) const PUBLIC_WORKER_BOOTSTRAP_MAX_BYTES: usize = 64 << 10;
#[cfg(not(all(
    feature = "block-v2",
    feature = "gpu",
    feature = "stream",
    target_os = "linux"
)))]
const UNAVAILABLE: i32 = 2;
#[cfg(any(
    test,
    all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda"))
))]
static LIFECYCLE: Mutex<()> = Mutex::new(());

#[cfg(any(
    test,
    all(feature = "block-v2", any(feature = "gpu", feature = "gpu-cuda"))
))]
fn call(operation: impl FnOnce() -> Result<(), String> + std::panic::UnwindSafe) -> i32 {
    std::panic::catch_unwind(|| {
        let _guard = LIFECYCLE
            .lock()
            .map_err(|_| "native GPU lifecycle poisoned")?;
        // Catch inside the guard so a rejected operation does not poison the
        // lifecycle mutex and prevent a later drain or shutdown.
        std::panic::catch_unwind(operation)
            .map_err(|_| "native GPU operation panicked".to_owned())?
    })
    .map_or(
        REJECTED,
        |result| if result.is_ok() { OK } else { REJECTED },
    )
}

/// Initialize the explicitly configured complete wallet proving path.
/// CUDA requires a private wallet resource assignment in a fresh Linux process.
/// Configure the process environment before starting native or Rust proof work.
#[no_mangle]
pub extern "C" fn lattica_gpu_initialize_from_env() -> i32 {
    #[cfg(all(feature = "block-v2", feature = "gpu"))]
    return call(crate::block_v2::native_gpu::initialize);
    #[cfg(all(feature = "block-v2", feature = "gpu-cuda"))]
    if crate::block_v2::cuda_wallet::is_selected() {
        return call(crate::block_v2::cuda_wallet::initialize);
    }
    #[cfg(not(all(feature = "block-v2", feature = "gpu")))]
    UNAVAILABLE
}

/// Start the complete owned GPU path in a fresh Linux public-worker process.
/// Uses the existing public worker assignment; grants no private wallet access.
#[no_mangle]
pub extern "C" fn lattica_gpu_public_worker_initialize_from_env() -> i32 {
    #[cfg(all(
        feature = "block-v2",
        feature = "gpu",
        feature = "stream",
        target_os = "linux"
    ))]
    return call(crate::block_v2::native_public_gpu::initialize);
    #[cfg(not(all(
        feature = "block-v2",
        feature = "gpu",
        feature = "stream",
        target_os = "linux"
    )))]
    UNAVAILABLE
}

/// Initialize, serve the existing typed public-worker protocol, and shut down.
/// The caller retains its connected Unix stream descriptor. Success requires
/// a clean protocol STOP and GPU teardown; no wallet or registry authority is
/// granted. Call once in a fresh process, without prior GPU initialization.
/// CUDA builds select this owned service only with an explicit `cuda` worker
/// assignment; standalone lifecycle calls only control a separately assigned
/// private wallet context and never this public worker runtime.
///
/// Worker admission includes 65,537 bytes for the qualified caller's bootstrap
/// buffer (including its EOF probe) and 65,536 bytes for retained launch-path
/// backing throughout the service. Additional caller-owned storage needs its
/// own allowance; a borrowed slice does not expose its owner's full capacity.
/// Admission also reserves an 8 MiB caller stack plus bounded guards/signal
/// backing. Keep the calling stack and its alternate stack within these bounds
/// throughout the call. A main-thread caller must keep RLIMIT_STACK at most
/// 8 MiB; raising it after admission invalidates the resource contract. Other
/// caller threads and their storage require separate accounting.
/// GNU/Linux stream workers require a valid glibc allocator observation no
/// greater than the reserved 512 MiB System baseline before assignment decoding
/// and again before Rayon starts. Missing observations reject startup. This is
/// a boundary check; direct mappings and later allocator growth remain separate.
/// Before Rayon starts, stream admission also fixes a process-wide ceiling on
/// live/in-flight Rust System requests, outside stack and retained-heap reserves.
/// Refused requests follow the caller's allocation-failure behavior; infallible
/// Rust allocations may abort the worker. The ceiling lasts until process exit
/// and excludes allocator metadata/retention, foreign allocations and mappings.
/// A second shared ceiling charges simultaneous System requests and full spill
/// backing, including in-flight reservations, with mapped GPU staging reserved
/// separately. Nonresident spill capacity is still charged. This ceiling also
/// persists through exit and is not complete allocator or RSS admission.
/// Stream startup checks cold private writable data, then lowers both soft and
/// hard RLIMIT_DATA to worker RAM minus caller/Rayon stacks, the full assigned
/// spill allowance and mapped GPU staging. Disk-backed spill capacity is still
/// reserved; this does not assume those pages remain nonresident. The hard
/// limit persists until process exit and is not restored after failure. Keep
/// other startup owners quiescent during admission; discard a failed worker.
/// The allocator's cached spill cap, directory and backing must match admission;
/// a changed environment cannot replace an older cached configuration. Active
/// spill scopes reject before thread creation, without changing that configuration.
/// Shared mappings, grow-down stacks and complete RSS remain separate.
/// Kernel ignore_rlimit_data must be observable, disabled and remain fixed;
/// unavailable or unknown enforcement rejects startup.
///
/// # Safety
/// `bootstrap` must reference `bootstrap_len` readable bytes for this call.
/// `completed_out` must be aligned, writable and disjoint from those bytes.
/// Neither region may be concurrently mutated. Non-null pointers must remain
/// valid until this blocking call returns. The output is zero on failure.
#[no_mangle]
pub unsafe extern "C" fn lattica_gpu_public_worker_serve(
    socket_fd: i32,
    bootstrap: *const u8,
    bootstrap_len: usize,
    completed_out: *mut u64,
) -> i32 {
    if completed_out.is_null() {
        return REJECTED;
    }
    unsafe { completed_out.write(0) };
    if socket_fd < 0
        || bootstrap.is_null()
        || bootstrap_len == 0
        || bootstrap_len > PUBLIC_WORKER_BOOTSTRAP_MAX_BYTES
    {
        return REJECTED;
    }
    #[cfg(all(
        feature = "block-v2",
        any(feature = "gpu", feature = "gpu-cuda"),
        feature = "stream",
        target_os = "linux"
    ))]
    return call(|| {
        use crate::block_v2::execution::native_worker;
        let socket = native_worker::duplicate_socket(socket_fd).map_err(|e| e.to_string())?;
        let bytes = unsafe { std::slice::from_raw_parts(bootstrap, bootstrap_len) };
        let completed = native_worker::serve(socket, bytes).map_err(|e| {
            eprintln!("native public worker service rejected: {e}");
            e.to_string()
        })?;
        unsafe { completed_out.write(completed) };
        Ok(())
    });
    #[cfg(not(all(
        feature = "block-v2",
        any(feature = "gpu", feature = "gpu-cuda"),
        feature = "stream",
        target_os = "linux"
    )))]
    UNAVAILABLE
}

/// Finish submitted work without retiring live device sessions or commitments.
#[no_mangle]
pub extern "C" fn lattica_gpu_drain() -> i32 {
    #[cfg(all(feature = "block-v2", feature = "gpu"))]
    return call(crate::block_v2::gpu_hash::drain);
    #[cfg(all(feature = "block-v2", feature = "gpu-cuda"))]
    if crate::block_v2::cuda_wallet::is_selected() {
        return call(crate::block_v2::cuda_wallet::drain);
    }
    #[cfg(not(all(feature = "block-v2", feature = "gpu")))]
    UNAVAILABLE
}

/// Retire the engine only when its retained commitments and sessions are gone.
/// Repeated shutdown is harmless; it does not switch proving back to CPU.
#[no_mangle]
pub extern "C" fn lattica_gpu_shutdown() -> i32 {
    #[cfg(all(feature = "block-v2", feature = "gpu"))]
    return call(crate::block_v2::gpu_hash::shutdown);
    #[cfg(all(feature = "block-v2", feature = "gpu-cuda"))]
    if crate::block_v2::cuda_wallet::is_selected() {
        return call(crate::block_v2::cuda_wallet::shutdown);
    }
    #[cfg(not(all(feature = "block-v2", feature = "gpu")))]
    UNAVAILABLE
}

#[cfg(test)]
mod tests;
