//! Process-local native lifecycle for the explicitly selected owned GPU prover.

#[cfg(any(test, all(feature = "block-v2", feature = "gpu")))]
use std::sync::Mutex;

#[cfg(any(test, all(feature = "block-v2", feature = "gpu")))]
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
#[cfg(any(test, all(feature = "block-v2", feature = "gpu")))]
static LIFECYCLE: Mutex<()> = Mutex::new(());

#[cfg(any(test, all(feature = "block-v2", feature = "gpu")))]
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

/// Initialize the explicitly configured complete OpenCL proving path.
/// Configure the process environment before starting native or Rust proof work.
#[no_mangle]
pub extern "C" fn lattica_gpu_initialize_from_env() -> i32 {
    #[cfg(all(feature = "block-v2", feature = "gpu"))]
    return call(crate::block_v2::native_gpu::initialize);
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
        feature = "gpu",
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
        feature = "gpu",
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
    #[cfg(not(all(feature = "block-v2", feature = "gpu")))]
    UNAVAILABLE
}

/// Retire the engine only when its retained commitments and sessions are gone.
/// Repeated shutdown is harmless; it does not switch proving back to CPU.
#[no_mangle]
pub extern "C" fn lattica_gpu_shutdown() -> i32 {
    #[cfg(all(feature = "block-v2", feature = "gpu"))]
    return call(crate::block_v2::gpu_hash::shutdown);
    #[cfg(not(all(feature = "block-v2", feature = "gpu")))]
    UNAVAILABLE
}

#[cfg(test)]
mod tests;
