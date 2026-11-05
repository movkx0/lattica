//! A larger, explicitly selected research worker does not enlarge an operation.
//! This is only the host envelope check; recorders still validate exact census,
//! reservation ownership, categories, device limits and source geometry.
pub(super) fn allowed(worker_host: u64, recording_host: u64) -> bool {
    const OPERATION_MAX: u64 = 32 << 30;
    (worker_host <= OPERATION_MAX || worker_host == 36 << 30 || worker_host == 40 << 30)
        && recording_host <= OPERATION_MAX
        && recording_host <= worker_host
}
