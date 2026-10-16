//! Host allowances shared by worker admission and allocator reuse checks.

/// Reserve the allowed retained System backing beside the next job's session.
/// Additional cache reservations are charged separately by session admission.
/// This covers the reuse baseline, not allocator growth or complete process RSS.
pub(crate) const RETAINED_SYSTEM_HOST_BYTES: u64 = 512 << 20;

/// Known GPU staging mappings live beside System/spill requests. Keep this
/// declaration available to assignment validation even without a GPU backend.
pub(crate) const GPU_MAPPED_HOST_BYTES: u64 = 64 << 20;
