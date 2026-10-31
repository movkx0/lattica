//! Additional source census for the fixed native outer_host_v1 path.
//! Successful borrowed-slice transfer commands own no Rust heap backing.
//! Their inline owners and bounded failure overlap are still charged before
//! startup; this helper supplies no runtime or proof-dispatch authority.
use super::{engine, NttDeviceCensus};
use core::mem::size_of;

// The completed-tree caller and its offload fence overlap. Reload and scalar
// gather are sequential. Charge four complete fences rather than reuse their
// storage: caller, offload, reload, gather, each including both Queue handles.
const FENCES: usize = 4;
// One original failure plus two queue Results and one formatted error while
// dropping each of two overlapping fences. The eighth slot also covers the
// fatal-cleanup formatting owner. Each slot has an independent bounded reply
// slab plus fixed-format slack; no existing OpenCL claim is subtracted.
const ERROR_SLOTS: usize = 8;
const REPLY_BYTES: usize = 64 << 10;
const ERROR_FORMAT_BYTES: usize = 4096;

fn add(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_add(b)
        .ok_or("native host transfer census overflow")
}
fn mul(a: usize, b: usize) -> Result<usize, &'static str> {
    a.checked_mul(b)
        .ok_or("native host transfer census overflow")
}

fn inline_bytes() -> Result<usize, &'static str> {
    use ocl::builders::{BufferCmd, BufferReadCmd, BufferWriteCmd};
    let command_moves = [
        size_of::<BufferCmd<'static, u64>>(),
        size_of::<BufferReadCmd<'static, 'static, u64>>(),
        size_of::<BufferWriteCmd<'static, 'static, u64>>(),
        size_of::<ocl::Event>(),
        size_of::<std::iter::Enumerate<std::slice::Chunks<'static, u64>>>(),
        size_of::<std::iter::Enumerate<std::slice::ChunksMut<'static, u64>>>(),
        2 * size_of::<std::time::Instant>(),
        // Resolved event pointers, range, borrowed source/destination, closure
        // captures, loop/index/timestamp locals. The descriptors above already
        // include command fields; keeping this additional block takes no
        // compiler stack-slot or move-elision credit.
        64 * size_of::<usize>(),
    ]
    .into_iter()
    .try_fold(0, add)?;
    let errors = size_of::<ocl::Error>()
        + size_of::<ocl::core::Error>()
        + size_of::<Result<(), ocl::Error>>()
        + size_of::<Result<(), String>>()
        + size_of::<String>();
    [
        mul(FENCES, size_of::<engine::QueueFence>())?,
        mul(2, command_moves)?,
        // Original device tree, uploaded tree and Option/move owners are all
        // counted despite sequential use. The actual payloads remain in the
        // managed device plan and original 8 GiB host-tree quota.
        mul(2, size_of::<engine::Allocation>())?,
        mul(2, size_of::<Option<engine::Allocation>>())?,
        mul(2, size_of::<engine::retained_storage::HostBacking>())?,
        mul(ERROR_SLOTS, errors)?,
        // Profiling replies are sequential and each capped at sizeof(u64).
        // Charge both reply vectors and payloads without a liveness credit.
        mul(2, size_of::<Vec<u8>>() + size_of::<u64>())?,
    ]
    .into_iter()
    .try_fold(0, add)
}

impl NttDeviceCensus {
    /// Fixed host transfer wrappers only. Original startup owns mapped staging,
    /// timeline/engine backing and the entire tree quota; PCS owns proof/query
    /// data; the common native OpenCL census owns kernel/program wrappers.
    pub(crate) fn host_transfer_wrapper_bytes() -> Result<usize, &'static str> {
        if !cfg!(all(
            target_os = "linux",
            target_arch = "x86_64",
            feature = "gpu-bounded-info"
        )) || size_of::<usize>() != 8
            || ocl::core::bounded_info::MAX_REPLY_BYTES != REPLY_BYTES
        {
            return Err("native host transfer census requires the pinned OpenCL profile");
        }
        add(
            inline_bytes()?,
            mul(ERROR_SLOTS, add(REPLY_BYTES, ERROR_FORMAT_BYTES)?)?,
        )
    }
}
