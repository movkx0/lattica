use super::*;
use crate::block_v2::gpu_hash::cache_metadata::arc_bytes;

pub(super) fn counts() -> [usize; 6] {
    [input_layout::WORDS, ARENA_WORDS, SLOT_OFFSETS.len(), RNG_WORDS,
        STATUS_WORDS, REJECTION_OFFSETS.len()]
}
pub(super) fn managed_bytes() -> Result<usize> {
    counts().into_iter().try_fold(0, |total, words| add(total, mul(words, size_of::<u64>())?))
}
pub(super) fn output_bytes() -> Result<usize> {
    sum([InputSource::output_backing_bytes(), size_of::<PrivateSpendOutput>(),
        size_of::<SpendEvidence>(), size_of::<(PrivateSpendOutput, SpendEvidence)>()])
}
pub(super) fn static_bytes() -> Result<usize> {
    // Included source text and actual compiled layout tables coexist. The
    // source-lock strings are deliberately charged even when the linker can
    // merge identical literals. No heap/context allowance is deducted.
    sum([pins::static_bytes()?, pins::BUNDLE.len(), pins::CONTROLLER.len(),
        pins::DISPATCH.len(), pins::TYPES.len(), pins::ENTRY.len(),
        core::mem::size_of_val(&SLOT_OFFSETS),
        core::mem::size_of_val(&REJECTION_OFFSETS), core::mem::size_of_val(&STEPS),
        SOURCE_SHA256.len(), STEPS.iter().map(|step| step.name.len()).sum()])
}
pub(super) fn operation_host_bytes() -> Result<usize> {
    let buffers = counts().len();
    // Vec<Result<MatrixSpec,_>>::collect may grow before finding an error.
    // Six outputs fit a power-of-two capacity of eight; charge old capacity
    // four too so a moving allocation cannot overlap an uncharged payload.
    let specs = mul(4 + 8, size_of::<MatrixSpec>())?;
    let matrices = mul(buffers, size_of::<DeviceMatrix>())?;
    let allocations = mul(buffers, arc_bytes::<Allocation>())?;
    // The outer six-buffer plan and one temporary single-buffer recheck in
    // DeviceSession::allocate coexist. Keep both Vec backings admitted.
    let plan = mul(buffers + 1, size_of::<usize>())?;
    // read_public owns word and byte vectors together. NativeProof owns the
    // byte vectors; charge both complete word vectors here, without relying
    // on sequential reads. Key words coexist with returned key polynomials.
    let readbacks = sum([STATEMENT_BYTES, PROOF_BYTES,
        mul(18 * 256, size_of::<u64>())?])?;
    sum([InputSource::packed_backing_bytes(), specs, matrices, allocations,
        plan, readbacks, dispatch_backing()?, ocl_storage::requested_bytes()?,
        super::super::super::host_storage::session_bytes(), inline_bytes()?])
}
pub(super) fn dispatch_backing() -> Result<usize> {
    // preparations: two descriptions grow to four at step 14 (three live).
    // Result collect can request capacities 4 then 8; native_spend_step adds
    // exactly one final kernel, for max length four. Charge all old/new
    // request payloads conservatively; no accumulated per-attempt charge.
    sum([mul(2 + 4, size_of::<(&'static str, usize)>())?,
        mul(4 + 8, size_of::<(&'static str, ocl::Kernel)>())?])
}
fn inline_bytes() -> Result<usize> {
    use ocl::builders::{BufferCmd, BufferReadCmd, BufferWriteCmd, KernelCmd};
    // Explicit declared owners/returns of create_spend_inner, pack,
    // create_native_private_spend_inner, native_spend_step and read_public.
    // These are requested Rust backing facts, not compiler stack high-water.
    // Existing fixed worker-thread stacks and opaque driver internals remain
    // separately reserved by the runtime/process envelope.
    sum([
        size_of::<NativeSpendOperationPlan>(), size_of::<PrivateSpendRequest>(),
        InputSource::packing_inline_bytes(), size_of::<Run>(),
        size_of::<crate::proving::Request>(), size_of::<crate::proving::Capabilities>(),
        size_of::<super::super::super::ProofCapacity>(),
        size_of::<[usize; 6]>(), size_of::<Vec<MatrixSpec>>(),
        2 * size_of::<MemoryPlan>(), size_of::<Scratch>(), size_of::<SecretReadback>(),
        size_of::<[MatrixSpec; 1]>(), size_of::<Allocation>(), size_of::<Lease>(),
        size_of::<ocl::builders::BufferBuilder<'static, u64>>(),
        size_of::<core::result::Result<Allocation, String>>(),
        size_of::<core::result::Result<DeviceMatrix, String>>(),
        size_of::<Vec<u64>>(), size_of::<Vec<u8>>(), size_of::<Vec<[i64; 256]>>(),
        size_of::<PrivateOutputKeys>(), size_of::<[u64; STATUS_WORDS]>(),
        size_of::<[u32; STATUS_U32_WORDS]>(), size_of::<[u8; 8]>(),
        size_of::<[i64; 256]>(), size_of::<Vec<(&'static str, usize)>>(),
        size_of::<Vec<(&'static str, ocl::Kernel)>>(),
        size_of::<std::vec::IntoIter<(&'static str, ocl::Kernel)>>(),
        size_of::<std::vec::IntoIter<(&'static str, usize)>>(),
        size_of::<std::vec::IntoIter<MatrixSpec>>(), size_of::<std::vec::IntoIter<u64>>(),
        size_of::<ocl::Program>(), size_of::<ocl::Kernel>(), size_of::<ocl::Event>(),
        size_of::<BufferCmd<'static, u64>>(), size_of::<BufferReadCmd<'static, 'static, u64>>(),
        size_of::<BufferWriteCmd<'static, 'static, u64>>(), size_of::<KernelCmd<'static>>(),
        size_of::<Result<(PrivateSpendOutput, SpendEvidence)>>(),
        size_of::<core::result::Result<(PrivateSpendOutput, SpendEvidence), String>>(),
        size_of::<core::result::Result<Vec<u8>, String>>(),
        size_of::<core::result::Result<u32, String>>(),
        // Scalar/control locals: four entry argument groups, counts/loop
        // offsets, one step descriptor, transfer counters and two masks.
        4 * size_of::<(&DeviceSession, &Engine, SpendLimits, &Run)>(),
        12 * size_of::<usize>(), 4 * size_of::<u64>(), 4 * size_of::<u32>(),
        size_of::<&layout::Step>(),
        // Engine::fence is the maintained drain owner, including its Queue.
        size_of::<super::super::super::super::QueueFence>(),
    ])
}
