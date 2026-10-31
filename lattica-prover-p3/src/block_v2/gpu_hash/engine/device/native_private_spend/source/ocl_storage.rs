//! Rust backing of the fixed ocl 0.19.7 builder path. Driver/compiler internals
//! remain in the existing 4 GiB context reserve. See BOUNDS.md for the source
//! inventory and allocation canaries; this is not a new allowance.
use super::*;
use core::any::TypeId;
use std::{ffi::CString, path::PathBuf};

const ARGUMENTS: usize = 9;
const BUILDER_CAPACITY: usize = 16;
const RETAINED_KERNELS: usize = 4;
const PROGRAM_CAPACITY: usize = 64;
const REPLY: usize = 64 << 10;

// The private ocl ArgValKeeper has these three payload variants. repr(C)
// retains a separate discriminant and therefore bounds its Rust enum layout
// on this pinned 64-bit target; Option<TypeId> is the actual public type.
#[allow(dead_code)]
#[repr(C)]
enum ArgumentBacking<'a> {
    Shared(ocl::core::ArgVal<'a>),
    OwnedPrm(Vec<u8>),
    OwnedMem(ocl::core::Mem),
}

pub(super) fn requested_bytes() -> Result<usize> {
    if ocl::core::bounded_info::MAX_REPLY_BYTES != REPLY
        || ocl::core::bounded_info::MAX_KERNEL_ARGUMENTS != 128
        || ocl::core::bounded_info::MAX_DEVICES != PROGRAM_CAPACITY
    { return Err(NativeSpendSourceError::Configuration); }
    sum([program_bytes()?, kernel_bytes()?, diagnostic_bytes()?,
        size_of::<ocl::core::DeviceInfoResult>(),
        size_of::<ocl::core::KernelArgInfoResult>(),
        size_of::<ocl::core::KernelInfoResult>(),
        size_of::<ocl::Error>(), size_of::<ocl::core::Error>()])
}

pub(super) fn program_bytes() -> Result<usize> {
    use ocl::builders::{BuildOpt, DeviceSpecifier, ProgramBuilder};
    let source = add(pins::BUNDLE.len(), 1)?;
    // IncludeRaw String, cloned CString construction input, includes CString,
    // copied source-list CString, and a moving shrink/conversion allocation.
    // Charge all five simultaneously instead of relying on move elision.
    let source_copies = mul(5, source)?;
    // The builder, source list, includes and EOF constructors each request a
    // 64-entry Vec. Empty source-file history still requests its HashSet:
    // with_capacity(64) uses 128 buckets plus one 16-byte control group.
    let descriptor_vectors = sum([
        mul(PROGRAM_CAPACITY, size_of::<BuildOpt>())?,
        mul(3 * PROGRAM_CAPACITY + 2 + 1 + 3, size_of::<CString>())?,
        mul(PROGRAM_CAPACITY, size_of::<String>())?,
        mul(128, add(size_of::<PathBuf>(), size_of::<usize>())?)?, 16,
        // Device selector, selected-device copy, cl source pointer/length
        // lists, and core program/device-version scratch are independent.
        mul(PROGRAM_CAPACITY, size_of::<ocl::Device>())?,
        mul(PROGRAM_CAPACITY, size_of::<ocl::core::DeviceId>())?,
        mul(2 * PROGRAM_CAPACITY, size_of::<usize>())?,
        mul(PROGRAM_CAPACITY, size_of::<ocl::core::OpenclVersion>())?,
    ])?;
    let options_and_newlines = sum([
        mul(4, add("-cl-std=CL1.2".len(), 1)?)?,
        // Source-list clones of its two newline CStrings and conversions.
        8 * 2,
    ])?;
    sum([source_copies, descriptor_vectors, options_and_newlines,
        size_of::<ProgramBuilder<'static>>(), size_of::<DeviceSpecifier>(),
        size_of::<ocl::Program>(), size_of::<ocl::core::Program>(),
        3 * size_of::<Vec<CString>>(), size_of::<Vec<String>>(),
        size_of::<std::collections::HashSet<PathBuf>>(),
        size_of::<Vec<ocl::Device>>(), size_of::<Vec<usize>>()])
}

pub(super) fn kernel_bytes() -> Result<usize> {
    // At most three preparation kernels survive while the final step kernel
    // is constructed. One builder therefore overlaps four returned kernels.
    // <=4 retained Mem args fit a single 11-key BTree leaf. Charge its full
    // internal-node upper bound to each map (builder + every live Kernel).
    let map_node = sum([4 * size_of::<usize>(),
        mul(11, size_of::<(u32, ocl::core::Mem)>())?,
        mul(12, size_of::<usize>())?])?;
    let maps = mul(RETAINED_KERNELS + 1, map_node)?;
    let argument_slots = mul(BUILDER_CAPACITY,
        size_of::<(ArgumentBacking<'static>, Option<TypeId>)>())?;
    let scalar_copies = mul(ARGUMENTS, size_of::<u64>())?;
    // ArgType consists of BaseType, Cardinality and bool. Three complete
    // machine words bound those private enum fields on the locked target.
    let argument_types = mul(RETAINED_KERNELS + 1,
        mul(ARGUMENTS, size_of::<[usize; 3]>())?)?;
    let longest = STEPS.iter().map(|step| step.name.len()).chain([
        "pq_spend_parallel_admit".len(), "pq_spend_parallel_polynomials".len(),
        "pq_spend_parallel_early_rows".len(),
    ]).max().ok_or(NativeSpendSourceError::Source)?;
    sum([maps, argument_slots, scalar_copies, argument_types,
        mul(2, add(longest, 1)?)?,
        size_of::<ocl::builders::KernelBuilder<'static>>(),
        size_of::<ocl::core::Kernel>(),
        size_of::<core::result::Result<ocl::Kernel, ocl::Error>>()])
}

fn diagnostic_bytes() -> Result<usize> {
    // Sequential bounded-info replies, two argument-type/name replies on a
    // mismatch, retained original error, and formatting during queue/fence
    // cleanup. Eight independent reply slabs follow the maintained bounded
    // OCL error inventory. Fixed-format text is bounded by the complete two
    // native caller sources plus 128 decimal u64 arguments (20 chars each).
    sum([mul(8, REPLY)?, pins::CONTROLLER.len(), pins::DISPATCH.len(),
        128 * 20, 8 * size_of::<String>()])
}
