//! Additive Rust/OpenCL wrapper census for the fixed registered outer entry.
//!
//! This is pure source arithmetic, not a dispatch permission or measured peak.
//! Its caller must reserve the result before startup and retain that original
//! claim through backend and runtime retirement. Startup has a separate owner;
//! none of its raw-kernel or source allowance is subtracted here.
use super::super::Error;
use crate::block_v2::quotient_program::specialize::{
    BLOCK, MAX_INSTRUCTIONS, MAX_REGISTERS, MAX_SOURCE_BYTES,
};
use core::mem::size_of;

// The fixed outer path has <=16 supplied arguments, including the two NTT
// local-memory descriptors. No named arguments or retained Kernel cache occur.
// Build temporaries die in their statement/loop body, including error paths.
// Charge two complete pairs despite the normal sequential one-pair schedule.
const SUPPLIED_ARGUMENTS: usize = 16;
const LIVE_BUILDER_KERNEL_PAIRS: usize = 2;
const PER_BUILDER_KERNEL_PAIR: usize = 16 * 1024;
// ProgramBuilder's 64-entry option/source vectors, empty 64-slot path table,
// one-device selector and pointer vectors, compiler option and all inline
// Program/Compiled/core-Kernel handles. The specialization retains one Program.
const PROGRAM_DESCRIPTORS: usize = 64 * 1024;
const REPLY_BYTES: usize = 64 * 1024;
// Sequential bounded info/build-log responses plus original errors and their
// formatting. This claim does not rely on truncating an already-created String.
const METADATA_AND_ERROR_BACKING: usize = 8 * REPLY_BYTES + 4096;
const SAMPLER_COMMAND_BACKING: usize = 4096;
const SAMPLER_READ_BUFFER: usize = 8193;
const SOURCE_SMALL_FORMATTING: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedOuterOclStorage {
    required_host_bytes: usize,
}

fn source_copy_requests(source: usize) -> Option<usize> {
    // Unlike the startup program's moved String, specialized::prepare passes
    // &source. Count original source, builder clone, CString's source clone,
    // terminator-growth request, and final CString clone separately. This
    // bounds cumulative source requests, hence also their overlapping backing.
    source.checked_add(1)?.checked_mul(5)
}

fn source_liveness_bytes(instructions: usize, registers: usize) -> Option<usize> {
    // specialize.rs stores one [u64;8] at each 64-instruction boundary.
    if BLOCK != 64 || registers > 512 {
        return None;
    }
    instructions
        .checked_add(BLOCK - 1)?
        .checked_div(BLOCK)?
        .checked_add(1)?
        .checked_mul(size_of::<[u64; 8]>())
}

impl FixedOuterOclStorage {
    /// Applies only to the pinned registered-machine GPU path, one fresh
    /// runtime, one quotient specialization, no Kernel cache/named arguments,
    /// and default tuning. The consuming backend and PendingRuntime enforce
    /// that fixed execution; this value supplies no such authority itself.
    ///
    /// Native SHAKE, caller-selected kernels, note dispatch and arbitrary
    /// Programs need their own complete phase admission. Opaque compiler,
    /// driver, device code and <=128 MiB resident private backing remain under
    /// the existing 4 GiB context reserve, never this host-only claim.
    pub fn fixed() -> Result<Self, Error> {
        if size_of::<usize>() != 8
            || MAX_INSTRUCTIONS != 8192
            || MAX_REGISTERS != 512
            || MAX_SOURCE_BYTES != 2 << 20
            || ocl::core::bounded_info::MAX_REPLY_BYTES != REPLY_BYTES
            || ocl::core::bounded_info::MAX_DEVICES != 64
            || ocl::core::bounded_info::MAX_KERNEL_ARGUMENTS != 128
            || SUPPLIED_ARGUMENTS > ocl::core::bounded_info::MAX_KERNEL_ARGUMENTS
        {
            return Err(Error::ComponentRejected);
        }
        let sources = source_copy_requests(MAX_SOURCE_BYTES).ok_or(Error::ComponentRejected)?;
        let liveness = source_liveness_bytes(MAX_INSTRUCTIONS, MAX_REGISTERS)
            .ok_or(Error::ComponentRejected)?;
        let wrappers = LIVE_BUILDER_KERNEL_PAIRS
            .checked_mul(PER_BUILDER_KERNEL_PAIR)
            .ok_or(Error::ComponentRejected)?;
        let required_host_bytes = [
            sources,
            liveness,
            SOURCE_SMALL_FORMATTING,
            PROGRAM_DESCRIPTORS,
            METADATA_AND_ERROR_BACKING,
            wrappers,
            SAMPLER_COMMAND_BACKING,
            SAMPLER_READ_BUFFER,
            size_of::<Self>(),
        ]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or(Error::ComponentRejected)?;
        Ok(Self {
            required_host_bytes,
        })
    }

    pub fn required_host_bytes(self) -> usize {
        self.required_host_bytes
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;
