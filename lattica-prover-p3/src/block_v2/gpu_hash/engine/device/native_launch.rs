//! Disconnected Linux/OpenCL candidate for the seven raw witness kernels.
//!
//! No parent module hook or production caller is installed. This owns only a
//! synchronous launch scope, not constructor admission or retained graph state.
#![cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]

use super::{random::SecretAllocation, Engine};
use crate::block_v2::native_gpu::operations_arithmetic::ArithmeticOperationSpec;
use core::{fmt, mem::size_of};
use ocl::ffi;

mod driver;
mod geometry;
#[cfg(test)]
mod gpu_tests;
#[cfg(test)]
mod tests;

use geometry::{ArithmeticShape, CryptoShape};
pub(super) use geometry::{CryptoKind, NodeKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kernel {
    Arithmetic,
    AesSboxes,
    Aes,
    Shake,
    Uniform,
    Sparse,
    Node,
}
impl Kernel {
    fn name(self) -> &'static core::ffi::CStr {
        match self {
            Self::Arithmetic => c"pq_graph_arithmetic",
            Self::AesSboxes => c"pq_raw_aes_sboxes",
            Self::Aes => c"pq_raw_aes",
            Self::Shake => c"pq_raw_shake",
            Self::Uniform => c"pq_raw_uniform",
            Self::Sparse => c"pq_raw_sparse",
            Self::Node => c"pq_operation_commit_node",
        }
    }
    fn label(self) -> &'static str {
        // All seven literals are ASCII and contain no interior NUL.
        self.name().to_str().expect("static ASCII kernel name")
    }
    fn arguments(self) -> u32 {
        if self == Self::Node {
            8
        } else {
            4
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Shape,
    Queue,
    Create,
    Signature,
    Upload,
    Clear,
    Argument,
    Enqueue,
    FinishCopy,
    FinishCompute,
    EventStatus,
    ProfileStart,
    ProfileEnd,
    ReleaseEvent,
    ReleaseKernel,
}

/// Original signed driver status plus fixed source context. No queried names,
/// compiler logs, String, or allocation-sized-by-driver data are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Failure {
    kernel: Kernel,
    phase: Phase,
    argument: u8,
    status: i32,
}
impl Failure {
    fn at(kernel: Kernel, phase: Phase, argument: u8, status: i32) -> Self {
        Self {
            kernel,
            phase,
            argument,
            status,
        }
    }
    fn shape(kernel: Kernel) -> Self {
        Self::at(kernel, Phase::Shape, 0, 0)
    }
    pub(super) fn diagnostic(self) -> Diagnostic {
        use fmt::Write;
        let mut text = Diagnostic {
            bytes: [0; 192],
            len: 0,
        };
        if write!(
            text,
            "native_launch kernel={} phase={:?} argument={} status={}",
            self.kernel.label(),
            self.phase,
            self.argument,
            self.status,
        )
        .is_err()
        {
            // A future longer enum label cannot cause allocation or truncation
            // of an uncontrolled string. Preserve an explicit bounded failure.
            text.len = 0;
            let _ = text.write_str("native_launch diagnostic capacity exceeded");
        }
        text
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.diagnostic(), f)
    }
}

pub(super) struct Diagnostic {
    bytes: [u8; 192],
    len: usize,
}
impl fmt::Write for Diagnostic {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(core::str::from_utf8(&self.bytes[..self.len]).map_err(|_| fmt::Error)?)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Timing {
    pub(super) label: &'static str,
    pub(super) nanoseconds: u64,
}
#[derive(Debug)]
pub(super) struct Completion {
    // Only completed, successfully profiled events occur here. The caller still
    // has to attach observations to its existing Run; this is not a proof receipt.
    pub(super) kernels: [Option<Timing>; 2],
}

/// Actual owners, not cloned OpenCL handles. Their private creation paths own
/// the allocation leases and scrub-on-drop behavior used by the existing engine.
pub(super) struct ArithmeticBuffers<'a> {
    pub(super) input: &'a SecretAllocation,
    pub(super) metadata: &'a SecretAllocation,
    pub(super) output: &'a SecretAllocation,
    pub(super) status: &'a SecretAllocation,
}
pub(super) struct CryptoBuffers<'a> {
    pub(super) input: &'a SecretAllocation,
    pub(super) geometry: &'a SecretAllocation,
    pub(super) scratch: &'a SecretAllocation,
    pub(super) output: &'a SecretAllocation,
}
pub(super) struct NodeBuffers<'a> {
    pub(super) input: &'a SecretAllocation,
    pub(super) output: &'a SecretAllocation,
}

// Scope borrows this owner until both queues drain and all kernel/event handles
// are released. The engine borrow also holds its actual JobLease and constants.
struct Owners<'engine, 'buffers> {
    engine: &'engine mut Engine,
    buffers: [Option<&'buffers SecretAllocation>; 4],
}
impl Owners<'_, '_> {
    fn handles(&self) -> driver::Handles {
        driver::Handles {
            program: self.engine.pq.program().as_core().as_ptr(),
            compute: self.engine.pq.queue().as_core().as_ptr(),
            copy: self.engine.copy_queue.as_core().as_ptr(),
        }
    }
    fn check(&self, kernel: Kernel, words: &[usize]) -> Result<[ffi::cl_mem; 4], Failure> {
        let queue = self.handles().compute;
        if words.len() > 4 {
            return Err(Failure::shape(kernel));
        }
        let mut handles = [core::ptr::null_mut(); 4];
        for (index, &expected) in words.iter().enumerate() {
            let buffer = self.buffers[index].ok_or(Failure::shape(kernel))?.buffer();
            if expected == 0
                || buffer.len() != expected
                || buffer.offset().is_some()
                || buffer.default_queue().map(|q| q.as_core().as_ptr()) != Some(queue)
            {
                return Err(Failure::at(kernel, Phase::Shape, index as u8, 0));
            }
            let handle = buffer.as_core().as_ptr();
            if handle.is_null() || handles[..index].contains(&handle) {
                return Err(Failure::at(kernel, Phase::Shape, index as u8, 0));
            }
            handles[index] = handle;
        }
        if self.buffers[words.len()..].iter().any(Option::is_some) {
            return Err(Failure::shape(kernel));
        }
        Ok(handles)
    }
}

pub(super) fn arithmetic(
    engine: &mut Engine,
    spec: &ArithmeticOperationSpec,
    input: &[u64],
    buffers: ArithmeticBuffers<'_>,
) -> Result<Completion, Failure> {
    let shape = ArithmeticShape::check(spec)?;
    if input.len() != shape.words[0] {
        return Err(Failure::shape(Kernel::Arithmetic));
    }
    let owners = Owners {
        engine,
        buffers: [
            Some(buffers.input),
            Some(buffers.metadata),
            Some(buffers.output),
            Some(buffers.status),
        ],
    };
    let handles = owners.check(Kernel::Arithmetic, &shape.words)?;
    let mut api = driver::OpenCl;
    let mut scope = driver::Scope::new(&owners, owners.handles(), &mut api, Kernel::Arithmetic)?;
    scope.upload(Kernel::Arithmetic, handles[0], input)?;
    scope.upload(Kernel::Arithmetic, handles[1], &spec.metadata)?;
    scope.clear(Kernel::Arithmetic, handles[3], shape.words[3])?;
    scope.launch(
        Kernel::Arithmetic,
        &handles.map(driver::Argument::Memory),
        shape.work_items,
    )?;
    scope.complete()
}

pub(super) fn crypto(
    engine: &mut Engine,
    kind: CryptoKind,
    input: &[u8],
    output_count: usize,
    buffers: CryptoBuffers<'_>,
) -> Result<Completion, Failure> {
    let shape = CryptoShape::new(kind, input.len(), output_count)?;
    let primary = shape.launches[0].0;
    let owners = Owners {
        engine,
        buffers: [
            Some(buffers.input),
            Some(buffers.geometry),
            Some(buffers.scratch),
            Some(buffers.output),
        ],
    };
    let handles = owners.check(primary, &shape.words)?;
    let mut api = driver::OpenCl;
    // Declare host staging before Scope: unwinding/error cleanup must drain
    // both queues before these borrowed upload words are scrubbed.
    let mut staging = ByteStaging([0; 2048]);
    let mut scope = driver::Scope::new(&owners, owners.handles(), &mut api, primary)?;
    // Upload exactly the borrowed bytes as u64 words; no caller-supplied device
    // geometry is trusted. The stack staging owner is scrubbed on every return.
    for (chunk_index, chunk) in input.chunks(staging.0.len()).enumerate() {
        for (word, &byte) in staging.0.iter_mut().zip(chunk) {
            *word = u64::from(byte);
        }
        scope.upload_at(
            primary,
            handles[0],
            chunk_index * 2048,
            &staging.0[..chunk.len()],
        )?;
    }
    scope.upload(primary, handles[1], &shape.geometry)?;
    scope.clear(primary, handles[3], shape.words[3])?;
    for &(kernel, work) in &shape.launches[..shape.launch_count] {
        scope.launch(kernel, &handles.map(driver::Argument::Memory), work)?;
    }
    scope.complete()
}

struct ByteStaging([u64; 2048]);
impl Drop for ByteStaging {
    fn drop(&mut self) {
        for word in &mut self.0 {
            // SAFETY: this stack storage remains exclusively owned here.
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

pub(super) fn node(
    engine: &mut Engine,
    kind: NodeKind,
    input: &[u64],
    buffers: NodeBuffers<'_>,
) -> Result<Completion, Failure> {
    let (tag, modulus, words) = kind.fields();
    if input.len() != words {
        return Err(Failure::shape(Kernel::Node));
    }
    let owners = Owners {
        engine,
        buffers: [Some(buffers.input), Some(buffers.output), None, None],
    };
    let handles = owners.check(Kernel::Node, &[words, 5])?;
    use p3_goldilocks::{
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL as F,
        GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL as I, GOLDILOCKS_POSEIDON2_RC_8_INTERNAL as P,
        MATRIX_DIAG_8_GOLDILOCKS as D,
    };
    let expected = [I.len() * 8, P.len(), F.len() * 8, D.len()];
    let mut constants = [core::ptr::null_mut(); 4];
    for (index, constant) in owners.engine.constants.iter().enumerate() {
        let buffer = &constant.buffer;
        let handle = buffer.as_core().as_ptr();
        if buffer.len() != expected[index]
            || buffer.offset().is_some()
            || buffer.default_queue().map(|q| q.as_core().as_ptr())
                != Some(owners.handles().compute)
            || handle.is_null()
            || handles[..2].contains(&handle)
            || constants[..index].contains(&handle)
        {
            return Err(Failure::at(Kernel::Node, Phase::Shape, index as u8 + 4, 0));
        }
        constants[index] = handle;
    }
    let mut api = driver::OpenCl;
    let mut scope = driver::Scope::new(&owners, owners.handles(), &mut api, Kernel::Node)?;
    scope.upload(Kernel::Node, handles[0], input)?;
    use driver::Argument::{Memory, Uint, Ulong};
    let args = [
        Memory(handles[0]),
        Uint(tag),
        Ulong(modulus),
        Memory(handles[1]),
        Memory(constants[0]),
        Memory(constants[1]),
        Memory(constants[2]),
        Memory(constants[3]),
    ];
    scope.launch(Kernel::Node, &args, 1)?;
    scope.complete()
}
