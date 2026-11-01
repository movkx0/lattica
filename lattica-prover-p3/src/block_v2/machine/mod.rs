//! Experimental, single-table execution engine for the bounded recursive verifier.
//!
//! A proof of execution is NOT a recursive proof unless the registered program
//! implements every inner-verifier check. No production ABI reaches this module.

mod air;
pub mod analysis;
pub mod backend;
pub mod circuit;
pub(crate) mod compiler_constants;
#[doc(hidden)]
pub mod cpu_queue;
mod fingerprint;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) mod gpu_backend;
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
pub(crate) mod gpu_program;
pub mod merkle;
pub mod pq_bytes;
pub mod pq_modular;
pub mod program;
pub mod programs;
pub(crate) mod symbolic;
pub mod transcript;
pub mod typed_finalizer;
pub mod typed_pairs;
pub mod typed_programs;
pub mod usage;
pub mod verifier;

pub use air::{MachineAir, WIDTH};
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream"
))]
pub use gpu_backend::resources::admission::aes_pcs::{NativeAesPcsFootprint, NativeAesPcsPlan};
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::graph_source_pcs::{
    NativeGraphSourcePcsFootprint, NativeGraphSourcePcsPlan,
};
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream"
))]
pub use gpu_backend::resources::admission::shake_pcs::{
    NativeShakePcsFootprint, NativeShakePcsPlan,
};

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub use gpu_backend::resources::admission::outer_diagnostic::{
    inspect_registered_gpu_outer, RegisteredGpuOuterFootprint, RegisteredGpuOuterHostBounds,
};
#[cfg(feature = "gpu")]
pub use gpu_backend::resources::admission::outer_producer::source::{
    OuterSourceEnvelope, OuterSourceFootprint, OuterSourceShape, PreissuedOuterBackend,
};
#[cfg(feature = "gpu")]
pub use gpu_backend::resources::admission::outer_producer::{
    OuterBackendAdmission, OuterBackendFootprint, OuterBackendPlan,
};
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub use gpu_backend::resources::admission::output::{
    inspect_registered_gpu_output, RegisteredGpuOutputFootprint,
};
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub use gpu_backend::resources::admission::{
    RegisteredGpuAdmission, RegisteredGpuFootprint, RegisteredGpuLimits, RegisteredGpuMemoryPlan,
    REGISTERED_GPU_CALLER_HOST_BYTES,
};
pub use program::{ExecutionError, Program, ProgramBuilder, Wire};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::transcript_pcs::{
    NativeTranscriptPcsFootprint, NativeTranscriptPcsPlan,
};
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::uniform_pcs::{
    NativeUniformPcsFootprint, NativeUniformPcsPlan,
};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::affine_pcs::{
    NativeAffinePcsFootprint, NativeAffinePcsPlan,
};
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::sparse_pcs::{
    NativeSparsePcsFootprint, NativeSparsePcsPlan,
};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::ntt_pcs::{NativeNttPcsFootprint, NativeNttPcsPlan};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::mul_pcs::{NativeMulPcsFootprint, NativeMulPcsPlan};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::g_bound_pcs::{
    NativeGBoundPcsFootprint, NativeGBoundPcsPlan,
};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::permutation_pcs::{
    NativePermutationPcsFootprint, NativePermutationPcsPlan,
};

#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream",
    feature = "ringct-research-quota"
))]
pub use gpu_backend::resources::admission::linear_map_pcs::{
    NativeLinearMapPcsFootprint, NativeLinearMapPcsPlan,
};
