//! Candidate block-proof foundations and bounded execution engine.
//! NOT a recursive block prover or verifier.
//!
//! There is deliberately no aggregate acceptance API: a fixed-geometry recursive AIR
//! must first prove and verify at full strength through depth six. Native commitment
//! calculations and leaf proofs do not satisfy that gate. Historical v1 is unchanged.

mod challenger;
pub mod codec;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) mod worker_memory;
#[cfg(all(feature = "gpu-metal", target_os = "macos"))]
pub(crate) use crate::metal_compute as compute;
#[cfg(feature = "gpu")]
pub(crate) use ocl as compute;
pub mod commitment;
#[cfg(feature = "stream")]
pub mod coset_workspace;
pub mod execution;
pub mod feasibility;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub mod gpu_hash;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod gpu_quotient_prover;
#[cfg(feature = "gpu")]
mod gpu_startup;
#[cfg(feature = "stream")]
pub mod heap_dft;
#[cfg(feature = "block-v2-host")]
pub mod host;
pub mod leaf;
#[cfg(feature = "gpu")]
pub(crate) mod legacy_wallet;
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
pub(crate) mod lookup_program;
pub mod machine;
#[cfg(feature = "gpu")]
pub(crate) mod native_gpu;
#[cfg(all(feature = "gpu", feature = "stream", target_os = "linux"))]
pub(crate) mod native_public_gpu;
#[cfg(feature = "stream")]
pub mod normalization_workspace;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod opening_pcs;
pub mod pcs_field;
pub mod perf;
pub mod profile;
pub mod quotient_pcs;
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
pub(crate) mod quotient_program;
mod randomness;
pub mod recursive;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod resident_pcs;
mod statements;
pub mod typed_fixture;
pub mod typed_leaf;
pub mod typed_recursive;
#[cfg(feature = "gpu")]
mod wallet_output;
#[cfg(feature = "gpu")]
pub(crate) mod wallet_worker;

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod batched_fri;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod extension_mmcs;
