//! Candidate block-proof foundations and bounded execution engine.
//! NOT a recursive block prover or verifier.
//!
//! There is deliberately no aggregate acceptance API: a fixed-geometry recursive AIR
//! must first prove and verify at full strength through depth six. Native commitment
//! calculations and leaf proofs do not satisfy that gate. Historical v1 is unchanged.

pub mod codec;
#[cfg(all(feature = "gpu-metal", target_os = "macos"))]
pub(crate) mod apple_memory;
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
#[cfg(feature = "stream")]
pub mod heap_dft;
pub mod leaf;
#[cfg(feature = "block-v2-host")]
pub mod host;
pub mod typed_fixture;
pub mod machine;
#[cfg(feature = "stream")]
pub mod normalization_workspace;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod opening_pcs;
pub mod perf;
pub mod profile;
pub mod quotient_pcs;
pub mod recursive;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod resident_pcs;
pub mod typed_leaf;
pub mod typed_recursive;

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
mod batched_fri;
