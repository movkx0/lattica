//! Candidate block-proof foundations and bounded execution engine.
//! NOT a recursive block prover or verifier.
//!
//! There is deliberately no aggregate acceptance API: a fixed-geometry recursive AIR
//! must first prove and verify at full strength through depth six. Native commitment
//! calculations and leaf proofs do not satisfy that gate. Historical v1 is unchanged.

pub mod codec;
pub mod commitment;
pub mod execution;
#[cfg(feature = "stream")]
pub mod coset_workspace;
pub mod feasibility;
#[cfg(feature = "gpu")]
pub mod gpu_hash;
#[cfg(feature = "stream")]
pub mod heap_dft;
pub mod leaf;
pub mod machine;
#[cfg(feature = "stream")]
pub mod normalization_workspace;
pub mod perf;
pub mod profile;
pub mod quotient_pcs;
#[cfg(feature = "gpu")]
mod opening_pcs;
pub mod recursive;
#[cfg(feature = "gpu")]
mod resident_pcs;
