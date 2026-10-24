//! Experimental, single-table execution engine for the bounded recursive verifier.
//!
//! A proof of execution is NOT a recursive proof unless the registered program
//! implements every inner-verifier check. No production ABI reaches this module.

mod air;
pub mod analysis;
pub mod backend;
pub mod circuit;
pub(crate) mod compiler_constants;
mod fingerprint;
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) mod gpu_backend;
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
pub(crate) mod gpu_program;
pub mod merkle;
pub mod program;
pub mod pq_bytes;
pub mod pq_modular;
pub mod programs;
pub(crate) mod symbolic;
pub mod transcript;
pub mod typed_finalizer;
pub mod typed_pairs;
pub mod typed_programs;
pub mod usage;
pub mod verifier;

pub use air::{MachineAir, WIDTH};
pub use program::{ExecutionError, Program, ProgramBuilder, Wire};
