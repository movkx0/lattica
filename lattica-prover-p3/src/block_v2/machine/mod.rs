//! Experimental, single-table execution engine for the bounded recursive verifier.
//!
//! A proof of execution is NOT a recursive proof unless the registered program
//! implements every inner-verifier check. No production ABI reaches this module.

mod air;
pub mod analysis;
pub mod backend;
pub mod circuit;
mod fingerprint;
pub mod merkle;
pub mod program;
pub mod programs;
pub mod transcript;
pub mod typed_programs;
pub mod usage;
pub mod verifier;

pub use air::{MachineAir, WIDTH};
pub use program::{ExecutionError, Program, ProgramBuilder, Wire};
