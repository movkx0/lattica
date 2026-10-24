//! Compilers for the pinned candidate proof protocols. Proof values are witness
//! inputs; all acceptance equalities are instructions in the execution program.
pub mod batch;
pub mod expressions;
pub mod pcs;
pub(crate) mod periodic;
pub mod template;
pub mod uni;

use super::circuit::Extension;
use super::merkle::Digest;
use super::program::ScopedProgramBuilder as ProgramBuilder;
use super::program::Val;
use super::Wire;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileError {
    /// An explicit sticky builder TooLarge admission refusal, never a malformed
    /// proof, unsupported relation or backend failure. No fallback is performed.
    ResourceAdmission(&'static str),
    Shape(&'static str),
    Unsupported(&'static str),
    Backend(String),
}

impl CompileError {
    /// Preserve typed builder admission at its original source. Future or
    /// non-resource builder errors retain the previous hard Shape failure.
    pub(crate) fn from_builder_admission(
        error: super::program::ExecutionError,
        reason: &'static str,
    ) -> Self {
        match error {
            super::program::ExecutionError::TooLarge => Self::ResourceAdmission(reason),
            _ => Self::Shape(reason),
        }
    }
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for CompileError {}

pub use super::program::ProofInputs;

pub(crate) fn ext_base(b: &mut ProgramBuilder, value: Wire) -> Extension {
    use p3_field::PrimeCharacteristicRing;
    let zero = b.constant(Val::ZERO);
    [value, zero, zero]
}

pub(crate) fn observe_cap(
    t: &mut super::transcript::Transcript,
    b: &mut ProgramBuilder,
    cap: &[Digest],
) {
    for digest in cap {
        t.observe_slice(b, digest);
    }
}

#[cfg(test)]
mod resource_admission_tests;
