//! Independent pure-Rust public verifier for the fixed patched MatRiCT+ n10
//! experiment. This module ports the author verifier, not a new construction.
//! It is a differential oracle for a constrained verifier; executing it is not
//! itself a recursive proof or a substitute for circuit constraints.

pub(crate) mod arithmetic;
pub(crate) mod constants;
#[cfg(feature = "recursive")]
pub mod committed_backend;
#[cfg(feature = "recursive")]
pub mod constraints;
#[cfg(feature = "recursive")]
pub mod constraints_crypto;
#[cfg(feature = "recursive")]
pub mod constraints_decode;
#[cfg(feature = "recursive")]
pub mod constraints_ntt;
#[cfg(feature = "recursive")]
pub mod constraints_poly;
mod decode;
pub mod generic;
mod native_backend;
pub(crate) mod primitives;
mod relation;

pub use decode::{Account, Proof, Statement};

pub const Q: u64 = 167_770_241;
pub const QHAT: u64 = 3_489_661_057;
pub const D: usize = 256;
pub type Poly = [u64; D];
pub type SignedPoly = [i64; D];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyError {
    Length,
    NonCanonical,
    DuplicateSerial,
    SamplingExhausted,
    Rejected,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Length => "incorrect fixed-profile packet length",
            Self::NonCanonical => "noncanonical MatRiCT+ coefficient",
            Self::DuplicateSerial => "duplicate MatRiCT+ serial",
            Self::Rejected => "MatRiCT+ verifier relation rejected",
            Self::SamplingExhausted => {
                "fixed-profile rejection sampling exhausted its bounded stream"
            }
        })
    }
}
impl std::error::Error for VerifyError {}

pub fn verify(context: &[u8; 32], statement: &[u8], proof: &[u8]) -> Result<bool, VerifyError> {
    let statement = Statement::decode(statement)?;
    let proof = Proof::decode(proof)?;
    relation::verify(context, &statement, &proof)
}

pub fn verify_generic(
    context: &[u8; 32],
    statement: &[u8],
    proof: &[u8],
) -> Result<bool, VerifyError> {
    let statement = Statement::decode(statement)?;
    let proof = Proof::decode(proof)?;
    match generic::verify_relation(
        &mut native_backend::NativeBackend,
        context,
        &native_backend::statement(&statement),
        &native_backend::proof(&proof),
    ) {
        Ok(()) => Ok(true),
        Err(VerifyError::Rejected) => Ok(false),
        Err(error) => Err(error),
    }
}
