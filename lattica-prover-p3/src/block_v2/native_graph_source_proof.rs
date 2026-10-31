//! Data-only schemas shared with the isolated Statement/PrivateProof sources.
//! These types grant no verification, transaction acceptance or dispatch right.
use super::profile::Config;
use crate::config::Val;

pub const STATEMENT_PUBLIC_VALUES: usize = 8;
pub const PRIVATE_PROOF_PUBLIC_VALUES: usize = 4;

pub struct NativeStatementProof {
    pub public_values: [Val; STATEMENT_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}

pub struct NativePrivateProof {
    pub public_values: [Val; PRIVATE_PROOF_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}

/// Neither variant is cloneable. The retained output owner exposes borrows.
pub enum NativeGraphSourceProof {
    Statement(NativeStatementProof),
    PrivateProof(NativePrivateProof),
}

impl NativeGraphSourceProof {
    pub fn public_values(&self) -> &[Val] {
        match self {
            Self::Statement(proof) => &proof.public_values,
            Self::PrivateProof(proof) => &proof.public_values,
        }
    }

    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> {
        match self {
            Self::Statement(proof) => &proof.proof,
            Self::PrivateProof(proof) => &proof.proof,
        }
    }

    pub fn statement(&self) -> Option<&NativeStatementProof> {
        match self { Self::Statement(proof) => Some(proof), _ => None }
    }

    pub fn private_proof(&self) -> Option<&NativePrivateProof> {
        match self { Self::PrivateProof(proof) => Some(proof), _ => None }
    }
}
