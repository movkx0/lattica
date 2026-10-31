//! Exact native source inputs, borrowed from the original prepared graph owner.
//! This value is data only. A closed research operation must establish its
//! exact source membership and retain that owner through native verification.
use super::super::graph_source_preparation::GraphSourceKind;

pub enum GraphSourceInput<'a> {
    Statement {
        bytes: &'a [u8; 202_848],
        setup_seed: &'a [u8; 32],
    },
    PrivateProof {
        polynomials: &'a [[i64; 256]; 91],
        alpha: &'a [u8; 32],
    },
}

impl GraphSourceInput<'_> {
    pub fn kind(&self) -> GraphSourceKind {
        match self {
            Self::Statement { .. } => GraphSourceKind::Statement,
            Self::PrivateProof { .. } => GraphSourceKind::PrivateProof,
        }
    }
}
