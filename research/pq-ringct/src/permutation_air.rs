//! Fixed MatRiCT automorphism and inverse sparse-challenge permutation.
//!
//! Every coefficient in an immutable 256-field bank is bounded and hashed into
//! the input root before fixed reads establish the output. There is no native
//! lookup acceptance or unproved permutation argument.
use crate::{
    ntt_air::constraints::canonical_range,
    rust_verify::{
        arithmetic,
        constants::{AUT_Q, OMEGA_Q},
        constraints_ntt::{POLYNOMIAL_DOMAIN, SIGNED_POLYNOMIAL_DOMAIN},
        D, Q,
    },
    shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

mod constraints;
#[cfg(feature = "opencl")]
mod gpu;
pub mod graph;
mod join;
#[cfg(test)]
mod tests;
mod witness;
pub use join::{PendingPermutation, PermutationProof, RegisteredPermutationAir};
pub use witness::{PermutationInput, PermutationWitness};

pub const HEIGHT: usize = 256;
pub const PUBLIC_VALUES: usize = 8;
const BANK: usize = 0;
const READ: usize = 256;
const SIGN: usize = 260;
const ACC: usize = 264;
const RANGES: usize = 272;
const SELECT_INPUT: usize = 0;
const SELECT_OUTPUT: usize = 64;
const HASH_INPUT: usize = 128;
const HASH_OUTPUT: usize = 129;
const FACTOR: usize = 130;
const PERIODIC_COLUMNS: usize = 134;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermutationKind {
    AutomorphismQ,
    InverseChallenge,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Descriptor,
    NonCanonical,
}
#[derive(Clone, Debug)]
pub struct PermutationAir {
    kind: PermutationKind,
}
impl PermutationAir {
    pub fn new(kind: PermutationKind) -> Self {
        Self { kind }
    }
    pub fn kind(&self) -> PermutationKind {
        self.kind
    }
    fn bits(&self) -> usize {
        if self.kind == PermutationKind::AutomorphismQ {
            28
        } else {
            4
        }
    }
    fn range_width(&self) -> usize {
        1 + self.bits() + self.bits() / 4
    }
    fn range(&self, lane: usize) -> usize {
        RANGES + lane * self.range_width()
    }
    fn quotient(&self, lane: usize) -> usize {
        self.range(4) + lane * self.range_width()
    }
    fn poseidon(&self) -> usize {
        if self.kind == PermutationKind::AutomorphismQ {
            self.quotient(4)
        } else {
            self.range(4)
        }
    }
    pub fn width(&self) -> usize {
        self.poseidon() + POSEIDON_WIDTH
    }
    fn modulus(&self) -> u64 {
        if self.kind == PermutationKind::AutomorphismQ {
            Q
        } else {
            2
        }
    }
    fn initial(&self) -> [Val; 4] {
        if self.kind == PermutationKind::AutomorphismQ {
            [
                Val::from_u64(POLYNOMIAL_DOMAIN),
                Val::from_u64(Q),
                Val::from_usize(D),
                Val::ZERO,
            ]
        } else {
            [
                Val::from_u64(SIGNED_POLYNOMIAL_DOMAIN),
                Val::ZERO,
                Val::from_usize(D),
                Val::ZERO,
            ]
        }
    }
    fn source_index(&self, target: usize) -> usize {
        if self.kind == PermutationKind::InverseChallenge {
            return 3 * target % D;
        }
        let block = target / 4;
        let source = (block / 32 * 32 + (block + 1) % 32) * 4;
        source + [0, 3, 2, 1][target % 4]
    }
    fn factor(&self, target: usize) -> Val {
        if self.kind == PermutationKind::InverseChallenge {
            return if (86..171).contains(&target) {
                -Val::ONE
            } else {
                Val::ONE
            };
        }
        let (negative, position) = AUT_Q[target / 4];
        let factor = match target % 4 {
            0 | 3 => 1,
            1 => {
                let twiddle = if position % 2 == 0 {
                    OMEGA_Q[position / 2]
                } else {
                    arithmetic::sub(0, OMEGA_Q[position / 2], Q)
                };
                arithmetic::mont(1, twiddle, Q)
            }
            _ => {
                let factor = arithmetic::mont(1, OMEGA_Q[position], Q);
                if negative {
                    arithmetic::sub(0, factor, Q)
                } else {
                    factor
                }
            }
        };
        Val::from_u64(factor)
    }
    fn metadata(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(HEIGHT); PERIODIC_COLUMNS];
        for block in 0..64 {
            columns[SELECT_INPUT + block][block] = Val::ONE;
            columns[SELECT_OUTPUT + block][64 + block] = Val::ONE;
            columns[HASH_INPUT][block] = Val::ONE;
            columns[HASH_OUTPUT][64 + block] = Val::ONE;
            for lane in 0..4 {
                columns[FACTOR + lane][64 + block] = self.factor(4 * block + lane);
            }
        }
        columns
    }
}
impl BaseAir<Val> for PermutationAir {
    fn width(&self) -> usize {
        self.width()
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.metadata()
    }
}
