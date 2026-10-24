//! Serial, bounded affine polynomial predicates over the shared commitments.
//!
//! A registration fixes one operation, modulus, signed bound and batch count.
//! Its four public fields bind every ordered operand/output root. This component
//! proves only its registered relation, never a complete MatRiCT spend.
use crate::{
    ntt_air::constraints::canonical_range,
    rust_verify::{
        constraints_ntt::{POLYNOMIAL_DOMAIN, SIGNED_POLYNOMIAL_DOMAIN},
        D, Q, QHAT,
    },
    shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use std::borrow::Borrow;

mod constraints;
#[cfg(feature = "opencl")]
mod gpu;
mod join;
#[cfg(test)]
mod tests;
mod witness;
pub use join::{AffineBatchProof, PendingAffine, RegisteredAffineAir};
pub use witness::{AffineInput, AffineRoots, AffineWitness};

pub const ROWS_PER_POLYNOMIAL: usize = 512;
pub const PUBLIC_VALUES: usize = 4;
pub const BUNDLE_DOMAIN: u64 = 0x4146_4649_4e45_3031;
const LEFT: usize = 0;
const RIGHT: usize = 4;
const SIGN: usize = 8;
const CARRY: usize = 12;
const ACC: usize = 16;
const BUNDLE: usize = 28;
const RANGES: usize = 32;
const HASH_A: usize = 0;
const HASH_B: usize = 1;
const HASH_O: usize = 2;
const BUNDLE_A: usize = 3;
const BUNDLE_B: usize = 4;
const BUNDLE_O: usize = 5;
const LINK: usize = 6;
const RESET: usize = 7;
const IDLE: usize = 8;
const PERIODIC_COLUMNS: usize = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AffineKind {
    Add,
    Sub,
    SignedToCanonical { bound: u32 },
}
impl AffineKind {
    pub fn code(self) -> u64 {
        match self {
            Self::Add => 1,
            Self::Sub => 2,
            Self::SignedToCanonical { .. } => 3,
        }
    }
    pub fn bound(self) -> u32 {
        match self {
            Self::SignedToCanonical { bound } => bound,
            _ => 0,
        }
    }
    pub fn is_conversion(self) -> bool {
        matches!(self, Self::SignedToCanonical { .. })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Descriptor,
    Length,
    NonCanonical,
    Overflow,
}

#[derive(Clone, Debug)]
pub struct AffineAir {
    kind: AffineKind,
    modulus: u64,
    count: usize,
    height: usize,
}
impl AffineAir {
    pub fn new(kind: AffineKind, modulus: u64, count: usize) -> Result<Self, Error> {
        if !matches!(modulus, Q | QHAT) || !count.is_power_of_two() || count > 128 {
            return Err(Error::Descriptor);
        }
        if let AffineKind::SignedToCanonical { bound } = kind {
            if bound == 0 || bound > i32::MAX as u32 || u64::from(bound) >= modulus {
                return Err(Error::Descriptor);
            }
        }
        let height = count
            .checked_mul(ROWS_PER_POLYNOMIAL)
            .ok_or(Error::Overflow)?;
        Ok(Self {
            kind,
            modulus,
            count,
            height,
        })
    }
    pub fn kind(&self) -> AffineKind {
        self.kind
    }
    pub fn modulus(&self) -> u64 {
        self.modulus
    }
    pub fn count(&self) -> usize {
        self.count
    }
    pub fn height(&self) -> usize {
        self.height
    }
    fn bits(&self) -> usize {
        if self.modulus == Q {
            28
        } else {
            32
        }
    }
    fn magnitude_bits(&self) -> usize {
        // The range helper requires its exclusive bound below 2^bits.
        let bits = (32 - (self.kind.bound() + 1).leading_zeros()) as usize;
        bits.max(1).div_ceil(4) * 4
    }
    fn range_width(bits: usize) -> usize {
        1 + bits + bits / 4
    }
    fn range(&self, lane: usize) -> usize {
        RANGES + lane * Self::range_width(self.bits())
    }
    fn magnitude(&self, lane: usize) -> usize {
        self.range(4) + lane * Self::range_width(self.magnitude_bits())
    }
    fn poseidon(&self) -> usize {
        if self.kind.is_conversion() {
            self.magnitude(4)
        } else {
            self.range(4)
        }
    }
    pub fn width(&self) -> usize {
        self.poseidon() + POSEIDON_WIDTH
    }
    fn initial(&self, which: usize) -> [Val; 4] {
        if which == 0 && self.kind.is_conversion() {
            [
                Val::from_u64(SIGNED_POLYNOMIAL_DOMAIN),
                Val::ZERO,
                Val::from_usize(D),
                Val::ZERO,
            ]
        } else {
            [
                Val::from_u64(POLYNOMIAL_DOMAIN),
                Val::from_u64(self.modulus),
                Val::from_usize(D),
                Val::ZERO,
            ]
        }
    }
    fn bundle_initial(&self) -> [Val; 4] {
        let mut state = [
            Val::from_u64(BUNDLE_DOMAIN),
            Val::from_u64(self.kind.code()),
            Val::from_u64(self.modulus),
            Val::from_usize(self.count),
            Val::from_u32(self.kind.bound()),
            Val::from_usize(D),
            Val::ZERO,
            Val::ZERO,
        ];
        p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut state);
        state[..4].try_into().unwrap()
    }
    fn metadata(&self) -> Vec<Vec<Val>> {
        // Fixed 512-row period; no full-height or per-operation selector columns.
        let mut columns = vec![Val::zero_vec(ROWS_PER_POLYNOMIAL); PERIODIC_COLUMNS];
        for block in 0..64 {
            let row = block * 4;
            columns[HASH_A][row] = Val::ONE;
            if !self.kind.is_conversion() {
                columns[HASH_B][row + 1] = Val::ONE;
            }
            columns[HASH_O][row + 2] = Val::ONE;
            for phase in 0..3 {
                columns[LINK][row + phase] = Val::ONE;
            }
        }
        columns[BUNDLE_A][256] = Val::ONE;
        if !self.kind.is_conversion() {
            columns[BUNDLE_B][257] = Val::ONE;
        }
        columns[BUNDLE_O][258] = Val::ONE;
        columns[RESET][511] = Val::ONE;
        for row in 256..512 {
            columns[IDLE][row] = Val::ONE;
        }
        columns
    }
}
impl BaseAir<Val> for AffineAir {
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
