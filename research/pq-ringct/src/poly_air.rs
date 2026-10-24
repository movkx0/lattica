//! Serial exact products in the author's four-coefficient incomplete NTT ring.
//!
//! Each independent block hashes its canonical operands, accumulates all sixteen
//! terms with exact bounded integer reductions, and hashes the canonical result.
//! A common polynomial commitment allows typed NTT/product joins to reuse roots.
use crate::{
    ntt_air::constraints::canonical_range,
    rust_verify::{
        arithmetic,
        constants::{MUL_Q, OMEGA_Q, OMEGA_QHAT},
        constraints_ntt::POLYNOMIAL_DOMAIN,
        D, Q, QHAT,
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
mod join;
pub use join::{MulBatchProof, MulRootRequest, RegisteredMulAir};
#[cfg(test)]
mod tests;
mod witness;
pub use witness::MulWitness;

const LEFT: usize = 0;
const RIGHT: usize = 4;
const STATE: usize = 8;
const READS: usize = 12;
const RANGES: usize = 15;
const IS_A: usize = 0;
const IS_B: usize = 1;
const IS_O: usize = 2;
const IS_MUL: usize = 3;
const LINK_INPUT: usize = 4;
const RESET_ACC: usize = 5;
const RESET_STATE: usize = 6;
const NEGATIVE: usize = 7;
const FACTOR: usize = 8;
const SELECT_A: usize = 9;
const SELECT_B: usize = 13;
const SELECT_O: usize = 17;
const ENDS: usize = 21;
pub const ROWS_PER_BLOCK: usize = 19;
pub const ROWS_PER_POLYNOMIAL: usize = 64 * ROWS_PER_BLOCK;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Modulus,
    Count,
    Length,
    NonCanonical,
    Overflow,
}
#[derive(Clone, Debug)]
pub struct MulAir {
    pub modulus: u64,
    pub count: usize,
    pub height: usize,
}
impl MulAir {
    pub fn new(modulus: u64, count: usize) -> Result<Self, Error> {
        if !matches!(modulus, Q | QHAT) {
            return Err(Error::Modulus);
        }
        if count == 0 || count > 128 {
            return Err(Error::Count);
        }
        let height = count
            .checked_mul(ROWS_PER_POLYNOMIAL)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(Error::Overflow)?;
        let air = Self {
            modulus,
            count,
            height,
        };
        height.checked_mul(air.width()).ok_or(Error::Overflow)?;
        Ok(air)
    }
    pub fn public_values(&self) -> usize {
        12 * self.count
    }
    fn bits(&self) -> usize {
        if self.modulus == Q {
            28
        } else {
            32
        }
    }
    fn nibbles(&self) -> usize {
        self.bits() / 4
    }
    fn range_width(&self) -> usize {
        1 + self.bits() + self.nibbles()
    }
    fn range(&self, index: usize) -> usize {
        RANGES + index * self.range_width()
    }
    fn carry(&self) -> usize {
        RANGES + 5 * self.range_width()
    }
    fn acc(&self) -> usize {
        self.carry() + 1
    }
    fn poseidon(&self) -> usize {
        self.acc() + 12
    }
    pub fn width(&self) -> usize {
        self.poseidon() + POSEIDON_WIDTH
    }
    fn term(&self, block: usize, i: usize, j: usize) -> (u64, bool) {
        let (negative, position) = if self.modulus == Q {
            MUL_Q[block]
        } else {
            (block % 2 != 0, 32 + block / 2)
        };
        let omega = if self.modulus == Q {
            OMEGA_Q[position]
        } else {
            OMEGA_QHAT[position]
        };
        let inverse = arithmetic::mont(1, 1, self.modulus);
        if i + j < 4 {
            (inverse, false)
        } else {
            (arithmetic::mont(inverse, omega, self.modulus), negative)
        }
    }
    fn initial(&self) -> [Val; 4] {
        [
            Val::from_u64(POLYNOMIAL_DOMAIN),
            Val::from_u64(self.modulus),
            Val::from_usize(D),
            Val::ZERO,
        ]
    }
    fn metadata(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(self.height); ENDS + self.count];
        for polynomial in 0..self.count {
            for block in 0..64 {
                for local in 0..ROWS_PER_BLOCK {
                    let row = polynomial * ROWS_PER_POLYNOMIAL + block * ROWS_PER_BLOCK + local;
                    columns[LINK_INPUT][row] = Val::from_bool(local + 1 < ROWS_PER_BLOCK);
                    columns[RESET_STATE][row] = Val::from_bool(local + 1 == ROWS_PER_BLOCK);
                    match local {
                        0 => columns[IS_A][row] = Val::ONE,
                        1 => columns[IS_B][row] = Val::ONE,
                        18 => columns[IS_O][row] = Val::ONE,
                        _ => {
                            let term = local - 2;
                            let i = term / 4;
                            let j = term % 4;
                            let (factor, negative) = self.term(block, i, j);
                            columns[IS_MUL][row] = Val::ONE;
                            columns[SELECT_A + i][row] = Val::ONE;
                            columns[SELECT_B + j][row] = Val::ONE;
                            columns[SELECT_O + (i + j) % 4][row] = Val::ONE;
                            columns[FACTOR][row] = Val::from_u64(factor);
                            columns[NEGATIVE][row] = Val::from_bool(negative);
                        }
                    }
                    if block == 63 && local + 1 == ROWS_PER_BLOCK {
                        columns[ENDS + polynomial][row] = Val::ONE;
                        columns[RESET_ACC][row] = Val::from_bool(polynomial + 1 < self.count);
                    }
                }
            }
        }
        columns
    }
}
impl BaseAir<Val> for MulAir {
    fn width(&self) -> usize {
        MulAir::width(self)
    }
    fn num_public_values(&self) -> usize {
        self.public_values()
    }
    fn num_periodic_columns(&self) -> usize {
        ENDS + self.count
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.metadata()
    }
}
