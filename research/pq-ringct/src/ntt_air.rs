//! Serial, fixed-profile incomplete NTT relation with exact integer arithmetic.
//!
//! Every row carries the polynomial state, while a fixed schedule changes two
//! coefficients at each butterfly. All initial coefficients are range checked
//! before the first butterfly. Each updated coefficient is canonical, so
//! induction bounds every subsequent product strictly below Goldilocks.
//! Ordered input/output commitments match `constraints_ntt::PendingNtt`.
pub use crate::rust_verify::constraints_ntt::{INPUT_DOMAIN, OUTPUT_DOMAIN};
use crate::{
    rust_verify::{
        arithmetic,
        constants::{OMEGA_Q, OMEGA_QHAT, PERM_NTT},
        D, Q, QHAT,
    },
    shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH},
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

pub(crate) mod constraints;
#[cfg(feature = "opencl")]
mod gpu;
mod join;
pub use join::{NttBatchProof, NttRootRequest, RegisteredNttAir};
#[cfg(test)]
mod tests;
mod witness;
pub use witness::NttWitness;

const STATE: usize = 0;
const INDEX_BITS: usize = D;
const PREFIX: usize = INDEX_BITS + 16;
const READS: usize = PREFIX + 64;
const RANGES: usize = READS + 4;
const ADDRESS_A: usize = 0;
const ADDRESS_B: usize = 1;
const FACTOR_U: usize = 2;
const FACTOR_V: usize = 3;
const IS_NTT: usize = 4;
const IS_HASH: usize = 5;
const RESET_OUTPUT: usize = 6;
const RESET_INPUT: usize = 7;
const LINK_STATE: usize = 8;
const ENDS: usize = 9;
pub const ROWS_PER_POLYNOMIAL: usize = 896;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Modulus,
    Count,
    Length,
    NonCanonical,
    Overflow,
}
#[derive(Clone, Debug)]
pub struct NttAir {
    pub modulus: u64,
    pub count: usize,
    pub height: usize,
}
#[derive(Clone, Copy)]
struct Step {
    a: usize,
    b: usize,
    factor_u: u64,
    factor_v: u64,
}
impl NttAir {
    pub fn new(modulus: u64, count: usize) -> Result<Self, Error> {
        if modulus != Q && modulus != QHAT {
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
        8 * self.count
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
    fn carries(&self) -> usize {
        RANGES + 6 * self.range_width()
    }
    fn acc(&self) -> usize {
        self.carries() + 2
    }
    fn poseidon(&self) -> usize {
        self.acc() + 4
    }
    pub fn width(&self) -> usize {
        self.poseidon() + POSEIDON_WIDTH
    }
    fn periodic_count(&self) -> usize {
        ENDS + 2 * self.count
    }
    fn steps(&self) -> Vec<Step> {
        let q = self.modulus;
        let omega = if q == Q { &OMEGA_Q } else { &OMEGA_QHAT };
        let conversion = if q == Q { 138_438_709 } else { 2_333_348_873 };
        let mut steps = Vec::with_capacity(768);
        for i in 0..128 {
            steps.push(Step {
                a: i,
                b: i + 128,
                factor_u: arithmetic::mont(1, conversion, q),
                factor_v: arithmetic::mont(1, omega[1], q),
            });
        }
        let mut stride = 128;
        let mut groups = 2;
        while groups < 64 {
            stride >>= 1;
            for group in 0..groups {
                let first = 2 * group * stride;
                for j in first..first + stride {
                    steps.push(Step {
                        a: j,
                        b: j + stride,
                        factor_u: 1,
                        factor_v: arithmetic::mont(1, omega[groups + group], q),
                    });
                }
            }
            groups <<= 1;
        }
        assert_eq!(steps.len(), 768);
        steps
    }
    fn metadata(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(self.height); self.periodic_count()];
        let steps = self.steps();
        for polynomial in 0..self.count {
            for row in 0..ROWS_PER_POLYNOMIAL {
                let index = polynomial * ROWS_PER_POLYNOMIAL + row;
                columns[LINK_STATE][index] = Val::from_bool(row + 1 < ROWS_PER_POLYNOMIAL);
                if row < 64 {
                    columns[ADDRESS_A][index] = Val::from_usize(row * 4);
                    columns[IS_HASH][index] = Val::ONE;
                } else if row < 832 {
                    let step = steps[row - 64];
                    columns[ADDRESS_A][index] = Val::from_usize(step.a);
                    columns[ADDRESS_B][index] = Val::from_usize(step.b);
                    columns[FACTOR_U][index] = Val::from_u64(step.factor_u);
                    columns[FACTOR_V][index] = Val::from_u64(step.factor_v);
                    columns[IS_NTT][index] = Val::ONE;
                } else {
                    let block = row - 832;
                    let source = if self.modulus == Q {
                        PERM_NTT[block] as usize
                    } else {
                        block
                    };
                    columns[ADDRESS_A][index] = Val::from_usize(source * 4);
                    columns[IS_HASH][index] = Val::ONE;
                }
                if row == 63 {
                    columns[RESET_OUTPUT][index] = Val::ONE;
                    columns[ENDS + polynomial][index] = Val::ONE;
                }
                if row + 1 == ROWS_PER_POLYNOMIAL {
                    columns[ENDS + self.count + polynomial][index] = Val::ONE;
                    if polynomial + 1 < self.count {
                        columns[RESET_INPUT][index] = Val::ONE;
                    }
                }
            }
        }
        columns
    }
}
impl BaseAir<Val> for NttAir {
    fn width(&self) -> usize {
        NttAir::width(self)
    }
    fn num_public_values(&self) -> usize {
        self.public_values()
    }
    fn num_periodic_columns(&self) -> usize {
        self.periodic_count()
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.metadata()
    }
}

pub(crate) fn nibble_eq<E: PrimeCharacteristicRing>(bits: &[E], candidate: u8) -> E {
    bits.iter().enumerate().fold(E::ONE, |value, (i, bit)| {
        value
            * if candidate & (1 << i) != 0 {
                bit.clone()
            } else {
                E::ONE - bit.clone()
            }
    })
}
