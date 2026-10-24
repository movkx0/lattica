//! Exact integer negacyclic convolution for the native MatRiCT+ g_bound checks.
//!
//! Both input polynomials use the shared signed-polynomial commitment. Bounded
//! signed inputs are transformed directly over Goldilocks: forward DIF, a
//! pointwise product, then inverse DIT, with a primitive512th-root twist. The
//! recovered coefficients are bounded by the native g limit. For either pinned
//! descriptor, 256*f_bound*(f_bound+1)+g_bound < Goldilocks, so the field relation
//! cannot accept a different integer convolution by modular aliasing.

use crate::rust_verify::{constraints_ntt::SIGNED_POLYNOMIAL_DOMAIN, D};
use crate::shake_air::{round_constants, PoseidonAir, PoseidonCols, SubBuilder, POSEIDON_WIDTH};
use crate::statement_air::bundle::absorb;
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks as Linear, Goldilocks as Val};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Borrow;

mod constraints;
#[cfg(feature = "opencl")]
mod gpu;
pub mod join;
#[cfg(test)]
mod tests;
mod witness;
pub use witness::GBoundWitness;

pub const HEIGHT: usize = 4096;
pub const SCHEDULE_PERIOD: usize = 128;
pub const PUBLIC_VALUES: usize = 8;
const LEFT: usize = 0;
const RIGHT: usize = D;
const ADDRESS_BITS: usize = 2 * D;
const ADDRESS_PREFIX: usize = ADDRESS_BITS + 16;
const READS: usize = ADDRESS_PREFIX + 64;
const RANGES: usize = READS + 4;
const RANGE_BITS: usize = 24;
const RANGE_WIDTH: usize = 1 + RANGE_BITS + RANGE_BITS / 4;
const PHASE: usize = RANGES + 4 * RANGE_WIDTH;
const PHASES: usize = HEIGHT / SCHEDULE_PERIOD;
const ACC: usize = PHASE + PHASES;
const POSEIDON: usize = ACC + 4;
pub const WIDTH: usize = POSEIDON + POSEIDON_WIDTH;
const ADDRESS_A: usize = 0;
const ADDRESS_B: usize = 8;
const FORWARD_FACTOR: usize = 16;
const INVERSE_FACTOR: usize = 24;
const TWIST_FACTOR: usize = 32;
const UNTWIST_FACTOR: usize = 33;
const ROW_INDEX: usize = 34;
const HASH_INDEX: usize = 35;
const FIRST_HALF: usize = 36;
const HASH_END: usize = 37;
const BLOCK_END: usize = 38;
const PERIODIC: usize = 39;
const GOLDILOCKS_MODULUS: u128 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Descriptor,
    Encoding,
    IntegerBound,
}

/// Descriptor is fixed by the consuming graph obligation, never by the witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GBoundAir {
    f_bound: u32,
    g_bound: u32,
}
impl GBoundAir {
    pub fn new(g_bound: u32) -> Result<Self, Error> {
        let f_bound = match g_bound {
            6_825_771 => 5086,
            1_137_628 => 565,
            _ => return Err(Error::Descriptor),
        };
        let maximum =
            (D as u128) * u128::from(f_bound) * (u128::from(f_bound) + 1) + u128::from(g_bound);
        if maximum >= GOLDILOCKS_MODULUS {
            return Err(Error::IntegerBound);
        }
        Ok(Self { f_bound, g_bound })
    }
    pub fn f_bound(&self) -> u32 {
        self.f_bound
    }
    pub fn g_bound(&self) -> u32 {
        self.g_bound
    }
    pub fn maximum_integer_difference(&self) -> u64 {
        D as u64 * u64::from(self.f_bound) * (u64::from(self.f_bound) + 1) + u64::from(self.g_bound)
    }
    fn schedule(&self) -> Vec<Vec<Val>> {
        let mut columns = vec![Val::zero_vec(SCHEDULE_PERIOD); PERIODIC];
        let psi = Val::two_adic_generator(9);
        let omega = psi.square();
        let omega_inverse = omega.inverse();
        let inverse_n = Val::from_usize(D).inverse();
        for row in 0..SCHEDULE_PERIOD {
            for stage in 0..8 {
                let size = D >> stage;
                let half = size / 2;
                let j = row % half;
                let a = (row / half) * size + j;
                columns[ADDRESS_A + stage][row] = Val::from_usize(a);
                columns[ADDRESS_B + stage][row] = Val::from_usize(a + half);
                columns[FORWARD_FACTOR + stage][row] = omega.exp_u64((j * D / size) as u64);
                // Inverse DIT uses the same address tables in reverse order.
                columns[INVERSE_FACTOR + stage][row] = omega_inverse.exp_u64((j * D / size) as u64);
            }
            columns[TWIST_FACTOR][row] = psi.exp_u64(row as u64);
            columns[UNTWIST_FACTOR][row] = psi.inverse().exp_u64(row as u64) * inverse_n;
            columns[ROW_INDEX][row] = Val::from_usize(row);
            columns[HASH_INDEX][row] = Val::from_usize(4 * (row % 64));
            columns[FIRST_HALF][row] = Val::from_bool(row < 64);
            columns[HASH_END][row] = Val::from_bool(row == 63);
            columns[BLOCK_END][row] = Val::from_bool(row == 127);
        }
        columns
    }
}
fn signed(value: i64) -> Val {
    if value < 0 {
        -Val::from_u64(value.unsigned_abs())
    } else {
        Val::from_u64(value as u64)
    }
}
fn initial() -> [Val; 4] {
    [
        Val::from_u64(SIGNED_POLYNOMIAL_DOMAIN),
        Val::ZERO,
        Val::from_usize(D),
        Val::ZERO,
    ]
}
impl BaseAir<Val> for GBoundAir {
    fn width(&self) -> usize {
        WIDTH
    }
    fn num_public_values(&self) -> usize {
        PUBLIC_VALUES
    }
    fn num_periodic_columns(&self) -> usize {
        PERIODIC
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        self.schedule()
    }
}
