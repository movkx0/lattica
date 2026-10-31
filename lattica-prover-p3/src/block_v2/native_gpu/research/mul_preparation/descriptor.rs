//! Closed four-coefficient product schedule, independent of private inputs.
use super::*;
use super::constants::{MUL_Q, OMEGA_Q, OMEGA_QHAT};
pub const Q: u64 = 167_770_241;
pub const QHAT: u64 = 3_489_661_057;
pub const ROWS_PER_BLOCK: usize = 19;
pub const ROWS_PER_POLYNOMIAL: usize = 64 * ROWS_PER_BLOCK;
pub const MAX_POLYNOMIALS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MulDescriptor { modulus: u64, count: usize }
impl MulDescriptor {
    pub fn new(modulus: u64, count: usize) -> Result<Self> {
        if !matches!(modulus, Q | QHAT) || count == 0 || count > MAX_POLYNOMIALS {
            return Err(Error::UnsupportedProfile);
        }
        Ok(Self { modulus, count })
    }
    pub fn modulus(self) -> u64 { self.modulus }
    pub fn count(self) -> usize { self.count }
    fn bits(self) -> usize { if self.modulus == Q { 28 } else { 32 } }
    pub fn geometry_tuple(self) -> (usize, usize, usize, usize) {
        let range_width = 1 + self.bits() + self.bits() / 4;
        ((self.count * ROWS_PER_POLYNOMIAL).next_power_of_two(),
            15 + 5 * range_width + 1 + 12 + 94, 12 * self.count, 21 + self.count)
    }
    // Identical Montgomery reduction to the reference product relation.
    fn mont(self, a: u64, b: u64) -> u64 {
        let factor = if self.modulus == Q { 2_887_272_321u64 } else { 1_071_660_929u64 };
        let product = u128::from(a) * u128::from(b);
        let correction = (product as u64 & 0xffff_ffff).wrapping_mul(factor) & 0xffff_ffff;
        let value = (product >> 32) as i128
            - ((u128::from(correction) * u128::from(self.modulus)) >> 32) as i128;
        value.rem_euclid(i128::from(self.modulus)) as u64
    }
    /// Original block/i/j order, [canonical factor, negative flag].
    pub fn term(self, index: usize) -> Result<[u64; 2]> {
        if index >= 64 * 16 { return Err(Error::UnsupportedProfile); }
        let block = index / 16;
        let i = (index % 16) / 4;
        let j = index % 4;
        let (negative, position) = if self.modulus == Q { MUL_Q[block] }
            else { (block % 2 != 0, 32 + block / 2) };
        let omega = if self.modulus == Q { OMEGA_Q[position] } else { OMEGA_QHAT[position] };
        let inverse = self.mont(1, 1);
        Ok(if i + j < 4 { [inverse, 0] }
            else { [self.mont(inverse, omega), negative as u64] })
    }
    pub fn terms(self) -> [[u64; 2]; 1024] {
        core::array::from_fn(|i| self.term(i).expect("fixed product schedule index"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MulGeometry { kind: MulDescriptor }
impl MulGeometry {
    pub fn for_kind(kind: MulDescriptor) -> Self { Self { kind } }
    pub fn kind(self) -> MulDescriptor { self.kind }
    pub fn rows(self) -> usize { self.kind.geometry_tuple().0 }
    pub fn width(self) -> usize { self.kind.geometry_tuple().1 }
    pub fn public_values(self) -> usize { self.kind.geometry_tuple().2 }
    pub fn periodic_columns(self) -> usize { self.kind.geometry_tuple().3 }
    // Per-polynomial terminal selectors require the full padded height.
    pub fn period(self) -> usize { self.rows() }
    pub fn periodic_length(self) -> usize { self.period() }
    pub fn raw_words(self) -> usize { self.kind.count * 512 }
    pub fn geometry_words(self) -> usize { 32 + 1024 * 2 }
    pub fn endpoint_words(self) -> usize { self.public_values() }
    pub fn periodic_value(self, index: usize, global: usize) -> Result<Val> {
        if index >= self.periodic_columns() || global >= self.period() {
            return Err(Error::UnsupportedProfile);
        }
        let polynomial = global / ROWS_PER_POLYNOMIAL;
        if polynomial >= self.kind.count { return Ok(Val::ZERO); }
        let block = (global % ROWS_PER_POLYNOMIAL) / ROWS_PER_BLOCK;
        let local = global % ROWS_PER_BLOCK;
        let mut word = match index {
            4 => (local + 1 < ROWS_PER_BLOCK) as u64,
            6 => (local + 1 == ROWS_PER_BLOCK) as u64,
            0 => (local == 0) as u64,
            1 => (local == 1) as u64,
            2 => (local == 18) as u64,
            5 => (block == 63 && local == 18 && polynomial + 1 < self.kind.count) as u64,
            _ => 0,
        };
        if (2..18).contains(&local) {
            let term = local - 2;
            let i = term / 4;
            let j = term % 4;
            if index == 3 || index == 9 + i || index == 13 + j || index == 17 + (i + j) % 4 {
                word = 1;
            }
            if index == 8 || index == 7 {
                let factor = self.kind.term(block * 16 + term)?;
                word = factor[if index == 8 { 0 } else { 1 }];
            }
        }
        if index == 21 + polynomial && block == 63 && local == 18 { word = 1; }
        Ok(Val::from_u64(word))
    }
}
