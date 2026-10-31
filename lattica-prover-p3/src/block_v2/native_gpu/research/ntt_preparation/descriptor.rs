//! Closed incomplete-NTT schedule, derived without a trace or caller metadata.
use super::*;
use super::constants::{OMEGA_Q, OMEGA_QHAT, PERM_NTT};
pub const Q: u64 = 167_770_241;
pub const QHAT: u64 = 3_489_661_057;
pub const ROWS_PER_POLYNOMIAL: usize = 896;
pub const MAX_POLYNOMIALS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NttDescriptor { modulus: u64, count: usize }
impl NttDescriptor {
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
            340 + 6 * range_width + 2 + 4 + 94, 8 * self.count, 9 + 2 * self.count)
    }
    // Unchanged reference Montgomery reduction over immutable source constants.
    fn mont(self, a: u64, b: u64) -> u64 {
        let factor = if self.modulus == Q { 2_887_272_321u64 } else { 1_071_660_929u64 };
        let product = u128::from(a) * u128::from(b);
        let correction = (product as u64 & 0xffff_ffff).wrapping_mul(factor) & 0xffff_ffff;
        let value = (product >> 32) as i128
            - ((u128::from(correction) * u128::from(self.modulus)) >> 32) as i128;
        value.rem_euclid(i128::from(self.modulus)) as u64
    }
    pub fn step(self, index: usize) -> Result<[u64; 4]> {
        if index >= 768 { return Err(Error::UnsupportedProfile); }
        let omega = if self.modulus == Q { &OMEGA_Q } else { &OMEGA_QHAT };
        if index < 128 {
            let conversion = if self.modulus == Q { 138_438_709 } else { 2_333_348_873 };
            Ok([index as u64, (index + 128) as u64,
                self.mont(1, conversion), self.mont(1, omega[1])])
        } else {
            let stage = index / 128;
            let stride = 128 >> stage;
            let group = (index % 128) / stride;
            let a = 2 * group * stride + index % stride;
            Ok([a as u64, (a + stride) as u64, 1,
                self.mont(1, omega[(1 << stage) + group])])
        }
    }
    pub fn steps(self) -> [[u64; 4]; 768] {
        core::array::from_fn(|i| self.step(i).expect("fixed NTT schedule index"))
    }
    pub fn permutation(self) -> [u64; 64] {
        if self.modulus == Q { PERM_NTT } else { core::array::from_fn(|i| i as u64) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct NttGeometry { kind: NttDescriptor }
impl NttGeometry {
    pub fn for_kind(kind: NttDescriptor) -> Self { Self { kind } }
    pub fn kind(self) -> NttDescriptor { self.kind }
    pub fn rows(self) -> usize { self.kind.geometry_tuple().0 }
    pub fn width(self) -> usize { self.kind.geometry_tuple().1 }
    pub fn public_values(self) -> usize { self.kind.geometry_tuple().2 }
    pub fn periodic_columns(self) -> usize { self.kind.geometry_tuple().3 }
    // Per-polynomial terminal selectors require the complete padded height.
    pub fn period(self) -> usize { self.rows() }
    pub fn periodic_length(self) -> usize { self.period() }
    pub fn raw_words(self) -> usize { self.kind.count * 256 }
    pub fn geometry_words(self) -> usize { 32 + 768 * 4 + 64 }
    pub fn endpoint_words(self) -> usize { self.public_values() }
    pub fn periodic_value(self, index: usize, global: usize) -> Result<Val> {
        if index >= self.periodic_columns() || global >= self.period() {
            return Err(Error::UnsupportedProfile);
        }
        let polynomial = global / ROWS_PER_POLYNOMIAL;
        let row = global % ROWS_PER_POLYNOMIAL;
        if polynomial >= self.kind.count { return Ok(Val::ZERO); }
        let mut word = match index {
            8 => (row + 1 < ROWS_PER_POLYNOMIAL) as u64,
            6 => (row == 63) as u64,
            7 => (row + 1 == ROWS_PER_POLYNOMIAL && polynomial + 1 < self.kind.count) as u64,
            5 => (row < 64 || row >= 832) as u64,
            4 => (64..832).contains(&row) as u64,
            _ => 0,
        };
        if index == 9 + polynomial && row == 63 { word = 1; }
        if index == 9 + self.kind.count + polynomial && row + 1 == ROWS_PER_POLYNOMIAL { word = 1; }
        if index <= 3 {
            if (64..832).contains(&row) {
                word = self.kind.step(row - 64)?[index];
            } else if index == 0 {
                word = 4 * if row < 64 { row as u64 }
                    else if self.kind.modulus == Q { PERM_NTT[row - 832] }
                    else { (row - 832) as u64 };
            }
        }
        Ok(Val::from_u64(word))
    }
}
