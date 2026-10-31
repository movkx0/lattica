//! Exact MatRiCT automorphism and inverse-challenge schedules.
use super::*;
use super::constants::{AUT_Q, OMEGA_Q};
pub const HEIGHT: usize = 256;
pub const PUBLIC_VALUES: usize = 8;
pub const PERIOD: usize = HEIGHT;
pub const PERIODIC_COLUMNS: usize = 134;
pub const Q: u64 = 167_770_241;
const D: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PermutationOperation { AutomorphismQ, InverseChallenge }
impl PermutationOperation {
    pub fn code(self) -> u64 { match self { Self::AutomorphismQ => 1, Self::InverseChallenge => 2 } }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PermutationDescriptor { operation: PermutationOperation }
impl PermutationDescriptor {
    pub fn new(operation: PermutationOperation) -> Self { Self { operation } }
    pub fn from_code(code: u64) -> Result<Self> {
        match code {
            1 => Ok(Self::new(PermutationOperation::AutomorphismQ)),
            2 => Ok(Self::new(PermutationOperation::InverseChallenge)),
            _ => Err(Error::UnsupportedProfile),
        }
    }
    pub fn operation(self) -> PermutationOperation { self.operation }
    pub fn count(self) -> usize { 1 }
    pub fn geometry_tuple(self) -> (usize, usize, usize, usize) {
        let width = match self.operation { PermutationOperation::AutomorphismQ => 654,
            PermutationOperation::InverseChallenge => 390 };
        (HEIGHT, width, PUBLIC_VALUES, PERIODIC_COLUMNS)
    }
    pub fn source_index(self, target: usize) -> Result<usize> {
        if target >= D { return Err(Error::UnsupportedProfile); }
        Ok(match self.operation {
            PermutationOperation::InverseChallenge => 3 * target % D,
            PermutationOperation::AutomorphismQ => {
                let block = target / 4;
                (block / 32 * 32 + (block + 1) % 32) * 4 + [0, 3, 2, 1][target % 4]
            }
        })
    }
    fn mont_one(value: u64) -> u64 {
        let correction = value.wrapping_mul(2_887_272_321) & 0xffff_ffff;
        let reduced = (value >> 32) as i128 - ((u128::from(correction) * u128::from(Q)) >> 32) as i128;
        reduced.rem_euclid(i128::from(Q)) as u64
    }
    pub fn factor(self, target: usize) -> Result<Val> {
        if target >= D { return Err(Error::UnsupportedProfile); }
        if self.operation == PermutationOperation::InverseChallenge {
            return Ok(if (86..171).contains(&target) { Val::NEG_ONE } else { Val::ONE });
        }
        let (negative, position) = AUT_Q[target / 4];
        let factor = match target % 4 {
            0 | 3 => 1,
            1 => {
                let twiddle = if position % 2 == 0 { OMEGA_Q[position / 2] }
                    else { (Q - OMEGA_Q[position / 2]) % Q };
                Self::mont_one(twiddle)
            }
            _ => {
                let factor = Self::mont_one(OMEGA_Q[position]);
                if negative { (Q - factor) % Q } else { factor }
            }
        };
        Ok(Val::from_u64(factor))
    }
    pub fn sources(self) -> [u64; D] {
        core::array::from_fn(|i| self.source_index(i).expect("fixed permutation source") as u64)
    }
    pub fn factors(self) -> [u64; D] {
        use p3_field::PrimeField64;
        core::array::from_fn(|i| self.factor(i).expect("fixed permutation factor").as_canonical_u64())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct PermutationGeometry { kind: PermutationDescriptor }
impl PermutationGeometry {
    pub fn for_kind(kind: PermutationDescriptor) -> Self { Self { kind } }
    pub fn kind(self) -> PermutationDescriptor { self.kind }
    pub fn rows(self) -> usize { HEIGHT }
    pub fn width(self) -> usize { self.kind.geometry_tuple().1 }
    pub fn public_values(self) -> usize { PUBLIC_VALUES }
    pub fn periodic_columns(self) -> usize { PERIODIC_COLUMNS }
    pub fn period(self) -> usize { PERIOD }
    pub fn periodic_length(self) -> usize { PERIOD }
    pub fn raw_words(self) -> usize { D }
    pub fn geometry_words(self) -> usize { 32 + 2 * D }
    pub fn endpoint_words(self) -> usize { PUBLIC_VALUES }
    pub fn periodic_value(self, index: usize, row: usize) -> Result<Val> {
        if index >= PERIODIC_COLUMNS || row >= PERIOD { return Err(Error::UnsupportedProfile); }
        if index < 128 { return Ok(Val::from_bool(row == index)); }
        Ok(match index {
            128 => Val::from_bool(row < 64),
            129 => Val::from_bool((64..128).contains(&row)),
            _ if (64..128).contains(&row) => self.kind.factor(4 * (row - 64) + index - 130)?,
            _ => Val::ZERO,
        })
    }
}
