//! Immutable bounded coefficientwise relation; constructor mirrors the original
//! canonical normalization and integer nonaliasing checks. Equality compares all
//! coefficients; the identity digest is for bounded reporting, never authority.
use super::*;
use sha3::{Digest, Sha3_256};
pub const MAX_INPUTS: usize = 16;
pub const D: usize = 256;
pub const MAX_PUBLIC_VALUES: usize = 68;
pub const MAX_HEIGHT: usize = 2048;
pub const MAX_PERIODIC_COLUMNS: usize = 104;
pub const Q: u64 = 167_770_241;
pub const QHAT: u64 = 3_489_661_057;
const FIELD: u128 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct LinearMapDescriptor {
    inputs: usize,
    kinds: [[u64; 2]; MAX_INPUTS + 1],
    #[serde(skip)] coefficients: [[i64; D]; MAX_INPUTS],
    #[serde(skip)] constant: [i64; D],
    bits: usize,
    quotient_bound: u64,
    bounds: [u32; MAX_INPUTS + 2],
    bounds_len: usize,
    identity: [u8; 32],
}
impl core::fmt::Debug for LinearMapDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinearMapDescriptor").field("inputs", &self.inputs)
            .field("output", &self.kinds[self.inputs]).field("bits", &self.bits)
            .field("quotient_bound", &self.quotient_bound).field("identity", &self.identity).finish()
    }
}
fn centered(value: i64, modulus: u64) -> i64 {
    let residue = i128::from(value).rem_euclid(i128::from(modulus));
    if residue > i128::from(modulus / 2) { (residue - i128::from(modulus)) as i64 }
    else { residue as i64 }
}
impl LinearMapDescriptor {
    /// Kinds are exactly [modulus,0] (canonical) or [0,bound] (signed),
    /// ordered input kinds followed by the output kind. No source IDs/witness.
    pub fn new(kinds: &[[u64; 2]], coefficients: &[[i64; D]], constant: &[i64; D]) -> Result<Self> {
        let inputs = coefficients.len();
        if !(1..=MAX_INPUTS).contains(&inputs) || kinds.len() != inputs + 1 {
            return Err(Error::UnsupportedProfile);
        }
        let mut result = Self { inputs, kinds: [[0; 2]; MAX_INPUTS + 1],
            coefficients: [[0; D]; MAX_INPUTS], constant: *constant,
            bits: 0, quotient_bound: 0, bounds: [0; MAX_INPUTS + 2],
            bounds_len: 0, identity: [0; 32] };
        result.kinds[..kinds.len()].copy_from_slice(kinds);
        result.coefficients[..inputs].copy_from_slice(coefficients);
        let output = kinds[inputs];
        if output[0] != 0 {
            let q = output[0];
            if !matches!(q, Q | QHAT) || output[1] != 0 || kinds.iter().any(|kind| *kind != output) {
                return Err(Error::UnsupportedProfile);
            }
            for row in &mut result.coefficients[..inputs] {
                for coefficient in row { *coefficient = centered(*coefficient, q); }
            }
            for value in &mut result.constant { *value = centered(*value, q); }
            let mut maximum = 0u128;
            for lane in 0..D {
                let mut sum = u128::from(result.constant[lane].unsigned_abs());
                for row in &result.coefficients[..inputs] {
                    sum = sum.checked_add(u128::from(row[lane].unsigned_abs()) * u128::from(q - 1))
                        .ok_or(Error::Overflow)?;
                }
                maximum = maximum.max(sum);
            }
            let q128 = u128::from(q);
            if 2 * maximum + 2 * q128 >= FIELD { return Err(Error::UnsupportedProfile); }
            let bound = maximum.div_ceil(q128) + 1;
            if bound > i32::MAX as u128 || maximum + u128::from(q - 1) + bound * q128 >= FIELD {
                return Err(Error::UnsupportedProfile);
            }
            result.bits = if q == Q { 28 } else { 32 };
            result.quotient_bound = bound as u64;
        } else {
            if kinds.iter().any(|kind| kind[0] != 0 || kind[1] == 0 || kind[1] > i32::MAX as u64) {
                return Err(Error::UnsupportedProfile);
            }
            // Stack-only sorted unique bounds, matching BTreeSet [0,output,inputs].
            result.bounds_len = 1;
            for kind in kinds {
                let bound = kind[1] as u32;
                if !result.bounds[..result.bounds_len].contains(&bound) {
                    result.bounds[result.bounds_len] = bound;
                    result.bounds_len += 1;
                }
            }
            result.bounds[..result.bounds_len].sort_unstable();
            for lane in 0..D {
                let mut maximum = u128::from(constant[lane].unsigned_abs()) + u128::from(output[1]);
                for (row, kind) in coefficients.iter().zip(kinds) {
                    maximum = maximum.checked_add(u128::from(row[lane].unsigned_abs()) * u128::from(kind[1]))
                        .ok_or(Error::Overflow)?;
                }
                if maximum >= FIELD { return Err(Error::UnsupportedProfile); }
            }
            let limit = 2 * u64::from(result.bounds[result.bounds_len - 1]) + 1;
            result.bits = (64 - limit.leading_zeros() as usize).div_ceil(4) * 4;
        }
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/ringct/linear-map-descriptor/v1");
        identity.update((inputs as u64).to_le_bytes());
        for kind in result.kinds() { for value in kind { identity.update(value.to_le_bytes()); } }
        for row in result.coefficients() { for value in row { identity.update(value.to_le_bytes()); } }
        for value in result.constant() { identity.update(value.to_le_bytes()); }
        identity.update((result.bits as u64).to_le_bytes());
        identity.update(result.quotient_bound.to_le_bytes());
        for value in result.bounds() { identity.update(value.to_le_bytes()); }
        result.identity = identity.finalize().into();
        Ok(result)
    }
    pub fn count(&self) -> usize { 1 }
    pub fn inputs(&self) -> usize { self.inputs }
    pub fn kinds(&self) -> &[[u64; 2]] { &self.kinds[..=self.inputs] }
    pub fn coefficients(&self) -> &[[i64; D]] { &self.coefficients[..self.inputs] }
    pub fn constant(&self) -> &[i64; D] { &self.constant }
    pub fn bits(&self) -> usize { self.bits }
    pub fn quotient_bound(&self) -> u64 { self.quotient_bound }
    pub fn bounds(&self) -> &[u32] { &self.bounds[..self.bounds_len] }
    pub fn identity(&self) -> [u8; 32] { self.identity }
    pub fn canonical(&self) -> bool { self.kinds[self.inputs][0] != 0 }
    pub fn quotient_bits(&self) -> usize {
        let limit = 2 * self.quotient_bound + 1;
        (64 - limit.leading_zeros() as usize).max(1).div_ceil(4) * 4
    }
    pub fn stride(&self) -> usize { (self.inputs + 1).next_power_of_two() }
    pub fn public_values(&self) -> usize { 4 * (self.inputs + 1) }
    pub fn geometry_tuple(&self) -> (usize, usize, usize, usize) {
        let rw = |bits: usize| 1 + bits + bits / 4;
        let width = 4 * self.inputs + self.public_values() + 4 * rw(self.bits)
            + if self.canonical() { 4 * rw(self.quotient_bits()) } else { 0 } + 94;
        (64 * self.stride(), width, self.public_values(), 5 * self.inputs + 6 + self.bounds_len)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LinearMapGeometry { kind: LinearMapDescriptor }
impl LinearMapGeometry {
    pub fn for_kind(kind: LinearMapDescriptor) -> Self { Self { kind } }
    pub fn kind(&self) -> LinearMapDescriptor { self.kind }
    pub fn descriptor(&self) -> &LinearMapDescriptor { &self.kind }
    pub fn rows(&self) -> usize { self.kind.geometry_tuple().0 }
    pub fn width(&self) -> usize { self.kind.geometry_tuple().1 }
    pub fn public_values(&self) -> usize { self.kind.public_values() }
    pub fn periodic_columns(&self) -> usize { self.kind.geometry_tuple().3 }
    /// Maximum supported source period. Each actual column is minimized below.
    pub fn period(&self) -> usize { self.rows() }
    pub fn periodic_length(&self) -> usize { self.rows() }
    pub fn raw_words(&self) -> usize { D * self.kind.inputs() }
    pub fn geometry_words(&self) -> usize { 32 + 2 * (self.kind.inputs() + 1) + D * self.kind.inputs() + D }
    pub fn endpoint_words(&self) -> usize { self.public_values() }
    pub fn periodic_value(&self, index: usize, row: usize) -> Result<Val> {
        if index >= self.periodic_columns() || row >= self.rows() { return Err(Error::UnsupportedProfile); }
        let descriptor = &self.kind;
        let phase = row % descriptor.stride();
        let chunk = row / descriptor.stride();
        let link = descriptor.inputs + 1;
        if index < link { return Ok(Val::from_bool(index == phase)); }
        if index == link { return Ok(Val::from_bool(phase + 1 < descriptor.stride())); }
        let coefficient = link + 1;
        let constant = coefficient + 4 * descriptor.inputs;
        let bound_selector = constant + 4;
        let signed = |v: i64| if v < 0 { -Val::from_u64(v.unsigned_abs()) } else { Val::from_u64(v as u64) };
        if index < constant {
            let cell = index - coefficient;
            return Ok(signed(descriptor.coefficients[cell / 4][4 * chunk + cell % 4]));
        }
        if index < bound_selector { return Ok(signed(descriptor.constant[4 * chunk + index - constant])); }
        let bound = if phase <= descriptor.inputs { descriptor.kinds[phase][1] as u32 } else { 0 };
        Ok(Val::from_bool(descriptor.bounds[index - bound_selector] == bound))
    }
    pub fn column_len(&self, index: usize) -> Result<usize> {
        if index >= self.periodic_columns() { return Err(Error::UnsupportedProfile); }
        let mut len = self.rows();
        while len > 1 {
            let mut repeats = true;
            for row in 0..len / 2 {
                if self.periodic_value(index, row)? != self.periodic_value(index, row + len / 2)? {
                    repeats = false; break;
                }
            }
            if !repeats { break; }
            len /= 2;
        }
        Ok(len)
    }
    pub fn periodic_elements(&self) -> Result<usize> {
        (0..self.periodic_columns()).try_fold(0, |total, index| add(total, self.column_len(index)?))
    }
}
