//! Fixed arithmetic geometry derived without allocating or observing a trace.
use super::*;
pub const Q: u64 = 167_770_241;
pub const QHAT: u64 = 3_489_661_057;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum AffineOperation { Add, Subtract, SignedToCanonical { bound: u32 } }
impl AffineOperation {
    pub fn code(self) -> u64 { match self { Self::Add => 1, Self::Subtract => 2, Self::SignedToCanonical { .. } => 3 } }
    pub fn bound(self) -> u32 { match self { Self::SignedToCanonical { bound } => bound, _ => 0 } }
    pub fn is_conversion(self) -> bool { matches!(self, Self::SignedToCanonical { .. }) }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AffineDescriptor { operation: AffineOperation, modulus: u64, count: usize }
impl AffineDescriptor {
    pub fn new(operation: AffineOperation, modulus: u64, count: usize) -> Result<Self> {
        if !matches!(modulus, Q | QHAT) || !count.is_power_of_two() || count > 64 {
            return Err(Error::UnsupportedProfile);
        }
        let bound = operation.bound();
        if operation.is_conversion() && (bound == 0 || bound > i32::MAX as u32 || u64::from(bound) >= modulus) {
            return Err(Error::UnsupportedProfile);
        }
        Ok(Self { operation, modulus, count })
    }
    pub fn operation(self) -> AffineOperation { self.operation }
    pub fn modulus(self) -> u64 { self.modulus }
    pub fn count(self) -> usize { self.count }
    fn range_width(bits: usize) -> usize { 1 + bits + bits / 4 }
    fn bits(self) -> usize { if self.modulus == Q { 28 } else { 32 } }
    fn magnitude_bits(self) -> usize { ((32 - (self.operation.bound() + 1).leading_zeros()) as usize).max(1).div_ceil(4) * 4 }
    pub fn geometry_tuple(self) -> (usize, usize, usize, usize) {
        let magnitude = if self.operation.is_conversion() { 4 * Self::range_width(self.magnitude_bits()) } else { 0 };
        (self.count * 512, 32 + 4 * Self::range_width(self.bits()) + magnitude + 94, 4, 9)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AffineGeometry { kind: AffineDescriptor }
impl AffineGeometry {
    pub fn for_kind(kind: AffineDescriptor) -> Self { Self { kind } }
    pub fn kind(self) -> AffineDescriptor { self.kind }
    pub fn rows(self) -> usize { self.kind.geometry_tuple().0 }
    pub fn width(self) -> usize { self.kind.geometry_tuple().1 }
    pub fn public_values(self) -> usize { 4 }
    pub fn periodic_columns(self) -> usize { 9 }
    pub fn period(self) -> usize { 512 }
    pub fn periodic_length(self) -> usize { self.period() }
    pub fn raw_words(self) -> usize { self.kind.count * 256 * if self.kind.operation.is_conversion() { 1 } else { 2 } }
    pub fn geometry_words(self) -> usize { 32 }
    pub fn endpoint_words(self) -> usize { self.kind.count * 12 }
    pub fn periodic_value(self, index: usize, row: usize) -> Result<Val> {
        if index >= self.periodic_columns() || row >= self.period() { return Err(Error::UnsupportedProfile); }
        let conversion = self.kind.operation.is_conversion();
        Ok(Val::from_bool(match index {
            0 => row < 256 && row % 4 == 0,
            1 => row < 256 && row % 4 == 1 && !conversion,
            2 => row < 256 && row % 4 == 2,
            3 => row == 256,
            4 => row == 257 && !conversion,
            5 => row == 258,
            6 => row < 256 && row % 4 != 3,
            7 => row == 511,
            8 => row >= 256,
            _ => return Err(Error::UnsupportedProfile),
        }))
    }
}
