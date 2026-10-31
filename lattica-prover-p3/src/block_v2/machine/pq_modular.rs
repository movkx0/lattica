//! Exact bounded integer constraints for the lattice verifier.
//!
//! Quotients, remainders and signs may be supplied as witness hints, but every
//! returned value is constrained. No native acceptance flag enters this module.
//! Moduli fit in u32, so products of two canonical residues are strictly below
//! the Goldilocks modulus; modular equalities therefore cannot hide a field wrap.

use super::program::{ScopedProgramBuilder, Val, Wire};
use p3_field::PrimeCharacteristicRing;

const FIELD_MODULUS: u128 = 0xffff_ffff_0000_0001;
const MAX_BOUND: u64 = (1_u64 << 62) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidModulus,
    DifferentModuli,
    BoundTooLarge,
    SignedBoundExceedsModulus,
    NormCanWrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Modulus(u32);

impl Modulus {
    pub fn new(value: u32) -> Result<Self, Error> {
        if value < 2 {
            return Err(Error::InvalidModulus);
        }
        Ok(Self(value))
    }

    pub fn value(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Residue {
    wire: Wire,
    modulus: Modulus,
}

impl Residue {
    pub fn wire(self) -> Wire {
        self.wire
    }

    pub fn modulus(self) -> Modulus {
        self.modulus
    }
}

/// A field encoding of an integer in [-bound, bound]. Its signed interpretation
/// is unique because the enforced interval is much smaller than the field.
#[derive(Clone, Copy, Debug)]
pub struct Signed {
    wire: Wire,
    bound: u32,
}

impl Signed {
    pub fn wire(self) -> Wire {
        self.wire
    }

    pub fn bound(self) -> u32 {
        self.bound
    }
}

/// Canonical bounded decomposition. At most 62 Boolean bits reconstruct the
/// exact field value, so no alternate integer differing by p is possible.
pub fn bounded_bits(
    builder: &mut ScopedProgramBuilder<'_>,
    value: Wire,
    bits: u32,
) -> Result<Vec<Wire>, Error> {
    if bits > 62 {
        return Err(Error::BoundTooLarge);
    }
    let mut sum = builder.constant(Val::ZERO);
    let mut result = Vec::with_capacity(bits as usize);
    for i in 0..bits {
        let bit = builder.bit_hint(value, i as usize);
        builder.assert_bool(bit);
        let weight = builder.constant(Val::from_u64(1_u64 << i));
        let term = builder.mul(bit, weight);
        sum = builder.add(sum, term);
        result.push(bit);
    }
    builder.assert_equal(sum, value);
    Ok(result)
}

/// Both value and bound-value are reconstructed from at most 62 Boolean bits.
/// Their sum is below 2^63, hence below the field modulus: no modular alias can
/// make an out-of-range value satisfy the comparison.
pub fn assert_at_most(
    builder: &mut ScopedProgramBuilder<'_>,
    value: Wire,
    bound: u64,
) -> Result<(), Error> {
    if bound > MAX_BOUND {
        return Err(Error::BoundTooLarge);
    }
    let width = u64::BITS - bound.leading_zeros();
    bounded_bits(builder, value, width)?;
    if bound != (1_u64 << width) - 1 {
        let max = builder.constant(Val::from_u64(bound));
        let slack = builder.sub(max, value);
        bounded_bits(builder, slack, width)?;
    }
    Ok(())
}

pub fn canonical(builder: &mut ScopedProgramBuilder<'_>, wire: Wire, modulus: Modulus) -> Residue {
    assert_at_most(builder, wire, u64::from(modulus.0) - 1)
        .expect("u32 residue bound is below 2^62");
    Residue { wire, modulus }
}

/// Reuse a little-endian bit encoding with constrained Booleanity, exact
/// reconstruction and strict comparison. No caller-supplied hint is trusted.
pub fn canonical_from_bits(
    builder: &mut ScopedProgramBuilder<'_>,
    bits: &[Wire],
    modulus: Modulus,
) -> Result<Residue, Error> {
    if bits.len() > 32 {
        return Err(Error::BoundTooLarge);
    }
    let zero = builder.constant(Val::ZERO);
    let one = builder.constant(Val::ONE);
    let mut wire = zero;
    let mut less = zero;
    // Pad short encodings for comparison. More significant bits override the
    // lower-bit comparison. A 32-bit reconstruction cannot wrap Goldilocks.
    for i in 0..32 {
        let bit = bits.get(i).copied().unwrap_or(zero);
        builder.assert_bool(bit);
        let weight = builder.constant(Val::from_u64(1_u64 << i));
        let term = builder.mul(bit, weight);
        wire = builder.add(wire, term);
        less = if (modulus.0 >> i) & 1 == 1 {
            builder.select(bit, one, less)
        } else {
            builder.select(bit, less, zero)
        };
    }
    builder.assert_equal(less, one);
    Ok(Residue { wire, modulus })
}

fn same_modulus(a: Residue, b: Residue) -> Result<Modulus, Error> {
    if a.modulus != b.modulus {
        return Err(Error::DifferentModuli);
    }
    Ok(a.modulus)
}

/// Enforce a*b = quotient*modulus + remainder as an integer equality.
/// With all four residues below modulus, both sides are < modulus^2 < p.
pub fn mul(
    builder: &mut ScopedProgramBuilder<'_>,
    a: Residue,
    b: Residue,
    quotient: Wire,
    remainder: Wire,
) -> Result<Residue, Error> {
    let modulus = same_modulus(a, b)?;
    let quotient = canonical(builder, quotient, modulus);
    let remainder = canonical(builder, remainder, modulus);
    let m = builder.constant(Val::from_u32(modulus.0));
    let qm = builder.mul(quotient.wire, m);
    let rhs = builder.add(qm, remainder.wire);
    let lhs = builder.mul(a.wire, b.wire);
    builder.assert_equal(lhs, rhs);
    Ok(remainder)
}

/// carry is a Boolean hint for the single modular correction.
pub fn add(
    builder: &mut ScopedProgramBuilder<'_>,
    a: Residue,
    b: Residue,
    carry: Wire,
    remainder: Wire,
) -> Result<Residue, Error> {
    let modulus = same_modulus(a, b)?;
    builder.assert_bool(carry);
    let remainder = canonical(builder, remainder, modulus);
    let m = builder.constant(Val::from_u32(modulus.0));
    let correction = builder.mul(carry, m);
    let rhs = builder.add(correction, remainder.wire);
    let lhs = builder.add(a.wire, b.wire);
    builder.assert_equal(lhs, rhs);
    Ok(remainder)
}

/// Enforce a + modulus - b = carry*modulus + remainder. In particular, equal
/// operands require carry=1 and remainder=0, not a noncanonical zero encoding.
pub fn sub(
    builder: &mut ScopedProgramBuilder<'_>,
    a: Residue,
    b: Residue,
    carry: Wire,
    remainder: Wire,
) -> Result<Residue, Error> {
    let modulus = same_modulus(a, b)?;
    builder.assert_bool(carry);
    let remainder = canonical(builder, remainder, modulus);
    let m = builder.constant(Val::from_u32(modulus.0));
    let correction = builder.mul(carry, m);
    let rhs = builder.add(correction, remainder.wire);
    let shifted = builder.add(a.wire, m);
    let lhs = builder.sub(shifted, b.wire);
    builder.assert_equal(lhs, rhs);
    Ok(remainder)
}

pub fn signed(
    builder: &mut ScopedProgramBuilder<'_>,
    wire: Wire,
    bound: u32,
) -> Result<Signed, Error> {
    if bound > i32::MAX as u32 {
        return Err(Error::BoundTooLarge);
    }
    let offset = builder.constant(Val::from_u32(bound));
    let shifted = builder.add(wire, offset);
    assert_at_most(builder, shifted, u64::from(bound) * 2)?;
    Ok(Signed { wire, bound })
}

/// Decode the canonical offset encoding x+bound, reusing constrained bits.
pub fn signed_from_offset_bits(
    builder: &mut ScopedProgramBuilder<'_>,
    bits: &[Wire],
    bound: u32,
) -> Result<Signed, Error> {
    if bound > i32::MAX as u32 || bits.len() > 32 {
        return Err(Error::BoundTooLarge);
    }
    let encoded = if bound == 0 {
        let zero = builder.constant(Val::ZERO);
        for &bit in bits {
            builder.assert_equal(bit, zero);
        }
        zero
    } else {
        canonical_from_bits(builder, bits, Modulus::new(2 * bound + 1)?)?.wire
    };
    let offset = builder.constant(Val::from_u32(bound));
    let wire = builder.sub(encoded, offset);
    Ok(Signed { wire, bound })
}

/// For |x| < modulus, the canonical residue is x + negative*modulus.
/// Booleanity and canonicality determine negative; it is not trusted.
pub fn signed_to_residue(
    builder: &mut ScopedProgramBuilder<'_>,
    value: Signed,
    modulus: Modulus,
    negative: Wire,
) -> Result<Residue, Error> {
    if value.bound >= modulus.0 {
        return Err(Error::SignedBoundExceedsModulus);
    }
    builder.assert_bool(negative);
    let m = builder.constant(Val::from_u32(modulus.0));
    let correction = builder.mul(negative, m);
    let result = builder.add(value.wire, correction);
    Ok(canonical(builder, result, modulus))
}

/// Check an exact integer squared norm. The static bounds must establish that
/// the entire sum, not merely each product, is below the field modulus.
pub fn assert_squared_norm(
    builder: &mut ScopedProgramBuilder<'_>,
    values: &[Signed],
    maximum: u64,
) -> Result<Wire, Error> {
    if maximum > MAX_BOUND {
        return Err(Error::BoundTooLarge);
    }
    let total_bound = values.iter().try_fold(0_u128, |sum, value| {
        sum.checked_add(u128::from(value.bound).pow(2))
    });
    if total_bound.is_none_or(|bound| bound >= FIELD_MODULUS) {
        return Err(Error::NormCanWrap);
    }
    let mut norm = builder.constant(Val::ZERO);
    for value in values {
        let square = builder.mul(value.wire, value.wire);
        norm = builder.add(norm, square);
    }
    assert_at_most(builder, norm, maximum)?;
    Ok(norm)
}

#[cfg(test)]
mod tests;
