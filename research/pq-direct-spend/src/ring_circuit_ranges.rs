//! Reuse exact bounded bit decompositions for sealed canonical range checks.
//! Selection is public and opt-in; all existing representations keep their
//! double-decomposition schedule. See RANGES_REPRESENTATION.md.

use super::{budget, ConstraintContext, ResidueValue, AUXILIARY_BYTES, Q};
use crate::{Error, GOLDILOCKS_MODULUS};
use lattica_prover_p3::block_v2::machine::{
    pq_modular,
    program::{Val, Wire},
};
use p3_field::PrimeCharacteristicRing;

const Q_BITS: u32 = 28;
// One bounded_bits Vec (at most 32 Wire entries) is live per helper. Include
// its header, fixed comparison state, and conservative temporary moves within
// a subdivision of the existing auxiliary allowance; this is not extra RAM.
const RANGE_AUXILIARY_BYTES: usize = 16 << 10;
const _: () = {
    assert!(Q == 167_770_241);
    assert!(Q > 1 << (Q_BITS - 1) && Q < 1 << Q_BITS);
    assert!((1_u128 << 32) < GOLDILOCKS_MODULUS as u128);
    assert!(RANGE_AUXILIARY_BYTES < AUXILIARY_BYTES / 4);
    assert!(
        4 * (core::mem::size_of::<Vec<Wire>>() + 32 * core::mem::size_of::<Wire>())
            < RANGE_AUXILIARY_BYTES
    );
};

/// Constrain Booleanity, exact reconstruction and strict <Q using the core's
/// public sealed constructor. Short encodings (including an existing amount
/// bit) are zero-padded. No private native value enters this constraint path.
pub(super) fn canonical_from_bits_q(
    c: &mut ConstraintContext<'_, '_>,
    bits: &[Wire],
    phase: &'static str,
) -> Result<pq_modular::Residue, Error> {
    if bits.len() > Q_BITS as usize {
        return Err(Error::Geometry);
    }
    budget::guard_phase(c, phase);
    let modulus = pq_modular::Modulus::new(Q as u32).map_err(|_| Error::NonCanonical)?;
    let residue =
        pq_modular::canonical_from_bits(c.builder, bits, modulus).map_err(|_| Error::Range)?;
    budget::guard_phase(c, phase);
    Ok(residue)
}

/// One 28-bit decomposition fixes the integer representative below 2^28. The
/// strict comparator returns a sealed Q residue; explicitly link its rebuilt
/// wire to the original. The builder reuses Boolean/reconstruction expressions.
pub(super) fn canonical_q(
    c: &mut ConstraintContext<'_, '_>,
    wire: Wire,
    phase: &'static str,
) -> Result<pq_modular::Residue, Error> {
    budget::guard_phase(c, phase);
    let bits = pq_modular::bounded_bits(c.builder, wire, Q_BITS).map_err(|_| Error::Range)?;
    let residue = canonical_from_bits_q(c, &bits, phase)?;
    c.builder.assert_equal(residue.wire(), wire);
    drop(bits);
    budget::guard_phase(c, phase);
    Ok(residue)
}

/// Public u32 bounds only. All-ones bounds need reconstruction alone; other
/// bounds use strict comparison with bound+1. Check the range before arithmetic
/// or narrowing, so u32::MAX cannot overflow into the comparison modulus.
pub(super) fn assert_at_most(
    c: &mut ConstraintContext<'_, '_>,
    wire: Wire,
    bound: u64,
    phase: &'static str,
) -> Result<(), Error> {
    if bound > u64::from(u32::MAX) {
        return Err(Error::Range);
    }
    budget::guard_phase(c, phase);
    if bound == 0 {
        let zero = c.builder.constant(Val::ZERO);
        c.builder.assert_equal(wire, zero);
    } else {
        let width = u64::BITS - bound.leading_zeros();
        let bits = pq_modular::bounded_bits(c.builder, wire, width).map_err(|_| Error::Range)?;
        if bound != (1_u64 << width) - 1 {
            // This branch excludes u32::MAX and zero, hence 2 <= modulus <=
            // u32::MAX. Every reconstruction is at most 32 bits, below p.
            let value = u32::try_from(bound.checked_add(1).ok_or(Error::Range)?)
                .map_err(|_| Error::Range)?;
            let modulus = pq_modular::Modulus::new(value).map_err(|_| Error::Range)?;
            let canonical = pq_modular::canonical_from_bits(c.builder, &bits, modulus)
                .map_err(|_| Error::Range)?;
            c.builder.assert_equal(canonical.wire(), wire);
        }
        drop(bits);
    }
    budget::guard_phase(c, phase);
    Ok(())
}

pub(super) fn input_q(
    c: &mut ConstraintContext<'_, '_>,
    value: u64,
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    if value >= Q {
        return Err(Error::NonCanonical);
    }
    budget::guard_phase(c, phase);
    let wire = c.input(value);
    let constrained = canonical_q(c, wire, phase)?;
    Ok(ResidueValue { value, constrained })
}

#[cfg(test)]
#[path = "ring_circuit_ranges/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ring_circuit_ranges_audit.rs"]
mod audit;
