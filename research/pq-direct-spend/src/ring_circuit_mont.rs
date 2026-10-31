//! Exact Montgomery multiplication for the isolated inline research compiler.
//!
//! The existing backend rechecks a public adjusted factor with a private-style
//! range decomposition on every call. Here only builder-known constants take
//! the public-constant path. Private operands and quotient/remainder hints keep
//! the existing checked modular multiply, with no witness-dependent branching.

use super::{budget, public_constant_in_phase, ConstraintContext, ResidueValue, Q};
use crate::ring::QHAT;
use lattica_prover_p3::block_v2::machine::pq_modular;
use p3_field::PrimeField64;

const fn profile_inverse_r(q: u64) -> u64 {
    // Evaluated only for the two fixed profiles, never in the compiler loop.
    assert!(matches!(q, Q | QHAT));
    let (mut old_r, mut r) = (q as i128, ((1_u64 << 32) % q) as i128);
    let (mut old_s, mut s) = (0_i128, 1_i128);
    while r != 0 {
        let quotient = old_r / r;
        (old_r, r) = (r, old_r - quotient * r);
        (old_s, s) = (s, old_s - quotient * s);
    }
    assert!(old_r == 1);
    old_s.rem_euclid(q as i128) as u64
}

fn inverse_r(q: u64) -> u64 {
    const Q_INVERSE_R: u64 = profile_inverse_r(Q);
    const QHAT_INVERSE_R: u64 = profile_inverse_r(QHAT);
    match q {
        Q => Q_INVERSE_R,
        QHAT => QHAT_INVERSE_R,
        _ => panic!("unsupported research modulus"),
    }
}

fn multiply(
    c: &mut ConstraintContext<'_, '_>,
    a: ResidueValue,
    b: ResidueValue,
    q: u64,
    phase: &'static str,
) -> ResidueValue {
    budget::guard_phase(c, phase);
    let product = u128::from(a.value) * u128::from(b.value);
    let quotient = c.input((product / u128::from(q)) as u64);
    let value = (product % u128::from(q)) as u64;
    let remainder = c.input(value);
    // The unchanged gadget checks both hints canonically and enforces the
    // exact a*b = quotient*q + remainder integer equation in Goldilocks.
    let constrained = pq_modular::mul(c.builder, a.constrained, b.constrained, quotient, remainder)
        .expect("same fixed research modulus");
    budget::guard_phase(c, phase);
    ResidueValue { value, constrained }
}

pub(super) fn mont(
    c: &mut ConstraintContext<'_, '_>,
    a: ResidueValue,
    b: ResidueValue,
    q: u64,
    phase: &'static str,
) -> ResidueValue {
    budget::guard_phase(c, phase);
    assert!(matches!(q, Q | QHAT));
    // Keep modulus checks even when a public zero or identity folds away the
    // multiply. The sealed Residue constructors already emitted canonical input
    // constraints, which remain in the program even when this result folds.
    assert_eq!(u64::from(a.constrained.modulus().value()), q);
    assert_eq!(u64::from(b.constrained.modulus().value()), q);
    let public_a = c.builder.known_constant(a.constrained.wire());
    let public_b = c.builder.known_constant(b.constrained.wire());
    let inverse = inverse_r(q);
    if let (Some(a), Some(b)) = (public_a, public_b) {
        let value = ((u128::from(a.as_canonical_u64()) * u128::from(b.as_canonical_u64())
            % u128::from(q))
            * u128::from(inverse)
            % u128::from(q)) as u64;
        return public_constant_in_phase(c, value, q, phase)
            .expect("public Montgomery result is canonical");
    }
    let public_factor = public_b
        .map(|factor| (a, factor))
        .or_else(|| public_a.map(|factor| (b, factor)));
    if let Some((private, factor)) = public_factor {
        let adjusted =
            (u128::from(factor.as_canonical_u64()) * u128::from(inverse) % u128::from(q)) as u64;
        match adjusted {
            0 => return public_constant_in_phase(c, 0, q, phase).expect("zero is canonical"),
            1 => return private,
            _ => {}
        }
        let factor = public_constant_in_phase(c, adjusted, q, phase)
            .expect("public adjusted factor is canonical");
        return multiply(c, private, factor, q, phase);
    }
    // General private/private semantics are unchanged: two canonical modular
    // reductions. Only the public inverse-R constant avoids redundant hints.
    let product = multiply(c, a, b, q, phase);
    let inverse =
        public_constant_in_phase(c, inverse, q, phase).expect("public inverse R is canonical");
    multiply(c, product, inverse, q, phase)
}

#[cfg(test)]
#[path = "ring_circuit_mont/tests.rs"]
mod tests;
