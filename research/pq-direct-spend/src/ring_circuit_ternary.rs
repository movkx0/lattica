//! Exact fixed-Q NTT using the existing constrained ternary wires directly.
//! Public multiples of Q shift each dot product into a small nonnegative
//! integer interval. See TERNARY_REPRESENTATION.md for the no-wrap argument.

use super::{
    budget, ntt::PublicTransform, ranges, ConstraintContext, ResidueValue, AUXILIARY_BYTES, Q,
};
use crate::{Error, GOLDILOCKS_MODULUS};
use lattica_pq_ringct_research::rust_verify::{constraints::SignedValue, generic::Polynomial, D};
use lattica_prover_p3::block_v2::machine::{pq_modular, program::Val};
use p3_field::PrimeCharacteristicRing;

const LANES: usize = 4;
const WIDTH: usize = D / LANES;
const COEFFICIENT_SUM_BOUND: u128 = WIDTH as u128 * (Q - 1) as u128;
const BIAS_BOUND: u128 = WIDTH as u128 * Q as u128;
const SUM_BOUND: u128 = BIAS_BOUND + COEFFICIENT_SUM_BOUND;
const QUOTIENT_BOUND: u64 = (SUM_BOUND / Q as u128) as u64;
const RHS_BOUND: u128 = QUOTIENT_BOUND as u128 * Q as u128 + (Q - 1) as u128;

// The same 512 KiB subdivision of the existing 16 MiB auxiliary allowance as
// the fused public NTT, not an additional allowance. Fixed table derivation,
// table moves, batch outputs and signed lane storage fit simultaneously here.
const TERNARY_AUXILIARY_BYTES: usize = 512 << 10;
const _: () = {
    assert!(D == 256 && WIDTH == 64 && Q == 167_770_241);
    assert!(QUOTIENT_BOUND == 127);
    assert!(SUM_BOUND < (QUOTIENT_BOUND as u128 + 1) * Q as u128);
    assert!(SUM_BOUND < GOLDILOCKS_MODULUS as u128);
    assert!(RHS_BOUND < GOLDILOCKS_MODULUS as u128);
    assert!(TERNARY_AUXILIARY_BYTES <= AUXILIARY_BYTES / 4);
    assert!(
        4 * core::mem::size_of::<PublicTransform>()
            + 4 * D * core::mem::size_of::<u64>()
            + 16 * D * core::mem::size_of::<ResidueValue>()
            + 2 * D * core::mem::size_of::<SignedValue>()
            <= TERNARY_AUXILIARY_BYTES
    );
};

fn validate_input(input: &[SignedValue]) -> Result<(), Error> {
    // Only sealed constraints from this builder establish the domain. Host
    // metadata is checked defensively but never chooses the program shape.
    if input
        .iter()
        .any(|value| value.value.unsigned_abs() > 1 || value.constrained.bound() != 1)
    {
        return Err(Error::Range);
    }
    Ok(())
}

/// B = ceil(sum(a)/Q)*Q depends only on canonical public coefficients. Check
/// row geometry and the full integer interval before creating any dot hints.
fn bias(coefficients: &[u64; WIDTH]) -> Result<(u128, u128), Error> {
    if coefficients.iter().any(|&coefficient| coefficient >= Q) {
        return Err(Error::NonCanonical);
    }
    let sum = coefficients.iter().try_fold(0_u128, |sum, &coefficient| {
        sum.checked_add(u128::from(coefficient))
            .ok_or(Error::Geometry)
    })?;
    let bias = sum
        .checked_add(u128::from(Q) - 1)
        .and_then(|rounded| (rounded / u128::from(Q)).checked_mul(u128::from(Q)))
        .ok_or(Error::Geometry)?;
    let upper = bias.checked_add(sum).ok_or(Error::Geometry)?;
    if sum > COEFFICIENT_SUM_BOUND
        || bias < sum
        || bias > BIAS_BOUND
        || upper > SUM_BOUND
        || upper / u128::from(Q) > u128::from(QUOTIENT_BOUND)
    {
        return Err(Error::Geometry);
    }
    Ok((bias, sum))
}

/// Constrain B + sum(a[j]*x[j]) = k*Q + r on the existing signed wires.
/// Each x[j] has bound one, 0 <= k <= 127, and 0 <= r < Q. Every integer
/// partial sum stays in [B-sum(a), B+sum(a)], inside [0, SUM_BOUND]. Both
/// complete sides are below Goldilocks, so field equality is integer equality.
/// The last two witness inputs are the bounded quotient and canonical remainder.
#[cfg(test)]
fn dot(
    c: &mut ConstraintContext<'_, '_>,
    coefficients: &[u64; WIDTH],
    input: &[SignedValue; WIDTH],
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    dot_inner::<false>(c, coefficients, input, phase)
}

fn dot_inner<const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    coefficients: &[u64; WIDTH],
    input: &[SignedValue; WIDTH],
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    validate_input(input)?;
    let (bias, coefficient_sum) = bias(coefficients)?;
    let sum =
        coefficients
            .iter()
            .zip(input)
            .try_fold(bias as i128, |sum, (&coefficient, value)| {
                i128::from(coefficient)
                    .checked_mul(i128::from(value.value))
                    .and_then(|term| sum.checked_add(term))
                    .ok_or(Error::Range)
            })?;
    if sum < (bias - coefficient_sum) as i128 || sum > (bias + coefficient_sum) as i128 {
        return Err(Error::Range);
    }
    let sum = sum as u128;
    budget::guard_phase(c, phase);
    let mut lhs = c.builder.constant(Val::from_u64(bias as u64));
    for (&coefficient, value) in coefficients.iter().zip(input) {
        let factor = c.builder.constant(Val::from_u64(coefficient));
        let term = c.builder.mul(factor, value.constrained.wire());
        lhs = c.builder.add(lhs, term);
    }
    let quotient = c.input((sum / u128::from(Q)) as u64);
    let value = (sum % u128::from(Q)) as u64;
    let remainder = c.input(value);
    pq_modular::assert_at_most(c.builder, quotient, QUOTIENT_BOUND).map_err(|_| Error::Range)?;
    let constrained = if REUSE_RANGES {
        ranges::canonical_q(c, remainder, phase)?
    } else {
        let modulus = pq_modular::Modulus::new(Q as u32).map_err(|_| Error::NonCanonical)?;
        pq_modular::canonical(c.builder, remainder, modulus)
    };
    let q = c.builder.constant(Val::from_u64(Q));
    let multiple = c.builder.mul(quotient, q);
    let rhs = c.builder.add(multiple, remainder);
    c.builder.assert_equal(lhs, rhs);
    budget::guard_phase(c, phase);
    Ok(ResidueValue { value, constrained })
}

pub(super) fn ntt(
    c: &mut ConstraintContext<'_, '_>,
    input: &Polynomial<SignedValue>,
    transform: &PublicTransform,
    phase: &'static str,
) -> Result<Polynomial<ResidueValue>, Error> {
    ntt_inner::<false>(c, input, transform, phase)
}

pub(super) fn ntt_ranges(
    c: &mut ConstraintContext<'_, '_>,
    input: &Polynomial<SignedValue>,
    transform: &PublicTransform,
    phase: &'static str,
) -> Result<Polynomial<ResidueValue>, Error> {
    ntt_inner::<true>(c, input, transform, phase)
}

fn ntt_inner<const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    input: &Polynomial<SignedValue>,
    transform: &PublicTransform,
    phase: &'static str,
) -> Result<Polynomial<ResidueValue>, Error> {
    validate_input(input)?;
    let lanes: [[SignedValue; WIDTH]; LANES] =
        std::array::from_fn(|lane| std::array::from_fn(|column| input[column * LANES + lane]));
    let first = dot_inner::<REUSE_RANGES>(c, transform.coefficient_row(0)?, &lanes[0], phase)?;
    let mut output = [first; D];
    for index in 1..D {
        output[index] = dot_inner::<REUSE_RANGES>(
            c,
            transform.coefficient_row(index / LANES)?,
            &lanes[index % LANES],
            phase,
        )?;
    }
    Ok(output)
}

pub(super) fn ntt_many<const N: usize>(
    c: &mut ConstraintContext<'_, '_>,
    input: &[Polynomial<SignedValue>; N],
    transform: &PublicTransform,
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; N], Error> {
    ntt_many_inner::<N, false>(c, input, transform, phase)
}

pub(super) fn ntt_many_ranges<const N: usize>(
    c: &mut ConstraintContext<'_, '_>,
    input: &[Polynomial<SignedValue>; N],
    transform: &PublicTransform,
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; N], Error> {
    ntt_many_inner::<N, true>(c, input, transform, phase)
}

fn ntt_many_inner<const N: usize, const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    input: &[Polynomial<SignedValue>; N],
    transform: &PublicTransform,
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; N], Error> {
    if N == 0 || N > 9 {
        return Err(Error::Geometry);
    }
    for polynomial in input {
        validate_input(polynomial)?;
    }
    let first = ntt_inner::<REUSE_RANGES>(c, &input[0], transform, phase)?;
    let mut output = [first; N];
    for i in 1..N {
        output[i] = ntt_inner::<REUSE_RANGES>(c, &input[i], transform, phase)?;
    }
    Ok(output)
}

#[cfg(test)]
#[path = "ring_circuit_ternary/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ring_circuit_ternary_audit.rs"]
mod audit;
