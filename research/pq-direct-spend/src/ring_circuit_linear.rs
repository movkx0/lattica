//! Fixed-Q public linear maps. NTTs remain inline; no child proof or host
//! acceptance result replaces a relation constraint. See LINEAR_REPRESENTATION.md.
use super::{
    budget, montgomery, public_constant_in_phase, ranges, ConstraintContext, ResidueValue, Q,
};
use crate::{ring_native as native, Error, GOLDILOCKS_MODULUS};
use lattica_pq_ringct_research::rust_verify::{
    constraints::SignedValue,
    generic::{Backend, Polynomial},
    D, MUL_Q, OMEGA_Q,
};
use lattica_prover_p3::block_v2::machine::{pq_modular, program::Val};
use p3_field::PrimeCharacteristicRing;

const MAX_TERMS: usize = 20;
const MAX_ADDENDS: usize = 2;
const R_INVERSE: u64 = 54_987_456;
const QUOTIENT_BOUND: u64 = MAX_TERMS as u64 * (Q - 1) + MAX_ADDENDS as u64;
const SUM_BOUND: u128 =
    MAX_TERMS as u128 * (Q - 1) as u128 * (Q - 1) as u128 + MAX_ADDENDS as u128 * (Q - 1) as u128;
const RHS_BOUND: u128 = QUOTIENT_BOUND as u128 * Q as u128 + (Q - 1) as u128;
const _: () = {
    assert!(Q == 167_770_241);
    assert!(((1_u128 << 32) * R_INVERSE as u128) % Q as u128 == 1);
    assert!(SUM_BOUND < GOLDILOCKS_MODULUS as u128);
    assert!(RHS_BOUND < GOLDILOCKS_MODULUS as u128);
};

/// Fold only public factors. Generic quartic multiplication first applies
/// Montgomery reduction to a_i*x_j, then another reduction with omega if the
/// degree wraps. Canonicalizing a negative coefficient preserves the result
/// modulo Q while allowing a nonnegative, bounded integer dot product.
fn coefficient(public: &[u64; D], block: usize, output: usize, input: usize) -> Result<u64, Error> {
    if block >= D / 4 || output >= 4 || input >= 4 {
        return Err(Error::Geometry);
    }
    let source = (output + 4 - input) % 4;
    let value = public[block * 4 + source];
    if value >= Q {
        return Err(Error::NonCanonical);
    }
    let mut value = (u128::from(value) * u128::from(R_INVERSE) % u128::from(Q)) as u64;
    if source + input >= 4 {
        let (negative, position) = MUL_Q[block];
        value = (u128::from(value) * u128::from(OMEGA_Q[position]) * u128::from(R_INVERSE)
            % u128::from(Q)) as u64;
        if negative && value != 0 {
            value = Q - value;
        }
    }
    Ok(value)
}

/// Every input already has a sealed canonical residue constraint. The host
/// values below only produce hints; the field equation independently binds
/// their wires. Both sides are strictly below Goldilocks, ruling out aliases.
/// The quotient and remainder are the last two witness inputs of this helper.
#[cfg(test)]
fn dot(
    c: &mut ConstraintContext<'_, '_>,
    terms: &[(u64, ResidueValue)],
    addends: &[ResidueValue],
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    dot_inner::<false>(c, terms, addends, phase)
}

fn dot_inner<const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    terms: &[(u64, ResidueValue)],
    addends: &[ResidueValue],
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    if terms.len() > MAX_TERMS || addends.len() > MAX_ADDENDS {
        return Err(Error::Geometry);
    }
    if terms.iter().any(|(coefficient, _)| *coefficient >= Q)
        || terms
            .iter()
            .map(|(_, value)| value)
            .chain(addends)
            .any(|value| value.value >= Q || u64::from(value.constrained.modulus().value()) != Q)
    {
        return Err(Error::NonCanonical);
    }
    budget::guard_phase(c, phase);
    let mut sum = 0_u128;
    let mut lhs = c.builder.constant(Val::ZERO);
    for &(coefficient, value) in terms {
        sum += u128::from(coefficient) * u128::from(value.value);
        let factor = c.builder.constant(Val::from_u64(coefficient));
        let term = c.builder.mul(factor, value.constrained.wire());
        lhs = c.builder.add(lhs, term);
    }
    for value in addends {
        sum += u128::from(value.value);
        lhs = c.builder.add(lhs, value.constrained.wire());
    }
    // Static arity, canonical coefficients and canonical inputs imply this
    // bound independently of hints; keep a host diagnostic as well.
    if sum > SUM_BOUND {
        return Err(Error::Range);
    }
    let quotient = c.input((sum / u128::from(Q)) as u64);
    let value = (sum % u128::from(Q)) as u64;
    let remainder = c.input(value);
    let constrained = if REUSE_RANGES {
        ranges::assert_at_most(c, quotient, QUOTIENT_BOUND, phase)?;
        ranges::canonical_q(c, remainder, phase)?
    } else {
        pq_modular::assert_at_most(c.builder, quotient, QUOTIENT_BOUND)
            .map_err(|_| Error::Range)?;
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

#[cfg(test)]
fn matrix_poly(
    c: &mut ConstraintContext<'_, '_>,
    base: &Polynomial<ResidueValue>,
    columns: &[(&native::Poly, &Polynomial<ResidueValue>)],
    extra: Option<&Polynomial<ResidueValue>>,
    phase: &'static str,
) -> Result<Polynomial<ResidueValue>, Error> {
    matrix_poly_inner::<false>(c, base, columns, extra, phase)
}

fn matrix_poly_inner<const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    base: &Polynomial<ResidueValue>,
    columns: &[(&native::Poly, &Polynomial<ResidueValue>)],
    extra: Option<&Polynomial<ResidueValue>>,
    phase: &'static str,
) -> Result<Polynomial<ResidueValue>, Error> {
    if columns.len() > MAX_TERMS / 4 {
        return Err(Error::Geometry);
    }
    let mut result = *base;
    for index in 0..D {
        let block = index / 4;
        let output = index % 4;
        let mut terms = [(0, base[index]); MAX_TERMS];
        for (column, (public, private)) in columns.iter().enumerate() {
            for input in 0..4 {
                terms[column * 4 + input] = (
                    coefficient(public, block, output, input)?,
                    private[block * 4 + input],
                );
            }
        }
        let addends = [
            base[index],
            extra.map_or(base[index], |values| values[index]),
        ];
        result[index] = dot_inner::<REUSE_RANGES>(
            c,
            &terms[..columns.len() * 4],
            &addends[..if extra.is_some() { 2 } else { 1 }],
            phase,
        )?;
    }
    Ok(result)
}

pub(super) fn public_key(
    c: &mut ConstraintContext<'_, '_>,
    spending: &[Polynomial<SignedValue>; 8],
    mat1: &[[native::Poly; 4]],
    g: &[Polynomial<ResidueValue>; 4],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 4], Error> {
    if mat1.len() != 7 {
        return Err(Error::Geometry);
    }
    let r = spending
        .each_ref()
        .map(|p| native::ntt(&mut budget::Limited(&mut *c, phase), p));
    public_key_from_ntt(c, &r, mat1, g, phase)
}

/// The caller supplies canonical, constrained NTT outputs from this builder.
pub(super) fn public_key_from_ntt(
    c: &mut ConstraintContext<'_, '_>,
    r: &[Polynomial<ResidueValue>; 8],
    mat1: &[[native::Poly; 4]],
    g: &[Polynomial<ResidueValue>; 4],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 4], Error> {
    public_key_from_ntt_inner::<false>(c, r, mat1, g, phase)
}

pub(super) fn public_key_from_ntt_ranges(
    c: &mut ConstraintContext<'_, '_>,
    r: &[Polynomial<ResidueValue>; 8],
    mat1: &[[native::Poly; 4]],
    g: &[Polynomial<ResidueValue>; 4],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 4], Error> {
    public_key_from_ntt_inner::<true>(c, r, mat1, g, phase)
}

fn public_key_from_ntt_inner<const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    r: &[Polynomial<ResidueValue>; 8],
    mat1: &[[native::Poly; 4]],
    g: &[Polynomial<ResidueValue>; 4],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 4], Error> {
    if mat1.len() != 7 {
        return Err(Error::Geometry);
    }
    let mut result = [r[0]; 4];
    for j in 0..4 {
        let columns: [(&native::Poly, &Polynomial<ResidueValue>); 4] =
            std::array::from_fn(|i| (&mat1[i][j], &r[4 + i]));
        result[j] = matrix_poly_inner::<REUSE_RANGES>(c, &r[j], &columns, Some(&g[j]), phase)?;
    }
    Ok(result)
}

pub(super) fn commitment(
    c: &mut ConstraintContext<'_, '_>,
    opening: &[Polynomial<SignedValue>; 9],
    bits: &[ResidueValue; 64],
    mat1: &[[native::Poly; 4]],
    mat2: &[[native::Poly; 3]],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 5], Error> {
    if mat1.len() != 7 || mat2.len() != 4 {
        return Err(Error::Geometry);
    }
    let r = opening
        .each_ref()
        .map(|p| native::ntt(&mut budget::Limited(&mut *c, phase), p));
    commitment_from_ntt(c, &r, bits, mat1, mat2, phase)
}

/// The caller supplies canonical, constrained NTT outputs from this builder.
pub(super) fn commitment_from_ntt(
    c: &mut ConstraintContext<'_, '_>,
    r: &[Polynomial<ResidueValue>; 9],
    bits: &[ResidueValue; 64],
    mat1: &[[native::Poly; 4]],
    mat2: &[[native::Poly; 3]],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 5], Error> {
    commitment_from_ntt_inner::<false>(c, r, bits, mat1, mat2, phase)
}

pub(super) fn commitment_from_ntt_ranges(
    c: &mut ConstraintContext<'_, '_>,
    r: &[Polynomial<ResidueValue>; 9],
    bits: &[ResidueValue; 64],
    mat1: &[[native::Poly; 4]],
    mat2: &[[native::Poly; 3]],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 5], Error> {
    commitment_from_ntt_inner::<true>(c, r, bits, mat1, mat2, phase)
}

fn commitment_from_ntt_inner<const REUSE_RANGES: bool>(
    c: &mut ConstraintContext<'_, '_>,
    r: &[Polynomial<ResidueValue>; 9],
    bits: &[ResidueValue; 64],
    mat1: &[[native::Poly; 4]],
    mat2: &[[native::Poly; 3]],
    phase: &'static str,
) -> Result<[Polynomial<ResidueValue>; 5], Error> {
    if mat1.len() != 7 || mat2.len() != 4 {
        return Err(Error::Geometry);
    }
    let mut result = [r[0]; 5];
    for j in 0..4 {
        let columns: [(&native::Poly, &Polynomial<ResidueValue>); 5] =
            std::array::from_fn(|i| (&mat1[i][j], &r[4 + i]));
        result[j] = matrix_poly_inner::<REUSE_RANGES>(c, &r[j], &columns, None, phase)?;
    }
    let columns = [(&mat2[0][0], &r[7]), (&mat2[1][0], &r[8])];
    result[4] = matrix_poly_inner::<REUSE_RANGES>(c, &r[4], &columns, None, phase)?;
    // Preserve the original 52-bit value encoding and its Montgomery factor.
    let radix_squared = public_constant_in_phase(
        c,
        (((1_u128 << 32) % u128::from(Q)).pow(2) % u128::from(Q)) as u64,
        Q,
        phase,
    )?;
    for i in 0..64 {
        let encoded = montgomery::mont(c, bits[i], radix_squared, Q, phase);
        budget::guard_phase(c, phase);
        result[4][i * 4] = c.add(result[4][i * 4], encoded, Q);
        budget::guard_phase(c, phase);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "ring_circuit_linear/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ring_circuit_linear_audit.rs"]
mod audit;
