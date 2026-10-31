//! Exact fixed-Q transform expressed as bounded public linear equations.
//! The public basis table is derived once, never from a private witness. See
//! NTT_REPRESENTATION.md for the integer bound and auxiliary storage accounting.
use super::{budget, ConstraintContext, ResidueValue, AUXILIARY_BYTES, Q};
use crate::{ring_native as native, Error, GOLDILOCKS_MODULUS};
use lattica_pq_ringct_research::rust_verify::{
    constraints::SignedValue,
    generic::{self, Backend, Polynomial},
    D,
};
use lattica_prover_p3::block_v2::machine::{pq_modular, program::Val};
use p3_field::PrimeCharacteristicRing;

const LANES: usize = 4;
const WIDTH: usize = D / LANES;
const QUOTIENT_BOUND: u64 = WIDTH as u64 * (Q - 1);
const SUM_BOUND: u128 = WIDTH as u128 * (Q - 1) as u128 * (Q - 1) as u128;
const RHS_BOUND: u128 = QUOTIENT_BOUND as u128 * Q as u128 + (Q - 1) as u128;
// A fixed part of the existing 16 MiB auxiliary allowance, not an additional
// allowance. Covers retained table, basis/result buffers, constrained lanes,
// output array and conservative temporary table moves. The process guard still
// covers allocator/compiler stack overhead; this is not an RSS measurement.
const NTT_AUXILIARY_BYTES: usize = 512 << 10;
const _: () = {
    assert!(D == 256 && WIDTH == 64 && Q == 167_770_241);
    assert!(SUM_BOUND < GOLDILOCKS_MODULUS as u128);
    assert!(RHS_BOUND < GOLDILOCKS_MODULUS as u128);
    assert!(NTT_AUXILIARY_BYTES <= AUXILIARY_BYTES / 4);
    assert!(
        4 * core::mem::size_of::<PublicTransform>()
            + 4 * D * core::mem::size_of::<u64>()
            + 16 * D * core::mem::size_of::<ResidueValue>()
            <= NTT_AUXILIARY_BYTES
    );
};

/// Every NTT stride is a multiple of four, and the final permutation keeps the
/// within-quartic lane. All four lanes therefore use the same public 64x64 map.
/// Private fields prevent production callers from supplying a different map.
pub(super) struct PublicTransform {
    coefficients: [[u64; WIDTH]; WIDTH],
}

impl PublicTransform {
    /// Derive the exact frozen transform, including the initial conversion,
    /// every Montgomery factor, all signs, twiddles and final permutation.
    /// Only public unit vectors enter this native arithmetic. Its outputs are
    /// program constants, never a native acceptance bit for a private witness.
    pub(super) fn derive() -> Self {
        let mut coefficients = [[0; WIDTH]; WIDTH];
        for column in 0..WIDTH {
            let mut basis = [0; D];
            basis[column * LANES] = 1;
            let output = generic::ntt_residues(&mut native::Native, &basis, Q);
            for row in 0..WIDTH {
                coefficients[row][column] = output[row * LANES];
            }
        }
        Self { coefficients }
    }

    /// Read-only access for the separately selected signed-input equation.
    /// The table remains derived exclusively from the fixed public transform.
    pub(super) fn coefficient_row(&self, row: usize) -> Result<&[u64; WIDTH], Error> {
        self.coefficients.get(row).ok_or(Error::Geometry)
    }

    pub(super) fn ntt(
        &self,
        c: &mut ConstraintContext<'_, '_>,
        input: &Polynomial<SignedValue>,
        phase: &'static str,
    ) -> Result<Polynomial<ResidueValue>, Error> {
        // This representation is deliberately restricted to the direct-spend
        // ternary domain. The sealed same-builder constraints enforce it;
        // these host checks only reject an invalid internal call early.
        if input
            .iter()
            .any(|value| value.value.unsigned_abs() > 1 || value.constrained.bound() != 1)
        {
            return Err(Error::Range);
        }
        let residues = input.map(|value| budget::Limited(&mut *c, phase).to_residue(value, Q));
        let lanes: [[ResidueValue; WIDTH]; LANES] = std::array::from_fn(|lane| {
            std::array::from_fn(|column| residues[column * LANES + lane])
        });
        let mut output = residues;
        for index in 0..D {
            output[index] = dot(
                c,
                &self.coefficients[index / LANES],
                &lanes[index % LANES],
                phase,
            )?;
        }
        Ok(output)
    }

    pub(super) fn ntt_many<const N: usize>(
        &self,
        c: &mut ConstraintContext<'_, '_>,
        input: &[Polynomial<SignedValue>; N],
        phase: &'static str,
    ) -> Result<[Polynomial<ResidueValue>; N], Error> {
        if N == 0 || N > 9 {
            return Err(Error::Geometry);
        }
        let mut output = [self.ntt(c, &input[0], phase)?; N];
        for i in 1..N {
            output[i] = self.ntt(c, &input[i], phase)?;
        }
        Ok(output)
    }
}

/// Inputs carry sealed canonical constraints from the same builder. Arity and
/// modulus are fixed here: neither this bound nor these constants apply to
/// QHAT. Host values generate hints only; the equation binds the existing wires.
/// The last two witness inputs are the bounded quotient and canonical remainder.
fn dot(
    c: &mut ConstraintContext<'_, '_>,
    coefficients: &[u64; WIDTH],
    input: &[ResidueValue; WIDTH],
    phase: &'static str,
) -> Result<ResidueValue, Error> {
    if coefficients.iter().any(|&coefficient| coefficient >= Q)
        || input
            .iter()
            .any(|value| value.value >= Q || u64::from(value.constrained.modulus().value()) != Q)
    {
        return Err(Error::NonCanonical);
    }
    budget::guard_phase(c, phase);
    let mut sum = 0_u128;
    let mut lhs = c.builder.constant(Val::ZERO);
    for (&coefficient, value) in coefficients.iter().zip(input) {
        sum += u128::from(coefficient) * u128::from(value.value);
        let factor = c.builder.constant(Val::from_u64(coefficient));
        let term = c.builder.mul(factor, value.constrained.wire());
        lhs = c.builder.add(lhs, term);
    }
    // Fixed arity and canonical inputs imply this independently of hints.
    if sum > SUM_BOUND {
        return Err(Error::Range);
    }
    let quotient = c.input((sum / u128::from(Q)) as u64);
    let value = (sum % u128::from(Q)) as u64;
    let remainder = c.input(value);
    pq_modular::assert_at_most(c.builder, quotient, QUOTIENT_BOUND).map_err(|_| Error::Range)?;
    let modulus = pq_modular::Modulus::new(Q as u32).map_err(|_| Error::NonCanonical)?;
    let constrained = pq_modular::canonical(c.builder, remainder, modulus);
    let q = c.builder.constant(Val::from_u64(Q));
    let multiple = c.builder.mul(quotient, q);
    let rhs = c.builder.add(multiple, remainder);
    c.builder.assert_equal(lhs, rhs);
    budget::guard_phase(c, phase);
    Ok(ResidueValue { value, constrained })
}

#[cfg(test)]
#[path = "ring_circuit_ntt/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "ring_circuit_ntt_audit.rs"]
mod audit;
