//! Explicit exact NTT-ring polynomial-product proof obligations.
//! A pending product is an untrusted hint until its typed component proof is
//! verified and every canonical operand/output commitment is joined.
use super::{
    arithmetic,
    constraints::{ConstraintContext, ResidueValue},
    constraints_ntt::commit,
    generic::Polynomial,
};
use lattica_prover_p3::block_v2::machine::program::Wire;

#[derive(Clone, Debug)]
pub struct PendingMul {
    pub modulus: u64,
    pub left: Polynomial<ResidueValue>,
    pub right: Polynomial<ResidueValue>,
    pub output: Polynomial<ResidueValue>,
    pub left_commitment: [Wire; 4],
    pub right_commitment: [Wire; 4],
    pub output_commitment: [Wire; 4],
}

pub fn request_mul(
    c: &mut ConstraintContext<'_, '_>,
    left: &Polynomial<ResidueValue>,
    right: &Polynomial<ResidueValue>,
    modulus: u64,
) -> Polynomial<ResidueValue> {
    let values = arithmetic::mul(&left.map(|v| v.value), &right.map(|v| v.value), modulus);
    let output = values.map(|value| c.residue(value, modulus));
    let left_commitment = commit(c, modulus, left);
    let right_commitment = commit(c, modulus, right);
    let output_commitment = commit(c, modulus, &output);
    c.crypto.mul.push(PendingMul {
        modulus,
        left: *left,
        right: *right,
        output,
        left_commitment,
        right_commitment,
        output_commitment,
    });
    output
}
