//! Graph-vector storage derived from the exact fixed n10 constructor.
//! These shared formulas replace the census-only copy. They cover graph
//! payloads/growth, not memo maps, symbolic imports, raw operations or runtime.
use super::super::*;
use core::mem::size_of;
type Error = &'static str;
pub(super) fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or("graph storage sum overflow")
}
pub(super) fn mul(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_mul(b).ok_or("graph storage product overflow")
}
pub(super) fn backing<T>(capacity: usize) -> Result<usize, Error> {
    mul(capacity, size_of::<T>())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rust_verify::committed_backend) struct Ceilings {
    pub(in crate::rust_verify::committed_backend) polynomials: usize,
    pub(in crate::rust_verify::committed_backend) bytes: usize,
    pub(in crate::rust_verify::committed_backend) expressions: usize,
    pub(in crate::rust_verify::committed_backend) operations: usize,
    pub(in crate::rust_verify::committed_backend) canonical_lookups: usize,
    pub(in crate::rust_verify::committed_backend) signed_lookups: usize,
    pub(in crate::rust_verify::committed_backend) byte_lookups: usize,
    pub(in crate::rust_verify::committed_backend) constant_calls: usize,
    pub(in crate::rust_verify::committed_backend) alpha_parts: usize,
    pub(in crate::rust_verify::committed_backend) x_parts: usize,
    pub(in crate::rust_verify::committed_backend) norm_inputs: usize,
}
impl Ceilings {
    /// Fixed loops in generic::verify_relation, using CommittedBackend's whole
    /// polynomial overrides. Every identity lookup is conservatively a miss.
    pub(in crate::rust_verify::committed_backend) const fn fixed() -> Self {
        let linear_products = (5 + 5 + 5 + 7 + 7 + 4) * 4;
        let auxiliary_products = 4 + 4 + 2 + 2 + 4 + 4;
        let other_multiply_add = 2 + 1 + 10 + 2 + 1 + 25 + 12 * 5 * 2;
        let multiply_add = linear_products + auxiliary_products + other_multiply_add;
        let multiply_sub = 2 * 4 + 10 * 4 + 2 * 4 + 2 + 1 + 5 + 10 * 4;
        let standalone_products = 1 + 3 + 1 + 12 + 10 * 4;
        let products = multiply_add + multiply_sub + standalone_products;
        let adds = multiply_add + (10 * 5 + 2 + 3 + 1 + 10 * 4);
        let subs = multiply_sub + (2 + 1 + 1 + 1 + 12 + 10 * 4 * 2);
        let automorphisms = 2;
        let ntt = 3 + 18 + 9 + 12 + 12 + 11 + 11 + 10 + 1 + 8;
        let whole = adds + subs + products + automorphisms;
        let parameters = 7 * 4 + 4 * 3 + 29 * 5;
        let alpha_polynomials = 10 * 2 * (4 + 5) + 2 * 4 + 2 * 5 + 2 * 4 + 4 + 4 + 3 + 4 + 4;
        let x_polynomials = 1 + 1 + 5 + 5 + 4;
        let canonical_lookups = 2 * (adds + subs + products)
            + automorphisms
            + parameters
            + alpha_polynomials
            + x_polynomials;
        let norm_inputs = 9 + 9 + 9 + 11 + 11 + 8;
        let signed_lookups = ntt + norm_inputs + 12 * 2 + 2;
        let byte_lookups = 2 * 2 + 1 + 2 + 1 + 3 + 1;
        let imported_polynomials = 10 * 2 * (4 + 5) + 2 * 4 + 2 * 5 + 12 + 79;
        let polynomials = imported_polynomials
            + whole
            + 2 * ntt
            + 2 * 4
            + 3
            + 1
            + canonical_lookups
            + signed_lookups;
        // One zero in verify_relation; two column-2 auxiliary zero calls.
        let constant_calls = parameters * D + 3;
        let scalar_expressions = 9 * D + 85 + 5 * D + 4 * D + 4 * 5;
        let expressions = polynomials * D + constant_calls + scalar_expressions;
        let operations = whole
            + 2 * ntt
            + 6
            + 12
            + 2
            + 1
            + 1
            + 2
            + 1
            + 1
            + 1
            + canonical_lookups
            + signed_lookups
            + byte_lookups;
        Self {
            polynomials,
            bytes: 5 + 1 + 1 + 1 + byte_lookups,
            expressions,
            operations,
            canonical_lookups,
            signed_lookups,
            byte_lookups,
            constant_calls,
            alpha_parts: alpha_polynomials + 3,
            x_parts: x_polynomials + 1,
            norm_inputs,
        }
    }

    pub(in crate::rust_verify::committed_backend) fn main_vector_bytes(
        self,
        factor: usize,
    ) -> Result<usize, Error> {
        let mut total = 0;
        for bytes in [
            backing::<PolynomialNode>(mul(factor, self.polynomials)?)?,
            backing::<BytesNode>(mul(factor, self.bytes)?)?,
            backing::<Expression>(mul(factor, self.expressions)?)?,
            backing::<Operation>(mul(factor, self.operations)?)?,
        ] {
            total = add(total, bytes)?;
        }
        Ok(total)
    }

    pub(in crate::rust_verify::committed_backend) fn nested_vector_bytes(
        self,
        factor: usize,
    ) -> Result<usize, Error> {
        let map_calls = add(self.canonical_lookups, self.signed_lookups)?;
        // Each dependency set contains at most every graph polynomial once.
        let ids = add(mul(map_calls, self.polynomials)?, self.norm_inputs)?;
        let parts = add(self.alpha_parts, self.x_parts)?;
        add(
            backing::<PolyId>(mul(factor, ids)?)?,
            backing::<TranscriptPart>(mul(factor, parts)?)?,
        )
    }
}
