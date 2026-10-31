//! Fixed symbolic container scratch, reserved before the actual imports.
//! Raw native return buffers and adapters are a separate ownership layer.
use super::super::*;
use super::bounds::{add, backing, mul};
use super::collections::Collections;
use core::mem::size_of;

type Error = &'static str;
type Canonical = Polynomial<ResidueRef>;
type Signed = Polynomial<SignedRef>;
type ImportedStatement = GStatement<ResidueRef, ByteRef>;
type ImportedProof = GProof<ResidueRef, SignedRef, ByteRef>;

// All source vectors here start empty/exact or collect from borrowed fixed
// slices. None inherits an owned native allocation. Three times the logical
// length covers old/new vector backing, including f's one-to-twelve growth.
fn growing<T>(count: usize) -> Result<usize, Error> {
    backing::<T>(mul(3, count)?)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct SymbolicScratch {
    pub(super) imported_bytes: usize,
    pub(super) parameter_bytes: usize,
    pub(super) relation_bytes: usize,
    pub(super) collection_bytes: usize,
    pub(super) requested_bytes: usize,
}
impl SymbolicScratch {
    pub(super) fn fixed() -> Result<Self, Error> {
        let imported_bytes = add(
            add(growing::<Canonical>(198 + 9)?, growing::<Signed>(78)?)?,
            add(
                add(
                    growing::<[GAccount<ResidueRef>; 2]>(10)?,
                    add(
                        growing::<Vec<Canonical>>(2 + 2)?,
                        growing::<Vec<Signed>>(2)?,
                    )?,
                )?,
                add(size_of::<ImportedStatement>(), size_of::<ImportedProof>())?,
            )?,
        )?;
        let parameter_bytes = add(
            add(
                growing::<Canonical>(7 * 4 + 4 * 3 + 29 * 5)?,
                growing::<Vec<Canonical>>(7 + 4 + 29)?,
            )?,
            size_of::<GParameters<ResidueRef, ByteRef>>(),
        )?;
        // generic::verify_relation's 23 named heap containers. f is signed;
        // every other polynomial container uses the canonical reference type.
        let canonical_arrays = [
            18, // z_out
            9,  // z0
            8,  // w_out
            4,  // w0
            50, // t_in
            12, // f_ntt
            12, // f_qhat
            11, // z1
            11, // z2
            4,  // w1
            4,  // w2
            3,  // h
            3,  // hx
            2,  // alpha
            10, // zb
            12, // g_qhat
            5,  // a
            4,  // gamma0
            4,  // gamma1
            40, // p
            8,  // z
            4,  // e
        ]
        .into_iter()
        .try_fold(0, add)?;
        let relation_bytes = add(
            add(
                growing::<Canonical>(canonical_arrays)?,
                growing::<Signed>(12)?,
            )?,
            add(
                // z_out, w_out, t_in and p own these inner Vec descriptors.
                growing::<Vec<Canonical>>(2 + 2 + 10 + 10)?,
                // Top-level descriptors are inline, not another heap Vec.
                backing::<Vec<Canonical>>(23)?,
            )?,
        )?;
        let collection_bytes = Collections::fixed()?.partial_constructor_requested_bytes;
        let requested_bytes = add(
            add(imported_bytes, parameter_bytes)?,
            add(relation_bytes, collection_bytes)?,
        )?;
        Ok(Self {
            imported_bytes,
            parameter_bytes,
            relation_bytes,
            collection_bytes,
            requested_bytes,
        })
    }
}

/// Source-drift check after the already reserved exact import path. It cannot
/// admit arbitrary caller allocations and is not the source of the bound.
pub(super) fn check_imported_storage(
    statement: &ImportedStatement,
    proof: &ImportedProof,
) -> Result<(), Error> {
    let bound = SymbolicScratch::fixed()?.imported_bytes;
    if imported_retained_bytes(statement, proof)? > bound {
        return Err("source graph symbolic import exceeds its preceding bound");
    }
    Ok(())
}

fn imported_retained_bytes(
    statement: &ImportedStatement,
    proof: &ImportedProof,
) -> Result<usize, Error> {
    let mut bytes = add(size_of::<ImportedStatement>(), size_of::<ImportedProof>())?;
    bytes = add(
        bytes,
        backing::<[GAccount<ResidueRef>; 2]>(statement.ring.capacity())?,
    )?;
    for account in statement.ring.iter().flatten() {
        bytes = add(bytes, backing::<Canonical>(account.pk.capacity())?)?;
        bytes = add(bytes, backing::<Canonical>(account.cn.capacity())?)?;
    }
    for rows in [&statement.recipients, &statement.coins] {
        bytes = add(bytes, backing::<Vec<Canonical>>(rows.capacity())?)?;
        for row in rows {
            bytes = add(bytes, backing::<Canonical>(row.capacity())?)?;
        }
    }
    for row in [&proof.v, &proof.b] {
        bytes = add(bytes, backing::<Canonical>(row.capacity())?)?;
    }
    bytes = add(bytes, backing::<Vec<Signed>>(proof.z_out.capacity())?)?;
    for row in proof.z_out.iter().chain([
        &proof.z0, &proof.z1, &proof.z2, &proof.f1, &proof.zb, &proof.z,
    ]) {
        bytes = add(bytes, backing::<Signed>(row.capacity())?)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
