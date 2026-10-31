//! Allocation-free raw shape and retained-capacity boundary. This verifies
//! dimensions only; it is not native verification or source authentication.
use super::super::*;
use core::mem::size_of;

type Error = &'static str;
fn add(a: usize, b: usize) -> Result<usize, Error> {
    a.checked_add(b).ok_or("decoded input storage sum overflow")
}
fn backing<T>(capacity: usize) -> Result<usize, Error> {
    capacity
        .checked_mul(size_of::<T>())
        .ok_or("decoded input storage product overflow")
}

/// The actual constructor imports through this immutable view, preventing a
/// shape check from referring to different or subsequently mutated inputs.
pub(in crate::rust_verify::committed_backend) struct FixedInputs<'a> {
    statement: &'a Statement,
    proof: &'a Proof,
}

impl<'a> FixedInputs<'a> {
    pub(in crate::rust_verify::committed_backend) fn inspect(
        statement: &'a Statement,
        proof: &'a Proof,
    ) -> Result<Self, Error> {
        if statement.ring.len() != 10
            || statement
                .ring
                .iter()
                .flatten()
                .any(|a| a.pk.len() != 4 || a.cn.len() != 5)
            || statement.recipients.len() != 2
            || statement.recipients.iter().any(|a| a.len() != 4)
            || statement.coins.len() != 2
            || statement.coins.iter().any(|a| a.len() != 5)
            || proof.v.len() != 4
            || proof.b.len() != 5
            || proof.z_out.len() != 2
            || proof.z_out.iter().any(|z| z.len() != 9)
            || proof.z0.len() != 9
            || proof.z1.len() != 11
            || proof.z2.len() != 11
            || proof.f1.len() != 11
            || proof.zb.len() != 10
            || proof.z.len() != 8
        {
            return Err("graph requires the fixed n10 native dimensions");
        }
        Ok(Self { statement, proof })
    }

    pub(in crate::rust_verify::committed_backend) fn statement(&self) -> &'a Statement {
        self.statement
    }

    pub(in crate::rust_verify::committed_backend) fn proof(&self) -> &'a Proof {
        self.proof
    }

    /// Includes real spare capacity at every nested Vec, plus inline structs.
    /// Inspecting these bytes does not retroactively own their allocation.
    pub(in crate::rust_verify::committed_backend) fn retained_bytes(&self) -> Result<usize, Error> {
        let s = self.statement;
        let p = self.proof;
        let mut bytes = add(size_of::<Statement>(), size_of::<Proof>())?;
        bytes = add(bytes, backing::<[Account; 2]>(s.ring.capacity())?)?;
        for account in s.ring.iter().flatten() {
            bytes = add(bytes, backing::<[u64; D]>(account.pk.capacity())?)?;
            bytes = add(bytes, backing::<[u64; D]>(account.cn.capacity())?)?;
        }
        for outer in [&s.recipients, &s.coins] {
            bytes = add(bytes, backing::<Vec<[u64; D]>>(outer.capacity())?)?;
            for row in outer {
                bytes = add(bytes, backing::<[u64; D]>(row.capacity())?)?;
            }
        }
        for row in [&p.v, &p.b] {
            bytes = add(bytes, backing::<[u64; D]>(row.capacity())?)?;
        }
        bytes = add(bytes, backing::<Vec<[i64; D]>>(p.z_out.capacity())?)?;
        for row in p
            .z_out
            .iter()
            .chain([&p.z0, &p.z1, &p.z2, &p.f1, &p.zb, &p.z])
        {
            bytes = add(bytes, backing::<[i64; D]>(row.capacity())?)?;
        }
        Ok(bytes)
    }
}

/// The maintained decoder uses exact `with_capacity`/`vec!` requests and never
/// grows these vectors. Four one-polynomial temporary Vecs (c/v1/v2/x) retire
/// during Proof::decode; conservatively charge all four at once separately.
pub(super) fn decoded_retained_bytes() -> Result<usize, Error> {
    let mut bytes = add(size_of::<Statement>(), size_of::<Proof>())?;
    bytes = add(bytes, backing::<[Account; 2]>(10)?)?;
    bytes = add(bytes, backing::<Vec<[u64; D]>>(2 + 2)?)?;
    bytes = add(bytes, backing::<Vec<[i64; D]>>(2)?)?;
    // Statement 198, proof heap canonical 9, proof heap signed 78. Four
    // inline proof polynomials are already included in size_of::<Proof>().
    bytes = add(bytes, backing::<[u64; D]>(198 + 9)?)?;
    add(bytes, backing::<[i64; D]>(78)?)
}

pub(super) fn decode_temporary_bytes() -> Result<usize, Error> {
    backing::<[u64; D]>(4)
}
