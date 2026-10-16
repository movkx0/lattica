//! Late wallet-output admission: retained proof/public backing plus one encoded
//! buffer share the configured operation allowance. This does not reserve the
//! earlier construction of those objects, other caller/configuration/driver
//! storage, diagnostics, allocator overhead, stack or the exported output's
//! subsequent lifetime. Proof arithmetic and verifier encoding stay unchanged.

use super::pcs_field::{PcsField, ProvingConfig};
use crate::config::Val;
use p3_uni_stark::Proof;
use postcard::ser_flavors::Flavor;

mod storage;
#[cfg(all(test, feature = "stream"))]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    HostLimit,
    SizeLimit,
    Encoding,
    Allocation,
}

impl From<Error> for super::leaf::LeafError {
    fn from(error: Error) -> Self {
        match error {
            Error::HostLimit | Error::Allocation => Self::GpuFailure,
            Error::SizeLimit => Self::SizeLimit,
            Error::Encoding => Self::InvalidEncoding,
        }
    }
}

/// Postcard's Size flavor adds without overflow checks or an early byte limit.
/// Count the exact same serialization with checked, bounded arithmetic instead.
struct BoundedSize {
    bytes: usize,
    limit: usize,
}

impl BoundedSize {
    fn add(&mut self, bytes: usize) -> postcard::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .filter(|total| *total <= self.limit)
            .ok_or(postcard::Error::SerializeBufferFull)?;
        Ok(())
    }
}

impl Flavor for BoundedSize {
    type Output = usize;
    fn try_push(&mut self, _byte: u8) -> postcard::Result<()> {
        self.add(1)
    }
    fn try_extend(&mut self, bytes: &[u8]) -> postcard::Result<()> {
        self.add(bytes.len())
    }
    fn finalize(self) -> postcard::Result<usize> {
        Ok(self.bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Plan {
    proof_backing_bytes: usize,
    public_backing_bytes: usize,
    prefix_bytes: usize,
    payload_bytes: usize,
    encoded_bytes: usize,
    aggregate_bytes: usize,
}

impl Plan {
    fn new<E: PcsField>(
        proof: &Proof<ProvingConfig<E>>,
        publics: &[&Vec<Val>],
        prefix: &[&[u8]],
        encoded_limit: usize,
        allowance: usize,
    ) -> Result<Self, Error> {
        let mut backing = storage::Backing::new(allowance);
        for public in publics {
            backing.vector(public)?;
        }
        let public_backing_bytes = backing.bytes();
        backing.proof(proof)?;
        let proof_backing_bytes = backing.bytes() - public_backing_bytes;
        let available = allowance
            .checked_sub(backing.bytes())
            .ok_or(Error::HostLimit)?;
        // Also enforce Rust's maximum single-allocation size.
        let encoded_limit = encoded_limit.min(isize::MAX as usize);
        let limit = available.min(encoded_limit);
        let limit_error = if encoded_limit <= available {
            Error::SizeLimit
        } else {
            Error::HostLimit
        };
        let prefix_bytes = prefix.iter().try_fold(0usize, |total, part| {
            total
                .checked_add(part.len())
                .filter(|n| *n <= limit)
                .ok_or(limit_error)
        })?;
        let payload_bytes = postcard::serialize_with_flavor(
            proof,
            BoundedSize {
                bytes: 0,
                limit: limit - prefix_bytes,
            },
        )
        .map_err(|error| match error {
            postcard::Error::SerializeBufferFull => limit_error,
            _ => Error::Encoding,
        })?;
        // The bounded census above admits both additions before allocation.
        let encoded_bytes = prefix_bytes + payload_bytes;
        let aggregate_bytes = backing.bytes() + encoded_bytes;
        Ok(Self {
            proof_backing_bytes,
            public_backing_bytes,
            prefix_bytes,
            payload_bytes,
            encoded_bytes,
            aggregate_bytes,
        })
    }
}

fn encode<E: PcsField>(
    proof: &Proof<ProvingConfig<E>>,
    publics: &[&Vec<Val>],
    prefix: &[&[u8]],
    encoded_limit: usize,
    allowance: usize,
) -> Result<(Vec<u8>, Plan), Error> {
    let plan = Plan::new(proof, publics, prefix, encoded_limit, allowance)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(plan.encoded_bytes)
        .map_err(|_| Error::Allocation)?;
    if bytes.capacity() != plan.encoded_bytes {
        return Err(Error::Allocation);
    }
    bytes.resize(plan.encoded_bytes, 0);
    let mut offset = 0;
    for part in prefix {
        bytes[offset..offset + part.len()].copy_from_slice(part);
        offset += part.len();
    }
    let encoded = postcard::to_slice(proof, &mut bytes[offset..]).map_err(|_| Error::Encoding)?;
    if encoded.len() != plan.payload_bytes {
        return Err(Error::Encoding);
    }
    Ok((bytes, plan))
}

/// Callers supply every retained public vector and only borrowed prefix bytes.
/// The sealed proof fields have allocation-free serializers. The count and write
/// borrow the same immutable proof; no intervening mutation can change its size.
pub(super) fn serialize<E: PcsField>(
    proof: &Proof<ProvingConfig<E>>,
    publics: &[&Vec<Val>],
    prefix: &[&[u8]],
    encoded_limit: usize,
    allowance: usize,
) -> Result<Vec<u8>, Error> {
    let (bytes, plan) = encode(proof, publics, prefix, encoded_limit, allowance)?;
    eprintln!(
        "bounded_wallet_serialization proof_backing_bytes={} public_backing_bytes={} prefix_bytes={} payload_bytes={} encoded_bytes={} aggregate_bytes={} allowance_bytes={} encoded_limit_bytes={} whole_proof=false",
        plan.proof_backing_bytes, plan.public_backing_bytes, plan.prefix_bytes,
        plan.payload_bytes, plan.encoded_bytes, plan.aggregate_bytes, allowance, encoded_limit,
    );
    Ok(bytes)
}
