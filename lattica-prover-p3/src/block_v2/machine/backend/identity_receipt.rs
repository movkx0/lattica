//! A bounded in-process index for an identity already computed on the GPU.
//!
//! SHA3-512 here hashes public registration metadata for cache lookup. It does
//! not replace or evaluate the protocol's Poseidon execution-program identity.
//! Reuse relies on SHA3-512 collision resistance, in addition to the protocol's
//! existing assumptions. No receipt is accepted from serialized/untrusted data.
use crate::block_v2::commitment::MODULUS;
use sha3::{Digest, Sha3_512};

const CACHE_DOMAIN: &[u8] = b"lattica/gpu-registered-identity-cache/sha3-512/v1";

#[cfg(test)]
std::thread_local! {
    static GPU_HASHES: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

#[cfg(test)]
pub(super) fn full_gpu_hash_completed() {
    GPU_HASHES.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(super) fn full_gpu_hashes() -> u64 {
    GPU_HASHES.with(core::cell::Cell::get)
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct StreamFingerprint {
    domain: u64,
    fields: u64,
    digest: [u8; 64],
}

/// An opaque identity result from successful GPU registration, with no heap
/// allocation or serialization API. It retains neither proof nor witness data.
///
/// Callers may clone/cache this hint, but cannot supply its protocol identity or
/// fingerprint. Every use rechecks the complete current identity stream,
/// including the actual freshly computed preprocessing-cap roots. Mismatches
/// run the original GPU identity hash; they never select a CPU fallback.
#[derive(Clone)]
pub struct RegisteredIdentityReceipt {
    id: [u64; 4],
    fingerprint: StreamFingerprint,
}

impl RegisteredIdentityReceipt {
    /// Exact inline payload size. Container capacity/keys must be charged by the
    /// caller; this value must not be added again if sizeof(container entry)
    /// already includes the receipt inline. There are no heap allocations.
    pub const fn accounted_bytes(&self) -> usize {
        core::mem::size_of::<Self>()
    }

    // Only the GPU registration implementation calls this constructor. The
    // enclosing RegisteredProgram is returned only after Run::finish and all
    // preprocessing/storage admission gates succeed.
    pub(super) fn from_gpu_result(id: [u64; 4], fingerprint: StreamFingerprint) -> Self {
        Self { id, fingerprint }
    }

    pub(super) fn matching_id(&self, fingerprint: &StreamFingerprint) -> Option<[u64; 4]> {
        (self.fingerprint == *fingerprint).then_some(self.id)
    }
}

impl StreamFingerprint {
    pub(super) fn fields(&self) -> u64 {
        self.fields
    }
}

/// Two bounded passes over immutable public metadata: count/validate, then hash
/// the exact domain, total field count, and little-endian canonical field stream.
/// The emitter is internal and reads immutable Program/CommonData/constraints.
pub(super) fn fingerprint_stream(
    domain: u64,
    mut emit: impl FnMut(&mut dyn FnMut(u64) -> Result<(), String>) -> Result<(), String>,
) -> Result<StreamFingerprint, String> {
    if domain >= MODULUS {
        return Err("identity cache domain is not canonical".into());
    }
    let mut fields = 0u64;
    emit(&mut |field| {
        if field >= MODULUS {
            return Err("identity cache field is not canonical".into());
        }
        fields = fields
            .checked_add(1)
            .ok_or("identity cache field count overflow")?;
        if fields >= MODULUS {
            return Err("identity cache field count is not canonical".into());
        }
        Ok(())
    })?;
    let mut hash = Sha3_512::new();
    hash.update(CACHE_DOMAIN);
    hash.update(domain.to_le_bytes());
    hash.update(fields.to_le_bytes());
    let mut observed = 0u64;
    emit(&mut |field| {
        if field >= MODULUS || observed >= fields {
            return Err("identity cache stream is noncanonical or changed length".into());
        }
        hash.update(field.to_le_bytes());
        observed += 1;
        Ok(())
    })?;
    if observed != fields {
        return Err("identity cache stream changed length".into());
    }
    Ok(StreamFingerprint {
        domain,
        fields,
        digest: hash.finalize().into(),
    })
}

#[cfg(test)]
mod tests;
