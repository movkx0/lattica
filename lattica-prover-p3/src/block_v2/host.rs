//! Versioned CPU root verification for the research host integration.
//!
//! The host derives the ordered root from complete public transaction envelopes
//! and supplies its own registry pin and chain context. This API does not infer
//! issuance authority, choose a registry from a proof, apply state, or activate
//! a candidate consensus profile.

use super::{
    codec,
    commitment::{self, Context, NodeSummary},
    machine::{programs, typed_pairs},
    profile,
    recursive::Error,
    typed_recursive::Registry,
};

#[path = "host_wallet.rs"]
pub mod wallet;

pub const REGISTRY_MAGIC: &[u8; 8] = b"LBV2RG01";
pub const EXPECTED_MAGIC: &[u8; 8] = b"LBV2EX01";
pub const MAX_REGISTRY_BYTES: usize = 64 * 1024;
pub const EXPECTED_BYTES: usize = 112;

/// The registry comes from trusted host configuration, independently of a
/// submitted block. Canonical decoding rejects alternate/trailing encodings.
pub fn encode_registry(registry: &Registry<12>) -> Result<Vec<u8>, Error> {
    registry.id()?;
    let mut bytes = REGISTRY_MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(registry)?);
    if bytes.len() > MAX_REGISTRY_BYTES {
        return Err("research host registry size".into());
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expected {
    pub context: Context,
    pub root: commitment::Digest,
    pub count: u8,
}

impl Expected {
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != EXPECTED_BYTES || !bytes.starts_with(EXPECTED_MAGIC) {
            return Err("research host expectation version/length".into());
        }
        let count = u64::from_le_bytes(bytes[104..112].try_into()?);
        if !(1..=64).contains(&count) {
            return Err("research host root count".into());
        }
        Ok(Self {
            context: Context {
                profile_id: bytes[8..40].try_into()?,
                chain_id: bytes[40..72].try_into()?,
            },
            root: commitment::digest_from_bytes(&bytes[72..104])?,
            count: count as u8,
        })
    }

    pub fn encode(self) -> Result<[u8; EXPECTED_BYTES], Error> {
        if !(1..=64).contains(&self.count) {
            return Err("research host root count".into());
        }
        let mut bytes = [0; EXPECTED_BYTES];
        bytes[..8].copy_from_slice(EXPECTED_MAGIC);
        bytes[8..40].copy_from_slice(&self.context.profile_id);
        bytes[40..72].copy_from_slice(&self.context.chain_id);
        bytes[72..104].copy_from_slice(&commitment::digest_bytes(self.root)?);
        bytes[104..].copy_from_slice(&u64::from(self.count).to_le_bytes());
        Ok(bytes)
    }
}

pub fn verify_root(
    registry_bytes: &[u8],
    expected_bytes: &[u8],
    proof: &[u8],
) -> Result<(), Error> {
    if registry_bytes.len() > MAX_REGISTRY_BYTES
        || !registry_bytes.starts_with(REGISTRY_MAGIC)
        || proof.is_empty()
        || proof.len() > profile::MAX_PROOF_BYTES
    {
        return Err("research host registry/proof bounds".into());
    }
    let expected = Expected::decode(expected_bytes)?;
    let registry: Registry<12> = codec::decode(&registry_bytes[REGISTRY_MAGIC.len()..])?;
    if registry.id()? != expected.context.profile_id {
        return Err("research host registry differs from independently pinned profile".into());
    }
    let public = programs::statement(
        NodeSummary {
            context: expected.context,
            root: expected.root,
            count: expected.count,
            level: commitment::DEPTH,
        },
        if expected.count <= 32 {
            typed_pairs::FINALIZE
        } else {
            programs::MERGE
        },
    );
    let node = codec::decode_node(proof)?;
    registry.verify(expected.context.profile_id, &node, &public)
}

/// Version 1 of the opt-in research verifier. Returns 0 only on success.
///
/// # Safety
/// Each nonempty pointer/length pair must describe a live readable allocation
/// for the duration of the call. The host must obtain the expected context and
/// registry from its own trusted configuration, not from the submitted proof.
#[no_mangle]
pub unsafe extern "C" fn lattica_v2_research_root_verify_v1(
    proof: *const u8,
    proof_len: usize,
    expected: *const u8,
    expected_len: usize,
    registry: *const u8,
    registry_len: usize,
) -> i32 {
    if proof.is_null()
        || expected.is_null()
        || registry.is_null()
        || proof_len == 0
        || proof_len > profile::MAX_PROOF_BYTES
        || expected_len != EXPECTED_BYTES
        || registry_len < REGISTRY_MAGIC.len()
        || registry_len > MAX_REGISTRY_BYTES
    {
        return -1;
    }
    std::panic::catch_unwind(|| {
        // SAFETY: caller supplies readable allocations; sizes and null pointers
        // were checked before constructing slices. No input is mutated.
        let (proof, expected, registry) = unsafe {
            (
                std::slice::from_raw_parts(proof, proof_len),
                std::slice::from_raw_parts(expected, expected_len),
                std::slice::from_raw_parts(registry, registry_len),
            )
        };
        if verify_root(registry, expected, proof).is_ok() {
            0
        } else {
            -1
        }
    })
    .unwrap_or(-2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expectation_is_versioned_exact_and_canonical() {
        let expected = Expected {
            context: Context {
                profile_id: [7; 32],
                chain_id: [9; 32],
            },
            root: [0, 1, commitment::MODULUS - 1, 99],
            count: 64,
        };
        let bytes = expected.encode().unwrap();
        assert_eq!(Expected::decode(&bytes).unwrap(), expected);
        assert!(Expected::decode(&bytes[..111]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(Expected::decode(&trailing).is_err());
        for count in [0, 65, u64::MAX] {
            let mut bad = bytes;
            bad[104..].copy_from_slice(&count.to_le_bytes());
            assert!(Expected::decode(&bad).is_err());
        }
        let mut bad = bytes;
        bad[72..80].copy_from_slice(&commitment::MODULUS.to_le_bytes());
        assert!(Expected::decode(&bad).is_err());
        let mut bad = bytes;
        bad[7] ^= 1;
        assert!(Expected::decode(&bad).is_err());
    }

    #[test]
    fn malformed_abi_inputs_fail_before_pointer_access() {
        let p = std::ptr::null();
        // SAFETY: every call is rejected by the null/size guards.
        unsafe {
            assert_ne!(
                lattica_v2_research_root_verify_v1(p, 0, p, EXPECTED_BYTES, p, 8),
                0
            );
            assert_ne!(
                lattica_v2_research_root_verify_v1(p, usize::MAX, p, usize::MAX, p, usize::MAX),
                0
            );
        }
    }
}
