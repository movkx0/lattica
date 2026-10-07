//! Bounded public host-policy bindings for a persistent local worker session.
//! These are not consensus statements or permission to disclose wallet witnesses.
//! The coordinator derives `binding` from its independently checked native head,
//! candidate, and policy. Remote transport must authenticate that authority.

use super::job::{ArtifactKind, ArtifactRef};
use crate::block_v2::{recursive::Error, typed_recursive::Policy};

const MAGIC: &[u8; 8] = b"LVPCX001";
const ENTRY_BYTES: usize = 32 + 4 + 1 + 8;
pub const MAX_BYTES: usize = 8 + 32 + 4 + 64 * ENTRY_BYTES;

#[derive(Clone)]
pub struct PolicyContext {
    binding: [u8; 32],
    policies: Vec<(ArtifactRef, Policy)>,
}

impl PolicyContext {
    pub fn new(binding: [u8; 32], policies: Vec<(ArtifactRef, Policy)>) -> Result<Self, Error> {
        if binding == [0; 32] || policies.len() > 64 {
            return Err("worker context binding/count".into());
        }
        for (index, (artifact, policy)) in policies.iter().enumerate() {
            if artifact.kind() != ArtifactKind::Wallet
                || policies[..index].iter().any(|(a, _)| a == artifact)
            {
                return Err("worker context requires distinct public wallet artifacts".into());
            }
            match policy {
                Policy::Htlc { expected_height } if *expected_height >= 1 << 52 => {
                    return Err("worker context height".into())
                }
                Policy::Issuance { authorized_mint }
                    if *authorized_mint == 0 || *authorized_mint >= 1 << 52 =>
                {
                    return Err("worker context issuance".into())
                }
                _ => {}
            }
        }
        Ok(Self { binding, policies })
    }

    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub fn policy(&self, artifact: ArtifactRef) -> Result<Policy, Error> {
        self.policies
            .iter()
            .find(|(a, _)| *a == artifact)
            .map(|(_, p)| *p)
            .ok_or_else(|| "wallet artifact absent from current host policy".into())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend(self.binding);
        bytes.extend((self.policies.len() as u32).to_le_bytes());
        for (artifact, policy) in &self.policies {
            bytes.extend(artifact.digest_bytes());
            bytes.extend(artifact.byte_len().to_le_bytes());
            let (kind, value) = match policy {
                Policy::JoinSplit => (0, 0),
                Policy::Htlc { expected_height } => (1, *expected_height),
                Policy::Issuance { authorized_mint } => (2, *authorized_mint),
            };
            bytes.push(kind);
            bytes.extend(value.to_le_bytes());
        }
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 44 || bytes.len() > MAX_BYTES || &bytes[..8] != MAGIC {
            return Err("worker context size/version".into());
        }
        let count = u32::from_le_bytes(bytes[40..44].try_into()?) as usize;
        if count > 64 || bytes.len() != 44 + count * ENTRY_BYTES {
            return Err("worker context noncanonical length".into());
        }
        let mut policies = Vec::with_capacity(count);
        for entry in bytes[44..].chunks_exact(ENTRY_BYTES) {
            let artifact = ArtifactRef::from_descriptor(
                ArtifactKind::Wallet,
                u32::from_le_bytes(entry[32..36].try_into()?),
                entry[..32].try_into()?,
            )?;
            let value = u64::from_le_bytes(entry[37..45].try_into()?);
            let policy = match (entry[36], value) {
                (0, 0) => Policy::JoinSplit,
                (1, expected_height) => Policy::Htlc { expected_height },
                (2, authorized_mint) => Policy::Issuance { authorized_mint },
                _ => return Err("worker context policy encoding".into()),
            };
            policies.push((artifact, policy));
        }
        Self::new(bytes[8..40].try_into()?, policies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn context_roundtrip_rejects_stale_artifacts_and_mutated_lengths() {
        let wallet = ArtifactRef::from_bytes(ArtifactKind::Wallet, b"public proof").unwrap();
        let other = ArtifactRef::from_bytes(ArtifactKind::Wallet, b"different proof").unwrap();
        let context = PolicyContext::new(
            [1; 32],
            vec![(
                wallet,
                Policy::Htlc {
                    expected_height: 42,
                },
            )],
        )
        .unwrap();
        let bytes = context.encode();
        let decoded = PolicyContext::decode(&bytes).unwrap();
        assert_eq!(decoded.binding(), [1; 32]);
        assert!(matches!(
            decoded.policy(wallet).unwrap(),
            Policy::Htlc {
                expected_height: 42
            }
        ));
        assert!(decoded.policy(other).is_err());
        for len in 0..bytes.len() {
            assert!(PolicyContext::decode(&bytes[..len]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PolicyContext::decode(&trailing).is_err());
        assert!(PolicyContext::new(
            [1; 32],
            vec![(wallet, Policy::JoinSplit), (wallet, Policy::JoinSplit)]
        )
        .is_err());
    }

    #[test]
    fn context_rejects_noncanonical_policy_and_node_artifacts() {
        let wallet = ArtifactRef::from_bytes(ArtifactKind::Wallet, b"proof").unwrap();
        let mut bytes = PolicyContext::new([2; 32], vec![(wallet, Policy::JoinSplit)])
            .unwrap()
            .encode();
        bytes[44 + 37] = 1;
        assert!(PolicyContext::decode(&bytes).is_err());
        assert!(PolicyContext::new(
            [1; 32],
            vec![(wallet, Policy::Issuance { authorized_mint: 0 })]
        )
        .is_err());
        let node = ArtifactRef::from_bytes(ArtifactKind::Node, b"proof").unwrap();
        assert!(PolicyContext::new([1; 32], vec![(node, Policy::JoinSplit)]).is_err());
    }
}
