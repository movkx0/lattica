//! Canonical encoding of the closed, immutable native descriptor vocabulary.
use super::{unchanged::OtherNativeDescriptor, NativeDescriptor};
use crate::{
    affine_air::AffineKind, graph_proofs::ComponentKind, permutation_air::PermutationKind,
    sparse_air, transcript_air::PartKind, uniform_air,
};
use sha3::{Digest, Sha3_256};

pub(crate) trait DescriptorKey {
    fn encode(&self, hash: &mut Sha3_256);
    fn family(&self) -> usize;
    #[cfg(test)]
    fn portable(&self) -> Option<super::cache::PortableDescriptor> { None }
    #[cfg(test)]
    fn portable_heap_bytes(&self) -> Option<usize> { None }
}
fn word(hash: &mut Sha3_256, value: usize) {
    hash.update((value as u64).to_le_bytes());
}
impl DescriptorKey for NativeDescriptor<'_> {
    #[cfg(test)]
    fn portable_heap_bytes(&self) -> Option<usize> {
        match self {
            Self::Aes { .. } | Self::Shake { .. } => Some(0),
            Self::Transcript(parts) => Some(parts.len()),
            _ => None,
        }
    }
    #[cfg(test)]
    fn portable(&self) -> Option<super::cache::PortableDescriptor> {
        match *self {
            Self::Aes { descriptor, first, count } => Some(super::cache::PortableDescriptor::Aes {
                domain: descriptor.domain, start_counter: descriptor.start_counter, output_len: descriptor.output_len, first, count }),
            Self::Transcript(parts) => Some(super::cache::PortableDescriptor::Transcript {
                parts: parts.iter().map(|p| match p { PartKind::Bytes32 => 0, PartKind::PolynomialQ => 1, PartKind::PolynomialQhat => 2 }).collect() }),
            Self::Shake { descriptor, first, count } => Some(super::cache::PortableDescriptor::Shake {
                input_len: descriptor.input_len, output_len: descriptor.output_len, first, count }),
            _ => None,
        }
    }
    fn family(&self) -> usize {
        match self {
            Self::Aes { .. } => 0,
            Self::Shake { .. } => 1,
            Self::Transcript(_) => 2,
            Self::Sparse(_) => 3,
            Self::Uniform(_) => 4,
        }
    }
    fn encode(&self, h: &mut Sha3_256) {
        match *self {
            Self::Aes {
                descriptor,
                first,
                count,
            } => {
                h.update([0]);
                h.update(descriptor.domain.to_le_bytes());
                h.update(descriptor.start_counter.to_le_bytes());
                for n in [descriptor.output_len, first, count] {
                    word(h, n);
                }
            }
            Self::Shake {
                descriptor,
                first,
                count,
            } => {
                h.update([1]);
                for n in [descriptor.input_len, descriptor.output_len, first, count] {
                    word(h, n);
                }
            }
            Self::Transcript(parts) => {
                h.update([2]);
                word(h, parts.len());
                for part in parts {
                    h.update([match part {
                        PartKind::Bytes32 => 0,
                        PartKind::PolynomialQ => 1,
                        PartKind::PolynomialQhat => 2,
                    }]);
                }
            }
            Self::Sparse(kind) => h.update([
                3,
                match kind {
                    sparse_air::Kind::AlphaPrime39 => 0,
                    sparse_air::Kind::ChallengeX44 => 1,
                },
            ]),
            Self::Uniform(kind) => h.update([
                4,
                match kind {
                    uniform_air::Kind::SampleG4 => 0,
                    uniform_air::Kind::ExpandAlpha2 => 1,
                },
            ]),
        }
    }
}
impl DescriptorKey for OtherNativeDescriptor<'_> {
    #[cfg(test)]
    fn portable_heap_bytes(&self) -> Option<usize> {
        match self {
            Self::Statement { .. } | Self::Algebra { kind: ComponentKind::Affine { .. }, .. } => Some(0),
            Self::Algebra { kind: ComponentKind::LinearMap { descriptor }, .. } => Some(descriptor.portable_heap_bytes()),
            _ => None,
        }
    }
    #[cfg(test)]
    fn portable(&self) -> Option<super::cache::PortableDescriptor> {
        match *self {
            Self::Statement { setup_seed } => Some(super::cache::PortableDescriptor::Statement { setup_seed }),
            Self::Algebra { kind: ComponentKind::LinearMap { descriptor }, count } => Some(super::cache::PortableDescriptor::Linear {
                descriptor: Box::new(descriptor.portable()), count }),
            Self::Algebra { kind: ComponentKind::Affine { kind, modulus }, count } => Some(super::cache::PortableDescriptor::Affine {
                operation: kind.code(), bound: match kind { AffineKind::SignedToCanonical { bound } => *bound, _ => 0 }, modulus: *modulus, count }),
            _ => None,
        }
    }
    fn family(&self) -> usize {
        match self {
            Self::Statement { .. } => 5,
            Self::PrivateProof => 6,
            Self::Algebra { kind, .. } => match kind {
                ComponentKind::Affine { .. } => 7,
                ComponentKind::Ntt { .. } => 8,
                ComponentKind::Mul { .. } => 9,
                ComponentKind::GBound { .. } => 10,
                ComponentKind::Permutation { .. } => 11,
                ComponentKind::LinearMap { .. } => 12,
                ComponentKind::External => 12,
            },
        }
    }
    fn encode(&self, h: &mut Sha3_256) {
        match self {
            Self::Statement { setup_seed } => {
                h.update([0]);
                h.update(setup_seed);
            }
            Self::PrivateProof => h.update([1]),
            Self::Algebra { kind, count } => {
                h.update([2]);
                word(h, *count);
                match kind {
                    ComponentKind::Affine { kind, modulus } => {
                        h.update([0]);
                        h.update(modulus.to_le_bytes());
                        match kind {
                            AffineKind::Add => h.update([0]),
                            AffineKind::Sub => h.update([1]),
                            AffineKind::SignedToCanonical { bound } => {
                                h.update([2]);
                                h.update(bound.to_le_bytes());
                            }
                        }
                    }
                    ComponentKind::Ntt { modulus } => {
                        h.update([1]);
                        h.update(modulus.to_le_bytes());
                    }
                    ComponentKind::Mul { modulus } => {
                        h.update([2]);
                        h.update(modulus.to_le_bytes());
                    }
                    ComponentKind::GBound { bound } => {
                        h.update([3]);
                        h.update(bound.to_le_bytes());
                    }
                    ComponentKind::Permutation { kind } => h.update([
                        4,
                        match kind {
                            PermutationKind::AutomorphismQ => 0,
                            PermutationKind::InverseChallenge => 1,
                        },
                    ]),
                    ComponentKind::LinearMap { descriptor } => {
                        h.update([5]);
                        h.update(descriptor.metadata_key());
                    }
                    ComponentKind::External => h.update([6]), // rejected by source preflight
                }
            }
        }
    }
}
pub(super) fn descriptor<D: DescriptorKey>(family: u8, descriptor: &D) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"ringct/native-descriptor/v2\0");
    h.update([family]);
    descriptor.encode(&mut h);
    h.finalize().into()
}
#[cfg(test)]
impl DescriptorKey for usize {
    fn family(&self) -> usize {
        0
    }
    fn encode(&self, h: &mut Sha3_256) {
        word(h, *self);
    }
}
