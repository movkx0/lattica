//! Data-only PERMUTATION schema; only the owned producer seals it under originals.
use super::{profile::Config, native_gpu::permutation_preparation::PermutationDescriptor};
use crate::config::Val;
pub const PERMUTATION_MAX_PUBLIC_VALUES: usize = 8;
pub struct NativePermutationProof {
    pub kind: PermutationDescriptor,
    /// Exact ordered commitments to the input and output polynomials.
    pub public_values: [Val; PERMUTATION_MAX_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativePermutationProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values[..8 * self.kind.count()] }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
