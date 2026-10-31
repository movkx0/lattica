//! Data-only LINEAR_MAP schema; only the owned producer seals it under originals.
use super::{profile::Config, native_gpu::linear_map_preparation::LinearMapDescriptor};
use crate::config::Val;
pub const LINEAR_MAP_MAX_PUBLIC_VALUES: usize = 68;
pub struct NativeLinearMapProof {
    pub kind: LinearMapDescriptor,
    /// Exact ordered commitments to the input and output polynomials.
    pub public_values: [Val; LINEAR_MAP_MAX_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeLinearMapProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values[..self.kind.public_values()] }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
