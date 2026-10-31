//! Data-only sparse sampler schema. Only the owned producer can seal this
//! proof under originals; this public schema confers no verified status.
use super::{profile::Config, native_gpu::sparse_preparation::SparseKind};
use crate::config::Val;
pub const UNIFORM_PUBLIC_VALUES: usize = 8;
pub struct NativeSparseProof {
    pub kind: SparseKind,
    pub public_values: [Val; UNIFORM_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeSparseProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
