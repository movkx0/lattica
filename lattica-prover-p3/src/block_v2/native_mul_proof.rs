//! Data-only MUL schema; only the owned producer seals it under originals.
use super::{profile::Config, native_gpu::mul_preparation::MulDescriptor};
use crate::config::Val;
pub const MUL_MAX_PUBLIC_VALUES: usize = 12 * 128;
pub struct NativeMulProof {
    pub kind: MulDescriptor,
    /// Fixed source-bounded backing; the unused suffix is always zero.
    pub public_values: [Val; MUL_MAX_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeMulProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values[..12 * self.kind.count()] }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
