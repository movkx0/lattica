//! Data-only NTT schema; only the owned producer seals it under originals.
use super::{profile::Config, native_gpu::ntt_preparation::NttDescriptor};
use crate::config::Val;
pub const NTT_MAX_PUBLIC_VALUES: usize = 8 * 128;
pub struct NativeNttProof {
    pub kind: NttDescriptor,
    /// Fixed source-bounded backing; the unused suffix is always zero.
    pub public_values: [Val; NTT_MAX_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeNttProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values[..8 * self.kind.count()] }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
