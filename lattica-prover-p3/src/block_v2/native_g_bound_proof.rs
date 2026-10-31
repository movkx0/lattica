//! Data-only G_BOUND schema; only the owned producer seals it under originals.
use super::{profile::Config, native_gpu::g_bound_preparation::GBoundDescriptor};
use crate::config::Val;
pub const G_BOUND_MAX_PUBLIC_VALUES: usize = 8;
pub struct NativeGBoundProof {
    pub kind: GBoundDescriptor,
    /// Exact ordered commitments to the signed f and x polynomials.
    pub public_values: [Val; G_BOUND_MAX_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeGBoundProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values[..8 * self.kind.count()] }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
