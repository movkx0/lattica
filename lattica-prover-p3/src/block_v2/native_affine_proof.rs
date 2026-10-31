//! Data-only affine arithmetic schema. Only the owned producer can seal this
//! proof under originals; this public schema confers no verified status.
use super::{profile::Config, native_gpu::affine_preparation::AffineDescriptor};
use crate::config::Val;
pub const AFFINE_PUBLIC_VALUES: usize = 4;
pub struct NativeAffineProof {
    pub kind: AffineDescriptor,
    pub public_values: [Val; AFFINE_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeAffineProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
