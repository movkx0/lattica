//! Data-only transcript source proof schema. Only the owned producer can seal this
//! proof under originals; this public schema confers no verified status.
use super::{profile::Config, native_gpu::transcript_preparation::TranscriptLayout};
use crate::config::Val;
pub const TRANSCRIPT_PUBLIC_VALUES: usize = 8;
pub struct NativeTranscriptProof {
    pub kind: TranscriptLayout,
    pub public_values: [Val; TRANSCRIPT_PUBLIC_VALUES],
    pub proof: p3_uni_stark::Proof<Config>,
}
impl NativeTranscriptProof {
    pub fn public_values(&self) -> &[Val] { &self.public_values }
    pub fn proof(&self) -> &p3_uni_stark::Proof<Config> { &self.proof }
}
