//! Source-only serialized operands; no trace or result can enter this input.
//! The research adapter proves exact membership in its retained source batch.
use super::super::ntt_preparation::NttDescriptor;
pub struct NttInput<'a> { pub kind: NttDescriptor, pub words: &'a [u64] }
impl NttInput<'_> { pub fn kind(&self) -> NttDescriptor { self.kind } }
