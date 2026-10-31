//! Source-only serialized operands; no trace or result can enter this input.
//! The research adapter proves exact membership in its retained source batch.
use super::super::mul_preparation::MulDescriptor;
pub struct MulInput<'a> { pub kind: MulDescriptor, pub words: &'a [u64] }
impl MulInput<'_> { pub fn kind(&self) -> MulDescriptor { self.kind } }
