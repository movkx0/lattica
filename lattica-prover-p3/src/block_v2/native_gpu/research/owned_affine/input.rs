//! Source-only serialized operands; no trace or result can enter this input.
//! The research adapter proves exact membership in its retained source batch.
use super::super::affine_preparation::AffineDescriptor;
pub struct AffineInput<'a> { pub kind: AffineDescriptor, pub words: &'a [u64] }
impl AffineInput<'_> { pub fn kind(&self) -> AffineDescriptor { self.kind } }
