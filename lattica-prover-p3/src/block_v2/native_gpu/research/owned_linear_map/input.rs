//! Source-only serialized operands; no trace or result can enter this input.
//! The research adapter proves exact membership in its retained source batch.
use super::super::linear_map_preparation::LinearMapDescriptor;
pub struct LinearMapInput<'a> { pub kind: LinearMapDescriptor, pub words: &'a [u64] }
impl LinearMapInput<'_> { pub fn kind(&self) -> LinearMapDescriptor { self.kind } }
