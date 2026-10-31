//! Source-only serialized operands; no trace or result can enter this input.
//! The research adapter proves exact membership in its retained source batch.
use super::super::g_bound_preparation::GBoundDescriptor;
pub struct GBoundInput<'a> { pub kind: GBoundDescriptor, pub words: &'a [u64] }
impl GBoundInput<'_> { pub fn kind(&self) -> GBoundDescriptor { self.kind } }
