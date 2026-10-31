//! Source-only serialized operands; no trace or result can enter this input.
//! The research adapter proves exact membership in its retained source batch.
use super::super::permutation_preparation::PermutationDescriptor;
pub struct PermutationInput<'a> { pub kind: PermutationDescriptor, pub words: &'a [u64] }
impl PermutationInput<'_> { pub fn kind(&self) -> PermutationDescriptor { self.kind } }
