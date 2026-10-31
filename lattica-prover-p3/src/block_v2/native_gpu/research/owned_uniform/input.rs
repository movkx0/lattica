//! Immutable raw bytes borrowed from the exact original auxiliary request.
//! The research source owner binds operation, role, context and endpoint roots.
use super::super::uniform_preparation::UniformKind;
pub struct UniformInput<'a> { pub kind: UniformKind, pub bytes: &'a [u8] }
impl UniformInput<'_> { pub fn kind(&self) -> UniformKind { self.kind } }
