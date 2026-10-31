//! Immutable raw bytes borrowed from the exact original auxiliary request.
//! The research source owner binds operation, role, context and endpoint roots.
use super::super::sparse_preparation::SparseKind;
pub struct SparseInput<'a> { pub kind: SparseKind, pub bytes: &'a [u8] }
impl SparseInput<'_> { pub fn kind(&self) -> SparseKind { self.kind } }
