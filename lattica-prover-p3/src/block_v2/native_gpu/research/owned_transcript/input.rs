//! Fixed native references borrow immutable original transcript part values.
use super::super::transcript_preparation::{TranscriptLayout, TranscriptPartKind, MAX_PARTS};
use crate::block_v2::native_gpu::TranscriptPart;
use super::{Error, Result};
pub struct TranscriptInput<'a> {
    pub(super) kind: TranscriptLayout,
    parts: [TranscriptPart<'a>; MAX_PARTS],
}
impl<'a> TranscriptInput<'a> {
    pub fn new(kind: TranscriptLayout, parts: [TranscriptPart<'a>; MAX_PARTS]) -> Result<Self> {
        for (i, part) in parts[..kind.part_count()].iter().enumerate() {
            let actual = match part {
                TranscriptPart::Bytes32(_) => TranscriptPartKind::Bytes32,
                TranscriptPart::PolynomialQ(values) => {
                    if values.iter().any(|&word| word > u32::MAX as u64) { return Err(Error::Geometry); }
                    TranscriptPartKind::PolynomialQ
                }
                TranscriptPart::PolynomialQhat(values) => {
                    if values.iter().any(|&word| word > u32::MAX as u64) { return Err(Error::Geometry); }
                    TranscriptPartKind::PolynomialQhat
                }
            };
            if kind.part_kind(i) != Some(actual) { return Err(Error::Geometry); }
        }
        Ok(Self { kind, parts })
    }
    pub fn kind(&self) -> TranscriptLayout { self.kind }
    pub fn parts(&self) -> &[TranscriptPart<'a>] { &self.parts[..self.kind.part_count()] }
}
