//! Canonical public transcript layout, bounded before witness allocation.
use super::{Error, Result};
use serde::Serialize;
pub const MAX_PARTS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TranscriptPartKind { Bytes32, PolynomialQ, PolynomialQhat }
impl TranscriptPartKind {
    fn code(self) -> u64 {
        match self { Self::Bytes32 => 0, Self::PolynomialQ => 1, Self::PolynomialQhat => 2 }
    }
    fn byte_len(self) -> usize { if self == Self::Bytes32 { 32 } else { 1024 } }
}

/// Two bits per part; private unused bits are zero and code three is forbidden.
/// No deserializer or caller-supplied row/width/event count can bypass new().
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TranscriptLayout {
    kinds: [u64; 8],
    count: u16,
    events: u16,
    bytes: u32,
}
impl TranscriptLayout {
    pub fn new(parts: &[TranscriptPartKind]) -> Result<Self> {
        if parts.is_empty() || parts.len() > MAX_PARTS { return Err(Error::UnsupportedProfile); }
        let mut result = Self { kinds: [0; 8], count: parts.len() as u16, events: 0, bytes: 0 };
        for (i, kind) in parts.iter().copied().enumerate() {
            result.kinds[i / 32] |= kind.code() << (2 * (i % 32));
            result.bytes = result.bytes.checked_add(kind.byte_len() as u32).ok_or(Error::Overflow)?;
            // The final part always transitions to the distinct terminal class.
            if parts.get(i + 1).copied() != Some(kind) { result.events += 1; }
        }
        Ok(result)
    }
    pub fn part_count(self) -> usize { self.count as usize }
    pub fn event_count(self) -> usize { self.events as usize }
    pub fn byte_len(self) -> usize { self.bytes as usize }
    pub fn part_kind(self, index: usize) -> Option<TranscriptPartKind> {
        if index >= self.part_count() { return None; }
        match (self.kinds[index / 32] >> (2 * (index % 32))) & 3 {
            0 => Some(TranscriptPartKind::Bytes32),
            1 => Some(TranscriptPartKind::PolynomialQ),
            2 => Some(TranscriptPartKind::PolynomialQhat),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_layout_preserves_order_boundaries_and_terminal_events() {
        use TranscriptPartKind::*;
        let parts = [Bytes32, Bytes32, PolynomialQ, PolynomialQhat, PolynomialQhat];
        let layout = TranscriptLayout::new(&parts).unwrap();
        assert_eq!((layout.part_count(), layout.event_count(), layout.byte_len()), (5, 3, 3136));
        for (i, kind) in parts.into_iter().enumerate() { assert_eq!(layout.part_kind(i), Some(kind)); }
        assert_eq!(layout.part_kind(5), None);
        assert!(TranscriptLayout::new(&[]).is_err());
        assert!(TranscriptLayout::new(&[Bytes32; 257]).is_err());
        let repeated = TranscriptLayout::new(&[PolynomialQ; 256]).unwrap();
        assert_eq!((repeated.event_count(), repeated.byte_len()), (1, 262144));
        let alternating = core::array::from_fn::<_, 256, _>(|i| if i % 2 == 0 { Bytes32 } else { PolynomialQhat });
        let maximal = TranscriptLayout::new(&alternating).unwrap();
        assert_eq!((maximal.event_count(), maximal.byte_len()), (256, 135168));
        for i in [0, 31, 32, 63, 64, 127, 128, 254, 255] {
            assert_eq!(maximal.part_kind(i), Some(alternating[i]));
        }
    }
}
