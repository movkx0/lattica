//! Allocation-free algebra for the concrete fixed-u64 Postcard decoder.
use super::{add, mul, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Layout {
    pub(super) encoded: usize,
    pub(super) backing: usize,
    pub(super) allocations: usize,
    pub(super) items: usize,
    pub(super) max_sequence: usize,
    pub(super) depth: usize,
}

impl Layout {
    pub(super) const EMPTY: Self = Self::scalar(0);

    pub(super) const fn scalar(encoded: usize) -> Self {
        Self {
            encoded,
            backing: 0,
            allocations: 0,
            items: 0,
            max_sequence: 0,
            depth: 0,
        }
    }

    pub(super) fn merge(self, other: Self) -> Result<Self> {
        Ok(Self {
            encoded: add(self.encoded, other.encoded)?,
            backing: add(self.backing, other.backing)?,
            allocations: add(self.allocations, other.allocations)?,
            items: add(self.items, other.items)?,
            max_sequence: self.max_sequence.max(other.max_sequence),
            depth: self.depth.max(other.depth),
        })
    }

    fn repeated(self, count: usize) -> Result<Self> {
        if count == 0 {
            return Ok(Self::EMPTY);
        }
        Ok(Self {
            encoded: mul(self.encoded, count)?,
            backing: mul(self.backing, count)?,
            allocations: mul(self.allocations, count)?,
            items: mul(self.items, count)?,
            max_sequence: self.max_sequence,
            depth: self.depth,
        })
    }

    fn tuple_body(mut self, count: usize) -> Result<Self> {
        self.items = add(self.items, count)?;
        self.max_sequence = self.max_sequence.max(count);
        self.depth = add(self.depth, 1)?;
        Ok(self)
    }

    pub(super) fn structure(fields: &[Self]) -> Result<Self> {
        let mut body = Self::EMPTY;
        for &field in fields {
            body = body.merge(field)?;
        }
        body.tuple_body(fields.len())
    }

    pub(super) fn array(self, count: usize) -> Result<Self> {
        self.repeated(count)?.tuple_body(count)
    }

    /// Wrap an already-summed heterogeneous vector body. Only the pinned
    /// geometry module can call this; no proof or untrusted count enters it.
    pub(super) fn vector_body(mut self, count: usize, element_size: usize) -> Result<Self> {
        let backing = mul(count, element_size)?;
        self.backing = add(self.backing, backing)?;
        self.allocations = add(self.allocations, usize::from(backing != 0))?;
        self.encoded = add(self.encoded, varint_len(count))?;
        self.tuple_body(count)
    }

    pub(super) fn vector(self, count: usize, element_size: usize) -> Result<Self> {
        self.repeated(count)?.vector_body(count, element_size)
    }

    pub(super) const fn none() -> Self {
        Self {
            encoded: 1,
            depth: 1,
            ..Self::EMPTY
        }
    }

    pub(super) fn some(mut self) -> Result<Self> {
        self.encoded = add(self.encoded, 1)?;
        self.depth = add(self.depth, 1)?;
        Ok(self)
    }
}

pub(super) fn varint_len(mut value: usize) -> usize {
    let mut bytes = 1;
    while value >= 128 {
        value >>= 7;
        bytes += 1;
    }
    bytes
}
