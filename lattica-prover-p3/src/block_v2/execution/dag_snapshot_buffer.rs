//! Count first, then serialize into one exact-capacity snapshot payload.

use crate::block_v2::{execution::bounded_io, recursive::Error};

pub(super) struct Buffer {
    bytes: Option<Vec<u8>>,
    length: usize,
    limit: usize,
}

#[cfg(test)]
thread_local! {
    pub(super) static PAYLOAD_ALLOCATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

impl Buffer {
    pub(super) fn count(limit: usize) -> Self {
        Self {
            bytes: None,
            length: 0,
            limit,
        }
    }

    pub(super) fn allocate(length: usize, limit: usize) -> Result<Self, Error> {
        let bytes = bounded_io::byte_capacity(length, limit)?;
        #[cfg(test)]
        PAYLOAD_ALLOCATIONS.with(|n| n.set(n.get() + usize::from(length != 0)));
        Ok(Self {
            bytes: Some(bytes),
            length: 0,
            limit: length,
        })
    }

    pub(super) fn len(&self) -> usize {
        self.length
    }

    pub(super) fn extend(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), Error> {
        let bytes = bytes.as_ref();
        let length = self
            .length
            .checked_add(bytes.len())
            .ok_or("checkpoint byte overflow")?;
        if length > self.limit {
            return Err("checkpoint byte limit before allocation/write".into());
        }
        if let Some(output) = &mut self.bytes {
            output.extend_from_slice(bytes);
        }
        self.length = length;
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Vec<u8>, Error> {
        let bytes = self
            .bytes
            .ok_or("checkpoint counting buffer cannot be published")?;
        if self.length != self.limit || bytes.len() != self.length || bytes.capacity() != self.limit
        {
            return Err("checkpoint measured/written capacity mismatch".into());
        }
        Ok(bytes)
    }
}
