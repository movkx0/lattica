//! Concrete proof decoding with fallible, pre-admitted backing arrays.
//!
//! The quota is cumulative across all inputs in a request, including canonical
//! re-encoding. It never recycles a charge while returned proof data is live.
//! Caller packet storage, verification scratch and allocator overhead are
//! separate enclosing lifetimes; this is not a complete worker RSS bound.
use super::{encode_payload, Encoding, Guard, MAX_ITEMS, NODE_ENCODING};
use crate::block_v2::{
    profile,
    recursive::{NodeProof, WalletProof},
};
use serde::{de::DeserializeSeed, Serialize};
use std::cell::Cell;

mod schema;
#[cfg(test)]
mod tests;

pub(crate) const INPUT_STORAGE_LIMIT: usize = 64 << 20;

pub(crate) struct Storage {
    limit: usize,
    vector_bytes: Cell<usize>,
    canonical_bytes: Cell<usize>,
    allocations: Cell<usize>,
    rejected: Cell<bool>,
}

struct Attempt<'a>(&'a Storage);
impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.rejected.set(true);
        }
    }
}

impl Storage {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit: limit.min(INPUT_STORAGE_LIMIT),
            vector_bytes: Cell::new(0),
            canonical_bytes: Cell::new(0),
            allocations: Cell::new(0),
            rejected: Cell::new(false),
        }
    }

    fn reject(&self) -> postcard::Error {
        self.rejected.set(true);
        postcard::Error::SerdeDeCustom
    }

    fn reserve<T>(&self, count: usize, canonical: bool) -> Result<Vec<T>, postcard::Error> {
        let bytes = count
            .checked_mul(core::mem::size_of::<T>())
            .ok_or_else(|| self.reject())?;
        let admitted = self
            .vector_bytes
            .get()
            .checked_add(self.canonical_bytes.get())
            .and_then(|n| n.checked_add(bytes))
            .ok_or_else(|| self.reject())?;
        if self.rejected.get() || admitted > self.limit {
            return Err(self.reject());
        }
        let counter = if canonical {
            &self.canonical_bytes
        } else {
            &self.vector_bytes
        };
        counter.set(counter.get() + bytes);
        let mut values = Vec::new();
        if values.try_reserve_exact(count).is_err()
            || (core::mem::size_of::<T>() != 0 && values.capacity() != count)
        {
            return Err(self.reject());
        }
        self.allocations
            .set(self.allocations.get() + usize::from(bytes != 0));
        Ok(values)
    }

    fn payload<T: schema::Decode + Serialize>(
        &self,
        bytes: &[u8],
        encoding: Encoding,
    ) -> Result<T, postcard::Error> {
        let _attempt = Attempt(self);
        let result = (|| {
            if self.rejected.get() || bytes.len() > profile::MAX_PROOF_BYTES {
                return Err(self.reject());
            }
            let mut decoder = postcard::Deserializer::from_bytes(bytes);
            let items = Cell::new(MAX_ITEMS);
            let value = schema::Seed::<T>::new(self).deserialize(Guard {
                inner: &mut decoder,
                depth: 0,
                items: &items,
                encoding,
            })?;
            if !decoder.finalize()?.is_empty() {
                return Err(self.reject());
            }
            let mut canonical = self.reserve(bytes.len(), true)?;
            canonical.resize(bytes.len(), 0u8);
            if encode_payload(&value, encoding, &mut canonical)? != bytes {
                return Err(self.reject());
            }
            Ok(value)
        })();
        if result.is_err() {
            self.rejected.set(true);
        }
        result
    }

    pub(crate) fn node(&self, bytes: &[u8]) -> Result<NodeProof, postcard::Error> {
        if bytes.len() > profile::MAX_PROOF_BYTES || !bytes.starts_with(NODE_ENCODING.magic()) {
            return Err(self.reject());
        }
        self.payload(&bytes[8..], NODE_ENCODING)
    }

    pub(crate) fn wallet(&self, bytes: &[u8]) -> Result<WalletProof, postcard::Error> {
        self.payload(bytes, Encoding::Legacy)
    }
}

impl Drop for Storage {
    fn drop(&mut self) {
        eprintln!("bounded_decoded_proof_storage vector_bytes={} canonical_bytes={} admitted_bytes={} allocations={} limit_bytes={} rejected={}",
            self.vector_bytes.get(), self.canonical_bytes.get(),
            self.vector_bytes.get() + self.canonical_bytes.get(), self.allocations.get(),
            self.limit, self.rejected.get());
    }
}
