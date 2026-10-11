//! One launch store, including its shared Arc/Mutex wrapper and refresh overlap.
//! Request/proof buffers belong to per-job admission. Opaque iterator, lock,
//! allocator and kernel storage remain runtime components.

use super::*;
use crate::block_v2::execution::{
    io_storage,
    storage_bound::{add, arc, btree, growing_vector, mul},
};
use core::mem::size_of;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchStorage {
    pub owner_bytes: usize,
    pub retained_records_bytes: usize,
    pub refresh_records_bytes: usize,
    pub control_bytes: usize,
}
impl LaunchStorage {
    pub fn retained_bytes(self) -> Result<usize, Error> {
        add(self.owner_bytes, self.retained_records_bytes)
    }
    pub fn total_bytes(self) -> Result<usize, Error> {
        [
            self.retained_bytes()?,
            self.refresh_records_bytes,
            self.control_bytes,
        ]
        .into_iter()
        .try_fold(0, add)
    }
    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("launch storage component admission".into());
        }
        Ok(())
    }
}
impl LaunchLimits {
    pub fn storage_plan(self) -> Result<LaunchStorage, Error> {
        self.validate()?;
        Ok(LaunchStorage {
            owner_bytes: add(arc::<Mutex<LaunchStore>>()?, io_storage::ANCHOR_BYTES)?,
            retained_records_bytes: btree::<[u8; 32], u8>(self.records)?,
            // refresh checks its new cardinality after inserting the next key.
            // Keep the previous inventory and that rejected extra entry charged.
            refresh_records_bytes: btree::<[u8; 32], u8>(add(self.records, 1)?)?,
            control_bytes: add(
                io_storage::work_bytes()?,
                mul(
                    8,
                    add(
                        growing_vector::<u8>(MAX_TOKEN_BYTES)?,
                        size_of::<Token>() + size_of::<Vec<u8>>(),
                    )?,
                )?,
            )?,
        })
    }
}
impl LaunchStore {
    pub fn storage_plan(&self) -> Result<LaunchStorage, Error> {
        self.limits.storage_plan()
    }
    /// Conservatively charges the Arc/Mutex wrapper even for an unshared store.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let bytes = [
            arc::<Mutex<LaunchStore>>()?,
            self.directory.path.capacity(),
            btree::<[u8; 32], u8>(self.records.len())?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        if self.records.len() > self.limits.records
            || self.directory.path.capacity() > io_storage::ANCHOR_BYTES
            || bytes > self.storage_plan()?.retained_bytes()?
        {
            return Err("launch retained storage invariant".into());
        }
        Ok(bytes)
    }
}
