//! One immutable selection, one input conversion and one shared-input admission.
//! Caller input-list backing, additional selections/results and verification
//! remain separate owners. Proof Arc allocations are counted once per selection.

use super::*;
use crate::block_v2::{
    execution::{
        job::ArtifactRef,
        storage_bound::{add, arc_slice, mul, vector},
    },
    profile::MAX_PROOF_BYTES,
};
use core::mem::size_of;
use std::sync::Arc;

const MAX_ENTRIES: usize = 2 * CAPACITY - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectionStorage {
    pub metadata_bytes: usize,
    pub proof_bytes: usize,
    pub construction_bytes: usize,
    pub input_conversion_bytes: usize,
    pub admission_bytes: usize,
}

impl SelectionStorage {
    pub fn retained_bytes(self) -> Result<usize, Error> {
        add(self.metadata_bytes, self.proof_bytes)
    }

    pub fn total_bytes(self) -> Result<usize, Error> {
        [
            self.retained_bytes()?,
            self.construction_bytes,
            self.input_conversion_bytes,
            self.admission_bytes,
        ]
        .into_iter()
        .try_fold(0, add)
    }

    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("selection storage component admission".into());
        }
        Ok(())
    }
}

fn job_heap() -> Result<usize, Error> {
    add(vector::<JobId>(2)?, vector::<ArtifactRef>(2)?)
}

impl Selection {
    pub fn storage_plan() -> Result<SelectionStorage, Error> {
        // Two job values per recursion level, plus root/finalizer construction
        // locals. This also covers the temporary two-input leaf handle vector.
        let local_jobs = 2 * (DEPTH as usize + 3);
        Ok(SelectionStorage {
            metadata_bytes: [
                size_of::<Selection>(),
                vector::<Entry>(MAX_ENTRIES)?,
                mul(MAX_ENTRIES, job_heap()?)?,
                vector::<PublicInput>(CAPACITY)?,
            ]
            .into_iter()
            .try_fold(0, add)?,
            proof_bytes: mul(CAPACITY, arc_slice::<u8>(MAX_PROOF_BYTES)?)?,
            construction_bytes: [
                vector::<Job>(local_jobs)?,
                mul(local_jobs, job_heap()?)?,
                size_of::<Vec<PublicInput>>(),
                vector::<PublicInput>(2)?,
                vector::<Option<&Arc<[u8]>>>(CAPACITY)?, // census stack array
            ]
            .into_iter()
            .try_fold(0, add)?,
            input_conversion_bytes: [
                PublicInput::INPUT_CAPACITY_BYTES,
                arc_slice::<u8>(MAX_PROOF_BYTES)?,
                size_of::<Vec<u8>>(),
                size_of::<PublicInput>(),
            ]
            .into_iter()
            .try_fold(0, add)?,
            admission_bytes: [
                size_of::<Job>(),
                job_heap()?,
                size_of::<&[PublicInput]>(),
                size_of::<Vec<Arc<[u8]>>>(),
                vector::<Arc<[u8]>>(2)?,
                // Preserve the prior two-proof allowance conservatively. The
                // shared admission path allocates only handles; disk integrity
                // reads and detached callers remain independently bounded.
                mul(2, MAX_PROOF_BYTES)?,
            ]
            .into_iter()
            .try_fold(0, add)?,
        })
    }

    /// Includes shared proof backing once per Arc allocation, even when a
    /// typed odd-input leaf retains two handles to the same proof. Independent
    /// selections are conservatively charged independently by their caller.
    pub fn retained_storage_bytes(&self) -> Result<usize, Error> {
        let plan = Self::storage_plan()?;
        if self.entries.is_empty() || self.entries.capacity() > MAX_ENTRIES {
            return Err("selection entry backing invariant".into());
        }
        let mut metadata = add(
            size_of::<Selection>(),
            vector::<Entry>(self.entries.capacity())?,
        )?;
        let mut proofs = 0;
        let mut handles = 0;
        let mut unique = 0;
        let mut seen: [Option<&Arc<[u8]>>; CAPACITY] = [None; CAPACITY];
        for entry in &self.entries {
            let heap = entry.job.owned_heap_bytes()?;
            if heap > job_heap()? || entry.inputs.capacity() > 2 {
                return Err("selection job backing invariant".into());
            }
            metadata = add(
                metadata,
                add(heap, vector::<PublicInput>(entry.inputs.capacity())?)?,
            )?;
            handles = add(handles, entry.inputs.capacity())?;
            for input in &entry.inputs {
                if input.bytes().len() > MAX_PROOF_BYTES {
                    return Err("selection proof backing invariant".into());
                }
                if seen[..unique]
                    .iter()
                    .flatten()
                    .any(|old| Arc::ptr_eq(old, input.shared_bytes()))
                {
                    continue;
                }
                if unique == CAPACITY {
                    return Err("selection distinct proof bound".into());
                }
                seen[unique] = Some(input.shared_bytes());
                unique += 1;
                proofs = add(proofs, arc_slice::<u8>(input.bytes().len())?)?;
            }
        }
        if handles > CAPACITY || metadata > plan.metadata_bytes || proofs > plan.proof_bytes {
            return Err("selection retained storage invariant".into());
        }
        add(metadata, proofs)
    }
}

#[cfg(test)]
#[path = "selection_storage_tests.rs"]
mod tests;
