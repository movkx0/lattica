//! Caller input/policy lists and one temporary registry during preparation.
//! Proof Arc backing belongs to the selection component even before selection
//! construction. Body/expectation parsing, verification and runtime costs remain
//! separate; this is not a complete preparation or physical admission plan.

use super::*;
use crate::block_v2::{
    execution::{
        job::ArtifactRef,
        storage_bound::{add, vector},
    },
    typed_recursive::{Policy, Registry},
};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreparationStorage {
    pub input_list_bytes: usize,
    pub policy_list_bytes: usize,
    pub temporary_registry_bytes: usize,
    pub registry_conversion_bytes: usize,
}

impl PreparationStorage {
    /// Backing for the CLI's bounded map; its value handle is charged by the caller.
    pub fn authorization_map_backing_bytes() -> Result<usize, Error> {
        crate::block_v2::execution::storage_bound::btree::<usize, u64>(CAPACITY)
    }

    pub fn new() -> Result<Self, Error> {
        type Cap = Vec<[crate::config::Val; 4]>;
        Ok(Self {
            input_list_bytes: add(
                size_of::<Vec<PublicInput>>(),
                vector::<PublicInput>(CAPACITY)?,
            )?,
            policy_list_bytes: add(
                size_of::<Vec<(ArtifactRef, Policy)>>(),
                vector::<(ArtifactRef, Policy)>(CAPACITY)?,
            )?,
            temporary_registry_bytes: Registry::<12>::STORAGE_LIMIT_BYTES,
            // The source/iterator array, temporary Vec and destination array
            // move cap ownership. Cap backing is charged by the registry once.
            registry_conversion_bytes: add(
                2 * size_of::<[Cap; 12]>(),
                add(size_of::<Vec<Cap>>(), vector::<Cap>(12)?)?,
            )?,
        })
    }

    pub fn total_bytes(self) -> Result<usize, Error> {
        [
            self.input_list_bytes,
            self.policy_list_bytes,
            self.temporary_registry_bytes,
            self.registry_conversion_bytes,
        ]
        .into_iter()
        .try_fold(0, add)
    }

    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("preparation input storage component admission".into());
        }
        Ok(())
    }

    // Capacity is part of the contract, including an empty but reserved list.
    pub fn input_list_storage_bytes(inputs: &Vec<PublicInput>) -> Result<usize, Error> {
        if inputs.capacity() > CAPACITY {
            return Err("preparation input-list capacity".into());
        }
        add(
            size_of::<Vec<PublicInput>>(),
            vector::<PublicInput>(inputs.capacity())?,
        )
    }

    pub fn policy_list_storage_bytes(
        policies: &Vec<(ArtifactRef, Policy)>,
    ) -> Result<usize, Error> {
        if policies.capacity() > CAPACITY {
            return Err("preparation policy-list capacity".into());
        }
        add(
            size_of::<Vec<(ArtifactRef, Policy)>>(),
            vector::<(ArtifactRef, Policy)>(policies.capacity())?,
        )
    }
}
