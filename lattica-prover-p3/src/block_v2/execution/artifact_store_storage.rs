//! Inventory backing only, including coexistence during refresh and pruning.
//! File/path/iterator storage, artifact reads and caller buffers are separate.
use super::*;
use crate::block_v2::execution::storage_bound::{add, btree, growing_vector, mul, vector};
use core::mem::size_of;

pub(super) const ARTIFACT_NAME_BYTES: usize = 72;
const PENDING_NAME_BYTES: usize = PENDING.len() + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryStorage {
    /// One inventory: map, pending vector, owned names and inline Inventory.
    pub retained_bytes: usize,
    /// Includes old/new inventories and prune's keep-map/removal list together.
    pub refresh_prune_bytes: usize,
}

impl InventoryStorage {
    /// Component admission only; no physical limit is increased.
    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.refresh_prune_bytes > bytes {
            return Err("artifact inventory storage admission".into());
        }
        Ok(())
    }
}

impl StoreLimits {
    pub fn inventory_storage(self) -> Result<InventoryStorage, Error> {
        self.validate()?;
        // Artifact and pending populations share an entry limit. Charge both
        // at that limit to avoid depending on their changing mix during scan.
        let retained_bytes = [
            size_of::<Inventory>(),
            btree::<String, ArtifactRef>(self.entries)?,
            mul(self.entries, ARTIFACT_NAME_BYTES + PENDING_NAME_BYTES)?,
            growing_vector::<String>(self.entries)?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        let refresh_prune_bytes = [
            mul(2, retained_bytes)?,
            size_of::<BTreeMap<String, ArtifactRef>>(),
            btree::<String, ArtifactRef>(self.entries)?,
            mul(self.entries, ARTIFACT_NAME_BYTES)?, // prune keep-map names
            size_of::<Vec<String>>(),
            growing_vector::<String>(self.entries)?,
            mul(self.entries, ARTIFACT_NAME_BYTES)?, // prune removed names
            2 * ARTIFACT_NAME_BYTES,                 // current insertion/replacement names
        ]
        .into_iter()
        .try_fold(0, add)?;
        Ok(InventoryStorage {
            retained_bytes,
            refresh_prune_bytes,
        })
    }
}

impl ArtifactStore {
    pub fn storage_plan(&self) -> Result<ArtifactStorage, Error> {
        self.limits.storage_plan()
    }

    pub(in crate::block_v2::execution) fn handle_storage_bytes(&self) -> Result<usize, Error> {
        if self.anchored.capacity() > super::super::io_storage::ANCHOR_BYTES {
            return Err("artifact path backing bound".into());
        }
        add(size_of::<ArtifactStore>(), self.anchored.capacity())
    }
    /// Census includes String/Vec capacities and conservative BTree backing.
    pub fn inventory_storage_bytes(&self) -> Result<usize, Error> {
        let mut bytes = add(
            size_of::<Inventory>(),
            btree::<String, ArtifactRef>(self.inventory.artifacts.len())?,
        )?;
        bytes = add(bytes, vector::<String>(self.inventory.pending.capacity())?)?;
        for name in self
            .inventory
            .artifacts
            .keys()
            .chain(&self.inventory.pending)
        {
            bytes = add(bytes, name.capacity())?;
        }
        if bytes > self.limits.inventory_storage()?.retained_bytes {
            return Err("artifact inventory storage invariant".into());
        }
        Ok(bytes)
    }
}

/// Includes one returned inventory list and one checked file-read buffer.
/// Caller-retained read results and opaque directory/libc buffers are separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactStorage {
    pub inventory: InventoryStorage,
    pub handle_and_query_bytes: usize,
    pub read_bytes: usize,
    pub path_work_bytes: usize,
}
impl ArtifactStorage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        [
            self.inventory.refresh_prune_bytes,
            self.handle_and_query_bytes,
            self.read_bytes,
            self.path_work_bytes,
        ]
        .into_iter()
        .try_fold(0, add)
    }
}
impl StoreLimits {
    pub fn storage_plan(self) -> Result<ArtifactStorage, Error> {
        let inventory = self.inventory_storage()?;
        Ok(ArtifactStorage {
            inventory,
            handle_and_query_bytes: [
                size_of::<ArtifactStore>(),
                super::super::io_storage::ANCHOR_BYTES,
                size_of::<Vec<ArtifactRef>>(),
                vector::<ArtifactRef>(self.entries)?,
            ]
            .into_iter()
            .try_fold(0, add)?,
            read_bytes: usize::try_from(self.bytes.min(MAX_PROOF_BYTES as u64))?,
            path_work_bytes: super::super::io_storage::work_bytes()?,
        })
    }
}
