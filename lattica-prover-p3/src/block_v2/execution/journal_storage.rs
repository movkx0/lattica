//! Composition of graph backing during persistence and recovery. Durable
//! handles, store inventory, verification, callers, queues and OS costs remain
//! separate components of physical coordinator admission.
use super::*;
use crate::block_v2::execution::{
    io_storage,
    storage_bound::{add, arc, btree, growing_vector, mul, vector},
};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraphStorage {
    pub retained: dag::RetainedStorage,
    pub snapshot: dag::SnapshotStorage,
    pub payload_bytes: usize,
}

impl GraphStorage {
    /// Recovery resume retains previous-candidate/attempt/workspace vectors
    /// while encoding the next snapshot. Add both metadata phases, rather than
    /// taking their maximum and silently omitting that overlap.
    pub fn total_bytes(self) -> Result<usize, Error> {
        [
            self.retained.total_bytes()?,
            self.snapshot.encode_metadata_bytes,
            self.snapshot.recover_metadata_bytes,
            self.payload_bytes,
        ]
        .into_iter()
        .try_fold(0, add)
    }

    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("journal graph storage admission".into());
        }
        Ok(())
    }
}

impl JournalLimits {
    pub fn graph_storage(self, limits: Limits) -> Result<GraphStorage, Error> {
        Ok(GraphStorage {
            retained: limits.retained_storage()?,
            snapshot: limits.snapshot_storage()?,
            payload_bytes: self.payload_storage_bytes()?,
        })
    }

    /// Compose known shared owners, preserving every physical cap. Caller/job
    /// work, supervisors, queues, registries and opaque runtime overhead remain
    /// separate; this does not admit an incomplete proving phase profile.
    pub fn durable_storage(
        self,
        limits: Limits,
        store: artifact_store::StoreLimits,
    ) -> Result<DurableStorage, Error> {
        Ok(DurableStorage {
            graph: self.graph_storage(limits)?,
            transitions: limits.transition_storage()?,
            store: store.storage_plan()?,
            owner_metadata_bytes: owner_bound(limits)?,
            path_work_bytes: io_storage::work_bytes()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableStorage {
    pub graph: GraphStorage,
    pub transitions: dag::TransitionStorage,
    pub store: artifact_store::ArtifactStorage,
    pub owner_metadata_bytes: usize,
    pub path_work_bytes: usize,
}
impl DurableStorage {
    pub fn total_bytes(self) -> Result<usize, Error> {
        [
            self.graph.total_bytes()?,
            self.transitions.total_bytes()?,
            self.store.total_bytes()?,
            self.owner_metadata_bytes,
            self.path_work_bytes,
        ]
        .into_iter()
        .try_fold(0, add)
    }
    pub fn admit(self, bytes: usize) -> Result<(), Error> {
        if self.total_bytes()? > bytes {
            return Err("durable storage component admission".into());
        }
        Ok(())
    }
}

fn owner_bound(limits: Limits) -> Result<usize, Error> {
    // Two extra Arc allocations cover construction and completion locals.
    [
        size_of::<DurableDag>(),
        btree::<AttemptId, Weak<VerificationOwner>>(limits.attempts)?,
        btree::<WorkspaceId, Weak<workspace_guard::Owner>>(limits.attempts)?,
        mul(add(limits.attempts, 2)?, arc::<VerificationOwner>()?)?,
        mul(add(limits.attempts, 2)?, arc::<workspace_guard::Owner>()?)?,
        io_storage::ANCHOR_BYTES,
        growing_vector::<String>(MAX_PENDING)?,
        mul(MAX_PENDING, 41)?,
    ]
    .into_iter()
    .try_fold(0, add)
}

impl DurableDag {
    pub fn storage_plan(&self) -> Result<DurableStorage, Error> {
        let limits = self.core.storage_limits();
        Ok(DurableStorage {
            graph: self.journal.limits.graph_storage(limits)?,
            transitions: limits.transition_storage()?,
            store: self.store.storage_plan()?,
            owner_metadata_bytes: owner_bound(limits)?,
            path_work_bytes: io_storage::work_bytes()?,
        })
    }

    /// Retained guard/header census. Expired Weak entries still retain the Arc
    /// allocation, so count them until the existing rejection path removes them.
    pub fn owner_storage_bytes(&self) -> Result<usize, Error> {
        let mut bytes = [
            size_of::<DurableDag>(),
            btree::<AttemptId, Weak<VerificationOwner>>(self.verifiers.len())?,
            btree::<WorkspaceId, Weak<workspace_guard::Owner>>(self.workspaces.len())?,
            mul(self.verifiers.len(), arc::<VerificationOwner>()?)?,
            mul(self.workspaces.len(), arc::<workspace_guard::Owner>()?)?,
            self.journal.path.capacity(),
            vector::<String>(self.journal.pending.capacity())?,
        ]
        .into_iter()
        .try_fold(0, add)?;
        for name in &self.journal.pending {
            bytes = add(bytes, name.capacity())?;
        }
        if self.verifiers.len() > self.core.storage_limits().attempts
            || self.workspaces.len() > self.core.storage_limits().attempts
            || self.journal.pending.len() > MAX_PENDING
            || self.journal.pending.iter().any(|n| n.capacity() > 41)
            || self.journal.path.capacity() > io_storage::ANCHOR_BYTES
            || bytes > owner_bound(self.core.storage_limits())?
        {
            return Err("durable owner storage invariant".into());
        }
        self.store.handle_storage_bytes()?;
        self.store.inventory_storage_bytes()?;
        Ok(bytes)
    }
}
