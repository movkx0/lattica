//! Persistent workspace reservations, separate from individual job attempts.
//!
//! This is admission metadata, not an allocator, OS quota or warm prover. The
//! durable owner adds lifetime guards and explicit crash reconciliation.

use super::{dag::WorkerId, resources::Resources};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkspaceId {
    pub(super) session: [u8; 32],
    pub(super) epoch: u64,
    pub(super) sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkspaceLease {
    pub(super) id: WorkspaceId,
    pub(super) worker: WorkerId,
    pub(super) resources: Resources,
}

impl WorkspaceLease {
    pub fn id(self) -> WorkspaceId {
        self.id
    }
    pub fn worker(self) -> WorkerId {
        self.worker
    }
    pub fn resources(self) -> Resources {
        self.resources
    }
}
