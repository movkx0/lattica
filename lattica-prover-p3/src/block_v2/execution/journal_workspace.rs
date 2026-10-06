//! Runtime ownership of separately journaled persistent workspace budgets.
//! Guards fence trusted local users, not hostile same-UID code or untracked
//! external processes. No cache allocation or warm proving is performed here.

use super::*;

pub(super) struct Owner {
    journal: [u64; 2],
    lock: File,
    lease: WorkspaceLease,
}

#[must_use = "release the drained workspace through its durable owner"]
pub struct WorkspaceReservation {
    owner: Option<Arc<Owner>>,
}

/// A local cache user retains both its reservation and the recovery lock.
/// This grants no job-dispatch or proof-acceptance authority.
#[must_use = "retain this guard for the whole cache-use lifetime"]
pub struct WorkspaceUse {
    owner: Arc<Owner>,
}

impl WorkspaceReservation {
    pub fn lease(&self) -> Result<WorkspaceLease, Error> {
        Ok(self.owner.as_ref().ok_or("workspace already closed")?.lease)
    }

    pub fn begin_use(&self) -> Result<WorkspaceUse, Error> {
        Ok(WorkspaceUse {
            owner: Arc::clone(self.owner.as_ref().ok_or("workspace already closed")?),
        })
    }

    #[cfg(feature = "stream")]
    pub(crate) fn require_idle(&self) -> Result<(), Error> {
        if Arc::strong_count(self.owner.as_ref().ok_or("workspace already closed")?) != 1 {
            return Err("workspace still has active local users".into());
        }
        Ok(())
    }
}

impl WorkspaceUse {
    pub fn lease(&self) -> WorkspaceLease {
        self.owner.lease
    }
}

impl DurableDag {
    #[cfg(feature = "stream")]
    fn checked_workspace_owner(&self, owner: &Arc<Owner>) -> Result<Arc<Owner>, Error> {
        self.live()?;
        let issued = self
            .workspaces
            .get(&owner.lease.id())
            .and_then(Weak::upgrade)
            .ok_or("workspace has no issuing owner")?;
        let held = self.journal.lock.metadata()?;
        let guarded = owner.lock.metadata()?;
        if owner.journal != self.journal.identity()?
            || (held.dev(), held.ino()) != (guarded.dev(), guarded.ino())
            || !Arc::ptr_eq(&issued, owner)
        {
            return Err("workspace belongs to another owner".into());
        }
        Ok(issued)
    }

    #[cfg(feature = "stream")]
    pub(crate) fn check_workspace_reservation(
        &self,
        reservation: &WorkspaceReservation,
    ) -> Result<(), Error> {
        self.checked_workspace_owner(
            reservation
                .owner
                .as_ref()
                .ok_or("workspace already closed")?,
        )?;
        Ok(())
    }

    #[cfg(feature = "stream")]
    pub(crate) fn prepare_workspace_job(
        &mut self,
        reservation: &WorkspaceReservation,
        lease: Lease,
        now_ms: u64,
    ) -> Result<WorkspaceUse, Error> {
        self.advance(now_ms)?;
        self.check_workspace_reservation(reservation)?;
        self.core.check_workspace_job(reservation.lease()?, lease)?;
        self.core.assignment(lease)?;
        reservation.begin_use()
    }

    /// Only trusted cached adapters mint their opaque completed-job receipts.
    /// The inline call or bound child response has completed after GPU drain,
    /// and its single-use launch guard
    /// has been dropped. Mark that per-job producer quiescent, not the cache
    /// carrier process terminated: the workspace remains fully reserved.
    #[cfg(feature = "stream")]
    pub(crate) fn acknowledge_workspace_job(
        &mut self,
        user: &WorkspaceUse,
        lease: Lease,
        now_ms: u64,
    ) -> Result<(), Error> {
        self.checked_workspace_owner(&user.owner)?;
        self.core.check_workspace_job(user.lease(), lease)?;
        self.worker_stopped(lease, now_ms)
    }

    /// Persist a separate reservation before any persistent cache is allocated.
    /// FD duplication precedes the state change so failure cannot expose an
    /// unguarded successful reservation. The cold per-job path is unchanged.
    pub fn reserve_workspace(
        &mut self,
        worker: WorkerId,
        resources: Resources,
        now_ms: u64,
    ) -> Result<WorkspaceReservation, Error> {
        self.live()?;
        let journal = self.journal.identity()?;
        let lock = self.journal.lock.try_clone()?;
        let outcome = self.core.reserve_workspace(worker, resources, now_ms);
        let lease = self.persist(outcome)?;
        let owner = Arc::new(Owner {
            journal,
            lock,
            lease,
        });
        self.workspaces.insert(lease.id(), Arc::downgrade(&owner));
        Ok(WorkspaceReservation { owner: Some(owner) })
    }

    /// The caller must first drop the cache itself and drain every external
    /// user. Local use guards additionally prevent early release. Failed
    /// precondition checks preserve the handle so draining/close can be retried.
    pub fn release_workspace(
        &mut self,
        reservation: &mut WorkspaceReservation,
        now_ms: u64,
    ) -> Result<(), Error> {
        self.live()?;
        let owner = reservation
            .owner
            .as_ref()
            .ok_or("workspace already closed")?;
        let issued = self
            .workspaces
            .get(&owner.lease.id())
            .and_then(Weak::upgrade)
            .ok_or("workspace has no issuing owner")?;
        let held = self.journal.lock.metadata()?;
        let guarded = owner.lock.metadata()?;
        if owner.journal != self.journal.identity()?
            || (held.dev(), held.ino()) != (guarded.dev(), guarded.ino())
            || !Arc::ptr_eq(&issued, owner)
        {
            return Err("workspace belongs to another owner".into());
        }
        // The reservation and this issuing-owner check are the only allowed
        // strong references. A moved local user must actually finish/drop.
        if Arc::strong_count(owner) != 2 {
            return Err("workspace still has active local users".into());
        }
        let lease = owner.lease;
        let outcome = self.core.release_workspace(lease, now_ms);
        self.persist(outcome)?;
        self.workspaces.remove(&lease.id());
        reservation.owner = None;
        Ok(())
    }
}
