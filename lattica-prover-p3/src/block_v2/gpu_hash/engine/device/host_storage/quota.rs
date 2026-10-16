//! One host allowance shared by all transcript families in a proof session.
//! Reservations own their charge through cleanup. GPU operations exclusively
//! reborrow a reservation for known nested storage rather than spending it twice.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) struct HostQuota {
    limit: usize,
    live: AtomicUsize,
}

#[must_use = "retain the host reservation until its buffers are released"]
pub(crate) struct HostScope {
    owner: Arc<HostQuota>,
    bytes: usize,
}

impl HostQuota {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            live: AtomicUsize::new(0),
        }
    }

    pub(super) fn reserve(self: &Arc<Self>, bytes: usize) -> Result<HostScope, String> {
        if bytes == 0 {
            return Err("transcript host reservation must be nonzero".into());
        }
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                live.checked_add(bytes).filter(|&next| next <= self.limit)
            })
            .map_err(|_| "simultaneous transcript host storage exceeds allowance")?;
        Ok(HostScope {
            owner: self.clone(),
            bytes,
        })
    }

    #[cfg(test)]
    pub(super) fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
}

impl HostScope {
    pub(super) fn check(&self, owner: &Arc<HostQuota>, bytes: usize) -> Result<(), String> {
        if !Arc::ptr_eq(&self.owner, owner) || bytes == 0 || bytes > self.bytes {
            return Err(
                "transcript host reservation belongs to another session or is too small".into(),
            );
        }
        Ok(())
    }
}

impl Drop for HostScope {
    fn drop(&mut self) {
        let previous = self.owner.live.fetch_sub(self.bytes, Ordering::AcqRel);
        debug_assert!(previous >= self.bytes);
    }
}

#[cfg(test)]
mod tests;
