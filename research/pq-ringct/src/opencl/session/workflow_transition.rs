//! One-way retirement of the ordinary source-preparation session.
//! A returned borrow proves real shutdown of that Session; copied telemetry
//! never authorizes another runtime or dispatch. Later epochs need original
//! startup reservations and the source-closed native/outer issuers.
use super::*;
use std::{cell::Cell, time::Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ordinary,
    Retiring,
    Retired,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionError {
    Lifecycle,
    ReservedSession,
    QueueDrain,
    MissingObservation,
    ManagedAllowance,
    Shutdown,
}

/// Fixed inline evidence from the actual retired source epoch. These values
/// are observations only, including source preparation rather than GPU proof
/// work. Full process/driver memory remains the external runner's duty.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(crate) struct SourceRetirement {
    pub elapsed_ns: u128,
    pub managed_peak_bytes: usize,
    pub allocations: u64,
    pub commits: u64,
    pub uploaded_bytes: u64,
    pub downloaded_bytes: u64,
    pub queue_drained: bool,
    pub context_closed: bool,
}

pub(super) struct State {
    phase: Cell<Phase>,
    retirement: Cell<Option<SourceRetirement>>,
}

impl State {
    pub(super) fn new() -> Self {
        Self { phase: Cell::new(Phase::Ordinary), retirement: Cell::new(None) }
    }

    fn begin(&self) -> Result<(), TransitionError> {
        if self.phase.get() != Phase::Ordinary {
            return Err(TransitionError::Lifecycle);
        }
        self.phase.set(Phase::Retiring);
        Ok(())
    }

    pub(super) fn retired(&self) -> bool {
        self.phase.get() == Phase::Retired
    }

    pub(super) fn legacy_open(&self) -> bool {
        self.phase.get() == Phase::Ordinary
    }
}

/// Prepared-state cleanup remains inside the enclosing original source phase.
/// Dropping this guard, including on an asynchronous error, permanently blocks
/// legacy dispatch. Explicit final destruction may still retry raw shutdown.
pub(crate) struct RetiringSourceSession<'session> {
    session: &'session Session,
    started: Instant,
    completed: bool,
}

/// Non-Clone, nonconstructible proof that this exact ordinary Session retired.
/// The Session and its public identity remain borrowed through later epochs.
pub(crate) struct RetiredSourceSession<'session> {
    session: &'session Session,
}

impl Session {
    pub(crate) fn workflow_transition_additional_host_bytes() -> usize { additional_host_bytes() }

    pub(crate) fn begin_workflow_retirement(&self) -> Result<RetiringSourceSession<'_>, TransitionError> {
        if self.closed {
            return Err(TransitionError::Lifecycle);
        }
        if self.runtime_lifetime.is_some() {
            return Err(TransitionError::ReservedSession);
        }
        self.workflow_transition.begin()?;
        Ok(RetiringSourceSession { session: self, started: Instant::now(), completed: false })
    }

    pub(crate) fn check_legacy_workflow_dispatch(&self) -> Result<(), &'static str> {
        if self.closed || !self.workflow_transition.legacy_open() {
            return Err("ordinary Session retired or poisoned by owned workflow transition");
        }
        Ok(())
    }

    /// Cleanup only; a retired Session must not drain or destroy a later owned
    /// epoch. A failed transition still owns its old engine and may clean it up.
    pub(crate) fn needs_ordinary_workflow_cleanup(&self) -> bool {
        !self.closed && !self.workflow_transition.retired()
    }
}

impl<'session> RetiringSourceSession<'session> {
    pub(crate) fn retire(mut self) -> Result<RetiredSourceSession<'session>, TransitionError> {
        gpu_hash::drain().map_err(|_| TransitionError::QueueDrain)?;
        let snapshot = gpu_hash::report("owned workflow source session retirement")
            .ok_or(TransitionError::MissingObservation)?;
        if snapshot.managed_peak_bytes as u64 > self.session.limits.device_bytes {
            return Err(TransitionError::ManagedAllowance);
        }
        // This checks outstanding leases, drains the real queue, and destroys
        // the actual engine. No bit-only close or legacy-engine adoption occurs.
        gpu_hash::shutdown().map_err(|_| TransitionError::Shutdown)?;
        self.session.workflow_transition.retirement.set(Some(SourceRetirement {
            elapsed_ns: self.started.elapsed().as_nanos(),
            managed_peak_bytes: snapshot.managed_peak_bytes,
            allocations: snapshot.allocations,
            commits: snapshot.commits,
            uploaded_bytes: snapshot.uploaded_bytes,
            downloaded_bytes: snapshot.downloaded_bytes,
            queue_drained: true,
            context_closed: true,
        }));
        self.session.workflow_transition.phase.set(Phase::Retired);
        ACTIVE.store(false, Ordering::Release);
        self.completed = true;
        Ok(RetiredSourceSession { session: self.session })
    }
}

impl Drop for RetiringSourceSession<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.session.workflow_transition.phase.set(Phase::Failed);
        }
    }
}

impl RetiredSourceSession<'_> {
    pub(crate) fn retirement(&self) -> SourceRetirement {
        self.session.workflow_transition.retirement.get().expect("sealed source retirement")
    }

    pub(crate) fn limits(&self) -> Limits { self.session.limits }

    pub(crate) fn device_identity(&self) -> &Identity { &self.session.device }

    pub(crate) fn belongs_to(&self, session: &Session) -> bool {
        core::ptr::eq(self.session, session) && session.workflow_transition.retired()
    }
}

/// Additive transition frames. The owning Session/census already charges the
/// inline State and retained public identity; no extra allocation is required.
pub(crate) fn additional_host_bytes() -> usize {
    4 * core::mem::size_of::<RetiringSourceSession<'static>>()
        + 4 * core::mem::size_of::<RetiredSourceSession<'static>>()
        + 4 * core::mem::size_of::<SourceRetirement>()
        + 4 * core::mem::size_of::<Result<RetiredSourceSession<'static>, TransitionError>>()
        + 2 * core::mem::size_of::<lattica_prover_p3::block_v2::gpu_hash::Snapshot>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_is_one_way_and_never_reopens_failed_dispatch() {
        let state = State::new();
        assert!(state.legacy_open());
        state.begin().unwrap();
        assert!(!state.legacy_open());
        assert!(!state.retired());
        assert_eq!(state.begin(), Err(TransitionError::Lifecycle));
        state.phase.set(Phase::Failed);
        assert!(!state.legacy_open());
        assert_eq!(state.begin(), Err(TransitionError::Lifecycle));
    }

    #[test]
    fn retired_state_cannot_restart_an_ordinary_epoch() {
        let state = State::new();
        state.begin().unwrap();
        state.phase.set(Phase::Retired);
        assert!(state.retired());
        assert!(!state.legacy_open());
        assert_eq!(state.begin(), Err(TransitionError::Lifecycle));
    }
}
