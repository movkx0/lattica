//! Unused accounting/lifecycle prerequisite for one serial execution context.
//!
//! This module supplies no footprint derivation, workflow admission or dispatch
//! authority. Only execution-owned code can bind a capability and start a phase;
//! a future trusted planner must account for enclosing owners before binding and
//! derive every simultaneous phase request before allocating. The existing
//! baseline methods do not consult this state and remain unchanged.
//!
//! Charge the existing backend's complete allowance once in `PhaseScratch`.
//! Its internal compiler/PCS/verifier partition is not another outer charge.
//! Separately owned children, inputs, reports and external verification need
//! their own categories. A planner must establish any claimed overlap; this
//! module never subtracts estimated internal storage or increases an allowance.
//!
//! Completion uses the actual context's prepared-release and queue-drain paths.
//! It does not prove that arbitrary caller-owned native/backend locals have
//! dropped. Future typed adapters must enforce those lifetimes, phase-specific
//! limits (including the native sublimit), and exclusive use of this capability
//! before any runtime integration. No paired path or prepared retention is added.
//! Escaping cleanup diagnostics are fixed inline stage codes. Existing backend
//! error construction/logging may still allocate temporarily; a future trusted
//! phase bound must cover those failure paths before granting runtime authority.
use super::{
    retained_resources::{
        Bytes, Category, Error as ReservationError, Ledger, Requirements, Reservation,
        WorkerAllowance,
    },
    ProvingContext,
};
use std::cell::{OnceCell, RefCell};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Unbound,
    Ready,
    Active,
    Poisoned,
    Retired,
}

/// No owned message can outlive a phase after successful cleanup releases its
/// reservation. Existing backend diagnostics retain their established scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CleanupFailure {
    PreparedRelease,
    QueueDrain,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Error {
    AlreadyBound,
    WorkAlreadyStarted,
    EnclosingAllowance,
    EmptyPhase,
    GenerationExhausted,
    NotReady(Status),
    StalePhase,
    BackendReservationCannotEscape,
    Reservation(ReservationError),
    Cleanup(CleanupFailure),
}

impl From<ReservationError> for Error {
    fn from(error: ReservationError) -> Self {
        Self::Reservation(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "execution phase lifecycle: {self:?}")
    }
}
impl std::error::Error for Error {}

struct State {
    status: Status,
    generation: u64,
    // Data owners must drop before successful cleanup releases this token.
    held: Option<Reservation>,
}

/// Construction is allocation-free. No ledger exists on the baseline path.
pub(super) struct ContextPhases {
    ledger: OnceCell<Ledger>,
    state: RefCell<State>,
}

impl ContextPhases {
    pub(super) fn new() -> Self {
        Self {
            ledger: OnceCell::new(),
            state: RefCell::new(State {
                status: Status::Unbound,
                generation: 0,
                held: None,
            }),
        }
    }

    fn bind(&self, allowance: WorkerAllowance, enclosing: Bytes) -> Result<(), Error> {
        if self.ledger.get().is_some() {
            return Err(Error::AlreadyBound);
        }
        // The enclosing charge includes this fixed bookkeeping and any graph,
        // fixture, public-cache or allocator reserve accounted outside the
        // ledger. It is not a second allowance. The caller derives that charge.
        let remaining = WorkerAllowance {
            host: allowance
                .host
                .checked_sub(enclosing.host)
                .ok_or(Error::EnclosingAllowance)?,
            device: allowance
                .device
                .checked_sub(enclosing.device)
                .ok_or(Error::EnclosingAllowance)?,
        };
        self.ledger
            .set(Ledger::new(remaining))
            .map_err(|_| Error::AlreadyBound)?;
        self.state.borrow_mut().status = Status::Ready;
        Ok(())
    }

    fn ledger(&self) -> &Ledger {
        self.ledger.get().expect("bound execution capability")
    }

    fn admit(&self, requirements: Requirements) -> Result<u64, Error> {
        let mut state = self.state.borrow_mut();
        if state.status != Status::Ready {
            return Err(Error::NotReady(state.status));
        }
        if requirements.total()? == Bytes::ZERO {
            return Err(Error::EmptyPhase);
        }
        let generation = state
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        // All categories share one atomic admission. Refusal leaves both the
        // existing owners and the phase state/generation unchanged.
        let held = self.ledger().admit_phase(requirements)?;
        state.held = Some(held);
        state.generation = generation;
        state.status = Status::Active;
        Ok(generation)
    }

    fn check_active(state: &State, generation: u64) -> Result<(), Error> {
        if state.status != Status::Active || state.generation != generation {
            return Err(Error::StalePhase);
        }
        Ok(())
    }

    fn split(&self, generation: u64, requested: Requirements) -> Result<Reservation, Error> {
        let mut state = self.state.borrow_mut();
        Self::check_active(&state, generation)?;
        // The backend envelope always survives until context cleanup. Outputs
        // and external verifier tokens may move without releasing a charge.
        if requested.get(Category::PhaseScratch) != Bytes::ZERO {
            return Err(Error::BackendReservationCannotEscape);
        }
        Ok(state
            .held
            .as_mut()
            .expect("active phase reservation")
            .split(requested)?)
    }

    fn abandon(&self, generation: u64) {
        let mut state = self.state.borrow_mut();
        if state.status == Status::Active && state.generation == generation {
            state.status = Status::Poisoned;
        }
    }

    // Private injection point for lifecycle tests. The only non-test caller
    // passes the actual context adapter below, never a caller cleanup receipt.
    fn complete_with_cleanup(
        &self,
        generation: u64,
        cleanup: impl FnOnce() -> Result<(), CleanupFailure>,
    ) -> Result<(), Error> {
        Self::check_active(&self.state.borrow(), generation)?;
        let result = cleanup();
        let mut state = self.state.borrow_mut();
        Self::check_active(&state, generation)?;
        if let Err(error) = result {
            state.status = Status::Poisoned;
            return Err(Error::Cleanup(error));
        }
        let held = state.held.take();
        state.status = Status::Ready;
        drop(state);
        drop(held);
        Ok(())
    }

    fn retire_with_cleanup(
        &self,
        cleanup: impl FnOnce() -> Result<(), CleanupFailure>,
    ) -> Result<(), Error> {
        match self.state.borrow().status {
            Status::Retired => return Ok(()),
            Status::Ready | Status::Poisoned => {}
            status => return Err(Error::NotReady(status)),
        }
        let result = cleanup();
        let mut state = self.state.borrow_mut();
        if let Err(error) = result {
            state.status = Status::Poisoned;
            return Err(Error::Cleanup(error));
        }
        // Cleanup may be retried after failure, but proof dispatch cannot be:
        // successful recovery retires this accounting scope permanently.
        let held = state.held.take();
        state.status = Status::Retired;
        drop(state);
        drop(held);
        Ok(())
    }
}

impl Drop for ContextPhases {
    fn drop(&mut self) {
        if let Some(held) = self.state.get_mut().held.take() {
            // Abandonment is not evidence of GPU retirement. Strand at most one
            // fixed-size reservation plus its shared ledger bookkeeping instead
            // of reopening capacity in a surviving ledger handle. This does not
            // retain proof payloads. Explicit successful cleanup avoids this
            // bounded bookkeeping leak; an unclean worker must terminate.
            std::mem::forget(held);
        }
    }
}

/// Linear capability; only execution-owned code can construct it. Its borrowed
/// context and that context's OnceCell prevent cross-context use or replacement
/// with a fresh ledger after phase/output tokens have escaped.
#[must_use = "retire the accounting scope after its final phase"]
pub(crate) struct PhaseCapability<'context> {
    context: &'context ProvingContext,
}

impl ProvingContext {
    /// Accounting only. The future execution-owned workflow planner must supply
    /// the enclosing bound before any baseline/proving work has been attempted.
    /// This private entry point does not validate a workflow or admit dispatch.
    pub(super) fn phase_capability(&self, enclosing: Bytes) -> Result<PhaseCapability<'_>, Error> {
        if self.diagnostics.has_work_attempted() {
            return Err(Error::WorkAlreadyStarted);
        }
        #[cfg(feature = "opencl")]
        let device = self
            .session
            .as_ref()
            .map_or(0, |session| session.limits().device_bytes);
        #[cfg(not(feature = "opencl"))]
        let device = 0;
        self.phases.bind(
            WorkerAllowance {
                host: self.host_bytes,
                device,
            },
            enclosing,
        )?;
        Ok(PhaseCapability { context: self })
    }

    fn cleanup_accounted_phase(&self) -> Result<(), CleanupFailure> {
        // release_prepared drains before dropping the prepared allocation. A
        // final drain also closes work submitted by its destruction. Failures
        // retain the phase reservation and poison the accounting scope.
        // Drop the backend's owned error while the phase charge is still held.
        // Its temporary construction is a separate future backend-bound duty.
        self.release_prepared()
            .map_err(|_| CleanupFailure::PreparedRelease)?;
        #[cfg(feature = "opencl")]
        if self.session.is_some() {
            lattica_prover_p3::block_v2::gpu_hash::drain()
                .map_err(|_| CleanupFailure::QueueDrain)?;
        }
        Ok(())
    }
}

impl<'context> PhaseCapability<'context> {
    pub(crate) fn ledger(&self) -> &Ledger {
        self.context.phases.ledger()
    }

    pub(crate) fn belongs_to(&self, context: &ProvingContext) -> bool {
        std::ptr::eq(self.context, context)
    }

    pub(crate) fn status(&self) -> Status {
        self.context.phases.state.borrow().status
    }

    /// Caller requirements must come from the future trusted execution planner.
    /// Restrict issuance to execution-owned code; other modules may only receive
    /// the resulting borrowed lease and split its already-admitted outputs.
    pub(super) fn admit(
        &mut self,
        requirements: Requirements,
    ) -> Result<PhaseLease<'_, 'context>, Error> {
        let generation = self.context.phases.admit(requirements)?;
        Ok(PhaseLease {
            capability: self,
            generation,
            completed: false,
        })
    }

    pub(crate) fn retire(&mut self) -> Result<(), Error> {
        self.context
            .phases
            .retire_with_cleanup(|| self.context.cleanup_accounted_phase())
    }
}

impl Drop for PhaseCapability<'_> {
    fn drop(&mut self) {
        let mut state = self.context.phases.state.borrow_mut();
        match state.status {
            Status::Ready => state.status = Status::Retired,
            // A forgotten lease cannot turn an abandoned phase into readiness.
            Status::Active => state.status = Status::Poisoned,
            _ => {}
        }
    }
}

/// Borrowing the linear capability prevents a second phase while this lease is
/// live. Its reservation stays in the context, so Err/unwind/abandonment cannot
/// release storage still used by asynchronous work.
#[must_use = "finish through actual context cleanup or leave the scope poisoned"]
pub(crate) struct PhaseLease<'phase, 'context> {
    capability: &'phase mut PhaseCapability<'context>,
    generation: u64,
    completed: bool,
}

impl PhaseLease<'_, '_> {
    pub(crate) fn ledger(&self) -> &Ledger {
        self.capability.ledger()
    }

    pub(crate) fn belongs_to(&self, context: &ProvingContext) -> bool {
        self.capability.belongs_to(context)
    }

    pub(crate) fn backend_allowance(&self) -> Result<Bytes, Error> {
        let state = self.capability.context.phases.state.borrow();
        ContextPhases::check_active(&state, self.generation)?;
        Ok(state
            .held
            .as_ref()
            .expect("active phase reservation")
            .requirements()
            .get(Category::PhaseScratch))
    }

    /// Transfer already-reserved outputs/verifier scratch to their real owners.
    /// Those owners must release actual data before dropping the returned token.
    pub(crate) fn split(&mut self, requested: Requirements) -> Result<Reservation, Error> {
        self.capability
            .context
            .phases
            .split(self.generation, requested)
    }

    pub(crate) fn complete_after_cleanup(mut self) -> Result<(), Error> {
        let context = self.capability.context;
        let result = context
            .phases
            .complete_with_cleanup(self.generation, || context.cleanup_accounted_phase());
        self.completed = true;
        result
    }
}

impl Drop for PhaseLease<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.capability.context.phases.abandon(self.generation);
        }
    }
}

#[cfg(test)]
mod tests;
