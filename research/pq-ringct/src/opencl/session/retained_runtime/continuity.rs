//! Move the actual private startup token through exact consuming retirement.
use super::*;
use crate::execution::retained_resources::Requirements;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::RetiredNativeReservations;

pub(super) fn additional_host_bytes() -> usize {
    2 * size_of::<std::result::Result<core::RetiredRuntime, RuntimeError>>()
        + size_of::<Session>()
        + size_of::<RuntimeLifetime>()
        + size_of::<Reservation>()
        + size_of::<Ledger>()
        + 2 * size_of::<
            std::result::Result<
                (PendingRuntime, Reservation, Reservation),
                (RuntimeError, RetiredNativeReservations),
            >,
        >()
        + 2 * size_of::<Requirements>()
        + 2 * size_of::<core::StartupPlan>()
        + 2 * size_of::<std::result::Result<core::StartupPlan, RuntimeError>>()
        + outer_startup::additional_host_bytes()
        + native_successor::additional_host_bytes()
}

// Pure source checks only. The public continuation below additionally requires
// the unforgeable original owner; these numbers never construct a pending owner.
fn restoration_plan(
    original: Requirements,
    original_ledger: bool,
    ledger: &Ledger,
    limits: Limits,
) -> Result<core::StartupPlan, RuntimeError> {
    fixed_limits(limits)?;
    let allowance = ledger.snapshot().allowance;
    if allowance.host == 0
        || allowance.host > limits.host_bytes
        || allowance.device == 0
        || allowance.device > MANAGED_DEVICE
    {
        return Err(RuntimeError::Configuration);
    }
    let plan = core::StartupPlan::outer_host_v1().map_err(|_| RuntimeError::Configuration)?;
    if !original_ledger {
        return Err(RuntimeError::WrongLedger);
    }
    if original != Requirements::single(Category::PhaseScratch, requested(&plan)?) {
        return Err(RuntimeError::Admission);
    }
    Ok(plan)
}

impl PendingRuntime {
    /// Consume the sealed original native-retirement owner and restore only
    /// its actual host startup token. No raw token or copied retirement receipt
    /// can call this path. It performs no admission or device selection.
    /// Refusal returns the complete original owner; success also returns its
    /// unchanged original wrapper and PCS tokens to the closed phase planner.
    pub(crate) fn restore_outer_host_v1(
        originals: RetiredNativeReservations,
        ledger: &Ledger,
        limits: Limits,
    ) -> Result<(Self, Reservation, Reservation), (RuntimeError, RetiredNativeReservations)> {
        let plan = match restoration_plan(
            originals.startup_requirements(),
            originals.belongs_to(ledger),
            ledger,
            limits,
        ) {
            Ok(plan) => plan,
            Err(error) => return Err((error, originals)),
        };
        let (startup, wrappers, pcs) = originals.into_originals();
        Ok((
            Self {
                selection: None,
                plan,
                limits,
                reservation: startup,
            },
            wrappers,
            pcs,
        ))
    }
}

impl Session {
    /// Retire the actual runtime and destroy its selection/device storage,
    /// while retaining the original startup token in a sealed core owner.
    /// The caller receives no detached token or numerically forgeable marker.
    pub(crate) fn finish_reserved_with_owner(
        mut self,
        ledger: &Ledger,
    ) -> Result<core::RetiredRuntime, RuntimeError> {
        if self.closed {
            return Err(RuntimeError::Lifecycle);
        }
        let lifetime = self
            .runtime_lifetime
            .as_ref()
            .ok_or(RuntimeError::MissingOwner)?;
        if !lifetime.reservation.belongs_to(ledger) {
            return Err(RuntimeError::WrongLedger);
        }
        // The previous immutable check guarantees Some and has ended. Moving
        // these private fields is the only issuer of this continuation path.
        let RuntimeLifetime {
            runtime,
            reservation,
        } = self
            .runtime_lifetime
            .take()
            .expect("checked original runtime");
        // SAFETY: PendingRuntime::start stored this exact runtime/reservation
        // pair together. The Session's immutable-process contract still holds.
        let retired = unsafe {
            runtime
                .into_inner()
                .retire_with_original(reservation, ledger)
        };
        match retired {
            Ok(retired) => {
                self.closed = true;
                ACTIVE.store(false, Ordering::Release);
                // The returned original reservation also backs the remaining
                // Session identity strings until they are destroyed here.
                drop(self);
                Ok(retired)
            }
            Err((_, runtime, original)) => {
                // Preserve exact runtime-before-quota ordering on refusal.
                // Runtime Drop aborts if actual cleanup cannot be established.
                drop(runtime);
                self.closed = true;
                ACTIVE.store(false, Ordering::Release);
                drop(self);
                drop(original);
                Err(RuntimeError::Lifecycle)
            }
        }
    }
}

#[cfg(all(test, not(debug_assertions)))]
mod tests;

mod outer_startup;

mod native_successor;
mod hashx;
