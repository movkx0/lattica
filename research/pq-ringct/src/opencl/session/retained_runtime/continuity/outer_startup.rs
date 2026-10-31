//! Restore a sealed outer runtime startup original, without readmission.
use super::*;

pub(super) fn additional_host_bytes() -> usize {
    2 * size_of::<PendingRuntime>()
        + 2 * size_of::<core::RetiredRuntime>()
        + 2 * size_of::<std::result::Result<PendingRuntime, (RuntimeError, core::RetiredRuntime)>>()
        + 2 * size_of::<std::result::Result<Reservation, (core::Error, core::RetiredRuntime)>>()
        + 2 * size_of::<std::result::Result<core::StartupPlan, RuntimeError>>()
        + 2 * size_of::<core::StartupPlan>()
        + 2 * size_of::<Requirements>()
        + size_of::<Limits>()
        + size_of::<&Ledger>()
        + 2 * size_of::<Reservation>()
}

impl PendingRuntime {
    /// Only a genuine consuming Session retirement can issue this argument.
    /// Exact enclosing census, original ledger, host profile and absence of
    /// another phase binding are checked before moving the original owner.
    /// Refusal returns the complete seal; no quota is admitted or released.
    pub(crate) fn restore_retired_outer_host_v1(
        retired: core::RetiredRuntime,
        ledger: &Ledger,
        limits: Limits,
    ) -> Result<Self, (RuntimeError, core::RetiredRuntime)> {
        let plan = match restoration_plan(
            retired.startup_requirements(),
            retired.belongs_to(ledger),
            ledger,
            limits,
        ) {
            Ok(plan) => plan,
            Err(error) => return Err((error, retired)),
        };
        let startup = match retired.into_outer_host_original(ledger) {
            Ok(startup) => startup,
            Err((_, retired)) => return Err((RuntimeError::Lifecycle, retired)),
        };
        Ok(Self {
            selection: None,
            plan,
            limits,
            reservation: startup,
        })
    }
}
