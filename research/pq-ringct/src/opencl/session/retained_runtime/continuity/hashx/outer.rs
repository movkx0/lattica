//! Private adapter for the original HashX startup; no research token getter.
use super::*;
use lattica_prover_p3::block_v2::{
    machine::PreissuedOuterBackend,
    native_gpu::owned_shake::{
        BoundHashxOuterBackend, HashxOuterBackend, PreissuedHashxOuterBackend,
    },
};

pub(super) fn additional_host_bytes() -> usize {
    8 * size_of::<Result<PreissuedHashxOuterBackend, RuntimeError>>()
        + 8 * size_of::<Result<(PendingRuntime, HashxOuterBackend<'static>), RuntimeError>>()
        + 8 * size_of::<(PendingRuntime, HashxOuterBackend<'static>)>()
        + 8 * size_of::<BoundHashxOuterBackend<'static>>()
        + 8 * size_of::<HashxOuterBackend<'static>>()
        + 8 * size_of::<SealedHashxStartup>()
        + 8 * size_of::<PendingRuntime>()
        + 8 * size_of::<core::StartupPlan>()
        + 8 * size_of::<Requirements>()
        + 8 * size_of::<Limits>()
        + (8 << 10)
}

impl PendingRuntime {
    pub(crate) fn hashx_outer_restoration_host_bytes() -> usize {
        additional_host_bytes()
    }

    pub(crate) fn prebind_hashx_outer_backend(
        &self,
        phase: &NativeHashxPhase,
        backend: PreissuedOuterBackend,
        preparation: &Reservation,
        verifier: &Reservation,
        metadata: &Reservation,
        ledger: &Ledger,
    ) -> Result<PreissuedHashxOuterBackend, RuntimeError> {
        restoration_plan(
            self.reservation.requirements(),
            self.belongs_to(ledger),
            ledger,
            self.limits,
        )?;
        if self.reserved_tree_host_bytes() != 8 << 30 || self.selection.is_none() {
            return Err(RuntimeError::Lifecycle);
        }
        phase
            .prebind_outer_backend(
                backend,
                &self.reservation,
                preparation,
                verifier,
                metadata,
                ledger,
            )
            .map_err(|_| RuntimeError::Lifecycle)
    }

    /// The public research caller receives two opaque owners, never the
    /// startup/PCS/wrapper reservations. Any refusal consumes the whole input.
    pub(crate) fn restore_bound_hashx_outer<'inputs>(
        bound: BoundHashxOuterBackend<'inputs>,
        ledger: &Ledger,
        limits: Limits,
    ) -> Result<(Self, HashxOuterBackend<'inputs>), RuntimeError> {
        let plan = restoration_plan(
            bound.startup_requirements(),
            bound.belongs_to(ledger),
            ledger,
            limits,
        )?;
        let (startup, backend) = bound
            .restore_startup(ledger)
            .map_err(|_| RuntimeError::Lifecycle)?;
        Ok((
            Self {
                selection: None,
                plan,
                limits,
                reservation: startup.into_original(),
            },
            backend,
        ))
    }
}
