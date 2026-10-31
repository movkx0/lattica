//! Restore only a source-preissued exact HashX successor and actual originals.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::{
    NativeHashxPhase, NativeHashxSuccessor, RetiredHashxReservations, SealedHashxStartup,
};

mod outer;

pub(crate) fn additional_hashx_host_bytes() -> usize {
    8 * size_of::<Result<PendingRuntime, RuntimeError>>()
        + 8 * size_of::<Result<PendingRuntimeGuard<'static>, RuntimeError>>()
        + 8 * size_of::<Result<Session, RuntimeError>>()
        + 8 * size_of::<Result<ReservedRuntime<'static>, RuntimeError>>()
        + 8 * size_of::<Result<OriginalRuntimeBorrow<'static>, RuntimeError>>()
        + 8 * size_of::<Result<core::RetiredRuntime, RuntimeError>>()
        + 8 * size_of::<Session>()
        + 8 * size_of::<RuntimeLifetime>()
        + 8 * size_of::<ActiveStart>()
        + 8 * size_of::<SealedHashxStartup>()
        + 8 * size_of::<core::StartupPlan>()
        + 8 * size_of::<Result<core::StartupPlan, RuntimeError>>()
        + 8 * size_of::<
            Result<
                (PendingRuntime, NativeHashxPhase),
                (RuntimeError, NativeHashxSuccessor, RetiredHashxReservations),
            >,
        >()
        + 8 * size_of::<PendingRuntime>()
        + 8 * size_of::<Limits>()
        + 8 * size_of::<Requirements>()
}

impl PendingRuntime {
    pub(crate) fn hashx_restoration_host_bytes() -> usize {
        additional_hashx_host_bytes()
    }

    pub(crate) fn restore_hashx_successor_outer_host_v1(
        successor: NativeHashxSuccessor,
        originals: RetiredHashxReservations,
        preparation: &Reservation,
        verification: &Reservation,
        ledger: &Ledger,
        limits: Limits,
    ) -> Result<
        (Self, NativeHashxPhase),
        (RuntimeError, NativeHashxSuccessor, RetiredHashxReservations),
    > {
        let plan = match restoration_plan(
            originals.startup_requirements(),
            originals.belongs_to(ledger),
            ledger,
            limits,
        ) {
            Ok(plan) => plan,
            Err(error) => return Err((error, successor, originals)),
        };
        match successor.restore(originals, preparation, verification, ledger) {
            Err((_, successor, originals)) => Err((RuntimeError::Lifecycle, successor, originals)),
            Ok((phase, startup)) => Ok((
                PendingRuntime {
                    selection: None,
                    plan,
                    limits,
                    reservation: startup.into_original(),
                },
                phase,
            )),
        }
    }
}
