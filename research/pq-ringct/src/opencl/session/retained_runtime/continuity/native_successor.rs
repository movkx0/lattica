//! Restore only the sealed startup issued by the actual native-successor move.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::owned_shake::{
    NativeShakePhase, NativeShakeSuccessor, SealedNativeStartup,
};

pub(super) fn additional_host_bytes() -> usize {
    4 * size_of::<SealedNativeStartup>()
        + 4 * size_of::<core::StartupPlan>()
        + 4 * size_of::<Result<core::StartupPlan, RuntimeError>>()
        + 4 * size_of::<
            Result<
                (PendingRuntime, NativeShakePhase),
                (
                    RuntimeError,
                    NativeShakeSuccessor,
                    RetiredNativeReservations,
                ),
            >,
        >()
        + 4 * size_of::<PendingRuntime>()
        + 4 * size_of::<Limits>()
        + 4 * size_of::<Requirements>()
}

// Called only after restoration_plan validates the complete actual original
// startup, then core moves exactly that same owner into this unforgeable seal.
// No subsequent fallible operation can strand a transformed input owner.
fn restore_sealed(
    plan: core::StartupPlan,
    limits: Limits,
    startup: SealedNativeStartup,
) -> PendingRuntime {
    PendingRuntime {
        selection: None,
        plan,
        limits,
        reservation: startup.into_original(),
    }
}

impl PendingRuntime {
    /// Prepare the exact restoration plan before consuming either input. Core
    /// validates the successful original retirement and source-preissued next
    /// phase before issuing its sealed startup. Every refusal preserves both
    /// complete owners; success neither admits quota nor queries a device.
    pub(crate) fn restore_native_successor_outer_host_v1(
        successor: NativeShakeSuccessor,
        originals: RetiredNativeReservations,
        preparation: &Reservation,
        verification: &Reservation,
        ledger: &Ledger,
        limits: Limits,
    ) -> Result<
        (Self, NativeShakePhase),
        (
            RuntimeError,
            NativeShakeSuccessor,
            RetiredNativeReservations,
        ),
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
            Ok((phase, startup)) => Ok((restore_sealed(plan, limits, startup), phase)),
        }
    }
}
