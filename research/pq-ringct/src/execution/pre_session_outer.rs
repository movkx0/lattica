//! CLOSED pre-session reservation scaffold for an outer backend schedule.
//!
//! Unlike a live ProvingContext capability, this can inspect an idle engine
//! before Session initialization. It deliberately has no Session constructor,
//! registration/proving method, callback, or admission-token accessor. A
//! borrowed source graph has no complete enclosing reservation, and the
//! existing Session drop path cannot retain outer leases on uncertain cleanup.
//! Neither missing authority can be manufactured by reserving numeric bytes.
use super::retained_resources::{Bytes, Category, Ledger, Reservation, Snapshot};
use lattica_prover_p3::block_v2::machine::{
    program::{Program, Val},
    OuterBackendAdmission, OuterBackendFootprint, OuterBackendPlan, RegisteredGpuLimits,
};
use std::sync::Arc;

const WORKER_HOST: u64 = 32 << 30;
const MANAGED_DEVICE: u64 = 8 << 30;
const CONTEXT_DEVICE: u64 = 4 << 30;
const NATIVE_HOST: u64 = 24 << 30;
pub(crate) use super::retained_resources::OUTER_PLANNING_HOST_BYTES as PLANNING_HOST;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    WorkerEnvelope,
    PlanningReservation,
    ExecutionSelection,
    NativeAllowance,
    BackendPlan,
    BackendReservation,
    BackendAdmission,
}

/// Fixed outstanding boundaries, not switches that a caller can set to true.
/// No constructor accepting declarations can turn this scaffold into dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MissingBoundary {
    CompleteSourceGraphOwnership,
    RuntimeReportAndErrorBound,
    CleanupLifetime,
}
pub(crate) const MISSING: [MissingBoundary; 3] = [
    MissingBoundary::CompleteSourceGraphOwnership,
    MissingBoundary::RuntimeReportAndErrorBound,
    MissingBoundary::CleanupLifetime,
];

#[derive(Clone, Copy, Debug)]
pub(crate) struct Report {
    pub(crate) backend: OuterBackendFootprint,
    pub(crate) while_reserved: Snapshot,
    pub(crate) planning_host_bytes: u64,
    pub(crate) backend_host_bytes: u64,
    pub(crate) backend_device_bytes: u64,
    pub(crate) missing: [MissingBoundary; 3],
    pub(crate) source_graph_owned: bool,
    pub(crate) cleanup_lifetime_bound: bool,
    pub(crate) workflow_admitted: bool,
}

/// This fixed claim precedes source inspection, selection capture, output
/// planning and all bounded core planner temporaries. It is not backend memory.
pub(crate) struct PlanningLease {
    ledger: Ledger,
    reservation: Reservation,
}
impl PlanningLease {
    pub(crate) fn reserve(ledger: &Ledger) -> Result<Self, Error> {
        let snapshot = ledger.snapshot();
        if snapshot.allowance.host == 0
            || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(snapshot.allowance.host)
            || snapshot.allowance.device != MANAGED_DEVICE
        {
            // A CPU compiler capability has device allowance zero. Its token
            // cannot be silently upgraded into a GPU pre-session capability.
            return Err(Error::WorkerEnvelope);
        }
        let reservation = ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: PLANNING_HOST,
                    device: 0,
                },
            )
            .map_err(|_| Error::PlanningReservation)?;
        Ok(Self {
            ledger: ledger.clone(),
            reservation,
        })
    }

    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.reservation.belongs_to(ledger)
    }

    /// Source-only schedule inspection. Actual source/input/output owners must
    /// already retain their claims in this ledger; the caller binds those
    /// owners. No core capability is exposed to the caller on success.
    pub(crate) fn inspect<'inputs>(
        self,
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
        max_rows: usize,
    ) -> Result<ClosedBackendScope<'inputs>, Error> {
        let limits =
            RegisteredGpuLimits::new(WORKER_HOST, MANAGED_DEVICE, CONTEXT_DEVICE, max_rows)
                .map_err(|_| Error::ExecutionSelection)?;
        let remaining = self.ledger.remaining();
        let native = remaining
            .host
            .checked_sub(limits.retained_tree_host_bytes())
            .filter(|bytes| *bytes > 0)
            .ok_or(Error::NativeAllowance)?
            .min(NATIVE_HOST);
        let plan = OuterBackendPlan::new(program, public, witness, limits, native)
            .map_err(|_| Error::BackendPlan)?;
        let footprint = plan.footprint();
        let backend = self
            .ledger
            .reserve(
                Category::PhaseScratch,
                Bytes {
                    host: footprint.backend_scope_host_bytes,
                    // Keep the full managed allowance even if the selected
                    // fixed phase peak is smaller. No idle-state overlap credit.
                    device: MANAGED_DEVICE,
                },
            )
            .map_err(|_| Error::BackendReservation)?;
        let admission = plan.admit().map_err(|_| Error::BackendAdmission)?;
        let report = Report {
            backend: footprint,
            while_reserved: self.ledger.snapshot(),
            planning_host_bytes: PLANNING_HOST,
            backend_host_bytes: footprint.backend_scope_host_bytes,
            backend_device_bytes: MANAGED_DEVICE,
            missing: MISSING,
            source_graph_owned: false,
            cleanup_lifetime_bound: false,
            workflow_admitted: false,
        };
        Ok(ClosedBackendScope {
            _admission: admission,
            report,
            _backend: backend,
            _planning: self,
        })
    }
}

/// The admission remains private and has no extraction path. Since no session
/// can be created, destruction is synchronous and cannot release in-flight
/// device owners. A future OwnedOuterPhase needs a separately reviewed cleanup
/// owner; adding a Session field here would violate this scaffold's contract.
pub(crate) struct ClosedBackendScope<'inputs> {
    _admission: OuterBackendAdmission<'inputs>,
    report: Report,
    _backend: Reservation,
    _planning: PlanningLease,
}
impl ClosedBackendScope<'_> {
    pub(crate) fn report(&self) -> Report {
        self.report
    }
}

// Inline reports and copies fit inside the existing 1 MiB planner/caller
// allowance; no JSON tree, heap report, callback or runtime error is retained.
const _: () = assert!(
    core::mem::size_of::<ClosedBackendScope<'static>>()
        + 8 * core::mem::size_of::<Report>()
        + (64 << 10)
        < PLANNING_HOST as usize
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::retained_resources::WorkerAllowance;

    #[test]
    fn closed_planning_claim_moves_and_releases_in_its_original_ledger() {
        let ledger = Ledger::new(WorkerAllowance {
            host: WORKER_HOST,
            device: MANAGED_DEVICE,
        });
        let other = Ledger::new(WorkerAllowance {
            host: WORKER_HOST,
            device: MANAGED_DEVICE,
        });
        let owner = ledger
            .reserve(
                Category::CompilerInputs,
                Bytes {
                    host: 17,
                    device: 0,
                },
            )
            .unwrap();
        let before = ledger.snapshot();
        let planning = PlanningLease::reserve(&ledger).unwrap();
        assert!(planning.belongs_to(&ledger));
        assert!(!planning.belongs_to(&other));
        assert_eq!(
            ledger.snapshot().current.host,
            before.current.host + PLANNING_HOST
        );
        assert_eq!(ledger.snapshot().current.device, 0);
        let moved = planning;
        assert_eq!(
            ledger.snapshot().current.host,
            before.current.host + PLANNING_HOST
        );
        drop(moved);
        assert_eq!(ledger.snapshot().current, before.current);
        drop(owner);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }

    #[test]
    fn cpu_and_oversized_allowances_cannot_create_pre_session_gpu_claims() {
        for allowance in [
            WorkerAllowance {
                host: WORKER_HOST,
                device: 0,
            },
            WorkerAllowance {
                host: WORKER_HOST + 1,
                device: MANAGED_DEVICE,
            },
            WorkerAllowance {
                host: WORKER_HOST,
                device: MANAGED_DEVICE + 1,
            },
            WorkerAllowance {
                host: 0,
                device: MANAGED_DEVICE,
            },
        ] {
            let ledger = Ledger::new(allowance);
            assert!(matches!(
                PlanningLease::reserve(&ledger),
                Err(Error::WorkerEnvelope)
            ));
            assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        }
        let ledger = Ledger::new(WorkerAllowance {
            host: PLANNING_HOST - 1,
            device: MANAGED_DEVICE,
        });
        assert!(matches!(
            PlanningLease::reserve(&ledger),
            Err(Error::PlanningReservation)
        ));
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
