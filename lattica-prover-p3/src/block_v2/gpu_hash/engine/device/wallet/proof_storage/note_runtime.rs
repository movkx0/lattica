//! Note-specific ownership bridge from a pre-context phase model to the exact
//! live engine. This module provides no public dispatch API or quota authority.
//! A consumed shared-quota reservation follows the plan into the capacity owner
//! and remains live through destruction of the plan and device session.
use super::{phases, WalletDevicePlan, WalletProofMinimum};
use crate::block_v2::gpu_hash::{
    device::{self, DeviceSession, ProofCapacity},
    engine::{self, Limits},
};
use crate::note_research_quota::Reservation;
use device::note_quotient_policy::NoteQuotientPlan;
use phases::{planner_storage::PlannerResources, runtime_geometry::RuntimeGeometry};
use std::sync::Arc;

/// A source-built plan owns the exact runtime model and physical OpenCL handle
/// used during preflight. Fields are private; numeric receipts cannot create it.
pub(crate) struct NoteDevicePlan {
    plan: WalletDevicePlan,
    runtime: RuntimeGeometry,
    selected_device: ocl::Device,
    quotient_policy: NoteQuotientPlan,
    // Last field: the plan/runtime payload is destroyed before its charge.
    reservation: Reservation,
}

/// Neither Clone nor Send. The underlying capacity lease is thread bound and
/// keeps the engine's managed allowance unavailable to competing proof owners.
/// This owner is kept until all device work and raw-proof construction finish.
pub(crate) struct NoteDeviceLease {
    capacity: ProofCapacity,
    session: DeviceSession,
    selected_device: ocl::Device,
    quotient_policy: NoteQuotientPlan,
    configuration_attempted: bool,
    proof_session_bound: bool,
    // Follows the same plan through acquisition instead of duplicating its
    // numeric allowance. Last field releases after capacity/session payload.
    reservation: Reservation,
}

impl NoteDevicePlan {
    /// Pure payload census. PlannerResources already includes its Plan inline
    /// owner; charge the additional model and lease wrappers conservatively.
    pub(crate) fn required_host_bytes() -> Result<usize, String> {
        PlannerResources::new()?
            .required_host_bytes()
            .checked_add(core::mem::size_of::<Self>())
            .and_then(|n| n.checked_add(core::mem::size_of::<NoteDeviceLease>()))
            // A temporary bootstrap session acquires capacity before the
            // configuration imports GPU seeds or allocates transcript state.
            .and_then(|n| n.checked_add(device::host_storage::session_bytes()))
            .ok_or_else(|| "note device owner storage overflow".to_string())
    }

    /// No context, queue, private arithmetic or proof is created here. The
    /// supplied OpenCL handle comes from the enclosing pinned selector capture.
    pub(crate) fn new(
        minimum: WalletProofMinimum,
        selected_device: ocl::Device,
        limits: Limits,
        max_allocation: usize,
        transfer_slots: usize,
        reservation: Reservation,
    ) -> Result<Self, String> {
        let required = Self::required_host_bytes()?;
        if reservation.reserved_bytes() < required {
            return Err("note device plan exceeds its host reservation".into());
        }
        minimum.check(limits.managed_bytes, max_allocation)?;
        let runtime = RuntimeGeometry::fresh(limits, max_allocation, transfer_slots, 0)?;
        let plan = WalletDevicePlan::from_geometry_bounded(
            minimum,
            runtime,
            PlannerResources::new()?.required_host_bytes(),
        )?;
        Ok(Self {
            plan,
            runtime,
            selected_device,
            quotient_policy: NoteQuotientPlan::new(),
            reservation,
        })
    }

    /// Use this source-built precontext policy for the enclosing runtime's
    /// wrapper census. The runtime must retain that real same-ledger charge
    /// until after configuration/lease retirement and successful shutdown.
    pub(crate) fn source_specialization_allowed(&self) -> bool {
        self.quotient_policy.source_specialization_allowed()
    }

    /// Writes borrowed metadata directly. The writer's own buffering belongs
    /// to its caller; no temporary JSON Value tree or report String is created.
    pub(crate) fn write_report(&self, writer: impl std::io::Write) -> std::io::Result<()> {
        self.plan.write_report(writer)
    }

    /// Consume the admitted plan exactly once. Physical handle, fresh runtime
    /// geometry and the accounting snapshot are checked under the engine lock
    /// used to grant the existing full-managed-capacity lease. A failed check
    /// cannot consume a capacity generation or dispatch private work.
    pub(crate) fn acquire(self, session: &DeviceSession) -> Result<NoteDeviceLease, String> {
        session.with_engine(|live_engine| {
            require_note_engine(live_engine, self.selected_device)?;
            let capacity = engine::capacity::Lease::new_checked(
                live_engine.accounting.clone(),
                live_engine.limits.managed_bytes,
                live_engine.limits.managed_bytes,
                |live| self.runtime.check_engine(live_engine, live),
            )?;
            Ok(NoteDeviceLease {
                capacity: ProofCapacity {
                    _capacity: capacity,
                    _plan: Some(self.plan),
                    _context: live_engine._job_lease.clone(),
                },
                session: session.clone(),
                selected_device: self.selected_device,
                quotient_policy: self.quotient_policy,
                configuration_attempted: false,
                proof_session_bound: false,
                reservation: self.reservation,
            })
        })
    }
}

impl NoteDeviceLease {
    pub(crate) fn same_ledger(&self, other: &Reservation) -> bool {
        self.reservation.same_ledger(other)
    }

    /// Configuration creation is allowed only while this still owns the fresh
    /// bootstrap session, under the exact engine epoch and capacity owner.
    /// This does not authorize private arithmetic or prove driver bounds.
    pub(crate) fn begin_configuration(&mut self) -> Result<(), String> {
        if self.configuration_attempted {
            return Err("note device lease configuration was already attempted".into());
        }
        self.session.with_engine(|live_engine| {
            if !Arc::ptr_eq(&self.capacity._context, &live_engine._job_lease) {
                return Err("note device lease belongs to another engine lifetime".into());
            }
            require_note_engine(live_engine, self.selected_device)
        })?;
        // Once constructor work can begin, an error cannot be retried with the
        // same capacity owner or partially initialized engine lifetime.
        self.configuration_attempted = true;
        Ok(())
    }

    /// Configuration construction happens only after capacity is held. Its
    /// resident PCS creates a fresh observation/session owner in that same
    /// engine epoch. Bind it once, before normalization or private witness work.
    pub(crate) fn bind_proof_session(&mut self, session: &DeviceSession) -> Result<(), String> {
        if !self.configuration_attempted
            || self.proof_session_bound
            || !Arc::ptr_eq(&self.session.session.context, &session.session.context)
        {
            return Err("note device lease cannot bind this proof session".into());
        }
        session.with_engine(|live_engine| {
            if !Arc::ptr_eq(&self.capacity._context, &live_engine._job_lease) {
                return Err("note device lease belongs to another engine lifetime".into());
            }
            require_note_engine(live_engine, self.selected_device)
        })?;
        // A source specialization would allocate a second Program outside the
        // fixed note's baseline wrapper census. Pin before normalization and
        // refuse a session that already prepared any quotient program.
        self.quotient_policy.bind_session(session)?;
        self.session = session.clone();
        self.proof_session_bound = true;
        Ok(())
    }

    /// Bind subsequent configuration/normalization/witness work to this same
    /// session and live engine epoch. Environment policy is independently
    /// recaptured by the enclosing note selector owner before each handoff.
    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        if !self.proof_session_bound
            || !Arc::ptr_eq(&self.session.session, &session.session)
            || !self.quotient_policy.check_session(session)
        {
            return Err("note device lease belongs to another proof session".into());
        }
        session.with_engine(|live_engine| {
            if !Arc::ptr_eq(&self.capacity._context, &live_engine._job_lease) {
                return Err("note device lease belongs to another engine lifetime".into());
            }
            require_note_engine(live_engine, self.selected_device)
        })
    }
}

fn require_note_engine(live: &engine::Engine, selected: ocl::Device) -> Result<(), String> {
    let trees = live.tree_storage.selection();
    if live.pq.device() != selected
        || live.assigned_max_alloc.is_some()
        || !live.retain_trees
        || !live.query_gather
        || !live.fri_fold
        || live.opening_denominator_cache
        || live.lde_workspace_limit != 0
        || live.tuning != Default::default()
        || trees.mode != engine::RetainedTreeStorageMode::Device
        || trees.host_bytes != 0
    {
        return Err("note producer requires its pinned device-only baseline engine".into());
    }
    Ok(())
}
