//! Internal bridge from the admitted source model to the exact owned engine.
//! No constructor is public and no generator, AIR, proof or seed is accepted.
use super::{MulDeviceCensus, WalletProofMinimum};
use crate::block_v2::{
    gpu_hash::{
        device::{
            ringct_runtime::{Runtime, StartupPlan},
            DeviceSession, ProofCapacity,
        },
        engine,
    },
    machine::NativeMulPcsPlan,
    native_gpu::mul_preparation::MulPreparationPlan,
};
use crate::ringct_research_quota::{Bytes, Category, Ledger, Reservation};
use core::mem::size_of;
use std::sync::Arc;

type Result<T> = core::result::Result<T, &'static str>;

/// Actual capacity/session payload drops before the original owner borrows.
/// The closed producer additionally retains those owners through retirement.
/// This internal helper alone cannot authorize a proof or return one.
pub(crate) struct MulDeviceLease<'owner> {
    capacity: ProofCapacity,
    session: DeviceSession,
    configuration_attempted: bool,
    proof_session_bound: bool,
    runtime: &'owner Runtime,
    ledger: &'owner Ledger,
    preparation_owner: &'owner Reservation,
    runtime_owner: &'owner Reservation,
    pcs_owner: &'owner Reservation,
}

fn only_phase(token: &Reservation) -> Result<Bytes> {
    if Category::ALL
        .into_iter()
        .filter(|category| *category != Category::PhaseScratch)
        .any(|category| token.requirements().get(category) != Bytes::ZERO)
    {
        return Err("native mul phase owner has unrelated categories");
    }
    Ok(token.requirements().get(Category::PhaseScratch))
}

impl MulDeviceCensus {
    /// Original token checks precede execution recapture, the actual legacy
    /// planner's allocations and capacity acquisition. The model and actual
    /// planner are sequential users of the same retained preparation claim.
    pub(crate) fn acquire<'owner>(
        &self,
        pcs: &NativeMulPcsPlan,
        preparation: MulPreparationPlan,
        minimum: WalletProofMinimum,
        session: &DeviceSession,
        runtime: &'owner Runtime,
        ledger: &'owner Ledger,
        preparation_owner: &'owner Reservation,
        runtime_owner: &'owner Reservation,
        pcs_owner: &'owner Reservation,
    ) -> Result<MulDeviceLease<'owner>> {
        let allowance = ledger.snapshot().allowance;
        if allowance.host == 0
            || allowance.host > 32u64 << 30
            || allowance.device != self.managed_ceiling_bytes as u64
            || allowance.device > 8u64 << 30
            || !preparation_owner.belongs_to(ledger)
            || !runtime_owner.belongs_to(ledger)
            || !pcs_owner.belongs_to(ledger)
        {
            return Err("native mul requires original same-ledger phase owners");
        }
        let geometry = preparation.geometry();
        let host = preparation.host();
        let symbolic = host
            .prepared_partition_bytes()
            .map_err(|_| "native mul preparation partition overflow")?;
        let other = host
            .required_host_bytes()
            .checked_sub(symbolic)
            .ok_or("native mul preparation partition overflow")?;
        let prepared = preparation_owner.requirements();
        if geometry != self.source || geometry.rows() != self.rows
            || geometry.width() != self.main_width
            || prepared.get(Category::SymbolicCompiler)
                != (Bytes {
                    host: symbolic as u64,
                    device: 0,
                })
            || prepared.get(Category::PhaseScratch).host < other as u64
            || prepared.get(Category::PhaseScratch).device != 0
            || Category::ALL
                .into_iter()
                .filter(|category| {
                    !matches!(
                        category,
                        Category::SymbolicCompiler | Category::PhaseScratch
                    )
                })
                .any(|category| prepared.get(category) != Bytes::ZERO)
        {
            return Err("native mul original preparation claim differs from source");
        }
        let startup = runtime.footprint();
        let expected_startup = match self.trees.mode {
            engine::RetainedTreeStorageMode::Device => StartupPlan::new(),
            engine::RetainedTreeStorageMode::HostBacking => StartupPlan::outer_host_v1(),
        }
        .map_err(|_| "native mul source runtime profile changed")?
        .footprint();
        let runtime_bytes = only_phase(runtime_owner)?;
        let phase_bytes = only_phase(pcs_owner)?;
        let footprint = pcs.footprint();
        let additional_device = self
            .managed_ceiling_bytes
            .checked_sub(startup.managed_device_bytes)
            .ok_or("native mul runtime exceeds managed ceiling")?;
        if startup != expected_startup
            || startup.retained_tree_host_bytes != self.trees.host_bytes
            || startup.managed_device_bytes != self.runtime_baseline_bytes
            || runtime_bytes.host < startup.requested_host_bytes as u64
            || runtime_bytes.device != startup.managed_device_bytes as u64
            || footprint.rows != self.rows
            || footprint.main_width != self.main_width
            || footprint.operation_host_budget_bytes != self.operation_host_bytes
            || footprint.managed_phase_ceiling_bytes != self.managed_ceiling_bytes
            || footprint.fresh_runtime_baseline_bytes != self.runtime_baseline_bytes
            || footprint.retained_tree_storage_mode != self.trees.mode
            || footprint.selected_tree_host_quota_bytes != self.trees.host_bytes
            || footprint.required_tree_host_bytes > self.trees.host_bytes
            || footprint.required_pcs_host_bytes > self.operation_host_bytes
            || phase_bytes.host != self.operation_host_bytes as u64
            || phase_bytes.device != additional_device as u64
        {
            return Err("native mul original runtime/PCS partitions differ from source");
        }
        self.check_prepared_minimum(minimum)
            .map_err(|_| "native mul recording exceeds its captured source model")?;
        pcs.check_execution_selection()
            .map_err(|_| "native mul execution selection changed before acquisition")?;
        session
            .with_engine(|live_engine| {
                runtime
                    .check_engine(live_engine)
                    .map_err(|_| "native mul capacity requires its exact runtime epoch")?;
                if live_engine.tree_storage.selection() != self.trees
                    || live_engine.tree_storage.live() != 0
                {
                    return Err(
                        "native mul capacity requires its fresh original tree quota".into(),
                    );
                }
                minimum.check(live_engine.limits.managed_bytes, live_engine.max_alloc)?;
                let mut actual_plan = None;
                let capacity = engine::capacity::Lease::new_checked(
                    live_engine.accounting.clone(),
                    self.managed_ceiling_bytes,
                    live_engine.limits.managed_bytes,
                    |live| {
                        self.runtime.check_engine(live_engine, live)?;
                        // Preserve the original legacy Plan and JSON report
                        // path, both explicitly covered by A016's census.
                        actual_plan = Some(minimum.plan(live_engine, live)?);
                        Ok(())
                    },
                )?;
                actual_plan
                    .as_ref()
                    .expect("successful capacity callback constructs the plan")
                    .report();
                Ok(MulDeviceLease {
                    capacity: ProofCapacity {
                        _capacity: capacity,
                        _plan: actual_plan,
                        _context: live_engine._job_lease.clone(),
                    },
                    session: session.clone(),
                    configuration_attempted: false,
                    proof_session_bound: false,
                    runtime,
                    ledger,
                    preparation_owner,
                    runtime_owner,
                    pcs_owner,
                })
            })
            .map_err(|_| "native mul actual runtime or capacity admission refused")
    }
}

impl MulDeviceLease<'_> {
    pub(crate) fn inline_host_bytes() -> usize {
        size_of::<Self>()
    }

    fn check_original_owners(&self) -> Result<()> {
        if !self.preparation_owner.belongs_to(self.ledger)
            || !self.runtime_owner.belongs_to(self.ledger)
            || !self.pcs_owner.belongs_to(self.ledger)
        {
            return Err("native mul original owner identity changed");
        }
        Ok(())
    }

    fn check_engine(&self, session: &DeviceSession) -> Result<()> {
        self.check_original_owners()?;
        session
            .with_engine(|live_engine| {
                if !Arc::ptr_eq(&self.capacity._context, &live_engine._job_lease) {
                    return Err("native mul capacity belongs to another engine lifetime".into());
                }
                self.runtime
                    .check_engine(live_engine)
                    .map_err(|_| "native mul runtime differs from capacity owner".into())
            })
            .map_err(|_| "native mul session/runtime lifetime mismatch")
    }

    pub(crate) fn begin_configuration(&mut self) -> Result<()> {
        if self.configuration_attempted {
            return Err("native mul configuration was already attempted");
        }
        self.check_engine(&self.session)?;
        // Set before the constructor draws OS entropy or creates RNG backing.
        // Failure cannot retry configuration inside this same runtime attempt.
        self.configuration_attempted = true;
        Ok(())
    }

    pub(crate) fn bind_proof_session(&mut self, session: &DeviceSession) -> Result<()> {
        if !self.configuration_attempted
            || self.proof_session_bound
            || !Arc::ptr_eq(&self.session.session.context, &session.session.context)
        {
            return Err("native mul capacity cannot bind this proof session");
        }
        self.check_engine(session)?;
        self.session = session.clone();
        self.proof_session_bound = true;
        Ok(())
    }

    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<()> {
        if !self.proof_session_bound || !Arc::ptr_eq(&self.session.session, &session.session) {
            return Err("native mul capacity belongs to another proof session");
        }
        self.check_engine(session)
    }
}
