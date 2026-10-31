//! Source-bound backend schedule for a consuming outer registration.
//!
//! This is deliberately separate from both the direct four-public workflow
//! admission and the report-only outer diagnostic. It admits backend work
//! only. The enclosing owner must preclaim its source graph, request, compiler
//! inputs, retained children, output/key/verifier storage, reports and cleanup
//! lifetime before creating a session or invoking this backend. In particular,
//! an OuterBackendAdmission is not authority to dispatch a transaction graph.
use super::{opening, precommit, selection::ExecutionSelection, RegisteredGpuLimits};
use crate::block_v2::{
    gpu_hash::engine::{retained_storage::Selection, Limits},
    machine::{gpu_backend::resources::Bounds, program::MAX_PUBLIC_VALUES, Program},
};
use crate::config::Val;
use std::sync::Arc;

pub mod source;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct OuterBackendFootprint {
    pub public_values: u64,
    pub rows: u64,
    pub source_program_host_bytes: u64,
    pub source_construction_host_bytes: u64,
    pub public_backing_host_bytes: u64,
    pub witness_backing_host_bytes: u64,
    pub full_tree_quota_host_bytes: u64,
    pub runtime_host_reserved_bytes: u64,
    pub native_host_budget_bytes: u64,
    pub backend_host_budget_bytes: u64,
    pub witness_reserved_host_bytes: u64,
    pub pcs_host_budget_bytes: u64,
    /// Native allowance plus the full retained-tree quota. Existing source and
    /// input owners are additional; no enclosing owner is included implicitly.
    pub backend_scope_host_bytes: u64,
    pub backend_host_phase_peak_bytes: u64,
    pub managed_limit_bytes: u64,
    pub context_reserve_bytes: u64,
    pub device_phase_peak_bytes: u64,
    pub minimum_required_device_bytes: u64,
    pub largest_allocation_bytes: u64,
    pub required_tree_host_bytes: u64,
    pub physical_global_bytes: u64,
    pub physical_max_allocation_bytes: u64,
    pub physical_device_uuid: [u8; 16],
    pub backend_phase_bounds_complete: bool,
    /// These remain false. Only a separate enclosing owner can establish them.
    pub enclosing_ownership_bound_complete: bool,
    pub workflow_dispatch_authority: bool,
    precommit_phases: precommit::PrecommitBounds,
    opening_phases: opening::OpeningBounds,
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or_else(|| "outer backend host sum overflow".into())
}
fn sum(parts: &[u64]) -> Result<u64, String> {
    parts.iter().try_fold(0, |total, part| add(total, *part))
}
fn backing(capacity: usize) -> Result<u64, String> {
    super::mul(capacity as u64, core::mem::size_of::<Val>() as u64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Partition {
    backend: u64,
    pcs: u64,
}
impl Partition {
    fn new(native: u64, runtime: u64, witness: u64) -> Result<Self, String> {
        if native == 0 || native > super::NATIVE_HOST_LIMIT {
            return Err("outer backend native allowance exceeds fixed envelope".into());
        }
        let backend = native
            .checked_sub(runtime)
            .filter(|bytes| *bytes > 0)
            .ok_or("outer backend runtime exhausts native allowance")?;
        let pcs = backend
            .checked_sub(witness)
            .filter(|bytes| *bytes > 0)
            .ok_or("outer backend witness exhausts backend allowance")?;
        Ok(Self { backend, pcs })
    }
}

/// Immutable borrows bind actual source and input capacities through dispatch.
/// The native budget is a backend allowance, not a declaration of other owners.
pub struct OuterBackendPlan<'inputs> {
    program: &'inputs Arc<Program>,
    // Capacity is validated by the concrete Vec or fixed-array entry before
    // this immutable borrow is stored. No input can resize during admission.
    public: &'inputs [Val],
    witness: &'inputs Vec<Val>,
    limits: RegisteredGpuLimits,
    footprint: OuterBackendFootprint,
}

/// Backend-only capability. It cannot be constructed from a diagnostic report,
/// cloned, or used by the borrowed/reusable registration path.
pub struct OuterBackendAdmission<'inputs> {
    plan: OuterBackendPlan<'inputs>,
}

impl RegisteredGpuLimits {
    /// The already-captured full host-tree quota. This is part of, not extra to,
    /// the worker allowance. Reading it creates no reservation or admission.
    pub fn retained_tree_host_bytes(&self) -> u64 {
        self.trees.host_bytes as u64
    }
}

// Shared phase planner for genuine Programs and pre-native source ceilings.
// It only inspects geometry and captured limits; it issues no enclosing claim.
fn inspect_bounds(
    bounds: &Bounds,
    public_values: usize,
    public_backing: u64,
    witness_backing: u64,
    limits: RegisteredGpuLimits,
    native_host_budget_bytes: u64,
) -> Result<OuterBackendFootprint, String> {
    let selected = limits
        .execution
        .ok_or("outer backend requires captured OpenCL selection")?;
    selected.qualify(limits)?;
    let witness_reserved = bounds.reservation_with_tree_storage(1, limits.trees)?;
    let runtime = add(
        crate::block_v2::randomness::resources::Bounds {
            rows: bounds.rows,
            main_columns: bounds.main_columns,
            preprocessing_columns: bounds.preprocessing_columns,
            lookup_columns: 51,
            quotient_rows: super::mul(bounds.rows, 16)?,
            quotient_chunks: 16,
        }
        .reservation(1)?
        .host_bytes,
        crate::block_v2::challenger::resources::reservation().host_bytes,
    )?;
    let partition = Partition::new(
        native_host_budget_bytes,
        runtime,
        witness_reserved.host_bytes,
    )?;
    let backend_scope = add(native_host_budget_bytes, limits.trees.host_bytes as u64)?;
    // Necessary source-derived floor only; this does not admit the enclosing
    // graph or claim the remaining worker allowance belongs to the backend.
    if sum(&[
        backend_scope,
        bounds.program_retained_host_bytes,
        public_backing,
        witness_backing,
    ])? > limits.host_bytes
    {
        return Err("outer backend and concrete source exceed worker allowance".into());
    }
    selected.qualify_host_output(partition.backend)?;
    let device_limits = Limits {
        managed_bytes: usize::try_from(limits.device_bytes)
            .map_err(|_| "outer backend managed overflow")?,
        ..Default::default()
    };
    let max_allocation = usize::try_from(selected.physical_max_allocation_bytes)
        .map_err(|_| "outer backend physical allocation overflow")?;
    let precommit = precommit::plan(
        bounds,
        public_values,
        limits.trees,
        device_limits,
        max_allocation,
        selected.slots,
        selected.transform_allowance,
    )?;
    let opening = opening::plan(
        bounds.rows as usize,
        precommit.common_device_bytes,
        partition.pcs as usize,
        device_limits,
        max_allocation,
        limits.trees,
    )?;
    let backend_host = sum(&[
        witness_reserved.host_bytes,
        opening.host_workspace_peak_bytes as u64,
        opening.retained_host_metadata_bytes as u64,
    ])?;
    let device = precommit
        .peak_device_bytes
        .max(opening.opening_device_peak_bytes)
        .max(opening.fri_device_peak_bytes)
        .max(opening.query_device_peak_bytes) as u64;
    let minimum = precommit
        .minimum_required_device_bytes
        .max(opening.minimum_required_device_bytes) as u64;
    let largest = precommit
        .largest_allocation_bytes
        .max(opening.largest_allocation_bytes) as u64;
    if !opening.host_bound_complete
        || backend_host > partition.backend
        || device > limits.device_bytes
        || minimum > device
        || largest > selected.physical_max_allocation_bytes
        || opening.required_tree_host_bytes > limits.trees.host_bytes
    {
        return Err("outer backend phase bound exceeds scoped allowance".into());
    }
    Ok(OuterBackendFootprint {
        public_values: public_values as u64,
        rows: bounds.rows,
        source_program_host_bytes: bounds.program_retained_host_bytes,
        source_construction_host_bytes: bounds.program_host_bytes,
        public_backing_host_bytes: public_backing,
        witness_backing_host_bytes: witness_backing,
        full_tree_quota_host_bytes: limits.trees.host_bytes as u64,
        runtime_host_reserved_bytes: runtime,
        native_host_budget_bytes,
        backend_host_budget_bytes: partition.backend,
        witness_reserved_host_bytes: witness_reserved.host_bytes,
        pcs_host_budget_bytes: partition.pcs,
        backend_scope_host_bytes: backend_scope,
        backend_host_phase_peak_bytes: backend_host,
        managed_limit_bytes: limits.device_bytes,
        context_reserve_bytes: limits.context_bytes,
        device_phase_peak_bytes: device,
        minimum_required_device_bytes: minimum,
        largest_allocation_bytes: largest,
        required_tree_host_bytes: opening.required_tree_host_bytes as u64,
        physical_global_bytes: selected.physical_global_bytes,
        physical_max_allocation_bytes: selected.physical_max_allocation_bytes,
        physical_device_uuid: selected.uuid,
        backend_phase_bounds_complete: true,
        enclosing_ownership_bound_complete: false,
        workflow_dispatch_authority: false,
        precommit_phases: precommit,
        opening_phases: opening,
    })
}

impl<'inputs> OuterBackendPlan<'inputs> {
    pub fn new(
        program: &'inputs Arc<Program>,
        public: &'inputs Vec<Val>,
        witness: &'inputs Vec<Val>,
        limits: RegisteredGpuLimits,
        native_host_budget_bytes: u64,
    ) -> Result<Self, String> {
        let public_values = program.public_values();
        if !cfg!(all(not(debug_assertions), target_arch = "x86_64"))
            || MAX_PUBLIC_VALUES != 64
            || public_values > MAX_PUBLIC_VALUES
            || public.len() != public_values
            || witness.len() != program.witness_values()
            || program.height() > limits.max_rows
            || limits.trees.host_bytes > 8 << 30
        {
            return Err("outer backend source/input/profile mismatch".into());
        }
        let bounds = Bounds::for_program_with_tree_storage(program, true, limits.trees)?;
        let footprint = inspect_bounds(
            &bounds,
            public_values,
            backing(public.capacity())?,
            backing(witness.capacity())?,
            limits,
            native_host_budget_bytes,
        )?;
        Ok(Self {
            program,
            public,
            witness,
            limits,
            footprint,
        })
    }

    pub fn footprint(&self) -> OuterBackendFootprint {
        self.footprint
    }

    /// Requires the pre-session idle boundary. The enclosing owner must keep
    /// all preclaims live while subsequently initializing and draining a session.
    pub fn admit(self) -> Result<OuterBackendAdmission<'inputs>, String> {
        let admission = OuterBackendAdmission { plan: self };
        admission.check_execution_selection()?;
        if !crate::block_v2::gpu_hash::engine::registration_preflight_idle()? {
            return Err("outer backend admission requires idle shared GPU engine".into());
        }
        Ok(admission)
    }
}

impl OuterBackendAdmission<'_> {
    pub fn program(&self) -> &Arc<Program> {
        self.plan.program
    }
    pub fn public(&self) -> &[Val] {
        self.plan.public
    }
    pub fn witness(&self) -> &[Val] {
        self.plan.witness
    }
    pub fn host_budget_bytes(&self) -> u64 {
        self.plan.footprint.backend_host_budget_bytes
    }
    pub fn footprint(&self) -> OuterBackendFootprint {
        self.plan.footprint
    }
    pub fn check_execution_selection(&self) -> Result<(), String> {
        if Selection::from_env()? != self.plan.limits.trees {
            return Err("outer backend tree storage selection changed after admission".into());
        }
        let selected = ExecutionSelection::capture()?;
        if Some(selected) != self.plan.limits.execution {
            return Err(
                "outer backend physical identity or execution selection changed after admission"
                    .into(),
            );
        }
        selected.qualify(self.plan.limits)?;
        selected.qualify_host_output(self.host_budget_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_native_budget_never_borrows_enclosing_storage() {
        let native = 24 << 30;
        let runtime = 2 << 20;
        let witness = 3 << 30;
        let p = Partition::new(native, runtime, witness).unwrap();
        assert_eq!(p.backend + runtime, native);
        assert_eq!(p.pcs + witness, p.backend);
        let smaller = Partition::new(native - 1, runtime, witness).unwrap();
        assert_eq!(smaller.pcs + 1, p.pcs);
        assert!(Partition::new(native + 1, runtime, witness).is_err());
        assert!(Partition::new(u64::MAX, runtime, witness).is_err());
    }

    #[test]
    fn runtime_and_witness_must_leave_nonzero_pcs_allowance() {
        assert!(Partition::new(0, 0, 0).is_err());
        assert!(Partition::new(300, 301, 0).is_err());
        assert!(Partition::new(300, 300, 0).is_err());
        assert!(Partition::new(300, 100, 201).is_err());
        assert!(Partition::new(300, 100, 200).is_err());
        assert_eq!(Partition::new(301, 100, 200).unwrap().pcs, 1);
    }
}
