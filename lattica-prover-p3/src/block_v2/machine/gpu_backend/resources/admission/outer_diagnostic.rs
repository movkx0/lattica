//! Report-only composition for an already-compiled outer program.
//!
//! Declared outer bytes are not authority. This module never constructs a
//! RegisteredGpuMemoryPlan/Admission, initializes a session, registers a program,
//! or produces a proof. Source-owned callers must reserve all enclosing owners
//! and establish the output producer's bound before any future dispatch gate.
use super::{opening, precommit, Bounds, RegisteredGpuLimits};
use crate::block_v2::{
    gpu_hash::engine::Limits,
    machine::{program::MAX_PUBLIC_VALUES, Program},
};
use crate::config::Val;
use std::sync::Arc;

/// Separate diagnostic declarations, never a reservation or dispatch permit.
/// Existing owners exclude the two other fields, preventing an implicit overlap
/// credit between already-live storage and the proposed phase/output owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RegisteredGpuOuterHostBounds {
    pub existing_host_bytes: u64,
    pub output_host_bytes: u64,
    pub adapter_scratch_host_bytes: u64,
}

/// A copyable public-geometry report. Both output-ownership and dispatch fields
/// are always false: accepting numeric declarations cannot establish ownership.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RegisteredGpuOuterFootprint {
    pub public_values: u64,
    pub rows: u64,
    pub source_program_host_bytes: u64,
    pub source_construction_host_bytes: u64,
    pub public_backing_host_bytes: u64,
    pub witness_backing_host_bytes: u64,
    pub concrete_source_and_inputs_host_bytes: u64,
    pub declared_outer: RegisteredGpuOuterHostBounds,
    pub full_tree_quota_host_bytes: u64,
    pub runtime_host_reserved_bytes: u64,
    pub native_host_budget_bytes: u64,
    pub backend_host_budget_bytes: u64,
    pub witness_reserved_host_bytes: u64,
    pub pcs_host_budget_bytes: u64,
    pub worker_committed_host_bytes: u64,
    pub backend_host_phase_peak_bytes: u64,
    pub declared_host_phase_peak_bytes: u64,
    pub device_phase_peak_bytes: u64,
    pub minimum_required_device_bytes: u64,
    pub largest_allocation_bytes: u64,
    pub required_tree_host_bytes: u64,
    pub physical_global_bytes: u64,
    pub physical_max_allocation_bytes: u64,
    pub physical_device_uuid: [u8; 16],
    pub backend_phase_bounds_complete: bool,
    pub output_ownership_bound_complete: bool,
    pub dispatch_authority: bool,
    precommit_phases: precommit::PrecommitBounds,
    opening_phases: opening::OpeningBounds,
}

fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or_else(|| "outer diagnostic host sum overflow".into())
}
fn sum(parts: &[u64]) -> Result<u64, String> {
    parts.iter().try_fold(0, |sum, part| add(sum, *part))
}
fn backing(capacity: usize) -> Result<u64, String> {
    super::mul(capacity as u64, core::mem::size_of::<Val>() as u64)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Partition {
    external: u64,
    native: u64,
    backend: u64,
    pcs: u64,
    committed: u64,
}
impl Partition {
    fn new(
        outer: RegisteredGpuOuterHostBounds,
        full_tree_quota: u64,
        runtime: u64,
        witness_reserved: u64,
        worker_host: u64,
    ) -> Result<Self, String> {
        if worker_host == 0
            || worker_host > super::HOST_LIMIT
            || outer.adapter_scratch_host_bytes < super::REGISTERED_GPU_CALLER_HOST_BYTES as u64
        {
            return Err("outer diagnostic lacks its fixed caller or worker envelope".into());
        }
        let external = sum(&[
            outer.existing_host_bytes,
            outer.output_host_bytes,
            outer.adapter_scratch_host_bytes,
            full_tree_quota,
        ])?;
        let native = worker_host
            .checked_sub(external)
            .ok_or("outer owners exhaust the worker allowance")?
            .min(super::NATIVE_HOST_LIMIT);
        let backend = native
            .checked_sub(runtime)
            .ok_or("outer diagnostic runtime exhausts native allowance")?;
        let pcs = backend
            .checked_sub(witness_reserved)
            .filter(|bytes| *bytes > 0)
            .ok_or("outer diagnostic witness exhausts backend allowance")?;
        Ok(Self {
            external,
            native,
            backend,
            pcs,
            committed: add(external, native)?,
        })
    }
}

/// Inspect actual immutable source and input capacities. No field evaluation,
/// GPU context, proof work, or execution token is created. This deliberately
/// accepts Vec references so spare public/witness capacity cannot disappear.
pub fn inspect_registered_gpu_outer(
    program: &Arc<Program>,
    public: &Vec<Val>,
    witness: &Vec<Val>,
    limits: RegisteredGpuLimits,
    outer: RegisteredGpuOuterHostBounds,
) -> Result<RegisteredGpuOuterFootprint, String> {
    let public_values = program.public_values();
    if MAX_PUBLIC_VALUES != 64
        || public_values > MAX_PUBLIC_VALUES
        || public.len() != public_values
        || witness.len() != program.witness_values()
        || program.height() > limits.max_rows
        || limits.trees.host_bytes > 8 << 30
    {
        return Err("outer diagnostic source/input/profile mismatch".into());
    }
    let selected = limits
        .execution
        .ok_or("outer diagnostic requires captured OpenCL selection")?;
    selected.qualify(limits)?;
    let bounds = Bounds::for_program_with_tree_storage(program, true, limits.trees)?;
    let witness_reserved = bounds.reservation_with_tree_storage(1, limits.trees)?;
    let public_backing = backing(public.capacity())?;
    let witness_backing = backing(witness.capacity())?;
    let concrete_source = sum(&[
        bounds.program_retained_host_bytes,
        public_backing,
        witness_backing,
    ])?;
    if outer.existing_host_bytes < concrete_source {
        return Err("outer declared owners omit concrete source/input backing".into());
    }
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
        outer,
        limits.trees.host_bytes as u64,
        runtime,
        witness_reserved.host_bytes,
        limits.host_bytes,
    )?;
    selected.qualify_host_output(partition.backend)?;
    let device_limits = Limits {
        managed_bytes: usize::try_from(limits.device_bytes)
            .map_err(|_| "outer managed overflow")?,
        ..Default::default()
    };
    let max_allocation = usize::try_from(selected.physical_max_allocation_bytes)
        .map_err(|_| "outer physical allocation overflow")?;
    let precommit = precommit::plan(
        &bounds,
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
    let complete_host = sum(&[partition.external, runtime, backend_host])?;
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
        || complete_host > partition.committed
        || device > limits.device_bytes
        || minimum > device
        || largest > selected.physical_max_allocation_bytes
        || opening.required_tree_host_bytes > limits.trees.host_bytes
    {
        return Err("outer complete backend phase bound exceeds declared envelope".into());
    }
    Ok(RegisteredGpuOuterFootprint {
        public_values: public_values as u64,
        rows: bounds.rows,
        source_program_host_bytes: bounds.program_retained_host_bytes,
        source_construction_host_bytes: bounds.program_host_bytes,
        public_backing_host_bytes: public_backing,
        witness_backing_host_bytes: witness_backing,
        concrete_source_and_inputs_host_bytes: concrete_source,
        declared_outer: outer,
        full_tree_quota_host_bytes: limits.trees.host_bytes as u64,
        runtime_host_reserved_bytes: runtime,
        native_host_budget_bytes: partition.native,
        backend_host_budget_bytes: partition.backend,
        witness_reserved_host_bytes: witness_reserved.host_bytes,
        pcs_host_budget_bytes: partition.pcs,
        worker_committed_host_bytes: partition.committed,
        backend_host_phase_peak_bytes: backend_host,
        declared_host_phase_peak_bytes: complete_host,
        device_phase_peak_bytes: device,
        minimum_required_device_bytes: minimum,
        largest_allocation_bytes: largest,
        required_tree_host_bytes: opening.required_tree_host_bytes as u64,
        physical_global_bytes: selected.physical_global_bytes,
        physical_max_allocation_bytes: selected.physical_max_allocation_bytes,
        physical_device_uuid: selected.uuid,
        backend_phase_bounds_complete: true,
        output_ownership_bound_complete: false,
        dispatch_authority: false,
        precommit_phases: precommit,
        opening_phases: opening,
    })
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;

    #[test]
    fn separate_outer_owners_reduce_the_native_allowance_without_overlap_credits() {
        let outer = RegisteredGpuOuterHostBounds {
            existing_host_bytes: 2 << 30,
            output_host_bytes: 257 << 20,
            adapter_scratch_host_bytes: 1 << 20,
        };
        let p = Partition::new(outer, 8 << 30, 2 << 20, 3 << 30, 32 << 30).unwrap();
        assert_eq!(p.external, (10 << 30) + (258 << 20));
        assert_eq!(p.native + p.external, 32 << 30);
        assert_eq!(p.backend + (2 << 20), p.native);
        assert_eq!(p.pcs + (3 << 30), p.backend);
        assert!(p.native < 24 << 30);
        let larger = RegisteredGpuOuterHostBounds {
            existing_host_bytes: outer.existing_host_bytes + 1,
            ..outer
        };
        let reduced = Partition::new(larger, 8 << 30, 2 << 20, 3 << 30, 32 << 30).unwrap();
        assert_eq!(p.native - 1, reduced.native);
    }

    #[test]
    fn outer_partition_requires_positive_pcs_and_explicit_caller_storage() {
        let outer = RegisteredGpuOuterHostBounds {
            existing_host_bytes: 0,
            output_host_bytes: 0,
            adapter_scratch_host_bytes: 1 << 20,
        };
        let required = (1 << 20) + 100 + 200;
        assert!(Partition::new(outer, 0, 100, 200, required).is_err());
        let exact = Partition::new(outer, 0, 100, 200, required + 1).unwrap();
        assert_eq!(exact.pcs, 1);
        assert!(Partition::new(
            RegisteredGpuOuterHostBounds {
                adapter_scratch_host_bytes: (1 << 20) - 1,
                ..outer
            },
            0,
            100,
            200,
            32 << 30
        )
        .is_err());
        assert!(Partition::new(
            RegisteredGpuOuterHostBounds {
                existing_host_bytes: u64::MAX,
                ..outer
            },
            8 << 30,
            100,
            200,
            32 << 30
        )
        .is_err());
    }
}
