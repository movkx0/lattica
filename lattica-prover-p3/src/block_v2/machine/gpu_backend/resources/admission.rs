//! Program-bound preflight for fresh registered GPU proving.
//!
//! The allocation-free source census is separate from complete phase planning.
//! Only the pinned consuming-registration schedule can produce a token. Other
//! profiles retain bounded diagnostics and refuse before session creation.
use super::{add, mul, Bounds};
use crate::block_v2::{
    gpu_hash::engine::retained_storage::{RetainedTreeStorageMode, Selection},
    machine::Program,
};
use crate::config::Val;
use std::sync::Arc;

mod opening;
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream"
))]
pub mod shake_pcs;
#[cfg(all(
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info",
    feature = "stream"
))]
pub mod aes_pcs;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod graph_source_pcs;

pub mod outer_diagnostic;
pub mod outer_producer;
pub mod output;
mod precommit;
mod selection;
use selection::ExecutionSelection;

pub const REGISTERED_GPU_CALLER_HOST_BYTES: usize = 1 << 20;
const HOST_LIMIT: u64 = 32 << 30;
const DEVICE_LIMIT: u64 = 8 << 30;
const NATIVE_HOST_LIMIT: u64 = 24 << 30;
const CONTEXT_RESERVE: u64 = 4 << 30;
const ROW_LIMIT: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisteredGpuLimits {
    host_bytes: u64,
    device_bytes: u64,
    context_bytes: u64,
    max_rows: usize,
    trees: Selection,
    execution: Option<ExecutionSelection>,
}

impl RegisteredGpuLimits {
    /// Capture the selected tree policy once, before reading the immutable
    /// program geometry. The host quota is part of the worker allowance.
    pub fn new(
        host_bytes: u64,
        device_bytes: u64,
        context_bytes: u64,
        max_rows: usize,
    ) -> Result<Self, String> {
        let mut limits = Self::with_selection(
            host_bytes,
            device_bytes,
            context_bytes,
            max_rows,
            Selection::from_env()?,
        )?;
        #[cfg(feature = "gpu")]
        {
            limits.execution = Some(ExecutionSelection::capture()?);
        }
        Ok(limits)
    }

    fn with_selection(
        host_bytes: u64,
        device_bytes: u64,
        context_bytes: u64,
        max_rows: usize,
        trees: Selection,
    ) -> Result<Self, String> {
        if host_bytes == 0
            || host_bytes > HOST_LIMIT
            || device_bytes == 0
            || device_bytes > DEVICE_LIMIT
            || context_bytes != CONTEXT_RESERVE
            || !max_rows.is_power_of_two()
            || !(8..=ROW_LIMIT).contains(&max_rows)
            || trees.host_bytes as u64 > host_bytes
        {
            return Err("registered GPU limits exceed the fixed worker envelope".into());
        }
        Ok(Self {
            host_bytes,
            device_bytes,
            context_bytes,
            max_rows,
            trees,
            execution: None,
        })
    }
}

/// Bounded diagnostics only. A floor is never passed to the runtime as an
/// allowance or presented as a complete host/device memory reservation.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct RegisteredGpuFootprint {
    pub rows: u64,
    pub managed_limit_bytes: u64,
    pub context_reserve_bytes: u64,
    pub worker_host_limit_bytes: u64,
    pub physical_global_bytes: Option<u64>,
    pub physical_max_allocation_bytes: Option<u64>,
    pub physical_device_uuid: Option<[u8; 16]>,
    pub requires_consuming_registration: bool,
    pub witness_instructions_retired_before_quotient_required: bool,
    pub main_columns: u64,
    pub preprocessing_columns: u64,
    pub program_retained_host_bytes: u64,
    pub program_construction_host_bytes: u64,
    pub compiler_peak_host_bytes: u64,
    pub compiler_retained_host_bytes: u64,
    pub witness_instruction_device_bytes: u64,
    pub witness_reserved_host_bytes: u64,
    pub caller_reserved_host_bytes: u64,
    pub input_backing_host_bytes: u64,
    /// Actual allowance passed to RegisteredProgram and its PCS partition.
    pub backend_host_budget_bytes: u64,
    pub runtime_host_reserved_bytes: u64,
    pub native_host_budget_bytes: u64,
    pub worker_committed_host_bytes: u64,
    pub pcs_host_budget_bytes: u64,
    pub host_tree_quota_bytes: u64,
    pub tree_storage_mode: RetainedTreeStorageMode,
    pub public_salt_device_bytes: u64,
    pub full_tree_device_construction_bytes: u64,
    /// Includes five committed prefix owners for the pinned wide machine.
    pub retained_prefix_device_bytes: Option<u64>,
    pub retained_digest_tree_device_bytes: Option<u64>,
    /// Original prefixes, projected copies, complete quotient, PP salts and
    /// largest-first transform buffers. Excludes engine/code/transcript scratch.
    pub quotient_payload_floor_bytes: Option<u64>,
    pub host_phase_bound_complete: bool,
    pub device_phase_bound_complete: bool,
    /// Conservative complete worker host peak, including separate tree quota.
    pub host_phase_peak_bytes: Option<u64>,
    pub backend_host_phase_peak_bytes: Option<u64>,
    /// Enforced adaptive scheduling ceilings, not measured peak allocations.
    pub device_phase_peak_bytes: Option<u64>,
    pub minimum_required_device_bytes: Option<u64>,
    pub largest_allocation_bytes: Option<u64>,
    pub required_tree_host_bytes: Option<u64>,
    precommit_phases: Option<precommit::PrecommitBounds>,
    opening_phases: Option<opening::OpeningBounds>,
}

/// Borrows the actual immutable inputs, including real witness spare capacity.
/// Callers keep their Statement/reports within REGISTERED_GPU_CALLER_HOST_BYTES;
/// the four public fields are included in that independently checked envelope.
pub struct RegisteredGpuMemoryPlan<'a> {
    program: &'a Arc<Program>,
    public: &'a [Val],
    witness: &'a Vec<Val>,
    limits: RegisteredGpuLimits,
    footprint: RegisteredGpuFootprint,
}

/// Sealed, consuming-registration-only admission. The witness instruction
/// owner must be retired after the observed trace finishes and before quotient
/// proving begins. The reusable registration API cannot accept this token.
/// Only a complete internal phase plan can create an execution token.
pub struct RegisteredGpuAdmission<'a> {
    plan: RegisteredGpuMemoryPlan<'a>,
}

impl<'a> RegisteredGpuMemoryPlan<'a> {
    /// No field evaluation, symbolic compiler, matrix allocation, session, or
    /// GPU arithmetic. Source census is allocation-free; complete phase planners
    /// use only bounded geometry scratch which retires before this returns.
    pub fn new(
        program: &'a Arc<Program>,
        public: &'a [Val],
        witness: &'a Vec<Val>,
        limits: RegisteredGpuLimits,
    ) -> Result<Self, String> {
        if program.height() > limits.max_rows
            || public.len() != 4
            || public.len() != program.public_values()
            || witness.len() != program.witness_values()
        {
            return Err("registered GPU input identity or row bound mismatch".into());
        }
        let bounds = Bounds::for_program_with_tree_storage(program, true, limits.trees)?;
        let witness_reserved = bounds.reservation_with_tree_storage(1, limits.trees)?;
        let input_bytes = mul(
            witness.capacity() as u64,
            core::mem::size_of::<Val>() as u64,
        )?;
        let external = add(
            add(REGISTERED_GPU_CALLER_HOST_BYTES as u64, input_bytes)?,
            limits.trees.host_bytes as u64,
        )?;
        let randomness = crate::block_v2::randomness::resources::Bounds {
            rows: bounds.rows,
            main_columns: bounds.main_columns,
            preprocessing_columns: bounds.preprocessing_columns,
            lookup_columns: 51,
            quotient_rows: mul(bounds.rows, 16)?,
            quotient_chunks: 16,
        }
        .reservation(1)?;
        let runtime_host_reserved_bytes = add(
            randomness.host_bytes,
            crate::block_v2::challenger::resources::reservation().host_bytes,
        )?;
        let native_host_budget_bytes = limits
            .host_bytes
            .checked_sub(external)
            .filter(|bytes| *bytes > 0)
            .ok_or("caller inputs and host trees exhaust registered host allowance")?
            .min(NATIVE_HOST_LIMIT);
        let backend_host_budget_bytes = native_host_budget_bytes
            .checked_sub(runtime_host_reserved_bytes)
            .ok_or("registered runtime reserves exhaust native host allowance")?;
        let worker_committed_host_bytes = add(external, native_host_budget_bytes)?;
        if witness_reserved.host_bytes >= backend_host_budget_bytes {
            return Err("registered witness reservation exhausts native host allowance".into());
        }
        let h = bounds.rows;
        let height = mul(h, 2 << crate::block_v2::profile::LOG_BLOWUP)?;
        let public_salts = mul(height, 32)?;
        let tree = mul(mul(height, 2)?.checked_sub(1).ok_or("tree geometry")?, 32)?;
        // These pinned wide-machine dimensions were qualified independently of
        // the witness. Other profiles receive metadata diagnostics only until
        // their symbolic geometry has an equally explicit bound.
        let wide = bounds.main_columns == 94 && bounds.preprocessing_columns == 200;
        let retained_prefixes = wide.then(|| mul(mul(h, 2 * 8)?, 472)).transpose()?;
        let retained_trees = wide
            .then(|| match limits.trees.mode {
                RetainedTreeStorageMode::Device => mul(tree, 5),
                RetainedTreeStorageMode::HostBacking => Ok(0),
            })
            .transpose()?;
        let quotient_floor = wide
            .then(|| {
                let prefix_row = mul(h, 2 * 8)?;
                let original = mul(prefix_row, 200 + 98 + 55)?;
                let projected = mul(prefix_row, 94 + 51)?;
                let complete_quotient = mul(h, 16 * 3 * 8)?;
                let largest_transform = mul(prefix_row, 2 * 200)?;
                add(
                    add(
                        add(add(original, projected)?, complete_quotient)?,
                        largest_transform,
                    )?,
                    public_salts,
                )
            })
            .transpose()?;
        let footprint = RegisteredGpuFootprint {
            rows: bounds.rows,
            managed_limit_bytes: limits.device_bytes,
            context_reserve_bytes: limits.context_bytes,
            worker_host_limit_bytes: limits.host_bytes,
            physical_global_bytes: limits
                .execution
                .map(|selected| selected.physical_global_bytes),
            physical_max_allocation_bytes: limits
                .execution
                .map(|selected| selected.physical_max_allocation_bytes),
            physical_device_uuid: limits.execution.map(|selected| selected.uuid),
            requires_consuming_registration: true,
            witness_instructions_retired_before_quotient_required: true,
            main_columns: bounds.main_columns,
            preprocessing_columns: bounds.preprocessing_columns,
            program_retained_host_bytes: bounds.program_retained_host_bytes,
            program_construction_host_bytes: bounds.program_host_bytes,
            compiler_peak_host_bytes: bounds.compiler_host_bytes,
            compiler_retained_host_bytes: bounds.compiler_retained_host_bytes,
            witness_instruction_device_bytes: bounds.metadata_bytes,
            witness_reserved_host_bytes: witness_reserved.host_bytes,
            caller_reserved_host_bytes: REGISTERED_GPU_CALLER_HOST_BYTES as u64,
            input_backing_host_bytes: input_bytes,
            backend_host_budget_bytes,
            runtime_host_reserved_bytes,
            native_host_budget_bytes,
            worker_committed_host_bytes,
            pcs_host_budget_bytes: backend_host_budget_bytes - witness_reserved.host_bytes,
            host_tree_quota_bytes: limits.trees.host_bytes as u64,
            tree_storage_mode: limits.trees.mode,
            public_salt_device_bytes: public_salts,
            full_tree_device_construction_bytes: tree,
            retained_prefix_device_bytes: retained_prefixes,
            retained_digest_tree_device_bytes: retained_trees,
            quotient_payload_floor_bytes: quotient_floor,
            host_phase_bound_complete: false,
            device_phase_bound_complete: false,
            host_phase_peak_bytes: None,
            backend_host_phase_peak_bytes: None,
            device_phase_peak_bytes: None,
            minimum_required_device_bytes: None,
            largest_allocation_bytes: None,
            required_tree_host_bytes: None,
            precommit_phases: None,
            opening_phases: None,
        };
        let mut result = Self {
            program,
            public,
            witness,
            limits,
            footprint,
        };
        // A diagnostic for an unsupported selection must never imply an
        // admission. Eligible selections compose the actual runtime planners.
        if wide && limits.trees.mode == RetainedTreeStorageMode::HostBacking {
            if let Some(selected) = limits.execution {
                if selected.qualify(limits).is_ok() {
                    result.complete_phases(&bounds, selected)?;
                }
            }
        }
        Ok(result)
    }

    pub fn footprint(&self) -> RegisteredGpuFootprint {
        self.footprint
    }

    fn complete_phases(
        &mut self,
        bounds: &Bounds,
        selected: ExecutionSelection,
    ) -> Result<(), String> {
        selected.qualify_host_output(self.footprint.backend_host_budget_bytes)?;
        if self.limits.trees.host_bytes > 8 << 30 {
            return Err("registered host-tree quota exceeds the guarded 8 GiB experiment".into());
        }
        let device_limits = crate::block_v2::gpu_hash::engine::Limits {
            managed_bytes: usize::try_from(self.limits.device_bytes)
                .map_err(|_| "managed byte overflow")?,
            ..Default::default()
        };
        let max_allocation = usize::try_from(selected.physical_max_allocation_bytes)
            .map_err(|_| "physical allocation byte overflow")?;
        let precommit = precommit::plan(
            bounds,
            4,
            self.limits.trees,
            device_limits,
            max_allocation,
            selected.slots,
            selected.transform_allowance,
        )?;
        let opening = opening::plan(
            self.footprint.rows as usize,
            precommit.common_device_bytes,
            self.footprint.pcs_host_budget_bytes as usize,
            device_limits,
            max_allocation,
            self.limits.trees,
        )?;
        let opening_host = add(
            opening.host_workspace_peak_bytes as u64,
            opening.retained_host_metadata_bytes as u64,
        )?;
        let backend_host = add(self.footprint.witness_reserved_host_bytes, opening_host)?;
        let worker_host = add(
            add(
                add(
                    add(backend_host, self.footprint.runtime_host_reserved_bytes)?,
                    self.footprint.host_tree_quota_bytes,
                )?,
                self.footprint.input_backing_host_bytes,
            )?,
            self.footprint.caller_reserved_host_bytes,
        )?;
        let source_construction = add(
            add(
                self.footprint.program_construction_host_bytes,
                self.footprint.input_backing_host_bytes,
            )?,
            self.footprint.caller_reserved_host_bytes,
        )?;
        if source_construction > worker_host {
            return Err("registered source construction exceeds complete host phase bound".into());
        }
        let device_peak = precommit
            .peak_device_bytes
            .max(opening.opening_device_peak_bytes)
            .max(opening.fri_device_peak_bytes)
            .max(opening.query_device_peak_bytes) as u64;
        let largest = precommit
            .largest_allocation_bytes
            .max(opening.largest_allocation_bytes) as u64;
        let minimum = precommit
            .minimum_required_device_bytes
            .max(opening.minimum_required_device_bytes) as u64;
        if !opening.host_bound_complete
            || backend_host > self.footprint.backend_host_budget_bytes
            || worker_host > self.limits.host_bytes
            || device_peak > self.limits.device_bytes
            || minimum > device_peak
            || largest > selected.physical_max_allocation_bytes
            || opening.required_tree_host_bytes > self.limits.trees.host_bytes
        {
            return Err(
                "registered complete phase composition exceeds its selected envelope".into(),
            );
        }
        self.footprint.host_phase_peak_bytes = Some(worker_host);
        self.footprint.backend_host_phase_peak_bytes = Some(backend_host);
        self.footprint.device_phase_peak_bytes = Some(device_peak);
        self.footprint.minimum_required_device_bytes = Some(minimum);
        self.footprint.largest_allocation_bytes = Some(largest);
        self.footprint.required_tree_host_bytes = Some(opening.required_tree_host_bytes as u64);
        self.footprint.precommit_phases = Some(precommit);
        self.footprint.opening_phases = Some(opening);
        self.footprint.host_phase_bound_complete = true;
        self.footprint.device_phase_bound_complete = true;
        Ok(())
    }

    pub fn admit(self) -> Result<RegisteredGpuAdmission<'a>, String> {
        if !self.footprint.host_phase_bound_complete || !self.footprint.device_phase_bound_complete
        {
            return Err("registered GPU complete phase bound unavailable; diagnostic floors cannot admit execution".into());
        }
        let admission = RegisteredGpuAdmission { plan: self };
        admission.check_execution_selection()?;
        if !crate::block_v2::gpu_hash::engine::registration_preflight_idle()? {
            return Err("registered one-shot admission requires an idle shared GPU engine".into());
        }
        Ok(admission)
    }
}

impl<'a> RegisteredGpuAdmission<'a> {
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
    pub fn footprint(&self) -> RegisteredGpuFootprint {
        self.plan.footprint
    }
    pub fn check_execution_selection(&self) -> Result<(), String> {
        if Selection::from_env()? != self.plan.limits.trees {
            return Err("registered GPU tree storage selection changed after admission".into());
        }
        let selected = ExecutionSelection::capture()?;
        if Some(selected) != self.plan.limits.execution {
            return Err(
                "registered GPU physical identity or execution selection changed after admission"
                    .into(),
            );
        }
        selected.qualify(self.plan.limits)
    }
}

#[cfg(all(test, feature = "stream"))]
mod tests;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod uniform_pcs;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod transcript_pcs;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod affine_pcs;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod sparse_pcs;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod ntt_pcs;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod mul_pcs;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod g_bound_pcs;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod permutation_pcs;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub mod linear_map_pcs;
