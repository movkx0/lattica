//! Native cubic mul PCS host and opening-phase source composition.
//! Preparation, configuration, trace generation, reports, OpenCL wrappers and
//! output/verification ownership are separate. The maintained source device
//! model is checked before startup under the caller's planner reservation.
//! This type contains no permission to dispatch an AIR or accept a proof.
#![cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    feature = "gpu-bounded-info"
))]
use super::{opening, selection::ExecutionSelection, RegisteredGpuLimits};
use crate::block_v2::{
    gpu_hash::{
        device,
        engine::{self, Limits},
    },
    gpu_quotient_prover::opened_value_descriptor_host_bound,
    profile,
    quotient_program::{MAX_CONSTRAINTS, MAX_NODES, WORDS_PER_INSTRUCTION},
};
use core::mem::size_of;
use crate::block_v2::native_gpu::mul_preparation::{MulGeometry, MulDescriptor};

mod preopening;

fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "native mul PCS addition overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b)
        .ok_or_else(|| "native mul PCS multiplication overflow".into())
}
fn bytes<T>(count: usize) -> Result<usize, String> {
    mul(count, size_of::<T>())
}
fn sum(parts: &[usize]) -> Result<usize, String> {
    parts.iter().try_fold(0, |n, &part| add(n, part))
}

#[derive(Clone, Copy, Debug)]
struct Geometry {
    source: MulGeometry,
    rows: usize,
    main_width: usize,
    public_values: usize,
    quotient_chunks: usize,
    log_blowup: usize,
    cap_height: usize,
}
impl Geometry {
    fn new(source: MulGeometry) -> Result<Self, String> {
        let result = Self {
            source,
            rows: source.rows(),
            main_width: source.width(),
            public_values: source.public_values(),
            quotient_chunks: 32,
            log_blowup: profile::LOG_BLOWUP,
            cap_height: profile::CAP_HEIGHT,
        };
        result.check()?;
        Ok(result)
    }
    fn check(self) -> Result<(), String> {
        let expected = self.source.kind().geometry_tuple();
        if !cfg!(all(
            not(debug_assertions),
            target_arch = "x86_64",
            feature = "gpu-bounded-info",
            feature = "block-v2-wide-lanes"
        )) || (self.rows, self.main_width, self.public_values, self.source.periodic_columns()) != expected
            || !self.rows.is_power_of_two()
            || self.source.period() != self.source.rows()
            || self.quotient_chunks != 32
            || self.log_blowup != 4
            || self.cap_height != 6
            || profile::NUM_RANDOM_CODEWORDS != 4
            || profile::NUM_QUERIES != 128
            || size_of::<profile::Challenge>() != 24
        {
            return Err("native mul PCS requires pinned cubic source geometry".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct NativeMulPcsFootprint {
    pub rows: usize,
    pub main_width: usize,
    pub maximum_quotient_chunks: usize,
    pub maximum_matrices: usize,
    pub preopening_host_bytes: usize,
    pub opening_workspace_host_bytes: usize,
    pub retained_metadata_host_bytes: usize,
    pub opened_value_descriptors_host_bytes: usize,
    pub required_pcs_host_bytes: usize,
    pub operation_host_budget_bytes: usize,
    pub maintained_device_plan_complete: bool,
    pub managed_phase_ceiling_bytes: usize,
    pub maintained_phase_peak_bytes: usize,
    pub fresh_runtime_baseline_bytes: usize,
    pub source_allocation_ceiling_bytes: usize,
    pub opening_device_peak_bytes: usize,
    pub fri_device_peak_bytes: usize,
    pub query_device_peak_bytes: usize,
    pub minimum_opening_device_bytes: usize,
    pub largest_opening_allocation_bytes: usize,
    pub retained_tree_storage_mode: engine::RetainedTreeStorageMode,
    pub selected_tree_host_quota_bytes: usize,
    pub required_tree_host_bytes: usize,
    pub complete_native_dispatch_admission: bool,
}

/// This source plan uses bounded planner scratch and consumes no externally
/// supplied proof, closure or key. Its enclosing source owner must establish
/// the exact request, preparation/normalization profile and full phase owners.
pub struct NativeMulPcsPlan {
    limits: RegisteredGpuLimits,
    footprint: NativeMulPcsFootprint,
    source_device: device::MulDeviceCensus,
}

impl NativeMulPcsPlan {
    /// Disconnected internal model until the actual native producer binds its
    /// original planner reservation. No production call site is installed by
    /// this phase capsule. Selection is already captured under runtime bounds.
    pub(crate) fn new(
        source: MulGeometry,
        operation_host_budget_bytes: usize,
        limits: RegisteredGpuLimits,
    ) -> Result<Self, String> {
        let g = Geometry::new(source)?;
        let rows = source.rows();
        let main_width = source.width();
        if rows > limits.max_rows
            || operation_host_budget_bytes == 0
            || operation_host_budget_bytes > 24 << 30
            || limits.trees.host_bytes > 8 << 30
        {
            return Err("native mul PCS exceeds fixed worker limits".into());
        }
        let selected = limits
            .execution
            .ok_or("native mul PCS requires captured physical selection")?;
        selected.qualify(limits)?;
        selected.qualify_host_output(operation_host_budget_bytes as u64)?;
        let device_limits = Limits {
            managed_bytes: limits.device_bytes as usize,
            ..Default::default()
        };
        let max_allocation = usize::try_from(selected.physical_max_allocation_bytes)
            .map_err(|_| "native mul PCS physical allocation overflow")?;
        let source_device = device::MulDeviceCensus::new(
            source,
            operation_host_budget_bytes,
            device_limits,
            max_allocation,
            selected.slots,
        )?;
        if source_device.tree_selection() != limits.trees {
            return Err(
                "native mul source tree selection differs from captured admission".into(),
            );
        }
        // Charge bounded quotient code throughout the opening, even though the
        // actual uni adapter releases its compiled owner first. Retaining the
        // periodic/compiler scratch ceiling also avoids unowned overlap credit.
        let common = sum(&[
            engine::retained_query_base_bytes(device_limits)?,
            mul(
                mul(add(MAX_NODES, MAX_CONSTRAINTS)?, WORDS_PER_INSTRUCTION)?,
                8,
            )?,
            crate::block_v2::challenger::resources::reservation().managed_bytes as usize,
            5 * 32,
            device::public_hash::WORKSPACE_BYTES.max(device::PERIODIC_WORKSPACE_BYTES) as usize,
        ])?;
        let opening = opening::native_plan(
            rows,
            main_width,
            common,
            operation_host_budget_bytes,
            device_limits,
            max_allocation,
            limits.trees,
        )?;
        let preopening = preopening::Preopening::new(g)?;
        let descriptors = opened_value_descriptor_host_bound::<profile::Challenge>(1, 0, 32)
            .map_err(|_| "native mul opened-value descriptor census")?;
        let required_pcs_host_bytes = sum(&[
            preopening.host_bytes,
            opening.host_workspace_peak_bytes,
            opening.retained_host_metadata_bytes,
            descriptors,
            size_of::<Self>(),
            size_of::<p3_uni_stark::Proof<profile::Config>>(),
            #[cfg(feature = "ringct-research-quota")]
            device::MulDeviceLease::inline_host_bytes(),
        ])?;
        if !opening.host_bound_complete
            || required_pcs_host_bytes > operation_host_budget_bytes
            || opening.required_tree_host_bytes > limits.trees.host_bytes
        {
            return Err("native mul PCS source backing exceeds its actual allowance".into());
        }
        Ok(Self {
            limits,
            source_device,
            footprint: NativeMulPcsFootprint {
                rows,
                main_width,
                maximum_quotient_chunks: 32,
                maximum_matrices: 34,
                preopening_host_bytes: preopening.host_bytes,
                opening_workspace_host_bytes: opening.host_workspace_peak_bytes,
                retained_metadata_host_bytes: opening.retained_host_metadata_bytes,
                opened_value_descriptors_host_bytes: descriptors,
                required_pcs_host_bytes,
                operation_host_budget_bytes,
                maintained_device_plan_complete: true,
                managed_phase_ceiling_bytes: source_device.managed_ceiling_bytes(),
                maintained_phase_peak_bytes: source_device.maximum_planned_phase_bytes(),
                fresh_runtime_baseline_bytes: source_device.runtime_baseline_bytes(),
                source_allocation_ceiling_bytes: source_device.allocation_ceiling_bytes(),
                opening_device_peak_bytes: opening.opening_device_peak_bytes,
                fri_device_peak_bytes: opening.fri_device_peak_bytes,
                query_device_peak_bytes: opening.query_device_peak_bytes,
                minimum_opening_device_bytes: opening.minimum_required_device_bytes,
                largest_opening_allocation_bytes: opening.largest_allocation_bytes,
                retained_tree_storage_mode: limits.trees.mode,
                selected_tree_host_quota_bytes: limits.trees.host_bytes,
                required_tree_host_bytes: opening.required_tree_host_bytes,
                complete_native_dispatch_admission: false,
            },
        })
    }

    pub fn footprint(&self) -> NativeMulPcsFootprint {
        self.footprint
    }

    /// Only a closed unattempted native phase may preissue a future geometry.
    /// Preserve the captured selector and original operation capacity exactly;
    /// this helper creates neither quota nor dispatch authority.
    pub(crate) fn preissue_original_capacity(
        &self,
        source: MulGeometry,
    ) -> Result<Self, String> {
        Self::new(source, self.footprint.operation_host_budget_bytes, self.limits)
    }

    pub(crate) fn same_original_capacity(&self, other: &Self) -> bool {
        self.limits == other.limits
            && self.footprint.operation_host_budget_bytes == other.footprint.operation_host_budget_bytes
            && self.footprint.managed_phase_ceiling_bytes == other.footprint.managed_phase_ceiling_bytes
            && self.footprint.fresh_runtime_baseline_bytes == other.footprint.fresh_runtime_baseline_bytes
    }

    #[cfg(feature = "ringct-research-quota")]
    pub(crate) fn acquire_device<'a>(
        &self,
        preparation: crate::block_v2::native_gpu::mul_preparation::MulPreparationPlan,
        minimum: device::WalletProofMinimum,
        session: &device::DeviceSession,
        runtime: &'a device::ringct_runtime::Runtime,
        ledger: &'a crate::ringct_research_quota::Ledger,
        preparation_owner: &'a crate::ringct_research_quota::Reservation,
        runtime_owner: &'a crate::ringct_research_quota::Reservation,
        pcs_owner: &'a crate::ringct_research_quota::Reservation,
    ) -> Result<device::MulDeviceLease<'a>, &'static str> {
        self.source_device.acquire(
            self,
            preparation,
            minimum,
            session,
            runtime,
            ledger,
            preparation_owner,
            runtime_owner,
            pcs_owner,
        )
    }

    /// The original immutable environment/runtime guard must remain live. This
    /// only checks source selection; it cannot authorize a native callback.
    pub fn check_execution_selection(&self) -> Result<(), String> {
        if engine::retained_storage::Selection::from_env()? != self.limits.trees {
            return Err("native mul PCS tree selection changed".into());
        }
        let selection = ExecutionSelection::capture()?;
        if self.limits.execution != Some(selection) {
            return Err("native mul PCS execution selection changed".into());
        }
        selection.qualify(self.limits)?;
        selection.qualify_host_output(self.footprint.operation_host_budget_bytes as u64)
    }
}
