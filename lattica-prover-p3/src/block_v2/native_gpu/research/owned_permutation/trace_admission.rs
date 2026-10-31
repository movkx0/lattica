//! Six source-trace allocations, admitted before runtime or private upload.
use super::*;

/// The maintained PCS model includes the main trace. All five other source
/// matrices are additive; no overlap credit is taken for their destruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct NativePermutationTraceFootprint {
    generated_trace_bytes: usize,
    additional_trace_bytes: usize,
    trace_generation_peak_bytes: usize,
    maintained_pcs_peak_bytes: usize,
    combined_peak_bytes: usize,
    largest_trace_allocation_bytes: usize,
    allocation_ceiling_bytes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::permutation_preparation::{PermutationDescriptor};

    #[test]
    fn permutation_geometry_endpoints_and_public_are_additive_to_pcs_trace_peak() {
        let plan = PermutationPreparationPlan::new(PermutationDescriptor::from_code(1).unwrap()).unwrap();
        let d = plan.device();
        let expected = d.public_bytes + d.raw_bytes + d.geometry_bytes + d.endpoint_bytes + d.status_bytes;
        let pcs_peak = d.trace_bytes + 4096;
        let admitted = NativePermutationTraceFootprint::new(plan, pcs_peak, 4096, MANAGED_DEVICE as usize, usize::MAX).unwrap();
        assert_eq!(admitted.additional_trace_bytes(), expected);
        assert_eq!(admitted.combined_peak_bytes(), pcs_peak + expected);
        assert!(NativePermutationTraceFootprint::new(plan, MANAGED_DEVICE as usize - expected + 1,
            4096, MANAGED_DEVICE as usize, usize::MAX).is_err());
        assert!(NativePermutationTraceFootprint::new(plan, pcs_peak, 4096,
            MANAGED_DEVICE as usize, d.largest_allocation_bytes - 1).is_err());
        assert!(NativePermutationTraceFootprint::new(plan, pcs_peak, MANAGED_DEVICE as usize,
            MANAGED_DEVICE as usize, usize::MAX).is_err());
    }
}

impl NativePermutationTraceFootprint {
    pub(super) fn for_plan(
        preparation: PermutationPreparationPlan,
        pcs: NativePermutationPcsFootprint,
    ) -> Result<Self> {
        if preparation.geometry().rows() != pcs.rows
            || preparation.geometry().width() != pcs.main_width
            || !pcs.maintained_device_plan_complete
        { return Err(Error::Geometry); }
        Self::new(preparation, pcs.maintained_phase_peak_bytes,
            pcs.fresh_runtime_baseline_bytes, pcs.managed_phase_ceiling_bytes,
            pcs.source_allocation_ceiling_bytes)
    }

    fn new(preparation: PermutationPreparationPlan, maintained_pcs_peak_bytes: usize,
        runtime_baseline_bytes: usize, managed_ceiling_bytes: usize,
        allocation_ceiling_bytes: usize) -> Result<Self>
    {
        let trace = preparation.device();
        let generated_trace_bytes = trace.trace_bytes;
        let additional_trace_bytes = trace.generation_peak_bytes
            .checked_sub(generated_trace_bytes).ok_or(Error::Geometry)?;
        let combined_peak_bytes = maintained_pcs_peak_bytes
            .checked_add(additional_trace_bytes).ok_or(Error::Admission)?;
        let generation_with_runtime = trace.generation_peak_bytes
            .checked_add(runtime_baseline_bytes).ok_or(Error::Admission)?;
        if managed_ceiling_bytes as u64 != MANAGED_DEVICE
            || maintained_pcs_peak_bytes < generated_trace_bytes
            || additional_trace_bytes == 0
            || combined_peak_bytes > managed_ceiling_bytes
            || generation_with_runtime > managed_ceiling_bytes
            || trace.largest_allocation_bytes > allocation_ceiling_bytes
        { return Err(Error::Admission); }
        Ok(Self { generated_trace_bytes, additional_trace_bytes,
            trace_generation_peak_bytes: trace.generation_peak_bytes,
            maintained_pcs_peak_bytes, combined_peak_bytes,
            largest_trace_allocation_bytes: trace.largest_allocation_bytes,
            allocation_ceiling_bytes })
    }

    pub fn combined_peak_bytes(self) -> usize { self.combined_peak_bytes }
    pub fn additional_trace_bytes(self) -> usize { self.additional_trace_bytes }
    pub fn largest_trace_allocation_bytes(self) -> usize { self.largest_trace_allocation_bytes }
}
