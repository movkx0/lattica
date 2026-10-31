//! Six source-trace allocations, admitted before runtime or private upload.
use super::*;

/// The maintained PCS model includes the main trace. All five other source
/// matrices are additive; no overlap credit is taken for their destruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct NativeTranscriptTraceFootprint {
    generated_trace_bytes: usize,
    additional_trace_bytes: usize,
    trace_generation_peak_bytes: usize,
    maintained_pcs_peak_bytes: usize,
    combined_peak_bytes: usize,
    largest_trace_allocation_bytes: usize,
    allocation_ceiling_bytes: usize,
}

impl NativeTranscriptTraceFootprint {
    pub(super) fn for_plan(
        preparation: TranscriptPreparationPlan,
        pcs: NativeTranscriptPcsFootprint,
    ) -> Result<Self> {
        if preparation.geometry().rows() != pcs.rows
            || preparation.geometry().width() != pcs.main_width
            || !pcs.maintained_device_plan_complete
        { return Err(Error::Geometry); }
        Self::new(preparation, pcs.maintained_phase_peak_bytes,
            pcs.fresh_runtime_baseline_bytes, pcs.managed_phase_ceiling_bytes,
            pcs.source_allocation_ceiling_bytes)
    }

    fn new(preparation: TranscriptPreparationPlan, maintained_pcs_peak_bytes: usize,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_non_trace_matrices_are_additive_for_representative_transcript_sources() {
        for kind in crate::block_v2::native_gpu::transcript_preparation::test_layouts() {
            let source = TranscriptPreparationPlan::new(kind).unwrap();
            let trace = source.device();
            let expected = trace.public_bytes + trace.raw_bytes + trace.geometry_bytes
                + trace.endpoint_bytes + trace.status_bytes;
            let footprint = NativeTranscriptTraceFootprint::new(source,
                2 << 30, 1 << 20, 8 << 30, 1 << 30).unwrap();
            assert_eq!(footprint.additional_trace_bytes(), expected);
            assert_eq!(footprint.combined_peak_bytes(), (2 << 30) + expected);
            assert_eq!(footprint.trace_generation_peak_bytes, trace.trace_bytes + expected);
        }
    }

    #[test]
    fn trace_admission_refuses_every_exceeded_original_bound() {
        for kind in crate::block_v2::native_gpu::transcript_preparation::test_layouts() {
            let source = TranscriptPreparationPlan::new(kind).unwrap();
            let trace = source.device();
            let ceiling = 8 << 30;
            let extra = trace.generation_peak_bytes - trace.trace_bytes;
            assert!(NativeTranscriptTraceFootprint::new(source, ceiling - extra,
                0, ceiling, trace.largest_allocation_bytes).is_ok());
            for (pcs, startup, allocation) in [
                (ceiling - extra + 1, 0, trace.largest_allocation_bytes),
                (ceiling - extra, 0, trace.largest_allocation_bytes - 1),
                (trace.trace_bytes - 1, 0, trace.largest_allocation_bytes),
                (usize::MAX, 0, usize::MAX),
                (trace.trace_bytes, ceiling - trace.generation_peak_bytes + 1,
                    trace.largest_allocation_bytes),
            ] {
                assert_eq!(NativeTranscriptTraceFootprint::new(source, pcs,
                    startup, ceiling, allocation), Err(Error::Admission));
            }
        }
    }
}
