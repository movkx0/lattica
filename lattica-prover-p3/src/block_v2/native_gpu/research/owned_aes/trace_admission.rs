//! Exact prefix-sensitive AES trace storage, admitted before runtime creation.
use super::*;

/// Conservative source bound, not a runtime receipt or dispatch authority.
/// The maintained PCS planner includes the main trace. All four remaining
/// crypto-trace allocations are added without taking any overlap credit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct NativeAesTraceFootprint {
    generated_trace_bytes: usize,
    additional_trace_bytes: usize,
    trace_generation_peak_bytes: usize,
    maintained_pcs_peak_bytes: usize,
    combined_peak_bytes: usize,
    largest_trace_allocation_bytes: usize,
    allocation_ceiling_bytes: usize,
}

impl NativeAesTraceFootprint {
    pub(super) fn for_plan(
        preparation: AesPreparationPlan,
        pcs: NativeAesPcsFootprint,
    ) -> Result<Self> {
        if preparation.geometry().rows() != pcs.rows
            || preparation.geometry().width() != pcs.main_width
            || !pcs.maintained_device_plan_complete
        {
            return Err(Error::Geometry);
        }
        Self::new(
            preparation,
            pcs.maintained_phase_peak_bytes,
            pcs.fresh_runtime_baseline_bytes,
            pcs.managed_phase_ceiling_bytes,
            pcs.source_allocation_ceiling_bytes,
        )
    }

    fn new(
        preparation: AesPreparationPlan,
        maintained_pcs_peak_bytes: usize,
        runtime_baseline_bytes: usize,
        managed_ceiling_bytes: usize,
        allocation_ceiling_bytes: usize,
    ) -> Result<Self> {
        let trace = preparation.trace_device();
        let generated_trace_bytes = trace.trace_bytes();
        let additional_trace_bytes = trace
            .generation_peak_bytes()
            .checked_sub(generated_trace_bytes)
            .ok_or(Error::Geometry)?;
        let combined_peak_bytes = maintained_pcs_peak_bytes
            .checked_add(additional_trace_bytes)
            .ok_or(Error::Admission)?;
        let generation_with_runtime = trace
            .generation_peak_bytes()
            .checked_add(runtime_baseline_bytes)
            .ok_or(Error::Admission)?;
        if managed_ceiling_bytes as u64 != MANAGED_DEVICE
            || allocation_ceiling_bytes == 0
            || allocation_ceiling_bytes > managed_ceiling_bytes
            || maintained_pcs_peak_bytes < runtime_baseline_bytes
                .checked_add(generated_trace_bytes)
                .ok_or(Error::Admission)?
            || combined_peak_bytes > managed_ceiling_bytes
            || generation_with_runtime > combined_peak_bytes
            || trace.largest_allocation_bytes() > allocation_ceiling_bytes
        {
            return Err(Error::Admission);
        }
        Ok(Self {
            generated_trace_bytes,
            additional_trace_bytes,
            trace_generation_peak_bytes: trace.generation_peak_bytes(),
            maintained_pcs_peak_bytes,
            combined_peak_bytes,
            largest_trace_allocation_bytes: trace.largest_allocation_bytes(),
            allocation_ceiling_bytes,
        })
    }

    pub fn combined_peak_bytes(self) -> usize {
        self.combined_peak_bytes
    }
    pub fn additional_trace_bytes(self) -> usize {
        self.additional_trace_bytes
    }
    pub fn largest_trace_allocation_bytes(self) -> usize {
        self.largest_trace_allocation_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block_v2::native_gpu::AesTraceSpec;

    fn source(first_block: usize) -> AesPreparationPlan {
        AesPreparationPlan::new(AesTraceSpec {
            domain: 5,
            start_counter: u32::MAX,
            output_len: (first_block + 64) * 16,
            first_block,
            blocks: 64,
        })
        .unwrap()
    }

    #[test]
    fn prefix_is_additive_even_when_padded_rows_and_pcs_geometry_match() {
        let early = source(0);
        let later = source(64);
        assert_eq!(early.geometry().rows(), later.geometry().rows());
        let a = NativeAesTraceFootprint::new(early, 2 << 30, 1 << 20, 8 << 30, 1 << 30).unwrap();
        let b = NativeAesTraceFootprint::new(later, 2 << 30, 1 << 20, 8 << 30, 1 << 30).unwrap();
        assert_eq!(b.additional_trace_bytes() - a.additional_trace_bytes(), 64 * 16 * 8);
        assert_eq!(b.combined_peak_bytes() - a.combined_peak_bytes(), 64 * 16 * 8);
    }

    #[test]
    fn exact_combined_ceiling_and_largest_allocation_are_checked_before_dispatch() {
        let source = source(64);
        let trace = source.trace_device();
        let extra = trace.generation_peak_bytes() - trace.trace_bytes();
        let maximum = 8usize << 30;
        assert!(NativeAesTraceFootprint::new(source, maximum - extra, 0, maximum,
            trace.largest_allocation_bytes()).is_ok());
        assert_eq!(NativeAesTraceFootprint::new(source, maximum - extra + 1, 0, maximum,
            trace.largest_allocation_bytes()), Err(Error::Admission));
        assert_eq!(NativeAesTraceFootprint::new(source, maximum - extra, 0, maximum,
            trace.largest_allocation_bytes() - 1), Err(Error::Admission));
        assert_eq!(NativeAesTraceFootprint::new(source, usize::MAX, 0, maximum, maximum),
            Err(Error::Admission));
        assert_eq!(NativeAesTraceFootprint::new(source, trace.trace_bytes() - 1, 0, maximum, maximum),
            Err(Error::Admission));
    }
}
