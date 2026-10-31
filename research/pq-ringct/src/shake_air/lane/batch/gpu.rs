use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{
        self, GeneratedTrace, PeriodicSource, ProvedNative, ShakeTraceSpec, TraceContext,
    },
    proving::Request,
};
impl PeriodicSource for BatchShakeAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(SCHEDULE_PERIOD)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        LaneShakeAir::new(self.descriptor, self.first_permutation)
            .map_err(|e| format!("{e:?}"))?
            .fill_column(index, output)
    }
}
impl BatchShakeAir {
    pub fn generate_gpu(
        &self,
        context: &TraceContext<'_>,
        input: &[u8],
    ) -> Result<GeneratedTrace, String> {
        context.shake_lane_batch_trace(
            input,
            ShakeTraceSpec {
                input_len: self.descriptor.input_len,
                output_len: self.descriptor.output_len,
                first_permutation: self.first_permutation,
                permutations: self.permutations,
            },
        )
    }
    pub fn prove_gpu(
        &self,
        input: &[u8],
        host_bytes: usize,
        request: Request,
    ) -> Result<ProvedNative, String> {
        native_gpu::prove(
            "pq_shake_lane_batch_native",
            self,
            self,
            self.height,
            host_bytes,
            request,
            |context| self.generate_gpu(context, input),
        )
    }
}
impl PeriodicSource for ShakeSegmentAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(SCHEDULE_PERIOD)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        match self {
            Self::Single(air) => air.fill_column(index, output),
            Self::Batch(air) => air.fill_column(index, output),
        }
    }
}
impl ShakeSegmentAir {
    pub fn generate_gpu(
        &self,
        context: &TraceContext<'_>,
        input: &[u8],
    ) -> Result<GeneratedTrace, String> {
        match self {
            Self::Single(air) => air.generate_gpu(context, input),
            Self::Batch(air) => air.generate_gpu(context, input),
        }
    }
    pub fn prove_gpu(
        &self,
        input: &[u8],
        host_bytes: usize,
        request: Request,
    ) -> Result<ProvedNative, String> {
        native_gpu::prove(
            "pq_shake_segment_native",
            self,
            self,
            self.height(),
            host_bytes,
            request,
            |context| self.generate_gpu(context, input),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_gpu_periodic_columns_match_shake_batch_schedule() {
        let descriptor = Descriptor {
            input_len: 8 * RATE + 5,
            output_len: 9 * RATE + 1,
        };
        for air in [
            BatchShakeAir::full_absorb(descriptor, 0, 8).unwrap(),
            BatchShakeAir::full_squeeze(descriptor, 9, 4).unwrap(),
        ] {
            for (index, expected) in air.periodic_columns().iter().enumerate() {
                let mut actual = vec![Val::ZERO; SCHEDULE_PERIOD];
                air.fill_column(index, &mut actual).unwrap();
                assert_eq!(&actual, expected);
            }
        }
    }
}
