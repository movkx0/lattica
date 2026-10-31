use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{
        self, AesTraceSpec, GeneratedTrace, PeriodicSource, ProvedNative, TraceContext,
    },
    proving::Request,
};

impl PeriodicSource for AesLaneAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(SCHEDULE_PERIOD)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if index >= PERIODIC_COLUMNS || output.len() != SCHEDULE_PERIOD {
            return Err("AES lane periodic column geometry".into());
        }
        for (row, value) in output.iter_mut().enumerate() {
            let slot = row % 16;
            let operation = if row < 16 {
                SUB
            } else if row < 32 {
                MIX
            } else if slot < 4 {
                KEY_SUB
            } else {
                KEY_XOR
            };
            *value = Val::from_bool(
                index == SLOT + slot
                    || (row < 48 && index == operation)
                    || (index == KEY_ROTATE && row == 47)
                    || (index == PHASE_END && row == 63)
                    || ((HEADER..HEADER + 7).contains(&index) && row == index - HEADER)
                    || ((OUTPUT_CHUNK..OUTPUT_CHUNK + 2).contains(&index)
                        && row == index - OUTPUT_CHUNK),
            );
        }
        Ok(())
    }
}
impl AesLaneAir {
    pub fn generate_gpu(
        &self,
        context: &TraceContext<'_>,
        key: &[u8; 32],
    ) -> Result<GeneratedTrace, String> {
        context.aes_lane_trace(
            key,
            AesTraceSpec {
                domain: self.descriptor.domain,
                start_counter: self.descriptor.start_counter,
                output_len: self.descriptor.output_len,
                first_block: self.first_block,
                blocks: self.blocks,
            },
        )
    }
    pub fn prove_gpu(
        &self,
        key: &[u8; 32],
        host_bytes: usize,
        request: Request,
    ) -> Result<ProvedNative, String> {
        native_gpu::prove(
            "pq_aes_lane_native",
            self,
            self,
            self.height,
            host_bytes,
            request,
            |context| self.generate_gpu(context, key),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_gpu_periodic_columns_match_aes_lane_schedule() {
        let air = AesLaneAir::new(Descriptor {
            domain: 7,
            start_counter: 9,
            output_len: 17,
        })
        .unwrap();
        for (index, expected) in air.periodic_columns().iter().enumerate() {
            let mut actual = vec![Val::ZERO; SCHEDULE_PERIOD];
            air.fill_column(index, &mut actual).unwrap();
            assert_eq!(&actual, expected);
        }
    }
}
