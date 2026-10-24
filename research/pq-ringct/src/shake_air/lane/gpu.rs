use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{
        self, GeneratedTrace, PeriodicSource, ProvedNative, ShakeTraceSpec, TraceContext,
    },
    proving::Request,
};
impl PeriodicSource for LaneShakeAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(SCHEDULE_PERIOD)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if index >= PERIODIC_COLUMNS || output.len() != SCHEDULE_PERIOD {
            return Err("SHAKE lane periodic column geometry".into());
        }
        let raw = self.descriptor.input_bytes(self.permutation);
        let take = self.descriptor.output_bytes(self.permutation);
        for (step, value) in output.iter_mut().enumerate() {
            let (x, y, operation) = match step {
                0..=24 => (
                    step / 5,
                    step % 5,
                    if step % 5 == 0 { C_RESET } else { C_UPDATE },
                ),
                25..=49 => ((step - 25) % 5, (step - 25) / 5, THETA),
                50..=74 => ((step - 50) % 5, (step - 50) / 5, RHO),
                75..=99 => ((step - 75) % 5, (step - 75) / 5, CHI),
                100 => (0, 0, IOTA),
                101..=117 => ((step - 101) % 5, (step - 101) / 5, BYTES),
                _ => (0, 0, BLOCK_END),
            };
            let mut set = index == SX + x
                || index == SY + y
                || ((step <= 117 || step == 127) && index == operation);
            if (101..=117).contains(&step) {
                if (INPUT_RAW..INPUT_RAW + 8).contains(&index) {
                    set = (step - 101) * 8 + index - INPUT_RAW < raw;
                }
                if (SUFFIX..SUFFIX + 8).contains(&index) {
                    set = self.last_absorption() && (step - 101) * 8 + index - SUFFIX == raw;
                }
                if (OUTPUT_RAW..OUTPUT_RAW + 8).contains(&index) {
                    set = (step - 101) * 8 + index - OUTPUT_RAW < take;
                }
            }
            *value = Val::from_bool(set);
        }
        Ok(())
    }
}
impl LaneShakeAir {
    pub fn generate_gpu(
        &self,
        context: &TraceContext<'_>,
        input: &[u8],
    ) -> Result<GeneratedTrace, String> {
        context.shake_lane_trace(
            input,
            ShakeTraceSpec {
                input_len: self.descriptor.input_len,
                output_len: self.descriptor.output_len,
                first_permutation: self.permutation,
                permutations: 1,
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
            "pq_shake_lane_native",
            self,
            self,
            HEIGHT,
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
    fn bounded_gpu_periodic_columns_match_shake_lane_schedule() {
        for (input_len, output_len) in [(0, 1), (135, 137), (136, 272), (273, 409)] {
            let descriptor = Descriptor {
                input_len,
                output_len,
            };
            for permutation in 0..descriptor.permutations().unwrap() {
                let air = LaneShakeAir::new(descriptor, permutation).unwrap();
                for (index, expected) in air.periodic_columns().iter().enumerate() {
                    let mut actual = vec![Val::ZERO; SCHEDULE_PERIOD];
                    air.fill_column(index, &mut actual).unwrap();
                    assert_eq!(&actual, expected);
                }
            }
        }
    }
}
