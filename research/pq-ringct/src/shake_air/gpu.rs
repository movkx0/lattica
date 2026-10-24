use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{
        self, GeneratedTrace, PeriodicSource, ProvedNative, ShakeTraceSpec, TraceContext,
    },
    proving::Request,
};
impl PeriodicSource for ShakeAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(self.height)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if index >= PERIODIC_COLUMNS || output.len() != self.height {
            return Err("SHAKE wide periodic column geometry".into());
        }
        let last_absorb = self.descriptor.absorb_permutations() - 1;
        let output_end = last_absorb + self.descriptor.output_len / RATE;
        output.fill(Val::ZERO);
        for (row, value) in output.iter_mut().enumerate().take(self.permutations * 24) {
            let local = row / 24;
            let global = self.first_permutation + local;
            *value = Val::from_bool(match index {
                FULL_INPUT => global < last_absorb,
                LAST_INPUT => global == last_absorb,
                FULL_OUTPUT => global >= last_absorb && global < output_end,
                LAST_OUTPUT => self.descriptor.output_len % RATE != 0 && global == output_end,
                LINK => row % 24 == 23 && local + 1 < self.permutations,
                END => row + 1 == self.permutations * 24,
                _ => false,
            });
        }
        Ok(())
    }
}
impl ShakeAir {
    pub fn generate_gpu(
        &self,
        context: &TraceContext<'_>,
        input: &[u8],
    ) -> Result<GeneratedTrace, String> {
        context.shake_wide_trace(
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
            "pq_shake_wide_native",
            self,
            self,
            self.height,
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
    fn bounded_gpu_periodic_columns_match_wide_shake_schedule() {
        for (input_len, output_len) in [(0, 1), (135, 137), (136, 272), (273, 409)] {
            let descriptor = Descriptor {
                input_len,
                output_len,
            };
            let total = descriptor.permutations().unwrap();
            for first in 0..total {
                let air = ShakeAir::new(descriptor, first, total - first).unwrap();
                for (index, expected) in air.periodic_columns().iter().enumerate() {
                    let mut actual = vec![Val::ZERO; air.height];
                    air.fill_column(index, &mut actual).unwrap();
                    assert_eq!(&actual, expected);
                }
            }
        }
    }
}
