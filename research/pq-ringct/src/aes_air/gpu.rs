use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{
        self, AesTraceSpec, GeneratedTrace, PeriodicSource, ProvedNative, TraceContext,
    },
    proving::Request,
};

impl PeriodicSource for AesAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(self.height)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if index >= PERIODIC_COLUMNS || output.len() != self.height {
            return Err("AES periodic column geometry".into());
        }
        output.fill(Val::ZERO);
        let active_rows = self.descriptor.blocks() * 14;
        for (row, value) in output.iter_mut().enumerate().take(active_rows) {
            let round = row % 14;
            let block = row / 14;
            let take = self
                .descriptor
                .output_len
                .saturating_sub(block * 16)
                .min(16);
            let set = match index {
                ACTIVE => true,
                FIRST => round == 0,
                LAST => round == 13,
                MIDDLE => round < 13,
                END => row + 1 == active_rows,
                GLOBAL_LINK => row + 1 < active_rows,
                ROTATE => round % 2 == 0,
                FULL_BLOCK => block + 1 < self.descriptor.blocks(),
                _ if (RCON..RCON + 8).contains(&index) => {
                    round % 2 == 0 && ((gf_pow(2, (round / 2) as u16) >> (index - RCON)) & 1) != 0
                }
                _ if (INPUT_CHUNK..INPUT_CHUNK + 7).contains(&index) => {
                    block == 0 && round == index - INPUT_CHUNK
                }
                _ if (OUTPUT_CHUNK..OUTPUT_CHUNK + 2).contains(&index) => {
                    round == index - OUTPUT_CHUNK && round * 8 < take
                }
                _ => false,
            };
            *value = if index == COUNTER {
                Val::from_u32(self.descriptor.start_counter.wrapping_add(block as u32))
            } else {
                Val::from_bool(set)
            };
        }
        Ok(())
    }
}
impl AesAir {
    pub fn generate_gpu(
        &self,
        context: &TraceContext<'_>,
        key: &[u8; 32],
    ) -> Result<GeneratedTrace, String> {
        context.aes_wide_trace(
            key,
            AesTraceSpec {
                domain: self.descriptor.domain,
                start_counter: self.descriptor.start_counter,
                output_len: self.descriptor.output_len,
                first_block: 0,
                blocks: self.descriptor.blocks(),
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
            "pq_aes_wide_native",
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
    fn bounded_gpu_periodic_columns_match_wide_aes_schedule() {
        for output_len in [1, 15, 16, 17, 33, 1024] {
            let air = AesAir::new(Descriptor {
                domain: 7,
                start_counter: u32::MAX,
                output_len,
            })
            .unwrap();
            for (index, expected) in air.periodic_columns().iter().enumerate() {
                let mut actual = vec![Val::ZERO; air.height];
                air.fill_column(index, &mut actual).unwrap();
                assert_eq!(&actual, expected);
            }
        }
    }
}
