//! GPU-generated native trace with bounded immutable periodic metadata.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{
    arithmetic::ArithmeticSpec, operations_arithmetic::ArithmeticOperationSpec, GeneratedTrace,
    OperationContext, PeriodicSource, TraceContext,
};

impl MulAir {
    /// Evaluate canonical graph operands with the native AIR's public term
    /// schedule, without constructing a dense trace or computing host products.
    pub(crate) fn evaluate_gpu_operations(
        &self,
        ctx: &OperationContext<'_>,
        left: &[[u64; D]],
        right: &[[u64; D]],
    ) -> Result<Vec<[u64; D]>, String> {
        if left.len() != self.count || right.len() != self.count {
            return Err("raw product input count".into());
        }
        let terms = self.gpu_operation_terms();
        let spec = ArithmeticOperationSpec::mul(self.modulus, self.count, &terms)?;
        drop(terms);
        ctx.admit_arithmetic_operation(&spec)?;
        let mut raw = Vec::with_capacity(spec.raw_input_words());
        for (a, b) in left.iter().zip(right) {
            raw.extend_from_slice(a);
            raw.extend_from_slice(b);
        }
        let result = ctx.arithmetic_output(&spec, &raw)?;
        drop(raw);
        result
            .chunks_exact(D)
            .map(|words| {
                words
                    .try_into()
                    .map_err(|_| "raw product result shape".into())
            })
            .collect()
    }

    fn gpu_operation_terms(&self) -> Vec<[u64; 2]> {
        (0..64 * 16)
            .map(|k| {
                let (f, n) = self.term(k / 16, (k % 16) / 4, k % 4);
                [f, n as u64]
            })
            .collect()
    }

    pub fn generate_gpu(
        &self,
        ctx: &TraceContext<'_>,
        left: &[[u64; D]],
        right: &[[u64; D]],
    ) -> Result<GeneratedTrace, String> {
        if left.len() != self.count || right.len() != self.count {
            return Err("product input count".into());
        }
        let terms = self.gpu_operation_terms();
        let spec = ArithmeticSpec::mul(self.modulus, self.count, &terms)?;
        drop(terms);
        ctx.admit_arithmetic_raw(&spec)?;
        let mut raw = Vec::with_capacity(spec.raw_input_words());
        for (a, b) in left.iter().zip(right) {
            raw.extend_from_slice(a);
            raw.extend_from_slice(b);
        }
        ctx.arithmetic_trace(&spec, &raw)
    }
}
impl PeriodicSource for MulAir {
    fn column_count(&self) -> usize {
        ENDS + self.count
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < ENDS + self.count).then_some(self.height)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("product periodic shape".into());
        }
        for (global, v) in output.iter_mut().enumerate() {
            let poly = global / ROWS_PER_POLYNOMIAL;
            let block = (global % ROWS_PER_POLYNOMIAL) / ROWS_PER_BLOCK;
            let local = global % ROWS_PER_BLOCK;
            // ROWS_PER_POLYNOMIAL is a multiple of ROWS_PER_BLOCK.
            if poly >= self.count {
                *v = Val::ZERO;
                continue;
            }
            let mut word = match index {
                LINK_INPUT => (local + 1 < ROWS_PER_BLOCK) as u64,
                RESET_STATE => (local + 1 == ROWS_PER_BLOCK) as u64,
                IS_A => (local == 0) as u64,
                IS_B => (local == 1) as u64,
                IS_O => (local == 18) as u64,
                RESET_ACC => (block == 63 && local == 18 && poly + 1 < self.count) as u64,
                _ => 0,
            };
            if (2..18).contains(&local) {
                let term = local - 2;
                let i = term / 4;
                let j = term % 4;
                let (factor, negative) = self.term(block, i, j);
                if index == IS_MUL
                    || index == SELECT_A + i
                    || index == SELECT_B + j
                    || index == SELECT_O + (i + j) % 4
                {
                    word = 1;
                }
                if index == FACTOR {
                    word = factor;
                }
                if index == NEGATIVE {
                    word = negative as u64;
                }
            }
            if index == ENDS + poly && block == 63 && local == 18 {
                word = 1;
            }
            *v = Val::from_u64(word);
        }
        Ok(())
    }
}

impl RegisteredMulAir {
    /// Prove from raw inputs entirely on the admitted OpenCL backend, then
    /// independently verify with the unchanged native CPU verifier.
    pub fn prove_gpu(
        &self,
        left: &[[u64; D]],
        right: &[[u64; D]],
        host_bytes: usize,
        request: lattica_prover_p3::proving::Request,
    ) -> Result<(MulBatchProof, lattica_prover_p3::proving::Report), crate::crypto_join::Error>
    {
        let backend = |message: String| {
            crate::crypto_join::Error::Compile(
                lattica_prover_p3::block_v2::machine::verifier::CompileError::Backend(message),
            )
        };
        let proved = lattica_prover_p3::block_v2::native_gpu::prove(
            "matrict_poly_air_gpu",
            self.air(),
            self.air(),
            self.air().height,
            host_bytes,
            request,
            |ctx| self.air().generate_gpu(ctx, left, right),
        )
        .map_err(backend)?;
        let artifact = MulBatchProof {
            public_values: proved.public_values,
            proof: proved.proof,
        };
        self.verify(&artifact)?;
        Ok((artifact, proved.report))
    }
}
