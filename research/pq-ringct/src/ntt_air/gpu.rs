//! GPU-generated native trace with bounded immutable periodic metadata.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{
    arithmetic::ArithmeticSpec, operations_arithmetic::ArithmeticOperationSpec, GeneratedTrace,
    OperationContext, PeriodicSource, TraceContext,
};

#[cfg(test)]
mod operations_tests;

impl NttAir {
    /// Compute raw graph values on GPU from signed coefficients. Metadata uses
    /// the same public butterfly builder as the native AIR trace generator.
    pub(crate) fn evaluate_gpu_operations(
        &self,
        ctx: &OperationContext<'_>,
        inputs: &[[i64; D]],
    ) -> Result<Vec<[u64; D]>, String> {
        if inputs.len() != self.count {
            return Err("raw NTT input count".into());
        }
        let (steps, permutation) = self.gpu_operation_schedule();
        let spec = ArithmeticOperationSpec::ntt(self.modulus, self.count, &steps, &permutation)?;
        drop(steps);
        ctx.admit_arithmetic_operation(&spec)?;
        let raw: Vec<_> = inputs.iter().flatten().map(|&v| v as u64).collect();
        let result = ctx.arithmetic_output(&spec, &raw)?;
        // Retire staging before allocating the shaped result; its bytes fit in
        // the admitted raw input reservation while the returned words are live.
        drop(raw);
        result
            .chunks_exact(D)
            .map(|words| words.try_into().map_err(|_| "raw NTT result shape".into()))
            .collect()
    }

    fn gpu_operation_schedule(&self) -> (Vec<[u64; 4]>, [u64; 64]) {
        let steps = (0..768)
            .map(|i| {
                let s = self.gpu_step(i);
                [s.a as u64, s.b as u64, s.factor_u, s.factor_v]
            })
            .collect();
        let permutation = core::array::from_fn(|i| {
            if self.modulus == Q {
                PERM_NTT[i] as u64
            } else {
                i as u64
            }
        });
        (steps, permutation)
    }

    /// One public butterfly, without allocating the complete schedule.
    fn gpu_step(&self, index: usize) -> Step {
        let q = self.modulus;
        let omega = if q == Q { &OMEGA_Q } else { &OMEGA_QHAT };
        if index < 128 {
            let conversion = if q == Q { 138_438_709 } else { 2_333_348_873 };
            Step {
                a: index,
                b: index + 128,
                factor_u: arithmetic::mont(1, conversion, q),
                factor_v: arithmetic::mont(1, omega[1], q),
            }
        } else {
            let stage = index / 128;
            let stride = 128 >> stage;
            let group = (index % 128) / stride;
            let a = 2 * group * stride + index % stride;
            Step {
                a,
                b: a + stride,
                factor_u: 1,
                factor_v: arithmetic::mont(1, omega[(1 << stage) + group], q),
            }
        }
    }
    pub fn generate_gpu(
        &self,
        ctx: &TraceContext<'_>,
        inputs: &[[u64; D]],
    ) -> Result<GeneratedTrace, String> {
        if inputs.len() != self.count {
            return Err("NTT input count".into());
        }
        let (steps, permutation) = self.gpu_operation_schedule();
        let spec = ArithmeticSpec::ntt(self.modulus, self.count, &steps, &permutation)?;
        drop(steps);
        ctx.admit_arithmetic_raw(&spec)?;
        let raw: Vec<_> = inputs.iter().flatten().copied().collect();
        ctx.arithmetic_trace(&spec, &raw)
    }
}
impl PeriodicSource for NttAir {
    fn column_count(&self) -> usize {
        self.periodic_count()
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < self.periodic_count()).then_some(self.height)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("NTT periodic shape".into());
        }
        for (global, v) in output.iter_mut().enumerate() {
            let poly = global / ROWS_PER_POLYNOMIAL;
            let row = global % ROWS_PER_POLYNOMIAL;
            if poly >= self.count {
                *v = Val::ZERO;
                continue;
            }
            let mut word = match index {
                LINK_STATE => (row + 1 < ROWS_PER_POLYNOMIAL) as u64,
                RESET_OUTPUT => (row == 63) as u64,
                RESET_INPUT => (row + 1 == ROWS_PER_POLYNOMIAL && poly + 1 < self.count) as u64,
                IS_HASH => (row < 64 || row >= 832) as u64,
                IS_NTT => (64..832).contains(&row) as u64,
                _ => 0,
            };
            if index == ENDS + poly && row == 63 {
                word = 1;
            }
            if index == ENDS + self.count + poly && row + 1 == ROWS_PER_POLYNOMIAL {
                word = 1;
            }
            if index <= FACTOR_V {
                if (64..832).contains(&row) {
                    let s = self.gpu_step(row - 64);
                    word = [s.a as u64, s.b as u64, s.factor_u, s.factor_v][index];
                } else if index == ADDRESS_A {
                    word = 4 * if row < 64 {
                        row as u64
                    } else if self.modulus == Q {
                        PERM_NTT[row - 832] as u64
                    } else {
                        (row - 832) as u64
                    };
                }
            }
            *v = Val::from_u64(word);
        }
        Ok(())
    }
}

impl RegisteredNttAir {
    /// Prove from raw inputs entirely on the admitted OpenCL backend, then
    /// independently verify with the unchanged native CPU verifier.
    pub fn prove_gpu(
        &self,
        inputs: &[[u64; D]],
        host_bytes: usize,
        request: lattica_prover_p3::proving::Request,
    ) -> Result<(NttBatchProof, lattica_prover_p3::proving::Report), crate::crypto_join::Error>
    {
        let backend = |message: String| {
            crate::crypto_join::Error::Compile(
                lattica_prover_p3::block_v2::machine::verifier::CompileError::Backend(message),
            )
        };
        let proved = lattica_prover_p3::block_v2::native_gpu::prove(
            "matrict_ntt_air_gpu",
            self.air(),
            self.air(),
            self.air().height,
            host_bytes,
            request,
            |ctx| self.air().generate_gpu(ctx, inputs),
        )
        .map_err(backend)?;
        let artifact = NttBatchProof {
            public_values: proved.public_values,
            proof: proved.proof,
        };
        self.verify(&artifact)?;
        Ok((artifact, proved.report))
    }
}
