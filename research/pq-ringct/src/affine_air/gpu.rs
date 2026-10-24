//! GPU-generated native trace with bounded immutable periodic metadata.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{
    arithmetic::ArithmeticSpec, GeneratedTrace, PeriodicSource, TraceContext,
};

impl AffineAir {
    pub fn generate_gpu(
        &self,
        ctx: &TraceContext<'_>,
        inputs: &[AffineInput],
    ) -> Result<GeneratedTrace, String> {
        if inputs.len() != self.count {
            return Err("affine input count".into());
        }
        let spec = ArithmeticSpec::affine(
            self.modulus,
            self.count,
            self.kind.code(),
            self.kind.bound(),
        )?;
        ctx.admit_arithmetic_raw(&spec)?;
        let mut raw = Vec::with_capacity(spec.raw_input_words());
        for input in inputs {
            match (self.kind, input) {
                (AffineKind::Add | AffineKind::Sub, AffineInput::Binary { left, right }) => {
                    raw.extend_from_slice(left);
                    raw.extend_from_slice(right);
                }
                (AffineKind::SignedToCanonical { .. }, AffineInput::Signed(v)) => {
                    raw.extend(v.iter().map(|&v| v as u64))
                }
                _ => return Err("affine input kind".into()),
            }
        }
        ctx.arithmetic_trace(&spec, &raw)
    }
}
impl PeriodicSource for AffineAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(ROWS_PER_POLYNOMIAL)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("affine periodic shape".into());
        }
        for (row, v) in output.iter_mut().enumerate() {
            *v = Val::from_bool(match index {
                HASH_A => row < 256 && row % 4 == 0,
                HASH_B => row < 256 && row % 4 == 1 && !self.kind.is_conversion(),
                HASH_O => row < 256 && row % 4 == 2,
                BUNDLE_A => row == 256,
                BUNDLE_B => row == 257 && !self.kind.is_conversion(),
                BUNDLE_O => row == 258,
                LINK => row < 256 && row % 4 < 3,
                RESET => row == 511,
                IDLE => row >= 256,
                _ => unreachable!(),
            });
        }
        Ok(())
    }
}

impl RegisteredAffineAir {
    /// Prove from raw inputs entirely on the admitted OpenCL backend, then
    /// independently verify with the unchanged native CPU verifier.
    pub fn prove_gpu(
        &self,
        inputs: &[AffineInput],
        host_bytes: usize,
        request: lattica_prover_p3::proving::Request,
    ) -> Result<(AffineBatchProof, lattica_prover_p3::proving::Report), crate::crypto_join::Error>
    {
        let backend = |message: String| {
            crate::crypto_join::Error::Compile(
                lattica_prover_p3::block_v2::machine::verifier::CompileError::Backend(message),
            )
        };
        let proved = lattica_prover_p3::block_v2::native_gpu::prove(
            "matrict_affine_air_gpu",
            self.air(),
            self.air(),
            self.air().height(),
            host_bytes,
            request,
            |ctx| self.air().generate_gpu(ctx, inputs),
        )
        .map_err(backend)?;
        let artifact = AffineBatchProof {
            public_values: proved
                .public_values
                .try_into()
                .map_err(|_| backend("native public width".into()))?,
            proof: proved.proof,
        };
        self.verify(&artifact)?;
        Ok((artifact, proved.report))
    }
}

#[cfg(test)]
mod tests;
