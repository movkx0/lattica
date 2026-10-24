//! GPU-generated native trace with bounded immutable periodic metadata.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{
    arithmetic::ArithmeticSpec, operations_arithmetic::ArithmeticOperationSpec, GeneratedTrace,
    OperationContext, PeriodicSource, TraceContext,
};

use p3_field::PrimeField64;
impl PermutationAir {
    /// Return raw graph values using exactly the AIR's immutable permutation.
    pub(crate) fn evaluate_gpu_operations(
        &self,
        ctx: &OperationContext<'_>,
        input: &PermutationInput,
    ) -> Result<PermutationInput, String> {
        let sources: [u64; D] = core::array::from_fn(|i| self.source_index(i) as u64);
        match (self.kind, input) {
            (PermutationKind::AutomorphismQ, PermutationInput::Canonical(values)) => {
                let factors: [u64; D] = core::array::from_fn(|i| self.factor(i).as_canonical_u64());
                let spec = ArithmeticOperationSpec::automorphism(&sources, &factors)?;
                ctx.admit_arithmetic_operation(&spec)?;
                let output = ctx.arithmetic_output(&spec, values)?;
                Ok(PermutationInput::Canonical(
                    output
                        .try_into()
                        .map_err(|_| "raw automorphism result shape")?,
                ))
            }
            (PermutationKind::InverseChallenge, PermutationInput::Signed(values)) => {
                let negative: [bool; D] = core::array::from_fn(|i| self.factor(i) == Val::NEG_ONE);
                let spec = ArithmeticOperationSpec::inverse_challenge(&sources, &negative)?;
                ctx.admit_arithmetic_operation(&spec)?;
                let raw = values.map(|v| v as u64);
                let output: [u64; D] = ctx
                    .arithmetic_output(&spec, &raw)?
                    .try_into()
                    .map_err(|_| "raw signed permutation result shape")?;
                Ok(PermutationInput::Signed(output.map(|v| v as i64)))
            }
            _ => Err("raw permutation input kind".into()),
        }
    }

    pub fn generate_gpu(
        &self,
        ctx: &TraceContext<'_>,
        input: &PermutationInput,
    ) -> Result<GeneratedTrace, String> {
        let kind = if self.kind == PermutationKind::AutomorphismQ {
            1
        } else {
            2
        };
        let sources: [u64; D] = core::array::from_fn(|i| self.source_index(i) as u64);
        let factors: [u64; D] = core::array::from_fn(|i| self.factor(i).as_canonical_u64());
        let spec = ArithmeticSpec::permutation(kind, &sources, &factors)?;
        ctx.admit_arithmetic_raw(&spec)?;
        let raw: Vec<u64> = match (self.kind, input) {
            (PermutationKind::AutomorphismQ, PermutationInput::Canonical(v)) => v.to_vec(),
            (PermutationKind::InverseChallenge, PermutationInput::Signed(v)) => {
                v.iter().map(|&v| v as u64).collect()
            }
            _ => return Err("permutation input kind".into()),
        };
        ctx.arithmetic_trace(&spec, &raw)
    }
}
impl PeriodicSource for PermutationAir {
    fn column_count(&self) -> usize {
        PERIODIC_COLUMNS
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC_COLUMNS).then_some(HEIGHT)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("permutation periodic shape".into());
        }
        for (row, v) in output.iter_mut().enumerate() {
            *v = if index < 64 {
                Val::from_bool(row == index)
            } else if index < 128 {
                Val::from_bool(row == index)
            } else if index == HASH_INPUT {
                Val::from_bool(row < 64)
            } else if index == HASH_OUTPUT {
                Val::from_bool((64..128).contains(&row))
            } else if (64..128).contains(&row) {
                self.factor(4 * (row - 64) + index - FACTOR)
            } else {
                Val::ZERO
            };
        }
        Ok(())
    }
}

impl RegisteredPermutationAir {
    /// Prove from raw inputs entirely on the admitted OpenCL backend, then
    /// independently verify with the unchanged native CPU verifier.
    pub fn prove_gpu(
        &self,
        input: &PermutationInput,
        host_bytes: usize,
        request: lattica_prover_p3::proving::Request,
    ) -> Result<(PermutationProof, lattica_prover_p3::proving::Report), crate::crypto_join::Error>
    {
        let backend = |message: String| {
            crate::crypto_join::Error::Compile(
                lattica_prover_p3::block_v2::machine::verifier::CompileError::Backend(message),
            )
        };
        let proved = lattica_prover_p3::block_v2::native_gpu::prove(
            "matrict_permutation_air_gpu",
            self.air(),
            self.air(),
            HEIGHT,
            host_bytes,
            request,
            |ctx| self.air().generate_gpu(ctx, input),
        )
        .map_err(backend)?;
        let artifact = PermutationProof {
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
