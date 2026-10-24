//! GPU-generated native trace with bounded immutable periodic metadata.
use super::*;
use lattica_prover_p3::block_v2::native_gpu::{
    arithmetic::ArithmeticSpec, GeneratedTrace, PeriodicSource, TraceContext,
};

impl LinearMapAir {
    fn gpu_periodic_value(&self, index: usize, row: usize) -> Val {
        let phase = row % self.stride();
        let chunk = row / self.stride();
        if index < self.link() {
            return Val::from_bool(index == phase);
        }
        if index == self.link() {
            return Val::from_bool(phase + 1 < self.stride());
        }
        if index < self.constant(0) {
            let cell = index - self.coefficient(0, 0);
            return field_signed(self.descriptor.coefficients[cell / 4][4 * chunk + cell % 4]);
        }
        if index < self.bound_selector(0) {
            return field_signed(self.descriptor.constant[4 * chunk + index - self.constant(0)]);
        }
        let kind = if phase < self.inputs() {
            Some(self.descriptor.inputs[phase])
        } else if phase == self.inputs() {
            Some(self.descriptor.output)
        } else {
            None
        };
        let bound = match kind {
            Some(PolynomialKind::Signed { bound }) => bound,
            None => 0,
            _ => unreachable!(),
        };
        Val::from_bool(self.descriptor.bounds[index - self.bound_selector(0)] == bound)
    }
    pub fn generate_gpu(
        &self,
        ctx: &TraceContext<'_>,
        inputs: &[LinearMapInput],
    ) -> Result<GeneratedTrace, String> {
        if inputs.len() != self.inputs() {
            return Err("linear-map input count".into());
        }
        let kinds: Vec<[u64; 2]> = self
            .descriptor
            .inputs
            .iter()
            .chain(core::iter::once(&self.descriptor.output))
            .map(|kind| match *kind {
                PolynomialKind::Canonical { modulus } => [modulus, 0],
                PolynomialKind::Signed { bound } => [0, bound as u64],
            })
            .collect();
        let spec = ArithmeticSpec::linear_map(
            &kinds,
            &self.descriptor.coefficients,
            &self.descriptor.constant,
            self.bits(),
            self.descriptor.quotient_bound,
        )?;
        drop(kinds);
        ctx.admit_arithmetic_raw(&spec)?;
        let mut raw = Vec::with_capacity(spec.raw_input_words());
        for (input, kind) in inputs.iter().zip(&self.descriptor.inputs) {
            match (input, kind) {
                (LinearMapInput::Canonical(v), PolynomialKind::Canonical { .. }) => {
                    raw.extend_from_slice(v)
                }
                (LinearMapInput::Signed(v), PolynomialKind::Signed { .. }) => {
                    raw.extend(v.iter().map(|&v| v as u64))
                }
                _ => return Err("linear-map input kind".into()),
            }
        }
        ctx.arithmetic_trace(&spec, &raw)
    }
}
impl PeriodicSource for LinearMapAir {
    fn column_count(&self) -> usize {
        self.periodic_count()
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        if index >= self.periodic_count() {
            return None;
        }
        let mut len = self.height();
        while len > 1
            && (0..len / 2).all(|row| {
                self.gpu_periodic_value(index, row) == self.gpu_periodic_value(index, row + len / 2)
            })
        {
            len /= 2;
        }
        Some(len)
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("linear-map periodic shape".into());
        }
        for (row, v) in output.iter_mut().enumerate() {
            *v = self.gpu_periodic_value(index, row);
        }
        Ok(())
    }
}

impl RegisteredLinearMapAir {
    /// Prove from raw inputs entirely on the admitted OpenCL backend, then
    /// independently verify with the unchanged native CPU verifier.
    pub fn prove_gpu(
        &self,
        inputs: &[LinearMapInput],
        host_bytes: usize,
        request: lattica_prover_p3::proving::Request,
    ) -> Result<(LinearMapProof, lattica_prover_p3::proving::Report), crate::crypto_join::Error>
    {
        let backend = |message: String| {
            crate::crypto_join::Error::Compile(
                lattica_prover_p3::block_v2::machine::verifier::CompileError::Backend(message),
            )
        };
        let proved = lattica_prover_p3::block_v2::native_gpu::prove(
            "matrict_linear_map_air_gpu",
            self.air(),
            self.air(),
            self.air().height(),
            host_bytes,
            request,
            |ctx| self.air().generate_gpu(ctx, inputs),
        )
        .map_err(backend)?;
        let artifact = LinearMapProof {
            public_values: proved.public_values,
            proof: proved.proof,
        };
        self.verify(&artifact)?;
        Ok((artifact, proved.report))
    }
}
