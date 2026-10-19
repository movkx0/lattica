//! The separate STARK randomization polynomial is already uniformly random.
//! Commit its original rows and masking columns without trace row interleaving.
use super::*;

#[cfg(test)]
mod tests;

impl Hiding {
    pub(crate) fn prepare_randomization(
        &self,
        log_rows: u32,
        shift: u64,
        extension: Extension,
        random: &DeviceRandom,
        output_log: u32,
        tile_columns: usize,
    ) -> Result<RandomizationInput> {
        random.check_runtime(&self.runtime)?;
        if !matches!(extension, Extension::Quadratic | Extension::Cubic)
            || !(1..=25).contains(&log_rows)
            || output_log > 25
        {
            return Err("unsupported CUDA randomization polynomial geometry".into());
        }
        let width = extension.degree() + crate::config::NUM_RANDOM_CODEWORDS;
        let spec = MatrixSpec::new(log_rows, width, Extension::Base, RowOrder::Natural, shift)?;
        let plan = TilePlan::new(log_rows, width, output_log, tile_columns, false)?;
        plan.admit(&self.runtime, &[spec.words()])?;
        random.preflight_fields(&[spec.words()], &[])?;
        random.with_attempt(|| {
            Ok(RandomizationInput {
                samples: random.sample_matrix(spec)?,
                family: random.clone(),
                plan,
            })
        })
    }

    pub(crate) fn with_randomization_lde<T>(
        &self,
        input: &RandomizationInput,
        first: usize,
        columns: usize,
        order: RowOrder,
        consume: impl FnOnce(&Matrix) -> Result<T>,
    ) -> Result<T> {
        self.transforms.check_owner(&input.samples)?;
        input.family.check_runtime(&self.runtime)?;
        let plan = input.plan.tile(first, columns)?;
        plan.admit(&self.runtime, &[])?;
        input
            .family
            .with_attempt(|| consume(&self.randomization_lde(input, first, plan, order)?))
    }

    fn randomization_lde(
        &self,
        input: &RandomizationInput,
        first: usize,
        plan: TilePlan,
        order: RowOrder,
    ) -> Result<Matrix> {
        let output = plan.output(plan.columns, order)?;
        let a = self.runtime.allocate(output.words())?;
        let b = self.runtime.allocate(output.words())?;
        let inverse = self.transforms.roots(plan.input_log, true)?;
        let forward = self.transforms.roots(plan.output_log, false)?;
        let parameters = self.transforms.parameters(input.samples.spec, GENERATOR)?;
        // Preparation binds source dimensions; tile admission bounds the
        // selected columns and both transform buffers before this launch.
        unsafe {
            self.randomization_columns.launch(
                super::super::transform::linear_launch(input.samples.spec.rows() * plan.columns)?,
                &[
                    Argument::Buffer(&input.samples.buffer),
                    Argument::Buffer(&a),
                    Argument::U32(input.samples.spec.rows() as u32),
                    Argument::U32(plan.width as u32),
                    Argument::U32(first as u32),
                    Argument::U32(plan.columns as u32),
                ],
            )?
        }
        .finish()?;
        let in_b = self.transforms.ntt(
            &a,
            &b,
            &inverse,
            plan.input_log,
            plan.columns,
            RowOrder::Natural,
            RowOrder::Natural,
        )?;
        let (coefficients, scratch) = if in_b { (&b, &a) } else { (&a, &b) };
        self.transforms.scale(
            coefficients,
            scratch,
            &parameters,
            plan.columns,
            input.samples.spec.rows(),
            output.rows(),
        )?;
        let (buffer, scratch) = if in_b { (a, b) } else { (b, a) };
        self.evaluate(ScaledCoefficients { buffer, output }, scratch, &forward)
    }
}
