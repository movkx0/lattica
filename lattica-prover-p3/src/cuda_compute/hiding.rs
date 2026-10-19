//! Reference-compatible polynomial hiding with resident samples and bounded
//! column tiles. Preparation admits both sampling and subsequent LDE peaks.
//! This is a PCS building block, not selection of a complete CUDA prover.
use super::{
    Argument, Buffer, DeviceRandom, Kernel, Matrix, RandomWords, Result, Runtime, Transforms,
};
use crate::{
    gpu_hiding::{QuotientCommitShape, TraceCommitShape},
    gpu_matrix::{roots, Extension, MatrixSpec, RowOrder},
};
mod batch;
mod plan;
pub(crate) use batch::{
    HiddenCommitment, HiddenOpenings, HidingInput, OpeningShape, RetainedOpening,
};
use plan::TilePlan;
#[cfg(test)]
mod tests;

pub(super) const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("hiding.cu"));
// Goldilocks' multiplicative generator, pinned by the production PCS.
const GENERATOR: u64 = 7;

pub(crate) struct Hiding {
    runtime: Runtime,
    transforms: Transforms,
    trace_columns: Kernel,
    quotient_parameters: Kernel,
    quotient_columns: Kernel,
    quotient_coefficients: Kernel,
    retain_prefix: Kernel,
}

pub(crate) struct TraceHidingInput {
    trace: Matrix,
    random: Option<RandomWords>,
    family: Option<DeviceRandom>,
    shape: TraceCommitShape,
    plan: TilePlan,
}
pub(crate) struct QuotientHidingInput {
    quotient: Matrix,
    random: RandomWords,
    masks: RandomWords,
    parameters: Buffer,
    family: DeviceRandom,
    shape: QuotientCommitShape,
    plan: TilePlan,
}

// Coefficients already scaled for the generator coset, padded to output size.
// Deliberately not a Matrix: feeding these to an evaluation-domain LDE would
// interpolate twice. Ownership is consumed by the final forward transform.
struct ScaledCoefficients {
    buffer: Buffer,
    output: MatrixSpec,
}

impl Hiding {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        let result = Self {
            runtime: runtime.clone(),
            transforms: Transforms::new(runtime)?,
            trace_columns: module.kernel("hiding_trace_columns")?,
            quotient_parameters: module.kernel("hiding_quotient_parameters")?,
            quotient_columns: module.kernel("hiding_quotient_columns")?,
            quotient_coefficients: module.kernel("hiding_quotient_coefficients")?,
            retain_prefix: module.kernel("hiding_retain_prefix")?,
        };
        for kernel in [
            &result.trace_columns,
            &result.quotient_parameters,
            &result.quotient_columns,
            &result.quotient_coefficients,
            &result.retain_prefix,
        ] {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA hiding kernel exceeds private memory allowance".into());
            }
        }
        Ok(result)
    }

    pub(crate) fn prepare_trace(
        &self,
        trace: &Matrix,
        random: &DeviceRandom,
        output_log: u32,
        tile_columns: usize,
    ) -> Result<TraceHidingInput> {
        self.transforms.check_owner(trace)?;
        random.check_runtime(&self.runtime)?;
        let shape =
            TraceCommitShape::new(trace.spec, crate::block_v2::profile::NUM_RANDOM_CODEWORDS)?;
        let plan = TilePlan::new(
            shape.height.ilog2(),
            shape.width,
            output_log,
            tile_columns,
            false,
        )?;
        plan.admit(&self.runtime, &[shape.random_words])?;
        random.preflight_fields(&[shape.random_words], &[])?;
        random.with_attempt(|| {
            Ok(TraceHidingInput {
                trace: trace.clone(),
                random: Some(random.sample_fields(shape.random_words)?),
                family: Some(random.clone()),
                shape,
                plan,
            })
        })
    }

    pub(crate) fn prepare_preprocessing(
        &self,
        trace: &Matrix,
        output_log: u32,
        tile_columns: usize,
    ) -> Result<TraceHidingInput> {
        self.transforms.check_owner(trace)?;
        drop(self.runtime.state.enter()?);
        let shape = TraceCommitShape::preprocessing(trace.spec)?;
        let plan = TilePlan::new(
            shape.height.ilog2(),
            shape.width,
            output_log,
            tile_columns,
            false,
        )?;
        plan.admit(&self.runtime, &[])?;
        Ok(TraceHidingInput {
            trace: trace.clone(),
            random: None,
            family: None,
            shape,
            plan,
        })
    }

    pub(crate) fn prepare_quotient(
        &self,
        quotient: &Matrix,
        chunks: usize,
        random: &DeviceRandom,
        output_log: u32,
        tile_columns: usize,
    ) -> Result<QuotientHidingInput> {
        self.transforms.check_owner(quotient)?;
        random.check_runtime(&self.runtime)?;
        let shape = QuotientCommitShape::new(
            quotient.spec,
            chunks,
            crate::block_v2::profile::NUM_RANDOM_CODEWORDS,
        )?;
        let plan = TilePlan::new(
            shape.height.ilog2(),
            shape.width,
            output_log,
            tile_columns,
            true,
        )?;
        plan.admit(&self.runtime, &shape.allocation_words())?;
        let requests = [shape.random_words, shape.mask_words];
        random.preflight_fields(&requests, &[chunks * 3 * 8])?;
        random.with_attempt(|| {
            let mut samples = random.sample_fields_batch(&requests, &[chunks * 3 * 8])?;
            let masks = samples.pop().unwrap();
            let columns = samples.pop().unwrap();
            let parameters = self.runtime.allocate(chunks * 3)?;
            // The complete uniform partition was checked by the shared shape.
            // Every division/power is evaluated on CUDA; omega is a public root.
            unsafe {
                self.quotient_parameters.launch(
                    super::transform::linear_launch(chunks)?,
                    &[
                        Argument::Buffer(&parameters),
                        Argument::U32(shape.height as u32),
                        Argument::U32(chunks as u32),
                        Argument::U64(quotient.spec.shift),
                        Argument::U64(roots::root(quotient.spec.log_rows)),
                        Argument::U64(GENERATOR),
                    ],
                )?
            }
            .finish()?;
            Ok(QuotientHidingInput {
                quotient: quotient.clone(),
                random: columns,
                masks,
                parameters,
                family: random.clone(),
                shape,
                plan,
            })
        })
    }

    /// The consumer remains inside the RNG family's failure guard, allowing
    /// commitments to consume the LDE without private host transfers. Invalid
    /// public geometry or insufficient admission fails before private work.
    pub(crate) fn with_trace_lde<T>(
        &self,
        input: &TraceHidingInput,
        first: usize,
        columns: usize,
        order: RowOrder,
        consume: impl FnOnce(&Matrix) -> Result<T>,
    ) -> Result<T> {
        self.transforms.check_owner(&input.trace)?;
        if let Some(family) = &input.family {
            family.check_runtime(&self.runtime)?;
        }
        let plan = input.plan.tile(first, columns)?;
        plan.admit(&self.runtime, &[])?;
        let run = || consume(&self.trace_lde(input, first, plan, order)?);
        match &input.family {
            Some(family) => family.with_attempt(run),
            None => run(),
        }
    }

    pub(crate) fn with_quotient_lde<T>(
        &self,
        input: &QuotientHidingInput,
        chunk: usize,
        first: usize,
        columns: usize,
        order: RowOrder,
        consume: impl FnOnce(&Matrix) -> Result<T>,
    ) -> Result<T> {
        self.transforms.check_owner(&input.quotient)?;
        input.family.check_runtime(&self.runtime)?;
        if chunk >= input.shape.chunks {
            return Err("CUDA hiding chunk outside partition".into());
        }
        let plan = input.plan.tile(first, columns)?;
        plan.admit(&self.runtime, &[])?;
        input
            .family
            .with_attempt(|| consume(&self.quotient_lde(input, chunk, first, plan, order)?))
    }

    fn evaluate(
        &self,
        coefficients: ScaledCoefficients,
        scratch: Buffer,
        roots: &Buffer,
    ) -> Result<Matrix> {
        let output = coefficients.output;
        let in_scratch = self.transforms.ntt(
            &coefficients.buffer,
            &scratch,
            roots,
            output.log_rows,
            output.columns,
            RowOrder::Natural,
            output.order,
        )?;
        Ok(Matrix {
            spec: output,
            buffer: if in_scratch {
                scratch
            } else {
                coefficients.buffer
            },
        })
    }

    fn trace_lde(
        &self,
        input: &TraceHidingInput,
        first: usize,
        plan: TilePlan,
        order: RowOrder,
    ) -> Result<Matrix> {
        let output = plan.output(plan.columns, order)?;
        let a = self.runtime.allocate(output.words())?;
        let b = self.runtime.allocate(output.words())?;
        let inverse = self.transforms.roots(plan.input_log, true)?;
        let forward = self.transforms.roots(plan.output_log, false)?;
        let input_spec = MatrixSpec::new(
            plan.input_log,
            plan.columns,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let parameters = self.transforms.parameters(input_spec, GENERATOR)?;
        let random = input
            .random
            .as_ref()
            .map(RandomWords::buffer)
            .unwrap_or(&input.trace.buffer);
        // When no random columns are present the kernel never dereferences the
        // random argument. All other indices are bounded by the shared shape.
        unsafe {
            self.trace_columns.launch(
                super::transform::linear_launch(input.shape.height * plan.columns)?,
                &[
                    Argument::Buffer(&input.trace.buffer),
                    Argument::Buffer(random),
                    Argument::Buffer(&a),
                    Argument::U32(input.shape.height as u32),
                    Argument::U32(input.shape.trace_width as u32),
                    Argument::U32(input.shape.random_columns as u32),
                    Argument::U32(first as u32),
                    Argument::U32(plan.columns as u32),
                ],
            )?
        }
        .finish()?;
        self.transforms.ntt(
            &a,
            &b,
            &inverse,
            plan.input_log,
            plan.columns,
            RowOrder::Natural,
            RowOrder::Natural,
        )?;
        self.transforms.scale(
            &b,
            &a,
            &parameters,
            plan.columns,
            input.shape.height,
            output.rows(),
        )?;
        self.evaluate(ScaledCoefficients { buffer: a, output }, b, &forward)
    }

    fn quotient_lde(
        &self,
        input: &QuotientHidingInput,
        chunk: usize,
        first: usize,
        plan: TilePlan,
        order: RowOrder,
    ) -> Result<Matrix> {
        let output = plan.output(plan.columns, order)?;
        let a = self.runtime.allocate(output.words())?;
        let b = self.runtime.allocate(output.words())?;
        let inverse = self.transforms.roots(plan.input_log, true)?;
        let forward = self.transforms.roots(plan.output_log, false)?;
        let shape = input.shape;
        unsafe {
            self.quotient_columns.launch(
                super::transform::linear_launch(shape.height * plan.columns)?,
                &[
                    Argument::Buffer(&input.quotient.buffer),
                    Argument::Buffer(input.random.buffer()),
                    Argument::Buffer(&a),
                    Argument::U32(shape.height as u32),
                    Argument::U32(shape.chunks as u32),
                    Argument::U32(chunk as u32),
                    Argument::U32(shape.degree as u32),
                    Argument::U32(shape.random_columns as u32),
                    Argument::U32(first as u32),
                    Argument::U32(plan.columns as u32),
                ],
            )?
        }
        .finish()?;
        self.transforms.ntt(
            &a,
            &b,
            &inverse,
            plan.input_log,
            plan.columns,
            RowOrder::Natural,
            RowOrder::Natural,
        )?;
        // Distinct buffers: the doubled prefix is written after inverse NTT;
        // the remaining zero padding in a is untouched by either kernel.
        unsafe {
            self.quotient_coefficients.launch(
                super::transform::linear_launch(shape.height * plan.columns)?,
                &[
                    Argument::Buffer(&b),
                    Argument::Buffer(input.masks.buffer()),
                    Argument::Buffer(&input.parameters),
                    Argument::Buffer(&a),
                    Argument::U32(shape.height as u32),
                    Argument::U32(shape.chunks as u32),
                    Argument::U32(chunk as u32),
                    Argument::U32(shape.width as u32),
                    Argument::U32(first as u32),
                    Argument::U32(plan.columns as u32),
                    Argument::U64(GENERATOR),
                ],
            )?
        }
        .finish()?;
        self.evaluate(ScaledCoefficients { buffer: a, output }, b, &forward)
    }
}
