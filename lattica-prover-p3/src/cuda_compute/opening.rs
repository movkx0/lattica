//! Native out-of-domain evaluation from retained bit-reversed coset prefixes.
//! Challenges and arithmetic stay on CUDA; only status and claimed values have
//! host interfaces. Prefixes, points and results can feed later FRI reduction.
use super::{
    Argument, Buffer, FieldSpan, Kernel, Launch, Limits, Matrix, Result, Runtime, Snapshot,
};
use crate::gpu_matrix::{roots, Extension, MatrixSpec, RowOrder};
use std::sync::Arc;

pub(super) const SOURCE: &str = concat!(
    include_str!("field.cuh"),
    include_str!("opening.cu"),
    include_str!("opening_reduce.cu")
);
mod reduce;
pub(crate) use reduce::OpeningAccumulator;
const MAX_POINTS: usize = 32;
const MAX_WIDTH: usize = 4096;
const MAX_LOG: u32 = 25;
const TILE_BYTES: usize = 64 << 20;

#[derive(Debug)]
struct EvaluationPlan {
    rows: usize,
    inverse_words: usize,
    partial_words: usize,
    peak: usize,
}

impl EvaluationPlan {
    fn new(
        spec: MatrixSpec,
        extension: Extension,
        count: usize,
        state: Snapshot,
        limits: Limits,
    ) -> Result<Self> {
        if spec.extension != Extension::Base
            || spec.order != RowOrder::BitReversed
            || spec.log_rows > MAX_LOG
            || !(1..=MAX_WIDTH).contains(&spec.columns)
            || !matches!(extension, Extension::Quadratic | Extension::Cubic)
            || !(1..=MAX_POINTS).contains(&count)
            || MatrixSpec::new(
                spec.log_rows,
                spec.columns,
                spec.extension,
                spec.order,
                spec.shift,
            )? != spec
        {
            return Err("unsupported CUDA opening prefix or point geometry".into());
        }
        if state
            .allocations
            .checked_add(6)
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA opening exceeds allocation count".into());
        }
        let degree = extension.degree();
        let fixed = [
            count * degree,
            count * degree * 2,
            count * spec.columns * degree,
            1,
        ];
        let mut rows = spec.rows().min(65536);
        while rows != 0 {
            let inverse_words = rows * count * degree;
            let partial_words = rows.div_ceil(128) * count * spec.columns * degree;
            let mut peak = Some(state.live_bytes);
            for words in fixed.into_iter().chain([inverse_words, partial_words]) {
                peak = peak
                    .and_then(|live| live.checked_add(words * 8))
                    .filter(|&live| {
                        words * 8 <= limits.max_allocation_bytes && live <= limits.managed_bytes
                    });
            }
            if (inverse_words + partial_words) * 8 <= TILE_BYTES {
                if let Some(peak) = peak {
                    return Ok(Self {
                        rows,
                        inverse_words,
                        partial_words,
                        peak,
                    });
                }
            }
            rows /= 2;
        }
        Err("CUDA opening budget cannot fit one row".into())
    }
}

struct Kernels {
    parameters: Kernel,
    inverses: Kernel,
    dot: Kernel,
    accumulate: Kernel,
    scale: Kernel,
    weights: Kernel,
    terms: Kernel,
    compress: Kernel,
    reduce: Kernel,
}

pub(crate) struct Openings {
    runtime: Runtime,
    quadratic: Kernels,
    cubic: Kernels,
}

pub(crate) struct DeviceOpening {
    prefix: Matrix,
    points: Buffer,
    values: Buffer,
    count: usize,
    extension: Extension,
}

impl DeviceOpening {
    pub(crate) fn words(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn observe(&self, transcript: &mut super::Transcript) -> Result<()> {
        for first in (0..self.values.len()).step_by(crate::transcript_limits::BATCH_WORDS) {
            transcript.observe_resident(
                &self.values,
                first,
                (self.values.len() - first).min(crate::transcript_limits::BATCH_WORDS),
            )?;
        }
        Ok(())
    }

    /// Point-major, then column-major flattened extension coefficients.
    pub(crate) fn values(&self, host_bytes: usize) -> Result<Vec<u64>> {
        if self.values.len() * 8 > host_bytes {
            return Err("CUDA claimed values exceed host allowance".into());
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(self.values.len())
            .map_err(super::error)?;
        values.resize(self.values.len(), 0);
        self.values.read(0, &mut values)?;
        Ok(values)
    }
}

impl Openings {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        let kernels = |degree: usize| -> Result<Kernels> {
            let result = Kernels {
                parameters: module.kernel(&format!("opening_parameters_{degree}"))?,
                inverses: module.kernel(&format!("opening_inverses_{degree}"))?,
                dot: module.kernel(&format!("opening_dot_{degree}"))?,
                accumulate: module.kernel(&format!("opening_accumulate_{degree}"))?,
                scale: module.kernel(&format!("opening_scale_{degree}"))?,
                weights: module.kernel(&format!("opening_weights_{degree}"))?,
                terms: module.kernel(&format!("opening_terms_{degree}"))?,
                compress: module.kernel(&format!("opening_compress_{degree}"))?,
                reduce: module.kernel(&format!("opening_reduce_{degree}"))?,
            };
            for kernel in [
                &result.parameters,
                &result.inverses,
                &result.dot,
                &result.accumulate,
                &result.scale,
                &result.weights,
                &result.terms,
                &result.compress,
                &result.reduce,
            ] {
                if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                    return Err("CUDA opening exceeds private memory allowance".into());
                }
            }
            Ok(result)
        };
        Ok(Self {
            runtime: runtime.clone(),
            quadratic: kernels(2)?,
            cubic: kernels(3)?,
        })
    }

    fn plan(
        &self,
        prefix: &Matrix,
        extension: Extension,
        points: FieldSpan<'_>,
        count: usize,
    ) -> Result<EvaluationPlan> {
        self.plan_with_retained(prefix, extension, points, count, 0, 0)
    }

    fn plan_with_retained(
        &self,
        prefix: &Matrix,
        extension: Extension,
        points: FieldSpan<'_>,
        count: usize,
        retained_bytes: usize,
        retained_allocations: usize,
    ) -> Result<EvaluationPlan> {
        if !Arc::ptr_eq(&self.runtime.state, prefix.buffer.owner())
            || !Arc::ptr_eq(&self.runtime.state, points.buffer.owner())
        {
            return Err("CUDA opening inputs belong to another runtime".into());
        }
        drop(self.runtime.state.enter()?);
        let mut state = self.runtime.snapshot();
        state.live_bytes = state
            .live_bytes
            .checked_add(retained_bytes)
            .ok_or("CUDA retained opening bytes overflow")?;
        state.allocations = state
            .allocations
            .checked_add(retained_allocations)
            .ok_or("CUDA retained opening allocation count overflow")?;
        let plan = EvaluationPlan::new(
            prefix.spec,
            extension,
            count,
            state,
            self.runtime.state.budget.limits,
        )?;
        if prefix.buffer.len() != prefix.spec.words()
            || count
                .checked_mul(extension.degree())
                .and_then(|n| points.first.checked_add(n))
                .is_none_or(|end| end > points.buffer.len())
        {
            return Err("CUDA opening input storage differs from declared shape".into());
        }
        Ok(plan)
    }

    pub(super) fn preflight(
        &self,
        prefix: &Matrix,
        extension: Extension,
        points: FieldSpan<'_>,
        count: usize,
    ) -> Result<()> {
        self.plan(prefix, extension, points, count).map(|_| ())
    }

    pub(super) fn preflight_with_retained(
        &self,
        prefix: &Matrix,
        extension: Extension,
        points: FieldSpan<'_>,
        count: usize,
        retained_bytes: usize,
        retained_allocations: usize,
    ) -> Result<()> {
        self.plan_with_retained(
            prefix,
            extension,
            points,
            count,
            retained_bytes,
            retained_allocations,
        )
        .map(|_| ())
    }

    pub(crate) fn evaluate(
        &self,
        prefix: &Matrix,
        extension: Extension,
        points: FieldSpan<'_>,
        count: usize,
    ) -> Result<DeviceOpening> {
        let plan = self.plan(prefix, extension, points, count)?;
        let degree = extension.degree();
        let kernels = if extension == Extension::Quadratic {
            &self.quadratic
        } else {
            &self.cubic
        };
        let owned_points = self.runtime.allocate(count * degree)?;
        let values = self
            .runtime
            .allocate(count * prefix.spec.columns * degree)?;
        let parameters = self.runtime.allocate(count * degree * 2)?;
        let inverse = self.runtime.allocate(plan.inverse_words)?;
        let partial = self.runtime.allocate(plan.partial_words)?;
        let status = self.runtime.allocate(1)?;
        owned_points.copy_from(0, points.buffer, points.first, count * degree)?;
        let linear = super::transform::linear_launch;
        let spec = prefix.spec;
        // All buffers are admitted together. Each kernel completes before its
        // scratch is reused; no incomplete result can escape this method.
        unsafe {
            kernels.parameters.launch(
                linear(count)?,
                &[
                    Argument::Buffer(&owned_points),
                    Argument::Buffer(&parameters),
                    Argument::Buffer(&status),
                    Argument::U32(count as u32),
                    Argument::U32(spec.rows() as u32),
                    Argument::U64(spec.shift),
                ],
            )?
        }
        .finish()?;
        for first in (0..spec.rows()).step_by(plan.rows) {
            let rows = plan.rows.min(spec.rows() - first);
            let blocks = rows.div_ceil(128);
            unsafe {
                kernels.inverses.launch(
                    linear(rows * count)?,
                    &[
                        Argument::Buffer(&owned_points),
                        Argument::Buffer(&inverse),
                        Argument::Buffer(&status),
                        Argument::U32(count as u32),
                        Argument::U32(first as u32),
                        Argument::U32(rows as u32),
                        Argument::U32(spec.log_rows),
                        Argument::U64(spec.shift),
                        Argument::U64(roots::root(spec.log_rows)),
                    ],
                )?
            }
            .finish()?;
            // Exactly 128 threads share one partial sum per point/column.
            unsafe {
                kernels.dot.launch(
                    Launch {
                        blocks: (blocks * count * spec.columns)
                            .try_into()
                            .map_err(|_| "CUDA opening grid overflow")?,
                        threads: 128,
                        shared_bytes: 0,
                    },
                    &[
                        Argument::Buffer(&prefix.buffer),
                        Argument::Buffer(&inverse),
                        Argument::Buffer(&parameters),
                        Argument::Buffer(&partial),
                        Argument::U32(spec.columns as u32),
                        Argument::U32(count as u32),
                        Argument::U32(first as u32),
                        Argument::U32(rows as u32),
                    ],
                )?
            }
            .finish()?;
            unsafe {
                kernels.accumulate.launch(
                    linear(count * spec.columns)?,
                    &[
                        Argument::Buffer(&partial),
                        Argument::Buffer(&values),
                        Argument::U32(spec.columns as u32),
                        Argument::U32(count as u32),
                        Argument::U32(blocks as u32),
                    ],
                )?
            }
            .finish()?;
        }
        unsafe {
            kernels.scale.launch(
                linear(count * spec.columns)?,
                &[
                    Argument::Buffer(&values),
                    Argument::Buffer(&parameters),
                    Argument::U32(spec.columns as u32),
                    Argument::U32(count as u32),
                ],
            )?
        }
        .finish()?;
        let mut failed = [0];
        status.read(0, &mut failed)?;
        if failed[0] != 0 {
            return Err("CUDA opening point is zero, noncanonical or on the prefix coset".into());
        }
        Ok(DeviceOpening {
            prefix: prefix.clone(),
            points: owned_points,
            values,
            count,
            extension,
        })
    }
}

#[cfg(test)]
mod tests;
