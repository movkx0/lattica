use super::*;
use crate::cuda_compute::Transforms;

fn admit(words: &[usize], state: Snapshot, limits: Limits) -> Result<usize> {
    if state
        .allocations
        .checked_add(words.len())
        .is_none_or(|n| n > limits.max_allocations)
    {
        return Err("CUDA opening reduction exceeds allocation count".into());
    }
    let mut peak = state.live_bytes;
    for &words in words {
        let bytes = words
            .checked_mul(8)
            .ok_or("CUDA opening reduction allocation overflow")?;
        peak = peak
            .checked_add(bytes)
            .ok_or("CUDA opening reduction peak overflow")?;
        if bytes == 0 || bytes > limits.max_allocation_bytes || peak > limits.managed_bytes {
            return Err("CUDA opening reduction exceeds device storage".into());
        }
    }
    Ok(peak)
}

struct ReductionPlan {
    rows: usize,
    peak: usize,
}

impl ReductionPlan {
    fn new(
        prefix: MatrixSpec,
        output: MatrixSpec,
        count: usize,
        state: Snapshot,
        limits: Limits,
    ) -> Result<Self> {
        if prefix.extension != Extension::Base
            || prefix.order != RowOrder::BitReversed
            || prefix.log_rows > output.log_rows
            || output.log_rows > MAX_LOG
            || prefix.shift != output.shift
            || output.order != RowOrder::BitReversed
            || output.columns != 1
            || !matches!(output.extension, Extension::Quadratic | Extension::Cubic)
            || !(1..=MAX_WIDTH).contains(&prefix.columns)
            || !(1..=MAX_POINTS).contains(&count)
        {
            return Err("CUDA reduction prefix, points or output domain mismatch".into());
        }
        let degree = output.extension.degree();
        let low = MatrixSpec::new(
            prefix.log_rows,
            1,
            output.extension,
            RowOrder::Natural,
            prefix.shift,
        )?;
        let terms = count * degree * 2;
        let compression = admit(
            &[low.words(), prefix.columns * degree, terms],
            state,
            limits,
        )?;
        // Weights are released before the transform. Its two vectors and three
        // immutable parameter/root buffers are all charged before any work.
        let transform_live = admit(&[low.words(), terms], state, limits)?;
        if state
            .allocations
            .checked_add(7)
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA opening transform exceeds allocation count".into());
        }
        let transform =
            super::super::transform::storage_plan(low, output.log_rows, transform_live, limits)?
                .peak_bytes;
        // The low prefix is released before denominator tiles are allocated.
        let mut rows = output.rows().min(65536);
        while rows != 0 {
            let inverse = rows * count * degree;
            if inverse * 8 <= TILE_BYTES {
                if let Ok(reduction) = admit(&[output.words(), terms, inverse, 1], state, limits) {
                    return Ok(Self {
                        rows,
                        peak: compression.max(transform).max(reduction),
                    });
                }
            }
            rows /= 2;
        }
        Err("CUDA opening reduction cannot fit one denominator row".into())
    }
}

/// Every append consumes the previous accumulator. No partially updated vector
/// can escape an error or unwind. Complete vectors remain resident for FRI.
pub(crate) struct OpeningAccumulator<'a> {
    engine: &'a Openings,
    output: Matrix,
    alpha: Buffer,
    next_power: u64,
    matrices: usize,
}

impl Openings {
    pub(crate) fn accumulator(
        &self,
        log_rows: u32,
        shift: u64,
        extension: Extension,
        alpha: FieldSpan<'_>,
        first_power: u64,
    ) -> Result<OpeningAccumulator<'_>> {
        if log_rows > MAX_LOG
            || !matches!(extension, Extension::Quadratic | Extension::Cubic)
            || !Arc::ptr_eq(&self.runtime.state, alpha.buffer.owner())
            || alpha
                .first
                .checked_add(extension.degree())
                .is_none_or(|n| n > alpha.buffer.len())
        {
            return Err("CUDA accumulator challenge, runtime or shape mismatch".into());
        }
        drop(self.runtime.state.enter()?);
        let spec = MatrixSpec::new(log_rows, 1, extension, RowOrder::BitReversed, shift)?;
        admit(
            &[spec.words(), extension.degree()],
            self.runtime.snapshot(),
            self.runtime.state.budget.limits,
        )?;
        let output = Matrix {
            spec,
            buffer: self.runtime.allocate(spec.words())?,
        };
        let owned_alpha = self.runtime.allocate(extension.degree())?;
        owned_alpha.copy_from(0, alpha.buffer, alpha.first, extension.degree())?;
        Ok(OpeningAccumulator {
            engine: self,
            output,
            alpha: owned_alpha,
            next_power: first_power,
            matrices: 0,
        })
    }
}

impl OpeningAccumulator<'_> {
    pub(crate) fn append(
        mut self,
        transforms: &Transforms,
        opening: &DeviceOpening,
    ) -> Result<Self> {
        let runtime = &self.engine.runtime;
        if !Arc::ptr_eq(&runtime.state, opening.prefix.buffer.owner())
            || !Arc::ptr_eq(&runtime.state, &transforms.runtime.state)
            || opening.extension != self.output.spec.extension
            || self.matrices >= 256
        {
            return Err("CUDA reduction runtime, extension or matrix count mismatch".into());
        }
        drop(runtime.state.enter()?);
        let prefix = opening.prefix.spec;
        let output = self.output.spec;
        let next_power = self
            .next_power
            .checked_add((prefix.columns * opening.count) as u64)
            .ok_or("CUDA opening alpha power overflow")?;
        let plan = ReductionPlan::new(
            prefix,
            output,
            opening.count,
            runtime.snapshot(),
            runtime.state.budget.limits,
        )?;
        let degree = output.extension.degree();
        let kernels = if degree == 2 {
            &self.engine.quadratic
        } else {
            &self.engine.cubic
        };
        let low_spec = MatrixSpec::new(
            prefix.log_rows,
            1,
            output.extension,
            RowOrder::Natural,
            prefix.shift,
        )?;
        let low = Matrix {
            spec: low_spec,
            buffer: runtime.allocate(low_spec.words())?,
        };
        let weights = runtime.allocate(prefix.columns * degree)?;
        let terms = runtime.allocate(opening.count * degree * 2)?;
        let linear = super::super::transform::linear_launch;
        // Separate completed passes produce immutable alpha weights and terms;
        // compression then writes disjoint natural-order prefix evaluations.
        unsafe {
            kernels.weights.launch(
                linear(prefix.columns)?,
                &[
                    Argument::Buffer(&self.alpha),
                    Argument::Buffer(&weights),
                    Argument::U32(prefix.columns as u32),
                ],
            )?
        }
        .finish()?;
        unsafe {
            kernels.terms.launch(
                linear(opening.count)?,
                &[
                    Argument::Buffer(&self.alpha),
                    Argument::Buffer(&weights),
                    Argument::Buffer(&opening.values),
                    Argument::Buffer(&terms),
                    Argument::U32(prefix.columns as u32),
                    Argument::U32(opening.count as u32),
                    Argument::U64(self.next_power),
                ],
            )?
        }
        .finish()?;
        unsafe {
            kernels.compress.launch(
                linear(prefix.rows())?,
                &[
                    Argument::Buffer(&opening.prefix.buffer),
                    Argument::Buffer(&weights),
                    Argument::Buffer(&low.buffer),
                    Argument::U32(prefix.columns as u32),
                    Argument::U32(prefix.rows() as u32),
                    Argument::U32(prefix.log_rows),
                ],
            )?
        }
        .finish()?;
        drop(weights);
        let expanded =
            transforms.lde(&low, output.log_rows, output.shift, RowOrder::BitReversed)?;
        drop(low);
        let inverse = runtime.allocate(plan.rows * opening.count * degree)?;
        let status = runtime.allocate(1)?;
        for first in (0..output.rows()).step_by(plan.rows) {
            let rows = plan.rows.min(output.rows() - first);
            unsafe {
                kernels.inverses.launch(
                    linear(rows * opening.count)?,
                    &[
                        Argument::Buffer(&opening.points),
                        Argument::Buffer(&inverse),
                        Argument::Buffer(&status),
                        Argument::U32(opening.count as u32),
                        Argument::U32(first as u32),
                        Argument::U32(rows as u32),
                        Argument::U32(output.log_rows),
                        Argument::U64(output.shift),
                        Argument::U64(roots::root(output.log_rows)),
                    ],
                )?
            }
            .finish()?;
            unsafe {
                kernels.reduce.launch(
                    linear(rows)?,
                    &[
                        Argument::Buffer(&expanded.buffer),
                        Argument::Buffer(&inverse),
                        Argument::Buffer(&terms),
                        Argument::Buffer(&self.output.buffer),
                        Argument::U32(first as u32),
                        Argument::U32(rows as u32),
                        Argument::U32(opening.count as u32),
                    ],
                )?
            }
            .finish()?;
        }
        let mut failed = [0];
        status.read(0, &mut failed)?;
        if failed[0] != 0 {
            return Err("CUDA opening point lies on the expanded coset".into());
        }
        self.next_power = next_power;
        self.matrices += 1;
        Ok(self)
    }

    pub(crate) fn finish(self) -> Result<Matrix> {
        if self.matrices == 0 {
            return Err("CUDA opening accumulator has no matrices".into());
        }
        Ok(self.output)
    }
}

#[cfg(test)]
mod tests;
