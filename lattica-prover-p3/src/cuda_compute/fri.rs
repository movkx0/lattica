//! Native FRI arithmetic on explicitly rescaled subgroup vectors. No host
//! arithmetic or implicit layer readback; only final proof egress is exposed.
use super::{Argument, Buffer, FieldSpan, Kernel, Matrix, Result, Runtime, Transforms};
use crate::{
    gpu_fri as shape,
    gpu_matrix::{roots, Extension, MatrixSpec, RowOrder},
};
use std::sync::Arc;

pub(super) const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("fri.cu"));
mod commitment;
pub(crate) use commitment::{FriLayer, FriLayerOpenings};
#[cfg(feature = "block-v2")]
mod protocol;
#[cfg(feature = "block-v2")]
pub(crate) use protocol::{FriField, FriParameters, NativeFriProof};

pub(crate) struct Fri {
    runtime: Runtime,
    transforms: Transforms,
    copy: Kernel,
    gather: Kernel,
    folds: [[Kernel; 4]; 2],
    mixes: [Kernel; 2],
}

/// The same resident values now describe g(X)=f(shift*X) on the unit subgroup.
/// This explicit view preserves Plonky3's FRI beta and final-coefficient convention.
pub(crate) struct FriVector {
    matrix: Matrix,
}

pub(crate) struct FriRound<'a> {
    engine: &'a Fri,
    beta: Buffer,
    extension: Extension,
    log_arity: usize,
}

/// Coefficients have a different type from evaluation vectors. The proof
/// transcript may consume them on the device before explicit final egress.
pub(crate) struct FinalPolynomial {
    coefficients: Buffer,
    extension: Extension,
    len: usize,
}

impl FinalPolynomial {
    pub(crate) fn span(&self) -> FieldSpan<'_> {
        FieldSpan {
            buffer: &self.coefficients,
            first: 0,
        }
    }
    pub(crate) fn words(&self) -> usize {
        self.len * self.extension.degree()
    }
    pub(crate) fn read(&self, host_bytes: usize) -> Result<Vec<u64>> {
        if self.words() * 8 > host_bytes {
            return Err("CUDA final coefficients exceed host allowance".into());
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(self.words())
            .map_err(super::error)?;
        result.resize(self.words(), 0);
        self.coefficients.read(0, &mut result)?;
        Ok(result)
    }
}

impl FriVector {
    pub(crate) fn log_rows(&self) -> u32 {
        self.matrix.spec.log_rows
    }
    pub(crate) fn extension(&self) -> Extension {
        self.matrix.spec.extension
    }
}

impl Fri {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        let folds = |degree| -> Result<[Kernel; 4]> {
            Ok([
                module.kernel_for_stage(
                    &format!("fri_fold_{degree}_1"),
                    crate::proving::Stage::FriFold,
                )?,
                module.kernel_for_stage(
                    &format!("fri_fold_{degree}_2"),
                    crate::proving::Stage::FriFold,
                )?,
                module.kernel_for_stage(
                    &format!("fri_fold_{degree}_3"),
                    crate::proving::Stage::FriFold,
                )?,
                module.kernel_for_stage(
                    &format!("fri_fold_{degree}_4"),
                    crate::proving::Stage::FriFold,
                )?,
            ])
        };
        let result = Self {
            runtime: runtime.clone(),
            transforms: Transforms::new(runtime)?,
            copy: module.kernel_for_stage("fri_copy", crate::proving::Stage::Scalar)?,
            gather: module.kernel_for_stage("fri_gather", crate::proving::Stage::FriQuery)?,
            folds: [folds(2)?, folds(3)?],
            mixes: [
                module.kernel_for_stage("fri_mix_2", crate::proving::Stage::FriFold)?,
                module.kernel_for_stage("fri_mix_3", crate::proving::Stage::FriFold)?,
            ],
        };
        for kernel in result
            .folds
            .iter()
            .flatten()
            .chain(result.mixes.iter())
            .chain([&result.copy, &result.gather])
        {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA FRI kernel exceeds private memory allowance".into());
            }
        }
        Ok(result)
    }

    fn owner(&self, matrix: &Matrix) -> Result<()> {
        let s = matrix.spec;
        if !Arc::ptr_eq(&self.runtime.state, matrix.buffer.owner())
            || MatrixSpec::new(s.log_rows, s.columns, s.extension, s.order, s.shift)? != s
            || matrix.buffer.len() != s.words()
        {
            return Err("CUDA FRI matrix owner or storage mismatch".into());
        }
        drop(self.runtime.state.enter()?);
        Ok(())
    }

    fn allocations(&self, count: usize) -> Result<()> {
        if self
            .runtime
            .snapshot()
            .allocations
            .checked_add(count)
            .is_none_or(|n| n > self.runtime.state.budget.limits.max_allocations)
        {
            return Err("CUDA FRI exceeds allocation count".into());
        }
        Ok(())
    }

    /// An explicit change of polynomial variable, with no data movement.
    pub(crate) fn rescale(&self, input: &Matrix) -> Result<FriVector> {
        self.owner(input)?;
        let s = input.spec;
        let spec = MatrixSpec::new(s.log_rows, s.columns, s.extension, s.order, 1)?;
        shape::vector(spec)?;
        Ok(FriVector {
            matrix: Matrix {
                spec,
                buffer: input.buffer.clone(),
            },
        })
    }

    pub(crate) fn leaves(&self, input: &FriVector, log_arity: usize) -> Result<Matrix> {
        self.owner(&input.matrix)?;
        let spec = shape::leaves(input.matrix.spec, log_arity)?;
        Ok(Matrix {
            spec,
            buffer: input.matrix.buffer.clone(),
        })
    }

    pub(crate) fn round(
        &self,
        extension: Extension,
        log_arity: usize,
        beta: FieldSpan<'_>,
    ) -> Result<FriRound<'_>> {
        if !matches!(extension, Extension::Quadratic | Extension::Cubic)
            || !(1..=4).contains(&log_arity)
            || !Arc::ptr_eq(&self.runtime.state, beta.buffer.owner())
            || beta
                .first
                .checked_add(extension.degree())
                .is_none_or(|end| end > beta.buffer.len())
        {
            return Err("CUDA FRI round challenge or arity mismatch".into());
        }
        drop(self.runtime.state.enter()?);
        self.allocations(1)?;
        let owned = self.runtime.allocate(extension.degree())?;
        self.copy_span(&self.copy, beta, &owned, extension.degree())?;
        Ok(FriRound {
            engine: self,
            beta: owned,
            extension,
            log_arity,
        })
    }

    fn copy_span(
        &self,
        kernel: &Kernel,
        source: FieldSpan<'_>,
        destination: &Buffer,
        words: usize,
    ) -> Result<()> {
        if words == 0
            || words > u32::MAX as usize
            || words > destination.len()
            || source
                .first
                .checked_add(words)
                .is_none_or(|end| end > source.buffer.len())
        {
            return Err("CUDA FRI copy exceeds storage".into());
        }
        // Each lane owns one destination word, with the complete source span
        // checked above. Kernel launch also checks runtime ownership.
        unsafe {
            kernel.launch(
                super::transform::linear_launch(words)?,
                &[
                    Argument::Buffer(source.buffer),
                    Argument::U64(source.first as u64),
                    Argument::Buffer(destination),
                    Argument::U32(words as u32),
                ],
            )?
        }
        .finish()
        .map(|_| ())
    }

    /// The host allowance includes queried values and temporary index staging.
    pub(crate) fn gather(
        &self,
        input: &Matrix,
        indices: &[usize],
        host_bytes: usize,
    ) -> Result<Vec<u64>> {
        self.owner(input)?;
        let plan = shape::GatherShape::new(input.spec, indices.len(), host_bytes)?;
        let limits = self.runtime.state.budget.limits;
        let storage = plan.plan(
            self.runtime.snapshot().live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        if indices.iter().any(|&i| i >= input.spec.rows())
            || storage
                .host_output_bytes
                .checked_add(storage.host_temporary_bytes)
                .is_none_or(|n| n > host_bytes)
        {
            return Err("CUDA FRI query indices or aggregate host storage exceed allowance".into());
        }
        self.allocations(2)?;
        let mut values = Vec::new();
        values.try_reserve_exact(plan.words).map_err(super::error)?;
        values.resize(plan.words, 0);
        let queries = self.runtime.allocate(indices.len())?;
        let output = self.runtime.allocate(plan.words)?;
        queries.write(0, &indices.iter().map(|&i| i as u64).collect::<Vec<_>>())?;
        // Every index is checked against the complete input matrix; each lane
        // owns one query/column result, preserving order and duplicates.
        unsafe {
            self.gather.launch(
                super::transform::linear_launch(plan.words)?,
                &[
                    Argument::Buffer(&input.buffer),
                    Argument::Buffer(&queries),
                    Argument::Buffer(&output),
                    Argument::U32(plan.width as u32),
                    Argument::U32(indices.len() as u32),
                ],
            )?
        }
        .finish()?;
        output.read(0, &mut values)?;
        Ok(values)
    }

    pub(crate) fn final_polynomial(
        &self,
        input: &FriVector,
        log_blowup: usize,
        log_final_len: usize,
        host_bytes: usize,
    ) -> Result<FinalPolynomial> {
        self.owner(&input.matrix)?;
        let shape =
            shape::FinalShape::new(input.matrix.spec, log_blowup, log_final_len, host_bytes)?;
        let limits = self.runtime.state.budget.limits;
        shape.plan(
            self.runtime.snapshot().live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        self.allocations(if log_final_len == 0 { 1 } else { 3 })?;
        let coefficients = self.runtime.allocate(shape.output.words())?;
        if log_final_len == 0 {
            self.copy_span(
                &self
                    .copy
                    .clone()
                    .with_stage(crate::proving::Stage::FinalPolynomial),
                FieldSpan {
                    buffer: &input.matrix.buffer,
                    first: 0,
                },
                &coefficients,
                shape.output.words(),
            )?;
        } else {
            let transforms = self.transforms.for_final_polynomial();
            let roots = transforms.roots(log_final_len as u32, true)?;
            let parameters = transforms.parameters(shape.output, 1)?;
            // The first 2^log_final_len physical rows evaluate the smaller
            // subgroup. Natural-order inverse NTT leaves the source untouched.
            transforms.ntt(
                &input.matrix.buffer,
                &coefficients,
                &roots,
                log_final_len as u32,
                input.extension().degree(),
                RowOrder::BitReversed,
                RowOrder::Natural,
            )?;
            transforms.scale(
                &coefficients,
                &coefficients,
                &parameters,
                input.extension().degree(),
                shape.output.rows(),
                shape.output.rows(),
            )?;
        }
        Ok(FinalPolynomial {
            coefficients,
            extension: input.extension(),
            len: shape.output.rows(),
        })
    }
}

impl FriRound<'_> {
    fn check(&self, input: &FriVector) -> Result<()> {
        self.engine.owner(&input.matrix)?;
        shape::vector(input.matrix.spec)?;
        if input.extension() != self.extension {
            return Err("CUDA FRI challenge extension differs from vector".into());
        }
        Ok(())
    }
    fn allocate(&self, spec: MatrixSpec) -> Result<Matrix> {
        let limits = self.engine.runtime.state.budget.limits;
        shape::vector_output(
            spec,
            self.engine.runtime.snapshot().live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        self.engine.allocations(1)?;
        Ok(Matrix {
            spec,
            buffer: self.engine.runtime.allocate(spec.words())?,
        })
    }
    pub(crate) fn fold(&self, input: &FriVector) -> Result<FriVector> {
        self.check(input)?;
        let output = self.allocate(shape::fold_output(input.matrix.spec, self.log_arity)?)?;
        let kernel = &self.engine.folds[self.extension.degree() - 2][self.log_arity - 1];
        // One lane owns one complete arity group; log_arity is compiled into
        // the selected kernel, and the source height is checked above.
        unsafe {
            kernel.launch(
                super::transform::linear_launch(output.spec.rows())?,
                &[
                    Argument::Buffer(&input.matrix.buffer),
                    Argument::Buffer(&self.beta),
                    Argument::Buffer(&output.buffer),
                    Argument::U32(input.log_rows()),
                    Argument::U64(roots::inverse_root(input.log_rows())),
                ],
            )?
        }
        .finish()?;
        Ok(FriVector { matrix: output })
    }
    pub(crate) fn mix(&self, folded: &FriVector, input: &FriVector) -> Result<FriVector> {
        self.check(folded)?;
        self.check(input)?;
        if folded.matrix.spec != input.matrix.spec {
            return Err("CUDA FRI mix shapes differ".into());
        }
        let output = self.allocate(folded.matrix.spec)?;
        // Both complete vectors have identical extents. The owned beta cannot
        // change between the fold and this beta^(2^log_arity) input mixture.
        unsafe {
            self.engine.mixes[self.extension.degree() - 2].launch(
                super::transform::linear_launch(output.spec.rows())?,
                &[
                    Argument::Buffer(&folded.matrix.buffer),
                    Argument::Buffer(&input.matrix.buffer),
                    Argument::Buffer(&self.beta),
                    Argument::Buffer(&output.buffer),
                    Argument::U32(output.spec.rows() as u32),
                    Argument::U32(self.log_arity as u32),
                ],
            )?
        }
        .finish()?;
        Ok(FriVector { matrix: output })
    }
}

#[cfg(test)]
mod benchmark;
#[cfg(test)]
mod tests;
