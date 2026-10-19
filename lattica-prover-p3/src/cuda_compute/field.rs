//! Bounded elementwise base, quadratic and cubic field arithmetic on CUDA.
use super::{Argument, Buffer, Completion, Kernel, Launch, Result, Runtime};
use crate::gpu_matrix::Extension;

pub(super) const SOURCE: &str = concat!(include_str!("field.cuh"), include_str!("field.cu"));

#[derive(Clone, Copy, Debug)]
pub(crate) enum FieldOperation {
    Canonicalize,
    Negate,
    /// Zero maps to zero, including noncanonical zero. Callers that require a
    /// nonzero denominator must enforce that condition as part of their stage.
    InverseOrZero,
    Power(u64),
    Add,
    Subtract,
    Multiply,
}

impl FieldOperation {
    fn code(self) -> (u32, u64, bool) {
        match self {
            Self::Canonicalize => (0, 0, false),
            Self::Negate => (1, 0, false),
            Self::InverseOrZero => (2, 0, false),
            Self::Power(exponent) => (3, exponent, false),
            Self::Add => (4, 0, true),
            Self::Subtract => (5, 0, true),
            Self::Multiply => (6, 0, true),
        }
    }
}

/// The first word of a span; its length is count times the extension degree.
#[derive(Clone, Copy)]
pub(crate) struct FieldSpan<'a> {
    pub buffer: &'a Buffer,
    pub first: usize,
}

fn extent(first: usize, count: usize, degree: usize, words: usize) -> Result<usize> {
    if count == 0 || !(1..=3).contains(&degree) {
        return Err("invalid CUDA field operation geometry".into());
    }
    count
        .checked_mul(degree)
        .and_then(|n| first.checked_add(n))
        .filter(|end| *end <= words)
        .ok_or_else(|| "CUDA field span exceeds buffer bounds".into())
}

fn partial_overlap(a: usize, b: usize, words: usize) -> bool {
    a != b && a.abs_diff(b) < words
}

pub(crate) struct FieldProgram {
    kernel: Kernel,
}

impl FieldProgram {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        Ok(Self {
            kernel: runtime
                .compile(SOURCE)?
                .kernel_for_stage("field_apply", crate::proving::Stage::Scalar)?,
        })
    }

    /// Enqueue an arithmetic operation without a host readback. Exact in-place
    /// spans are supported; partially overlapping spans are rejected.
    pub(crate) fn apply(
        &self,
        operation: FieldOperation,
        extension: Extension,
        count: usize,
        input: FieldSpan<'_>,
        rhs: Option<FieldSpan<'_>>,
        output: FieldSpan<'_>,
    ) -> Result<Completion> {
        let (code, exponent, binary) = operation.code();
        if binary != rhs.is_some() {
            return Err("CUDA field operation has the wrong number of operands".into());
        }
        let rhs = rhs.unwrap_or(input);
        let degree = extension.degree();
        let end = extent(output.first, count, degree, output.buffer.len())?;
        let words = end - output.first;
        for operand in [input, rhs] {
            extent(operand.first, count, degree, operand.buffer.len())?;
            if output.buffer.pointer() == operand.buffer.pointer()
                && partial_overlap(output.first, operand.first, words)
            {
                return Err("partially overlapping CUDA field spans".into());
            }
        }
        let blocks = count
            .div_ceil(128)
            .try_into()
            .map_err(|_| "CUDA field launch grid overflow")?;
        // Every lane loads its own complete element before writing. Checked
        // spans contain all count*degree words and only exact aliases survive.
        // Kernel::launch independently verifies runtime ownership and geometry.
        unsafe {
            self.kernel.launch(
                Launch {
                    blocks,
                    threads: 128,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(input.buffer),
                    Argument::Buffer(rhs.buffer),
                    Argument::Buffer(output.buffer),
                    Argument::U64(input.first as u64),
                    Argument::U64(rhs.first as u64),
                    Argument::U64(output.first as u64),
                    Argument::U64(count as u64),
                    Argument::U32(degree as u32),
                    Argument::U32(code),
                    Argument::U64(exponent),
                ],
            )
        }
    }
}

#[cfg(test)]
mod tests;
