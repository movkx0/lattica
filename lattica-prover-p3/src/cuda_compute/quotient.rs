//! Resident quadratic/cubic AIR evaluation. Public immutable programs can be
//! prepared once; inputs, challenges, parameters and scratch remain attempt-owned.
use super::{Argument, Buffer, Kernel, Launch, Limits, Matrix, Result, Runtime};
use crate::{
    block_v2::quotient_program::{specialize, Program},
    gpu_matrix::{roots, Extension, MatrixSpec, RowOrder},
};
use std::{sync::Arc, time::Instant};

pub(super) const SOURCE: &str = concat!(
    include_str!("field.cuh"), include_str!("quotient_helpers.cu"),
    "\n#define QUOTIENT_DEGREE 2\n#define QUOTIENT_ALPHA quotient_alpha_2\n#define QUOTIENT_EVALUATE quotient_evaluate_2\n",
    include_str!("quotient.cu"),
    "\n#define QUOTIENT_DEGREE 3\n#define QUOTIENT_ALPHA quotient_alpha_3\n#define QUOTIENT_EVALUATE quotient_evaluate_3\n",
    include_str!("quotient.cu")
);
const WORKSPACE_BYTES: usize = 64 << 20;
const MAX_TILE_ROWS: usize = 16 * 1024;
const MAX_PROGRAM_HOST_BYTES: usize = 16 << 20;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Specialization {
    Generic,
    Prefer,
}

/// Reuse is by this immutable handle, not by a partial hash of mutable inputs.
/// The program and code are public; no witness or sampled value is retained.
pub(crate) struct PreparedQuotient {
    program: Arc<Program>,
    code: Buffer,
    specialized: Option<Kernel>,
    pub(crate) preparation_ns: u128,
    pub(crate) source_bytes: usize,
    pub(crate) local_bytes: usize,
    _host_reservation: super::budget::Reservation,
}

#[derive(Clone, Copy)]
pub(crate) struct QuotientInputs<'a> {
    pub main: Option<&'a Matrix>,
    pub preprocessed: Option<&'a Matrix>,
    pub permutation: Option<&'a Matrix>,
}

pub(crate) struct Quotients {
    runtime: Runtime,
    evaluate: [Kernel; 2],
    alpha: [Kernel; 2],
    domain: Kernel,
    gather: Kernel,
    zero: Buffer,
}

#[derive(Debug)]
struct Plan {
    rows: usize,
    output_words: usize,
    weight_words: usize,
    input_words: usize,
    scratch_words: usize,
    peak_bytes: usize,
}

impl Plan {
    fn new(program: &Program, height: usize, live: usize, limits: Limits) -> Result<Self> {
        if !height.is_power_of_two() || height > 1usize << 31 {
            return Err("invalid CUDA quotient height".into());
        }
        let degree = program.extension.degree();
        let output_words = height
            .checked_mul(degree)
            .ok_or("CUDA quotient output overflow")?;
        let weight_words = program
            .constraints
            .checked_mul(degree)
            .ok_or("CUDA quotient weight overflow")?;
        for words in [output_words, weight_words, 1] {
            if words
                .checked_mul(8)
                .is_none_or(|n| n > limits.max_allocation_bytes)
            {
                return Err("CUDA quotient static allocation exceeds limit".into());
            }
        }
        let static_bytes = (weight_words + 1) * 8;
        let available = limits
            .managed_bytes
            .checked_sub(live)
            .and_then(|n| n.checked_sub(output_words * 8))
            .and_then(|n| n.checked_sub(static_bytes))
            .ok_or("CUDA quotient static storage exceeds managed allowance")?;
        let workspace = WORKSPACE_BYTES
            .checked_sub(static_bytes)
            .ok_or("CUDA quotient static workspace limit")?;
        let scratch_per_row = program
            .registers
            .checked_mul(degree)
            .ok_or("CUDA quotient register overflow")?;
        let per_row = program
            .row_words
            .checked_add(scratch_per_row)
            .and_then(|n| n.checked_mul(8))
            .filter(|n| *n > 0)
            .ok_or("CUDA quotient row size overflow")?;
        let capacity = (available.min(workspace) / per_row)
            .min(limits.max_allocation_bytes / per_row)
            .min(height)
            .min(MAX_TILE_ROWS);
        if capacity == 0 {
            return Err("CUDA quotient cannot fit one row".into());
        }
        let rows = 1usize << capacity.ilog2();
        Ok(Self {
            rows,
            output_words,
            weight_words,
            input_words: rows * program.row_words,
            scratch_words: rows * scratch_per_row,
            peak_bytes: live + output_words * 8 + static_bytes + rows * per_row,
        })
    }
}

fn launch(items: usize) -> Result<Launch> {
    if items == 0 {
        return Err("empty CUDA quotient launch".into());
    }
    Ok(Launch {
        blocks: items
            .div_ceil(128)
            .try_into()
            .map_err(|_| "CUDA quotient grid overflow")?,
        threads: 128,
        shared_bytes: 0,
    })
}

impl Quotients {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(SOURCE)?;
        let result = Self {
            runtime: runtime.clone(),
            evaluate: [
                module.kernel("quotient_evaluate_2")?,
                module.kernel("quotient_evaluate_3")?,
            ],
            alpha: [
                module.kernel("quotient_alpha_2")?,
                module.kernel("quotient_alpha_3")?,
            ],
            domain: module.kernel("quotient_domain")?,
            gather: module.kernel("quotient_gather")?,
            zero: runtime.allocate(1)?,
        };
        for kernel in &result.evaluate {
            if !result.admit_private(kernel.local_bytes()?)? {
                return Err("CUDA quotient interpreter exceeds private memory allowance".into());
            }
        }
        Ok(result)
    }

    fn admit_private(&self, bytes: usize) -> Result<bool> {
        let identity = self.runtime.identity();
        let backing = bytes
            .div_ceil(256)
            .checked_mul(256)
            .and_then(|n| n.checked_mul(identity.multiprocessors as usize))
            .and_then(|n| n.checked_mul(identity.max_threads_per_multiprocessor as usize))
            .ok_or("CUDA quotient private memory size overflow")?;
        // This comes from the separately reserved >=4 GiB context allowance.
        Ok(bytes <= 512
            && backing <= 128 << 20
            && identity.multiprocessors > 0
            && identity.max_threads_per_multiprocessor > 0)
    }

    fn check_owner(&self, buffer: &Buffer) -> Result<()> {
        if !Arc::ptr_eq(&self.runtime.state, buffer.owner()) {
            return Err("CUDA quotient input belongs to another runtime".into());
        }
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        program: Arc<Program>,
        mode: Specialization,
    ) -> Result<PreparedQuotient> {
        program.validate_quotient()?;
        let host_bytes = program
            .instructions
            .capacity()
            .checked_mul(8)
            .and_then(|n| {
                n.checked_add(
                    std::mem::size_of::<Program>()
                        + 2 * std::mem::size_of::<usize>()
                        + std::mem::size_of::<PreparedQuotient>(),
                )
            })
            .filter(|bytes| *bytes <= MAX_PROGRAM_HOST_BYTES)
            .ok_or("CUDA quotient public program exceeds host allowance")?;
        let host_reservation = self.runtime.state.budget.public_program(host_bytes)?;
        let started = Instant::now();
        let code = self.runtime.allocate(program.instructions.len())?;
        code.write(0, &program.instructions)?;
        let mut source_bytes = 0;
        let mut local_bytes = self.evaluate[program.extension.degree() - 2].local_bytes()?;
        let specialized = match mode {
            Specialization::Generic => None,
            Specialization::Prefer => {
                match specialize::source(&program, specialize::Backend::Cuda)? {
                    None => None, // Shapes outside the bounded compiler envelope use GPU IR.
                    Some(source) => {
                        source_bytes = source.len();
                        let module = self.runtime.compile(&source)?;
                        let kernel = module.kernel("specialized_quotient")?;
                        let bytes = kernel.local_bytes()?;
                        if self.admit_private(bytes)? {
                            local_bytes = bytes;
                            Some(kernel)
                        } else {
                            None
                        }
                    }
                }
            }
        };
        Ok(PreparedQuotient {
            program,
            code,
            specialized,
            preparation_ns: started.elapsed().as_nanos(),
            source_bytes,
            local_bytes,
            _host_reservation: host_reservation,
        })
    }

    fn input_domain(
        &self,
        program: &Program,
        inputs: QuotientInputs<'_>,
        log_trace: u32,
    ) -> Result<MatrixSpec> {
        let domain = inputs
            .main
            .or(inputs.preprocessed)
            .or(inputs.permutation)
            .ok_or("CUDA quotient has no input matrices")?
            .spec;
        if log_trace > domain.log_rows || domain.log_rows > 31 {
            return Err("CUDA quotient trace/domain mismatch".into());
        }
        for (matrix, width, extension) in [
            (inputs.main, program.layout.main_width, Extension::Base),
            (
                inputs.preprocessed,
                program.layout.preprocessed_width,
                Extension::Base,
            ),
            (
                inputs.permutation,
                program.layout.permutation_width,
                program.extension,
            ),
        ] {
            match (matrix, width) {
                (None, 0) => (),
                (Some(matrix), width)
                    if width != 0
                        && matrix.spec.columns == width
                        && matrix.spec.extension == extension
                        && matrix.spec.log_rows == domain.log_rows
                        && matrix.spec.shift == domain.shift =>
                {
                    self.check_owner(&matrix.buffer)?;
                }
                _ => {
                    return Err("CUDA quotient matrix differs from its AIR layout or domain".into())
                }
            }
        }
        Ok(domain)
    }

    /// All selectors, alpha powers, constraints and division execute on CUDA.
    /// Only one public domain-validity word is read back; output stays resident.
    pub(crate) fn evaluate(
        &self,
        prepared: &PreparedQuotient,
        log_trace: u32,
        inputs: QuotientInputs<'_>,
        alpha: &Buffer,
        parameters: Option<&Buffer>,
    ) -> Result<Matrix> {
        self.check_owner(&prepared.code)?;
        self.check_owner(alpha)?;
        let program = &prepared.program;
        let degree = program.extension.degree();
        if alpha.len() != degree {
            return Err("CUDA quotient alpha has the wrong extension width".into());
        }
        let parameters = match (parameters, program.parameter_words) {
            (None, 0) => &self.zero,
            (Some(buffer), words) if words != 0 && buffer.len() == words => {
                self.check_owner(buffer)?;
                buffer
            }
            _ => return Err("CUDA quotient parameters differ from program shape".into()),
        };
        let domain = self.input_domain(program, inputs, log_trace)?;
        let output_spec = MatrixSpec::new(
            domain.log_rows,
            1,
            program.extension,
            RowOrder::Natural,
            domain.shift,
        )?;
        let plan = Plan::new(
            program,
            domain.rows(),
            self.runtime.snapshot().live_bytes,
            self.runtime.state.budget.limits,
        )?;
        // Admit and allocate every temporary before enqueueing arithmetic.
        let output = self.runtime.allocate(plan.output_words)?;
        let weights = self.runtime.allocate(plan.weight_words)?;
        let gathered = self.runtime.allocate(plan.input_words)?;
        let scratch = self.runtime.allocate(plan.scratch_words)?;
        let status = self.runtime.allocate(1)?;
        // Exactly one thread writes the one-word status/weight passes. The
        // alpha and weights have degree and constraints*degree words respectively.
        unsafe {
            self.domain.launch(
                Launch {
                    blocks: 1,
                    threads: 1,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&status),
                    Argument::U32(domain.log_rows),
                    Argument::U64(domain.shift),
                ],
            )?
        }
        .finish()?;
        let mut validity = [u64::MAX];
        status.read(0, &mut validity)?;
        if validity != [0] {
            return Err("CUDA quotient coset intersects the trace subgroup".into());
        }
        unsafe {
            self.alpha[degree - 2].launch(
                Launch {
                    blocks: 1,
                    threads: 1,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&weights),
                    Argument::U32(program.constraints as u32),
                    Argument::Buffer(alpha),
                ],
            )?
        }
        .finish()?;
        let buffers = [inputs.main, inputs.preprocessed, inputs.permutation]
            .map(|matrix| matrix.map_or(&self.zero, |matrix| &matrix.buffer));
        let reversed = [inputs.main, inputs.preprocessed, inputs.permutation].map(|matrix| {
            u32::from(matrix.is_some_and(|matrix| matrix.spec.order == RowOrder::BitReversed))
        });
        let kernel = prepared
            .specialized
            .as_ref()
            .unwrap_or(&self.evaluate[degree - 2]);
        for first in (0..domain.rows()).step_by(plan.rows) {
            let rows = plan.rows.min(domain.rows() - first);
            // Validated widths/domains and bounded row tiles cover both row
            // windows of every matrix. Absent matrices have zero-width branches.
            unsafe {
                self.gather.launch(
                    launch(rows * program.row_words)?,
                    &[
                        Argument::Buffer(buffers[0]),
                        Argument::Buffer(buffers[1]),
                        Argument::Buffer(buffers[2]),
                        Argument::Buffer(&gathered),
                        Argument::U32(program.layout.main_width as u32),
                        Argument::U32(program.layout.preprocessed_width as u32),
                        Argument::U32((program.layout.permutation_width * degree) as u32),
                        Argument::U32(reversed[0]),
                        Argument::U32(reversed[1]),
                        Argument::U32(reversed[2]),
                        Argument::U32(domain.log_rows),
                        Argument::U32(1u32 << (domain.log_rows - log_trace)),
                        Argument::U32(first as u32),
                        Argument::U32(rows as u32),
                    ],
                )?
            }
            .finish()?;
            // validate_quotient proves every code, register, row and parameter
            // address. Scratch has registers*degree*rows words, and each thread
            // owns a separate row. Inputs, scratch and output never alias.
            unsafe {
                kernel.launch(
                    launch(rows)?,
                    &[
                        Argument::Buffer(&prepared.code),
                        Argument::U32(program.instruction_count() as u32),
                        Argument::Buffer(&gathered),
                        Argument::U32(program.row_words as u32),
                        Argument::Buffer(parameters),
                        Argument::Buffer(&weights),
                        Argument::Buffer(&scratch),
                        Argument::Buffer(&output),
                        Argument::U32(rows as u32),
                        Argument::U32(first as u32),
                        Argument::U32(first as u32),
                        Argument::U32(log_trace),
                        Argument::U64(domain.shift),
                        Argument::U64(roots::root(domain.log_rows)),
                        Argument::U64(roots::inverse_root(log_trace)),
                    ],
                )?
            }
            .finish()?;
        }
        Ok(Matrix {
            spec: output_spec,
            buffer: output,
        })
    }
}

#[cfg(test)]
mod tests;
