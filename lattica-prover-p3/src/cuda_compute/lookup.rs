//! Native LogUp witness generation from resident traces and challenges. Only
//! the validity word is read back; the permutation and terminal stay resident.
use super::{
    budget::Reservation, Argument, Buffer, FieldSpan, Kernel, Launch, Matrix, Result, Runtime,
};
use crate::{
    block_v2::lookup_program::{
        self,
        plan::{InputStorage, Plan},
        LookupProgram,
    },
    gpu_matrix::{Extension, MatrixSpec, RowOrder},
    proving::Stage,
};
use p3_air::symbolic::AirLayout;
use p3_lookup::Lookup;
use std::sync::Arc;

const TILE_BYTES: usize = 2 << 20;
const PROGRAM_HOST_BYTES: usize = 16 << 20;

fn source() -> String {
    [
        include_str!("field.cuh"),
        include_str!("quotient_helpers.cu"),
        include_str!("lookup.cuh"),
        lookup_program::kernels::KERNEL_SRC,
    ]
    .join("\n")
}

pub(crate) struct Lookups {
    runtime: Runtime,
    zero: Buffer,
    gather: Kernel,
    expressions: Kernel,
    denominators: Kernel,
    inverse: Kernel,
    fractions: Kernel,
    scan: Kernel,
    offsets: Kernel,
    accumulator: Kernel,
}

pub(crate) struct PreparedLookup {
    runtime: Runtime,
    program: LookupProgram,
    code: Buffer,
    tuples: Buffer,
    boundaries: Buffer,
    _host: Reservation,
}

impl PreparedLookup {
    pub(super) fn generation_plan(
        &self,
        spec: MatrixSpec,
        live: usize,
        limits: super::Limits,
    ) -> Result<Plan> {
        Plan::new(
            &self.program,
            spec,
            live,
            limits.managed_bytes,
            TILE_BYTES,
            InputStorage::Resident,
            limits.max_allocation_bytes,
        )
    }
}

pub(crate) struct LookupWitness {
    pub(crate) trace: Matrix,
    terminal: Buffer,
}

impl LookupWitness {
    pub(crate) fn terminal(&self) -> FieldSpan<'_> {
        FieldSpan {
            buffer: &self.terminal,
            first: 0,
        }
    }
}

impl Lookups {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(&source())?;
        let kernel = |name| module.kernel_for_stage(name, Stage::Lookup);
        let result = Self {
            runtime: runtime.clone(),
            zero: runtime.allocate(1)?,
            gather: kernel("quotient_gather")?,
            expressions: kernel("device_lookup_expressions")?,
            denominators: kernel("device_lookup_denominators")?,
            inverse: kernel("device_lookup_batch_inverse")?,
            fractions: kernel("device_lookup_fractions")?,
            scan: kernel("device_lookup_scan_blocks")?,
            offsets: kernel("device_lookup_scan_offsets")?,
            accumulator: kernel("device_lookup_accumulator")?,
        };
        for kernel in [
            &result.gather,
            &result.expressions,
            &result.denominators,
            &result.inverse,
            &result.fractions,
            &result.scan,
            &result.offsets,
            &result.accumulator,
        ] {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA lookup kernel exceeds private-memory allowance".into());
            }
        }
        Ok(result)
    }

    fn allocations(&self, count: usize, sizes: &[usize]) -> Result<()> {
        let limits = self.runtime.state.budget.limits;
        let snapshot = self.runtime.snapshot();
        if snapshot
            .allocations
            .checked_add(count)
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA lookup exceeds allocation count".into());
        }
        let mut live = snapshot.live_bytes;
        for &words in sizes {
            let bytes = words
                .checked_mul(8)
                .filter(|&bytes| bytes != 0 && bytes <= limits.max_allocation_bytes)
                .ok_or("CUDA lookup allocation exceeds size limit")?;
            live = live
                .checked_add(bytes)
                .filter(|&bytes| bytes <= limits.managed_bytes)
                .ok_or("CUDA lookup exceeds managed memory")?;
        }
        Ok(())
    }

    /// The caller separately admits the shared symbolic compiler's workspace.
    /// Accept symbolic lookups, not an arbitrary mutable instruction stream.
    pub(crate) fn prepare(
        &self,
        layout: AirLayout,
        lookups: &[Lookup<crate::config::Val>],
        host_bytes: usize,
    ) -> Result<PreparedLookup> {
        drop(self.runtime.state.enter()?);
        let required = (crate::block_v2::machine::symbolic::HOST_BYTES as usize)
            .checked_add(PROGRAM_HOST_BYTES)
            .and_then(|n| n.checked_add(self.runtime.snapshot().public_program_bytes))
            .ok_or("CUDA lookup compiler host allowance overflow")?;
        if host_bytes < required || layout.main_width == 0 {
            return Err("CUDA lookup preparation exceeds host allowance or main geometry".into());
        }
        let program = LookupProgram::compile(layout, lookups)?;
        let retained = program
            .instructions
            .capacity()
            .checked_add(program.tuples.capacity())
            .and_then(|n| n.checked_add(program.boundaries.capacity()))
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(std::mem::size_of::<PreparedLookup>()))
            .filter(|&n| n <= PROGRAM_HOST_BYTES)
            .ok_or("CUDA lookup public program exceeds host allowance")?;
        let host = self.runtime.state.budget.public_program(retained)?;
        let sizes = [
            program.instructions.len().max(1),
            program.tuples.len().max(1),
            program.boundaries.len(),
        ];
        self.allocations(3, &sizes)?;
        let code = self.runtime.allocate(sizes[0])?;
        let tuples = self.runtime.allocate(sizes[1])?;
        let boundaries = self.runtime.allocate(sizes[2])?;
        for (buffer, words) in [
            (&code, &program.instructions),
            (&tuples, &program.tuples),
            (&boundaries, &program.boundaries),
        ] {
            buffer.write(0, if words.is_empty() { &[0] } else { words })?;
        }
        Ok(PreparedLookup {
            runtime: self.runtime.clone(),
            program,
            code,
            tuples,
            boundaries,
            _host: host,
        })
    }

    fn owner(&self, matrix: &Matrix) -> Result<()> {
        let s = matrix.spec;
        if !Arc::ptr_eq(matrix.buffer.owner(), &self.runtime.state)
            || MatrixSpec::new(s.log_rows, s.columns, s.extension, s.order, s.shift)? != s
            || matrix.buffer.len() != s.words()
        {
            return Err("CUDA lookup matrix owner or storage mismatch".into());
        }
        Ok(())
    }

    pub(crate) fn generate(
        &self,
        prepared: &PreparedLookup,
        main: &Matrix,
        preprocessed: Option<&Matrix>,
        public_values: Option<&Buffer>,
        challenges: &Buffer,
        extension: Extension,
    ) -> Result<LookupWitness> {
        if !Arc::ptr_eq(&prepared.runtime.state, &self.runtime.state) {
            return Err("CUDA lookup program belongs to another runtime".into());
        }
        let program = &prepared.program;
        for matrix in [Some(main), preprocessed].into_iter().flatten() {
            self.owner(matrix)?;
        }
        if main.spec.extension != Extension::Base
            || main.spec.shift != 1
            || main.spec.log_rows > 31
            || main.spec.columns != program.layout.main_width
            || !matches!(extension, Extension::Quadratic | Extension::Cubic)
            || !Arc::ptr_eq(challenges.owner(), &self.runtime.state)
            || challenges.len() != program.lookup_count() * 2 * extension.degree()
        {
            return Err("CUDA lookup input or challenge layout mismatch".into());
        }
        match (preprocessed, program.layout.preprocessed_width) {
            (None, 0) => (),
            (Some(pre), width)
                if width != 0
                    && pre.spec.columns == width
                    && pre.spec.extension == Extension::Base
                    && pre.spec.rows() == main.spec.rows()
                    && pre.spec.shift == 1 =>
            {
                ()
            }
            _ => return Err("CUDA lookup preprocessing layout mismatch".into()),
        }
        let public = match (public_values, program.layout.num_public_values) {
            (None, 0) => &self.zero,
            (Some(values), count)
                if count != 0
                    && values.len() == count
                    && Arc::ptr_eq(values.owner(), &self.runtime.state) =>
            {
                values
            }
            _ => return Err("CUDA lookup public-value layout mismatch".into()),
        };
        drop(self.runtime.state.enter()?);
        let spec = MatrixSpec::new(
            main.spec.log_rows,
            program.lookup_count() + 1,
            extension,
            RowOrder::Natural,
            1,
        )?;
        let limits = self.runtime.state.budget.limits;
        let plan = prepared.generation_plan(spec, self.runtime.snapshot().live_bytes, limits)?;
        self.allocations(7 + plan.scan_rows.len(), &[])?;
        let output = self.runtime.allocate(spec.words())?;
        let status = self.runtime.allocate(1)?;
        let input = self.runtime.allocate(plan.tile[0])?;
        let scratch = self.runtime.allocate(plan.tile[1])?;
        let expressions = self.runtime.allocate(plan.tile[2])?;
        let inverses = self.runtime.allocate(plan.tile[3])?;
        let scans = plan
            .scan_rows
            .iter()
            .map(|rows| self.runtime.allocate(rows * extension.degree()))
            .collect::<Result<Vec<_>>>()?;
        let terminal = self.runtime.allocate(extension.degree())?;
        let pre = preprocessed.unwrap_or(main);
        for first in (0..spec.rows()).step_by(plan.rows) {
            let rows = plan.rows.min(spec.rows() - first);
            // The public compiler bounds every input/register/store offset.
            // All row windows and output allocations were admitted together.
            unsafe {
                if program.expression_words != 0 {
                    self.gather
                        .launch(
                            super::transform::linear_launch(rows * program.row_words)?,
                            &[
                                Argument::Buffer(&main.buffer),
                                Argument::Buffer(&pre.buffer),
                                Argument::Buffer(&main.buffer),
                                Argument::Buffer(&input),
                                Argument::U32(program.layout.main_width as u32),
                                Argument::U32(program.layout.preprocessed_width as u32),
                                Argument::U32(0),
                                Argument::U32(u32::from(main.spec.order == RowOrder::BitReversed)),
                                Argument::U32(u32::from(pre.spec.order == RowOrder::BitReversed)),
                                Argument::U32(0),
                                Argument::U32(spec.log_rows),
                                Argument::U32(1),
                                Argument::U32(first as u32),
                                Argument::U32(rows as u32),
                            ],
                        )?
                        .finish()?;
                    self.expressions
                        .launch(
                            super::transform::linear_launch(rows)?,
                            &[
                                Argument::Buffer(&prepared.code),
                                Argument::U32((program.instructions.len() / 5) as u32),
                                Argument::Buffer(&input),
                                Argument::U32(program.row_words as u32),
                                Argument::Buffer(public),
                                Argument::Buffer(&scratch),
                                Argument::Buffer(&expressions),
                                Argument::U32(program.expression_words as u32),
                                Argument::U32(rows as u32),
                                Argument::U32(first as u32),
                                Argument::U32(spec.rows() as u32),
                            ],
                        )?
                        .finish()?;
                }
                let count = rows * program.tuple_count();
                if count != 0 {
                    self.denominators
                        .launch(
                            super::transform::linear_launch(count)?,
                            &[
                                Argument::Buffer(&expressions),
                                Argument::U32(program.expression_words as u32),
                                Argument::Buffer(&prepared.tuples),
                                Argument::U32(program.tuple_count() as u32),
                                Argument::Buffer(challenges),
                                Argument::Buffer(&inverses),
                                Argument::U32(rows as u32),
                                Argument::U32(extension.degree() as u32),
                            ],
                        )?
                        .finish()?;
                    self.inverse
                        .launch(
                            Launch {
                                blocks: count.div_ceil(128) as u32,
                                threads: 128,
                                shared_bytes: 0,
                            },
                            &[
                                Argument::Buffer(&inverses),
                                Argument::U32(count as u32),
                                Argument::Buffer(&status),
                                Argument::U32(extension.degree() as u32),
                            ],
                        )?
                        .finish()?;
                }
                self.fractions
                    .launch(
                        super::transform::linear_launch(rows)?,
                        &[
                            Argument::Buffer(&inverses),
                            Argument::Buffer(&expressions),
                            Argument::U32(program.expression_words as u32),
                            Argument::Buffer(&prepared.tuples),
                            Argument::Buffer(&prepared.boundaries),
                            Argument::U32(program.lookup_count() as u32),
                            Argument::U32(program.tuple_count() as u32),
                            Argument::Buffer(&output),
                            Argument::Buffer(&scans[0]),
                            Argument::U32(rows as u32),
                            Argument::U32(first as u32),
                            Argument::U32(extension.degree() as u32),
                        ],
                    )?
                    .finish()?;
            }
        }
        let mut failed = [0];
        status.read(0, &mut failed)?;
        if failed[0] != 0 {
            return Err("active CUDA lookup denominator is zero".into());
        }
        // Each 128-lane block writes one allocated parent total. Propagate the
        // parents back down before converting the inclusive scan to column zero.
        unsafe {
            for (index, values) in scans.iter().enumerate() {
                let rows = plan.scan_rows[index];
                self.scan
                    .launch(
                        Launch {
                            blocks: rows.div_ceil(128) as u32,
                            threads: 128,
                            shared_bytes: 0,
                        },
                        &[
                            Argument::Buffer(values),
                            Argument::Buffer(scans.get(index + 1).unwrap_or(&terminal)),
                            Argument::U32(rows as u32),
                            Argument::U32(extension.degree() as u32),
                        ],
                    )?
                    .finish()?;
            }
            for index in (0..scans.len() - 1).rev() {
                self.offsets
                    .launch(
                        super::transform::linear_launch(plan.scan_rows[index])?,
                        &[
                            Argument::Buffer(&scans[index]),
                            Argument::Buffer(&scans[index + 1]),
                            Argument::U32(plan.scan_rows[index] as u32),
                            Argument::U32(extension.degree() as u32),
                        ],
                    )?
                    .finish()?;
            }
            self.accumulator
                .launch(
                    super::transform::linear_launch(spec.rows())?,
                    &[
                        Argument::Buffer(&scans[0]),
                        Argument::Buffer(&output),
                        Argument::U32(spec.rows() as u32),
                        Argument::U32(spec.columns as u32),
                        Argument::U32(extension.degree() as u32),
                    ],
                )?
                .finish()?;
        }
        Ok(LookupWitness {
            trace: Matrix {
                spec,
                buffer: output,
            },
            terminal,
        })
    }
}

#[cfg(test)]
mod tests;
