//! Native execution of immutable recursive machine programs. Host compilation
//! schedules dependencies; all private field evaluation and trace construction
//! runs on CUDA. This component does not construct a recursive STARK proof.
use super::{budget::Reservation, Argument, Buffer, Kernel, Matrix, Result, Runtime};
use crate::{
    block_v2::{
        lookup_program,
        machine::{
            gpu_program::{self, WitnessProgram, WitnessSchedule},
            Program,
        },
    },
    gpu_matrix::{Extension, MatrixSpec, RowOrder},
    proving::Stage,
};
use std::sync::Arc;

fn source() -> String {
    [
        include_str!("field.cuh"),
        include_str!("poseidon2.cuh"),
        include_str!("lookup.cuh"),
        lookup_program::kernels::KERNEL_SRC,
        include_str!("wallet.cuh"),
        include_str!("witness.cuh"),
        gpu_program::kernels::KERNEL_SRC,
    ]
    .join("\n")
}

pub(crate) struct Witnesses {
    runtime: Runtime,
    constants: [Buffer; 4],
    publics: Kernel,
    wire_publics: Kernel,
    wave: Kernel,
    rows: Kernel,
    preprocessing: Kernel,
}

pub(crate) struct PreparedWitness {
    runtime: Runtime,
    schedule: WitnessSchedule,
    metadata: Buffer,
    _host: Reservation,
}

impl PreparedWitness {
    /// Unique allocations used by generation, in execution order. Public
    /// metadata already belongs to the caller's starting runtime snapshot.
    pub(super) fn generation_words(&self) -> Result<[usize; 5]> {
        let p = &self.schedule;
        let spec = MatrixSpec::new(
            p.height.ilog2(),
            p.trace_width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let inputs = p
            .publics
            .checked_add(p.witnesses)
            .ok_or("CUDA machine input overflow")?;
        Ok([spec.words(), p.wires.max(1), inputs.max(1), 1, p.publics])
    }
}

pub(crate) struct ExecutionTrace {
    pub(crate) trace: Matrix,
    pub(crate) public: Option<Buffer>,
}

/// Only deterministic metadata expansion can produce this provenance wrapper.
pub(crate) struct PreprocessingTrace {
    matrix: Matrix,
}
impl PreprocessingTrace {
    pub(crate) fn matrix(&self) -> &Matrix {
        &self.matrix
    }
}

impl Witnesses {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(&source())?;
        let publics = module.kernel_for_stage("device_witness_public", Stage::PublicValues)?;
        let wire_publics = module.kernel_for_stage("device_witness_public", Stage::WitnessTrace)?;
        let wave = module.kernel_for_stage("device_witness_wave", Stage::WitnessTrace)?;
        let rows = module.kernel_for_stage("device_witness_rows", Stage::WitnessTrace)?;
        let preprocessing =
            module.kernel_for_stage("device_preprocessing_rows", Stage::Preprocessing)?;
        for kernel in [&publics, &wire_publics, &wave, &rows, &preprocessing] {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA machine kernel exceeds private-memory allowance".into());
            }
        }
        let upload = |words: &[u64]| -> Result<Buffer> {
            let buffer = runtime.allocate(words.len())?;
            buffer.write(0, words)?;
            Ok(buffer)
        };
        let (initial, internal, final_rounds, diagonal) = crate::gpu_constants::poseidon2_consts();
        Ok(Self {
            runtime: runtime.clone(),
            constants: [
                upload(&initial)?,
                upload(&internal)?,
                upload(&final_rounds)?,
                upload(&diagonal)?,
            ],
            publics,
            wire_publics,
            wave,
            rows,
            preprocessing,
        })
    }

    fn admit(&self, words: &[usize]) -> Result<()> {
        let before = self.runtime.snapshot();
        let limits = self.runtime.state.budget.limits;
        if before
            .allocations
            .checked_add(words.len())
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA machine exceeds allocation count".into());
        }
        let mut peak = before.live_bytes;
        for &count in words {
            let bytes = count
                .checked_mul(8)
                .filter(|&n| n > 0 && n <= limits.max_allocation_bytes)
                .ok_or("CUDA machine allocation exceeds size allowance")?;
            peak = peak
                .checked_add(bytes)
                .filter(|&n| n <= limits.managed_bytes)
                .ok_or("CUDA machine exceeds managed allowance")?;
        }
        Ok(())
    }

    /// The caller owns and separately admits the source Program. Compile it
    /// internally so callers cannot supply an unchecked mutable metadata buffer.
    pub(crate) fn prepare(&self, program: &Program, host_bytes: usize) -> Result<PreparedWitness> {
        drop(self.runtime.state.enter()?);
        let allowance = host_bytes
            .checked_sub(self.runtime.snapshot().public_program_bytes)
            .and_then(|n| n.checked_sub(std::mem::size_of::<PreparedWitness>()))
            .ok_or("CUDA machine compiler exceeds host allowance")?;
        let compiled = WitnessProgram::compile(program, allowance)
            .map_err(|e| format!("CUDA machine compilation: {e:?}"))?;
        let schedule = WitnessSchedule::try_new(&compiled, compiled.schedule_host_bytes)
            .map_err(|e| format!("CUDA machine schedule: {e:?}"))?;
        let retained = schedule
            .storage_bytes()
            .checked_add(
                std::mem::size_of::<PreparedWitness>() - std::mem::size_of::<WitnessSchedule>(),
            )
            .ok_or("CUDA machine retained host size overflow")?;
        let host = self.runtime.state.budget.public_program(retained)?;
        self.admit(&[compiled.words.len()])?;
        let metadata = self.runtime.allocate(compiled.words.len())?;
        metadata.write(0, &compiled.words)?;
        // The instructions and compiler-capacity wave vector are no longer retained.
        Ok(PreparedWitness {
            runtime: self.runtime.clone(),
            schedule,
            metadata,
            _host: host,
        })
    }

    fn owner(&self, prepared: &PreparedWitness) -> Result<()> {
        if !Arc::ptr_eq(&self.runtime.state, &prepared.runtime.state) {
            return Err("CUDA machine program belongs to another runtime".into());
        }
        drop(self.runtime.state.enter()?);
        Ok(())
    }

    pub(crate) fn preprocessing(&self, prepared: &PreparedWitness) -> Result<PreprocessingTrace> {
        self.owner(prepared)?;
        let p = &prepared.schedule;
        let spec = MatrixSpec::new(
            p.height.ilog2(),
            p.preprocessing_width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        self.admit(&[spec.words()])?;
        let output = self.runtime.allocate(spec.words())?;
        // The compiler bounds row/port offsets; each lane owns one admitted row.
        unsafe {
            self.preprocessing
                .launch(
                    super::transform::linear_launch(spec.rows())?,
                    &[
                        Argument::Buffer(&prepared.metadata),
                        Argument::Buffer(&output),
                    ],
                )?
                .finish()?;
        }
        Ok(PreprocessingTrace {
            matrix: Matrix {
                spec,
                buffer: output,
            },
        })
    }

    pub(crate) fn generate(
        &self,
        prepared: &PreparedWitness,
        public: &[u64],
        witness: &[u64],
        host_bytes: usize,
    ) -> Result<ExecutionTrace> {
        self.owner(prepared)?;
        let p = &prepared.schedule;
        if public.len() != p.publics || witness.len() != p.witnesses {
            return Err("CUDA machine input count mismatch".into());
        }
        if public
            .iter()
            .chain(witness)
            .any(|&v| v >= 0xffff_ffff_0000_0001)
        {
            return Err("CUDA machine noncanonical input".into());
        }
        let input_words = p
            .publics
            .checked_add(p.witnesses)
            .ok_or("CUDA machine input overflow")?;
        if input_words
            .checked_mul(8)
            .and_then(|n| n.checked_add(8))
            .is_none_or(|n| n > host_bytes)
        {
            return Err("CUDA machine input/status staging exceeds host allowance".into());
        }
        let spec = MatrixSpec::new(
            p.height.ilog2(),
            p.trace_width,
            Extension::Base,
            RowOrder::Natural,
            1,
        )?;
        let sizes = prepared.generation_words()?;
        self.admit(&sizes[..if p.publics == 0 { 4 } else { 5 }])?;
        let output = self.runtime.allocate(spec.words())?;
        let wires = self.runtime.allocate(p.wires.max(1))?;
        let input = self.runtime.allocate(input_words.max(1))?;
        let status = self.runtime.allocate(1)?;
        let public_output = if p.publics == 0 {
            None
        } else {
            Some(self.runtime.allocate(p.publics)?)
        };
        if !public.is_empty() {
            input.write(0, public)?;
        }
        if !witness.is_empty() {
            input.write(public.len(), witness)?;
        }
        // Public input copies and dependency waves have distinct, observed stage
        // tickets. A wave reads only preceding SSA values and writes disjoint wires.
        unsafe {
            if let Some(public_output) = &public_output {
                for (kernel, target) in
                    [(&self.publics, public_output), (&self.wire_publics, &wires)]
                {
                    kernel
                        .launch(
                            super::transform::linear_launch(p.publics)?,
                            &[
                                Argument::Buffer(&input),
                                Argument::Buffer(target),
                                Argument::U32(p.publics as u32),
                            ],
                        )?
                        .finish()?;
                }
            }
            for wave in &p.waves {
                self.wave
                    .launch(
                        super::transform::linear_launch(wave.len())?,
                        &[
                            Argument::Buffer(&prepared.metadata),
                            Argument::U32(wave.start as u32),
                            Argument::U32(wave.len() as u32),
                            Argument::Buffer(&input),
                            Argument::Buffer(&wires),
                            Argument::Buffer(&status),
                            Argument::Buffer(&self.constants[0]),
                            Argument::Buffer(&self.constants[1]),
                            Argument::Buffer(&self.constants[2]),
                            Argument::Buffer(&self.constants[3]),
                        ],
                    )?
                    .finish()?;
            }
        }
        let mut failed = [0];
        status.read(0, &mut failed)?;
        if failed[0] != 0 {
            return Err("unsatisfied CUDA machine witness".into());
        }
        // Rows are constructed only after all execution checks have succeeded.
        unsafe {
            self.rows
                .launch(
                    super::transform::linear_launch(spec.rows())?,
                    &[
                        Argument::Buffer(&prepared.metadata),
                        Argument::Buffer(&wires),
                        Argument::Buffer(&output),
                        Argument::Buffer(&self.constants[0]),
                        Argument::Buffer(&self.constants[1]),
                        Argument::Buffer(&self.constants[2]),
                        Argument::Buffer(&self.constants[3]),
                    ],
                )?
                .finish()?;
        }
        Ok(ExecutionTrace {
            trace: Matrix {
                spec,
                buffer: output,
            },
            public: public_output,
        })
    }
}

#[cfg(test)]
mod tests;
