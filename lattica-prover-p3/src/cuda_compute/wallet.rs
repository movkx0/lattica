//! Native wallet witness/public generation from raw input words. The shared
//! kernel bodies preserve the existing AIR's layout and validation rules.
use super::{Argument, Buffer, Kernel, Launch, Matrix, Result, Runtime};
use crate::gpu_matrix::MemoryPlan;
use crate::gpu_wallet::{self, InputWords, Plan};
use crate::proving::{Backend, Run, Stage};

mod prove;
pub(crate) use prove::{HtlcProver, JoinSplitProver, WalletProof, WalletProver};

#[cfg(test)]
mod tests;

fn source() -> String {
    [
        include_str!("field.cuh"),
        include_str!("poseidon2.cuh"),
        include_str!("wallet.cuh"),
        gpu_wallet::joinsplit_kernels::KERNEL_SRC,
        gpu_wallet::htlc_kernels::KERNEL_SRC,
    ]
    .join("\n")
}

pub(crate) struct Wallets {
    runtime: Runtime,
    constants: [Buffer; 4],
    joinsplit: [Kernel; 3],
    htlc: [Kernel; 3],
}

pub(crate) struct NativeWalletTrace {
    pub trace: Matrix,
    pub public: Buffer,
}

impl Wallets {
    pub(crate) fn new(runtime: &Runtime) -> Result<Self> {
        let module = runtime.compile(&source())?;
        let joinsplit = [
            module.kernel_for_stage(
                "device_joinsplit_regions",
                crate::proving::Stage::WitnessTrace,
            )?,
            module.kernel_for_stage(
                "device_joinsplit_columns",
                crate::proving::Stage::WitnessTrace,
            )?,
            module.kernel_for_stage(
                "device_joinsplit_public",
                crate::proving::Stage::PublicValues,
            )?,
        ];
        let htlc = [
            module.kernel_for_stage("device_htlc_regions", crate::proving::Stage::WitnessTrace)?,
            module.kernel_for_stage("device_htlc_columns", crate::proving::Stage::WitnessTrace)?,
            module.kernel_for_stage("device_htlc_public", crate::proving::Stage::PublicValues)?,
        ];
        for kernel in joinsplit.iter().chain(&htlc) {
            if !super::kernel::private_memory_fits(runtime.identity(), kernel.local_bytes()?)? {
                return Err("CUDA wallet kernel exceeds private-memory admission".into());
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
            joinsplit,
            htlc,
        })
    }

    pub(crate) fn joinsplit(
        &self,
        witness: &crate::joinsplit_air::Witness,
        host_bytes: usize,
        run: &Run,
    ) -> Result<NativeWalletTrace> {
        self.generate(
            Plan::new(host_bytes)?,
            &crate::joinsplit_air::device_trace_geometry(),
            || gpu_wallet::input_words(witness),
            &self.joinsplit,
            run,
        )
    }

    pub(crate) fn htlc(
        &self,
        witness: &crate::htlc_air::Witness,
        host_bytes: usize,
        run: &Run,
    ) -> Result<NativeWalletTrace> {
        self.generate(
            gpu_wallet::htlc::plan(host_bytes)?,
            &crate::htlc_air::device_trace_geometry(),
            || gpu_wallet::htlc::input_words(witness),
            &self.htlc,
            run,
        )
    }

    fn generate(
        &self,
        plan: Plan,
        geometry: &[u64],
        inputs: impl FnOnce() -> Result<InputWords>,
        kernels: &[Kernel; 3],
        run: &Run,
    ) -> Result<NativeWalletTrace> {
        self.runtime.check_report_run(run)?;
        for stage in [Stage::WitnessTrace, Stage::PublicValues] {
            run.check_device_stage(stage, Backend::Cuda)
                .map_err(super::error)?;
        }
        if geometry.len() != plan.geometry_words {
            return Err("CUDA wallet geometry length differs from admitted layout".into());
        }
        let specs = plan.specs()?;
        let before = self.runtime.snapshot();
        let limits = self.runtime.state.budget.limits;
        MemoryPlan::new(
            &specs,
            before.live_bytes,
            limits.managed_bytes,
            limits.max_allocation_bytes,
        )?;
        if before
            .allocations
            .checked_add(specs.len())
            .is_none_or(|n| n > limits.max_allocations)
        {
            return Err("CUDA wallet exceeds allocation-count admission".into());
        }
        // Exact-capacity staging is scrubbed by InputWords on every exit path.
        // All five device allocations are admitted before packing private inputs.
        let words = inputs()?;
        if words.0.len() != plan.input_words {
            return Err("CUDA wallet input length differs from admitted layout".into());
        }
        let trace = Matrix {
            spec: plan.trace,
            buffer: self.runtime.allocate(plan.trace.words())?,
        };
        let public = self.runtime.allocate(plan.public.words())?;
        let input = self.runtime.allocate(plan.input_words)?;
        let geometry_buffer = self.runtime.allocate(plan.geometry_words)?;
        let status = self.runtime.allocate(1)?;
        input.write(0, &words.0)?;
        geometry_buffer.write(0, geometry)?;
        drop(words);
        // Each region writes disjoint trace rows. The shared kernel ignores
        // excess launch lanes beyond the validated AIR's final padded region.
        record(run, Stage::WitnessTrace, unsafe {
            kernels[0].launch(
                super::transform::linear_launch(plan.regions)?,
                &[
                    Argument::Buffer(&input),
                    Argument::Buffer(&geometry_buffer),
                    Argument::Buffer(&trace.buffer),
                    Argument::Buffer(&self.constants[0]),
                    Argument::Buffer(&self.constants[1]),
                    Argument::Buffer(&self.constants[2]),
                    Argument::Buffer(&self.constants[3]),
                ],
            )
        })?;
        // Completed region work precedes the row-local accumulator columns.
        record(run, Stage::WitnessTrace, unsafe {
            kernels[1].launch(
                super::transform::linear_launch(plan.trace.rows())?,
                &[
                    Argument::Buffer(&input),
                    Argument::Buffer(&geometry_buffer),
                    Argument::Buffer(&trace.buffer),
                ],
            )
        })?;
        // Exactly one thread checks the witness and extracts its public statement.
        record(run, Stage::PublicValues, unsafe {
            kernels[2].launch(
                Launch {
                    blocks: 1,
                    threads: 1,
                    shared_bytes: 0,
                },
                &[
                    Argument::Buffer(&input),
                    Argument::Buffer(&geometry_buffer),
                    Argument::Buffer(&trace.buffer),
                    Argument::Buffer(&public),
                    Argument::Buffer(&status),
                ],
            )
        })?;
        let mut invalid = [0];
        status.read(0, &mut invalid)?;
        if invalid[0] != 0 {
            return Err("invalid CUDA wallet witness".into());
        }
        // Device buffers scrub on drop. Only this status word has crossed back
        // to the host; the trace and public values can feed Starks directly.
        Ok(NativeWalletTrace { trace, public })
    }
}

fn record(run: &Run, stage: Stage, completion: Result<super::Completion>) -> Result<()> {
    let reported = completion
        .as_ref()
        .is_ok_and(|completion| completion.is_reported());
    let ns = completion
        .and_then(super::Completion::finish)
        .map_err(|error| {
            run.observation_failed();
            error
        })?;
    if reported {
        Ok(())
    } else {
        run.observe_device(stage, Backend::Cuda, 1, u128::from(ns))
            .map_err(super::error)
    }
}
