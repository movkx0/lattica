//! Explicit, runtime-local public arithmetic for recursive request components.
//! Only public fields and compiler constants cross this boundary. Selecting this
//! context does not select a prover or authenticate a registry commitment.
mod constants;
mod hash;
#[cfg(test)]
mod tests;

use super::{budget::Reservation, storage::Schedule, Completion, Kernel, Launch, Result, Runtime};
use crate::proving::{Backend, Capabilities, CoverageScope, Profile, Run, Stage};

const SOURCE: &str = concat!(
    include_str!("field.cuh"),
    include_str!("poseidon2.cuh"),
    include_str!("public.cu")
);
const MODULUS: u64 = 0xffff_ffff_0000_0001;
const BATCH_WORDS: usize = 4096;
const CONSTANT_WORDS: usize = 94;
const SCRATCH_WORDS: usize = BATCH_WORDS + 4;
// One synchronous public compilation, including its bounded folding cache,
// fixed upload/readback arrays and context metadata. Source programs and the
// caller's input/output storage have separate caller/controller admission.
pub(crate) const HOST_BYTES: usize = 1 << 16;

pub(crate) struct PublicArithmetic {
    runtime: Runtime,
    poseidon: super::Buffer,
    hash: [Kernel; 2],
    summary: Kernel,
    constants: Kernel,
    periodic: Kernel,
    fold: Kernel,
    construction: Option<crate::block_v2::machine::compiler_constants::ConstructionLimits>,
    _host: Reservation,
}

impl PublicArithmetic {
    pub(crate) fn capabilities(stage: Stage) -> Result<Capabilities> {
        let scope = match stage {
            Stage::PublicValues => CoverageScope::Statement,
            Stage::Preprocessing => CoverageScope::RegistryCompilation,
            _ => return Err("invalid CUDA public arithmetic scope".into()),
        };
        let mut capabilities =
            Capabilities::cpu(Profile::BlockV2Cubic, true, true).scoped(scope, &[stage]);
        capabilities.set(stage, Backend::Cuda);
        Ok(capabilities)
    }

    pub(crate) fn new(runtime: &Runtime, host_bytes: usize) -> Result<Self> {
        Self::with_construction(runtime, host_bytes, None)
    }

    pub(crate) fn with_construction(
        runtime: &Runtime,
        host_bytes: usize,
        construction: Option<crate::block_v2::machine::compiler_constants::ConstructionLimits>,
    ) -> Result<Self> {
        let construction = construction.map(|limits| limits.validate()).transpose()?;
        drop(runtime.state.enter()?);
        if host_bytes < HOST_BYTES {
            return Err("CUDA public arithmetic exceeds host allowance".into());
        }
        // Admit the context and its largest scratch operation before compiling,
        // allocating or uploading. Actual scratch is released after each call.
        let mut plan = Schedule::new(runtime.snapshot(), runtime.state.budget.limits)?;
        plan.phase("public arithmetic");
        plan.hold([CONSTANT_WORDS])?;
        plan.scratch([BATCH_WORDS, 4])?;
        let host = runtime.state.budget.public_program(HOST_BYTES)?;
        let module = runtime.compile(SOURCE)?;
        Ok(Self {
            runtime: runtime.clone(),
            poseidon: super::commitment::poseidon_constants(runtime)?,
            hash: [
                module.kernel_for_stage("public_hash", Stage::PublicValues)?,
                module.kernel_for_stage("public_hash", Stage::Preprocessing)?,
            ],
            summary: module.kernel_for_stage("public_summary", Stage::PublicValues)?,
            constants: module.kernel_for_stage("public_constants", Stage::Preprocessing)?,
            periodic: module.kernel_for_stage("public_periodic", Stage::Preprocessing)?,
            fold: module.kernel_for_stage("public_fold", Stage::Preprocessing)?,
            construction,
            _host: host,
        })
    }

    pub(crate) fn construction_limits(
        &self,
    ) -> Option<crate::block_v2::machine::compiler_constants::ConstructionLimits> {
        self.construction
    }

    /// Bind completions to this exact component. No context or device handle is
    /// placed in the resulting program, report, proof or future worker packet.
    pub(crate) fn reported<T>(&self, run: &Run, body: impl FnOnce() -> Result<T>) -> Result<T> {
        self.runtime.reported(run, body)
    }

    fn check(&self, run: &Run, stage: Stage) -> Result<()> {
        self.runtime.check_report_run(run)?;
        run.cuda_require_capabilities(&Self::capabilities(stage)?)
            .map_err(super::error)
    }

    fn admit(&self, words: &[usize]) -> Result<()> {
        drop(self.runtime.state.enter()?);
        if words.len() > 2
            || words
                .iter()
                .try_fold(0usize, |n, w| n.checked_add(*w))
                .is_none_or(|n| n > SCRATCH_WORDS)
        {
            return Err("CUDA public arithmetic exceeds scratch envelope".into());
        }
        let mut plan = Schedule::new(self.runtime.snapshot(), self.runtime.state.budget.limits)?;
        plan.phase("public arithmetic scratch");
        plan.scratch(words.iter().copied())
    }

    fn record(&self, run: &Run, stage: Stage, completion: Result<Completion>) -> Result<()> {
        let reported = completion.as_ref().is_ok_and(Completion::is_reported);
        let ns = completion.and_then(Completion::finish).map_err(|error| {
            run.observation_failed();
            error
        })?;
        if !reported {
            run.observe_device(stage, Backend::Cuda, 1, u128::from(ns))
                .map_err(super::error)?;
        }
        Ok(())
    }
}

fn launch(count: usize) -> Launch {
    // All callers independently bound count to their fixed public envelope.
    Launch {
        blocks: count.div_ceil(128) as u32,
        threads: 128,
        shared_bytes: 0,
    }
}
const SINGLE: Launch = Launch {
    blocks: 1,
    threads: 1,
    shared_bytes: 0,
};
