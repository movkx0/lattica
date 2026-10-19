use super::*;
use crate::{
    block_v2::machine::compiler_constants::ConstructionLimits,
    cuda_compute::{
        BatchStarks, MachineInputs, NativeBatchProof, PublicArithmetic, RegisteredKey,
        RegisteredMachine, Runtime, Specialization,
    },
    gpu_wallet::{staging_words, InputWords},
    proving::{Backend as ArithmeticBackend, Capabilities, CoverageScope, Profile, Request, Stage},
};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub construction: ConstructionLimits,
}

pub(super) struct Context {
    pub(super) public: PublicArithmetic,
    engine: Arc<BatchStarks>,
    runtime: Runtime,
    pub(super) limits: Limits,
}

pub(super) struct Prepared {
    pub(super) air: MachineAir,
    pub(super) machine: RegisteredMachine,
    context: Arc<Context>,
    host_bytes: usize,
    pub(super) source_host_bytes: usize,
}

impl Context {
    pub(super) fn new(
        runtime: &Runtime,
        host_bytes: u64,
        limits: Limits,
    ) -> Result<Arc<Self>, Error> {
        let limits = Limits {
            construction: limits.construction.validate()?,
        };
        let host_bytes = usize::try_from(host_bytes)?;
        if limits.construction.workspace_bytes()? > host_bytes {
            return Err("CUDA session construction exceeds worker allowance".into());
        }
        let public =
            PublicArithmetic::with_construction(runtime, host_bytes, Some(limits.construction))?;
        let context = Arc::new(Self {
            public,
            engine: Arc::new(BatchStarks::new(runtime)?),
            runtime: runtime.clone(),
            limits,
        });
        context.admit_compilation(host_bytes as u64, 0)?;
        Ok(context)
    }

    pub(super) fn request<T>(
        &self,
        entry: &'static str,
        body: impl FnOnce(&Run) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, true);
        for stage in Stage::ARITHMETIC {
            capabilities.set(stage, ArithmeticBackend::Cuda);
        }
        let run = Run::request(
            entry,
            Request::from_env()?,
            capabilities,
            &[
                ("statement", CoverageScope::Statement),
                ("registry", CoverageScope::RegistryCompilation),
                ("statement_check", CoverageScope::Statement),
                ("preprocessing", CoverageScope::Preprocessing),
                ("proof", CoverageScope::RegisteredProof),
            ],
        )?;
        let result = body(&run);
        match result {
            Ok(value) => {
                let report = run.finish(true)?;
                if !report.succeeded || !report.stage_coverage_complete {
                    return Err("CUDA typed request lacks complete execution receipts".into());
                }
                Ok(value)
            }
            Err(error) => {
                let _ = run.finish(false);
                Err(error)
            }
        }
    }

    pub(super) fn admit_compilation(
        &self,
        budget: u64,
        retained_sources: usize,
    ) -> Result<(), Error> {
        let required = self
            .limits
            .construction
            .workspace_bytes()?
            .checked_add(retained_sources)
            .and_then(|n| n.checked_add(self.runtime.snapshot().public_program_bytes))
            .ok_or("CUDA session construction allowance overflow")?;
        if required as u64 > budget {
            return Err("CUDA session construction and cache exceed worker allowance".into());
        }
        Ok(())
    }

    pub(super) fn prepare(
        self: &Arc<Self>,
        air: MachineAir,
        budget: u64,
        request: &Run,
        cap: &[[Val; 4]],
    ) -> Result<Prepared, Error> {
        let program = air.program();
        let source_host_bytes = program.source_host_bytes()?;
        if program.wire_count() > self.limits.construction.wires
            || program
                .public_values()
                .checked_add(program.witness_values())
                .is_none_or(|n| n > self.limits.construction.input_values)
            || source_host_bytes > self.limits.construction.program_host_bytes
        {
            return Err("CUDA compiled program exceeds its construction assignment".into());
        }
        let host_bytes = usize::try_from(budget)?;
        // The caller retains its original field-value backing while the native
        // engine consumes exact raw-word staging. Reserve its configured upper
        // bound, plus the existing independent-verifier component allowance.
        let host_bytes = host_bytes
            .checked_sub(
                self.limits
                    .construction
                    .input_values
                    .checked_mul(8)
                    .ok_or("CUDA input allowance overflow")?,
            )
            .and_then(|n| {
                n.checked_sub(
                    super::super::super::machine::backend::NATIVE_VERIFIER_COMPONENT_BYTES as usize,
                )
            })
            .ok_or("CUDA session inputs and verification exceed worker allowance")?;
        let run = request.child(
            "preprocessing",
            "cuda_typed_preprocessing",
            BatchStarks::preprocessing_capabilities(),
        )?;
        let (machine, _) = self.engine.prepare_registered_in_run(
            &air,
            RegisteredKey {
                profile: Profile::BlockV2Cubic,
                height: program.height(),
                public_values: program.public_values(),
                witness_values: program.witness_values(),
                cap,
            },
            run,
            host_bytes,
            Specialization::Prefer,
        )?;
        Ok(Prepared {
            air,
            machine,
            context: self.clone(),
            host_bytes,
            source_host_bytes,
        })
    }
}

impl Prepared {
    pub(super) fn prove(
        &self,
        public: &[Val],
        witness: &[Val],
        request: &Run,
    ) -> Result<p3_batch_stark::BatchProof<profile::Config>, Error> {
        let count = public
            .len()
            .checked_add(witness.len())
            .ok_or("CUDA typed input count overflow")?;
        if public.len() != self.air.program().public_values()
            || witness.len() != self.air.program().witness_values()
            || count > self.context.limits.construction.input_values
        {
            return Err("CUDA typed inputs differ from registered program".into());
        }
        // Bound before encoding, retain no private staging in the cache, and
        // scrub the exact-capacity allocation on success, failure and unwind.
        let mut words = InputWords(staging_words(count)?);
        words.0.extend(
            public
                .iter()
                .chain(witness)
                .map(PrimeField64::as_canonical_u64),
        );
        let run = request.child(
            "proof",
            "cuda_typed_registered_program",
            self.machine.proof_capabilities(),
        )?;
        let result = self.machine.prove_in_run(
            MachineInputs {
                public: &words.0[..public.len()],
                witness: &words.0[public.len()..],
            },
            run,
            self.host_bytes,
        )?;
        Ok(into_application_proof(result.proof))
    }
}

/// These configurations intentionally share all concrete commitment/opening
/// types. Move their fields directly; do not serialize, allocate a second proof,
/// or reinterpret memory merely to change the orchestration configuration.
fn into_application_proof(proof: NativeBatchProof) -> p3_batch_stark::BatchProof<profile::Config> {
    p3_batch_stark::BatchProof {
        commitments: proof.commitments,
        opened_values: proof.opened_values,
        opening_proof: proof.opening_proof,
        lookup_terminals: proof.lookup_terminals,
        degree_bits: proof.degree_bits,
    }
}

impl<const N: usize> Session<N> {
    /// Explicit native entry point for maintained typed programs. Approval is
    /// still the independently supplied registry/profile; no backend is chosen
    /// from environment flags or from an untrusted proof/job packet.
    pub(crate) fn new_cuda(
        registry: Registry<N>,
        expected_profile: [u8; 32],
        worker_memory_bytes: u64,
        runtime: &Runtime,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut session = Self::new(registry, expected_profile, worker_memory_bytes)?;
        session.backend = Backend::Cuda(Context::new(
            runtime,
            storage::active_memory_bytes(worker_memory_bytes, 0)?,
            limits,
        )?);
        Ok(session)
    }
}

#[cfg(all(test, feature = "block-v2-host", feature = "stream"))]
mod full_size_tests;
#[cfg(test)]
mod tests;
