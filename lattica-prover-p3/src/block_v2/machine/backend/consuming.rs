//! A one-shot registration retires immutable instruction storage after the
//! fenced main trace. Reusable registrations retain their existing lifetime.
use super::{profile, BatchProof, Config, ExecutionError, PreparedProgram, Val};
use crate::block_v2::{
    challenger, gpu_hash, gpu_quotient_prover, machine::gpu_backend, quotient_pcs, randomness,
};
use crate::proving::{Backend, Run, Stage};
use p3_uni_stark::StarkGenericConfig;

/// No allocation or cloned instruction owner. The consuming variant is dropped
/// after the fenced trace closure returns and before quotient work can begin.
pub(super) enum WitnessOwner<'a, T> {
    Retained(&'a T),
    #[cfg(feature = "gpu")]
    Consumed(T),
}

impl<T> WitnessOwner<'_, T> {
    fn trace_and_retire<R, E>(self, trace: impl FnOnce(&T) -> Result<R, E>) -> Result<R, E> {
        let prepared = match &self {
            Self::Retained(prepared) => *prepared,
            #[cfg(feature = "gpu")]
            Self::Consumed(prepared) => prepared,
        };
        let result = trace(prepared);
        // On error the closure's queue/scratch guards have already run. On an
        // unwind those guards likewise run before this owner is destroyed.
        drop(self);
        result
    }
}

#[cfg(feature = "gpu")]
fn check_binding_and_policy(
    registered: &std::sync::Arc<crate::block_v2::machine::Program>,
    admitted: &std::sync::Arc<crate::block_v2::machine::Program>,
    request: crate::proving::Request,
) -> Result<(), ExecutionError> {
    if request.policy != crate::proving::Policy::GpuRequired
        || !std::sync::Arc::ptr_eq(registered, admitted)
    {
        return Err(ExecutionError::ProvingPolicy);
    }
    Ok(())
}

/// Each variant keeps its distinct authority. Only the backend mechanics are
/// shared; an outer backend token never becomes a direct workflow admission.
#[cfg(feature = "gpu")]
enum ConsumingAdmission<'borrow, 'inputs> {
    Direct(&'borrow crate::block_v2::machine::RegisteredGpuAdmission<'inputs>),
    Outer(&'borrow crate::block_v2::machine::OuterBackendAdmission<'inputs>),
}

#[cfg(feature = "gpu")]
impl ConsumingAdmission<'_, '_> {
    fn program(&self) -> &std::sync::Arc<crate::block_v2::machine::Program> {
        match self {
            Self::Direct(admission) => admission.program(),
            Self::Outer(admission) => admission.program(),
        }
    }
    fn public(&self) -> &[Val] {
        match self {
            Self::Direct(admission) => admission.public(),
            Self::Outer(admission) => admission.public(),
        }
    }
    fn witness(&self) -> &[Val] {
        match self {
            Self::Direct(admission) => admission.witness(),
            Self::Outer(admission) => admission.witness(),
        }
    }
    fn host_budget_bytes(&self) -> u64 {
        match self {
            Self::Direct(admission) => admission.host_budget_bytes(),
            Self::Outer(admission) => admission.host_budget_bytes(),
        }
    }
    fn check_execution_selection(&self) -> Result<(), String> {
        match self {
            Self::Direct(admission) => admission.check_execution_selection(),
            Self::Outer(admission) => admission.check_execution_selection(),
        }
    }
}

#[cfg(feature = "gpu")]
impl super::RegisteredProgram {
    /// Prove once using a sealed complete-workflow admission, consuming this
    /// registration. Inputs come only from that admission's immutable owners.
    ///
    /// After the observed main trace completes, its independent device matrix
    /// survives while PreparedWitness and its instruction/schedule storage are
    /// destroyed before any lookup or quotient allocation. This lifetime is a
    /// requirement of the one-shot memory bound; it does not authorize reusable
    /// registration under that bound. The existing borrowed APIs are unchanged.
    ///
    /// QueueFence and private scratch guards drain on every trace return and
    /// unwind. An uncertain drain aborts the worker, so this API never releases
    /// still-in-use instruction storage or reports such a failure as success.
    pub fn into_prove_with_request_and_report(
        self,
        admission: &crate::block_v2::machine::RegisteredGpuAdmission<'_>,
        request: crate::proving::Request,
    ) -> Result<(BatchProof<Config>, crate::proving::Report), ExecutionError> {
        self.into_prove_admitted(ConsumingAdmission::Direct(admission), request)
    }

    /// Backend-only outer proof. The caller must hold all enclosing source,
    /// compiler, child, output/key/verifier, report and cleanup reservations.
    /// In particular, acquire the real `verifier()` while this registration is
    /// alive and its independent metadata lifecycle is preclaimed, before this
    /// consuming call. This method grants no graph or transaction acceptance.
    pub fn into_prove_outer_with_request_and_report(
        self,
        admission: &crate::block_v2::machine::OuterBackendAdmission<'_>,
        request: crate::proving::Request,
    ) -> Result<(BatchProof<Config>, crate::proving::Report), ExecutionError> {
        self.into_prove_admitted(ConsumingAdmission::Outer(admission), request)
    }

    fn into_prove_admitted(
        self,
        admission: ConsumingAdmission<'_, '_>,
        request: crate::proving::Request,
    ) -> Result<(BatchProof<Config>, crate::proving::Report), ExecutionError> {
        check_binding_and_policy(&self.prepared.air.program, admission.program(), request)?;
        if !cfg!(all(not(debug_assertions), target_arch = "x86_64")) {
            return Err(ExecutionError::ProvingPolicy);
        }
        admission
            .check_execution_selection()
            .map_err(|_| ExecutionError::ProvingPolicy)?;
        gpu_backend::check_selected().map_err(|_| ExecutionError::GpuFailure)?;
        if !quotient_pcs::gpu_witness_enabled() || self.prepared.gpu_witness.is_none() {
            return Err(ExecutionError::GpuFailure);
        }
        // A registration built with a larger allowance cannot borrow a smaller
        // token. Re-derive setup's structural bound and host partition; the
        // small environment-selection temporaries remain caller-accounted.
        let host_allowance = usize::try_from(admission.host_budget_bytes())
            .map_err(|_| ExecutionError::TooLarge)?
            .min(crate::block_v2::resident_pcs::host_output_budget());
        let bounds = gpu_backend::resources::Bounds::for_program_with_device_salts(
            self.prepared.air.program(),
            quotient_pcs::gpu_randomness_enabled(),
        )
        .map_err(|_| ExecutionError::TooLarge)?;
        let partition = bounds
            .partition_host(host_allowance as u64)
            .map_err(|_| ExecutionError::TooLarge)?;
        if self.prepared.gpu_host_allowance > host_allowance
            || self.prepared.gpu_pcs_host_allowance as u64 > partition.pcs_bytes
        {
            return Err(ExecutionError::TooLarge);
        }
        let run = Run::new(
            "block_v2_registered_program",
            request,
            profile::registered_proof_capabilities(),
        )
        .map_err(|_| ExecutionError::ProvingPolicy)?;
        let _memory_phase =
            crate::block_v2::worker_memory::PhaseGuard::acquire("trace and quotient")
                .map_err(|_| ExecutionError::GpuFailure)?;
        // Declare the owner after the phase guard, so errors and unwinds also
        // retire every registration field before releasing the heavy phase.
        let mut state = self.prepared;
        let prepared = state.gpu_witness.take().ok_or(ExecutionError::GpuFailure)?;
        state.prove_gpu_in_run_with_report(
            WitnessOwner::Consumed(prepared),
            admission.public(),
            admission.witness(),
            run,
        )
    }
}

impl PreparedProgram {
    pub(super) fn prove_gpu_in_run_with_report(
        &self,
        prepared: WitnessOwner<'_, gpu_hash::device::PreparedWitness>,
        public: &[Val],
        witness: &[Val],
        run: Run,
    ) -> Result<(BatchProof<Config>, crate::proving::Report), ExecutionError> {
        if public.len() != self.air.program().public_values() {
            return Err(ExecutionError::PublicInputCount);
        }
        if witness.len() != self.air.program().witness_values() {
            return Err(ExecutionError::WitnessCount);
        }
        randomness::resources::check_worker(quotient_pcs::gpu_randomness_enabled(), None)
            .map_err(|_| ExecutionError::GpuFailure)?;
        challenger::resources::check_worker(quotient_pcs::gpu_transcript_enabled())
            .map_err(|_| ExecutionError::GpuFailure)?;
        let config = profile::make_proving_config_with_host_budget(self.gpu_pcs_host_allowance)
            .map_err(|_| ExecutionError::GpuFailure)?;
        let session = config
            .pcs()
            .quotient_session()
            .map_err(|_| ExecutionError::GpuFailure)?;
        let trace = prepared.trace_and_retire(|prepared| {
            run.measure(Stage::WitnessTrace, Backend::OpenCl, || {
                let _witness_observation = session
                    .observe_witness(&run)
                    .map_err(|_| ExecutionError::GpuFailure)?;
                tracing::info_span!(target: "lattica_block_v2_perf", "GPU execution trace")
                    .in_scope(|| {
                        gpu_backend::trace(
                            prepared,
                            &session,
                            public,
                            witness,
                            self.gpu_host_allowance,
                        )
                    })
            })
            .map_err(|_| ExecutionError::ProvingPolicy)?
        })?;
        // The owned variant has retired its instruction allocation and host
        // schedule here. The retained variant leaves its registration intact.
        // Both continue through identical proof machinery and native receipts.
        let proof = gpu_quotient_prover::prove_batch(
            &config,
            vec![gpu_quotient_prover::ProvingInstance::from_device(
                &self.air, trace, public,
            )],
            &self.data,
            gpu_hash::CandidateMmcs::release_quotient_prefix,
            |_, _| panic!("GPU witness mode cannot use host quotient commitment"),
            &run,
        );
        let report = run
            .finish(true)
            .map_err(|_| ExecutionError::ProvingPolicy)?;
        Ok((proof, report))
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests;
