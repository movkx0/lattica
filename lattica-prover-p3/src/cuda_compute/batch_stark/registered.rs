//! Registry-authenticated, runtime-local machine preparation and proof attempts.
//! Caller policy supplies the approved key; a GPU-produced root is never its own
//! approval. These component APIs do not yet route production worker requests.
use super::*;
use crate::proving::{
    Backend, CachedScope, Capabilities, CoverageScope, Profile, Report, Request, Run, Stage,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Bound the handle, provenance inventory, report staging and both cap views.
// Borrowed source capacities are charged by batch preparation and proof plans.
const REGISTERED_HOST: usize = (16 << 10) + 2 * CAP_BYTES;
const PREPROCESSING: [Stage; 5] = [
    Stage::Preprocessing,
    Stage::Randomness,
    Stage::Hiding,
    Stage::Transform,
    Stage::Commitment,
];

/// Public schema and cap obtained from the caller's authenticated registry.
/// Never populate this key from a proof header or from this prover's output.
#[derive(Clone, Copy)]
pub(crate) struct RegisteredKey<'a> {
    pub profile: Profile,
    pub height: usize,
    pub public_values: usize,
    pub witness_values: usize,
    pub cap: &'a [[Val; 4]],
}

/// Owns its executor and immutable public preparation, never private inputs or
/// random streams. A handle cannot be moved to another CUDA runtime or worker.
pub(crate) struct RegisteredMachine {
    engine: Arc<BatchStarks>,
    prepared: PreparedBatch,
    preprocessing_receipt: CachedScope,
    _host: Reservation,
}

pub(crate) struct RegisteredProof {
    pub proof: NativeBatchProof,
    pub report: Report,
    pub admission: ProofPlan,
}

fn capabilities(scope: CoverageScope, stages: &[Stage]) -> Capabilities {
    let mut capabilities =
        Capabilities::cpu(Profile::BlockV2Cubic, true, true).scoped(scope, stages);
    for &stage in stages {
        capabilities.set(stage, Backend::Cuda);
    }
    capabilities
}

fn finish<T>(run: Run, result: Result<T>) -> Result<(T, Report)> {
    match result {
        Ok(value) => {
            let report = run.finish(true).map_err(super::super::error)?;
            // Compatible policy also cannot publish a partial native result.
            if !report.succeeded || !report.stage_coverage_complete {
                return Err("CUDA registered component lacks complete execution receipts".into());
            }
            Ok((value, report))
        }
        Err(error) => {
            let _ = run.finish(false);
            Err(error)
        }
    }
}

impl RegisteredKey<'_> {
    fn check(&self, air: &MachineAir) -> Result<()> {
        let program = air.program();
        let log = program.height().ilog2() as usize;
        let roots = 1 << (log + 1 + parameters().log_blowup).min(profile::CAP_HEIGHT);
        if self.profile != Profile::BlockV2Cubic
            || self.height != program.height()
            || self.public_values != program.public_values()
            || self.witness_values != program.witness_values()
            || self.cap.len() != roots
        {
            return Err(
                "CUDA registered program schema or cap geometry differs from approval".into(),
            );
        }
        Ok(())
    }
}

impl BatchStarks {
    pub(crate) fn preprocessing_capabilities() -> Capabilities {
        capabilities(CoverageScope::Preprocessing, &PREPROCESSING)
    }

    pub(crate) fn prepare_registered(
        self: &Arc<Self>,
        air: &MachineAir,
        approved: RegisteredKey<'_>,
        request: Request,
        host_bytes: usize,
        mode: Specialization,
    ) -> Result<(RegisteredMachine, Report)> {
        let run = Run::new(
            "cuda_registered_preprocessing",
            request,
            Self::preprocessing_capabilities(),
        )
        .map_err(super::super::error)?;
        self.prepare_registered_in_run(air, approved, run, host_bytes, mode)
    }

    pub(crate) fn prepare_registered_in_run(
        self: &Arc<Self>,
        air: &MachineAir,
        approved: RegisteredKey<'_>,
        run: Run,
        host_bytes: usize,
        mode: Specialization,
    ) -> Result<(RegisteredMachine, Report)> {
        run.cuda_require_capabilities(&Self::preprocessing_capabilities())
            .map_err(super::super::error)?;
        approved.check(air)?;
        if host_bytes < REGISTERED_HOST {
            return Err("CUDA registered metadata exceeds host allowance".into());
        }
        let result = self.runtime.reported(&run, || {
            let host = self.runtime.state.budget.public_program(REGISTERED_HOST)?;
            let prepared = self.prepare(&[air], host_bytes, mode)?;
            if prepared.preprocessing_cap()?.roots() != approved.cap {
                return Err("CUDA preprocessing commitment differs from approved registry".into());
            }
            Ok((prepared, host))
        });
        let ((prepared, host), report) = finish(run, result)?;
        let preprocessing_receipt =
            CachedScope::preprocessing(&report).map_err(super::super::error)?;
        if preprocessing_receipt.retained_host_bytes()? > REGISTERED_HOST - 2 * CAP_BYTES {
            return Err("CUDA preprocessing provenance exceeds host allowance".into());
        }
        Ok((
            RegisteredMachine {
                engine: self.clone(),
                prepared,
                preprocessing_receipt,
                _host: host,
            },
            report,
        ))
    }
}

impl RegisteredMachine {
    pub(crate) fn proof_capabilities(&self) -> Capabilities {
        // Public values are generated as part of the witness trace when the
        // program declares them. Preparation is separate, immutable work.
        let public = self.prepared.instances[0].layout.num_public_values != 0;
        let stages: Vec<_> = Stage::ARITHMETIC
            .into_iter()
            .filter(|s| *s != Stage::Preprocessing && (public || *s != Stage::PublicValues))
            .collect();
        capabilities(CoverageScope::RegisteredProof, &stages)
    }

    pub(crate) fn preprocessing_cap(&self) -> Result<Cap> {
        self.prepared.preprocessing_cap()
    }

    /// Records cached provenance in an enclosing request without inventing
    /// fresh device work. The enclosing request owns its other component slots.
    pub(crate) fn reuse_preprocessing(&self, request: &Run) -> Result<()> {
        self.prepared
            .preprocessing
            .check_runtime(&self.engine.runtime)?;
        request
            .reuse_preprocessing("preprocessing", &self.preprocessing_receipt)
            .map_err(super::super::error)
    }

    pub(crate) fn prove(
        &self,
        input: MachineInputs<'_>,
        request: Request,
        host_bytes: usize,
    ) -> Result<RegisteredProof> {
        let run = Run::new("cuda_registered_proof", request, self.proof_capabilities())
            .map_err(super::super::error)?;
        self.prove_in_run(input, run, host_bytes)
    }

    pub(crate) fn prove_in_run(
        &self,
        input: MachineInputs<'_>,
        run: Run,
        host_bytes: usize,
    ) -> Result<RegisteredProof> {
        self.prove_attempt(input, run, host_bytes, prove::Fault::None)
    }

    fn prove_attempt(
        &self,
        input: MachineInputs<'_>,
        run: Run,
        host_bytes: usize,
        fault: prove::Fault,
    ) -> Result<RegisteredProof> {
        run.cuda_require_capabilities(&self.proof_capabilities())
            .map_err(super::super::error)?;
        let inputs = [input];
        let result = self.engine.runtime.reported(&run, || {
            // The reporting guard excludes submissions from other threads.
            // Read the live snapshot here, and admit the complete lifecycle
            // before generating or importing any private seed material.
            let pcs_host = self
                .engine
                .preflight_proof(&self.prepared, &inputs, host_bytes)?;
            let mut admission = self.engine.proof_plan(&self.prepared, pcs_host, 3)?;
            admission.host_peak_bytes += host_bytes - pcs_host;
            let fresh = || {
                self.engine
                    .randoms
                    .import(ChaCha20Rng::from_rng(&mut rand::rng()))
            };
            let masks = fresh()?;
            let commitments = fresh()?;
            let fri = fresh()?;
            let proof = self.engine.prove_impl(
                &self.prepared,
                &inputs,
                StarkRandomness {
                    masks: &masks,
                    commitments: &commitments,
                    fri: &fri,
                },
                host_bytes,
                fault,
            )?;
            Ok((proof, admission))
        });
        let ((proof, admission), report) = finish(run, result)?;
        Ok(RegisteredProof {
            proof,
            report,
            admission,
        })
    }
}

#[cfg(test)]
mod tests;
