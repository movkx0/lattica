//! Proving against an already approved preprocessing commitment.
//!
//! This type has no standalone diagnostic identity. Setup still constructs the
//! complete preprocessing and authenticates its cap before recording success.
use super::*;

pub(crate) struct RegistryProgram {
    prepared: PreparedProgram,
}

impl RegistryProgram {
    pub(crate) fn new_in_run(
        air: MachineAir,
        budget: u64,
        run: crate::proving::Run,
        expected_cap: &[[Val; 4]],
    ) -> Result<Self, super::super::analysis::AdmissionError> {
        let (prepared, identity) =
            PreparedProgram::prepare(air, budget, run, SetupIdentity::RegistryCap(expected_cap))?;
        assert!(
            identity.is_none(),
            "registry setup requested a diagnostic identity"
        );
        Ok(Self { prepared })
    }

    pub(crate) fn air(&self) -> &MachineAir {
        self.prepared.air()
    }

    pub(crate) fn preprocessing_cap(&self) -> &p3_batch_stark::Commitment<Config> {
        self.prepared.preprocessing_cap()
    }

    pub(crate) fn verifier(&self) -> RegisteredVerifier {
        self.prepared.verifier()
    }

    pub(crate) fn reuse_preprocessing(
        &self,
        request: &crate::proving::Run,
    ) -> Result<(), crate::proving::Error> {
        self.prepared.reuse_preprocessing(request)
    }

    pub(crate) fn prove_in_run(
        &self,
        public: &[Val],
        witness: &[Val],
        run: crate::proving::Run,
    ) -> Result<BatchProof<Config>, ExecutionError> {
        self.prepared.prove_in_run(public, witness, run)
    }
}

#[cfg(test)]
#[path = "registry_prover_tests.rs"]
mod tests;
