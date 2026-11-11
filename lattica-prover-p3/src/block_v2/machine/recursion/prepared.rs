//! Bounded CPU oracle for the architecture gate. This owner is deliberately
//! unavailable to the production aggregation selector until GPU qualification.
use super::*;
use crate::block_v2::profile::{self, Config};
use p3_batch_stark::{prove_batch, verify_batch, BatchProof, ProverData, StarkInstance};

pub struct PreparedRecursionTemplate {
    template: RecursionTemplate,
    airs: Vec<air::TableAir>,
    data: ProverData<Config>,
}

/// Locally generated oracle proof; no unbounded external proof decoder.
pub struct RecursionExecutionProof {
    pub(super) inner: BatchProof<Config>,
}
impl RecursionExecutionProof {
    pub fn retained_backing_bytes(&self, maximum: usize) -> Result<usize, ExecutionError> {
        super::super::backend::retained_proof_capacity_bytes(&self.inner, maximum)
    }
}

impl RecursionTemplate {
    pub fn prepare_cpu_reference(&self) -> Result<PreparedRecursionTemplate, String> {
        let geometry = self.geometry()?;
        // A reference correctness job must finish in minutes. Full inputs are
        // geometry-only until the architectural work and GPU admission gates.
        if geometry.tables.iter().any(|t| t.height > 256) || geometry.lde_payload_bytes > 256 << 20
        {
            return Err("recursion CPU oracle exceeds bounded correctness geometry".into());
        }
        if !geometry.degree_gate || !geometry.quotient_gate {
            return Err("recursion architecture degree gate".into());
        }
        let airs = self.airs();
        let degrees = airs
            .iter()
            .map(|air| air.height.ilog2() as usize + 1)
            .collect::<Vec<_>>();
        let data = ProverData::from_airs_and_degrees(
            &profile::recursion_reference_preprocessing_config(),
            &airs,
            &degrees,
        );
        Ok(PreparedRecursionTemplate {
            template: self.clone(),
            airs,
            data,
        })
    }
}

impl PreparedRecursionTemplate {
    pub fn verifier(&self) -> RecursionVerifier {
        RecursionVerifier::new(self.template.clone(), self.preprocessing_cap().clone())
    }

    pub fn compile_verifier(
        &self,
        proof: &RecursionExecutionProof,
        limits: super::super::program::ConstructionLimits,
    ) -> Result<CompiledRecursionVerifier, String> {
        parent::compile(&self.template, self.preprocessing_cap(), proof, limits)
    }
    pub fn identity(&self) -> [u8; 32] {
        self.template.identity()
    }
    pub fn preprocessing_cap(&self) -> &p3_batch_stark::Commitment<Config> {
        &self
            .data
            .common
            .preprocessed
            .as_ref()
            .expect("trusted preprocessed tables")
            .commitment
    }
    pub fn prove_cpu_reference(
        &self,
        public: &[Val],
        witness: &[Val],
    ) -> Result<RecursionExecutionProof, String> {
        let traces = self
            .template
            .traces(public, witness)
            .map_err(|e| format!("recursion witness: {e:?}"))?;
        let instances = self
            .airs
            .iter()
            .zip(&traces)
            .map(|(air, trace)| StarkInstance {
                air,
                trace,
                public_values: if air.kind == 3 {
                    public.to_vec()
                } else {
                    vec![]
                },
            })
            .collect::<Vec<_>>();
        // Always fresh private randomness. Deterministic setup configuration
        // above is never passed to the witness prover.
        let proof = RecursionExecutionProof {
            inner: prove_batch(&profile::make_cpu_config(), &instances, &self.data),
        };
        self.verify_cpu_reference(&proof, public)?;
        Ok(proof)
    }
    pub fn verify_cpu_reference(
        &self,
        proof: &RecursionExecutionProof,
        public: &[Val],
    ) -> Result<(), String> {
        if public.len() != self.template.program.publics
            || proof.inner.degree_bits
                != self
                    .airs
                    .iter()
                    .map(|air| air.height.ilog2() as usize + 1)
                    .collect::<Vec<_>>()
        {
            return Err("recursion trusted shape mismatch".into());
        }
        verify_batch(
            &profile::make_cpu_config(),
            &self.airs,
            &proof.inner,
            &self
                .airs
                .iter()
                .map(|air| {
                    if air.kind == 3 {
                        public.to_vec()
                    } else {
                        vec![]
                    }
                })
                .collect::<Vec<_>>(),
            &self.data.common,
        )
        .map_err(|e| format!("recursion verification: {e:?}"))
    }
}
