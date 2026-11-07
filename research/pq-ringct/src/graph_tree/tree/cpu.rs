//! CPU research adapters retain the actual registered graph key and scope.
use super::*;
impl NodeKey {
    /// Newly retained key backing. The shared plan is already held by the
    /// coordinator's live input Case and remains under its metadata reservation.
    pub(crate) fn cpu_retained_key_bytes(&self) -> Result<u64> {
        let cap = self
            .cap
            .capacity()
            .checked_mul(std::mem::size_of::<[Val; 4]>())
            .ok_or_else(|| err("key capacity overflow"))?;
        let bytes = self
            .verifier
            .cached_metadata_bytes()
            .checked_add(cap)
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Self>() + 4 * std::mem::size_of::<usize>())
            })
            .ok_or_else(|| err("key capacity overflow"))?;
        u64::try_from(bytes).map_err(err)
    }
}
use crate::{component_tree::cpu::Timings, execution::ProvingContext};
use lattica_prover_p3::proving::Policy;
use sha3::{Digest, Sha3_256};
use std::time::Instant;

impl CompiledNode {
    pub(crate) fn cpu_output_bytes(&self) -> Result<u64> {
        crate::component_tree::cpu::output_bytes(
            &self.program,
            self.public.capacity(),
            self.witness.capacity(),
        )
        .map_err(err)
    }
    pub(crate) fn cpu_admission_bytes(&self) -> Result<u64> {
        require(
            self.program.construction_host_bytes() <= 2 << 30
                && self.public.len().saturating_add(self.witness.len()) <= 1 << 20,
            "CPU graph compiled output exceeds reserved capacity",
        )?;
        crate::component_tree::cpu::admission(&self.geometry()?).map_err(err)
    }
    pub(crate) fn cpu_admission_bytes_with_variant(
        &self,
        variant: lattica_prover_p3::block_v2::cpu_commitment::Variant,
    ) -> Result<u64> {
        require(
            self.program.construction_host_bytes() <= 2 << 30
                && self.public.len().saturating_add(self.witness.len()) <= 1 << 20,
            "CPU graph compiled output exceeds reserved capacity",
        )?;
        crate::component_tree::cpu::admission_for(&self.geometry()?, variant).map_err(err)
    }
    pub(crate) fn cpu_identity(&self) -> Result<[u8; 32]> {
        let mut hash = Sha3_256::new();
        hash.update(b"ringct-cpu-prepared-program-v1");
        self.program
            .visit_manifest_fields(&mut |word| {
                hash.update(word.to_le_bytes());
                Ok(())
            })
            .map_err(err)?;
        Ok(hash.finalize().into())
    }
    pub(crate) fn prove_cpu(
        self,
        execution: &ProvingContext,
    ) -> Result<(NodeKey, NodeProof, Timings)> {
        require(
            execution.policy() == Policy::CpuRequired,
            "graph CPU proof requires CpuRequired",
        )?;
        require(
            self.cpu_admission_bytes_with_variant(execution.cpu_variant())?
                <= execution.host_bytes(),
            "CPU graph estimate exceeds allowance",
        )?;
        let Self {
            spec,
            program,
            public,
            witness,
        } = self;
        let start = Instant::now();
        execution
            .with_registered_shared(program, |registered| {
                let registration_ns = start.elapsed().as_nanos();
                let key = NodeKey {
                    spec,
                    height: registered.air().program().height(),
                    cap: registered.preprocessing_cap().roots().to_vec(),
                    verifier: registered.verifier(),
                };
                let start = Instant::now();
                let proof = registered.prove(&public, &witness)?;
                let proving_ns = start.elapsed().as_nanos();
                let start = Instant::now();
                key.verifier.verify(&proof, &public)?;
                let verification_ns = start.elapsed().as_nanos();
                Ok((
                    key,
                    NodeProof { public, proof },
                    Timings {
                        prepared_storage_bytes: registered.cpu_prepared_storage_bytes(),
                        registration_ns,
                        proving_ns,
                        verification_ns,
                    },
                ))
            })
            .map_err(err)
    }
}
