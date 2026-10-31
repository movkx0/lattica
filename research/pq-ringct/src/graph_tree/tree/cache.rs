//! Cache adapters for actual registration-derived graph keys. Storage never
//! reconstructs a key, changes a graph span, or supplies a verification token.
use super::*;
use crate::outer_cache::ProofCache;
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

impl NodeKey {
    pub(super) fn cache_identity(&self, context: &GraphContext) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(b"lattica-pq-registered-graph-node-cache-v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update((self.height as u64).to_le_bytes());
        hash.update((self.cap.len() as u64).to_le_bytes());
        for value in self.cap.iter().flatten() {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        // The header binds the trusted plan/profile, exact interval and level,
        // external context/statement and complete graph-node manifest.
        let expected = header(&self.spec, context);
        hash.update((expected.len() as u64).to_le_bytes());
        for value in expected {
            hash.update(value.as_canonical_u64().to_le_bytes());
        }
        hash.finalize().into()
    }
}

impl PreparedNode {
    pub(super) fn prove_or_load(
        &self,
        cache: &ProofCache,
        context: &GraphContext,
    ) -> Result<(NodeKey, NodeProof, bool)> {
        let key = self.key();
        let expected = header(&self.spec, context);
        require(
            self.public == expected,
            "prepared graph node context mismatch",
        )?;
        let identity = key.cache_identity(context);
        if let Some((public, proof)) = cache
            .load_verified(&identity, &expected, |public, proof| {
                key.verifier.verify(proof, public)
            })
            .map_err(err)?
        {
            return Ok((key, NodeProof { public, proof }, true));
        }
        cache.proof_attempt();
        let proof = self.prove()?;
        cache.fresh_proof();
        cache
            .store_verified(&identity, &proof.public, &proof.proof, |public, proof| {
                key.verifier.verify(proof, public)
            })
            .map_err(err)?;
        Ok((key, proof, false))
    }
}

impl CompiledNode {
    /// Register through an explicit worker context; the current node's trusted
    /// spec/publics are never taken from the worker's immutable program cache.
    pub fn prove_or_load_with_context(
        self,
        execution: &crate::execution::ProvingContext,
        cache: &ProofCache,
        context: &GraphContext,
    ) -> Result<(NodeKey, NodeProof, bool)> {
        require(
            self.geometry()?.retained_lde_bytes <= execution.host_bytes(),
            "graph node exceeds retained-LDE host admission; this is not a peak-memory bound",
        )?;
        let Self {
            program,
            spec,
            public,
            witness,
        } = self;
        let scope = format!(
            "graph span=[{},{}] level={} cache_policy={:?}",
            spec.first,
            spec.count,
            spec.level,
            cache.policy()
        );
        require(
            public == header(&spec, context),
            &format!("{scope}: prepared graph node context mismatch"),
        )?;
        execution.with_registered_shared(program, |registered| {
            let key = NodeKey {
                spec: spec.clone(), height: registered.air().program().height(),
                cap: registered.preprocessing_cap().roots().to_vec(), verifier: registered.verifier(),
            };
            let identity = key.cache_identity(context);
            let detail = format!("graph span=[{},{}] level={} program={:02x?} registered_id={:?} cap_sha3={:02x?} cache_identity={:02x?} cache_policy={:?}",
                spec.first, spec.count, spec.level, registered.program_identity(), registered.id(), crate::proof_cache_policy::cap_identity(&key.cap), identity, cache.policy());
            let work = || -> std::result::Result<_, String> {
                if let Some((public, proof)) = cache.load_verified(&identity, &public,
                    |public, proof| key.verifier.verify(proof, public)).map_err(|e| e.to_string())? {
                    return Ok((key, NodeProof { public, proof }, true));
                }
                cache.proof_attempt();
                let proof = registered.prove(&public, &witness)?;
                registered.verify(&proof, &public)?;
                cache.fresh_proof();
                cache.store_verified(&identity, &public, &proof,
                    |public, proof| key.verifier.verify(proof, public)).map_err(|e| e.to_string())?;
                Ok((key, NodeProof { public, proof }, false))
            };
            work().map_err(|error| format!("{detail}: {error}"))
        }).map_err(|error| err(format!("{scope}: {error}")))
    }
}
