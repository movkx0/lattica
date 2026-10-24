//! Verified, source-bound cache for actual producer branch proofs.
use super::*;
use sha3::{Digest, Sha3_256};
fn cache_identity(key: &NodeKey, public: &[Val]) -> Result<[u8; 32]> {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/matrict/producer-branch-outer-cache/v1");
    hash.update(crate::graph_proofs::compiled_source_fingerprint());
    hash.update(key.spec.profile);
    hash.update((key.height as u64).to_le_bytes());
    hash.update(key.spec.operation.to_le_bytes());
    hash.update(key.spec.descriptor.tag().to_le_bytes());
    for value in key.spec.descriptor_root()? {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    hash.update((key.cap.len() as u64).to_le_bytes());
    for value in key.cap.iter().flatten() {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    hash.update((public.len() as u64).to_le_bytes());
    for value in public {
        hash.update(value.as_canonical_u64().to_le_bytes());
    }
    Ok(hash.finalize().into())
}

impl PreparedNode {
    pub(super) fn cache_identity(&self, key: &NodeKey) -> Result<[u8; 32]> {
        cache_identity(key, &self.public)
    }
    pub fn prove_or_load(self, cache: &OuterProofCache) -> Result<ProvenBranch> {
        let key = self.key();
        let identity = self.cache_identity(&key)?;
        let cached = cache
            .load_verified(&identity, &self.public, |public, proof| {
                key.verifier
                    .verify(proof, public)
                    .map_err(|e| format!("{e:?}"))
            })
            .map_err(err)?;
        let (proof, cache_hit) = match cached {
            Some((public, proof)) => (NodeProof { public, proof }, true),
            None => {
                cache.proof_attempt();
                let proof = self.prove()?;
                cache.fresh_proof();
                cache
                    .store_verified(&identity, &proof.public, &proof.proof, |public, proof| {
                        key.verifier
                            .verify(proof, public)
                            .map_err(|e| format!("{e:?}"))
                    })
                    .map_err(err)?;
                (proof, false)
            }
        };
        drop(self);
        Ok(ProvenBranch {
            key,
            proof,
            cache_hit,
        })
    }
}

impl CompiledNode {
    /// Reuse only exact registered metadata; every returned key belongs to the
    /// current compiled statement, and proof reuse follows the explicit cache policy.
    pub fn prove_or_load_with_context(
        self,
        execution: &crate::execution::ProvingContext,
        cache: &OuterProofCache,
    ) -> Result<ProvenBranch> {
        require(
            self.geometry()?.retained_lde_bytes <= execution.host_bytes(),
            "producer branch exceeds retained-LDE host admission; this is not a peak-memory bound",
        )?;
        let Self {
            program,
            spec,
            public,
            witness,
        } = self;
        let scope = format!(
            "producer operation={} role={:?}",
            spec.operation,
            spec.descriptor.role()
        );
        execution.with_registered_shared(program, |registered| {
            let key = NodeKey { spec: spec.clone(), height: registered.air().program().height(),
                cap: registered.preprocessing_cap().roots().to_vec(), verifier: registered.verifier() };
            let identity = cache_identity(&key, &public).map_err(|e| format!("{e:?}"))?;
            let detail = format!("{scope} program={:02x?} registered_id={:?} cap_sha3={:02x?} cache_identity={:02x?} cache_policy={:?}",
                registered.program_identity(), registered.id(), crate::proof_cache_policy::cap_identity(&key.cap), identity, cache.policy());
            let work = || -> std::result::Result<_, String> {
                let cached = cache.load_verified(&identity, &public,
                    |public, proof| key.verifier.verify(proof, public)).map_err(|e| e.to_string())?;
                let (public, proof, cache_hit) = match cached {
                    Some((public, proof)) => (public, proof, true),
                    None => {
                        cache.proof_attempt();
                        let proof = registered.prove(&public, &witness)?;
                        registered.verify(&proof, &public)?;
                        cache.fresh_proof();
                        cache.store_verified(&identity, &public, &proof,
                            |public, proof| key.verifier.verify(proof, public)).map_err(|e| e.to_string())?;
                        (public, proof, false)
                    }
                };
                Ok(ProvenBranch { key, proof: NodeProof { public, proof }, cache_hit })
            };
            work().map_err(|error| format!("{detail}: {error}"))
        }).map_err(|error| err(format!("{scope}: {error}")))
    }
}
