//! Persistent actual proofs under a freshly registered, trusted program key.
use super::*;
use sha3::{Digest, Sha3_256};

pub struct CacheOutcome {
    pub key: NodeKey,
    pub proof: NodeProof,
    pub cache_hit: bool,
    pub identity: [u8; 32],
}

fn cache_identity(key: &NodeKey, public: &[Val]) -> Result<[u8; 32]> {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/matrict/component-outer-cache/v1");
    hash.update(crate::graph_proofs::compiled_source_fingerprint());
    hash.update(key.spec.contract.profile);
    for value in [
        key.height as u64,
        key.spec.contract.tag(),
        u64::from(key.spec.contract.request),
        u64::from(key.spec.contract.total),
        u64::from(key.spec.first),
        u64::from(key.spec.count),
        u64::from(key.spec.level),
    ] {
        hash.update(value.to_le_bytes());
    }
    for value in key.spec.contract.descriptor_root()? {
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
    fn cache_identity(&self, key: &NodeKey) -> Result<[u8; 32]> {
        cache_identity(key, &self.public)
    }

    /// Consumes the prepared program so its preprocessing LDE is released on
    /// both hits and misses. The disk never supplies a verification key.
    pub fn prove_or_load(self, cache: &OuterProofCache) -> Result<CacheOutcome> {
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
        Ok(CacheOutcome {
            key,
            proof,
            cache_hit,
            identity,
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
    ) -> Result<CacheOutcome> {
        self.prove_or_load_with_context_inner(execution, cache, None)
    }

    /// Prove a fresh outer node after the caller reserves retained siblings and
    /// other live owners. The allowance is for registered GPU preparation and
    /// proving, not independent verification scratch or whole-process peak RSS.
    /// Failure after registration starts propagates without retry or fallback.
    pub fn prove_fresh_with_context_and_host_allowance(
        self,
        execution: &crate::execution::ProvingContext,
        cache: &OuterProofCache,
        remaining_host_bytes: u64,
    ) -> Result<CacheOutcome> {
        require(
            execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired
                && cache.policy() == crate::proof_cache_policy::ProofCachePolicy::FreshOnly,
            "bounded outer proving requires GpuRequired and FreshOnly",
        )?;
        require(
            remaining_host_bytes != 0 && remaining_host_bytes <= execution.host_bytes(),
            "bounded outer remaining host allowance",
        )?;
        self.prove_or_load_with_context_inner(execution, cache, Some(remaining_host_bytes))
    }

    fn prove_or_load_with_context_inner(
        self,
        execution: &crate::execution::ProvingContext,
        cache: &OuterProofCache,
        remaining_host_bytes: Option<u64>,
    ) -> Result<CacheOutcome> {
        require(
            self.geometry()?.retained_lde_bytes
                <= remaining_host_bytes.unwrap_or_else(|| execution.host_bytes()),
            "component exceeds retained-LDE host admission; this is not a peak-memory bound",
        )?;
        let Self {
            program,
            spec,
            public,
            witness,
        } = self;
        let scope = format!(
            "component request={} span=[{},{}] level={}",
            spec.contract.request, spec.first, spec.count, spec.level
        );
        let prove = |registered: &crate::execution::RegisteredTemplate| {
            let key = NodeKey { spec: spec.clone(), height: registered.air().program().height(),
                cap: registered.preprocessing_cap().roots().to_vec(), verifier: registered.verifier() };
            let identity = cache_identity(&key, &public).map_err(|e| format!("{e:?}"))?;
            let detail = format!("{scope} program={:02x?} registered_id={:?} cap_sha3={:02x?} cache_identity={:02x?} cache_policy={:?}",
                registered.program_identity(), registered.id(), crate::proof_cache_policy::cap_identity(&key.cap), identity, cache.policy());
            let work = || -> std::result::Result<_, String> {
                let cached = if remaining_host_bytes.is_some() {
                    None
                } else {
                    cache.load_verified(&identity, &public,
                        |public, proof| key.verifier.verify(proof, public)).map_err(|e| e.to_string())?
                };
                let (public, proof, cache_hit) = match cached {
                    Some((public, proof)) => (public, proof, true),
                    None => {
                        cache.proof_attempt();
                        let proof = registered.prove(&public, &witness)?;
                        registered.verify(&proof, &public)?;
                        cache.fresh_proof();
                        if remaining_host_bytes.is_none() {
                            cache.store_verified(&identity, &public, &proof,
                                |public, proof| key.verifier.verify(proof, public)).map_err(|e| e.to_string())?;
                        }
                        (public, proof, false)
                    }
                };
                Ok(CacheOutcome { key, proof: NodeProof { public, proof }, cache_hit, identity })
            };
            work().map_err(|error| format!("{detail}: {error}"))
        };
        let result = if let Some(host_bytes) = remaining_host_bytes {
            execution.with_registered_shared_with_host_budget(program, host_bytes, prove)
        } else {
            execution.with_registered_shared(program, prove)
        };
        result.map_err(|error| err(format!("{scope}: {error}")))
    }
}
