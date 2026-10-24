//! Native source proof provisioning for an exact registered MatRiCT graph.
//! Cached proofs are checked against the current source roots and native AIR.
//! The graph leaf must still emit the complete recursive verifier and joins.
use crate::proof_cache_policy::{Control, Family, ProofCachePolicy};
use crate::{
    graph_tree::{GraphContext, Plan},
    proof_air::{self, join::ProofArtifact, ProofAir, ProofValues},
    rust_verify::{
        committed_backend::{Source, UnprovedRelationGraph},
        Proof,
    },
    statement_air::{
        self,
        bundle::{StatementBundle, StatementProof},
        StatementAir,
    },
};
use lattica_prover_p3::block_v2::{machine::program::Val, profile};
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

#[cfg(feature = "opencl")]
mod preparation;

#[derive(Debug)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn err(e: impl std::fmt::Debug) -> Error {
    Error(format!("{e:?}"))
}
fn require(ok: bool, why: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error(why.into()))
    }
}

pub struct SourceFactory<'a> {
    statement: &'a [u8],
    private: ProofValues,
    setup_seed: [u8; 32],
    expected_statement: [Val; 8],
    expected_private: [Val; 4],
    identity: [u8; 32],
    memory_budget: u64,
}
impl<'a> SourceFactory<'a> {
    /// Policy-aware factory preparation. GPU-required work uses raw source
    /// values and the graph's existing roots, then hashes all framing on GPU.
    pub fn new_with_context(
        plan: &Plan,
        graph: &UnprovedRelationGraph,
        context: &GraphContext,
        statement: &'a [u8],
        proof: &[u8],
        memory_budget: u64,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<Self> {
        if let Some(execution) = execution {
            if execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
                #[cfg(feature = "opencl")]
                {
                    let host_bytes =
                        usize::try_from(memory_budget.min(execution.host_bytes())).map_err(err)?;
                    let (factory, _) = execution
                        .with_witness_preparation(host_bytes, |operations| {
                            Self::new_on_gpu(
                                plan,
                                graph,
                                context,
                                statement,
                                proof,
                                memory_budget,
                                operations,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map_err(err)?;
                    return Ok(factory);
                }
                #[cfg(not(feature = "opencl"))]
                return Err(Error("GPU source preparation unavailable".into()));
            }
        }
        Self::new(plan, graph, context, statement, proof, memory_budget)
    }

    pub fn new(
        plan: &Plan,
        graph: &UnprovedRelationGraph,
        context: &GraphContext,
        statement: &'a [u8],
        proof: &[u8],
        memory_budget: u64,
    ) -> Result<Self> {
        require(memory_budget != 0, "zero source proof memory budget")?;
        require(
            plan.node_manifest_hint(graph).map_err(err)? == context.node_manifest,
            "source graph manifest mismatch",
        )?;
        let sb = StatementBundle::from_bytes(statement).map_err(err)?;
        require(
            sb.setup_seed == graph.setup_seed(),
            "source statement setup mismatch",
        )?;
        let digest = crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            context.context,
            statement,
        )
        .map_err(err)?
        .digest
        .map(Val::from_u64);
        require(
            digest == context.statement,
            "source statement digest mismatch",
        )?;
        let private = ProofValues::from_proof(&Proof::decode(proof).map_err(err)?).map_err(err)?;
        let pb = private.bundle().map_err(err)?;
        // The trusted plan validates exact source positions and multiplicity.
        // These comparisons additionally bind the supplied source bytes to the
        // same graph hints that every actual source leaf will constrain.
        for node in graph.polynomials() {
            let expected = match node.source {
                Source::StatementPolynomial { position } => sb.polynomial_roots.get(position),
                Source::ProofPolynomial { position } => pb.roots.get(position),
                _ => continue,
            }
            .ok_or_else(|| Error("source polynomial position".into()))?;
            require(
                node.commitment == *expected,
                "source polynomial root mismatch",
            )?;
        }
        for node in graph.bytes() {
            let expected: [u8; 32] = match node.source {
                Source::Context => context.context,
                Source::StatementSeed => sb.setup_seed,
                Source::ProofAlpha => private.alpha,
                Source::StatementSerial { position } if position < 2 => core::array::from_fn(|i| {
                    sb.serial_words[position * 8 + i / 4].to_le_bytes()[i % 4]
                }),
                Source::StatementSerial { .. } => {
                    return Err(Error("source serial position".into()))
                }
                _ => continue,
            };
            require(node.values == expected, "source bytes mismatch")?;
        }
        let mut expected_statement = [Val::ZERO; 8];
        expected_statement[..4].copy_from_slice(&digest);
        expected_statement[4..].copy_from_slice(&sb.commitment());
        let expected_private = pb.commitment();
        let mut hash = Sha3_256::new();
        hash.update(b"lattica/matrict/native-source-factory/v1");
        hash.update(crate::graph_proofs::compiled_source_fingerprint());
        hash.update(plan.label());
        hash.update(context.context);
        hash.update(statement);
        hash.update(proof);
        Ok(Self {
            statement,
            private,
            setup_seed: sb.setup_seed,
            expected_statement,
            expected_private,
            identity: hash.finalize().into(),
            memory_budget,
        })
    }
    fn key(&self, kind: u8) -> [u8; 32] {
        let mut hash = Sha3_256::new();
        hash.update(self.identity);
        hash.update([kind]);
        hash.finalize().into()
    }
    fn admit(&self, width: usize, height: usize) -> Result<()> {
        // Planning heuristic only. Hard process caps remain necessary for
        // measurements; this is not a cryptographic or allocation guarantee.
        let cells = (width as u64)
            .checked_mul(height as u64)
            .and_then(|n| n.checked_mul(8))
            .ok_or_else(|| Error("source size overflow".into()))?;
        let estimate = cells
            .checked_mul(48)
            .and_then(|n| n.checked_add(512 << 20))
            .ok_or_else(|| Error("source estimate overflow".into()))?;
        require(
            estimate <= self.memory_budget,
            "source child exceeds estimate budget",
        )
    }
    pub fn verify_statement(&self, artifact: &StatementProof) -> Result<()> {
        require(
            artifact.public_values == self.expected_statement,
            "source statement public roots",
        )?;
        require(
            artifact.proof.degree_bits == statement_air::HEIGHT.ilog2() as usize + 1,
            "source statement degree",
        )?;
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            &StatementAir {
                setup_seed: self.setup_seed,
            },
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(err)
    }
    pub fn verify_private(&self, artifact: &ProofArtifact) -> Result<()> {
        require(
            artifact.public_values == self.expected_private,
            "source private public roots",
        )?;
        require(
            artifact.proof.degree_bits == proof_air::HEIGHT.ilog2() as usize + 1,
            "source private degree",
        )?;
        p3_uni_stark::verify(
            &profile::make_cpu_config(),
            &ProofAir,
            &artifact.proof,
            &artifact.public_values,
        )
        .map_err(err)
    }
    pub fn prove_statement(&self) -> Result<StatementProof> {
        self.admit(statement_air::WIDTH, statement_air::HEIGHT)?;
        let air = StatementAir {
            setup_seed: self.setup_seed,
        };
        let witness = air.generate(self.statement).map_err(err)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &air,
            witness.trace,
            &witness.public_values,
        );
        let artifact = StatementProof {
            public_values: witness.public_values,
            proof,
        };
        self.verify_statement(&artifact)?;
        Ok(artifact)
    }
    pub fn prove_private(&self) -> Result<ProofArtifact> {
        self.admit(proof_air::WIDTH, proof_air::HEIGHT)?;
        let witness = ProofAir.generate(&self.private).map_err(err)?;
        let proof = p3_uni_stark::prove(
            &profile::make_cpu_config(),
            &ProofAir,
            witness.trace,
            &witness.public_values,
        );
        let artifact = ProofArtifact {
            public_values: witness.public_values,
            proof,
        };
        self.verify_private(&artifact)?;
        Ok(artifact)
    }
    pub fn prove_statement_with_context(
        &self,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<StatementProof> {
        let Some(context) = execution else {
            return self.prove_statement();
        };
        if context.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
            #[cfg(feature = "opencl")]
            {
                let air = StatementAir {
                    setup_seed: self.setup_seed,
                };
                let artifact = air
                    .prove_gpu(
                        context,
                        self.statement,
                        usize::try_from(self.memory_budget).map_err(err)?,
                    )
                    .map_err(err)?;
                self.verify_statement(&artifact)?;
                return Ok(artifact);
            }
            #[cfg(not(feature = "opencl"))]
            return Err(Error("native GPU proving unavailable".into()));
        }
        context
            .with_native_cpu(|| self.prove_statement().map_err(|e| e.to_string()))
            .map_err(err)
    }
    pub fn prove_or_load_statement(&self, cache: &SourceCache) -> Result<StatementProof> {
        self.prove_or_load_statement_with_context(cache, None)
    }
    pub fn prove_or_load_statement_with_context(
        &self,
        cache: &SourceCache,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<StatementProof> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && cache.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(Error(
                "native GPU source coverage requires FreshOnly".into(),
            ));
        }
        if let Some((public, proof)) = cache.load(&self.key(1))? {
            let artifact = StatementProof {
                public_values: public
                    .try_into()
                    .map_err(|_| Error("source statement public width".into()))?,
                proof,
            };
            self.verify_statement(&artifact)?;
            cache.control.hit(Family::Sources);
            eprintln!("SOURCE_CACHE statement hit");
            return Ok(artifact);
        }
        cache.control.attempt(Family::Sources);
        let artifact = self.prove_statement_with_context(execution)?;
        cache.control.fresh(Family::Sources);
        cache.store(&self.key(1), &artifact.public_values, &artifact.proof)?;
        eprintln!("SOURCE_CACHE statement generated");
        Ok(artifact)
    }
    pub fn prove_private_with_context(
        &self,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<ProofArtifact> {
        let Some(context) = execution else {
            return self.prove_private();
        };
        if context.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
            #[cfg(feature = "opencl")]
            {
                let air = ProofAir;
                let artifact = air
                    .prove_gpu(
                        context,
                        &self.private,
                        usize::try_from(self.memory_budget).map_err(err)?,
                    )
                    .map_err(err)?;
                self.verify_private(&artifact)?;
                return Ok(artifact);
            }
            #[cfg(not(feature = "opencl"))]
            return Err(Error("native GPU proving unavailable".into()));
        }
        context
            .with_native_cpu(|| self.prove_private().map_err(|e| e.to_string()))
            .map_err(err)
    }
    pub fn prove_or_load_private(&self, cache: &SourceCache) -> Result<ProofArtifact> {
        self.prove_or_load_private_with_context(cache, None)
    }
    pub fn prove_or_load_private_with_context(
        &self,
        cache: &SourceCache,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<ProofArtifact> {
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && cache.control.policy() != ProofCachePolicy::FreshOnly
        {
            return Err(Error(
                "native GPU source coverage requires FreshOnly".into(),
            ));
        }
        if let Some((public, proof)) = cache.load(&self.key(2))? {
            let artifact = ProofArtifact {
                public_values: public
                    .try_into()
                    .map_err(|_| Error("source private public width".into()))?,
                proof,
            };
            self.verify_private(&artifact)?;
            cache.control.hit(Family::Sources);
            eprintln!("SOURCE_CACHE private hit");
            return Ok(artifact);
        }
        cache.control.attempt(Family::Sources);
        let artifact = self.prove_private_with_context(execution)?;
        cache.control.fresh(Family::Sources);
        cache.store(&self.key(2), &artifact.public_values, &artifact.proof)?;
        eprintln!("SOURCE_CACHE private generated");
        Ok(artifact)
    }
}

pub struct SourceCache {
    directory: PathBuf,
    limit: u64,
    control: Control,
}
type NativeProof = p3_uni_stark::Proof<profile::Config>;
impl SourceCache {
    pub fn new(directory: impl Into<PathBuf>, limit: u64) -> Result<Self> {
        Self::new_with_policy(directory, limit, ProofCachePolicy::default())
    }
    pub fn new_with_policy(
        directory: impl Into<PathBuf>,
        limit: u64,
        policy: ProofCachePolicy,
    ) -> Result<Self> {
        Self::new_with_control(directory, limit, Control::new(policy))
    }
    pub(crate) fn new_with_control(
        directory: impl Into<PathBuf>,
        limit: u64,
        control: Control,
    ) -> Result<Self> {
        require(
            (1..=64 << 20).contains(&limit),
            "source cache limit must be in1..=64MiB",
        )?;
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(err)?;
        Ok(Self {
            directory,
            limit,
            control,
        })
    }
    fn path(&self, key: &[u8; 32]) -> PathBuf {
        let name: String = key.iter().map(|v| format!("{v:02x}")).collect();
        self.directory.join(format!("{name}.json"))
    }
    fn load(&self, key: &[u8; 32]) -> Result<Option<(Vec<Val>, NativeProof)>> {
        if !self.control.read(Family::Sources) {
            return Ok(None);
        }
        let file = match fs::File::open(self.path(key)) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(err(e)),
        };
        require(
            file.metadata().map_err(err)?.len() <= self.limit,
            "source cache byte limit",
        )?;
        let mut bytes = Vec::new();
        file.take(self.limit + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        require(bytes.len() as u64 <= self.limit, "source cache byte limit")?;
        let (schema, stored_key, public, proof): (u32, [u8; 32], Vec<Val>, NativeProof) =
            serde_json::from_slice(&bytes).map_err(err)?;
        require(schema == 1 && stored_key == *key, "source cache schema/key")?;
        Ok(Some((public, proof)))
    }
    fn store(&self, key: &[u8; 32], public: &[Val], proof: &NativeProof) -> Result<()> {
        struct Bounded {
            bytes: Vec<u8>,
            limit: u64,
        }
        impl Write for Bounded {
            fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
                if input.len() as u64 > self.limit.saturating_sub(self.bytes.len() as u64) {
                    return Err(std::io::Error::other("source cache byte limit"));
                }
                self.bytes.extend_from_slice(input);
                Ok(input.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = Bounded {
            bytes: Vec::new(),
            limit: self.limit,
        };
        serde_json::to_writer(&mut output, &(1u32, key, public, proof)).map_err(err)?;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(err)?
            .as_nanos();
        let temporary = self
            .directory
            .join(format!(".source-{}-{nonce}.tmp", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&output.bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, self.path(key))?;
            fs::File::open(&self.directory)?.sync_all()
        })();
        let _ = fs::remove_file(temporary);
        result.map_err(err)
    }
}

#[cfg(all(test, feature = "native-matrict"))]
mod tests;

#[cfg(test)]
mod fresh_cache_tests {
    use super::*;
    #[test]
    fn fresh_source_reads_bypass_malformed_and_oversized_files_repeatedly() {
        let directory = std::env::temp_dir().join(format!(
            "lattica-source-fresh-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let control = Control::new(ProofCachePolicy::FreshOnly);
        let cache = SourceCache::new_with_control(&directory, 8, control.clone()).unwrap();
        let key = [23; 32];
        for payload in [b"invalid".as_slice(), &[0u8; 32], b"invalid"] {
            fs::write(cache.path(&key), payload).unwrap();
            assert!(cache.load(&key).unwrap().is_none());
        }
        let counts = control.snapshot();
        assert_eq!(counts.families["sources"].reads, 0);
        assert_eq!(counts.families["sources"].hits, 0);
        assert_eq!(counts.families["sources"].bypasses, 3);
        fs::remove_dir_all(directory).unwrap();
    }
}
