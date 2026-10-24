//! End-to-end orchestration of the registered standalone MatRiCT relation.
//!
//! The caller supplies its trusted graph registration. Native proofs and cache
//! hits never substitute for recursive leaf checks or complete graph coverage.
//! This module does not add ledger membership, spent-serial state, or fees.
use crate::{
    execution::ProvingContext,
    graph_auxiliary::{AuxiliaryCache, AuxiliaryFactory, Role},
    graph_crypto::{self, CompleteRequestProof, OuterProofCache, RequestProver},
    graph_proofs::{self, GraphProofPlan},
    graph_sources::{SourceCache, SourceFactory},
    graph_tree::{
        self, AesProof, GraphContext, GraphProver, LeafArtifact, LeafKind, OperationFamily, Plan,
        ProvenNode, ShakeProof,
    },
    producer_branch,
    proof_cache_policy::{CacheStatistics, Control, ProofCachePolicy},
    rust_verify::committed_backend::UnprovedRelationGraph,
};
use std::path::Path;

#[cfg(all(test, feature = "native-matrict"))]
mod tests;

#[derive(Debug)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn err(e: impl std::fmt::Display) -> Error {
    Error(e.to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TranscriptLayout {
    Serial,
    /// Only HashAlpha/HashX use the wide AIR. The small PP request retains its
    /// serial AIR. Admission still uses the supplied native and outer budgets.
    Wide {
        maximum_permutations: usize,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AesLayout {
    Serial,
    /// Each selected request uses the original whole-request AES AIR. Smaller
    /// requests retain the serial AIR; every request still passes admission.
    WholeWide {
        minimum_blocks: usize,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositeLayout {
    Direct,
    /// Split only the large composite operations into typed internal proofs.
    /// Exact complete-operation coverage is still checked by the graph leaf.
    Branches,
}
#[derive(Clone, Copy, Debug)]
pub struct Budgets {
    pub native_bytes: u64,
    pub outer_bytes: u64,
    pub cache_entry_bytes: u64,
    pub crypto_policy: graph_crypto::Policy,
    pub transcripts: TranscriptLayout,
    pub aes: AesLayout,
    pub composites: CompositeLayout,
}
impl Default for Budgets {
    fn default() -> Self {
        Self {
            native_bytes: 8 << 30,
            outer_bytes: 48 << 30,
            cache_entry_bytes: 64 << 20,
            crypto_policy: graph_crypto::Policy::default(),
            transcripts: TranscriptLayout::Serial,
            aes: AesLayout::Serial,
            composites: CompositeLayout::Direct,
        }
    }
}

pub struct SpendPipeline {
    sources: SourceCache,
    algebra: graph_proofs::ProofCache,
    crypto: graph_crypto::ProofCache,
    auxiliary: AuxiliaryCache,
    outer: OuterProofCache,
    budgets: Budgets,
    cache_control: Control,
}
/// Construction is private: only a completely verified registered graph can
/// be returned here. Its relation is still the standalone research relation.
pub struct CompleteGraphProof {
    node: ProvenNode,
}
impl CompleteGraphProof {
    pub fn key(&self) -> &graph_tree::NodeKey {
        self.node.key()
    }
    pub fn proof(&self) -> &graph_tree::NodeProof {
        self.node.proof()
    }
    pub fn into_parts(self) -> (graph_tree::NodeKey, graph_tree::NodeProof) {
        self.node.into_parts()
    }
}
impl SpendPipeline {
    pub fn new(directory: impl AsRef<Path>, budgets: Budgets) -> Result<Self> {
        Self::new_with_policy(directory, budgets, ProofCachePolicy::default())
    }

    pub fn new_with_policy(
        directory: impl AsRef<Path>,
        budgets: Budgets,
        policy: ProofCachePolicy,
    ) -> Result<Self> {
        if budgets.native_bytes == 0
            || budgets.outer_bytes == 0
            || budgets.crypto_policy.child_memory_budget_bytes > budgets.native_bytes
            || matches!(budgets.aes, AesLayout::WholeWide { minimum_blocks: 0 })
            || matches!(
                budgets.transcripts,
                TranscriptLayout::Wide {
                    maximum_permutations: 0
                }
            )
        {
            return Err(Error("inconsistent spend worker memory budgets".into()));
        }
        let directory = directory.as_ref();
        let cache_control = Control::new(policy);
        Ok(Self {
            sources: SourceCache::new_with_control(
                directory.join("sources"),
                budgets.cache_entry_bytes,
                cache_control.clone(),
            )
            .map_err(err)?,
            algebra: graph_proofs::ProofCache::new_with_control(
                directory.join("algebra"),
                budgets.cache_entry_bytes,
                cache_control.clone(),
            )
            .map_err(err)?,
            crypto: graph_crypto::ProofCache::new_with_control(
                directory.join("crypto"),
                budgets.cache_entry_bytes,
                cache_control.clone(),
            )
            .map_err(err)?,
            auxiliary: AuxiliaryCache::new_with_control(
                directory.join("auxiliary"),
                budgets.cache_entry_bytes,
                cache_control.clone(),
            )
            .map_err(err)?,
            outer: OuterProofCache::new_with_control(
                directory.join("outer"),
                budgets.cache_entry_bytes,
                cache_control.clone(),
            )
            .map_err(err)?,
            budgets,
            cache_control,
        })
    }

    pub fn cache_statistics(&self) -> CacheStatistics {
        self.cache_control.snapshot()
    }

    /// Prove every source and operation under the caller's trusted registration.
    /// A resource failure returns an error; cached partial work is resumable but
    /// is never returned as a complete graph or spend proof.
    pub fn prove_registered(
        &self,
        plan: &Plan,
        algebra: &GraphProofPlan<'_>,
        graph: &UnprovedRelationGraph,
        context: &GraphContext,
        statement: &[u8],
        private_proof: &[u8],
    ) -> Result<CompleteGraphProof> {
        self.prove_registered_impl(
            plan,
            algebra,
            graph,
            context,
            statement,
            private_proof,
            None,
        )
    }

    /// Use one explicit backend/session for every eligible registered proof.
    /// Registered and native component proofs follow the context backend policy.
    pub fn prove_registered_with_context(
        &self,
        plan: &Plan,
        algebra: &GraphProofPlan<'_>,
        graph: &UnprovedRelationGraph,
        context: &GraphContext,
        statement: &[u8],
        private_proof: &[u8],
        execution: &ProvingContext,
    ) -> Result<CompleteGraphProof> {
        self.prove_registered_impl(
            plan,
            algebra,
            graph,
            context,
            statement,
            private_proof,
            Some(execution),
        )
    }

    fn prove_registered_impl(
        &self,
        plan: &Plan,
        algebra: &GraphProofPlan<'_>,
        graph: &UnprovedRelationGraph,
        context: &GraphContext,
        statement: &[u8],
        private_proof: &[u8],
        execution: Option<&ProvingContext>,
    ) -> Result<CompleteGraphProof> {
        if let Some(execution) = execution {
            execution.release_prepared().map_err(err)?;
        }
        if execution.is_some_and(|context| {
            context.policy() == lattica_prover_p3::proving::Policy::GpuRequired
        }) && algebra.native_host_limit_bytes() > self.budgets.native_bytes
        {
            return Err(Error(
                "algebra GPU host allowance exceeds pipeline native budget".into(),
            ));
        }
        let expected_schedule = algebra.operation_batches();
        let actual_schedule: Vec<_> = plan
            .leaves()
            .iter()
            .filter_map(|leaf| {
                matches!(leaf.kind(), LeafKind::Operations(_))
                    .then(|| leaf.operation_indices().to_vec())
            })
            .collect();
        if actual_schedule != expected_schedule {
            return Err(Error("graph and algebra operation schedules differ".into()));
        }
        let source = SourceFactory::new_with_context(
            plan,
            graph,
            context,
            statement,
            private_proof,
            self.budgets.native_bytes,
            execution,
        )
        .map_err(err)?;
        let crypto_plan = graph_crypto::Plan::new_with_context(
            plan,
            graph,
            self.budgets.crypto_policy,
            execution,
        )
        .map_err(err)?;
        let auxiliary = AuxiliaryFactory::new_with_context(
            plan,
            graph,
            context,
            self.budgets.native_bytes,
            execution,
        )
        .map_err(err)?;
        let requests = match execution {
            Some(execution) => RequestProver::new_with_context(
                &self.crypto,
                &self.outer,
                self.budgets.outer_bytes,
                execution,
            ),
            None => RequestProver::new(&self.crypto, &self.outer, self.budgets.outer_bytes),
        }
        .map_err(err)?;
        let graph_prover = match execution {
            Some(execution) => GraphProver::new_with_context(
                plan,
                context,
                &self.outer,
                self.budgets.outer_bytes,
                execution,
            ),
            None => GraphProver::new(plan, context, &self.outer, self.budgets.outer_bytes),
        }
        .map_err(err)?;
        let branches = match self.budgets.composites {
            CompositeLayout::Direct => None,
            CompositeLayout::Branches => Some(
                producer_branch::Factory::new_with_context(plan, graph, context, execution)
                    .map_err(err)?,
            ),
        };
        let prove_branch = |operation: usize,
                            role: &'static str,
                            compiled: producer_branch::CompiledNode|
         -> Result<producer_branch::ProvenBranch> {
            let geometry = compiled.geometry().map_err(err)?;
            if geometry.retained_lde_bytes > self.budgets.outer_bytes {
                return Err(Error(format!(
                    "producer branch {role} for operation {operation} exceeds retained-LDE admission: {} bytes > {}; this is not a peak-memory bound",
                    geometry.retained_lde_bytes, self.budgets.outer_bytes,
                )));
            }
            let proof = match execution {
                Some(execution) => compiled.prove_or_load_with_context(execution, &self.outer),
                None => compiled
                    .prepare(self.budgets.outer_bytes)
                    .and_then(|prepared| prepared.prove_or_load(&self.outer)),
            }
            .map_err(err)?;
            eprintln!(
                "SPEND_PIPELINE_BRANCH operation={operation} role={role} active_rows={} padded_rows={} retained_lde_bytes={} cache_hit={}",
                geometry.active_rows, geometry.padded_rows, geometry.retained_lde_bytes,
                proof.cache_hit,
            );
            Ok(proof)
        };
        let request = |operation, subrequest| -> Result<&graph_crypto::Request> {
            crypto_plan
                .requests()
                .iter()
                .find(|r| r.operation_index() == operation && r.subrequest() == subrequest)
                .ok_or_else(|| Error("missing registered crypto request".into()))
        };
        let transcript_request = |operation| -> Result<CompleteRequestProof> {
            let registered = request(operation, 0)?;
            match self.budgets.transcripts {
                TranscriptLayout::Serial => requests.prove_serial(registered, context).map_err(err),
                TranscriptLayout::Wide {
                    maximum_permutations,
                } => {
                    let factory = registered
                        .wide_shake(maximum_permutations, self.budgets.native_bytes)
                        .map_err(err)?;
                    requests.prove_wide(&factory, context).map_err(err)
                }
            }
        };
        let aes_request = |operation, subrequest| -> Result<CompleteRequestProof> {
            let registered = request(operation, subrequest)?;
            match self.budgets.aes {
                AesLayout::WholeWide { minimum_blocks } if registered.units() >= minimum_blocks => {
                    let factory = registered
                        .wide_aes(self.budgets.native_bytes)
                        .map_err(err)?;
                    requests.prove_wide_aes(&factory, context).map_err(err)
                }
                _ => requests.prove_serial(registered, context).map_err(err),
            }
        };
        let mut proven = Vec::with_capacity(plan.leaves().len());
        for (index, leaf) in plan.leaves().iter().enumerate() {
            eprintln!(
                "SPEND_PIPELINE leaf={index}/{} kind={:?}",
                plan.leaves().len(),
                leaf.kind()
            );
            let compile = |artifact| {
                if let Some(execution) = execution {
                    execution.release_prepared().map_err(err)?;
                }
                graph_tree::compile_leaf(plan, graph, index, context, artifact).map_err(err)
            };
            let operation = leaf.operation_indices().first().copied();
            let compiled = match leaf.kind() {
                LeafKind::FixedSources => compile(LeafArtifact::FixedSources)?,
                LeafKind::Statement => {
                    let proof = run_native(execution, || {
                        source
                            .prove_or_load_statement_with_context(&self.sources, execution)
                            .map_err(err)
                    })?;
                    compile(LeafArtifact::Statement(&proof))?
                }
                LeafKind::PrivateProof => {
                    let proof = run_native(execution, || {
                        source
                            .prove_or_load_private_with_context(&self.sources, execution)
                            .map_err(err)
                    })?;
                    compile(LeafArtifact::PrivateProof(&proof))?
                }
                LeafKind::Operations(family) => {
                    let operation =
                        operation.ok_or_else(|| Error("empty operation leaf".into()))?;
                    match family {
                        OperationFamily::Equality => compile(LeafArtifact::Equality)?,
                        OperationFamily::ParametersPp => {
                            let complete = requests
                                .prove_serial(request(operation, 0)?, context)
                                .map_err(err)?;
                            compile(LeafArtifact::ParametersPp(ShakeProof::Tree {
                                key: &complete.key,
                                proof: &complete.proof,
                            }))?
                        }
                        OperationFamily::SampleG => {
                            let complete = aes_request(operation, 0)?;
                            let sampler = run_native(execution, || {
                                self.auxiliary
                                    .load_or_prove_with_context(
                                        auxiliary
                                            .request(operation, Role::SampleGUniform)
                                            .map_err(err)?,
                                        execution,
                                    )
                                    .map_err(err)
                            })?;
                            compile(LeafArtifact::SampleG {
                                aes: AesProof::Tree {
                                    key: &complete.key,
                                    proof: &complete.proof,
                                },
                                sampler: sampler.artifact.uniform().map_err(err)?,
                            })?
                        }
                        OperationFamily::ExpandAlpha => {
                            let uniform_aes = aes_request(operation, 0)?;
                            let sparse_aes = aes_request(operation, 1)?;
                            let uniform = run_native(execution, || {
                                self.auxiliary
                                    .load_or_prove_with_context(
                                        auxiliary
                                            .request(operation, Role::AlphaUniform)
                                            .map_err(err)?,
                                        execution,
                                    )
                                    .map_err(err)
                            })?;
                            let sparse = run_native(execution, || {
                                self.auxiliary
                                    .load_or_prove_with_context(
                                        auxiliary
                                            .request(operation, Role::AlphaSparse)
                                            .map_err(err)?,
                                        execution,
                                    )
                                    .map_err(err)
                            })?;
                            if let Some(factory) = &branches {
                                let uniform = prove_branch(
                                    operation,
                                    "alpha-uniform",
                                    factory
                                        .compile_alpha_uniform(
                                            operation,
                                            &uniform_aes.key,
                                            &uniform_aes.proof,
                                            uniform.artifact.uniform().map_err(err)?,
                                        )
                                        .map_err(err)?,
                                )?;
                                if let Some(execution) = execution {
                                    execution.release_prepared().map_err(err)?;
                                }
                                let sparse = prove_branch(
                                    operation,
                                    "alpha-sparse",
                                    factory
                                        .compile_alpha_sparse(
                                            operation,
                                            &sparse_aes.key,
                                            &sparse_aes.proof,
                                            sparse.artifact.sparse().map_err(err)?,
                                        )
                                        .map_err(err)?,
                                )?;
                                compile(LeafArtifact::ExpandAlphaBranches {
                                    uniform: producer_branch::Artifact {
                                        key: &uniform.key,
                                        proof: &uniform.proof,
                                    },
                                    sparse: producer_branch::Artifact {
                                        key: &sparse.key,
                                        proof: &sparse.proof,
                                    },
                                })?
                            } else {
                                compile(LeafArtifact::ExpandAlpha {
                                    uniform_aes: AesProof::Tree {
                                        key: &uniform_aes.key,
                                        proof: &uniform_aes.proof,
                                    },
                                    uniform: uniform.artifact.uniform().map_err(err)?,
                                    sparse_aes: AesProof::Tree {
                                        key: &sparse_aes.key,
                                        proof: &sparse_aes.proof,
                                    },
                                    sparse: sparse.artifact.sparse().map_err(err)?,
                                })?
                            }
                        }
                        OperationFamily::HashAlpha => {
                            let complete = transcript_request(operation)?;
                            let transcript = run_native(execution, || {
                                self.auxiliary
                                    .load_or_prove_with_context(
                                        auxiliary
                                            .request(operation, Role::HashAlphaTranscript)
                                            .map_err(err)?,
                                        execution,
                                    )
                                    .map_err(err)
                            })?;
                            compile(LeafArtifact::HashAlpha {
                                transcript: transcript.artifact.transcript().map_err(err)?,
                                shake: ShakeProof::Tree {
                                    key: &complete.key,
                                    proof: &complete.proof,
                                },
                            })?
                        }
                        OperationFamily::HashX => {
                            let complete = transcript_request(operation)?;
                            let transcript = run_native(execution, || {
                                self.auxiliary
                                    .load_or_prove_with_context(
                                        auxiliary
                                            .request(operation, Role::HashXTranscript)
                                            .map_err(err)?,
                                        execution,
                                    )
                                    .map_err(err)
                            })?;
                            let sampler = run_native(execution, || {
                                self.auxiliary
                                    .load_or_prove_with_context(
                                        auxiliary
                                            .request(operation, Role::HashXSparse)
                                            .map_err(err)?,
                                        execution,
                                    )
                                    .map_err(err)
                            })?;
                            if let Some(factory) = &branches {
                                let branch = prove_branch(
                                    operation,
                                    "hash-x-transcript-shake",
                                    factory
                                        .compile_hash_x(
                                            operation,
                                            &complete.key,
                                            &complete.proof,
                                            transcript.artifact.transcript().map_err(err)?,
                                        )
                                        .map_err(err)?,
                                )?;
                                compile(LeafArtifact::HashXBranch {
                                    branch: producer_branch::Artifact {
                                        key: &branch.key,
                                        proof: &branch.proof,
                                    },
                                    sampler: sampler.artifact.sparse().map_err(err)?,
                                })?
                            } else {
                                compile(LeafArtifact::HashX {
                                    transcript: transcript.artifact.transcript().map_err(err)?,
                                    shake: ShakeProof::Tree {
                                        key: &complete.key,
                                        proof: &complete.proof,
                                    },
                                    sampler: sampler.artifact.sparse().map_err(err)?,
                                })?
                            }
                        }
                        _ => {
                            let batch = algebra
                                .batches()
                                .iter()
                                .position(|b| b.operation_indices() == leaf.operation_indices())
                                .ok_or_else(|| {
                                    Error("missing exact algebra operation batch".into())
                                })?;
                            let proof = run_native(execution, || {
                                self.algebra
                                    .load_or_prove_with_context(algebra, batch, execution)
                                    .map_err(err)
                            })?;
                            compile(proof.artifact.as_leaf_artifact())?
                        }
                    }
                }
            };
            proven.push(
                graph_prover
                    .prove_leaf(compiled)
                    .map_err(|e| Error(format!("graph leaf {index}: {e}")))?,
            );
        }
        let root = graph_prover.aggregate_adjacent(proven).map_err(err)?;
        graph_prover.verify_complete(&root).map_err(err)?;
        root.key()
            .verify_complete(root.proof(), context)
            .map_err(err)?;
        Ok(CompleteGraphProof { node: root })
    }
}

fn run_native<T>(
    _execution: Option<&ProvingContext>,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    operation()
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    #[test]
    fn pipeline_reports_all_cache_families_without_proof_access() {
        let directory = std::env::temp_dir().join(format!(
            "lattica-pipeline-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for (index, policy) in [ProofCachePolicy::default(), ProofCachePolicy::FreshOnly]
            .into_iter()
            .enumerate()
        {
            let pipeline = SpendPipeline::new_with_policy(
                directory.join(index.to_string()),
                Budgets::default(),
                policy,
            )
            .unwrap();
            let counts = pipeline.cache_statistics();
            assert_eq!(counts.policy, policy);
            assert_eq!(counts.families.len(), 5);
            for name in ["sources", "algebra", "crypto", "auxiliary", "outer"] {
                assert_eq!(counts.families[name], Default::default());
            }
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
