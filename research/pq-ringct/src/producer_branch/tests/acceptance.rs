//! Opt-in staged qualification with actual serial requests and actual producer
//! and atomic consumer proofs. Even the final stage covers only one of the91
//! graph leaves; it never establishes complete graph or transaction acceptance.
use super::*;
use crate::{
    graph_auxiliary::{AuxiliaryArtifact, AuxiliaryCache, AuxiliaryFactory, Role as AuxiliaryRole},
    graph_crypto::{self, CompleteRequestProof, RequestProver},
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{GraphProver, LeafArtifact},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use std::{path::PathBuf, time::Instant};

mod mutations;

const NATIVE_BUDGET: u64 = 32 << 30;
const OUTER_BUDGET: u64 = 48 << 30;

struct Setup {
    graph: UnprovedRelationGraph,
    plan: graph_tree::Plan,
    context: graph_tree::GraphContext,
}

fn setup() -> Setup {
    let archive = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit preserved graph fixture required"),
    );
    let fixture = crate::native_test_fixture::load_or_create(
        &archive,
        [71; 32],
        [29; 32],
        3,
        crate::native::FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
        false,
    )
    .unwrap();
    let graph = committed_backend::lower_unproved(
        fixture.setup_seed,
        &fixture.context,
        &Statement::decode(&fixture.statement).unwrap(),
        &Proof::decode(&fixture.proof).unwrap(),
    )
    .unwrap();
    let shape = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(
        &shape,
        &graph,
        ResourceLimits {
            max_batch_count: 64,
            max_ntt_batch_count: 32,
            max_mul_batch_count: 32,
            max_trace_cells: 1 << 27,
            max_estimated_prover_bytes: 16 << 30,
        },
    )
    .unwrap();
    let plan = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    assert_eq!(plan.leaves().len(), 91);
    let context = graph_tree::GraphContext {
        context: fixture.context,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            fixture.context,
            &fixture.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(&graph).unwrap(),
    };
    Setup {
        graph,
        plan,
        context,
    }
}

fn require_opt_in_and_guard() {
    assert_eq!(
        std::env::var("LATTICA_BRANCH_ACCEPTANCE_OUTER_OPT_IN").as_deref(),
        Ok("1"),
        "this test can generate many actual outer proofs; explicit opt-in required"
    );
    let limits = std::fs::read_to_string("/proc/self/limits")
        .expect("Linux process limits required to verify the external48GiB guard");
    let line = limits
        .lines()
        .find(|line| line.starts_with("Max address space"))
        .expect("external address-space limit missing");
    let columns: Vec<_> = line.split_whitespace().collect();
    let soft: u64 = columns[3]
        .parse()
        .expect("finite external address-space soft limit required");
    let hard: u64 = columns[4]
        .parse()
        .expect("finite external address-space hard limit required");
    assert_eq!(
        soft, OUTER_BUDGET,
        "coordinated external48GiB guard required"
    );
    assert_eq!(
        hard, OUTER_BUDGET,
        "coordinated external48GiB hard guard required"
    );
}

enum Branches {
    Alpha {
        uniform: ProvenBranch,
        sparse: ProvenBranch,
    },
    HashX {
        branch: ProvenBranch,
        sampler: AuxiliaryArtifact,
        transcript: TranscriptAir,
    },
}
impl Branches {
    fn artifact(&self) -> LeafArtifact<'_> {
        match self {
            Self::Alpha { uniform, sparse } => LeafArtifact::ExpandAlphaBranches {
                uniform: Artifact {
                    key: &uniform.key,
                    proof: &uniform.proof,
                },
                sparse: Artifact {
                    key: &sparse.key,
                    proof: &sparse.proof,
                },
            },
            Self::HashX {
                branch, sampler, ..
            } => LeafArtifact::HashXBranch {
                branch: Artifact {
                    key: &branch.key,
                    proof: &branch.proof,
                },
                sampler: sampler.sparse().unwrap(),
            },
        }
    }
    fn count(&self) -> usize {
        if matches!(self, Self::Alpha { .. }) {
            2
        } else {
            1
        }
    }
}

fn request_report(operation: usize, subrequest: u32, proof: &CompleteRequestProof) {
    let nodes: Vec<_> = proof
        .report
        .nodes
        .iter()
        .map(|node| {
            serde_json::json!({
                "stage": node.stage, "first_unit": node.first_unit, "units": node.units,
                "active_rows": node.active_rows, "padded_rows": node.padded_rows,
                "retained_lde_bytes": node.retained_lde_bytes, "cache_hit": node.cache_hit,
                "cache_identity": node.cache_identity,
            })
        })
        .collect();
    eprintln!(
        "BRANCH_ACCEPTANCE_REQUEST {}",
        serde_json::json!({
            "operation": operation, "subrequest": subrequest, "complete_request_verified": true,
            "native_children": proof.report.native_children, "native_cache_hits": proof.report.native_cache_hits,
            "outer_leaves": proof.report.outer_leaves, "outer_parents": proof.report.outer_parents,
            "outer_cache_hits": proof.report.outer_cache_hits,
            "maximum_retained_lde_bytes": proof.report.maximum_retained_lde_bytes, "nodes": nodes,
        })
    );
}

fn prove_branch(compiled: CompiledNode, cache: &OuterProofCache, role: &str) -> ProvenBranch {
    compiled.evaluate().unwrap();
    let geometry = compiled.geometry().unwrap();
    assert!(geometry.retained_lde_bytes <= OUTER_BUDGET);
    let started = Instant::now();
    let prepared = compiled.prepare(OUTER_BUDGET).unwrap();
    let identity = prepared.cache_identity(&prepared.key()).unwrap();
    let branch = prepared.prove_or_load(cache).unwrap();
    branch.key.verify(&branch.proof).unwrap();
    eprintln!(
        "BRANCH_ACCEPTANCE_PRODUCER {}",
        serde_json::json!({
            "role": role, "actual_proof_verified": true, "cache_hit": branch.cache_hit,
            "cache_file": cache.entry_path(&identity), "active_rows": geometry.active_rows,
            "padded_rows": geometry.padded_rows, "retained_lde_bytes": geometry.retained_lde_bytes,
            "seconds": started.elapsed().as_secs_f64(), "complete_graph": false,
        })
    );
    branch
}

fn finish(
    stage: &str,
    operation: usize,
    branches: usize,
    consumer: bool,
    mutations: Option<serde_json::Value>,
    elapsed: f64,
) {
    eprintln!(
        "BRANCH_ACCEPTANCE_RESULT {}",
        serde_json::json!({
            "operation": operation, "completed_stage": stage, "graph_schedule_entries": 91,
            "complete_requests_verified": true, "producer_branches_verified": branches,
            "atomic_consumer_proof_verified": consumer, "mutations": mutations,
            "incomplete_graph_rejected": consumer, "complete_graph_accepted": false,
            "complete_transaction_accepted": false, "seconds": elapsed,
            "scope": "Only the stated stage and operation are qualified. A valid atomic consumer remains a partial graph leaf and cannot pass complete-graph acceptance.",
        })
    );
}

#[test]
#[ignore = "explicit outer opt-in, exact fixture, persisted caches, external48GiB process guard; can prove complete serial requests, producer branches and one partial graph leaf"]
fn actual_serial_requests_producer_branches_and_atomic_consumer() {
    require_opt_in_and_guard();
    let started = Instant::now();
    let operation: usize = std::env::var("LATTICA_BRANCH_ACCEPTANCE_OPERATION")
        .expect("explicit operation624 or1309 required")
        .parse()
        .unwrap();
    assert!(matches!(operation, 624 | 1309));
    let stage = std::env::var("LATTICA_BRANCH_ACCEPTANCE_STAGE")
        .expect("explicit stage requests, branches or consumer required");
    assert!(matches!(
        stage.as_str(),
        "requests" | "branches" | "consumer"
    ));
    let directory = PathBuf::from(
        std::env::var_os("LATTICA_CRYPTO_QUALIFICATION_DIRECTORY")
            .expect("explicit persistent qualification cache directory required"),
    );
    let setup = setup();
    let crypto = graph_crypto::Plan::new(
        &setup.plan,
        &setup.graph,
        graph_crypto::Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: NATIVE_BUDGET,
            admission: graph_crypto::Admission::Estimated,
        },
    )
    .unwrap();
    let native_cache = graph_crypto::ProofCache::new(directory.join("native"), 64 << 20).unwrap();
    let outer_cache = OuterProofCache::new(directory.join("outer"), 64 << 20).unwrap();
    let auxiliary_cache = AuxiliaryCache::new(directory.join("auxiliary"), 64 << 20).unwrap();
    let requests = RequestProver::new(&native_cache, &outer_cache, OUTER_BUDGET).unwrap();
    let auxiliary =
        AuxiliaryFactory::new(&setup.plan, &setup.graph, &setup.context, NATIVE_BUDGET).unwrap();
    let factory = Factory::new(&setup.plan, &setup.graph, &setup.context).unwrap();
    let request = |subrequest| {
        crypto
            .requests()
            .iter()
            .find(|request| {
                request.operation_index() == operation && request.subrequest() == subrequest
            })
            .unwrap()
    };
    eprintln!(
        "BRANCH_ACCEPTANCE_PLAN {}",
        serde_json::json!({
            "operation": operation, "requested_stage": stage, "graph_schedule_entries": 91,
            "algebra_limits": { "global": 64, "ntt": 32, "mul": 32, "trace_cells": 1u64 << 27, "native_bytes": 16u64 << 30 },
            "crypto_policy": { "aes_blocks": 64, "shake_permutations": 32, "native_bytes": NATIVE_BUDGET, "admission": "Estimated" },
            "outer_retained_admission_bytes": OUTER_BUDGET, "external_address_space_guard_bytes": OUTER_BUDGET,
            "cache_directory": directory, "source_fingerprint": crate::graph_proofs::compiled_source_fingerprint(),
            "profile_label": setup.plan.label(), "fixture_creation_enabled": false, "complete_graph": false,
        })
    );
    let first = requests.prove_serial(request(0), &setup.context).unwrap();
    first
        .key
        .verify_request(
            &first.proof,
            &request(0).endpoint_context_hint(&setup.context),
        )
        .unwrap();
    request_report(operation, 0, &first);
    let second = (operation == 624).then(|| {
        let proof = requests.prove_serial(request(1), &setup.context).unwrap();
        proof
            .key
            .verify_request(
                &proof.proof,
                &request(1).endpoint_context_hint(&setup.context),
            )
            .unwrap();
        request_report(operation, 1, &proof);
        proof
    });
    if stage == "requests" {
        finish(
            &stage,
            operation,
            0,
            false,
            None,
            started.elapsed().as_secs_f64(),
        );
        return;
    }
    let mut branches = if operation == 624 {
        let uniform = auxiliary_cache
            .load_or_prove(
                auxiliary
                    .request(operation, AuxiliaryRole::AlphaUniform)
                    .unwrap(),
            )
            .unwrap();
        let sparse = auxiliary_cache
            .load_or_prove(
                auxiliary
                    .request(operation, AuxiliaryRole::AlphaSparse)
                    .unwrap(),
            )
            .unwrap();
        let uniform_branch = prove_branch(
            factory
                .compile_alpha_uniform(
                    operation,
                    &first.key,
                    &first.proof,
                    uniform.artifact.uniform().unwrap(),
                )
                .unwrap(),
            &outer_cache,
            "alpha-uniform",
        );
        let second = second.as_ref().unwrap();
        let sparse_branch = prove_branch(
            factory
                .compile_alpha_sparse(
                    operation,
                    &second.key,
                    &second.proof,
                    sparse.artifact.sparse().unwrap(),
                )
                .unwrap(),
            &outer_cache,
            "alpha-sparse",
        );
        Branches::Alpha {
            uniform: uniform_branch,
            sparse: sparse_branch,
        }
    } else {
        let request = auxiliary
            .request(operation, AuxiliaryRole::HashXTranscript)
            .unwrap();
        let transcript = auxiliary_cache.load_or_prove(request).unwrap();
        let air = TranscriptAir::new(request.transcript_air().unwrap().parts().to_vec()).unwrap();
        let sampler = auxiliary_cache
            .load_or_prove(
                auxiliary
                    .request(operation, AuxiliaryRole::HashXSparse)
                    .unwrap(),
            )
            .unwrap();
        let branch = prove_branch(
            factory
                .compile_hash_x(
                    operation,
                    &first.key,
                    &first.proof,
                    transcript.artifact.transcript().unwrap(),
                )
                .unwrap(),
            &outer_cache,
            "hash-x-transcript-shake",
        );
        Branches::HashX {
            branch,
            sampler: sampler.artifact,
            transcript: air,
        }
    };
    drop((first, second));
    if stage == "branches" {
        finish(
            &stage,
            operation,
            branches.count(),
            false,
            None,
            started.elapsed().as_secs_f64(),
        );
        return;
    }
    let ordinal = setup
        .plan
        .leaves()
        .iter()
        .position(|leaf| leaf.operation_indices() == [operation])
        .unwrap();
    let compiled = graph_tree::compile_leaf(
        &setup.plan,
        &setup.graph,
        ordinal,
        &setup.context,
        branches.artifact(),
    )
    .unwrap();
    compiled.evaluate().unwrap();
    let geometry = compiled.geometry().unwrap();
    assert!(geometry.retained_lde_bytes <= OUTER_BUDGET);
    let prover = GraphProver::new(&setup.plan, &setup.context, &outer_cache, OUTER_BUDGET).unwrap();
    let consumer = prover.prove_leaf(compiled).unwrap();
    consumer.key().verify(consumer.proof()).unwrap();
    assert_eq!(consumer.key().span(), (ordinal, 1));
    let incomplete = consumer
        .verify_complete(&setup.context)
        .err()
        .expect("partial leaf accepted as complete graph");
    assert!(incomplete.0.contains("incomplete graph coverage"));
    eprintln!(
        "BRANCH_ACCEPTANCE_CONSUMER {}",
        serde_json::json!({
            "operation": operation, "graph_ordinal": ordinal, "actual_proof_verified": true,
            "cache_hit": consumer.cache_hit(), "active_rows": geometry.active_rows,
            "padded_rows": geometry.padded_rows, "retained_lde_bytes": geometry.retained_lde_bytes,
            "incomplete_graph_rejected": true, "complete_graph": false,
        })
    );
    let (key, mut proof) = consumer.into_parts();
    let mutations = mutations::check(&setup, operation, ordinal, &mut branches, &key, &mut proof);
    finish(
        &stage,
        operation,
        branches.count(),
        true,
        Some(mutations),
        started.elapsed().as_secs_f64(),
    );
}
