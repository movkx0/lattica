//! Exact request/branch cap registration without generating outer proofs.
//! Every proof-shaped input is deliberately invalid. Contract-substitution
//! checks concern compiler structure, not soundness of an accepted proof.
use super::*;
use crate::{
    graph_auxiliary::{AuxiliaryFactory, Role as AuxiliaryRole},
    graph_crypto,
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{
        self,
        composite_shape_tests::{auxiliary_template, complete_request_shape},
        LeafArtifact,
    },
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use lattica_prover_p3::block_v2::machine::verifier;
use std::{path::PathBuf, time::Instant};

fn report(stage: &str, operation: usize, geometry: &crate::component_tree::Geometry) {
    eprintln!(
        "BRANCH_SHAPE_GEOMETRY {}",
        serde_json::json!({
            "stage": stage, "operation": operation,
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks, "constraints": geometry.constraints,
            "max_constraint_degree": geometry.max_constraint_degree,
            "fri_ali_bits": geometry.fri_ali_bits,
            "retained_lde_bytes": geometry.retained_lde_bytes,
            "outer_proof_produced": false,
        })
    );
}

fn register_invalid_branch(
    compiled: CompiledNode,
    stage: &str,
    operation: usize,
) -> (NodeKey, NodeProof) {
    report(stage, operation, &compiled.geometry().unwrap());
    assert!(
        compiled.evaluate().is_err(),
        "invalid template unexpectedly satisfied branch constraints"
    );
    let public = compiled.public.clone();
    let start = Instant::now();
    let prepared = compiled.prepare(64u64 << 30).unwrap();
    let key = prepared.key();
    drop(prepared);
    let proof = NodeProof {
        public,
        proof: verifier::template::batch(&key.air().unwrap()).unwrap(),
    };
    assert!(key.verify(&proof).is_err());
    eprintln!(
        "BRANCH_SHAPE_REGISTER {}",
        serde_json::json!({
            "stage": stage, "operation": operation, "seconds": start.elapsed().as_secs_f64(),
            "actual_registered_cap": true, "invalid_template_rejected": true,
            "retained_registration_admission_bytes": 64u64 << 30,
        })
    );
    (key, proof)
}

fn compare_request(operation: usize, subrequest: u32, geometry: &crate::component_tree::Geometry) {
    let previous_active_rows = match (operation, subrequest) {
        (624, 0) => 305_991,
        (624, 1) => 97_897,
        (1017 | 1018, 0) => 324_249,
        (1309, 0) => 373_056,
        _ => unreachable!(),
    };
    eprintln!(
        "BRANCH_SHAPE_REQUEST_COMPARISON {}",
        serde_json::json!({
            "operation": operation, "subrequest": subrequest,
            "previous_active_rows": previous_active_rows, "current_active_rows": geometry.active_rows,
            "current_padded_rows": geometry.padded_rows,
            "unchanged_active_rows": previous_active_rows == geometry.active_rows,
            "interpretation": "A difference may reflect the independently measured compiler optimization. The current actual registered predicate, not old geometry, supplies this branch's trusted source cap.",
        })
    );
}

#[test]
#[ignore = "real request and branch source-cap registration; coordinate an external32GiB process guard; no proofs"]
fn exact_typed_branches_and_atomic_graph_consumer_geometry() {
    let started = Instant::now();
    let operation: usize = std::env::var("LATTICA_BRANCH_SHAPE_OPERATION")
        .expect("explicit branch operation624 or1309 required")
        .parse()
        .unwrap();
    assert!(matches!(operation, 624 | 1309));
    let archive = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit persisted public graph fixture required"),
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
    let algebra_configuration =
        std::env::var("LATTICA_BRANCH_SHAPE_ALGEBRA_PLAN").unwrap_or_else(|_| "default".into());
    let (limits, expected_leaves) = match algebra_configuration.as_str() {
        "default" => (ResourceLimits::default(), 207),
        "chosen-ntt32-mul32" => (
            ResourceLimits {
                max_batch_count: 64,
                max_ntt_batch_count: 32,
                max_mul_batch_count: 32,
                max_trace_cells: 1 << 27,
                max_estimated_prover_bytes: 16u64 << 30,
            },
            91,
        ),
        other => panic!("unknown branch diagnostic algebra plan: {other}"),
    };
    let algebra = GraphProofPlan::new(&shape, &graph, limits).unwrap();
    let plan = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    assert_eq!(plan.leaves().len(), expected_leaves);
    let limits_record = serde_json::json!({
        "name": algebra_configuration,
        "max_batch_count": limits.max_batch_count,
        "max_ntt_batch_count": limits.max_ntt_batch_count,
        "max_mul_batch_count": limits.max_mul_batch_count,
        "max_trace_cells": limits.max_trace_cells,
        "max_estimated_prover_bytes": limits.max_estimated_prover_bytes,
    });
    let schedule: Vec<_> = plan.leaves().iter().enumerate().map(|(ordinal, leaf)| {
        serde_json::json!({ "ordinal": ordinal, "operations": leaf.operation_indices() })
    }).collect();
    eprintln!(
        "BRANCH_SHAPE_PLAN {}",
        serde_json::json!({
            "operation": operation, "algebra_configuration": limits_record,
            "profile_label": plan.label(), "registered_graph_schedule_entries": plan.leaves().len(),
            "schedule": schedule,
            "scope": "Geometry is specific to this exact plan, profile label, operation ordinal, and registered source caps.",
        })
    );
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
    let native_budget = 16u64 << 30;
    let registration_budget = 64u64 << 30;
    let crypto = graph_crypto::Plan::new(
        &plan,
        &graph,
        graph_crypto::Policy {
            child_memory_budget_bytes: native_budget,
            ..graph_crypto::Policy::default()
        },
    )
    .unwrap();
    let auxiliary = AuxiliaryFactory::new(&plan, &graph, &context, native_budget).unwrap();
    let factory = Factory::new(&plan, &graph, &context).unwrap();
    let ordinal = plan
        .leaves()
        .iter()
        .position(|leaf| leaf.operation_indices() == [operation])
        .unwrap();
    let request = |subrequest| {
        crypto
            .requests()
            .iter()
            .find(|r| r.operation_index() == operation && r.subrequest() == subrequest)
            .unwrap()
    };
    let mut request_registrations = 0;
    let first = complete_request_shape(
        request(0),
        &context,
        128,
        native_budget,
        registration_budget,
        &mut request_registrations,
    );
    compare_request(operation, 0, &first.geometry);
    let (compiled, branch_registrations, rejected_contract_substitutions) = if operation == 624 {
        let second = complete_request_shape(
            request(1),
            &context,
            128,
            native_budget,
            registration_budget,
            &mut request_registrations,
        );
        compare_request(operation, 1, &second.geometry);
        let uniform = auxiliary_template(
            auxiliary
                .request(operation, AuxiliaryRole::AlphaUniform)
                .unwrap(),
        );
        let sparse = auxiliary_template(
            auxiliary
                .request(operation, AuxiliaryRole::AlphaSparse)
                .unwrap(),
        );
        let uniform_branch = factory
            .compile_alpha_uniform(
                operation,
                &first.key,
                &first.invalid_proof,
                uniform.uniform().unwrap(),
            )
            .unwrap();
        let sparse_branch = factory
            .compile_alpha_sparse(
                operation,
                &second.key,
                &second.invalid_proof,
                sparse.sparse().unwrap(),
            )
            .unwrap();
        // Baseline compilation above succeeds despite invalid proof witnesses.
        // The wrong trusted request contracts must fail compilation itself.
        assert!(factory
            .compile_alpha_uniform(
                operation,
                &second.key,
                &second.invalid_proof,
                uniform.uniform().unwrap()
            )
            .is_err());
        assert!(factory
            .compile_alpha_sparse(
                operation,
                &first.key,
                &first.invalid_proof,
                sparse.sparse().unwrap()
            )
            .is_err());
        let (uniform_key, uniform_proof) =
            register_invalid_branch(uniform_branch, "alpha-uniform-branch", operation);
        let (sparse_key, sparse_proof) =
            register_invalid_branch(sparse_branch, "alpha-sparse-branch", operation);
        let compiled = graph_tree::compile_leaf(
            &plan,
            &graph,
            ordinal,
            &context,
            LeafArtifact::ExpandAlphaBranches {
                uniform: Artifact {
                    key: &uniform_key,
                    proof: &uniform_proof,
                },
                sparse: Artifact {
                    key: &sparse_key,
                    proof: &sparse_proof,
                },
            },
        )
        .unwrap();
        assert!(graph_tree::compile_leaf(
            &plan,
            &graph,
            ordinal,
            &context,
            LeafArtifact::ExpandAlphaBranches {
                uniform: Artifact {
                    key: &sparse_key,
                    proof: &sparse_proof
                },
                sparse: Artifact {
                    key: &uniform_key,
                    proof: &uniform_proof
                },
            }
        )
        .is_err());
        (compiled, 2, 3)
    } else {
        let transcript = auxiliary_template(
            auxiliary
                .request(operation, AuxiliaryRole::HashXTranscript)
                .unwrap(),
        );
        let sparse = auxiliary_template(
            auxiliary
                .request(operation, AuxiliaryRole::HashXSparse)
                .unwrap(),
        );
        let branch = factory
            .compile_hash_x(
                operation,
                &first.key,
                &first.invalid_proof,
                transcript.transcript().unwrap(),
            )
            .unwrap();
        let (key, proof) =
            register_invalid_branch(branch, "hash-x-transcript-shake-branch", operation);
        let compiled = graph_tree::compile_leaf(
            &plan,
            &graph,
            ordinal,
            &context,
            LeafArtifact::HashXBranch {
                branch: Artifact {
                    key: &key,
                    proof: &proof,
                },
                sampler: sparse.sparse().unwrap(),
            },
        )
        .unwrap();
        (compiled, 1, 0)
    };
    let geometry = compiled.geometry().unwrap();
    report("atomic-graph-consumer", operation, &geometry);
    assert!(compiled.evaluate().is_err());
    eprintln!(
        "BRANCH_SHAPE_RESULT {}",
        serde_json::json!({
            "operation": operation, "registered_graph_schedule_entries": plan.leaves().len(),
            "algebra_configuration": limits_record, "graph_ordinal": ordinal,
            "actual_request_cap_registrations": request_registrations,
            "actual_branch_cap_registrations": branch_registrations,
            "compiler_contract_substitutions_rejected": rejected_contract_substitutions,
            "atomic_graph_consumer_active_rows": geometry.active_rows,
            "atomic_graph_consumer_padded_rows": geometry.padded_rows,
            "atomic_graph_consumer_retained_lde_bytes": geometry.retained_lde_bytes,
            "native_proofs_produced": 0, "outer_proofs_produced": 0,
            "valid_proof_mutation_security_established": false,
            "complete_graph_acceptance": false, "seconds": started.elapsed().as_secs_f64(),
            "scope": "Exact trusted-cap shape registration and compiler contract checks using deliberately invalid templates. Valid-proof public/root/context mutation qualification remains outstanding.",
        })
    );
}
