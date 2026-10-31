//! Exact scheduled leaf geometry with deliberately invalid native proof inputs.
//! No native or outer proof is generated, no cap is registered, and successful
//! compilation is not proof acceptance. The six composite crypto leaves have
//! separate diagnostics and remain explicitly outside this screen.
use super::*;
use crate::{
    component_tree::shape_diagnostic::invalid_native_template,
    graph_tree::{self, GraphContext, LeafArtifact},
    proof_air::{join::ProofArtifact, ProofAir, ProofValues},
    statement_air::{
        bundle::{StatementBundle, StatementProof},
        StatementAir,
    },
};
use p3_field::PrimeCharacteristicRing;

fn invalid_algebra(plan: &GraphProofPlan<'_>, index: usize) -> ComponentArtifact {
    let batch = &plan.batches()[index];
    let public = plan.expected_public_values(batch).unwrap();
    let count = batch.indices.len();
    let artifact = match &batch.kind {
        ComponentKind::Affine { kind, modulus } => {
            let key = crate::affine_air::RegisteredAffineAir::new(*kind, *modulus, count).unwrap();
            ComponentArtifact::Affine(AffineBatchProof {
                public_values: public.try_into().unwrap(),
                proof: invalid_native_template(key.air(), key.air().height()),
            })
        }
        ComponentKind::Ntt { modulus } => {
            let key = crate::ntt_air::RegisteredNttAir::new(*modulus, count).unwrap();
            ComponentArtifact::Ntt(NttBatchProof {
                public_values: public,
                proof: invalid_native_template(key.air(), key.air().height),
            })
        }
        ComponentKind::Mul { modulus } => {
            let key = crate::poly_air::RegisteredMulAir::new(*modulus, count).unwrap();
            ComponentArtifact::Mul(MulBatchProof {
                public_values: public,
                proof: invalid_native_template(key.air(), key.air().height),
            })
        }
        ComponentKind::GBound { bound } => {
            let key = crate::g_bound_air::join::RegisteredGBoundAir::new(*bound).unwrap();
            ComponentArtifact::GBound(GBoundArtifact {
                public_values: public.try_into().unwrap(),
                proof: invalid_native_template(key.air(), crate::g_bound_air::HEIGHT),
            })
        }
        ComponentKind::Permutation { kind } => {
            let key = crate::permutation_air::RegisteredPermutationAir::new(*kind);
            ComponentArtifact::Permutation(PermutationProof {
                public_values: public.try_into().unwrap(),
                proof: invalid_native_template(key.air(), crate::permutation_air::HEIGHT),
            })
        }
        ComponentKind::LinearMap { descriptor } => {
            let key = crate::linear_map_air::RegisteredLinearMapAir::new(descriptor.clone());
            ComponentArtifact::LinearMap(LinearMapProof {
                public_values: public,
                proof: invalid_native_template(key.air(), key.air().height()),
            })
        }
        ComponentKind::External => panic!("external leaf needs its typed producer"),
    };
    assert!(plan.verify_batch(index, &artifact).is_err());
    artifact
}

fn report(
    plan: &graph_tree::Plan,
    graph: &UnprovedRelationGraph,
    context: &GraphContext,
    ordinal: usize,
    artifact: LeafArtifact<'_>,
    invalid_native_input: bool,
    native_estimate: Option<ResourceEstimate>,
) {
    let leaf = &plan.leaves()[ordinal];
    eprintln!(
        "planned leaf geometry begin {}",
        serde_json::json!({
            "ordinal": ordinal, "kind": format!("{:?}", leaf.kind()),
            "operations": leaf.operation_indices(), "invalid_native_input": invalid_native_input,
        })
    );
    let started = std::time::Instant::now();
    let compiled = graph_tree::compile_leaf(plan, graph, ordinal, context, artifact).unwrap();
    let g = compiled.geometry().unwrap();
    eprintln!(
        "planned leaf geometry result {}",
        serde_json::json!({
            "ordinal": ordinal, "kind": format!("{:?}", leaf.kind()),
            "operations": leaf.operation_indices(),
            "compile_and_analysis_seconds": started.elapsed().as_secs_f64(),
            "active_rows": g.active_rows, "padded_rows": g.padded_rows, "wires": g.wires,
            "main_width": g.main_width, "preprocessed_width": g.preprocessed_width,
            "permutation_width_base": g.permutation_width_base,
            "quotient_chunks": g.quotient_chunks, "constraints": g.constraints,
            "max_constraint_degree": g.max_constraint_degree, "fri_ali_bits": g.fri_ali_bits,
            "retained_lde_bytes": g.retained_lde_bytes,
            "retained_lde_below_48_gib": g.retained_lde_bytes < (48u64 << 30),
            "native_estimated_prover_bytes": native_estimate.map(|e| e.estimated_prover_bytes),
            "native_trace_bytes": native_estimate.map(|e| e.trace_bytes),
            "invalid_native_input": invalid_native_input,
            "invalid_native_template_rejected": invalid_native_input,
            "native_proof_generated": false, "outer_proof_attempted": false,
            "trace_evaluated": false, "cap_registered": false,
            "scope": "Compiled exact scheduled leaf geometry only. Invalid proof-shaped input is not a verified proof. Retained LDE is a lower bound, not peak process memory or proof admission.",
        })
    );
}

#[test]
#[ignore = "85 exact scheduled leaf geometries only; invalid native templates; external8GiB guard required"]
fn exact_91_leaf_plan_algebra_sources_and_equalities_geometry() {
    let (_, private, graph, statement_bytes) = tests::archived_fixture(false);
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let limits = ResourceLimits {
        max_batch_count: 64,
        max_ntt_batch_count: 32,
        max_mul_batch_count: 32,
        max_trace_cells: 1 << 27,
        max_estimated_prover_bytes: 32u64 << 30,
    };
    let algebra = GraphProofPlan::new(&registered, &graph, limits).unwrap();
    let plan = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    assert_eq!(plan.leaves().len(), 91);
    assert_eq!(algebra.batches().len(), 88);
    let prior = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_estimated_prover_bytes: 16u64 << 30,
            ..limits
        },
    )
    .unwrap();
    assert_eq!(algebra.operation_batches(), prior.operation_batches());
    let context = GraphContext {
        context: [71; 32],
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            [71; 32],
            &statement_bytes,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(&graph).unwrap(),
    };
    eprintln!(
        "planned leaf geometry configuration {}",
        serde_json::json!({
            "max_batch_count": limits.max_batch_count,
            "max_ntt_batch_count": limits.max_ntt_batch_count,
            "max_mul_batch_count": limits.max_mul_batch_count,
            "max_trace_cells": limits.max_trace_cells,
            "max_estimated_prover_bytes": limits.max_estimated_prover_bytes,
            "schedule_unchanged_from_native_16_gib": true,
            "compiled_source_fingerprint": cache::hex(&compiled_source_fingerprint()),
            "graph_plan_label": cache::hex(&plan.label()),
            "context": context.context, "node_manifest": context.node_manifest,
            "scheduled_leaves": plan.leaves().len(), "expected_screened_leaves": 85,
            "expected_skipped_crypto_leaves": 6, "recursive_wide": true,
            "required_external_address_space_limit_bytes": 8u64 << 30,
        })
    );

    report(
        &plan,
        &graph,
        &context,
        0,
        LeafArtifact::FixedSources,
        false,
        None,
    );
    let bundle = StatementBundle::from_bytes(&statement_bytes).unwrap();
    let mut public = [Val::ZERO; 8];
    public[..4].copy_from_slice(&context.statement);
    public[4..].copy_from_slice(&bundle.commitment());
    let air = StatementAir {
        setup_seed: graph.setup_seed(),
    };
    let statement = StatementProof {
        public_values: public,
        proof: invalid_native_template(&air, crate::statement_air::HEIGHT),
    };
    assert!(
        p3_uni_stark::verify(&profile::make_config(), &air, &statement.proof, &public).is_err()
    );
    report(
        &plan,
        &graph,
        &context,
        1,
        LeafArtifact::Statement(&statement),
        true,
        None,
    );
    let values = ProofValues::from_proof(&private).unwrap();
    let proof = ProofArtifact {
        public_values: values.bundle().unwrap().commitment(),
        proof: invalid_native_template(&ProofAir, crate::proof_air::HEIGHT),
    };
    assert!(p3_uni_stark::verify(
        &profile::make_config(),
        &ProofAir,
        &proof.proof,
        &proof.public_values
    )
    .is_err());
    report(
        &plan,
        &graph,
        &context,
        2,
        LeafArtifact::PrivateProof(&proof),
        true,
        None,
    );

    let (mut algebra_count, mut equalities, mut crypto_skipped) = (0, 0, Vec::new());
    for (index, batch) in algebra.batches().iter().enumerate() {
        let ordinal = index + 3;
        if batch.kind == ComponentKind::External {
            assert_eq!(batch.indices.len(), 1);
            let operation = batch.indices[0];
            if matches!(
                graph.operations()[operation],
                Operation::EqualBytes { .. } | Operation::EqualSigned { .. }
            ) {
                report(
                    &plan,
                    &graph,
                    &context,
                    ordinal,
                    LeafArtifact::Equality,
                    false,
                    None,
                );
                equalities += 1;
            } else {
                crypto_skipped.push(ordinal);
                eprintln!(
                    "planned leaf geometry skipped {}",
                    serde_json::json!({
                        "ordinal": ordinal, "operation": operation,
                        "kind": format!("{:?}", plan.leaves()[ordinal].kind()),
                        "reason": "Composite crypto producer has separate exact-request/branch geometry diagnostics; not screened here.",
                    })
                );
            }
        } else {
            let artifact = invalid_algebra(&algebra, index);
            report(
                &plan,
                &graph,
                &context,
                ordinal,
                artifact.as_leaf_artifact(),
                true,
                batch.estimate,
            );
            algebra_count += 1;
        }
    }
    assert_eq!(
        (algebra_count, equalities, crypto_skipped.len()),
        (79, 3, 6)
    );
    eprintln!(
        "planned leaf geometry complete {}",
        serde_json::json!({
            "scheduled_leaves": 91, "screened_leaves": 85, "algebra_leaves": algebra_count,
            "source_leaves": 3, "equality_leaves": equalities,
            "skipped_crypto_ordinals": crypto_skipped,
            "native_proofs_generated": 0, "outer_proofs_generated": 0,
            "accepted_graph_proofs": 0, "cap_registrations": 0,
            "complete_graph_proof": false,
        })
    );
}
