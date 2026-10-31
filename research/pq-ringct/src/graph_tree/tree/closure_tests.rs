//! Real registered graph leaf/parent caps and next-level geometry. Invalid
//! outer templates are used only to compile shape; they are never accepted.
use super::*;
use crate::{
    graph_proofs::{ComponentKind, GraphProofPlan, ResourceLimits},
    graph_sources::{SourceCache, SourceFactory},
    rust_verify::{committed_backend, Proof, Statement},
};
use std::{path::PathBuf, time::Instant};

fn report_geometry(label: &str, geometry: &Geometry) {
    eprintln!(
        "GRAPH_CLOSURE_GEOMETRY {}",
        serde_json::json!({
            "phase": label,
            "active_rows": geometry.active_rows,
            "padded_rows": geometry.padded_rows,
            "wires": geometry.wires,
            "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks,
            "constraints": geometry.constraints,
            "max_constraint_degree": geometry.max_constraint_degree,
            "fri_ali_bits": geometry.fri_ali_bits,
            "retained_lde_bytes": geometry.retained_lde_bytes,
        })
    );
}

fn register(compiled: CompiledNode, label: &str) -> PreparedNode {
    let geometry = compiled.geometry().unwrap();
    report_geometry(label, &geometry);
    let preprocessing_bytes = geometry.padded_rows as u64
        * (2_u64 << lattica_prover_p3::block_v2::profile::LOG_BLOWUP)
        * geometry.preprocessed_width as u64
        * 8;
    assert!(
        preprocessing_bytes <= 16_u64 << 30,
        "preprocessing payload alone exceeds the 16 GiB diagnostic guard"
    );
    // Full reference-prover admission is unchanged. The process's separate
    // 16 GiB guard covers registration only, not a 32 GiB outer-proof claim.
    let started = Instant::now();
    let prepared = compiled.prepare(32_u64 << 30).unwrap();
    eprintln!(
        "GRAPH_CLOSURE_REGISTER {}",
        serde_json::json!({"phase": label, "seconds": started.elapsed().as_secs_f64(), "preprocessing_payload_bytes": preprocessing_bytes})
    );
    prepared
}

fn invalid_shape_template(key: &NodeKey, context: &GraphContext) -> NodeProof {
    NodeProof {
        public: header(&key.spec, context),
        proof: verifier::template::batch(&key.air().unwrap()).unwrap(),
    }
}

#[test]
#[ignore = "real graph sources, fixed leaf proof and parent source-cap registrations; coordinated 16 GiB diagnostic guard"]
fn actual_graph_source_caps_and_next_level_closure_geometry() {
    let started = Instant::now();
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
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    assert_ne!(*algebra.batches()[0].kind(), ComponentKind::External);
    let plan = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = GraphContext {
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
    let directory = std::env::var_os("LATTICA_GRAPH_SOURCE_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tools/pq-child-cache/sources")
        });
    let cache = SourceCache::new(directory, 64 << 20).unwrap();
    let sources = SourceFactory::new(
        &plan,
        &graph,
        &context,
        &fixture.statement,
        &fixture.proof,
        8 << 30,
    )
    .unwrap();
    let mut keys = Vec::new();

    let fixed = compile_leaf(&plan, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    fixed.evaluate().unwrap();
    let prepared = register(fixed, "fixed-leaf");
    let fixed_key = prepared.key();
    let tick = Instant::now();
    let fixed_proof = prepared.prove().unwrap();
    eprintln!(
        "GRAPH_CLOSURE_FIXED_PROOF seconds={}",
        tick.elapsed().as_secs_f64()
    );
    drop(prepared);
    fixed_key.verify(&fixed_proof).unwrap();
    assert!(fixed_key.verify_complete(&fixed_proof, &context).is_err());
    keys.push(fixed_key);

    {
        let tick = Instant::now();
        let statement = sources.prove_or_load_statement(&cache).unwrap();
        eprintln!(
            "GRAPH_CLOSURE_NATIVE_STATEMENT seconds={}",
            tick.elapsed().as_secs_f64()
        );
        let compiled = compile_leaf(
            &plan,
            &graph,
            1,
            &context,
            LeafArtifact::Statement(&statement),
        )
        .unwrap();
        compiled.evaluate().unwrap();
        let prepared = register(compiled, "statement-leaf");
        keys.push(prepared.key());
        drop(prepared);
    }
    {
        let tick = Instant::now();
        let private = sources.prove_or_load_private(&cache).unwrap();
        eprintln!(
            "GRAPH_CLOSURE_NATIVE_PRIVATE seconds={}",
            tick.elapsed().as_secs_f64()
        );
        let compiled = compile_leaf(
            &plan,
            &graph,
            2,
            &context,
            LeafArtifact::PrivateProof(&private),
        )
        .unwrap();
        compiled.evaluate().unwrap();
        let prepared = register(compiled, "private-leaf");
        keys.push(prepared.key());
        drop(prepared);
    }
    {
        let tick = Instant::now();
        let child = algebra.prove_batch(0).unwrap();
        eprintln!(
            "GRAPH_CLOSURE_NATIVE_ALGEBRA seconds={} operations={:?}",
            tick.elapsed().as_secs_f64(),
            algebra.batches()[0].operation_indices()
        );
        let compiled = compile_leaf(&plan, &graph, 3, &context, child.as_leaf_artifact()).unwrap();
        compiled.evaluate().unwrap();
        let prepared = register(compiled, "algebra-leaf");
        keys.push(prepared.key());
        drop(prepared);
    }

    let mut parents = Vec::new();
    for (index, pair) in keys.chunks_exact(2).enumerate() {
        let left_template = invalid_shape_template(&pair[0], &context);
        let right_template = invalid_shape_template(&pair[1], &context);
        let left = if index == 0 {
            &fixed_proof
        } else {
            &left_template
        };
        // Calling private merge_impl here is strictly a geometry diagnostic.
        // It emits both complete verifiers under the actual registered caps;
        // these invalid witness templates are not evaluated, accepted or proved.
        let compiled = merge_impl(&pair[0], &pair[1], [left, &right_template]).unwrap();
        drop(left_template);
        drop(right_template);
        let prepared = register(compiled, &format!("parent-{index}"));
        parents.push(prepared.key());
        drop(prepared);
    }
    drop(fixed_proof);
    drop(keys);
    let left = invalid_shape_template(&parents[0], &context);
    let right = invalid_shape_template(&parents[1], &context);
    let next = merge_impl(&parents[0], &parents[1], [&left, &right]).unwrap();
    let geometry = next.geometry().unwrap();
    report_geometry("next-level", &geometry);
    let stable = parents.iter().all(|key| key.height == geometry.padded_rows);
    eprintln!(
        "GRAPH_CLOSURE_RESULT {}",
        serde_json::json!({
            "height_stable": stable,
            "active_row_margin": geometry.padded_rows - geometry.active_rows,
            "real_leaf_caps": 4,
            "real_parent_caps": 2,
            "actual_fixed_leaf_outer_proof": true,
            "actual_statement_private_algebra_native_proofs": true,
            "other_leaf_outer_proofs": false,
            "outer_parent_proofs": false,
            "complete_graph_proof": false,
            "covered_schedule_entries": 4,
            "registered_schedule_entries": plan.leaves().len(),
            "seconds": started.elapsed().as_secs_f64(),
        })
    );
    assert!(merge_impl(&parents[0], &parents[0], [&left, &left]).is_err());
    assert!(merge_impl(&parents[1], &parents[0], [&right, &left]).is_err());
}
