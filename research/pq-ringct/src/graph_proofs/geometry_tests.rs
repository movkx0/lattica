use super::*;
use lattica_prover_p3::block_v2::machine::{
    analysis, verifier::ProofInputs, MachineAir, ProgramBuilder,
};
use p3_field::PrimeCharacteristicRing;

fn geometry_json(geometry: &crate::component_tree::Geometry) -> serde_json::Value {
    serde_json::json!({
        "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
        "wires": geometry.wires, "main_width": geometry.main_width,
        "preprocessed_width": geometry.preprocessed_width,
        "permutation_width_base": geometry.permutation_width_base,
        "quotient_chunks": geometry.quotient_chunks, "constraints": geometry.constraints,
        "max_constraint_degree": geometry.max_constraint_degree,
        "fri_ali_bits": geometry.fri_ali_bits, "retained_lde_bytes": geometry.retained_lde_bytes,
    })
}

fn archived_geometry(ntt: bool, count: usize) {
    let (_, _, graph, statement_bytes) = tests::archived_fixture(false);
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let plan = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_batch_count: 64,
            max_ntt_batch_count: 32,
            max_mul_batch_count: 16,
            max_trace_cells: 1 << 27,
            max_estimated_prover_bytes: 8 << 30,
        },
    )
    .unwrap();
    let (index, batch) = plan
        .batches()
        .iter()
        .enumerate()
        .filter(|(_, b)| {
            b.indices.len() == count
                && if ntt {
                    matches!(b.kind, ComponentKind::Ntt { .. })
                } else {
                    matches!(b.kind, ComponentKind::Mul { .. })
                }
        })
        .max_by_key(|(_, b)| b.estimate.unwrap().trace_bytes)
        .unwrap();
    let path = std::path::PathBuf::from(std::env::var_os("LATTICA_GRAPH_PROOF_ARCHIVE")
        .expect("explicit LATTICA_GRAPH_PROOF_ARCHIVE path required; this diagnostic never generates a missing child proof"));
    let cache = ProofCache::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tools/pq-child-cache/algebra"),
        64 << 20,
    )
    .unwrap();
    let imported = cache.reverify_archived_entry(&plan, index, &path).unwrap();
    let family = if ntt { "ntt" } else { "mul" };
    let profile_name = if cfg!(feature = "recursive-wide") {
        "wide"
    } else {
        "default"
    };
    eprintln!(
        "graph cached geometry import {}",
        serde_json::json!({
            "family": family, "count": count, "profile": profile_name,
            "archive": path, "archived_key": imported.archived_key,
            "current_key": cache::hex(&imported.current_key),
            "compiled_source_fingerprint": cache::hex(&compiled_source_fingerprint()),
            "classification": "archival proof reverified under current exact AIR/degree/ordered roots; not a source-version cache hit",
        })
    );

    // Standalone typed verifier geometry with the exact verified graph roots.
    // Public roots are constants here only for isolating verifier geometry; the
    // following graph leaf binds them to the shared manifest and schedule.
    let mut builder = ProgramBuilder::new(0).unwrap();
    let mut inputs = ProofInputs::default();
    match (&batch.kind, &imported.artifact) {
        (ComponentKind::Ntt { modulus }, ComponentArtifact::Ntt(artifact)) => {
            let requests: Vec<_> = artifact
                .public_values
                .chunks_exact(8)
                .map(|root| crate::ntt_air::NttRootRequest {
                    modulus: *modulus,
                    input_commitment: core::array::from_fn(|i| builder.constant(root[i])),
                    output_commitment: core::array::from_fn(|i| builder.constant(root[4 + i])),
                })
                .collect();
            crate::ntt_air::RegisteredNttAir::new(*modulus, count)
                .unwrap()
                .compile_root_join(&mut builder, &mut inputs, &requests, artifact)
                .unwrap();
        }
        (ComponentKind::Mul { modulus }, ComponentArtifact::Mul(artifact)) => {
            let requests: Vec<_> = artifact
                .public_values
                .chunks_exact(12)
                .map(|root| crate::poly_air::MulRootRequest {
                    modulus: *modulus,
                    left_commitment: core::array::from_fn(|i| builder.constant(root[i])),
                    right_commitment: core::array::from_fn(|i| builder.constant(root[4 + i])),
                    output_commitment: core::array::from_fn(|i| builder.constant(root[8 + i])),
                })
                .collect();
            crate::poly_air::RegisteredMulAir::new(*modulus, count)
                .unwrap()
                .compile_root_join(&mut builder, &mut inputs, &requests, artifact)
                .unwrap();
        }
        _ => panic!("selected artifact family mismatch"),
    }
    let program = builder.finish(None).unwrap();
    let active = program.active_rows();
    let height = program.height();
    let wires = program.wire_count();
    drop(inputs);
    let air = MachineAir::new(program);
    let report = analysis::analyze(&air).unwrap();
    eprintln!(
        "graph cached typed verifier geometry {}",
        serde_json::json!({
            "family": family, "count": count, "profile": profile_name,
            "active_rows": active, "padded_rows": height, "wires": wires,
            "main_width": report.main_width, "preprocessed_width": report.preprocessed_width,
            "permutation_width_base": report.permutation_width_base,
            "quotient_chunks": report.quotient_chunks, "constraints": report.constraints,
            "max_constraint_degree": report.max_constraint_degree,
            "fri_ali_bits": report.fri_ali_bits, "retained_lde_bytes": report.retained_lde_bytes,
            "trace_evaluated": false, "outer_proof_attempted": false,
        })
    );
    drop(air);

    let tree =
        crate::graph_tree::Plan::from_trusted_graph(&graph, plan.operation_batches()).unwrap();
    let context = crate::graph_tree::GraphContext {
        context: [71; 32],
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(),
            [71; 32],
            &statement_bytes,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    let node = crate::graph_tree::compile_leaf(
        &tree,
        &graph,
        index + 3,
        &context,
        imported.artifact.as_leaf_artifact(),
    )
    .unwrap();
    let geometry = node.geometry().unwrap();
    eprintln!(
        "graph cached leaf geometry {}",
        serde_json::json!({
            "family": family, "count": count, "profile": profile_name,
            "leaf_ordinal": index+3, "operations": batch.indices,
            "geometry": geometry_json(&geometry), "trace_evaluated": false,
            "outer_proof_attempted": false,
            "scope": "Actual child proof reverified and full typed verifier / exact graph-leaf program compiled and analyzed. No witness trace or outer proof generated; retained-LDE bytes are a lower bound, not peak process memory.",
        })
    );
}

#[test]
#[ignore = "archival NTT32 typed/graph-leaf geometry only; external8GiB guard required"]
fn cached_ntt32_typed_and_graph_leaf_geometry() {
    archived_geometry(true, 32);
}

#[test]
#[ignore = "archival Mul16 typed/graph-leaf geometry only; external8GiB guard required"]
fn cached_mul16_typed_and_graph_leaf_geometry() {
    archived_geometry(false, 16);
}
