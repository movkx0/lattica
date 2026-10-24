//! Whole-HashX native evidence and recursive verifier geometry. No outer proof.
use super::*;
use crate::{
    graph_crypto,
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree,
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape, Operation},
        Proof, Statement,
    },
};
use std::{path::PathBuf, time::Instant};

#[test]
#[ignore = "actual wide HashX child and recursive geometry; reserve exclusive16GiB process window"]
fn actual_wide_hash_x_native_proof_and_recursive_geometry() {
    let fingerprint: String = crate::graph_proofs::compiled_source_fingerprint()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    eprintln!("COMPILED_SOURCE_IDENTITY {fingerprint}");
    let path = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing public fixture required"),
    );
    let fixture = crate::native_test_fixture::load_or_create(
        &path,
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
    let algebra = GraphProofPlan::new(&shape, &graph, ResourceLimits::default()).unwrap();
    let tree = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = graph_tree::GraphContext {
        context: fixture.context,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(),
            fixture.context,
            &fixture.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    let crypto = graph_crypto::Plan::new(&tree, &graph, graph_crypto::Policy::default()).unwrap();
    let request = crypto
        .requests()
        .iter()
        .find(|r| {
            matches!(
                graph.operations()[r.operation_index()],
                Operation::HashX { .. }
            )
        })
        .unwrap();
    let factory = request.wide_shake(1024, 8 << 30).unwrap();
    assert_eq!(factory.segments().len(), 1);
    let cache = graph_crypto::ProofCache::new(
        PathBuf::from(
            std::env::var_os("LATTICA_WIDE_SHAKE_CACHE")
                .expect("explicit wide native proof cache required"),
        ),
        64 << 20,
    )
    .unwrap();
    let start = Instant::now();
    let explicit_archive = std::env::var_os("LATTICA_WIDE_SHAKE_ARCHIVE").map(PathBuf::from);
    let (replay, archive_path, original_archive_digest) = if let Some(path) = explicit_archive {
        let imported = cache.import_wide(&factory, 0, &path).unwrap();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        eprintln!(
            "WIDE_HASH_X_ARCHIVE {}",
            serde_json::json!({
                "path": path,
                "archived_schema": imported.archived_schema,
                "archived_key": hex(&imported.archived_key),
                "archived_source_fingerprint": imported.archived_source_fingerprint.as_ref().map(|source| hex(source)),
                "archive_sha3_256": hex(&imported.archive_sha3_256),
                "current_key": hex(&imported.current_key),
                "current_source_fingerprint": hex(&imported.current_source_fingerprint),
                "native_proof_verified_under_current_registration": true,
                "archive_metadata_is_authenticated_build_provenance": false,
                "automatic_cache_hit": false,
                "promoted_to_current_cache": false,
            })
        );
        eprintln!(
            "WIDE_HASH_X_NATIVE {}",
            serde_json::json!({
                "cache_hit": false,
                "explicit_archive_revalidated": true,
                "elapsed_seconds": start.elapsed().as_secs_f64(),
                "native_proof_verified": true,
                "outer_proof": false,
                "operation": request.operation_index(),
                "request_index": request.request_index(),
            })
        );
        (imported.artifact, path, Some(imported.archive_sha3_256))
    } else {
        let native = cache.load_or_prove_wide(&factory, 0).unwrap();
        eprintln!(
            "WIDE_HASH_X_NATIVE {}",
            serde_json::json!({
                "cache_hit": native.cache_hit,
                "explicit_archive_revalidated": false,
                "elapsed_seconds": start.elapsed().as_secs_f64(),
                "native_proof_verified": true,
                "outer_proof": false,
                "operation": request.operation_index(),
                "request_index": request.request_index(),
            })
        );
        let replay = cache
            .load_wide(&factory, 0)
            .unwrap()
            .expect("verified native cache hit");
        assert_eq!(native.artifact.public_values, replay.public_values);
        (replay, cache.entry_path(&native.key), None)
    };
    let mut imported = cache.import_wide(&factory, 0, &archive_path).unwrap();
    assert_eq!(imported.artifact.public_values, replay.public_values);
    if let Some(original_digest) = original_archive_digest {
        use sha3::{Digest, Sha3_256};
        assert_eq!(imported.archive_sha3_256, original_digest);
        let current_digest: [u8; 32] =
            Sha3_256::digest(std::fs::read(&archive_path).unwrap()).into();
        assert_eq!(
            current_digest, original_digest,
            "explicit import changed archive bytes"
        );
    } else {
        assert_eq!(imported.archived_schema, 2);
        assert_eq!(imported.archived_key, factory.cache_key(0).unwrap());
        assert_eq!(
            imported.archived_source_fingerprint,
            Some(imported.current_source_fingerprint)
        );
    }
    imported.artifact.proof.opened_values.trace_local[0] +=
        lattica_prover_p3::block_v2::profile::Challenge::ONE;
    assert!(factory.verify_segment(0, &imported.artifact).is_err());
    drop(imported);
    let start = Instant::now();
    let mut compiled = factory.compile_segment_leaf(0, &context, &replay).unwrap();
    let geometry = compiled.geometry().unwrap();
    eprintln!(
        "WIDE_HASH_X_GEOMETRY {}",
        serde_json::json!({
            "active_rows": geometry.active_rows,
            "padded_rows": geometry.padded_rows,
            "wires": geometry.wires,
            "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks,
            "retained_lde_bytes": geometry.retained_lde_bytes,
            "outer_proof": false,
        })
    );
    compiled.evaluate().unwrap();
    // The same compiled constraints reject public endpoint substitution and
    // modified child proof inputs. These are witness checks, not outer proofs.
    for offset in [EXPECTED_INPUT, EXPECTED_OUTPUT, HEADER] {
        compiled.public[offset] += Val::ONE;
        assert!(compiled.evaluate().is_err());
        compiled.public[offset] -= Val::ONE;
    }
    compiled.witness[shake_air::OUTPUT_END] += Val::ONE;
    assert!(compiled.evaluate().is_err());
    compiled.witness[shake_air::OUTPUT_END] -= Val::ONE;
    compiled.evaluate().unwrap();
    eprintln!(
        "WIDE_HASH_X_CHECKED {}",
        serde_json::json!({
            "elapsed_seconds": start.elapsed().as_secs_f64(),
            "checked_recursive_verifier_trace": true,
            "public_mutations_rejected": 3,
            "child_public_mutation_rejected": true,
            "outer_proof": false,
            "complete_spend_proof": false,
        })
    );
}
