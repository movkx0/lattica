//! Opt-in proof qualification of one exact interval. This never invokes a
//! complete-request proving loop and never claims complete graph acceptance.
use super::*;
use crate::{
    graph_crypto::{self, Admission, Policy, Request, SegmentArtifact},
    graph_proofs::{GraphProofPlan, ResourceLimits},
    graph_tree::{self, GraphContext},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use lattica_prover_p3::block_v2::profile;
use sha3::{Digest, Sha3_256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

fn public_delta(artifact: &mut SegmentArtifact, value: Val) {
    match artifact {
        SegmentArtifact::Aes(a) => a.public_values[0] += value,
        SegmentArtifact::Shake(a) => a.public_values[0] += value,
    }
}
fn opening_delta(artifact: &mut SegmentArtifact, value: profile::Challenge) {
    match artifact {
        SegmentArtifact::Aes(a) => a.proof.opened_values.trace_local[0] += value,
        SegmentArtifact::Shake(a) => a.proof.opened_values.trace_local[0] += value,
    }
}

fn archive_checks(
    cache: &graph_crypto::ProofCache,
    request: &Request,
    index: usize,
    archive: &Path,
    directory: &Path,
) {
    let original = fs::read(archive).unwrap();
    let imported = cache.import_segment(request, index, archive).unwrap();
    assert_eq!(
        imported.archive_sha3_256,
        <[u8; 32]>::from(Sha3_256::digest(&original))
    );
    assert!(imported.archived_source_fingerprint.is_none());
    request.verify_segment(index, &imported.artifact).unwrap();
    assert!(cache.import_segment(request, index ^ 1, archive).is_err());
    drop(imported);
    let path = directory.join(format!(
        "serial-import-probe-{}-{index}.json",
        std::process::id()
    ));
    assert!(!path.exists());
    for mutation in 0..4 {
        let (mut schema, mut key, mut public, mut proof): (
            u64,
            String,
            Vec<Val>,
            p3_uni_stark::Proof<Config>,
        ) = serde_json::from_slice(&original).unwrap();
        match mutation {
            0 => schema += 1,
            1 => key = "00".repeat(32),
            2 => public[0] += Val::ONE,
            _ => proof.opened_values.trace_local[0] += profile::Challenge::ONE,
        }
        let bytes = serde_json::to_vec(&(schema, key, public, proof)).unwrap();
        fs::write(&path, &bytes).unwrap();
        if mutation == 1 {
            // Archive key metadata is not trusted provenance or a circuit key.
            let imported = cache.import_segment(request, index, &path).unwrap();
            assert_eq!(imported.archived_key, [0; 32]);
            assert_ne!(imported.current_key, imported.archived_key);
        } else {
            assert!(cache.import_segment(request, index, &path).is_err());
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    fs::remove_file(path).unwrap();
    assert_eq!(fs::read(archive).unwrap(), original);
}

#[test]
#[ignore = "actual selected serial native proof; outer phase requires explicit48GiB opt-in and external guard"]
fn actual_serial_segment_native_and_optional_outer_qualification() {
    assert_eq!(
        std::env::var("LATTICA_CRYPTO_SEGMENT_PROOF_OPT_IN").as_deref(),
        Ok("1")
    );
    let started = Instant::now();
    let mode = std::env::var("LATTICA_CRYPTO_SEGMENT_PROOF_MODE").expect("explicit segment mode");
    let (aes_maximum, shake_maximum, operation, units) = match mode.as_str() {
        "aes64" => (64, 32, 1017, 64),
        "aes32" => (32, 16, 1017, 32),
        "shake32" => (64, 32, 622, 32),
        "shake16" => (32, 16, 622, 16),
        _ => panic!("unsupported selected serial qualification mode"),
    };
    let index = std::env::var("LATTICA_CRYPTO_SEGMENT_PROOF_INDEX")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(1);
    assert!(
        index <= 1,
        "select the exact first or first interior full batch"
    );
    let outer = match std::env::var("LATTICA_CRYPTO_SEGMENT_OUTER_OPT_IN") {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "0" => false,
        Ok(value) if value == "1" => true,
        other => panic!("invalid outer qualification opt-in: {other:?}"),
    };
    let directory = PathBuf::from(
        std::env::var_os("LATTICA_CRYPTO_QUALIFICATION_DIRECTORY")
            .expect("explicit persistent shared qualification directory"),
    );
    let fixture_path = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit preserved graph fixture"),
    );
    let fixture = crate::native_test_fixture::load_or_create(
        &fixture_path,
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
    let limits = ResourceLimits {
        max_batch_count: 64,
        max_ntt_batch_count: 32,
        max_mul_batch_count: 32,
        max_trace_cells: 1 << 27,
        max_estimated_prover_bytes: 16 << 30,
    };
    let algebra = GraphProofPlan::new(&shape, &graph, limits).unwrap();
    let tree = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    assert_eq!(tree.leaves().len(), 91);
    let context = GraphContext {
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
    let plan = graph_crypto::Plan::new(
        &tree,
        &graph,
        Policy {
            maximum_aes_blocks: aes_maximum,
            maximum_shake_permutations: shake_maximum,
            child_memory_budget_bytes: 32 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap();
    let request = plan
        .requests()
        .iter()
        .find(|r| r.operation_index() == operation && r.subrequest() == 0)
        .unwrap();
    let segment = &request.segments()[index];
    assert_eq!(segment.units, units);
    assert_eq!(segment.first_unit, index * units);
    let native_cache = graph_crypto::ProofCache::new(directory.join("native"), 64 << 20).unwrap();
    let explicit_archive =
        std::env::var_os("LATTICA_CRYPTO_SEGMENT_NATIVE_ARCHIVE").map(PathBuf::from);
    let native_start = Instant::now();
    let (mut artifact, archive_path, native_cache_hit, native_proof_generated, archive_imported) =
        if let Some(path) = explicit_archive {
            let imported = native_cache.import_segment(request, index, &path).unwrap();
            eprintln!(
                "SERIAL_SEGMENT_ARCHIVE {}",
                serde_json::json!({
                    "path": path, "archived_schema": imported.archived_schema,
                    "archived_key": imported.archived_key,
                    "archived_source_fingerprint": imported.archived_source_fingerprint,
                    "archive_sha3_256": imported.archive_sha3_256,
                    "current_key": imported.current_key, "current_source_fingerprint": imported.current_source_fingerprint,
                    "archive_metadata_is_authenticated_build_provenance": false,
                    "automatic_cache_hit": false, "promoted_to_current_cache": false,
                })
            );
            (imported.artifact, path, false, false, true)
        } else if outer {
            let artifact = native_cache.load(request, index).unwrap().expect(
                "outer phase requires an existing current cache entry or explicit native archive",
            );
            (
                artifact,
                native_cache.entry_path(&request.cache_key(index).unwrap()),
                true,
                false,
                false,
            )
        } else {
            let native = native_cache.load_or_prove(request, index).unwrap();
            (
                native.artifact,
                native_cache.entry_path(&native.key),
                native.cache_hit,
                !native.cache_hit,
                false,
            )
        };
    let native_seconds = native_start.elapsed().as_secs_f64();
    let archive_bytes = fs::read(&archive_path).unwrap();
    let archive_digest: [u8; 32] = Sha3_256::digest(&archive_bytes).into();
    request.verify_segment(index, &artifact).unwrap();
    public_delta(&mut artifact, Val::ONE);
    assert!(request.verify_segment(index, &artifact).is_err());
    public_delta(&mut artifact, -Val::ONE);
    opening_delta(&mut artifact, profile::Challenge::ONE);
    assert!(request.verify_segment(index, &artifact).is_err());
    opening_delta(&mut artifact, -profile::Challenge::ONE);
    request.verify_segment(index, &artifact).unwrap();
    archive_checks(&native_cache, request, index, &archive_path, &directory);
    let native_cache_replayed = if archive_imported {
        false
    } else {
        let replay = native_cache.load(request, index).unwrap().unwrap();
        assert_eq!(replay.public_values(), artifact.public_values());
        true
    };
    let compiled = request
        .compile_segment_leaf(index, &context, &artifact)
        .unwrap();
    let geometry = compiled.geometry().unwrap();
    compiled.evaluate().unwrap();
    eprintln!(
        "SERIAL_SEGMENT_NATIVE {}",
        serde_json::json!({
            "mode": mode, "operation": operation, "request_index": request.request_index(),
            "segment_index": index, "first_unit": segment.first_unit, "units": segment.units,
            "complete_request_units": request.units(), "complete_partition_segments": request.segments().len(),
            "descriptor": format!("{:?}", request.descriptor()), "graph_leaves": tree.leaves().len(),
            "profile_label": tree.label(), "native_cache_hit": native_cache_hit,
            "native_proof_generated": native_proof_generated, "native_seconds": native_seconds,
            "native_width": segment.width, "native_height": segment.height,
            "native_estimated_peak_bytes": segment.estimated_peak_bytes,
            "native_cache_replayed": native_cache_replayed, "explicit_archive_imported": archive_imported,
            "archive_path": archive_path, "archive_bytes": archive_bytes.len(), "archive_sha3_256": archive_digest,
            "current_source_fingerprint": crate::graph_proofs::compiled_source_fingerprint(),
            "native_public_mutation_rejected": true, "native_opening_mutation_rejected": true,
            "explicit_archive_roundtrip_verified": true, "wrong_interval_archive_rejected": true,
            "archive_schema_public_opening_mutations_rejected": true,
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "retained_lde_bytes": geometry.retained_lde_bytes, "checked_recursive_trace": true,
            "complete_request": false, "complete_graph": false, "outer_proof": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    if !outer {
        return;
    }
    let budget = std::env::var("LATTICA_CRYPTO_SEGMENT_OUTER_BYTES")
        .expect("explicit outer retained budget and separate48GiB process guard required")
        .parse::<u64>()
        .unwrap();
    assert!(budget > 0 && budget <= 48u64 << 30);
    assert!(geometry.retained_lde_bytes <= budget);
    let outer_cache = OuterProofCache::new(directory.join("outer"), 64 << 20).unwrap();
    let outer_start = Instant::now();
    let mut proven = compiled
        .prepare(budget)
        .unwrap()
        .prove_or_load(&outer_cache)
        .unwrap();
    let outer_seconds = outer_start.elapsed().as_secs_f64();
    proven.key.verify(&proven.proof).unwrap();
    assert!(proven
        .key
        .verify_request(&proven.proof, &request.endpoint_context_hint(&context))
        .is_err());
    let cache_hit = proven.cache_hit;
    let identity = proven.identity;
    for public_index in [CONTEXT, STATEMENT, FIRST, COUNT, REQUEST, EXPECTED_INPUT] {
        proven.proof.public[public_index] += Val::ONE;
        assert!(proven.key.verify(&proven.proof).is_err());
        proven.proof.public[public_index] -= Val::ONE;
    }
    proven.key.verify(&proven.proof).unwrap();
    proven.proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += profile::Challenge::ONE;
    assert!(proven.key.verify(&proven.proof).is_err());
    drop(proven);
    let replay_start = Instant::now();
    let replay = request
        .compile_segment_leaf(index, &context, &artifact)
        .unwrap()
        .prepare(budget)
        .unwrap()
        .prove_or_load(&outer_cache)
        .unwrap();
    assert!(replay.cache_hit);
    assert_eq!(replay.identity, identity);
    replay.key.verify(&replay.proof).unwrap();
    assert_eq!(fs::read(&archive_path).unwrap(), archive_bytes);
    eprintln!(
        "SERIAL_SEGMENT_OUTER {}",
        serde_json::json!({
            "mode": mode, "operation": operation, "request_index": request.request_index(),
            "segment_index": index, "first_unit": segment.first_unit, "units": segment.units,
            "outer_cache_hit": cache_hit, "outer_identity": identity, "outer_seconds": outer_seconds,
            "fresh_registration_cache_replay": true, "replay_seconds": replay_start.elapsed().as_secs_f64(),
            "public_mutation_rejected": true, "opening_mutation_rejected": true,
            "public_mutations_rejected": ["context", "statement", "first", "count", "request", "expected_input"],
            "incomplete_request_rejected": true, "native_archive_unchanged": true,
            "outer_proof": true, "complete_request": false, "complete_graph": false,
            "retained_lde_bytes": geometry.retained_lde_bytes,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}
