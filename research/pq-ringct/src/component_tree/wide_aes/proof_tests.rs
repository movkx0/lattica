use crate::{
    graph_crypto::{Plan, Policy, ProofCache, RequestDescriptor, WideAesFactory},
    graph_tree,
};
use lattica_prover_p3::block_v2::profile;
use sha3::{Digest, Sha3_256};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tools/pq-wide-aes-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

use super::*;
use crate::{
    component_tree,
    graph_proofs::{GraphProofPlan, ResourceLimits},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape, Operation},
        Proof, Statement,
    },
};
use std::time::Instant;

fn cache_checks(factory: &WideAesFactory<'_>, artifact: &WideAesProof) {
    let directory = Directory::new();
    let cache = ProofCache::new(&directory.0, 64 << 20).unwrap();
    cache.store_wide_aes(factory, artifact).unwrap();
    let path = cache.entry_path(&factory.cache_key().unwrap());
    let original = std::fs::read(&path).unwrap();
    let replay = cache.load_or_prove_wide_aes(factory).unwrap();
    assert!(replay.cache_hit);
    drop(replay);
    for mutation in 0..5 {
        let (mut schema, mut key, mut source, mut public, mut proof): (
            u64,
            String,
            [u8; 32],
            Vec<Val>,
            p3_uni_stark::Proof<profile::Config>,
        ) = serde_json::from_slice(&original).unwrap();
        match mutation {
            0 => schema += 1,
            1 => key = "00".repeat(32),
            2 => source[0] ^= 1,
            3 => public[0] += Val::ONE,
            _ => proof.opened_values.trace_local[0] += profile::Challenge::ONE,
        }
        let changed = serde_json::to_vec(&(schema, key, source, public, proof)).unwrap();
        std::fs::write(&path, &changed).unwrap();
        assert!(cache.load_wide_aes(factory).is_err());
        assert!(cache.load_or_prove_wide_aes(factory).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), changed);
        if mutation == 2 {
            // Corrupted metadata is only reported, never authenticated.
            // Explicit import still verifies the unchanged actual native proof.
            let imported = cache.import_wide_aes(factory, &path).unwrap();
            assert_ne!(
                imported.archived_source_fingerprint,
                imported.current_source_fingerprint
            );
            assert_eq!(std::fs::read(&path).unwrap(), changed);
        }
        if mutation == 0 || mutation >= 3 {
            assert!(cache.import_wide_aes(factory, &path).is_err());
        }
        std::fs::write(&path, &original).unwrap();
    }
    let imported = cache.import_wide_aes(factory, &path).unwrap();
    factory.verify(&imported.artifact).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

fn exact_request(alpha_uniform: bool) {
    let started = Instant::now();
    let fixture_path = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing exact public graph fixture required"),
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
    let plan = Plan::new(&tree, &graph, Policy::default()).unwrap();
    let request = plan
        .requests()
        .iter()
        .find(|r| match graph.operations()[r.operation_index()] {
            Operation::ExpandAlpha { .. } => alpha_uniform && r.subrequest() == 0,
            Operation::SampleG { .. } => !alpha_uniform,
            _ => false,
        })
        .unwrap();
    let (label, descriptor, blocks) = if alpha_uniform {
        (
            "alpha-uniform161",
            aes_air::Descriptor {
                domain: 0x4368,
                start_counter: 0,
                output_len: 2572,
            },
            161,
        )
    } else {
        (
            "sample-g300",
            aes_air::Descriptor {
                domain: 0,
                start_counter: 0,
                output_len: 4788,
            },
            300,
        )
    };
    assert_eq!(request.descriptor(), RequestDescriptor::Aes(descriptor));
    assert_eq!(request.units(), blocks);
    let budget = std::env::var("LATTICA_WIDE_AES_NATIVE_BYTES")
        .expect("explicit native estimate admission and separate external guard required")
        .parse::<u64>()
        .unwrap();
    assert!(
        budget > 0 && budget <= 16_u64 << 30,
        "local native admission exceeds16GiB"
    );
    let factory = request.wide_aes(budget).unwrap();
    let cache = ProofCache::new(
        PathBuf::from(
            std::env::var_os("LATTICA_WIDE_AES_CACHE")
                .expect("explicit persistent wide AES native cache required"),
        ),
        64 << 20,
    )
    .unwrap();
    let explicit_archive = std::env::var_os("LATTICA_WIDE_AES_ARCHIVE").map(PathBuf::from);
    let (mut artifact, archive_path, archive_digest, cache_hit) =
        if let Some(path) = explicit_archive {
            let imported = cache.import_wide_aes(&factory, &path).unwrap();
            eprintln!(
                "WIDE_AES_ARCHIVE {}",
                serde_json::json!({
                    "label": label, "path": path, "archived_schema": imported.archived_schema,
                    "archived_key": imported.archived_key,
                    "archived_source_fingerprint": imported.archived_source_fingerprint,
                    "archive_sha3_256": imported.archive_sha3_256,
                    "current_key": imported.current_key,
                    "current_source_fingerprint": imported.current_source_fingerprint,
                    "native_proof_verified_under_current_registration": true,
                    "archive_metadata_is_authenticated_build_provenance": false,
                    "automatic_cache_hit": false, "promoted_to_current_cache": false,
                })
            );
            (imported.artifact, path, imported.archive_sha3_256, false)
        } else {
            let native = cache.load_or_prove_wide_aes(&factory).unwrap();
            let path = cache.entry_path(&native.key);
            let digest: [u8; 32] = Sha3_256::digest(std::fs::read(&path).unwrap()).into();
            (native.artifact, path, digest, native.cache_hit)
        };
    let native_geometry = factory.geometry();
    eprintln!(
        "WIDE_AES_NATIVE {}",
        serde_json::json!({
            "label": label, "operation": request.operation_index(), "request_index": request.request_index(),
            "domain": descriptor.domain, "start_counter": descriptor.start_counter,
            "output_len": descriptor.output_len, "blocks": blocks,
            "width": native_geometry.width, "height": native_geometry.height,
            "raw_trace_bytes": native_geometry.raw_trace_bytes,
            "retained_main_lde_bytes": native_geometry.retained_main_lde_bytes,
            "uncalibrated_peak_estimate_bytes": native_geometry.uncalibrated_peak_estimate_bytes,
            "cache_hit": cache_hit, "archive_path": archive_path,
            "source_fingerprint": crate::graph_proofs::compiled_source_fingerprint(),
            "native_proof_verified": true, "outer_proof": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    for offset in [0, 4] {
        artifact.public_values[offset] += Val::ONE;
        assert!(factory.verify(&artifact).is_err());
        artifact.public_values[offset] -= Val::ONE;
    }
    artifact.proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(factory.verify(&artifact).is_err());
    artifact.proof.opened_values.trace_local[0] -= profile::Challenge::ONE;
    factory.verify(&artifact).unwrap();
    cache_checks(&factory, &artifact);
    let mut compiled = factory.compile_leaf(&context, &artifact).unwrap();
    let geometry = compiled.geometry().unwrap();
    eprintln!(
        "WIDE_AES_GEOMETRY {}",
        serde_json::json!({
            "label": label, "operation": request.operation_index(), "request_index": request.request_index(),
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks, "retained_lde_bytes": geometry.retained_lde_bytes,
            "outer_proof": false, "checked_recursive_verifier_trace": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    compiled.evaluate().unwrap();
    for offset in [
        0,
        component_tree::EXPECTED_INPUT,
        component_tree::EXPECTED_OUTPUT,
        component_tree::HEADER,
    ] {
        compiled.public[offset] += Val::ONE;
        assert!(compiled.evaluate().is_err());
        compiled.public[offset] -= Val::ONE;
    }
    for offset in [0, 4] {
        compiled.witness[offset] += Val::ONE;
        assert!(compiled.evaluate().is_err());
        compiled.witness[offset] -= Val::ONE;
    }
    compiled.evaluate().unwrap();
    let digest: [u8; 32] = Sha3_256::digest(std::fs::read(&archive_path).unwrap()).into();
    assert_eq!(
        digest, archive_digest,
        "actual native archive must remain unchanged"
    );
    eprintln!(
        "WIDE_AES_CHECKED {}",
        serde_json::json!({
            "label": label, "operation": request.operation_index(), "request_index": request.request_index(),
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks, "retained_lde_bytes": geometry.retained_lde_bytes,
            "checked_recursive_verifier_trace": true, "native_public_mutations_rejected": 2,
            "native_opening_mutation_rejected": true, "cache_mutations_rejected": 5,
            "public_mutations_rejected": 4, "child_public_mutations_rejected": 2,
            "archive_unchanged": true, "security_profile_changed": false, "outer_proof": false,
            "complete_operation_graph_leaf": false, "complete_matrict_graph": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}

#[test]
#[ignore = "actual exact Alpha uniform161 wide AES native proof and wrapper trace; coordinate16GiB guard"]
fn actual_alpha_uniform161_whole_wide_aes_native_and_wrapper_geometry() {
    exact_request(true);
}

#[test]
#[ignore = "actual exact SampleG300 wide AES native proof and wrapper trace; coordinate16GiB guard"]
fn actual_sample_g300_whole_wide_aes_native_and_wrapper_geometry() {
    exact_request(false);
}
