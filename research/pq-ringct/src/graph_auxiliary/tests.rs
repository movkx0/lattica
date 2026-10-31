use super::*;
use crate::{
    graph_proofs::{GraphProofPlan, ResourceLimits},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use p3_field::PrimeCharacteristicRing;

fn fixture() -> (
    UnprovedRelationGraph,
    graph_tree::Plan,
    graph_tree::GraphContext,
) {
    let path = std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE");
    let (statement, proof) = if let Some(path) = path {
        let saved = crate::native_test_fixture::load_or_create(
            std::path::Path::new(&path),
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
        (saved.statement, saved.proof)
    } else {
        let generated = crate::native::generate_fixture_with_setup_seed(
            [71; 32],
            [29; 32],
            3,
            crate::native::FixtureAmounts {
                input: [17, 23],
                output: [29, 11],
            },
        )
        .unwrap();
        (generated.statement, generated.proof)
    };
    let graph = committed_backend::lower_unproved(
        [29; 32],
        &[71; 32],
        &Statement::decode(&statement).unwrap(),
        &Proof::decode(&proof).unwrap(),
    )
    .unwrap();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let tree = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = graph_tree::GraphContext {
        context: [71; 32],
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(),
            [71; 32],
            &statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    (graph, tree, context)
}

#[cfg(feature = "opencl")]
#[test]
#[ignore = "real GPU auxiliary-factory raw-stream and endpoint parity; exclusive admitted OpenCL session"]
fn gpu_auxiliary_factory_matches_cpu_streams_roots_and_roles() {
    assert!(!cfg!(debug_assertions));
    let (graph, tree, context) = fixture();
    let expected = AuxiliaryFactory::new(&tree, &graph, &context, 1 << 30).unwrap();
    let execution = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30,
        device_bytes: 8 << 30,
        max_rows: 4096,
    })
    .unwrap();
    let actual =
        AuxiliaryFactory::new_with_context(&tree, &graph, &context, 1 << 30, Some(&execution))
            .unwrap();
    assert_eq!(actual.requests().len(), expected.requests().len());
    for (actual, expected) in actual.requests().iter().zip(expected.requests()) {
        assert_eq!(actual.operation_index(), expected.operation_index());
        assert_eq!(actual.role(), expected.role());
        assert_eq!(actual.kind(), expected.kind());
        assert_eq!(
            actual.expected_public_values(),
            expected.expected_public_values()
        );
        assert_eq!(actual.cache_key(), expected.cache_key());
        match (&actual.payload, &expected.payload) {
            (Payload::Uniform(a, av), Payload::Uniform(b, bv)) => {
                assert_eq!(a, b);
                assert_eq!(av, bv);
            }
            (Payload::Sparse(a, av), Payload::Sparse(b, bv)) => {
                assert_eq!(a, b);
                assert_eq!(av, bv);
            }
            (Payload::Transcript(a, av), Payload::Transcript(b, bv)) => {
                assert_eq!(a.parts(), b.parts());
                assert_eq!(a.serialize(av).unwrap(), b.serialize(bv).unwrap());
            }
            _ => panic!("auxiliary payload family mismatch"),
        }
    }
    let report = execution.report();
    assert_eq!(report["operations"]["native_cpu_calls"], 0);
    assert_eq!(report["operations"]["native_gpu_calls"], 0);
    assert_eq!(
        report["operations"]["witness_preparation_complete_reports"],
        1
    );
    let mut bad = context.clone();
    bad.node_manifest[0] += Val::ONE;
    assert!(
        AuxiliaryFactory::new_with_context(&tree, &graph, &bad, 1 << 30, Some(&execution),)
            .is_err()
    );
    assert_eq!(
        execution.report()["operations"]["witness_preparation_complete_reports"],
        1
    );
    drop(execution);
}

#[test]
fn exact_operation_roles_roots_context_and_budget_are_bound() {
    let (graph, tree, context) = fixture();
    let factory = AuxiliaryFactory::new(&tree, &graph, &context, 8 << 30).unwrap();
    let mut expected = Vec::new();
    for (index, operation) in graph.operations().iter().enumerate() {
        let roles: &[Role] = match operation {
            Operation::SampleG { .. } => &[Role::SampleGUniform],
            Operation::ExpandAlpha { .. } => &[Role::AlphaUniform, Role::AlphaSparse],
            Operation::HashAlpha { .. } => &[Role::HashAlphaTranscript],
            Operation::HashX { .. } => &[Role::HashXTranscript, Role::HashXSparse],
            _ => &[],
        };
        for &role in roles {
            expected.push((index, role));
        }
    }
    assert_eq!(
        factory
            .requests()
            .iter()
            .map(|r| (r.operation_index(), r.role()))
            .collect::<Vec<_>>(),
        expected
    );
    for request in factory.requests() {
        assert_eq!(
            factory
                .request(request.operation_index(), request.role())
                .unwrap()
                .cache_key(),
            request.cache_key()
        );
        let wrong = if request.role() == Role::SampleGUniform {
            Role::HashXSparse
        } else {
            Role::SampleGUniform
        };
        assert!(factory.request(request.operation_index(), wrong).is_err());
        match (&request.payload, request.role()) {
            (Payload::Uniform(uniform_air::Kind::SampleG4, _), Role::SampleGUniform)
            | (Payload::Uniform(uniform_air::Kind::ExpandAlpha2, _), Role::AlphaUniform)
            | (Payload::Sparse(sparse_air::Kind::AlphaPrime39, _), Role::AlphaSparse)
            | (Payload::Sparse(sparse_air::Kind::ChallengeX44, _), Role::HashXSparse)
            | (Payload::Transcript(..), Role::HashAlphaTranscript | Role::HashXTranscript) => {}
            _ => panic!("role/kind mismatch"),
        }
    }
    let repeat = AuxiliaryFactory::new(&tree, &graph, &context, 8 << 30).unwrap();
    assert_eq!(
        factory
            .requests()
            .iter()
            .map(|r| r.cache_key())
            .collect::<Vec<_>>(),
        repeat
            .requests()
            .iter()
            .map(|r| r.cache_key())
            .collect::<Vec<_>>()
    );
    let mut bad = context.clone();
    bad.context[0] ^= 1;
    assert!(AuxiliaryFactory::new(&tree, &graph, &bad, 8 << 30).is_err());
    let mut bad = context.clone();
    bad.node_manifest[0] += Val::ONE;
    assert!(AuxiliaryFactory::new(&tree, &graph, &bad, 8 << 30).is_err());
    let mut different_statement = context.clone();
    different_statement.statement[0] += Val::ONE;
    let changed = AuxiliaryFactory::new(&tree, &graph, &different_statement, 8 << 30).unwrap();
    assert_ne!(
        factory.requests()[0].cache_key(),
        changed.requests()[0].cache_key()
    );
    let tiny = AuxiliaryFactory::new(&tree, &graph, &context, 1).unwrap();
    for request in tiny.requests() {
        assert!(request.prove().is_err());
    }
    assert!(AuxiliaryFactory::new(&tree, &graph, &context, 0).is_err());
    eprintln!(
        "auxiliary exact plan {}",
        serde_json::json!({
            "requests": factory.requests().iter().map(|r| serde_json::json!({
                "operation": r.operation_index(), "role": format!("{:?}", r.role()),
                "kind": format!("{:?}", r.kind()), "width": r.geometry().width,
                "height": r.geometry().height, "raw_trace_bytes": r.geometry().raw_trace_bytes,
                "estimated_prover_bytes": r.geometry().estimated_prover_bytes,
            })).collect::<Vec<_>>(), "proofs_generated": false,
        })
    );
}

#[test]
fn bounded_cache_rejects_malformed_oversized_and_missing_entries() {
    let (graph, tree, context) = fixture();
    let factory = AuxiliaryFactory::new(&tree, &graph, &context, 8 << 30).unwrap();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/pq-auxiliary-cache-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let cache = AuxiliaryCache::new(&directory, 128).unwrap();
    let request = &factory.requests()[0];
    assert!(cache.load(request).unwrap().is_none());
    let path = cache.entry_path(&request.cache_key());
    std::fs::write(&path, b"invalid").unwrap();
    assert!(cache.load(request).is_err());
    std::fs::write(&path, [0u8; 129]).unwrap();
    assert!(cache.load(request).is_err());
    assert!(AuxiliaryCache::new(&directory, 0).is_err());
    assert!(AuxiliaryCache::new(&directory, (64 << 20) + 1).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "actual native auxiliary STARK/cache checks; requires assigned guarded8GiB window"]
fn actual_uniform_sparse_transcript_cache_replay_and_mutations() {
    assert!(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE").is_some(),
        "persistent public fixture required"
    );
    let (graph, tree, context) = fixture();
    let factory = AuxiliaryFactory::new(&tree, &graph, &context, 8 << 30).unwrap();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/pq-child-cache/auxiliary");
    let cache = AuxiliaryCache::new(&directory, 64 << 20).unwrap();
    for request in factory.requests() {
        let role = request.role();
        let start = std::time::Instant::now();
        let result = cache.load_or_prove(request).unwrap();
        request.verify(&result.artifact).unwrap();
        let path = cache.entry_path(&request.cache_key());
        let encoded = std::fs::read(&path).unwrap();
        let mut corrupt: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        corrupt[2][0] = serde_json::json!((request.expected[0] + Val::ONE).as_canonical_u64());
        let bad_path = directory.join(format!(
            "{}-mutation.json",
            cache::hex(&request.cache_key())
        ));
        std::fs::write(&bad_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(cache.reverify_archived_entry(request, &bad_path).is_err());
        let mut forged: (u64, String, Vec<Val>, p3_uni_stark::Proof<profile::Config>) =
            serde_json::from_slice(&encoded).unwrap();
        forged.3.opened_values.trace_local[0] += profile::Challenge::ONE;
        std::fs::write(&bad_path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(cache.reverify_archived_entry(request, &bad_path).is_err());
        corrupt = serde_json::from_slice(&encoded).unwrap();
        corrupt[3]["degree_bits"] = serde_json::json!(result.artifact.proof().degree_bits + 1);
        std::fs::write(&bad_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(cache.reverify_archived_entry(request, &bad_path).is_err());
        corrupt = serde_json::from_slice(&encoded).unwrap();
        corrupt[1] = serde_json::json!("ab".repeat(32));
        std::fs::write(&bad_path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        let imported = cache.reverify_archived_entry(request, &bad_path).unwrap();
        assert_eq!(imported.archived_key, "ab".repeat(32));
        assert_eq!(imported.current_key, request.cache_key());
        std::fs::remove_file(&bad_path).unwrap();
        drop(result.artifact);
        let reopened = AuxiliaryCache::new(&directory, 64 << 20).unwrap();
        assert!(reopened.load_or_prove(request).unwrap().cache_hit);
        eprintln!(
            "auxiliary actual native proof {}",
            serde_json::json!({
                "operation": request.operation_index(), "role": format!("{role:?}"),
                "cache_hit": result.cache_hit, "cache_path": path, "cache_bytes": encoded.len(),
                "elapsed_ms": start.elapsed().as_millis(), "width": request.geometry().width,
                "height": request.geometry().height, "outer_proof_attempted": false,
                "compiled_source_fingerprint": cache::hex(&crate::graph_proofs::compiled_source_fingerprint()),
            })
        );
    }
}
