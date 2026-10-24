use super::*;
use crate::{
    graph_proofs::{GraphProofPlan, ResourceLimits},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Statement,
    },
};

fn fixture() -> (
    crate::native::NativeFixture,
    UnprovedRelationGraph,
    Plan,
    GraphContext,
) {
    let native = crate::native::generate_fixture_with_setup_seed(
        [71; 32],
        [29; 32],
        3,
        crate::native::FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
    )
    .unwrap();
    fixture_from_native(native)
}

fn fixture_from_native(
    native: crate::native::NativeFixture,
) -> (
    crate::native::NativeFixture,
    UnprovedRelationGraph,
    Plan,
    GraphContext,
) {
    let graph = committed_backend::lower_unproved(
        [29; 32],
        &[71; 32],
        &Statement::decode(&native.statement).unwrap(),
        &Proof::decode(&native.proof).unwrap(),
    )
    .unwrap();
    let shape = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&shape, &graph, ResourceLimits::default()).unwrap();
    let plan = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = GraphContext {
        context: [71; 32],
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            [71; 32],
            &native.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(&graph).unwrap(),
    };
    (native, graph, plan, context)
}

#[test]
fn source_factory_binds_exact_statement_private_roots_and_graph_context() {
    let (native, graph, plan, context) = fixture();
    let make = |ctx: &GraphContext, statement: &[u8], proof: &[u8]| {
        SourceFactory::new(&plan, &graph, ctx, statement, proof, 8 << 30).map(|f| f.identity)
    };
    let expected = make(&context, &native.statement, &native.proof).unwrap();
    assert_eq!(
        make(&context, &native.statement, &native.proof).unwrap(),
        expected
    );
    for field in 0..3 {
        let mut bad = context.clone();
        match field {
            0 => bad.context[0] ^= 1,
            1 => bad.statement[0] += Val::ONE,
            _ => bad.node_manifest[0] += Val::ONE,
        }
        assert!(make(&bad, &native.statement, &native.proof).is_err());
    }
    let other = fixture().0;
    assert!(make(&context, &native.statement, &other.proof).is_err());
    assert!(make(&context, &other.statement, &native.proof).is_err());
    let factory =
        SourceFactory::new(&plan, &graph, &context, &native.statement, &native.proof, 1).unwrap();
    assert!(factory.prove_statement().is_err());
    assert!(factory.prove_private().is_err());
    assert_ne!(factory.key(1), factory.key(2));
}

#[cfg(feature = "opencl")]
#[test]
#[ignore = "real GPU source-factory endpoint parity; exclusive admitted OpenCL session"]
fn gpu_source_factory_matches_cpu_endpoints_and_rejects_changed_raw_sources() {
    assert!(!cfg!(debug_assertions));
    // Fixture and independent CPU oracle are diagnostic setup, outside GPU
    // preparation. This test does not claim to run complete native proofs.
    let (native, graph, plan, context) = fixture();
    let expected = SourceFactory::new(
        &plan,
        &graph,
        &context,
        &native.statement,
        &native.proof,
        1 << 30,
    )
    .unwrap();
    let execution = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
        host_bytes: 8 << 30,
        device_bytes: 8 << 30,
        max_rows: 4096,
    })
    .unwrap();
    let actual = SourceFactory::new_with_context(
        &plan,
        &graph,
        &context,
        &native.statement,
        &native.proof,
        1 << 30,
        Some(&execution),
    )
    .unwrap();
    assert_eq!(actual.expected_statement, expected.expected_statement);
    assert_eq!(actual.expected_private, expected.expected_private);
    assert_eq!(actual.identity, expected.identity);
    assert_eq!(actual.setup_seed, expected.setup_seed);
    assert_eq!(actual.private.polynomials, expected.private.polynomials);
    assert_eq!(actual.private.alpha, expected.private.alpha);
    let report = execution.report();
    assert_eq!(report["operations"]["native_cpu_calls"], 0);
    assert_eq!(report["operations"]["native_gpu_calls"], 0);
    assert_eq!(
        report["operations"]["witness_preparation_complete_reports"],
        1
    );

    let mut changed = native.statement.clone();
    changed[32] ^= 1;
    assert!(SourceFactory::new_with_context(
        &plan,
        &graph,
        &context,
        &changed,
        &native.proof,
        1 << 30,
        Some(&execution),
    )
    .is_err());
    for which in 0..3 {
        let mut bad = context.clone();
        match which {
            0 => bad.context[0] ^= 1,
            1 => bad.statement[0] += Val::ONE,
            _ => bad.node_manifest[0] += Val::ONE,
        }
        assert!(SourceFactory::new_with_context(
            &plan,
            &graph,
            &bad,
            &native.statement,
            &native.proof,
            1 << 30,
            Some(&execution),
        )
        .is_err());
    }
    assert_eq!(
        execution.report()["operations"]["witness_preparation_complete_reports"],
        1
    );
    drop(execution);
}

#[test]
fn malformed_and_oversized_source_cache_is_rejected_before_proving() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/pq-source-cache-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    let cache = SourceCache::new(&root, 128).unwrap();
    let key = [17; 32];
    assert!(cache.load(&key).unwrap().is_none());
    fs::write(cache.path(&key), b"invalid").unwrap();
    assert!(cache.load(&key).is_err());
    fs::write(cache.path(&key), vec![0u8; 129]).unwrap();
    assert!(cache.load(&key).is_err());
    assert!(SourceCache::new(&root, 0).is_err());
    assert!(SourceCache::new(&root, (64 << 20) + 1).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
#[ignore = "actual statement/private native STARKs and verified cache replay; reserve8GiB"]
fn actual_source_proofs_cache_replay_and_mutation_rejection() {
    let fingerprint: String = crate::graph_proofs::compiled_source_fingerprint()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    eprintln!("COMPILED_SOURCE_IDENTITY {fingerprint}");
    let path = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing public fixture required"),
    );
    let saved = crate::native_test_fixture::load_or_create(
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
    let (native, graph, plan, context) = fixture_from_native(crate::native::NativeFixture {
        statement: saved.statement,
        proof: saved.proof,
        generation_ns: 0,
        verification_ns: 0,
    });
    let factory = SourceFactory::new(
        &plan,
        &graph,
        &context,
        &native.statement,
        &native.proof,
        8 << 30,
    )
    .unwrap();
    let cache = SourceCache::new(
        PathBuf::from(
            std::env::var_os("LATTICA_SOURCE_CACHE")
                .expect("explicit source cache directory required"),
        ),
        64 << 20,
    )
    .unwrap();
    let mut statement = factory.prove_or_load_statement(&cache).unwrap();
    let replay = factory.prove_or_load_statement(&cache).unwrap();
    assert_eq!(statement.public_values, replay.public_values);
    statement.public_values[4] += Val::ONE;
    assert!(factory.verify_statement(&statement).is_err());
    statement.public_values[4] -= Val::ONE;
    statement.proof.opened_values.trace_local[0] += profile::Challenge::ONE;
    assert!(factory.verify_statement(&statement).is_err());
    let mut private = factory.prove_or_load_private(&cache).unwrap();
    let replay = factory.prove_or_load_private(&cache).unwrap();
    assert_eq!(private.public_values, replay.public_values);
    private.proof.degree_bits += 1;
    assert!(factory.verify_private(&private).is_err());
    private.proof.degree_bits -= 1;
    private.public_values[0] += Val::ONE;
    assert!(factory.verify_private(&private).is_err());
}
