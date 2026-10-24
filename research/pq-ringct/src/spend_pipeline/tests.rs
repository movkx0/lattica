//! Expensive acceptance test. This is deliberately opt-in and never reports
//! partial components as complete spends or a successful aggregate.
use super::*;
use crate::{
    graph_proofs::ResourceLimits,
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use lattica_prover_p3::block_v2::machine::program::Val;
use p3_field::PrimeCharacteristicRing;
use sha3::{Digest, Sha3_256};
use std::{path::PathBuf, time::Instant};

mod options;

#[test]
#[ignore = "two complete registered MatRiCT graph proofs and real ordered parent; long-running guarded job"]
fn actual_two_complete_graph_proofs_and_ordered_aggregate() {
    let directory = PathBuf::from(
        std::env::var_os("LATTICA_SPEND_JOB_DIRECTORY")
            .expect("explicit persistent spend job directory required"),
    );
    let options = options::Options::parse(|name| std::env::var(name).ok()).unwrap();
    let outer_bytes = options.budgets.outer_bytes;
    eprintln!(
        "SPEND_PIPELINE_OPTIONS limits={:?} budgets={:?}",
        options.limits, options.budgets
    );
    let pipeline = SpendPipeline::new(directory.join("cache"), options.budgets).unwrap();
    let fingerprint: String = crate::graph_proofs::compiled_source_fingerprint()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    eprintln!("COMPILED_SOURCE_IDENTITY {fingerprint}");
    let started = Instant::now();
    let mut children = Vec::new();
    let mut contexts = Vec::new();
    let mut statements = Vec::new();
    for index in 0..2 {
        let fixture = crate::native_test_fixture::load_or_create(
            &directory.join(format!("fixture-{index}.json")),
            [71; 32],
            [29; 32],
            index + 3,
            crate::native::FixtureAmounts {
                input: [17, 23],
                output: [29, 11],
            },
            true,
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
        let algebra = GraphProofPlan::new(&registered, &graph, options.limits).unwrap();
        // Test-only registration of the fixed research relation. Production
        // callers must supply their network's trusted graph/parameter registry.
        let plan = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
        let statement = crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            fixture.context,
            &fixture.statement,
        )
        .unwrap();
        let context = GraphContext {
            context: fixture.context,
            statement: statement.digest.map(Val::from_u64),
            node_manifest: plan.node_manifest_hint(&graph).unwrap(),
        };
        let proof = pipeline
            .prove_registered(
                &plan,
                &algebra,
                &graph,
                &context,
                &fixture.statement,
                &fixture.proof,
            )
            .unwrap();
        proof
            .key()
            .verify_complete(proof.proof(), &context)
            .unwrap();
        eprintln!(
            "COMPLETE_GRAPH_PROOF {}",
            serde_json::json!({
                "index": index, "registered_leaves": plan.leaves().len(), "verified": true,
                "elapsed_seconds": started.elapsed().as_secs_f64(), "ledger_binding": false,
            })
        );
        children.push(proof);
        contexts.push(context);
        statements.push(statement);
    }
    assert_ne!(statements[0].digest, statements[1].digest);
    let compiled = crate::spend_pair::compile([
        crate::spend_pair::Child {
            key: children[0].key(),
            proof: children[0].proof(),
            context: &contexts[0],
        },
        crate::spend_pair::Child {
            key: children[1].key(),
            proof: children[1].proof(),
            context: &contexts[1],
        },
    ])
    .unwrap();
    compiled.evaluate().unwrap();
    eprintln!(
        "COMPLETE_GRAPH_PAIR_GEOMETRY {:?}",
        compiled.geometry().unwrap()
    );
    let prepared = compiled.prepare(outer_bytes).unwrap();
    let key = prepared.key();
    let mut proof = prepared.prove().unwrap();
    drop(prepared);
    key.verify_expected(&proof, [&statements[0], &statements[1]])
        .unwrap();
    // Retain the actual aggregate before destructive rejection probes. This
    // diagnostic codec excludes the trusted registered key and ledger body.
    let encoded = postcard::to_allocvec(&(&proof.public, &proof.proof)).unwrap();
    let ((public, decoded), trailing): (
        (
            [Val; crate::recursive_aggregation::PUBLIC_VALUES],
            p3_batch_stark::BatchProof<lattica_prover_p3::block_v2::profile::Config>,
        ),
        &[u8],
    ) = postcard::take_from_bytes(&encoded).unwrap();
    assert!(trailing.is_empty());
    let decoded = crate::spend_pair::PairProof {
        public,
        proof: decoded,
    };
    key.verify_expected(&decoded, [&statements[0], &statements[1]])
        .unwrap();
    drop(decoded);
    let digest: String = Sha3_256::digest(&encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let artifact_directory = directory.join("artifacts");
    std::fs::create_dir_all(&artifact_directory).unwrap();
    let artifact_path = artifact_directory.join(format!("complete-pair-{digest}.postcard"));
    if artifact_path.exists() {
        assert_eq!(std::fs::read(&artifact_path).unwrap(), encoded);
    } else {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&artifact_path)
            .unwrap();
        file.write_all(&encoded).unwrap();
        file.sync_all().unwrap();
    }
    eprintln!(
        "COMPLETE_GRAPH_PAIR_ARTIFACT {}",
        serde_json::json!({
            "path": artifact_path, "sha3_256": digest, "bytes": encoded.len(),
            "codec": "diagnostic-postcard-public-and-proof-tuple",
            "compiled_source_identity": fingerprint,
            "decoded_complete_payload_reverified": true,
            "includes_trusted_registered_key": false, "includes_ledger_body": false,
        })
    );
    assert!(key
        .verify_expected(&proof, [&statements[1], &statements[0]])
        .is_err());
    let mut wrong = statements[0].clone();
    wrong.context[0] ^= 1;
    assert!(key
        .verify_expected(&proof, [&wrong, &statements[1]])
        .is_err());
    proof.public[crate::recursive_aggregation::ROOT] += Val::ONE;
    assert!(key
        .verify_expected(&proof, [&statements[0], &statements[1]])
        .is_err());
    eprintln!(
        "COMPLETE_GRAPH_PAIR_VERIFIED {}",
        serde_json::json!({
            "actual_complete_graph_proofs": 2, "actual_aggregate_stark": true,
            "order_context_root_mutations_rejected": true,
            "elapsed_seconds": started.elapsed().as_secs_f64(), "ledger_binding": false,
        })
    );
}
