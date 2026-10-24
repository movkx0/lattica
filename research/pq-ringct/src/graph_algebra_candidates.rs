//! Guarded exact native children, wide graph-leaf traces, and opt-in partial
//! outer proofs. No candidate establishes complete graph or spend validity.
use crate::{
    graph_proofs::{ComponentKind, GraphProofPlan, ProofCache, ResourceLimits},
    graph_tree,
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use lattica_prover_p3::block_v2::machine::program::Val;
use p3_field::PrimeCharacteristicRing;

fn exact_fixture() -> (
    std::path::PathBuf,
    crate::native_test_fixture::PublicFixture,
    committed_backend::UnprovedRelationGraph,
) {
    let path = std::path::PathBuf::from(
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
        [29; 32],
        &[71; 32],
        &Statement::decode(&fixture.statement).unwrap(),
        &Proof::decode(&fixture.proof).unwrap(),
    )
    .unwrap();
    (path, fixture, graph)
}

fn candidate(ntt: bool, count: usize, require_archive: bool, prove_outer: bool) {
    candidate_with_native_budget(ntt, count, require_archive, prove_outer, 8 << 30);
}

fn candidate_with_native_budget(
    ntt: bool,
    count: usize,
    require_archive: bool,
    prove_outer: bool,
    native_budget: u64,
) {
    if prove_outer {
        assert_eq!(
            std::env::var("LATTICA_GRAPH_OUTER_OPT_IN").as_deref(),
            Ok("1"),
            "actual partial outer proving requires explicit opt-in and an external 48 GiB guard"
        );
    }
    let (path, fixture, graph) = exact_fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let plan = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_batch_count: 64,
            max_ntt_batch_count: if ntt { count } else { 32 },
            max_mul_batch_count: if ntt { 16 } else { count },
            max_trace_cells: 1 << 27,
            max_estimated_prover_bytes: native_budget,
        },
    )
    .unwrap();
    let (index, batch) = plan
        .batches()
        .iter()
        .enumerate()
        .filter(|(_, b)| {
            b.operation_indices().len() == count
                && if ntt {
                    matches!(b.kind(), ComponentKind::Ntt { .. })
                } else {
                    matches!(b.kind(), ComponentKind::Mul { .. })
                }
        })
        .max_by_key(|(_, b)| b.resource_estimate().unwrap().trace_bytes)
        .unwrap();
    let cache = ProofCache::new(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tools/pq-child-cache/algebra"),
        64 << 20,
    )
    .unwrap();
    let started = std::time::Instant::now();
    let hex = |bytes: &[u8; 32]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let (artifact, cache_metadata) = if require_archive {
        let archive = std::path::PathBuf::from(
            std::env::var_os("LATTICA_ALGEBRA_ARCHIVE")
                .expect("explicit exact native child archive required"),
        );
        let imported = cache
            .reverify_archived_entry(&plan, index, &archive)
            .unwrap();
        let metadata = serde_json::json!({
            "classification": "archival proof reverified under current exact AIR/degree/ordered roots; not a source-version cache hit",
            "archive": archive,
            "archived_key": imported.archived_key,
            "current_key": hex(&imported.current_key),
        });
        (imported.artifact, metadata)
    } else {
        let outcome = cache.load_or_prove(&plan, index).unwrap();
        let metadata = serde_json::json!({
            "classification": "current compiled-source cache lookup or native proof generation",
            "cache_hit": outcome.cache_hit,
            "cache_key": hex(&outcome.key),
            "cache_file": cache.entry_path(&outcome.key),
        });
        (outcome.artifact, metadata)
    };
    let native_ms = started.elapsed().as_millis();
    let family = if ntt { "ntt" } else { "mul" };
    let source: String = plan
        .source_fingerprint()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    eprintln!(
        "small algebra native child {}",
        serde_json::json!({
            "family": family, "count": count, "operations": batch.operation_indices(),
            "cache": cache_metadata, "native_ms": native_ms,
            "raw_trace_bytes": batch.resource_estimate().unwrap().trace_bytes,
            "native_planning_budget_bytes": native_budget,
            "compiled_source_fingerprint": source, "fixture": path,
            "outer_proof_attempted": false,
        })
    );
    let tree = graph_tree::Plan::from_trusted_graph(&graph, plan.operation_batches()).unwrap();
    let context = graph_tree::GraphContext {
        context: [71; 32],
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(),
            [71; 32],
            &fixture.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    let compiled = graph_tree::compile_leaf(
        &tree,
        &graph,
        index + 3,
        &context,
        artifact.as_leaf_artifact(),
    )
    .unwrap();
    let geometry = compiled.geometry().unwrap();
    eprintln!(
        "small algebra wide graph-leaf geometry {}",
        serde_json::json!({
            "family": family, "count": count, "leaf": index + 3,
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "main_width": geometry.main_width,
            "preprocessed_width": geometry.preprocessed_width,
            "permutation_width_base": geometry.permutation_width_base,
            "quotient_chunks": geometry.quotient_chunks, "constraints": geometry.constraints,
            "max_constraint_degree": geometry.max_constraint_degree,
            "fri_ali_bits": geometry.fri_ali_bits, "retained_lde_bytes": geometry.retained_lde_bytes,
            "trace_evaluated": false, "outer_proof_attempted": false,
        })
    );
    compiled.evaluate().unwrap();
    eprintln!(
        "small algebra wide graph-leaf trace checked {}",
        serde_json::json!({
            "family": family, "count": count, "elapsed_ms": started.elapsed().as_millis(),
            "trace_evaluated": true, "outer_proof_attempted": false,
        })
    );
    if prove_outer {
        let outer_budget = 48_u64 << 30;
        assert!(geometry.retained_lde_bytes <= outer_budget);
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../.tools/pq-child-cache/outer-algebra")
            .join(format!("{family}{count}"))
            .join(&source);
        let outer_cache = graph_tree::ProofCache::new(&directory, 64 << 20).unwrap();
        let prover =
            graph_tree::GraphProver::new(&tree, &context, &outer_cache, outer_budget).unwrap();
        let expected_public = compiled.public_values().to_vec();
        eprintln!(
            "algebra partial graph-leaf outer attempt {}",
            serde_json::json!({
                "family": family, "count": count, "leaf": index + 3,
                "outer_proof_attempted": true, "complete_graph": false,
                "retained_memory_budget": outer_budget,
                "external_process_guard_required": true,
                "cache_directory": directory,
            })
        );
        let outer_started = std::time::Instant::now();
        let first = prover.prove_leaf(compiled).unwrap();
        first.key().verify(first.proof()).unwrap();
        assert_eq!(first.proof().public, expected_public);
        assert_eq!(first.key().span(), (index + 3, 1));
        assert!(prover.verify_complete(&first).is_err());
        assert!(first.verify_complete(&context).is_err());
        let cache_hit = first.cache_hit();
        let proof_and_verify_ms = outer_started.elapsed().as_millis();
        let entries: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "one exact source/fixture/leaf cache entry"
        );
        let path = &entries[0];
        let bytes = std::fs::read(path).unwrap();
        type Encoded = (
            u64,
            [u8; 32],
            [u8; 32],
            Vec<Val>,
            p3_batch_stark::BatchProof<lattica_prover_p3::block_v2::profile::Config>,
        );
        let (_, _, _, mut public, proof): Encoded = serde_json::from_slice(&bytes).unwrap();
        public[graph_tree::CONTEXT] += Val::ONE;
        let wrong_public = graph_tree::NodeProof { public, proof };
        assert!(first.key().verify(&wrong_public).is_err());
        drop(wrong_public);
        let (_, _, _, public, mut proof): Encoded = serde_json::from_slice(&bytes).unwrap();
        proof.opened_values.instances[0]
            .base_opened_values
            .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
        let corrupt = graph_tree::NodeProof { public, proof };
        assert!(first.key().verify(&corrupt).is_err());
        drop(corrupt);
        drop(first);
        // Re-register the exact current program and load through the full
        // verifier. No key/cap is reconstructed from the cached proof itself.
        let reopened = graph_tree::ProofCache::new(&directory, 64 << 20).unwrap();
        let replay_prover =
            graph_tree::GraphProver::new(&tree, &context, &reopened, outer_budget).unwrap();
        let replay_started = std::time::Instant::now();
        let replay = replay_prover
            .prove_leaf(
                graph_tree::compile_leaf(
                    &tree,
                    &graph,
                    index + 3,
                    &context,
                    artifact.as_leaf_artifact(),
                )
                .unwrap(),
            )
            .unwrap();
        assert!(replay.cache_hit());
        assert_eq!(replay.proof().public, expected_public);
        assert!(replay_prover.verify_complete(&replay).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        eprintln!(
            "algebra partial graph-leaf outer checked {}",
            serde_json::json!({
                "family": family, "count": count, "leaf": index + 3,
                "outer_proof_attempted": true, "outer_proof_verified": true,
                "complete_graph": false, "incomplete_graph_rejected": true,
                "wrong_public_rejected": true, "corrupted_proof_rejected": true,
                "initial_cache_hit": cache_hit, "replay_cache_hit": true,
                "proof_and_verify_ms": proof_and_verify_ms,
                "replay_registration_and_verify_ms": replay_started.elapsed().as_millis(),
                "cache_file": path, "cache_json_bytes": bytes.len(),
                "elapsed_ms": started.elapsed().as_millis(),
            })
        );
    }
}

#[test]
#[ignore = "native NTT4 and wide graph-leaf geometry/trace; external8GiB guard required"]
fn ntt4_wide_graph_leaf_candidate() {
    candidate(true, 4, false, false);
}
#[test]
#[ignore = "native NTT8 and wide graph-leaf geometry/trace; external8GiB guard required"]
fn ntt8_wide_graph_leaf_candidate() {
    candidate(true, 8, false, false);
}
#[test]
#[ignore = "native Mul4 and wide graph-leaf geometry/trace; external8GiB guard required"]
fn mul4_wide_graph_leaf_candidate() {
    candidate(false, 4, false, false);
}
#[test]
#[ignore = "native Mul8 and wide graph-leaf geometry/trace; external8GiB guard required"]
fn mul8_wide_graph_leaf_candidate() {
    candidate(false, 8, false, false);
}

#[test]
#[ignore = "archived NTT32 plus wide graph-leaf geometry/trace; external8GiB guard required"]
fn ntt32_archived_wide_graph_leaf_candidate() {
    candidate(true, 32, true, false);
}

#[test]
#[ignore = "archived Mul16 plus wide graph-leaf geometry/trace; external8GiB guard required"]
fn mul16_archived_wide_graph_leaf_candidate() {
    candidate(false, 16, true, false);
}

#[test]
#[ignore = "actual partial NTT32 graph-leaf outer proof/cache; opt-in and external48GiB guard required"]
fn ntt32_archived_wide_partial_outer_proof() {
    candidate(true, 32, true, true);
}

#[test]
#[ignore = "actual partial Mul16 graph-leaf outer proof/cache; opt-in and external48GiB guard required"]
fn mul16_archived_wide_partial_outer_proof() {
    candidate(false, 16, true, true);
}

#[test]
#[ignore = "exact archived Mul32 QHAT plus wide graph-leaf geometry/trace; external16GiB guard required"]
fn mul32_archived_wide_graph_leaf_candidate() {
    candidate_with_native_budget(false, 32, true, false, 16 << 30);
}

#[test]
#[ignore = "actual partial Mul32 graph-leaf outer proof/cache; explicit opt-in and external48GiB guard required"]
fn mul32_archived_wide_partial_outer_proof() {
    candidate_with_native_budget(false, 32, true, true, 16 << 30);
}

#[test]
#[ignore = "exact archived fixture global64 current/candidate plan census; no proof generation"]
fn global64_current_vs_mul32_exact_plan() {
    use std::collections::BTreeMap;
    let (path, _, graph) = exact_fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    for (mul_cap, native_budget, expected_leaves) in
        [(16, 8_u64 << 30, 105), (32, 16_u64 << 30, 91)]
    {
        let plan = GraphProofPlan::new(
            &registered,
            &graph,
            ResourceLimits {
                max_batch_count: 64,
                max_ntt_batch_count: 32,
                max_mul_batch_count: mul_cap,
                max_trace_cells: 1 << 27,
                max_estimated_prover_bytes: native_budget,
            },
        )
        .unwrap();
        let tree = graph_tree::Plan::from_trusted_graph(&graph, plan.operation_batches()).unwrap();
        let crypto_policy = crate::graph_crypto::Policy::default();
        let crypto = crate::graph_crypto::Plan::new(&tree, &graph, crypto_policy).unwrap();
        let crypto_requests: Vec<_> = crypto
            .requests()
            .iter()
            .map(|request| {
                use committed_backend::Operation;
                let operation_kind = match &graph.operations()[request.operation_index()] {
                    Operation::ParametersPp { .. } => "ParametersPp",
                    Operation::SampleG { .. } => "SampleG",
                    Operation::ExpandAlpha { .. } => "ExpandAlpha",
                    Operation::HashAlpha { .. } => "HashAlpha",
                    Operation::HashX { .. } => "HashX",
                    _ => panic!("unexpected crypto request operation"),
                };
                serde_json::json!({
                    "operation": request.operation_index(), "operation_kind": operation_kind,
                    "subrequest": request.subrequest(), "units": request.units(),
                    "descriptor": format!("{:?}", request.descriptor()),
                    "serial_native_segments": request.segments().len(),
                    "serial_request_outer_nodes": 2 * request.segments().len() - 1,
                })
            })
            .collect();
        let mut distribution = BTreeMap::<String, BTreeMap<usize, usize>>::new();
        let mut batches = Vec::new();
        let mut native_trace_sum = 0_u64;
        let mut native_trace_peak = 0_u64;
        let mut algebra_count = 0;
        let mut external_count = 0;
        for batch in plan.batches() {
            let kind = format!("{:?}", batch.kind());
            *distribution
                .entry(kind.clone())
                .or_default()
                .entry(batch.operation_indices().len())
                .or_default() += 1;
            let estimate = batch.resource_estimate().map(|estimate| {
                algebra_count += 1;
                native_trace_sum += estimate.trace_bytes;
                native_trace_peak = native_trace_peak.max(estimate.trace_bytes);
                serde_json::json!({
                    "width": estimate.width, "height": estimate.height,
                    "public_values": estimate.public_values,
                    "trace_bytes": estimate.trace_bytes,
                    "estimated_prover_bytes": estimate.estimated_prover_bytes,
                })
            });
            if estimate.is_none() {
                external_count += 1;
            }
            batches.push(serde_json::json!({
                "kind": kind, "operations": batch.operation_indices(), "estimate": estimate,
            }));
        }
        let leaves = tree.leaves().len();
        assert_eq!(leaves, algebra_count + external_count + 3);
        let hex = |bytes: &[u8; 32]| -> String {
            bytes.iter().map(|value| format!("{value:02x}")).collect()
        };
        eprintln!(
            "exact global64 algebra candidate plan {}",
            serde_json::json!({
                "global_batch_ceiling": 64, "ntt_batch_ceiling": 32,
                "mul_batch_ceiling": mul_cap, "native_planning_budget_bytes": native_budget,
                "source_fingerprint": hex(&plan.source_fingerprint()),
                "shape_fingerprint": hex(&plan.shape_fingerprint()),
                "fixture": path, "distribution": distribution, "batches": batches,
                "algebra_children": algebra_count, "external_operation_leaves": external_count,
                "source_leaves": 3, "graph_leaves": leaves,
                "prior_independent_fixture_reference_leaves": expected_leaves,
                "matches_prior_reference_leaf_count": leaves == expected_leaves,
                "graph_binary_merges": leaves - 1, "graph_layer_outer_nodes": 2 * leaves - 1,
                "native_trace_bytes_sum": native_trace_sum,
                "native_trace_bytes_peak": native_trace_peak,
                "crypto_policy": {
                    "maximum_aes_blocks": crypto_policy.maximum_aes_blocks,
                    "maximum_shake_permutations": crypto_policy.maximum_shake_permutations,
                    "native_budget_bytes": crypto_policy.child_memory_budget_bytes,
                    "admission": "ValidatedLocal",
                },
                "crypto_requests": crypto_requests,
                "crypto_request_count": crypto.requests().len(),
                "serial_crypto_native_segments": crypto.native_child_count(),
                "serial_crypto_request_outer_nodes": 2 * crypto.native_child_count() - crypto.requests().len(),
                "proofs_generated": false, "outer_proof_attempted": false,
                "scope": "Exact current planner census only. Outer-node counts assume one proof per graph leaf and binary merges; nested request proofs and spend/block coordinators are additional. No recursive geometry or compute savings inferred.",
            })
        );
    }
}
