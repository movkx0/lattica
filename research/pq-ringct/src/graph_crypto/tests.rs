#![cfg(feature = "native-matrict")]
use super::*;
use crate::{
    graph_proofs::{GraphProofPlan, ResourceLimits},
    rust_verify::{
        committed_backend::{self, source_binding::RegisteredGraphShape},
        Proof, Statement,
    },
};
use p3_field::PrimeCharacteristicRing;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const FIXTURE_CONTEXT: [u8; 32] = [71; 32];
const FIXTURE_SETUP: [u8; 32] = [29; 32];
type Fixture = (
    UnprovedRelationGraph,
    graph_tree::Plan,
    graph_tree::GraphContext,
);

fn fixture_amounts() -> crate::native::FixtureAmounts {
    crate::native::FixtureAmounts {
        input: [17, 23],
        output: [29, 11],
    }
}

fn graph_fixture(statement: &[u8], proof: &[u8]) -> Fixture {
    let graph = committed_backend::lower_unproved(
        FIXTURE_SETUP,
        &FIXTURE_CONTEXT,
        &Statement::decode(statement).unwrap(),
        &Proof::decode(proof).unwrap(),
    )
    .unwrap();
    let shape = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&shape, &graph, ResourceLimits::default()).unwrap();
    let tree = graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = graph_tree::GraphContext {
        context: FIXTURE_CONTEXT,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(),
            FIXTURE_CONTEXT,
            statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    (graph, tree, context)
}

fn archived_fixture(path: &Path, allow_create: bool) -> Fixture {
    let fixture = crate::native_test_fixture::load_or_create(
        path,
        FIXTURE_CONTEXT,
        FIXTURE_SETUP,
        3,
        fixture_amounts(),
        allow_create,
    )
    .unwrap();
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    eprintln!(
        "crypto public fixture archive {}",
        serde_json::json!({
            "path": path,
            "statement_sha3_256": hex(&Sha3_256::digest(&fixture.statement)),
            "proof_sha3_256": hex(&Sha3_256::digest(&fixture.proof)),
            "native_reverified": true, "contains_private_rng_or_keys": false,
        })
    );
    graph_fixture(&fixture.statement, &fixture.proof)
}

fn fixture() -> Fixture {
    if let Some(path) = std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE") {
        let allow_create = std::env::var("LATTICA_GRAPH_FIXTURE_CREATE").as_deref() == Ok("1");
        return archived_fixture(Path::new(&path), allow_create);
    }
    let native = crate::native::generate_fixture_with_setup_seed(
        FIXTURE_CONTEXT,
        FIXTURE_SETUP,
        3,
        fixture_amounts(),
    )
    .unwrap();
    graph_fixture(&native.statement, &native.proof)
}

#[test]
fn persisted_public_fixture_rebuilds_exact_crypto_requests_and_cache_identity() {
    let directory = TemporaryDirectory::new();
    let path = directory.0.join("public-graph.json");
    let (first_graph, first_tree, first_context) = archived_fixture(&path, true);
    let (second_graph, second_tree, second_context) = archived_fixture(&path, false);
    assert_eq!(first_tree.label(), second_tree.label());
    assert_eq!(first_context, second_context);
    let first = Plan::new(&first_tree, &first_graph, Policy::default()).unwrap();
    let second = Plan::new(&second_tree, &second_graph, Policy::default()).unwrap();
    for (a, b) in first.requests().iter().zip(second.requests()) {
        assert_eq!(a.request_index(), b.request_index());
        assert_eq!(a.descriptor(), b.descriptor());
        assert_eq!(a.segments(), b.segments());
        assert_eq!(a.cache_key(0).unwrap(), b.cache_key(0).unwrap());
    }
}

fn candidate(maximum: usize, budget: u64) -> Policy {
    Policy {
        maximum_aes_blocks: maximum,
        maximum_shake_permutations: maximum,
        child_memory_budget_bytes: budget,
        admission: Admission::Estimated,
    }
}

fn counts(plan: &Plan) -> (usize, usize) {
    plan.requests()
        .iter()
        .fold((0, 0), |(aes, shake), request| match request.descriptor() {
            RequestDescriptor::Aes(_) => (aes + request.segments().len(), shake),
            RequestDescriptor::Shake(_) => (aes, shake + request.segments().len()),
        })
}

#[test]
fn full_native_crypto_plan_preserves_all_seven_request_descriptors_and_phases() {
    let (graph, tree, _) = fixture();
    let plan = Plan::new(&tree, &graph, Policy::default()).unwrap();
    assert_eq!(plan.requests().len(), 7);
    let mut descriptors = Vec::new();
    for request in plan.requests() {
        assert_eq!(request.profile, tree.label());
        assert_eq!(
            request.request_index(),
            2 * request.operation_index() as u32 + request.subrequest()
        );
        let mut next = 0;
        for segment in request.segments() {
            assert_eq!(segment.first_unit, next);
            assert!(segment.units.is_power_of_two());
            assert!(segment.units <= 8);
            assert!(segment.within_previously_measured_batch_size);
            assert!(segment.estimated_peak_bytes <= 8 << 30);
            assert_eq!(
                segment.raw_trace_bytes,
                (segment.width * segment.height * 8) as u64
            );
            next += segment.units;
        }
        match request.descriptor() {
            RequestDescriptor::Aes(d) => {
                assert!(request.shake_partition().is_none());
                assert_eq!(request.aes_partition().unwrap().descriptor(), d);
                assert_eq!(next, d.blocks());
                descriptors.push((
                    "aes",
                    d.domain,
                    d.start_counter as usize,
                    d.output_len,
                    next,
                ));
            }
            RequestDescriptor::Shake(d) => {
                assert!(request.aes_partition().is_none());
                assert_eq!(request.shake_partition().unwrap().descriptor(), d);
                assert_eq!(next, d.permutations().unwrap());
                let last_absorb = d.input_len / shake_air::RATE;
                for segment in request.segments() {
                    if segment.first_unit < last_absorb {
                        assert!(segment.first_unit + segment.units <= last_absorb);
                    } else if segment.first_unit == last_absorb {
                        assert_eq!(
                            segment.units, 1,
                            "padding permutation is a separate exact phase"
                        );
                    }
                }
                descriptors.push(("shake", 0, d.input_len, d.output_len, next));
            }
        }
    }
    descriptors.sort_unstable();
    let pp_len = crate::transcript_bridge::pp_input_bytes(&FIXTURE_SETUP, &FIXTURE_CONTEXT).len();
    let mut expected = vec![
        ("aes", 0, 0, 4788, 300),
        ("aes", 0, 0, 4788, 300),
        ("aes", 0x4368, 0, 2572, 161),
        ("aes", 0x4368, 161, 127, 8),
        ("shake", 0, pp_len, 32, 1),
        ("shake", 0, 230496, 32, 1695),
        ("shake", 0, 16416, 137, 122),
    ];
    expected.sort_unstable();
    assert_eq!(descriptors, expected);
    assert_eq!(counts(&plan), (98, 232));
    assert_eq!(plan.native_child_count(), 330);
}

#[test]
fn candidate_batch_counts_and_local_admission_are_explicitly_separate() {
    let (graph, tree, _) = fixture();
    let mut reports = Vec::new();
    for (maximum, expected) in [
        (8, (98, 232)),
        (16, (50, 120)),
        (32, (27, 65)),
        (64, (14, 38)),
    ] {
        let plan = Plan::new(&tree, &graph, candidate(maximum, 64 << 30)).unwrap();
        assert_eq!(counts(&plan), expected);
        let requests: Vec<_> = plan.requests().iter().map(|request| {
            serde_json::json!({
                "operation": request.operation_index(), "subrequest": request.subrequest(),
                "request_index": request.request_index(), "descriptor": format!("{:?}", request.descriptor()),
                "units": request.units(), "children": request.segments().len(),
                "max_units": request.maximum_segment_units(),
                "max_estimated_child_bytes": request.segments().iter().map(|s| s.estimated_peak_bytes).max(),
            })
        }).collect();
        reports.push(serde_json::json!({
            "requested_maximum": maximum, "estimated_worker_budget_bytes": 64u64 << 30,
            "aes_children": expected.0, "shake_children": expected.1,
            "total_children": plan.native_child_count(), "requests": requests,
        }));
    }
    let validated = Plan::new(
        &tree,
        &graph,
        Policy {
            admission: Admission::ValidatedLocal,
            ..candidate(64, 8 << 30)
        },
    )
    .unwrap();
    assert_eq!(counts(&validated), (98, 232));
    assert!(validated
        .requests()
        .iter()
        .all(|r| r.maximum_segment_units() <= 8));
    let local_candidate = Plan::new(&tree, &graph, candidate(64, 8 << 30)).unwrap();
    assert_eq!(counts(&local_candidate), (27, 232));
    assert_eq!(local_candidate.native_child_count(), 259);
    eprintln!(
        "crypto production candidate plan {}",
        serde_json::json!({
            "status": "estimates only; no production measurements or outer-memory guarantee",
            "native_peak_heuristic": "48 * raw_trace_bytes + 512 MiB",
            "validated_local_unit_ceiling": 8,
            "candidates": reports,
            "local_8_gib_estimated_children": 259,
            "local_8_gib_validated_children": 330,
        })
    );
}

#[test]
fn invalid_policy_and_insufficient_crypto_memory_are_rejected_before_proving() {
    let (graph, tree, _) = fixture();
    for maximum in [0, 3, 65, 128] {
        assert!(Plan::new(&tree, &graph, candidate(maximum, 64 << 30)).is_err());
    }
    for budget in [0, 1, 512 << 20] {
        assert!(Plan::new(&tree, &graph, candidate(8, budget)).is_err());
    }
    let request = &Plan::new(&tree, &graph, Policy::default())
        .unwrap()
        .requests[0];
    assert!(request.cache_key(usize::MAX).is_err());
    assert!(request.prove_segment(usize::MAX).is_err());
}

#[test]
fn existing_wide_and_serial_layout_estimates_do_not_generate_traces_or_claim_measurements() {
    let (graph, tree, _) = fixture();
    let plan = Plan::new(&tree, &graph, Policy::default()).unwrap();
    let geometry = |g: &LayoutGeometry| {
        serde_json::json!({
            "width": g.width, "height": g.height, "raw_trace_bytes": g.raw_trace_bytes,
            "retained_main_lde_bytes": g.retained_main_lde_bytes,
            "uncalibrated_peak_estimate_bytes": g.uncalibrated_peak_estimate_bytes,
        })
    };
    let mut requests = Vec::new();
    for request in plan.requests() {
        let comparison = request.layout_comparison().unwrap();
        let wide = &comparison.wide_whole_request;
        assert_eq!(
            wide.retained_main_lde_bytes,
            wide.raw_trace_bytes << (profile::LOG_BLOWUP + 1)
        );
        assert!(wide.height.is_power_of_two());
        let serial_raw: u64 = comparison
            .serial_segments
            .iter()
            .map(|s| s.raw_trace_bytes)
            .sum();
        assert!(wide.raw_trace_bytes < serial_raw);
        match request.descriptor() {
            RequestDescriptor::Aes(d) => {
                assert_eq!(wide.height, (d.blocks() * 14).next_power_of_two());
                assert_eq!(wide.width, crate::aes_air::WIDTH);
                assert!(comparison.wide_shake_partitions.is_empty());
            }
            RequestDescriptor::Shake(d) => {
                assert_eq!(
                    wide.height,
                    (d.permutations().unwrap() * 24).next_power_of_two()
                );
                assert_eq!(wide.width, shake_air::WIDTH);
                assert_eq!(comparison.wide_shake_partitions.len(), 5);
                for partition in &comparison.wide_shake_partitions {
                    assert_eq!(
                        partition.segments.len(),
                        request.units().div_ceil(partition.maximum_permutations)
                    );
                }
            }
        }
        requests.push(serde_json::json!({
            "operation": request.operation_index(), "subrequest": request.subrequest(),
            "descriptor": format!("{:?}", request.descriptor()),
            "whole_wide": geometry(wide),
            "serial_child_count": comparison.serial_segments.len(),
            "serial_total_raw_trace_bytes": serial_raw,
            "serial_max_retained_main_lde_bytes": comparison.serial_segments.iter().map(|s| s.retained_main_lde_bytes).max(),
            "serial_to_wide_raw_cell_ratio": serial_raw as f64 / wide.raw_trace_bytes as f64,
            "wide_shake_partitions": comparison.wide_shake_partitions.iter().map(|partition| {
                serde_json::json!({
                    "maximum_permutations": partition.maximum_permutations,
                    "children": partition.segments.len(),
                    "total_raw_trace_bytes": partition.segments.iter().map(|s| s.raw_trace_bytes).sum::<u64>(),
                    "max_retained_main_lde_bytes": partition.segments.iter().map(|s| s.retained_main_lde_bytes).max(),
                    "max_uncalibrated_peak_estimate_bytes": partition.segments.iter().map(|s| s.uncalibrated_peak_estimate_bytes).max(),
                })
            }).collect::<Vec<_>>(),
        }));
    }
    eprintln!(
        "crypto wide layout estimate {}",
        serde_json::json!({
            "status": "allocation-free estimates of existing AIRs; no native proof or production measurement",
            "main_lde_excludes": "quotient/FRI matrices, hashes, openings and workspaces",
            "hiding_bits": 1, "log_blowup": profile::LOG_BLOWUP,
        "component_tree_wide_adapter": "available through explicit wide factory; this test proves no child or wrapper",
            "requests": requests,
        })
    );
}

fn aes_request(key: [u8; 32], operation: usize, maximum: usize) -> Request {
    Request::new(
        [17; 32],
        operation,
        0,
        RequestDescriptor::Aes(aes_lane_air::Descriptor {
            domain: 0x4368,
            start_counter: 161,
            output_len: 127,
        }),
        Payload::Aes(key),
        candidate(maximum, 8 << 30),
    )
    .unwrap()
}

#[test]
fn crypto_cache_identity_binds_payload_profile_request_and_exact_segment_geometry() {
    let a = aes_request([7; 32], 5, 4);
    let same = aes_request([7; 32], 5, 4);
    assert_eq!(a.cache_key(0).unwrap(), same.cache_key(0).unwrap());
    assert_ne!(a.cache_key(0).unwrap(), a.cache_key(1).unwrap());
    assert_ne!(
        a.cache_key(0).unwrap(),
        aes_request([8; 32], 5, 4).cache_key(0).unwrap()
    );
    assert_ne!(
        a.cache_key(0).unwrap(),
        aes_request([7; 32], 6, 4).cache_key(0).unwrap()
    );
    assert_ne!(
        a.cache_key(0).unwrap(),
        aes_request([7; 32], 5, 8).cache_key(0).unwrap()
    );
    let mut changed_profile = same;
    changed_profile.profile[0] ^= 1;
    assert_ne!(
        a.cache_key(0).unwrap(),
        changed_profile.cache_key(0).unwrap()
    );
}

struct TemporaryDirectory(PathBuf);
impl TemporaryDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "lattica-crypto-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn missing_malformed_and_oversized_cache_entries_do_not_become_proofs() {
    let directory = TemporaryDirectory::new();
    assert!(ProofCache::new(&directory.0, 0).is_err());
    assert!(ProofCache::new(&directory.0, (1 << 30) + 1).is_err());
    let cache = ProofCache::new(&directory.0, 128).unwrap();
    let request = aes_request([7; 32], 5, 4);
    assert!(cache.load(&request, 0).unwrap().is_none());
    let path = cache.entry_path(&request.cache_key(0).unwrap());
    std::fs::write(&path, b"[1,\"not-a-proof\",[],{}]").unwrap();
    assert!(cache.load(&request, 0).is_err());
    std::fs::write(&path, [0; 129]).unwrap();
    assert!(cache.load(&request, 0).is_err());
    assert!(cache.load_or_prove(&request, 0).is_err());
}

#[test]
fn wide_factory_uses_exact_request_partition_and_rejects_oversized_segments() {
    let (graph, tree, _) = fixture();
    let plan = Plan::new(&tree, &graph, Policy::default()).unwrap();
    let alpha = plan
        .requests()
        .iter()
        .find(|r| {
            matches!(
                graph.operations()[r.operation_index()],
                Operation::HashAlpha { .. }
            )
        })
        .unwrap();
    let x = plan
        .requests()
        .iter()
        .find(|r| {
            matches!(
                graph.operations()[r.operation_index()],
                Operation::HashX { .. }
            )
        })
        .unwrap();
    let whole_x = x.wide_shake(1024, 8 << 30).unwrap();
    assert_eq!(whole_x.segment_count(), 1);
    assert_eq!(whole_x.segments()[0].permutations, 122);
    assert_eq!(whole_x.geometry(0).unwrap().height, 4096);
    assert_eq!(whole_x.geometry(0).unwrap().width, shake_air::WIDTH);
    assert!(whole_x.cache_key(1).is_err());
    assert!(whole_x.prove_segment(1).is_err());
    for budget in [8u64 << 30, 64 << 30] {
        assert!(alpha.wide_shake(alpha.units(), budget).is_err());
    }
    let split = alpha.wide_shake(1024, 64 << 30).unwrap();
    assert_eq!(split.segment_count(), 2);
    assert_eq!(
        (
            split.segments()[0].first_permutation,
            split.segments()[0].permutations
        ),
        (0, 1024)
    );
    assert_eq!(
        (
            split.segments()[1].first_permutation,
            split.segments()[1].permutations
        ),
        (1024, 671)
    );
    assert!(x.wide_shake(0, 8 << 30).is_err());
    assert!(x.wide_shake(1024, 0).is_err());
    let aes = plan
        .requests()
        .iter()
        .find(|r| matches!(r.descriptor(), RequestDescriptor::Aes(_)))
        .unwrap();
    assert!(aes.wide_shake(1, 8 << 30).is_err());
    assert_ne!(x.cache_key(0).unwrap(), whole_x.cache_key(0).unwrap());
    assert_ne!(
        whole_x.cache_key(0).unwrap(),
        x.wide_shake(64, 8 << 30).unwrap().cache_key(0).unwrap()
    );
}

fn small_shake_request(input: Vec<u8>, operation: usize) -> Request {
    Request::new(
        [17; 32],
        operation,
        0,
        RequestDescriptor::Shake(shake_air::Descriptor {
            input_len: input.len(),
            output_len: 32,
        }),
        Payload::Shake(input),
        Policy::default(),
    )
    .unwrap()
}

#[test]
fn wide_cache_identity_binds_payload_profile_request_and_its_distinct_layout() {
    let a = small_shake_request(vec![7; 109], 5);
    let same = small_shake_request(vec![7; 109], 5);
    let payload = small_shake_request(vec![8; 109], 5);
    let operation = small_shake_request(vec![7; 109], 6);
    let mut profile = small_shake_request(vec![7; 109], 5);
    profile.profile[0] ^= 1;
    let key = a.wide_shake(1, 8 << 30).unwrap().cache_key(0).unwrap();
    assert_eq!(
        key,
        same.wide_shake(1, 8 << 30).unwrap().cache_key(0).unwrap()
    );
    for changed in [&payload, &operation, &profile] {
        assert_ne!(
            key,
            changed
                .wide_shake(1, 8 << 30)
                .unwrap()
                .cache_key(0)
                .unwrap()
        );
    }
    assert_ne!(key, a.cache_key(0).unwrap());
}

#[test]
fn malformed_and_oversized_wide_cache_entries_fail_without_proving() {
    let directory = TemporaryDirectory::new();
    let cache = ProofCache::new(&directory.0, 128).unwrap();
    let request = small_shake_request(vec![7; 109], 5);
    let wide = request.wide_shake(1, 8 << 30).unwrap();
    assert!(cache.load_wide(&wide, 0).unwrap().is_none());
    let path = cache.entry_path(&wide.cache_key(0).unwrap());
    assert!(cache.import_wide(&wide, 0, &path).is_err());
    std::fs::write(&path, b"[1,\"not-a-proof\",[],{}]").unwrap();
    assert!(cache.load_wide(&wide, 0).is_err());
    assert!(cache.import_wide(&wide, 0, &path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"[1,\"not-a-proof\",[],{}]");
    std::fs::write(&path, [0; 129]).unwrap();
    assert!(cache.load_wide(&wide, 0).is_err());
    assert!(cache.load_or_prove_wide(&wide, 0).is_err());
    assert!(cache.import_wide(&wide, 0, &path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), [0; 129]);
}

#[test]
#[ignore = "actual PP native proof/cache and recursive verifier trace; reserve guarded memory"]
fn actual_pp_crypto_child_cache_and_typed_wrapper_reject_mutations() {
    let (graph, tree, context) = fixture();
    let plan = Plan::new(&tree, &graph, Policy::default()).unwrap();
    let request = plan
        .requests()
        .iter()
        .find(|request| {
            matches!(
                graph.operations()[request.operation_index()],
                Operation::ParametersPp { .. }
            )
        })
        .unwrap();
    let directory = TemporaryDirectory::new();
    let cache = ProofCache::new(&directory.0, 32 << 20).unwrap();
    let first = cache.load_or_prove(request, 0).unwrap();
    assert!(!first.cache_hit);
    let second = cache.load_or_prove(request, 0).unwrap();
    assert!(second.cache_hit);
    assert_eq!(first.key, second.key);
    let node = request
        .compile_segment_leaf(0, &context, &second.artifact)
        .unwrap();
    node.evaluate().unwrap();
    let geometry = node.geometry().unwrap();
    eprintln!(
        "crypto PP child wrapper {}",
        serde_json::json!({
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "retained_lde_bytes": geometry.retained_lde_bytes,
            "outer_stark_proved": false,
        })
    );
    let path = cache.entry_path(&first.key);
    let mut encoded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    encoded[1] = serde_json::json!("00");
    std::fs::write(&path, serde_json::to_vec(&encoded).unwrap()).unwrap();
    assert!(cache.load(request, 0).is_err());
    let SegmentArtifact::Shake(mut changed) = first.artifact else {
        panic!("PP is SHAKE")
    };
    changed.public_values[0] += Val::ONE;
    assert!(request
        .verify_segment(0, &SegmentArtifact::Shake(changed))
        .is_err());
    let SegmentArtifact::Shake(mut changed) = second.artifact else {
        panic!("PP is SHAKE")
    };
    changed.proof.degree_bits += 1;
    assert!(request
        .verify_segment(0, &SegmentArtifact::Shake(changed))
        .is_err());
}

#[test]
#[ignore = "unmeasured AES32 native candidate; run only in reserved8GiB process window"]
fn actual_aes32_native_candidate_retains_full_security_profile() {
    let (graph, tree, _) = fixture();
    let plan = Plan::new(&tree, &graph, candidate(32, 8 << 30)).unwrap();
    let request = plan
        .requests()
        .iter()
        .find(|request| {
            matches!(
                graph.operations()[request.operation_index()],
                Operation::SampleG { .. }
            )
        })
        .unwrap();
    assert_eq!(request.segments()[0].units, 32);
    assert!(!request.segments()[0].within_previously_measured_batch_size);
    let started = std::time::Instant::now();
    let artifact = request.prove_segment(0).unwrap();
    let proving_seconds = started.elapsed().as_secs_f64();
    request.verify_segment(0, &artifact).unwrap();
    if let Some(directory) = std::env::var_os("LATTICA_PQ_CRYPTO_ARTIFACT_DIR") {
        ProofCache::new(PathBuf::from(directory), 64 << 20)
            .unwrap()
            .store(request, 0, &artifact)
            .unwrap();
    }
    eprintln!(
        "crypto AES32 native candidate {}",
        serde_json::json!({
            "units": 32, "width": request.segments()[0].width,
            "height": request.segments()[0].height, "proving_seconds": proving_seconds,
            "proof_bytes_json": serde_json::to_vec(artifact.proof()).unwrap().len(),
            "estimated_peak_bytes": request.segments()[0].estimated_peak_bytes,
            "source_fingerprint": format!("{:x?}", crate::graph_proofs::compiled_source_fingerprint()),
            "profile_changed": false, "outer_stark_proved": false,
        })
    );
}

#[cfg(feature = "recursive-wide")]
#[test]
#[ignore = "exact ExpandAlpha sparse request native proof/geometry; outer proof requires explicit opt-in and external guard"]
fn actual_expand_alpha_sparse_complete_request_geometry_and_optional_outer() {
    let started = std::time::Instant::now();
    let fixture_path = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing exact public fixture required"),
    );
    let (graph, tree, context) = archived_fixture(&fixture_path, false);
    let plan = Plan::new(&tree, &graph, Policy::default()).unwrap();
    let request = plan
        .requests()
        .iter()
        .find(|r| {
            r.subrequest() == 1
                && matches!(
                    graph.operations()[r.operation_index()],
                    Operation::ExpandAlpha { .. }
                )
        })
        .unwrap();
    assert_eq!(
        request.descriptor(),
        RequestDescriptor::Aes(aes_lane_air::Descriptor {
            domain: 0x4368,
            start_counter: 161,
            output_len: 127,
        })
    );
    assert_eq!(request.segments().len(), 1);
    assert_eq!(request.units(), 8);
    let directory = PathBuf::from(
        std::env::var_os("LATTICA_ALPHA_SPARSE_REQUEST_DIRECTORY")
            .expect("explicit persistent request job directory required"),
    );
    let native_cache = ProofCache::new(directory.join("native"), 64 << 20).unwrap();
    let native = native_cache.load_or_prove(request, 0).unwrap();
    let compiled = request
        .compile_segment_leaf(0, &context, &native.artifact)
        .unwrap();
    let geometry = compiled.geometry().unwrap();
    compiled.evaluate().unwrap();
    eprintln!(
        "ALPHA_SPARSE_REQUEST_GEOMETRY {}",
        serde_json::json!({
            "compiled_source_fingerprint": crate::graph_proofs::compiled_source_fingerprint(),
            "operation": request.operation_index(), "request_index": request.request_index(),
            "subrequest": 1, "domain": 0x4368, "start_counter": 161, "output_len": 127,
            "native_units": 8, "native_cache_hit": native.cache_hit,
            "active_rows": geometry.active_rows, "padded_rows": geometry.padded_rows,
            "wires": geometry.wires, "retained_lde_bytes": geometry.retained_lde_bytes,
            "checked_recursive_trace": true, "outer_proof": false,
            "complete_expand_alpha_graph_leaf": false, "complete_matrict_graph": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
    drop(compiled);
    drop(native);
    if std::env::var("LATTICA_ALPHA_SPARSE_REQUEST_OUTER_OPT_IN").as_deref() != Ok("1") {
        return;
    }
    // This is retained geometry admission, not an OS memory cap. The caller
    // must reserve a separate guarded proving process before enabling it.
    let budget = std::env::var("LATTICA_ALPHA_SPARSE_REQUEST_OUTER_BYTES")
        .expect("explicit retained budget and external process guard required")
        .parse::<u64>()
        .unwrap();
    assert!(
        budget > 0 && budget <= 48_u64 << 30,
        "local opt-in outer budget exceeds48GiB"
    );
    assert!(geometry.retained_lde_bytes <= budget,
        "exact sparse request exceeds retained budget before registration: active_rows={} padded_rows={} retained_bytes={} budget_bytes={}",
        geometry.active_rows, geometry.padded_rows, geometry.retained_lde_bytes, budget);
    let outer_cache = OuterProofCache::new(directory.join("outer"), 64 << 20).unwrap();
    let prover = RequestProver::new(&native_cache, &outer_cache, budget).unwrap();
    let mut complete = prover.prove_serial(request, &context).unwrap();
    assert_eq!(complete.report.native_children, 1);
    assert_eq!(complete.report.outer_leaves, 1);
    assert_eq!(complete.report.outer_parents, 0);
    let expected = request.endpoint_context_hint(&context);
    complete
        .key
        .verify_request(&complete.proof, &expected)
        .unwrap();
    complete.proof.public[crate::component_tree::EXPECTED_OUTPUT] += Val::ONE;
    assert!(complete.key.verify(&complete.proof).is_err());
    complete.proof.public[crate::component_tree::EXPECTED_OUTPUT] -= Val::ONE;
    let mut wrong = expected.clone();
    wrong.context[0] ^= 1;
    assert!(complete
        .key
        .verify_request(&complete.proof, &wrong)
        .is_err());
    complete.proof.proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
    assert!(complete.key.verify(&complete.proof).is_err());
    drop(complete);
    // Corruption above was only in memory; the independently verified cache
    // artifact is reopened and checked under a fresh trusted registration.
    let replay = prover.prove_serial(request, &context).unwrap();
    assert_eq!(replay.report.native_cache_hits, 1);
    assert_eq!(replay.report.outer_cache_hits, 1);
    replay.key.verify_request(&replay.proof, &expected).unwrap();
    eprintln!(
        "ALPHA_SPARSE_REQUEST_OUTER {}",
        serde_json::json!({
            "operation": request.operation_index(), "request_index": request.request_index(),
            "outer_proof": true, "complete_request": true, "public_mutation_rejected": true,
            "proof_mutation_rejected": true, "wrong_context_rejected": true,
            "replay_native_cache_hits": replay.report.native_cache_hits,
            "replay_outer_cache_hits": replay.report.outer_cache_hits,
            "maximum_retained_lde_bytes": replay.report.maximum_retained_lde_bytes,
            "complete_expand_alpha_graph_leaf": false, "complete_matrict_graph": false,
            "elapsed_seconds": started.elapsed().as_secs_f64(),
        })
    );
}
