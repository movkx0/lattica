use super::*;

#[cfg(feature = "native-matrict")]
fn fixture() -> (
    crate::rust_verify::Statement,
    crate::rust_verify::Proof,
    UnprovedRelationGraph,
) {
    let (statement, proof, graph, _) = fixture_with_bytes();
    (statement, proof, graph)
}

#[cfg(feature = "native-matrict")]
pub(super) fn fixture_with_bytes() -> (
    crate::rust_verify::Statement,
    crate::rust_verify::Proof,
    UnprovedRelationGraph,
    Vec<u8>,
) {
    let fixture = crate::native::generate_fixture_with_setup_seed(
        [71; 32],
        [29; 32],
        3,
        crate::native::FixtureAmounts {
            input: [17, 23],
            output: [29, 11],
        },
    )
    .unwrap();
    let statement = crate::rust_verify::Statement::decode(&fixture.statement).unwrap();
    let proof = crate::rust_verify::Proof::decode(&fixture.proof).unwrap();
    let graph = crate::rust_verify::committed_backend::lower_unproved(
        [29; 32], &[71; 32], &statement, &proof,
    )
    .unwrap();
    (statement, proof, graph, fixture.statement)
}

#[cfg(feature = "native-matrict")]
pub(super) fn archived_fixture(
    allow_create: bool,
) -> (
    crate::rust_verify::Statement,
    crate::rust_verify::Proof,
    UnprovedRelationGraph,
    Vec<u8>,
) {
    use sha3::Digest;
    let path = std::path::PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit public LATTICA_GRAPH_FIXTURE_ARCHIVE required"),
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
        allow_create,
    )
    .unwrap();
    let statement = crate::rust_verify::Statement::decode(&fixture.statement).unwrap();
    let proof = crate::rust_verify::Proof::decode(&fixture.proof).unwrap();
    let graph = crate::rust_verify::committed_backend::lower_unproved(
        [29; 32], &[71; 32], &statement, &proof,
    )
    .unwrap();
    let statement_hash: [u8; 32] = sha3::Sha3_256::digest(&fixture.statement).into();
    let proof_hash: [u8; 32] = sha3::Sha3_256::digest(&fixture.proof).into();
    eprintln!(
        "graph public fixture archive {}",
        serde_json::json!({
            "path": path,
            "statement_sha3_256": cache::hex(&statement_hash),
            "proof_sha3_256": cache::hex(&proof_hash),
            "native_reverified": true,
            "contains_private_rng_or_keys": false,
        })
    );
    (statement, proof, graph, fixture.statement)
}

#[test]
#[cfg(feature = "native-matrict")]
fn deterministic_plan_partitions_every_non_norm_operation_and_enforces_budgets() {
    let (_, _, graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let plan = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let mut seen = Vec::new();
    let mut algebra_operations = 0;
    let mut external = 0;
    for batch in plan.batches() {
        assert!(!batch.indices.is_empty());
        assert!(batch.indices.windows(2).all(|pair| pair[0] < pair[1]));
        seen.extend_from_slice(&batch.indices);
        if batch.kind == ComponentKind::External {
            external += 1;
            assert_eq!(batch.indices.len(), 1);
            assert!(batch.estimate.is_none());
        } else {
            algebra_operations += batch.indices.len();
            assert!(batch.indices.len().is_power_of_two());
            assert!(batch.indices.len() <= 8);
            assert!(ResourceLimits::default().accepts(batch.estimate.unwrap()));
        }
    }
    assert!(plan
        .batches
        .windows(2)
        .all(|pair| pair[0].indices[0] < pair[1].indices[0]));
    seen.sort_unstable();
    let expected: Vec<_> = graph
        .operations()
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, Operation::Norm { .. }))
        .map(|(index, _)| index)
        .collect();
    assert_eq!(seen, expected);
    assert_eq!(algebra_operations, 1296);
    assert_eq!(external, 9);
    let tree =
        crate::graph_tree::Plan::from_trusted_graph(&graph, plan.operation_batches()).unwrap();
    assert_eq!(tree.leaves().len(), plan.batches().len() + 3);
    let mut tree_operations: Vec<_> = tree
        .leaves()
        .iter()
        .flat_map(|leaf| leaf.operation_indices().iter().copied())
        .collect();
    tree_operations.sort_unstable();
    assert_eq!(tree_operations, (0..1311).collect::<Vec<_>>());
    let again = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    assert_eq!(plan.operation_batches(), again.operation_batches());
    let too_small = ResourceLimits {
        max_estimated_prover_bytes: 1,
        ..ResourceLimits::default()
    };
    assert!(GraphProofPlan::new(&registered, &graph, too_small).is_err());
    let invalid = ResourceLimits {
        max_batch_count: 129,
        ..ResourceLimits::default()
    };
    assert!(GraphProofPlan::new(&registered, &graph, invalid).is_err());
    let first_external = plan
        .batches
        .iter()
        .position(|b| b.kind == ComponentKind::External)
        .unwrap();
    assert!(plan.prove_batch(first_external).is_err());
    assert!(plan.cache_key(first_external).is_err());
    let report: Vec<_> = plan.batches.iter().map(|b| serde_json::json!({
        "indices": b.indices,
        "kind": match b.kind { ComponentKind::Affine { .. } => "affine", ComponentKind::Ntt { .. } => "ntt",
            ComponentKind::Mul { .. } => "mul", ComponentKind::GBound { .. } => "g-bound",
            ComponentKind::Permutation { .. } => "permutation", ComponentKind::LinearMap { .. } => "linear-map",
            ComponentKind::External => "external" },
        "trace_bytes": b.estimate.map(|e| e.trace_bytes),
        "estimated_prover_bytes": b.estimate.map(|e| e.estimated_prover_bytes),
    })).collect();
    eprintln!(
        "graph proof plan {}",
        serde_json::json!({ "batches": report,
        "algebra_operations": algebra_operations, "external_operations": external })
    );
}

#[test]
#[cfg(feature = "native-matrict")]
fn cache_identity_excludes_owner_and_includes_roots_source_and_batch_order() {
    let (statement, proof, graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let graph2 = crate::rust_verify::committed_backend::lower_unproved(
        [29; 32], &[71; 32], &statement, &proof,
    )
    .unwrap();
    let plan = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let mut plan2 = GraphProofPlan::new(&registered, &graph2, ResourceLimits::default()).unwrap();
    let index = plan
        .batches
        .iter()
        .position(|batch| {
            matches!(batch.kind, ComponentKind::Affine { .. }) && batch.indices.len() > 1
        })
        .unwrap();
    assert_eq!(
        plan.cache_key(index).unwrap(),
        plan2.cache_key(index).unwrap()
    );
    plan2.batches[index].indices.swap(0, 1);
    assert_ne!(
        plan.cache_key(index).unwrap(),
        plan2.cache_key(index).unwrap()
    );
    plan2.batches[index].indices.swap(0, 1);
    plan2.source_fingerprint[0] ^= 1;
    assert_ne!(
        plan.cache_key(index).unwrap(),
        plan2.cache_key(index).unwrap()
    );
    let mut changed_statement = statement;
    changed_statement.ring[0][0].pk[0][0] =
        (changed_statement.ring[0][0].pk[0][0] + 1) % crate::rust_verify::Q;
    let changed = crate::rust_verify::committed_backend::lower_unproved(
        [29; 32],
        &[71; 32],
        &changed_statement,
        &proof,
    )
    .unwrap();
    let changed_plan =
        GraphProofPlan::new(&registered, &changed, ResourceLimits::default()).unwrap();
    assert!(plan
        .batches
        .iter()
        .enumerate()
        .filter(|(_, b)| b.kind != ComponentKind::External)
        .any(|(i, _)| plan.cache_key(i).unwrap() != changed_plan.cache_key(i).unwrap()));
    let wrong_setup = crate::rust_verify::committed_backend::lower_unproved(
        [30; 32],
        &[71; 32],
        &changed_statement,
        &proof,
    )
    .unwrap();
    assert!(GraphProofPlan::new(&registered, &wrong_setup, ResourceLimits::default()).is_err());
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "actual two-operation graph proof/cache roundtrip; run with external memory guard"]
fn actual_graph_affine_batch_cache_roundtrip_rejects_corruption() {
    use p3_field::PrimeCharacteristicRing;
    let (_, _, graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let plan = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_batch_count: 2,
            ..ResourceLimits::default()
        },
    )
    .unwrap();
    let index = plan
        .batches
        .iter()
        .position(|batch| {
            matches!(
                batch.kind,
                ComponentKind::Affine {
                    kind: AffineKind::Add,
                    ..
                }
            ) && batch.indices.len() == 2
        })
        .unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../.tools/pq-child-cache/factory-test-{}-{nonce}",
        std::process::id()
    ));
    let cache = ProofCache::new(&directory, 64 << 20).unwrap();
    let fresh = cache.load_or_prove(&plan, index).unwrap();
    assert!(!fresh.cache_hit);
    drop(cache);
    let resumed = ProofCache::new(&directory, 64 << 20).unwrap();
    let hit = resumed.load_or_prove(&plan, index).unwrap();
    assert!(hit.cache_hit);
    assert_eq!(fresh.key, hit.key);
    assert_eq!(fresh.artifact.public_values(), hit.artifact.public_values());
    let path = resumed.entry_path(&hit.key);
    let original = std::fs::read(&path).unwrap();
    assert!(ProofCache::new(&directory, 1)
        .unwrap()
        .load(&plan, index)
        .is_err());
    let other = plan
        .batches
        .iter()
        .enumerate()
        .find(|(i, b)| *i != index && matches!(b.kind, ComponentKind::Affine { .. }))
        .unwrap()
        .0;
    assert!(plan.verify_batch(other, &hit.artifact).is_err());
    assert!(resumed
        .reverify_archived_entry(&plan, other, &path)
        .is_err());
    let mut new_version = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_batch_count: 2,
            ..ResourceLimits::default()
        },
    )
    .unwrap();
    new_version.source_fingerprint[0] ^= 1;
    assert!(resumed.load(&new_version, index).unwrap().is_none());
    let imported = resumed
        .reverify_archived_entry(&new_version, index, &path)
        .unwrap();
    assert_eq!(imported.archived_key, cache::hex(&hit.key));
    assert_ne!(imported.current_key, hit.key);
    assert_eq!(imported.current_key, new_version.cache_key(index).unwrap());
    assert!(!resumed.entry_path(&imported.current_key).exists());
    type Encoded = (u64, String, Vec<Val>, p3_uni_stark::Proof<profile::Config>);
    for mutation in 0..4 {
        let mut encoded: Encoded = serde_json::from_slice(&original).unwrap();
        match mutation {
            0 => encoded.1.replace_range(..2, "xx"),
            1 => encoded.2[0] += Val::ONE,
            2 => encoded.3.degree_bits += 1,
            _ => encoded.3.opened_values.trace_local[0] += profile::Challenge::ONE,
        }
        std::fs::write(&path, serde_json::to_vec(&encoded).unwrap()).unwrap();
        assert!(
            resumed.load(&plan, index).is_err(),
            "accepted corrupt cache case {mutation}"
        );
        assert!(resumed
            .reverify_archived_entry(&plan, index, &path)
            .is_err());
    }
    std::fs::write(&path, &original).unwrap();
    assert!(resumed.load(&plan, index).unwrap().is_some());
    eprintln!(
        "actual graph proof cache batch={:?} bytes={} key={} directory={}",
        plan.batches[index].indices,
        original.len(),
        cache::hex(&hit.key),
        directory.display()
    );
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "bounded full-graph planning diagnostic only; creates no STARKs"]
fn graph_batch_cost_plan() {
    report_cost_plans("local_family_caps", &[8, 16, 32, 64], 8 << 30, false, None);
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "unmeasured production schedule candidates only; creates no STARKs"]
fn graph_production_batch_cost_plan() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data/production-resource-envelope.json");
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let budget = envelope["production_planning"]
        ["candidate_virtual_memory_budget_bytes_per_worker"]
        .as_u64()
        .unwrap();
    assert_eq!(budget, 64 << 30);
    report_cost_plans(
        "unbenchmarked_production_candidate",
        &[64, 128],
        budget,
        true,
        Some(&envelope),
    );
}

#[cfg(feature = "native-matrict")]
fn report_cost_plans(
    environment: &str,
    maxima: &[usize],
    budget: u64,
    production: bool,
    hardware_envelope: Option<&serde_json::Value>,
) {
    let (_, _, graph) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    for &maximum in maxima {
        let limits = ResourceLimits {
            max_batch_count: maximum,
            max_ntt_batch_count: if production { maximum } else { 32 },
            max_mul_batch_count: if production { maximum } else { 16 },
            max_trace_cells: if production { budget / 8 } else { 1 << 27 },
            max_estimated_prover_bytes: budget,
        };
        let plan = GraphProofPlan::new(&registered, &graph, limits).unwrap();
        let tree =
            crate::graph_tree::Plan::from_trusted_graph(&graph, plan.operation_batches()).unwrap();
        let mut distribution = BTreeMap::<String, BTreeMap<usize, usize>>::new();
        let mut trace_sum = 0u64;
        let mut trace_peak = 0u64;
        let mut prover_peak = 0u64;
        let mut child_count = 0usize;
        let mut external_count = 0usize;
        let mut geometry = BTreeMap::<String, serde_json::Value>::new();
        for batch in plan.batches() {
            let name = match batch.kind() {
                ComponentKind::Affine { kind, modulus } => format!("affine/{kind:?}/{modulus}"),
                ComponentKind::Ntt { modulus } => format!("ntt/{modulus}"),
                ComponentKind::Mul { modulus } => format!("mul/{modulus}"),
                ComponentKind::GBound { bound } => format!("g-bound/{bound}"),
                ComponentKind::Permutation { kind } => format!("permutation/{kind:?}"),
                ComponentKind::LinearMap { descriptor } => format!(
                    "linear-map/{:?}/{}",
                    descriptor.output(),
                    descriptor.inputs().len()
                ),
                ComponentKind::External => "external".to_owned(),
            };
            *distribution
                .entry(name.clone())
                .or_default()
                .entry(batch.indices.len())
                .or_default() += 1;
            if let Some(estimate) = batch.estimate {
                child_count += 1;
                trace_sum += estimate.trace_bytes;
                trace_peak = trace_peak.max(estimate.trace_bytes);
                prover_peak = prover_peak.max(estimate.estimated_prover_bytes);
                geometry.insert(format!("{name}/count{}", batch.indices.len()), serde_json::json!({
                    "width": estimate.width, "height": estimate.height, "public_values": estimate.public_values,
                    "trace_bytes": estimate.trace_bytes, "estimated_prover_bytes": estimate.estimated_prover_bytes,
                }));
            } else {
                external_count += 1;
            }
        }
        eprintln!(
            "graph batch cost plan {}",
            serde_json::json!({
                "environment": environment,
                "hardware_envelope": hardware_envelope,
                "requested_max_batch_count": maximum,
                "ntt_family_batch_ceiling": limits.max_ntt_batch_count,
                "mul_family_batch_ceiling": limits.max_mul_batch_count,
                "algebra_child_count": child_count,
                "external_operation_leaves": external_count,
                "source_leaves": 3,
                "graph_tree_leaf_count": tree.leaves().len(),
                "algebra_trace_bytes_sum": trace_sum,
                "algebra_trace_bytes_peak": trace_peak,
                "estimated_prover_bytes_peak": prover_peak,
                "estimated_prover_bytes_limit": limits.max_estimated_prover_bytes,
                "batch_count_distribution": distribution,
                "component_geometry": geometry,
                "source_fingerprint": cache::hex(&plan.source_fingerprint()),
                "proofs_generated": false,
                "scope": "Exact child trace dimensions and graph-tree leaf count; memory estimates are heuristic, not measured peaks. No recursive-wrapper geometry or actual proofs."
            })
        );
    }
}

#[cfg(feature = "native-matrict")]
fn actual_largest_batch(ntt: bool, count: usize) {
    let (_, _, graph, _) = archived_fixture(true);
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let plan = GraphProofPlan::new(
        &registered,
        &graph,
        ResourceLimits {
            max_batch_count: 64,
            max_ntt_batch_count: 32,
            max_mul_batch_count: if ntt { 16 } else { count },
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
    let estimate = batch.estimate.unwrap();
    let family = if ntt { "ntt" } else { "mul" };
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/pq-child-cache/algebra");
    let cache = ProofCache::new(&directory, 64 << 20).unwrap();
    let key = plan.cache_key(index).unwrap();
    eprintln!(
        "graph batch{count} begin {}",
        serde_json::json!({
            "family": family, "indices": batch.indices,
            "width": estimate.width, "height": estimate.height,
            "public_values": estimate.public_values, "raw_trace_bytes": estimate.trace_bytes,
            "estimated_prover_bytes": estimate.estimated_prover_bytes,
            "key": cache::hex(&key), "source_fingerprint": cache::hex(&plan.source_fingerprint()),
        })
    );
    let start = std::time::Instant::now();
    let (artifact, hit) = match cache.load(&plan, index).unwrap() {
        Some(proof) => (proof, true),
        None => (plan.prove_batch(index).unwrap(), false),
    };
    let proof_elapsed = start.elapsed().as_millis();
    let persist = std::time::Instant::now();
    if !hit {
        cache.store(&plan, index, &artifact).unwrap();
    }
    let persist_elapsed = persist.elapsed().as_millis();
    // Re-open and verify the actual serialized proof before reporting success.
    drop(artifact);
    assert!(cache.load(&plan, index).unwrap().is_some());
    let path = cache.entry_path(&key);
    eprintln!(
        "graph batch{count} complete {}",
        serde_json::json!({
            "family": family, "count": count, "width": estimate.width, "height": estimate.height,
            "public_values": estimate.public_values,
            "cache_hit": hit, "prove_and_native_verify_or_cache_load_ms": proof_elapsed,
            "cache_persistence_ms": persist_elapsed,
            "cache_bytes": std::fs::metadata(&path).unwrap().len(), "cache_file": path,
            "key": cache::hex(&key), "outer_proof_attempted": false,
        })
    );
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "actual largest NTT32 factory child; requires external8GiB guard and exclusive proving window"]
fn actual_graph_ntt_batch32_cached() {
    actual_largest_batch(true, 32);
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "actual largest Mul32 factory child; requires external8GiB guard and exclusive proving window"]
fn actual_graph_mul_batch32_cached() {
    actual_largest_batch(false, 32);
}

#[test]
#[cfg(feature = "native-matrict")]
#[ignore = "actual largest Mul16 factory child; requires external8GiB guard and exclusive proving window"]
fn actual_graph_mul_batch16_cached() {
    actual_largest_batch(false, 16);
}
