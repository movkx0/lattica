use super::*;
use crate::graph_tree::tests::{context, fixture, singles};
use p3_field::PrimeCharacteristicRing;
use std::path::PathBuf;

fn directory(label: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../.tools/pq-graph-outer-cache-tests")
        .join(format!(
            "{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
}

#[test]
fn graph_prover_rejects_wrong_plan_context_empty_input_and_zero_budget_before_proving() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let directory = directory("admission");
    let cache = ProofCache::new(&directory, 64 << 20).unwrap();
    assert!(GraphProver::new(&plan, &context, &cache, 0).is_err());
    let prover = GraphProver::new(&plan, &context, &cache, 1 << 30).unwrap();
    assert!(prover.aggregate_adjacent(vec![]).is_err());
    let other_plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let other = compile_leaf(&other_plan, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    assert!(prover.prove_leaf(other).is_err());
    let mut wrong = context.clone();
    wrong.statement[0] += Val::ONE;
    let changed = compile_leaf(&plan, &graph, 0, &wrong, LeafArtifact::FixedSources).unwrap();
    assert!(prover.prove_leaf(changed).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "actual fixed-source outer proof, fresh registration/cache replay and corruption rejection; coordinate 2 GiB guard"]
fn actual_graph_outer_cache_reuses_only_verified_exact_partial_nodes() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let directory = directory("actual");
    let cache = ProofCache::new(&directory, 64 << 20).unwrap();
    let prover = GraphProver::new(&plan, &context, &cache, 2 << 30).unwrap();
    let compile = || compile_leaf(&plan, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    let first = prover.prove_leaf(compile()).unwrap();
    assert!(!first.cache_hit());
    assert!(prover.verify_complete(&first).is_err());
    assert!(first.verify_complete(&context).is_err());
    let identity = first.key.cache_identity(&context);
    let path = cache.entry_path(&identity);
    let bytes = std::fs::read(&path).unwrap();
    let replay = prover.prove_leaf(compile()).unwrap();
    assert!(replay.cache_hit());
    assert_eq!(replay.key.cache_identity(&context), identity);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    // A one-node aggregation remains a verified partial node, not acceptance.
    let replay = prover.aggregate_adjacent(vec![replay]).unwrap();
    assert!(prover.verify_complete(&replay).is_err());
    // Duplicated schedule intervals are rejected before any parent proving.
    assert!(prover.aggregate_adjacent(vec![first, replay]).is_err());

    let mut object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    object[3][CONTEXT] = serde_json::json!(0_u64);
    std::fs::write(&path, serde_json::to_vec(&object).unwrap()).unwrap();
    assert!(prover.prove_leaf(compile()).is_err());
    std::fs::write(&path, &bytes).unwrap();

    let (schema, source, identity, public, mut proof): (
        u64,
        [u8; 32],
        [u8; 32],
        Vec<Val>,
        p3_batch_stark::BatchProof<Config>,
    ) = serde_json::from_slice(&bytes).unwrap();
    proof.opened_values.instances[0]
        .base_opened_values
        .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
    std::fs::write(
        &path,
        serde_json::to_vec(&(schema, source, identity, public, proof)).unwrap(),
    )
    .unwrap();
    assert!(prover.prove_leaf(compile()).is_err());
    // Failed replay never silently overwrites corruption with a fresh proof.
    assert_ne!(std::fs::read(&path).unwrap(), bytes);
    std::fs::write(&path, &bytes).unwrap();
    assert!(prover.prove_leaf(compile()).unwrap().cache_hit());
    eprintln!("actual_graph_outer_cache_verified=true actual_parent_proof=false complete_graph_proof=false");
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(feature = "recursive-wide")]
#[test]
#[ignore = "actual fixed/statement graph leaves, parent and verified cache replay; coordinate 48 GiB external guard and eight threads"]
fn actual_adjacent_graph_leaves_parent_cache_and_partial_coverage() {
    use crate::{
        graph_proofs::{GraphProofPlan, ResourceLimits},
        graph_sources::{SourceCache, SourceFactory},
        rust_verify::{committed_backend, Proof, Statement},
    };
    use std::time::Instant;

    fn geometry(phase: &str, compiled: &CompiledNode) {
        let g = compiled.geometry().unwrap();
        assert!(g.retained_lde_bytes <= 32_u64 << 30);
        eprintln!(
            "GRAPH_PREFIX_GEOMETRY {}",
            serde_json::json!({
                "phase": phase, "active_rows": g.active_rows,
                "padded_rows": g.padded_rows, "wires": g.wires,
                "main_width": g.main_width, "preprocessed_width": g.preprocessed_width,
                "permutation_width_base": g.permutation_width_base,
                "quotient_chunks": g.quotient_chunks, "constraints": g.constraints,
                "max_constraint_degree": g.max_constraint_degree,
                "fri_ali_bits": g.fri_ali_bits, "retained_lde_bytes": g.retained_lde_bytes,
            })
        );
    }
    // Only an existing actual registration supplies the key. This helper
    // reloads and verifies real cached proofs for additional mutation checks;
    // the positive replay below separately performs fresh registration.
    fn reload(cache: &ProofCache, key: &NodeKey, context: &GraphContext) -> ProvenNode {
        let (public, proof) = cache
            .load_verified(
                &key.cache_identity(context),
                &header(&key.spec, context),
                |p, proof| key.verifier.verify(proof, p),
            )
            .unwrap()
            .unwrap();
        ProvenNode {
            key: key.clone(),
            proof: NodeProof { public, proof },
            cache_hit: true,
        }
    }
    fn phase(label: &str, started: Instant) {
        eprintln!(
            "GRAPH_PREFIX_TIME {}",
            serde_json::json!({"phase": label, "seconds": started.elapsed().as_secs_f64()})
        );
    }

    let started = Instant::now();
    let archive = PathBuf::from(
        std::env::var_os("LATTICA_GRAPH_FIXTURE_ARCHIVE")
            .expect("explicit existing public graph fixture archive required"),
    );
    let archived = crate::native_test_fixture::load_or_create(
        &archive,
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
        archived.setup_seed,
        &archived.context,
        &Statement::decode(&archived.statement).unwrap(),
        &Proof::decode(&archived.proof).unwrap(),
    )
    .unwrap();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let plan = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    assert!(plan.leaves().len() > 2);
    assert!(matches!(plan.leaves()[0].kind(), LeafKind::FixedSources));
    assert!(matches!(plan.leaves()[1].kind(), LeafKind::Statement));
    let context = GraphContext {
        context: archived.context,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            archived.context,
            &archived.statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(&graph).unwrap(),
    };
    let source_directory = std::env::var_os("LATTICA_GRAPH_SOURCE_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../.tools/pq-child-cache/sources")
        });
    let source_cache = SourceCache::new(source_directory, 64 << 20).unwrap();
    let source = SourceFactory::new(
        &plan,
        &graph,
        &context,
        &archived.statement,
        &archived.proof,
        8 << 30,
    )
    .unwrap();
    let native_started = Instant::now();
    let statement = source.prove_or_load_statement(&source_cache).unwrap();
    source.verify_statement(&statement).unwrap();
    phase("statement-native-proof-or-verified-cache", native_started);
    drop(source);

    let artifacts = std::env::var_os("LATTICA_GRAPH_PREFIX_ARTIFACT_DIR").map(PathBuf::from);
    let directory = artifacts
        .clone()
        .unwrap_or_else(|| directory("actual-prefix-parent"));
    assert!(
        !directory.exists(),
        "graph prefix outer cache must start fresh"
    );
    let cache = ProofCache::new(&directory, 64 << 20).unwrap();
    let prover = GraphProver::new(&plan, &context, &cache, 32 << 30).unwrap();
    let fixed = || compile_leaf(&plan, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    let statement_leaf = || {
        compile_leaf(
            &plan,
            &graph,
            1,
            &context,
            LeafArtifact::Statement(&statement),
        )
        .unwrap()
    };

    let phase_started = Instant::now();
    let compiled = fixed();
    geometry("fixed-leaf", &compiled);
    let left = prover.prove_leaf(compiled).unwrap();
    assert!(!left.cache_hit());
    assert_eq!(left.key.span(), (0, 1));
    let left_key = left.key.clone();
    phase("fixed-leaf-register-prove-verify-store", phase_started);

    let phase_started = Instant::now();
    let compiled = statement_leaf();
    geometry("statement-leaf", &compiled);
    let right = prover.prove_leaf(compiled).unwrap();
    assert!(!right.cache_hit());
    assert_eq!(right.key.span(), (1, 1));
    let right_key = right.key.clone();
    phase("statement-leaf-register-prove-verify-store", phase_started);

    // Exercise the actual constrained parent with both real child proofs.
    // No invalid templates or acceptance receipts enter this experiment.
    let phase_started = Instant::now();
    let mut compiled = compile_merge(&left.key, &right.key, [&left.proof, &right.proof]).unwrap();
    geometry("parent", &compiled);
    compiled.evaluate().unwrap();
    assert_eq!(
        &compiled.witness[..PUBLIC_VALUES],
        left.proof.public.as_slice()
    );
    for index in [
        0,
        CONTEXT,
        STATEMENT,
        NODE_MANIFEST,
        FIRST,
        COUNT,
        TOTAL,
        LEVEL,
    ] {
        compiled.public[index] += Val::ONE;
        assert!(
            compiled.evaluate().is_err(),
            "parent public mutation {index}"
        );
        compiled.public[index] -= Val::ONE;
        compiled.witness[index] += Val::ONE;
        assert!(
            compiled.evaluate().is_err(),
            "child public mutation {index}"
        );
        compiled.witness[index] -= Val::ONE;
    }
    compiled.evaluate().unwrap();
    drop(compiled);
    phase("parent-constrained-mutation-rejection", phase_started);

    let phase_started = Instant::now();
    let mut parent = prover.aggregate_adjacent(vec![left, right]).unwrap();
    assert!(!parent.cache_hit());
    assert_eq!(parent.key.span(), (0, 2));
    assert_eq!(parent.key.spec.level, 1);
    parent.key.verify(&parent.proof).unwrap();
    assert!(prover.verify_complete(&parent).is_err());
    assert!(parent.verify_complete(&context).is_err());
    phase("parent-register-prove-verify-store", phase_started);

    // Diagnostic binary encoding of public fields plus the actual parent
    // STARK, excluding the registered verifier key and any transaction/block
    // envelope. This is not a canonical consensus codec or a full graph proof.
    let binary = postcard::to_allocvec(&(&parent.proof.public, &parent.proof.proof)).unwrap();
    assert!(binary.len() <= 64 << 20);
    let ((public, proof), remaining): ((Vec<Val>, p3_batch_stark::BatchProof<Config>), &[u8]) =
        postcard::take_from_bytes(&binary).unwrap();
    assert!(remaining.is_empty());
    assert_eq!(public, parent.proof.public);
    let decoded = NodeProof { public, proof };
    parent.key.verify(&decoded).unwrap();
    assert!(parent.key.verify_complete(&decoded, &context).is_err());
    drop(decoded);
    let binary_path = directory.join("parent.node-proof.postcard");
    std::fs::write(&binary_path, &binary).unwrap();
    eprintln!(
        "GRAPH_PREFIX_BINARY {}",
        serde_json::json!({
            "format": "diagnostic-postcard-public-and-proof-tuple",
            "bytes": binary.len(), "roundtrip_verified": true,
            "path": binary_path, "public_fields": PUBLIC_VALUES,
            "includes_registered_key": false, "consensus_codec": false,
        })
    );

    for index in [
        0,
        CONTEXT,
        STATEMENT,
        NODE_MANIFEST,
        FIRST,
        COUNT,
        TOTAL,
        LEVEL,
    ] {
        parent.proof.public[index] += Val::ONE;
        assert!(parent.key.verify(&parent.proof).is_err());
        assert!(prover.verify_node(&parent).is_err());
        parent.proof.public[index] -= Val::ONE;
    }
    parent.key.verify(&parent.proof).unwrap();
    for field in 0..3 {
        let mut wrong = context.clone();
        match field {
            0 => wrong.context[0] ^= 1,
            1 => wrong.statement[0] += Val::ONE,
            _ => wrong.node_manifest[0] += Val::ONE,
        }
        assert!(GraphProver::new(&plan, &wrong, &cache, 32 << 30)
            .unwrap()
            .verify_node(&parent)
            .is_err());
    }
    let other_plan = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    assert!(GraphProver::new(&other_plan, &context, &cache, 32 << 30)
        .unwrap()
        .verify_node(&parent)
        .is_err());
    for keys in [[&left_key, &left_key], [&right_key, &left_key]] {
        let children = keys
            .into_iter()
            .map(|key| reload(&cache, key, &context))
            .collect();
        assert!(prover.aggregate_adjacent(children).is_err());
    }

    let identity = parent.key.cache_identity(&context);
    let path = cache.entry_path(&identity);
    let bytes = std::fs::read(&path).unwrap();
    let phase_started = Instant::now();
    let replay_left = prover.prove_leaf(fixed()).unwrap();
    let replay_right = prover.prove_leaf(statement_leaf()).unwrap();
    assert!(replay_left.cache_hit() && replay_right.cache_hit());
    let replay = prover
        .aggregate_adjacent(vec![replay_left, replay_right])
        .unwrap();
    assert!(replay.cache_hit());
    assert_eq!(replay.key.cache_identity(&context), identity);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    assert!(prover.verify_complete(&replay).is_err());
    phase(
        "fresh-registration-leaves-and-parent-cache-replay",
        phase_started,
    );

    let phase_started = Instant::now();
    for corrupt_opening in [false, true] {
        let (schema, source, identity, mut public, mut proof): (
            u64,
            [u8; 32],
            [u8; 32],
            Vec<Val>,
            p3_batch_stark::BatchProof<Config>,
        ) = serde_json::from_slice(&bytes).unwrap();
        if corrupt_opening {
            proof.opened_values.instances[0]
                .base_opened_values
                .trace_local[0] += lattica_prover_p3::block_v2::profile::Challenge::ONE;
        } else {
            public[CONTEXT] += Val::ONE;
        }
        let corrupted = serde_json::to_vec(&(schema, source, identity, public, proof)).unwrap();
        std::fs::write(&path, &corrupted).unwrap();
        assert!(prover
            .aggregate_adjacent(vec![
                reload(&cache, &left_key, &context),
                reload(&cache, &right_key, &context),
            ])
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), corrupted);
        std::fs::write(&path, &bytes).unwrap();
    }
    let restored = reload(&cache, &parent.key, &context);
    prover.verify_node(&restored).unwrap();
    assert!(prover.verify_complete(&restored).is_err());
    phase(
        "parent-cache-corruption-rejection-and-restoration",
        phase_started,
    );
    eprintln!(
        "GRAPH_PREFIX_RESULT {}",
        serde_json::json!({
            "actual_leaf_outer_proofs": 2, "actual_parent_outer_proof": true,
            "fresh_registration_cache_replay": true, "constrained_public_mutations": 16,
            "native_parent_public_mutations": 8, "cache_mutations_rejected": 2,
            "covered_schedule_entries": 2, "registered_schedule_entries": plan.leaves().len(),
            "complete_graph_proof": false, "cache_directory": directory,
            "parent_cache_path": path, "parent_diagnostic_json_bytes": bytes.len(),
            "parent_diagnostic_binary_bytes": binary.len(),
            "seconds": started.elapsed().as_secs_f64(),
        })
    );
    if artifacts.is_none() {
        std::fs::remove_dir_all(directory).unwrap();
    }
}
