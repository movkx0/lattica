#![cfg(feature = "native-matrict")]
use super::*;
use crate::rust_verify::{
    committed_backend::{self, Operation, Source},
    Proof, Statement,
};
use lattica_prover_p3::block_v2::machine::{verifier::ProofInputs, MachineAir};

pub(super) fn fixture() -> (UnprovedRelationGraph, Vec<u8>) {
    let native = crate::native::generate_fixture_with_setup_seed(
        [73; 32],
        [91; 32],
        4,
        crate::native::FixtureAmounts {
            input: [19, 31],
            output: [23, 27],
        },
    )
    .unwrap();
    let graph = committed_backend::lower_unproved(
        [91; 32],
        &[73; 32],
        &Statement::decode(&native.statement).unwrap(),
        &Proof::decode(&native.proof).unwrap(),
    )
    .unwrap();
    (graph, native.statement)
}
pub(super) fn singles(graph: &UnprovedRelationGraph) -> Vec<Vec<usize>> {
    graph
        .operations()
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, Operation::Norm { .. }))
        .map(|(i, _)| vec![i])
        .collect()
}
pub(super) fn context(plan: &Plan, graph: &UnprovedRelationGraph, statement: &[u8]) -> GraphContext {
    GraphContext {
        context: [73; 32],
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            plan.label(),
            [73; 32],
            statement,
        )
        .unwrap()
        .digest
        .map(Val::from_u64),
        node_manifest: plan.node_manifest_hint(graph).unwrap(),
    }
}

#[test]
fn grouped_leaf_coverage_keeps_registered_schedule_and_unique_producers() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let (polynomials, bytes, operations) = leaf::group_coverage(&graph, plan.leaves()).unwrap();
    assert_eq!(
        (polynomials.len(), bytes.len(), operations.len()),
        (1770, 8, FULL_OPERATIONS)
    );
    let (source_polynomials, source_bytes, norms) =
        leaf::group_coverage(&graph, &plan.leaves()[..3]).unwrap();
    assert_eq!(
        (source_polynomials.len(), source_bytes.len(), norms.len()),
        (474, 6, 6)
    );
    let mut changed = plan.leaves()[..3].to_vec();
    let repeated_polynomial = changed[0].polynomials[0];
    changed[1].polynomials.push(repeated_polynomial);
    changed[1].polynomials.sort_unstable();
    assert!(leaf::group_coverage(&graph, &changed).is_err());
    let mut changed = plan.leaves()[..3].to_vec();
    let repeated_operation = changed[2].operations[0];
    changed[0].operations.push(repeated_operation);
    assert!(leaf::group_coverage(&graph, &changed).is_err());
    let mut changed = plan.leaves()[..3].to_vec();
    let fixed_byte = graph
        .bytes()
        .iter()
        .position(|node| node.source == Source::Fixed)
        .unwrap();
    changed[1].bytes.push(fixed_byte);
    changed[1].bytes.sort_unstable();
    assert!(leaf::group_coverage(&graph, &changed).is_err());
    assert!(compile_group(&plan, &graph, 0, &context, vec![]).is_err());
    assert!(compile_group(
        &plan,
        &graph,
        usize::MAX,
        &context,
        vec![LeafArtifact::FixedSources]
    )
    .is_err());
    assert!(compile_group(
        &plan,
        &graph,
        plan.leaves().len(),
        &context,
        vec![LeafArtifact::FixedSources]
    )
    .is_err());
    let group =
        compile_group(&plan, &graph, 0, &context, vec![LeafArtifact::FixedSources]).unwrap();
    group.evaluate().unwrap();
    assert_eq!(group.spec.count, 1);
    assert_eq!(group.spec.plan.label, plan.label());
}

#[test]
#[ignore = "actual algebra child proofs and two/three grouped recursive trace geometries; reserve8GiB"]
fn actual_two_and_three_component_graph_group_geometry() {
    use crate::{
        graph_proofs::{ComponentKind, GraphProofPlan, ResourceLimits},
        rust_verify::committed_backend::source_binding::RegisteredGraphShape,
    };
    let (graph, statement) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let factory = GraphProofPlan::new(&registered, &graph, ResourceLimits::default()).unwrap();
    let first = factory
        .batches()
        .windows(3)
        .position(|batch| {
            batch
                .iter()
                .all(|entry| *entry.kind() != ComponentKind::External)
        })
        .unwrap();
    let plan = Plan::from_trusted_graph(&graph, factory.operation_batches()).unwrap();
    let context = context(&plan, &graph, &statement);
    let artifacts: Vec<_> = (first..first + 3)
        .map(|index| factory.prove_batch(index).unwrap())
        .collect();
    for count in 1..=3 {
        let mut compiled = compile_group(
            &plan,
            &graph,
            first + 3,
            &context,
            artifacts[..count]
                .iter()
                .map(|artifact| artifact.as_leaf_artifact())
                .collect(),
        )
        .unwrap();
        compiled.evaluate().unwrap();
        eprintln!(
            "grouped graph native_children={count} schedule_first={} operations={:?} geometry={:?}",
            first + 3,
            factory.batches()[first..first + count]
                .iter()
                .map(|entry| entry.operation_indices())
                .collect::<Vec<_>>(),
            compiled.geometry().unwrap()
        );
        compiled.public[CONTEXT] += Val::ONE;
        assert!(compiled.evaluate().is_err());
        compiled.public[CONTEXT] -= Val::ONE;
        compiled.public[NODE_MANIFEST] += Val::ONE;
        assert!(compiled.evaluate().is_err());
        compiled.public[NODE_MANIFEST] -= Val::ONE;
        compiled.public[COUNT] += Val::ONE;
        assert!(compiled.evaluate().is_err());
    }
}
#[test]
fn full_registered_schedule_covers_noncontiguous_batches_all_sources_and_six_norms() {
    let (graph, _) = fixture();
    let mut batches = singles(&graph);
    let adds: Vec<_> = graph
        .operations()
        .iter()
        .enumerate()
        .filter_map(|(i, op)| {
            matches!(
                op,
                Operation::Add {
                    modulus: crate::rust_verify::Q,
                    ..
                }
            )
            .then_some(i)
        })
        .collect();
    let pair = vec![adds[0], adds[2]];
    assert!(pair[1] > pair[0] + 1);
    batches.retain(|v| v[0] != pair[0] && v[0] != pair[1]);
    batches.push(pair.clone());
    batches.sort_by_key(|v| v[0]);
    let plan = Plan::from_trusted_graph(&graph, batches).unwrap();
    assert!(plan.leaves().iter().any(|v| v.operation_indices() == pair));
    assert_eq!(plan.leaves()[2].operations.len(), 6);
    assert_eq!(
        plan.leaves()
            .iter()
            .map(|v| v.operations.len())
            .sum::<usize>(),
        FULL_OPERATIONS
    );
    assert_eq!(
        plan.leaves()
            .iter()
            .map(|v| v.polynomials.len())
            .sum::<usize>(),
        1770
    );
    assert_eq!(
        plan.leaves()
            .iter()
            .map(|v| v.bytes.len() - 2)
            .sum::<usize>(),
        6
    );
    let mut seen = vec![false; FULL_OPERATIONS];
    for leaf in plan.leaves() {
        for &index in &leaf.operations {
            assert!(!std::mem::replace(&mut seen[index], true));
        }
    }
    assert!(seen.into_iter().all(|v| v));
    for (index, node) in graph.bytes().iter().enumerate() {
        if matches!(node.source, Source::Context | Source::StatementSeed) {
            assert!(plan.leaves().iter().all(|v| v.bytes.contains(&index)));
        }
    }
}
#[test]
fn graph_registration_rejects_missing_duplicate_reordered_norm_and_wrong_family_batches() {
    let (graph, _) = fixture();
    let batches = singles(&graph);
    let mut missing = batches.clone();
    missing.pop();
    assert!(Plan::from_trusted_graph(&graph, missing).is_err());
    let mut duplicate = batches.clone();
    duplicate.insert(1, duplicate[0].clone());
    assert!(Plan::from_trusted_graph(&graph, duplicate).is_err());
    let mut reordered = batches.clone();
    reordered.swap(0, 1);
    assert!(Plan::from_trusted_graph(&graph, reordered).is_err());
    let norm = graph
        .operations()
        .iter()
        .position(|v| matches!(v, Operation::Norm { .. }))
        .unwrap();
    let mut with_norm = batches.clone();
    with_norm.push(vec![norm]);
    with_norm.sort_by_key(|v| v[0]);
    assert!(Plan::from_trusted_graph(&graph, with_norm).is_err());
    let mut invalid = batches.clone();
    invalid[0] = vec![FULL_OPERATIONS];
    assert!(Plan::from_trusted_graph(&graph, invalid).is_err());
    let a = graph
        .operations()
        .iter()
        .position(|v| matches!(v, Operation::Add { .. }))
        .unwrap();
    let n = graph
        .operations()
        .iter()
        .position(|v| matches!(v, Operation::Ntt { .. }))
        .unwrap();
    let mut mixed = batches;
    mixed.retain(|v| v[0] != a && v[0] != n);
    let mut pair = vec![a, n];
    pair.sort();
    mixed.push(pair);
    mixed.sort_by_key(|v| v[0]);
    assert!(Plan::from_trusted_graph(&graph, mixed).is_err());
}
#[test]
fn fixed_source_leaf_binds_full_manifest_context_registration_and_rejects_wrong_artifacts() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let node = compile_leaf(&plan, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    node.evaluate().unwrap();
    assert!(!node.spec.complete());
    assert!(compile_leaf(&plan, &graph, 1, &context, LeafArtifact::FixedSources).is_err());
    assert!(compile_leaf(&plan, &graph, 2, &context, LeafArtifact::Equality).is_err());
    let machine = MachineAir::from_shared_program(Arc::clone(&node.program));
    for index in [
        0,
        CONTEXT,
        CONTEXT + 7,
        NODE_MANIFEST,
        NODE_MANIFEST + 1,
        NODE_MANIFEST + 2,
        NODE_MANIFEST + 3,
        FIRST,
        COUNT,
        TOTAL,
        LEVEL,
    ] {
        let mut public = node.public.clone();
        public[index] += Val::ONE;
        assert!(
            machine.trace(&public, &node.witness).is_err(),
            "public {index}"
        );
    }
    let mut witness = node.witness.clone();
    witness[0] += Val::ONE;
    assert!(machine.trace(&node.public, &witness).is_err());
    assert!(node.prepare(0).is_err());
}
/// This checks interval/shared-root equations only. It constructs no NodeKey,
/// accepted child, or proof; production compile_merge always verifies children.
#[test]
fn graph_merge_constraints_and_registration_reject_coverage_and_root_substitution() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let left = plan.leaf_spec(0).unwrap();
    let right = plan.leaf_spec(1).unwrap();
    let spec = Spec::merge(&left, &right).unwrap();
    assert!(!spec.complete());
    assert!(Spec::merge(&left, &left).is_err());
    assert!(Spec::merge(&right, &left).is_err());
    assert!(Spec::merge(&left, &plan.leaf_spec(2).unwrap()).is_err());
    let foreign = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    assert!(Spec::merge(&left, &foreign.leaf_spec(1).unwrap()).is_err());
    let mut complete = left.clone();
    for ordinal in 1..plan.leaves().len() {
        complete = Spec::merge(&complete, &plan.leaf_spec(ordinal).unwrap()).unwrap();
    }
    assert!(complete.complete());
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    let outer = public_wires(&mut b, &spec).unwrap();
    let mut inputs = ProofInputs::default();
    let a = inputs.bases(&mut b, &header(&left, &context)).unwrap();
    let z = inputs.bases(&mut b, &header(&right, &context)).unwrap();
    tree::bind_merge(&mut b, &outer, &a, &z);
    let machine = MachineAir::new(b.finish(None).unwrap());
    let public = header(&spec, &context);
    machine.trace(&public, &inputs.values).unwrap();
    for offset in [0, PUBLIC_VALUES] {
        for index in [0, CONTEXT, STATEMENT, NODE_MANIFEST, FIRST, COUNT, TOTAL] {
            let mut bad = inputs.values.clone();
            bad[offset + index] += Val::ONE;
            assert!(
                machine.trace(&public, &bad).is_err(),
                "child {offset}, public {index}"
            );
        }
    }
}
/// Only the outer binding equations are isolated here. No child artifact, key,
/// native acceptance claim or substitute proof is created by this test.
#[test]
fn outer_graph_context_binding_rejects_every_statement_manifest_and_context_field() {
    let mut b = ProgramBuilder::new(16).unwrap();
    let expected = ContextWires {
        context: core::array::from_fn(|i| b.public(i).unwrap()),
        statement: core::array::from_fn(|i| b.public(8 + i).unwrap()),
        node_manifest: core::array::from_fn(|i| b.public(12 + i).unwrap()),
    };
    let public: Vec<_> = (0..16).map(|i| Val::from_usize(i + 5)).collect();
    let mut child = vec![Val::ZERO; PUBLIC_VALUES];
    child[CONTEXT..NODE_MANIFEST + 4].copy_from_slice(&public);
    let mut inputs = ProofInputs::default();
    let child_wires = inputs.bases(&mut b, &child).unwrap();
    tree::bind_context(&mut b, &child_wires, &expected);
    let machine = MachineAir::new(b.finish(None).unwrap());
    machine.trace(&public, &inputs.values).unwrap();
    for index in 0..16 {
        let mut changed = public.clone();
        changed[index] += Val::ONE;
        assert!(machine.trace(&changed, &inputs.values).is_err());
        let mut changed = inputs.values.clone();
        changed[CONTEXT + index] += Val::ONE;
        assert!(machine.trace(&public, &changed).is_err());
    }
}
#[test]
#[ignore = "actual full-inventory fixed-source graph leaf STARK; reserve a memory window"]
fn actual_fixed_source_graph_leaf_proof_is_not_complete_transaction_acceptance() {
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let node = compile_leaf(&plan, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    node.evaluate().unwrap();
    let geometry = node.geometry().unwrap();
    eprintln!(
        "graph fixed-source leaf: active={} height={} wires={} retained_lde_bytes={}",
        geometry.active_rows, geometry.padded_rows, geometry.wires, geometry.retained_lde_bytes
    );
    let prepared = node.prepare(8 * 1024 * 1024 * 1024).unwrap();
    let key = prepared.key();
    let mut proof = prepared.prove().unwrap();
    key.verify(&proof).unwrap();
    assert!(key.verify_complete(&proof, &context).is_err());
    let mut outer = ProgramBuilder::new(16).unwrap();
    let expected = ContextWires {
        context: core::array::from_fn(|i| outer.public(i).unwrap()),
        statement: core::array::from_fn(|i| outer.public(8 + i).unwrap()),
        node_manifest: core::array::from_fn(|i| outer.public(12 + i).unwrap()),
    };
    assert!(key
        .compile_complete(&mut outer, &mut ProofInputs::default(), &proof, &expected)
        .is_err());
    for index in [CONTEXT, STATEMENT, NODE_MANIFEST, FIRST, COUNT] {
        proof.public[index] += Val::ONE;
        assert!(key.verify(&proof).is_err());
        proof.public[index] -= Val::ONE;
    }
    assert!(compile_merge(&key, &key, [&proof, &proof]).is_err());
}
