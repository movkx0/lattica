use super::*;

fn small_node(spec: Spec, context: &GraphContext) -> ProvenNode {
    // Isolate the recursive coverage/consumer bindings. Actual native graph
    // predicates are exercised by the separately guarded GPU subtree profile.
    let public = header(&spec, context);
    let mut b = ProgramBuilder::new(PUBLIC_VALUES).unwrap();
    public_wires(&mut b, &spec).unwrap();
    let program = Arc::new(b.finish(None).unwrap());
    let owner = RecursionTemplate::new(program, [2; 32])
        .unwrap()
        .prepare_cpu_reference()
        .unwrap();
    let proof = owner.prove_cpu_reference(&public, &[]).unwrap();
    ProvenNode {
        spec,
        public,
        key: owner.verifier(),
        proof,
    }
}
fn limits() -> ConstructionLimits {
    ConstructionLimits {
        // Match the expanded N4 compiler used for eight-child parents.
        max_requested_program_bytes: 6 << 30,
        max_wires: 1 << 26,
        max_input_values: 8 << 20,
    }
}
#[test]
fn typed_graph_parent_binds_plan_order_coverage_and_shared_roots() {
    use crate::graph_tree::tests::{context, fixture, singles};
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let mut nodes = (0..8)
        .map(|i| small_node(plan.leaf_spec(i).unwrap(), &context))
        .collect::<Vec<_>>();
    let children = nodes.iter().collect::<Vec<_>>();
    let merged = compile_merge(&children, limits()).unwrap();
    merged.evaluate().unwrap();
    assert_eq!(
        (merged.spec.first, merged.spec.count, merged.spec.level),
        (0, 8, 1)
    );
    assert!(nodes[0].verify_complete(&context).is_err());
    assert!(compile_merge(&[children[1], children[0], children[2]], limits()).is_err());
    assert!(compile_merge(&[children[0], children[0]], limits()).is_err());
    assert!(compile_merge(&[children[0], children[2]], limits()).is_err());
    let too_many = nodes.iter().chain(nodes[..1].iter()).collect::<Vec<_>>();
    assert!(compile_merge(&too_many, limits()).is_err());
    drop(too_many);
    let foreign = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let alien = small_node(foreign.leaf_spec(1).unwrap(), &context);
    assert!(nodes[0].verify(&foreign, &context).is_err());
    assert!(compile_merge(&[children[0], &alien], limits()).is_err());
    drop(children);
    for index in [CONTEXT, STATEMENT, NODE_MANIFEST] {
        let mut different = context.clone();
        match index {
            CONTEXT => different.context[0] ^= 1,
            STATEMENT => different.statement[0] += Val::ONE,
            _ => different.node_manifest[0] += Val::ONE,
        }
        // The last child must be constrained even at maximum fan-in.
        nodes[7] = small_node(plan.leaf_spec(7).unwrap(), &different);
        let compiled = compile_merge(&nodes.iter().collect::<Vec<_>>(), limits()).unwrap();
        assert!(compiled.evaluate().is_err());
    }
}
#[test]
fn typed_complete_graph_constrains_ordered_aggregate_consumer() {
    use crate::graph_tree::tests::{context, fixture, singles};
    let (graph, statement) = fixture();
    let plan = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&plan, &graph, &statement);
    let node = small_node(
        Spec {
            plan: Arc::clone(&plan.0),
            first: 0,
            count: plan.leaves().len() as u32,
            level: 1,
        },
        &context,
    );
    node.verify_complete(&context).unwrap();
    assert!(node.rejects_altered_public());
    let mut b = ProgramBuilder::new_with_construction_limits(16, limits()).unwrap();
    let expected = ContextWires {
        context: core::array::from_fn(|i| b.public(i).unwrap()),
        statement: core::array::from_fn(|i| b.public(8 + i).unwrap()),
        node_manifest: core::array::from_fn(|i| b.public(12 + i).unwrap()),
    };
    let mut inputs = ProofInputs::default();
    node.compile_complete(&mut b, &mut inputs, &expected)
        .unwrap();
    let air = MachineAir::new(b.finish(None).unwrap());
    let public = node.public[CONTEXT..NODE_MANIFEST + 4].to_vec();
    air.trace(&public, &inputs.values).unwrap();
    for index in 0..16 {
        let mut wrong = public.clone();
        wrong[index] += Val::ONE;
        assert!(air.trace(&wrong, &inputs.values).is_err());
    }
    let batch = crate::ordered_aggregation::Plan::new(plan.label(), context.context, 2).unwrap();
    batch.typed_graph_child(0, &node, &context).unwrap();
    let compiled = crate::ordered_aggregation::compile_merge([
        batch.typed_graph_child(0, &node, &context).unwrap().into(),
        batch.typed_graph_child(1, &node, &context).unwrap().into(),
    ])
    .unwrap();
    compiled.evaluate().unwrap();
    let wrong = crate::ordered_aggregation::Plan::new([0; 32], context.context, 2).unwrap();
    assert!(wrong.typed_graph_child(0, &node, &context).is_err());
    assert!(batch.typed_graph_child(2, &node, &context).is_err());
    let partial = small_node(plan.leaf_spec(0).unwrap(), &context);
    assert!(batch.typed_graph_child(0, &partial, &context).is_err());
}
