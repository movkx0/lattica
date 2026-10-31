use super::*;
use super::super::tests::{context, fixture, singles};
use lattica_prover_p3::block_v2::machine::MachineAir;

#[test]
fn bounded_fixed_source_matches_existing_leaf_and_rejects_public_mutations() {
    let (graph, statement) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&tree, &graph, &statement);
    let plan = FixedSourceCompilePlan::new(&tree, &graph, &context).unwrap();
    let bounded = plan.compile().unwrap();
    let reference = compile_leaf(&tree, &graph, 0, &context, LeafArtifact::FixedSources).unwrap();
    assert_eq!(bounded.program.manifest_fields(), reference.program.manifest_fields());
    assert_eq!(bounded.public, reference.public);
    assert_eq!(bounded.witness, reference.witness);
    assert_eq!(bounded.witness.len(), 4 * (POLYNOMIALS + BYTE_NODES));
    assert_eq!(bounded.witness.capacity(), bounded.witness.len());
    assert!(bounded.program.construction_host_bytes() <= PROGRAM_BYTES);
    assert!(!bounded.spec.complete());
    bounded.evaluate().unwrap();
    let machine = MachineAir::from_shared_program(Arc::clone(&bounded.program));
    for index in [0, CONTEXT, CONTEXT + 7, NODE_MANIFEST, NODE_MANIFEST + 3,
        FIRST, COUNT, TOTAL, LEVEL]
    {
        let mut public = bounded.public.clone();
        public[index] += Val::ONE;
        assert!(machine.trace(&public, &bounded.witness).is_err(), "public {index}");
    }
    let mut witness = bounded.witness.clone();
    witness[0] += Val::ONE;
    assert!(machine.trace(&bounded.public, &witness).is_err());
}

#[test]
fn fixed_source_rejects_wrong_family_and_missing_or_reordered_coverage() {
    let (graph, statement) = fixture();
    let mut tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&tree, &graph, &statement);
    let inner = Arc::get_mut(&mut tree.0).unwrap();
    inner.leaves[0].kind = LeafKind::Statement;
    assert!(matches!(FixedSourceCompilePlan::new(&tree, &graph, &context), Err(FixedSourceFailure::Coverage)));
    let inner = Arc::get_mut(&mut tree.0).unwrap();
    inner.leaves[0].kind = LeafKind::FixedSources;
    let removed = inner.leaves[0].polynomials.pop().unwrap();
    assert!(matches!(FixedSourceCompilePlan::new(&tree, &graph, &context), Err(FixedSourceFailure::Coverage)));
    let inner = Arc::get_mut(&mut tree.0).unwrap();
    inner.leaves[0].polynomials.push(removed);
    inner.leaves[0].polynomials.swap(0, 1);
    assert!(matches!(FixedSourceCompilePlan::new(&tree, &graph, &context), Err(FixedSourceFailure::Coverage)));
}

#[test]
fn bounded_constructor_failure_does_not_produce_a_partial_node() {
    let (graph, statement) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&tree, &graph, &statement);
    let mut plan = FixedSourceCompilePlan::new(&tree, &graph, &context).unwrap();
    plan.census.construction.max_requested_program_bytes = 1;
    assert!(plan.compile().is_err());
    plan.census = FixedSourceCensus::from_graph(&graph).unwrap();
    plan.census.construction.max_input_values -= 1;
    assert!(plan.compile().is_err());
    // A later independent compile has no sticky failed builder or input owner.
    FixedSourceCompilePlan::new(&tree, &graph, &context).unwrap().compile().unwrap();
}

#[test]
fn constructor_census_has_additive_source_and_program_allowances() {
    let (graph, _) = fixture();
    let census = FixedSourceCensus::from_graph(&graph).unwrap();
    assert_eq!(census.construction.max_input_values, 7112);
    assert_eq!(census.input_bytes, 56_896);
    assert!(census.source_scratch_bytes > 4 * POLYNOMIALS * (D + 14) * size_of::<u64>());
    assert!(census.frame_bytes > size_of::<ProgramBuilder>());
    assert!(vector::<u64>(usize::MAX).is_err());
}
