use super::*;
use crate::graph_tree::tests::{fixture, singles, context};
use lattica_prover_p3::block_v2::machine::MachineAir;

/// Exercise the actual pure equality compiler requirement query on the
/// full-screen CPU fixture. No prepared owner, proof receipt or permit is made.
#[test]
#[ignore = "guarded CPU graph budget census; no STARK or recursive proving"]
fn full_workflow_equality_compiler_census() {
    use crate::{graph_proofs::{GraphProofPlan, ResourceLimits},
        rust_verify::committed_backend::source_binding::RegisteredGraphShape};
    use super::super::super::source as shared;
    let (graph, _) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits {
        max_batch_count: 64, max_ntt_batch_count: 32, max_mul_batch_count: 32,
        max_trace_cells: 1 << 27, max_estimated_prover_bytes: 24 << 30,
    }).unwrap();
    let tree = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let mut first = None;
    let mut byte_leaves = 0usize;
    let mut signed_leaves = 0usize;
    for (ordinal, leaf) in tree.leaves().iter().enumerate() {
        if leaf.kind() != &LeafKind::Operations(OperationFamily::Equality) { continue; }
        let operation = validate_leaf(&tree, &graph, ordinal).unwrap();
        match graph.operations()[operation] {
            Operation::EqualBytes { .. } => byte_leaves += 1,
            Operation::EqualSigned { .. } => signed_leaves += 1,
            _ => panic!("validated equality operation required"),
        }
        first.get_or_insert(ordinal);
    }
    assert!(byte_leaves + signed_leaves > 0, "full-screen fixture must contain equality leaves");
    let census = FixedSourceCensus::from_graph(&graph).unwrap();
    let own_frames = frames().unwrap();
    let full = [census.source_scratch_bytes, census.frame_bytes, own_frames]
        .into_iter().try_fold(0, add).unwrap();
    let cap = shared::AUXILIARY_BYTES;
    let compiler_inputs = add(census.input_bytes, bytes::<Val>(2 * PUBLIC_VALUES).unwrap()).unwrap();
    let compiled = combine(&[
        requirement(Category::SymbolicCompiler, add(census.construction.max_requested_program_bytes,
            bytes::<OwnedGraphCompiled<'static>>(8).unwrap()).unwrap()).unwrap(),
        requirement(Category::CompilerInputs, compiler_inputs).unwrap(),
    ]).unwrap();
    let actual = compiler_requirements(census);
    match &actual {
        Ok((got_compiled, scratch)) => {
            assert!(full <= cap);
            assert_eq!(*got_compiled, compiled);
            assert_eq!(*scratch, requirement(Category::PhaseScratch, full).unwrap());
        }
        Err(cause) => {
            assert!(full > cap);
            assert_eq!(*cause, GraphParentFailure::Capacity);
        }
    }
    eprintln!(concat!("equality_compiler_census first_leaf={} byte_leaves={} signed_leaves={} graph_leaves={} ",
        "has_verifier_core=false core_auxiliary=0 fixed_source={} fixed_frames={} own_frames={} ",
        "full_auxiliary={} auxiliary_cap={} core_refusal=false combined_refusal={} compiler_ok={} compiler_inputs={} ",
        "program_limit={} wire_limit={} input_limit={} row_limit={} ",
        "native_fixture_proof=true stark_proof_produced=false recursive_proof_produced=false ",
        "compiler_requirement_called=true complete_admission=false"),
        first.unwrap(), byte_leaves, signed_leaves, tree.leaves().len(), census.source_scratch_bytes,
        census.frame_bytes, own_frames, full, cap, full > cap, actual.is_ok(), compiler_inputs,
        census.construction.max_requested_program_bytes, census.construction.max_wires,
        census.construction.max_input_values, shared::MAX_ROWS);
}

fn ordinal(tree: &Plan, graph: &UnprovedRelationGraph, signed: bool) -> usize {
    tree.leaves().iter().position(|leaf| {
        leaf.kind() == &LeafKind::Operations(OperationFamily::Equality)
            && matches!(graph.operations()[leaf.operation_indices()[0]],
                Operation::EqualSigned { .. }) == signed
    }).unwrap()
}
#[test]
fn owned_equality_matches_both_unchanged_reference_relations_and_rejects_mutations() {
    let (graph, statement) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&tree, &graph, &statement);
    let census = FixedSourceCensus::from_graph(&graph).unwrap();
    for signed in [false, true] {
        let ordinal = ordinal(&tree, &graph, signed);
        let source = derive(&tree, &graph, &context, ordinal, [17; 32], crate::graph_proofs::compiled_source_fingerprint()).unwrap();
        let compiled = super::super::operations::compile(source, &graph, census).unwrap();
        let reference = crate::graph_tree::compile_leaf(&tree, &graph, ordinal, &context,
            crate::graph_tree::LeafArtifact::Equality).unwrap();
        assert_eq!(compiled.node.program.manifest_fields(), reference.program.manifest_fields());
        assert_eq!(compiled.node.public, reference.public);
        assert_eq!(compiled.node.witness, reference.witness);
        assert_eq!(compiled.node.witness.capacity(), census.construction.max_input_values);
        assert_eq!(compiled.node.witness.len(), 4 * (1770 + 8));
        source.check_compiled(&compiled.node).unwrap();
        assert!(!compiled.node.spec.complete());
        compiled.node.evaluate().unwrap();
        let machine = MachineAir::from_shared_program(Arc::clone(&compiled.node.program));
        for i in [0, CONTEXT, NODE_MANIFEST, FIRST, COUNT, TOTAL, LEVEL] {
            let mut public = compiled.node.public.clone(); public[i] += Val::ONE;
            assert!(machine.trace(&public, &compiled.node.witness).is_err(), "public {i}");
        }
        let mut witness = compiled.node.witness.clone(); witness[0] += Val::ONE;
        assert!(machine.trace(&compiled.node.public, &witness).is_err());
    }
}
#[test]
fn owned_equality_rejects_wrong_missing_reordered_and_extra_source_coverage() {
    let (graph, _) = fixture();
    let mut tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let ordinal = ordinal(&tree, &graph, true);
    let operation = validate_leaf(&tree, &graph, ordinal).unwrap();
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].kind = LeafKind::FixedSources;
    assert!(validate_leaf(&tree, &graph, ordinal).is_err());
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].kind = LeafKind::Operations(OperationFamily::Equality);
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.swap(0, 1);
    assert!(validate_leaf(&tree, &graph, ordinal).is_err());
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.swap(0, 1);
    let value = Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.pop().unwrap();
    assert!(validate_leaf(&tree, &graph, ordinal).is_err());
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.push(value);
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].polynomials.push(0);
    assert!(validate_leaf(&tree, &graph, ordinal).is_err());
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].polynomials.clear();
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].operations.push(operation);
    assert!(validate_leaf(&tree, &graph, ordinal).is_err());
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].operations.pop();
    assert_eq!(validate_leaf(&tree, &graph, ordinal).unwrap(), operation);
}
#[test]
fn owned_equality_refuses_incomplete_compiler_and_input_budgets() {
    let (graph, statement) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let context = context(&tree, &graph, &statement);
    let source = derive(&tree, &graph, &context, ordinal(&tree, &graph, false), [17; 32],
        crate::graph_proofs::compiled_source_fingerprint()).unwrap();
    let mut census = FixedSourceCensus::from_graph(&graph).unwrap();
    census.construction.max_requested_program_bytes = 1;
    assert!(super::super::operations::compile(source, &graph, census).is_err());
    census = FixedSourceCensus::from_graph(&graph).unwrap();
    census.construction.max_input_values -= 1;
    assert!(super::super::operations::compile(source, &graph, census).is_err());
    census = FixedSourceCensus::from_graph(&graph).unwrap();
    let compiled = super::super::operations::compile(source, &graph, census).unwrap();
    compiled.node.evaluate().unwrap();
}
