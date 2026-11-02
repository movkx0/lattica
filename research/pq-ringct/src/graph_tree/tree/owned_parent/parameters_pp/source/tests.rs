use super::*;
use crate::graph_tree::tests::{fixture, singles};

#[test]
#[ignore = "guarded CPU source constructor regression; no recursive proofs"]
fn parameters_pp_compiler_scratch_uses_the_authenticated_child_height() {
    use crate::{graph_proofs::{GraphProofPlan, ResourceLimits},
        rust_verify::committed_backend::source_binding::RegisteredGraphShape,
        execution::retained_resources::WorkerAllowance,
        graph_crypto::{Admission, ShakeWrapperLayout}};
    let (graph, statement) = fixture();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits {
        max_batch_count: 64, max_ntt_batch_count: 32, max_mul_batch_count: 32,
        max_trace_cells: 1 << 27, max_estimated_prover_bytes: 24 << 30,
    }).unwrap();
    let tree = Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = crate::graph_tree::tests::context(&tree, &graph, &statement);
    let crypto = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy {
        maximum_aes_blocks: 64, maximum_shake_permutations: 32,
        child_memory_budget_bytes: 24 << 30, admission: Admission::Estimated,
    }).unwrap();
    let ordinal = pp_ordinal(&tree);
    let operation = tree.leaves()[ordinal].operation_indices()[0];
    let request = crypto.requests().iter().find(|r| r.operation_index() == operation).unwrap();
    validate_request_leaf(&tree, &graph, &crypto, request, ordinal).unwrap();
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let layout = ShakeWrapperLayout::PairedV1;
    let original = ledger.admit_phase(PairedRequestPlan::planning_requirements(request, layout).unwrap()).unwrap();
    let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(request, layout).unwrap()).unwrap();
    let request_plan = PairedRequestPlan::derive_pre_reserved(request, context, layout, original, &scratch, &ledger).unwrap();
    let root = request_plan.root_source();
    eprintln!("parameters_pp_child_bound height={} publics={}", root.maximum_padded_rows, root.public_values);
    assert_eq!(root.public_values, PUBLICS);
    assert!(root.maximum_padded_rows < super::super::super::source::MAX_ROWS);
    let (_, actual) = compiler_requirements_for_graph(&graph, root.maximum_padded_rows).unwrap();
    let actual = actual.total().unwrap().host;
    let cap = super::super::super::source::AUXILIARY_BYTES as u64;
    assert!(actual <= cap);
    assert!(matches!(compiler_requirements_for_graph(&graph, super::super::super::source::MAX_ROWS),
        Err(GraphParentFailure::Capacity)));
    eprintln!("parameters_pp_actual_compiler_scratch bytes={actual} cap={cap}");
    drop(request_plan);
    drop(scratch);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

/// Source-pinned budget diagnostic, not complete constructor admission. The
/// real compiler_requirements takes a genuine PreparedWorkflowSources owner;
/// this probe mirrors only its pure graph census without fabricating that owner.
#[test]
#[ignore = "guarded CPU graph budget census; no STARK or recursive proving"]
fn full_workflow_parameters_pp_compiler_census() {
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
    let mut leaves = 0usize;
    for (ordinal, leaf) in tree.leaves().iter().enumerate() {
        if leaf.kind() != &LeafKind::Operations(OperationFamily::ParametersPp) { continue; }
        let [operation] = leaf.operation_indices() else { panic!("one ParametersPp operation required"); };
        assert!(matches!(graph.operations()[*operation], Operation::ParametersPp { .. }));
        first.get_or_insert(ordinal);
        leaves += 1;
    }
    assert!(leaves > 0, "full-screen fixture must contain ParametersPp leaves");
    let construction = shared::construction();
    let shape = child_shape(shared::MAX_ROWS).unwrap();
    let planning_storage = PlanningStorage::for_children(0, &[shape], construction).unwrap();
    let storage = PlanningStorage::for_children(PUBLIC_VALUES, &[shape], construction).unwrap();
    let fixed = FixedSourceCensus::from_graph(&graph).unwrap();
    let own_frames = frames().unwrap();
    let coverage = add(add(graph.polynomials().len(), graph.bytes().len()).unwrap(), graph.operations().len()).unwrap();
    let group = add(mul(coverage, add(2 * size_of::<bool>(), 4 * size_of::<usize>()).unwrap()).unwrap(),
        bytes::<Vec<usize>>(16).unwrap()).unwrap();
    let byte_count = mul(4, add(PREFIX, 64).unwrap()).unwrap();
    let dynamic = [group, bytes::<lattica_prover_p3::block_v2::machine::pq_bytes::Byte>(byte_count).unwrap(),
        bytes::<u8>(byte_count).unwrap(), bytes::<Wire>(byte_count).unwrap(),
        bytes::<Vec<crate::graph_tree::LeafArtifact<'static>>>(8).unwrap(),
        bytes::<crate::graph_tree::LeafArtifact<'static>>(2).unwrap(), own_frames]
        .into_iter().try_fold(0, add).unwrap();
    let full = [storage.auxiliary_peak_bytes, fixed.source_scratch_bytes, fixed.frame_bytes, dynamic]
        .into_iter().try_fold(0, add).unwrap();
    let cap = shared::AUXILIARY_BYTES;
    let planning_bytes = add(shared::PROGRAM_BYTES, add(planning_storage.auxiliary_peak_bytes, own_frames).unwrap()).unwrap();
    let planning = planning_scratch_requirements();
    match &planning {
        Ok(required) => {
            assert!(planning_storage.auxiliary_peak_bytes <= cap);
            assert_eq!(*required, requirement(Category::PhaseScratch, planning_bytes).unwrap());
        }
        Err(cause) => {
            assert!(planning_storage.auxiliary_peak_bytes > cap);
            assert_eq!(*cause, GraphParentFailure::Capacity);
        }
    }
    let compiler_inputs = add(storage.input_backing_bytes, bytes::<Val>(2 * PUBLIC_VALUES).unwrap()).unwrap();
    eprintln!(concat!("parameters_pp_compiler_census first_leaf={} leaves={} graph_leaves={} ",
        "planning_core={} compiler_core={} fixed_source={} fixed_frames={} own_frames={} ",
        "group={} byte_count={} dynamic={} full_auxiliary={} auxiliary_cap={} ",
        "core_refusal={} combined_refusal={} planning_ok={} planning_original={} compiler_inputs={} ",
        "program_limit={} wire_limit={} input_limit={} row_limit={} ",
        "native_fixture_proof=true stark_proof_produced=false recursive_proof_produced=false ",
        "compiler_requirement_called=false complete_admission=false"),
        first.unwrap(), leaves, tree.leaves().len(), planning_storage.auxiliary_peak_bytes,
        storage.auxiliary_peak_bytes, fixed.source_scratch_bytes, fixed.frame_bytes, own_frames,
        group, byte_count, dynamic, full, cap, storage.auxiliary_peak_bytes > cap, full > cap,
        planning.is_ok(), planning_bytes, compiler_inputs, construction.max_requested_program_bytes,
        construction.max_wires, construction.max_input_values, shared::MAX_ROWS);
}

fn pp_ordinal(tree: &Plan) -> usize {
    tree.leaves().iter().position(|leaf|
        leaf.kind() == &LeafKind::Operations(OperationFamily::ParametersPp)).unwrap()
}
#[test]
fn parameters_pp_requires_the_original_request_owner_and_matching_operation() {
    let (graph, _) = fixture();
    let tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let crypto = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy::default()).unwrap();
    let ordinal = pp_ordinal(&tree);
    let operation = tree.leaves()[ordinal].operation_indices()[0];
    let request = crypto.requests().iter().find(|r| r.operation_index() == operation).unwrap();
    validate_request_leaf(&tree, &graph, &crypto, request, ordinal).unwrap();
    let foreign = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy::default()).unwrap();
    let same_value = foreign.requests().iter().find(|r| r.operation_index() == operation).unwrap();
    assert_eq!(same_value.descriptor(), request.descriptor());
    assert!(matches!(validate_request_leaf(&tree, &graph, &crypto, same_value, ordinal),
        Err(GraphParentFailure::Coverage)));
    let wrong = crypto.requests().iter().find(|r| r.operation_index() != operation).unwrap();
    assert!(matches!(validate_request_leaf(&tree, &graph, &crypto, wrong, ordinal),
        Err(GraphParentFailure::Coverage)));
}
#[test]
fn parameters_pp_rejects_missing_reordered_and_extra_coverage_before_compilation() {
    let (graph, _) = fixture();
    let mut tree = Plan::from_trusted_graph(&graph, singles(&graph)).unwrap();
    let crypto = crate::graph_crypto::Plan::new(&tree, &graph, crate::graph_crypto::Policy::default()).unwrap();
    let ordinal = pp_ordinal(&tree);
    let operation = tree.leaves()[ordinal].operation_indices()[0];
    let request = crypto.requests().iter().find(|r| r.operation_index() == operation).unwrap();
    let rejected = |tree: &Plan| matches!(validate_request_leaf(tree, &graph, &crypto, request, ordinal),
        Err(GraphParentFailure::Coverage));
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].kind = LeafKind::Operations(OperationFamily::SampleG);
    assert!(rejected(&tree));
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].kind = LeafKind::Operations(OperationFamily::ParametersPp);
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.swap(0, 1);
    assert!(rejected(&tree));
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.swap(0, 1);
    let last = Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.pop().unwrap();
    assert!(rejected(&tree));
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].bytes.push(last);
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].polynomials.push(0);
    assert!(rejected(&tree));
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].polynomials.clear();
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].operations.push(operation);
    assert!(rejected(&tree));
    Arc::get_mut(&mut tree.0).unwrap().leaves[ordinal].operations.pop();
    validate_request_leaf(&tree, &graph, &crypto, request, ordinal).unwrap();
}
