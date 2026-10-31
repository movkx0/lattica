use super::*;
use crate::rust_verify::committed_backend::{BytesId, NEXT_GRAPH};
use std::sync::atomic::Ordering;

// This storage-only fixture has the fixed nested inventory checked here. It is
// not a valid native relation or a source/dispatch authority. No GPU work runs.
pub(super) fn graph() -> UnprovedRelationGraph {
    let owner = NEXT_GRAPH.fetch_add(1, Ordering::Relaxed);
    let limits = Ceilings::fixed();
    let id = PolyId { owner, index: 0 };
    let bytes = BytesId { owner, index: 0 };
    let mut canonical = Vec::with_capacity(5); canonical.push(id);
    let mut signed = Vec::with_capacity(7); signed.push(id);
    UnprovedRelationGraph { owner, setup_seed: [7; 32],
        polynomials: Vec::with_capacity(2), bytes: Vec::with_capacity(3),
        expressions: Vec::with_capacity(5), operations: vec![
            Operation::CanonicalMap { modulus: 17, inputs: canonical,
                expressions: [0; crate::rust_verify::D], output: id },
            Operation::SignedMap { bound: 8, inputs: signed,
                expressions: [0; crate::rust_verify::D], output: id },
            Operation::HashAlpha { parts: vec![TranscriptPart::Polynomial(id); limits.alpha_parts], output: bytes },
            Operation::HashX { parts: vec![TranscriptPart::Polynomial(id); limits.x_parts], output: id },
            Operation::Norm { inputs: vec![id; limits.norm_inputs], maximum: 1 },
        ] }
}

#[test]
fn checked_owner_charges_spare_main_and_every_nested_vector_capacity() {
    let graph = graph();
    let mut ids = 0; let mut parts = 0;
    for operation in &graph.operations {
        match operation {
            Operation::CanonicalMap { inputs, .. } | Operation::SignedMap { inputs, .. }
                | Operation::Norm { inputs, .. } => ids += inputs.capacity(),
            Operation::HashAlpha { parts: values, .. } | Operation::HashX { parts: values, .. } => parts += values.capacity(),
            _ => unreachable!("fixture inventory"),
        }
    }
    let expected = size_of::<UnprovedRelationGraph>()
        + graph.polynomials.capacity() * size_of::<PolynomialNode>()
        + graph.bytes.capacity() * size_of::<BytesNode>()
        + graph.expressions.capacity() * size_of::<Expression>()
        + graph.operations.capacity() * size_of::<Operation>()
        + ids * size_of::<PolyId>() + parts * size_of::<TranscriptPart>();
    let owner = InitialSourceFootprint::fixed().unwrap().check_graph(graph).unwrap();
    assert_eq!(owner.retained_host_bytes(), expected);
    assert!(owner.retained_host_bytes() < owner.initial_host_bytes());
    assert_eq!(owner.graph().polynomials().len(), 0);
    assert!(expected > size_of::<UnprovedRelationGraph>());
    let identity = owner.graph.owner;
    let pointer = owner.graph.polynomials.as_ptr();
    let moved = owner;
    assert_eq!(moved.graph.owner, identity);
    assert_eq!(moved.graph.polynomials.as_ptr(), pointer);
    assert_eq!(moved.retained_host_bytes(), expected);
}

#[test]
fn exact_capacity_boundary_accepts_and_one_byte_below_refuses() {
    let mut footprint = InitialSourceFootprint::fixed().unwrap();
    let actual = footprint.check_graph(graph()).unwrap().retained_host_bytes();
    footprint.graph_retained = actual - size_of::<UnprovedRelationGraph>();
    let exact = footprint.check_graph(graph()).unwrap();
    assert_eq!(exact.initial_host_bytes(), exact.retained_host_bytes());
    footprint.graph_retained -= 1;
    assert!(footprint.check_graph(graph()).is_err());
}

#[test]
fn invalid_capacity_or_nested_inventory_cannot_issue_success_provenance() {
    let footprint = InitialSourceFootprint::fixed().unwrap();
    let mut invalid = graph();
    invalid.operations.retain(|operation| !matches!(operation, Operation::HashAlpha { .. }));
    assert!(footprint.check_graph(invalid).is_err());
    let mut invalid = graph();
    for operation in &mut invalid.operations {
        if let Operation::Norm { inputs, .. } = operation {
            let mut oversized = Vec::with_capacity(inputs.len() * 2 + 1);
            oversized.extend_from_slice(inputs);
            *inputs = oversized;
        }
    }
    assert!(footprint.check_graph(invalid).is_err());
    let mut smaller_ceiling = footprint;
    smaller_ceiling.ceiling.expressions = 0;
    assert!(smaller_ceiling.check_graph(graph()).is_err());
}

#[cfg(feature = "native-matrict")]
#[test]
#[ignore = "genuine full CPU native graph capacity observation; coordinator serialized memory window"]
fn genuine_native_cpu_graph_capacity_observation() {
    use crate::rust_verify::committed_backend::{lower_unproved, tests::fixture};
    let (statement, proof, _encoded) = fixture();
    // This validates the real n10 packet dimensions; no synthetic graph or
    // workflow source identity is substituted for the genuine native fixture.
    InitialSourceFootprint::decoded_owner_bytes(&statement, &proof).unwrap();
    let graph = lower_unproved([29; 32], &[71; 32], &statement, &proof).unwrap();
    let counts = [graph.polynomials.len(), graph.bytes.len(), graph.expressions.len(), graph.operations.len()];
    let graph = InitialSourceFootprint::fixed().unwrap().check_graph(graph).unwrap();
    let initial = graph.initial_host_bytes();
    let retained = graph.retained_host_bytes();
    assert!(retained <= initial);
    // Bounded observation only: CPU fixture capacities are not admission credit
    // for a GPU source, proof qualification, or complete-workflow performance.
    eprintln!("graph_capacity_observation scope=cpu-native-fixture initial_host_bytes={initial} retained_host_bytes={retained} surplus_host_bytes={} polynomials={} byte_nodes={} expressions={} operations={}",
        initial - retained, counts[0], counts[1], counts[2], counts[3]);
    #[cfg(all(feature = "full-workflow-experiment", target_os = "linux", target_arch = "x86_64"))]
    {
        use crate::{execution::workflow_resources::{SourcePreparationAccess, SourceRetained,
            source_retained_overhead_bytes}, spend_pipeline::full_workflow::PreparedGraphSources};
        let completion = SourcePreparationAccess::completion_retained_bytes().unwrap();
        let retention = SourcePreparationAccess::graph_retention_frame_bytes().unwrap();
        let overhead = usize::try_from(source_retained_overhead_bytes().unwrap()).unwrap();
        let prepared = size_of::<PreparedGraphSources>();
        let metadata = overhead.checked_add(prepared).unwrap().checked_add(completion).unwrap()
            .checked_add(retention).unwrap();
        eprintln!("graph_capacity_layout scope=cpu-native-fixture completion_retained_bytes={completion} graph_retention_frame_bytes={retention} checked_initial_graph_bytes={} prepared_graph_sources_bytes={prepared} source_retained_owner_bytes={} source_retained_overhead_bytes={overhead} initial_output_registered_metadata_bytes={metadata}",
            size_of::<CheckedInitialGraph>(), size_of::<SourceRetained<PreparedGraphSources>>());
        #[cfg(not(debug_assertions))]
        {
            use crate::{execution::workflow_resources::{SourceFailure, SourcePhaseFailure},
                spend_pipeline::full_workflow::{bootstrap_layers::GraphSourceResult,
                    fresh_generation::case_lifetime::{CaseRetirementState, CaseOwnerSlot, FixedCaseOwnerSlots}}};
            type GraphSlots3 = FixedCaseOwnerSlots<'static, GraphSourceResult, 3>;
            type GraphSlots4 = FixedCaseOwnerSlots<'static, GraphSourceResult, 4>;
            let slot = CaseRetirementState::owner_slot_requirements::<GraphSourceResult>().unwrap().total().unwrap();
            let array3 = CaseRetirementState::owner_slot_requirements::<GraphSlots3>().unwrap().total().unwrap();
            let array4 = CaseRetirementState::owner_slot_requirements::<GraphSlots4>().unwrap().total().unwrap();
            assert_eq!((slot.device, array3.device, array4.device), (0, 0, 0));
            eprintln!("graph_capacity_case_layout scope=cpu-native-fixture source_failure_bytes={} source_phase_failure_bytes={} graph_source_result_bytes={} graph_source_slot_bytes={} graph_source_slot_host_bytes={} graph_slots_n3_bytes={} graph_slots_n3_slot_host_bytes={} graph_slots_n4_bytes={} graph_slots_n4_slot_host_bytes={}",
                size_of::<SourceFailure<PreparedGraphSources>>(), size_of::<SourcePhaseFailure<PreparedGraphSources>>(),
                size_of::<GraphSourceResult>(), size_of::<CaseOwnerSlot<'static, GraphSourceResult>>(), slot.host,
                size_of::<GraphSlots3>(), array3.host, size_of::<GraphSlots4>(), array4.host);
        }
    }
}
