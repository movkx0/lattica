//! CPU reference-fixture source admission, not complete-workflow qualification.
//!
//! This creates one CPU reference MatRiCT proof to obtain the real verifier graph.
//! It performs no GPU, native STARK, recursive, or final-aggregate proving. The
//! original reservations below cover the production source constructors; the
//! test fixture/harness must additionally run inside the coordinator's process
//! guard. Complete N3/N4 retained pools and enclosing state still need the owned
//! fresh workflow. All reported rows and counts are source scheduling bounds.
use super::*;
use crate::{
    execution::workflow_resources::PhaseFacts,
    graph_crypto::{OwnedAesRequestPlan, OwnedAesStepKind, Plan as CryptoPlan},
    graph_proofs::{GraphProofPlan, ResourceLimits},
    rust_verify::{committed_backend::{self, source_binding::RegisteredGraphShape}, Proof, Statement},
};
use p3_air::BaseAir;

const FIXTURE_CONTEXT: [u8; 32] = [73; 32];
const FIXTURE_SETUP: [u8; 32] = [91; 32];
const NATIVE_HOST: u64 = 24 << 30;
const REQUESTED_SHAKE_MAXIMUM: usize = 32;

fn inventory() -> (CryptoPlan, GraphContext) {
    inventory_at(4)
}

fn inventory_at(index: u64) -> (CryptoPlan, GraphContext) {
    let native = crate::native::generate_fixture_with_setup_seed(
        FIXTURE_CONTEXT, FIXTURE_SETUP, index,
        crate::native::FixtureAmounts { input: [19, 31], output: [23, 27] },
    ).unwrap();
    let graph = committed_backend::lower_unproved(
        FIXTURE_SETUP, &FIXTURE_CONTEXT,
        &Statement::decode(&native.statement).unwrap(),
        &Proof::decode(&native.proof).unwrap(),
    ).unwrap();
    let registered = RegisteredGraphShape::from_trusted_graph(&graph).unwrap();
    // Match SourcePlanningPlan::derive, not ResourceLimits/Policy defaults.
    let algebra = GraphProofPlan::new(&registered, &graph, ResourceLimits {
        max_batch_count: 64, max_ntt_batch_count: 32, max_mul_batch_count: 32,
        max_trace_cells: 1 << 27, max_estimated_prover_bytes: NATIVE_HOST,
    }).unwrap();
    let tree = crate::graph_tree::Plan::from_trusted_graph(&graph, algebra.operation_batches()).unwrap();
    let context = GraphContext {
        context: FIXTURE_CONTEXT,
        statement: crate::recursive_aggregation::LeafStatement::from_bytes(
            tree.label(), FIXTURE_CONTEXT, &native.statement,
        ).unwrap().digest.map(crate::graph_crypto::Val::from_u64),
        node_manifest: tree.node_manifest_hint(&graph).unwrap(),
    };
    let crypto = CryptoPlan::new(&tree, &graph, Policy {
        maximum_aes_blocks: 64, maximum_shake_permutations: REQUESTED_SHAKE_MAXIMUM,
        child_memory_budget_bytes: NATIVE_HOST, admission: Admission::Estimated,
    }).unwrap();
    (crypto, context)
}

#[cfg(feature = "full-workflow-experiment")]
mod identity_matrix;

fn effective_shake_maximum(crypto: &CryptoPlan) -> usize {
    use crate::shake_air::lane::{self, batch};
    // Request::new halves the configured ceiling when any native segment's
    // existing planning estimate exceeds the child budget. A full32 batch is
    // legal by row geometry, but its 518 * (4096 * 32) * 8 * 48 +512MiB
    // estimate exceeds24GiB by800MiB. Full16 is the first admitted candidate.
    let selected = REQUESTED_SHAKE_MAXIMUM / 2;
    let rejected = crate::graph_crypto::estimate(0, REQUESTED_SHAKE_MAXIMUM,
        batch::WIDTH, lane::HEIGHT * REQUESTED_SHAKE_MAXIMUM).unwrap();
    let admitted = crate::graph_crypto::estimate(0, selected,
        batch::WIDTH, lane::HEIGHT * selected).unwrap();
    assert_eq!(rejected.estimated_peak_bytes, 26_608_664_576);
    assert_eq!(admitted.estimated_peak_bytes, 13_572_767_744);
    assert!(rejected.estimated_peak_bytes > NATIVE_HOST);
    assert!(admitted.estimated_peak_bytes <= NATIVE_HOST);
    let mut reduced_requests = 0;
    for request in crypto.requests() {
        let RequestDescriptor::Shake(descriptor) = request.descriptor() else { continue; };
        let proposed = batch::ShakeBatchPartition::new(descriptor, REQUESTED_SHAKE_MAXIMUM).unwrap();
        let over_budget = proposed.segments().iter().any(|segment| {
            crate::graph_crypto::estimate(segment.first_permutation(), segment.permutations(),
                segment.width(), segment.height()).unwrap().estimated_peak_bytes > NATIVE_HOST
        });
        let expected = if over_budget {
            reduced_requests += 1;
            assert!(proposed.segments().iter().any(|segment| segment.permutations() == REQUESTED_SHAKE_MAXIMUM));
            batch::ShakeBatchPartition::new(descriptor, selected).unwrap()
        } else { proposed };
        assert_eq!(request.segments().len(), expected.segments().len());
        for (actual, segment) in request.segments().iter().zip(expected.segments()) {
            let expected = crate::graph_crypto::estimate(segment.first_permutation(), segment.permutations(),
                segment.width(), segment.height()).unwrap();
            assert_eq!((actual.first_unit, actual.units, actual.width, actual.height,
                actual.raw_trace_bytes, actual.estimated_peak_bytes),
                (expected.first_unit, expected.units, expected.width, expected.height,
                expected.raw_trace_bytes, expected.estimated_peak_bytes));
            assert!(actual.estimated_peak_bytes <= NATIVE_HOST);
        }
    }
    assert!(reduced_requests > 0, "actual fixture must exercise the32-to16 budget selection");
    eprintln!("crypto_source_policy requested_shake_maximum={} effective_shake_maximum={} child_budget={} rejected_full32_estimate={} admitted_full16_estimate={} reduced_requests={}",
        REQUESTED_SHAKE_MAXIMUM, selected, NATIVE_HOST, rejected.estimated_peak_bytes,
        admitted.estimated_peak_bytes, reduced_requests);
    selected
}

#[derive(Default)]
struct Census {
    requests: usize,
    native_segments: usize,
    recursive_nodes: usize,
    paired_leaves: usize,
    singleton_leaves: usize,
    maximum_native_units: usize,
    maximum_active_rows: usize,
    maximum_padded_rows: usize,
    maximum_wires: usize,
    maximum_inputs: usize,
    metadata_sum: u64,
    construction_scratch_peak: u64,
    phase_output_peak: u64,
    phase_scratch_peak: u64,
    independent_verifier_peak: u64,
}

impl Census {
    fn planning(&mut self, request: &Request, original: Requirements, scratch: Requirements) {
        self.requests += 1;
        self.native_segments += request.segments().len();
        self.maximum_native_units = self.maximum_native_units.max(request.maximum_segment_units());
        let original = original.total().unwrap();
        let scratch = scratch.total().unwrap();
        assert_eq!(original.device, 0);
        assert_eq!(scratch.device, 0);
        self.metadata_sum = self.metadata_sum.checked_add(original.host).unwrap();
        self.construction_scratch_peak = self.construction_scratch_peak.max(scratch.host);
    }

    fn node(&mut self, source: ComponentSourceFacts) {
        self.recursive_nodes += 1;
        self.maximum_active_rows = self.maximum_active_rows.max(source.maximum_active_rows);
        self.maximum_padded_rows = self.maximum_padded_rows.max(source.maximum_padded_rows);
        self.maximum_wires = self.maximum_wires.max(source.maximum_wires);
        self.maximum_inputs = self.maximum_inputs.max(source.maximum_input_values);
        assert_eq!(source.public_values, source::PUBLICS);
        assert!(source.maximum_active_rows <= source.maximum_padded_rows);
        assert!(source.maximum_padded_rows <= source::MAX_ROWS);
        assert!(source.maximum_wires <= lattica_prover_p3::block_v2::machine::program::MAX_WIRES);
        assert!(source.maximum_input_values <= source::INPUT_VALUES);
    }

    fn phase(&mut self, facts: PhaseFacts) {
        let output = facts.output.total().unwrap();
        let scratch = facts.scratch.total().unwrap();
        // These are caller-side declarations. Backend allowances are sealed
        // by the complete workflow and are deliberately not invented here.
        self.phase_output_peak = self.phase_output_peak.max(output.host);
        self.phase_scratch_peak = self.phase_scratch_peak.max(scratch.host);
        self.independent_verifier_peak = self.independent_verifier_peak.max(
            facts.scratch.get(Category::IndependentVerifier).host,
        );
    }

    fn report(&self, layout: &str, ledger: &Ledger) {
        assert!(self.requests > 0);
        assert!(self.independent_verifier_peak > 0);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        eprintln!(concat!("crypto_source_preflight layout={} requests={} native_segments={} ",
            "source_recursive_nodes={} paired_leaves={} singleton_leaves={} max_native_units={} ",
            "source_active_rows_max={} source_padded_rows_max={} source_wires_max={} source_inputs_max={} ",
            "metadata_sum={} construction_scratch_peak={} constructor_reserved_peak={} ",
            "caller_output_peak={} caller_scratch_peak={} independent_verifier_peak={} ",
            "complete_workflow_admitted=false gpu_dispatches=0"),
            layout, self.requests, self.native_segments, self.recursive_nodes,
            self.paired_leaves, self.singleton_leaves, self.maximum_native_units,
            self.maximum_active_rows, self.maximum_padded_rows, self.maximum_wires,
            self.maximum_inputs, self.metadata_sum, self.construction_scratch_peak,
            ledger.snapshot().peak.host, self.phase_output_peak, self.phase_scratch_peak,
            self.independent_verifier_peak);
    }
}

fn inspect_shake(crypto: &CryptoPlan, context: &GraphContext, layout: ShakeWrapperLayout) -> Census {
    let ledger = ledger();
    let mut census = Census::default();
    for (ordinal, request) in crypto.requests().iter().enumerate() {
        if !matches!(request.descriptor(), RequestDescriptor::Shake(_)) { continue; }
        eprintln!("crypto_source_preflight_begin layout={} ordinal={} operation={} subrequest={} segments={} max_units={}",
            layout.name(), ordinal, request.operation_index(), request.subrequest(),
            request.segments().len(), request.maximum_segment_units());
        let metadata = PairedRequestPlan::planning_requirements(request, layout).unwrap();
        let scratch_required = PairedRequestPlan::planning_scratch_requirements(request, layout).unwrap();
        census.planning(request, metadata, scratch_required);
        let scratch = ledger.admit_phase(scratch_required).unwrap();
        let original = ledger.admit_phase(metadata).unwrap();
        let plan = PairedRequestPlan::derive_pre_reserved(
            request, context.clone(), layout, original, &scratch, &ledger,
        ).unwrap_or_else(|error| panic!("{} ordinal {ordinal} source constructor refused: {error:?}", layout.name()));
        assert!(plan.belongs_to(&ledger));
        assert_eq!(plan.layout(), layout);
        let mut next_native = 0;
        for step in plan.ordered_steps() {
            if let RequestStepKind::Native { index } = step.kind {
                assert_eq!(index, next_native);
                next_native += 1;
            }
            census.phase(step.facts);
        }
        assert_eq!(next_native, request.segments().len());
        for node in plan.node_sources() {
            census.node(node.source);
            if let Some(span) = node.group {
                match span.segment_count {
                    2 => { assert_eq!(layout, ShakeWrapperLayout::PairedV1); census.paired_leaves += 1; }
                    1 => {
                        census.singleton_leaves += 1;
                        if layout == ShakeWrapperLayout::PairedV1 {
                            assert_eq!(span.first_segment + 1, request.segments().len());
                        }
                    }
                    other => panic!("invalid wrapper width {other}"),
                }
            }
        }
        let root = &plan.node_sources()[plan.root_id()];
        assert_eq!(root.span.first, 0);
        assert_eq!(usize::try_from(root.span.count).unwrap(), request.units());
        drop(plan);
        assert_eq!(ledger.snapshot().current, scratch_required.total().unwrap());
        drop(scratch);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    census.report(layout.name(), &ledger);
    census
}

fn inspect_aes(crypto: &CryptoPlan, context: &GraphContext) -> Census {
    let ledger = ledger();
    let mut census = Census::default();
    for (ordinal, request) in crypto.requests().iter().enumerate() {
        if !matches!(request.descriptor(), RequestDescriptor::Aes(_)) { continue; }
        eprintln!("crypto_source_preflight_begin layout=aes-unchanged ordinal={} operation={} subrequest={} segments={} max_units={}",
            ordinal, request.operation_index(), request.subrequest(),
            request.segments().len(), request.maximum_segment_units());
        let metadata = OwnedAesRequestPlan::planning_requirements(request).unwrap();
        let scratch_required = OwnedAesRequestPlan::planning_scratch_requirements(request).unwrap();
        census.planning(request, metadata, scratch_required);
        let scratch = ledger.admit_phase(scratch_required).unwrap();
        let original = ledger.admit_phase(metadata).unwrap();
        let plan = OwnedAesRequestPlan::derive_pre_reserved(
            request, context.clone(), original, &scratch, &ledger,
        ).unwrap_or_else(|error| panic!("AES ordinal {ordinal} source constructor refused: {error:?}"));
        assert!(plan.belongs_to(&ledger));
        let mut next_native = 0;
        for step in plan.ordered_steps() {
            if let OwnedAesStepKind::Native { index } = step.kind {
                assert_eq!(index, next_native);
                next_native += 1;
            }
            census.phase(step.facts);
        }
        assert_eq!(next_native, request.segments().len());
        for node in plan.node_sources() {
            census.node(node.source);
            census.singleton_leaves += usize::from(node.segment.is_some());
        }
        let root = &plan.node_sources()[plan.root_id()];
        assert_eq!(root.span.first, 0);
        assert_eq!(usize::try_from(root.span.count).unwrap(), request.units());
        drop(plan);
        assert_eq!(ledger.snapshot().current, scratch_required.total().unwrap());
        drop(scratch);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    census.report("aes-unchanged", &ledger);
    census
}

#[test]
#[ignore = "guarded CPU full-screen crypto source admission; no GPU or recursive proofs"]
fn full_workflow_crypto_source_metadata_preflight() {
    let (crypto, context) = inventory();
    let effective_shake_maximum = effective_shake_maximum(&crypto);
    let singleton = inspect_shake(&crypto, &context, ShakeWrapperLayout::Singleton);
    let paired = inspect_shake(&crypto, &context, ShakeWrapperLayout::PairedV1);
    let aes = inspect_aes(&crypto, &context);
    assert_eq!(singleton.maximum_native_units, effective_shake_maximum,
        "fixture must exercise the largest SHAKE segment admitted by the unchanged full-screen policy");
    assert_eq!(aes.maximum_native_units, 64, "fixture must exercise full-screen AES64");
    assert_eq!(singleton.requests, paired.requests);
    assert_eq!(singleton.native_segments, paired.native_segments);
    assert!(paired.paired_leaves > 0);
    assert!(paired.singleton_leaves > 0, "fixture must exercise odd tails");
    assert!(paired.recursive_nodes < singleton.recursive_nodes);
    assert_eq!(singleton.paired_leaves, 0);
    assert_eq!(singleton.singleton_leaves, singleton.native_segments);
    assert_eq!(crypto.requests().len(), singleton.requests + aes.requests);
}
