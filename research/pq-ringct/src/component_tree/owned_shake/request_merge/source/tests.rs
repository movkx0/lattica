use super::*;
use crate::{
    component_tree::{owned_shake::GroupCompilePlan, EndpointContext, Val},
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Admission, Policy, ReservedShakeRequest, ShakeRequestPlan, ShakeWrapperLayout},
};
use p3_field::PrimeCharacteristicRing;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    })
}
fn context() -> EndpointContext {
    EndpointContext {
        context: [11; 32],
        statement: [Val::from_u64(13); 4],
        input: [Val::from_u64(17); 4],
        output: [Val::from_u64(19); 4],
    }
}
fn owner(ledger: &Ledger) -> ReservedShakeRequest {
    let input = [23; 16_416];
    let plan = ShakeRequestPlan::new_active_opt_validate_v1(
        [7; 32],
        9,
        0,
        &input,
        137,
        Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}
fn request<'a>(owner: &'a ReservedShakeRequest, ledger: &Ledger) -> ReservedRequestClosure<'a> {
    let plan = super::super::RequestClosurePlan::new(owner, context());
    let original = ledger.admit_phase(plan.requirements().unwrap()).unwrap();
    plan.open(original, ledger)
        .unwrap_or_else(|_| panic!("original request metadata"))
}

#[test]
fn parent_planning_requires_all_original_leaf_sources_and_original_worker() {
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = owner(&ledger);
    let request = request(&owner, &ledger);
    let before = ledger.snapshot();
    assert!(matches!(
        ParentSourcePlan::new(&request, &ledger),
        Err(Error::MissingLeafSources)
    ));
    assert!(matches!(
        ParentSourcePlan::new(&request, &foreign),
        Err(Error::Authority)
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    drop(request);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn finite_height_domain_checked_arithmetic_and_fixed_merge_bound_fail_closed() {
    for height in [0, 7, 9, MAX_ROWS + 1, MAX_ROWS * 2, usize::MAX] {
        assert_eq!(shape(height), Err(Error::Source));
    }
    let storage =
        PlanningStorage::for_children(0, &[shape(MAX_ROWS).unwrap()], construction()).unwrap();
    let mut envelope = VerifierHeightEnvelope {
        public_values: HEADER + 8,
        maximum_child_height: MAX_ROWS,
        heights_enumerated: MAX_ROWS.ilog2() as usize - 2,
        operations: OperationCounts::default(),
        wire_upper_bound: 0,
        input_values_upper_bound: 0,
        selection_hint_words_upper_bound: 0,
        planner_requested_program_bytes_peak: 0,
        planning_storage: storage,
    };
    // Arithmetic-helper test only. This local value cannot construct an
    // original ParentSourceBound or substitute for exhaustive inspection.
    assert_eq!(
        ParentGeometry::from_envelope(&envelope).unwrap().operations,
        framing::operations()
    );
    envelope.selection_hint_words_upper_bound = 7;
    assert_eq!(
        ParentGeometry::from_envelope(&envelope)
            .unwrap()
            .selection_hint_words_upper_bound,
        14
    );
    envelope.selection_hint_words_upper_bound = usize::MAX;
    assert_eq!(
        ParentGeometry::from_envelope(&envelope),
        Err(Error::Overflow)
    );
    envelope.selection_hint_words_upper_bound = 0;
    assert_eq!(
        framing::operations(),
        OperationCounts {
            scalar: 1419,
            cubic: 0,
            poseidon: 0
        }
    );
    envelope.heights_enumerated -= 1;
    assert_eq!(ParentGeometry::from_envelope(&envelope), Err(Error::Source));
    envelope.heights_enumerated += 1;
    envelope.operations.scalar = usize::MAX;
    assert_eq!(
        ParentGeometry::from_envelope(&envelope),
        Err(Error::Overflow)
    );
    envelope.operations.scalar = MAX_ROWS * 100;
    assert_eq!(
        ParentGeometry::from_envelope(&envelope),
        Err(Error::Capacity)
    );
    envelope.operations.scalar = 0;
    envelope.input_values_upper_bound = super::super::super::INPUT_VALUES;
    assert_eq!(
        ParentGeometry::from_envelope(&envelope),
        Err(Error::Capacity)
    );
    envelope.input_values_upper_bound = 0;
    envelope.wire_upper_bound = usize::MAX;
    assert_eq!(
        ParentGeometry::from_envelope(&envelope),
        Err(Error::Overflow)
    );
    let metadata = metadata_requirement().unwrap();
    assert_eq!(metadata.total().unwrap().device, 0);
    assert!(metadata.total().unwrap().host > size_of::<ParentSourceBound<'_, '_>>() as u64);
    assert!(caller_bytes().unwrap() > size_of::<ParentSourcePlan<'_, '_>>());
}

#[test]
#[ignore = "serialized CPU source inspection of five leaves and18 registered heights; zero proofs"]
fn exact_hashx_parent_sources_close_before_dispatch_and_keep_request_refusal() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_PARENT_SOURCE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let ledger = ledger();
    let owner = owner(&ledger);
    let mut request = request(&owner, &ledger);
    for ordinal in 0..LEAVES {
        let group = GroupCompilePlan::new(
            owner.request(),
            ShakeWrapperLayout::PairedV1,
            ordinal,
            context(),
        )
        .unwrap();
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, &ledger)
            .unwrap();
        let original = ledger.admit_phase(plan.requirements()).unwrap();
        let source = plan.inspect(original, &ledger).unwrap();
        request = request
            .retain_source(&group, source, &ledger)
            .unwrap_or_else(|_| panic!("exact source handoff"));
    }
    let before = ledger.snapshot().current;
    let plan = ParentSourcePlan::new(&request, &ledger).unwrap();
    let requirement = plan.requirements();
    assert!(
        requirement.get(Category::PhaseScratch).host > plan.storage.total_requested_bytes as u64
    );
    let original = ledger.admit_phase(requirement).unwrap();
    let source = plan.inspect(original, &ledger).unwrap();
    assert!(source.is_for(&request, &ledger));
    assert_eq!(source.envelope.heights_enumerated, 18);
    assert!(source.geometry().padded_rows_upper_bound <= MAX_ROWS);
    assert_eq!(
        source.parents[3],
        Interval {
            first: 0,
            count: 122,
            level: 3
        }
    );
    let caps: [_; LEAVES] =
        core::array::from_fn(|index| source.preissue_leaf_cap(index, &ledger).unwrap());
    assert!(matches!(
        source.preissue_leaf_cap(LEAVES, &ledger),
        Err(Error::Authority)
    ));
    let before_compilers = ledger.snapshot().current;
    let first_parent = source.preissue_leaf_parent_compiler(0, &ledger).unwrap();
    let second_parent = source.preissue_leaf_parent_compiler(1, &ledger).unwrap();
    // Parent2 and parent3 require authenticated parent children; they cannot
    // enter this leaf-only compiler seam or turn a source bound into a proof.
    assert!(matches!(
        source.preissue_leaf_parent_compiler(2, &ledger),
        Err(Error::Source)
    ));
    assert!(matches!(
        source.preissue_leaf_parent_compiler(3, &ledger),
        Err(Error::Source)
    ));
    assert!(matches!(
        source.preissue_leaf_parent_compiler(4, &ledger),
        Err(Error::Source)
    ));
    drop(first_parent);
    drop(second_parent);
    assert_eq!(ledger.snapshot().current, before_compilers);
    // Exact source-backed claims for all four edges, including parent children.
    // Admission alone mints no compiled program, output, proof or dispatch.
    let foreign_parent = self::ledger();
    for ordinal in 0..PARENTS {
        let parent = source.preissue_parent_compiler(ordinal, &ledger).unwrap();
        let acceptance = source.preissue_parent_acceptance(ordinal, &ledger).unwrap();
        let shape = source.parent_outer_shape(ordinal, &ledger).unwrap();
        let footprint = shape.output_footprint().unwrap();
        assert_eq!(footprint.public_values, (HEADER + 8) as u64);
        assert!(!footprint.dispatch_authority);
        assert!(footprint.producer_backing_bound_complete);
        drop(acceptance);
        drop(parent);
        assert_eq!(ledger.snapshot().current, before_compilers);
    }
    assert!(source.preissue_parent_compiler(PARENTS, &ledger).is_err());
    assert!(source.preissue_parent_acceptance(PARENTS, &ledger).is_err());
    assert!(source.parent_outer_shape(PARENTS, &ledger).is_err());
    assert!(source.preissue_parent_compiler(0, &foreign_parent).is_err());
    assert!(source
        .preissue_parent_acceptance(0, &foreign_parent)
        .is_err());
    assert!(source.parent_outer_shape(0, &foreign_parent).is_err());
    assert_eq!(ledger.snapshot().current, before_compilers);
    assert_eq!(foreign_parent.snapshot().current, Bytes::ZERO);

    // Real original source owners, with no native preparation or proof. The
    // first-leaf producer must reject a different source/index/group/ledger
    // before it can bind A's original unattempted request and backend.
    let group0 =
        GroupCompilePlan::new(owner.request(), ShakeWrapperLayout::PairedV1, 0, context()).unwrap();
    let group1 =
        GroupCompilePlan::new(owner.request(), ShakeWrapperLayout::PairedV1, 1, context()).unwrap();
    let leaf0 = request.sources[0].as_ref().unwrap();
    let leaf1 = request.sources[1].as_ref().unwrap();
    let acceptance = source.preissue_leaf_acceptance(0, &ledger).unwrap();
    let first =
        crate::component_tree::owned_shake::outer_producer::FutureHashxLeaf::reserve_before_native(
            leaf0, &group0, &owner, acceptance, &ledger,
        )
        .unwrap();
    drop(first);
    assert_eq!(ledger.snapshot().current, before_compilers);
    for (leaf, group, index) in [
        (leaf1, &group0, 0),
        (leaf0, &group1, 0),
        (leaf0, &group0, 1),
    ] {
        let acceptance = source.preissue_leaf_acceptance(index, &ledger).unwrap();
        assert!(crate::component_tree::owned_shake::outer_producer::FutureHashxLeaf::reserve_before_native(
            leaf, group, &owner, acceptance, &ledger,
        ).is_err());
        assert_eq!(ledger.snapshot().current, before_compilers);
    }
    let foreign = self::ledger();
    let acceptance = source.preissue_leaf_acceptance(0, &ledger).unwrap();
    assert!(
        crate::component_tree::owned_shake::outer_producer::FutureHashxLeaf::reserve_before_native(
            leaf0, &group0, &owner, acceptance, &foreign,
        )
        .is_err()
    );
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().current, before_compilers);
    eprintln!("owned_hashx_parent_source heights={} parents={} active_rows_bound={} padded_rows_bound={} wires_bound={} inputs_bound={} native_proofs=0 recursive_proofs=0 independent_parent_verifier_admitted=false correlated_lifecycle_admitted=false complete_workflow_admitted=false",
        source.envelope.heights_enumerated, PARENTS, source.geometry.active_rows_upper_bound,
        source.geometry.padded_rows_upper_bound, source.geometry.wires_upper_bound,
        source.geometry.input_values_upper_bound);
    drop(caps);
    drop(source);
    assert_eq!(ledger.snapshot().current, before);
    let refused = match request.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    assert_eq!(refused.report().retained_original_leaf_sources, LEAVES);
    // Base B051 remains unaltered; a separate source bound never turns its
    // incomplete compiler/verifier/lifetime graph into an execution permit.
    assert!(refused.report().missing[1..].iter().all(Option::is_some));
    drop(refused);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    for category in ledger.snapshot().categories {
        assert_eq!(category.current, Bytes::ZERO);
    }
}
