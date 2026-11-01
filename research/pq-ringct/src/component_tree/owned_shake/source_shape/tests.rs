use super::*;
use crate::{
    execution::retained_resources::{Bytes, WorkerAllowance},
    graph_crypto::{NativeProductionPlan, Policy, ShakeRequestPlan},
};
use p3_field::PrimeCharacteristicRing;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    })
}

fn owner(ledger: &Ledger, input_len: usize, output_len: usize) -> ReservedShakeRequest {
    let input = [5; 272];
    let plan = ShakeRequestPlan::new(
        [7; 32],
        9,
        0,
        &input[..input_len],
        output_len,
        Policy::default(),
    )
    .unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

fn context() -> EndpointContext {
    EndpointContext {
        context: [11; 32],
        statement: [super::super::Val::from_u64(13); 4],
        input: [super::super::Val::from_u64(17); 4],
        output: [super::super::Val::from_u64(19); 4],
    }
}

fn plan(
    owner: &ReservedShakeRequest,
    layout: ShakeWrapperLayout,
    ordinal: usize,
) -> GroupCompilePlan<'_> {
    GroupCompilePlan::new(owner.request(), layout, ordinal, context()).unwrap()
}

#[test]
fn single_pair_and_odd_tail_census_is_source_only_and_covers_planner_owners() {
    let ledger = ledger();
    let owner = owner(&ledger, 137, 137);
    assert_eq!(owner.request().segments().len(), 3);
    let before = ledger.snapshot();
    for (layout, ordinal, arity) in [
        (ShakeWrapperLayout::Singleton, 0, 1),
        (ShakeWrapperLayout::PairedV1, 0, 2),
        (ShakeWrapperLayout::PairedV1, 1, 1),
    ] {
        let group = plan(&owner, layout, ordinal);
        let source = group.source_shape_plan(&owner, &ledger).unwrap();
        assert!(source.identity.is_for(&group, &ledger));
        assert_eq!(source.descriptors.iter().flatten().count(), arity);
        assert_eq!(source.storage.iter().flatten().count(), arity);
        let total = source.requirements().total().unwrap();
        assert_eq!(total.device, 0);
        assert!(total.host < 3 << 30);
        assert!(
            source.metadata.get(Category::RegisteredMetadata).host
                > size_of::<GroupSourceBound<'_>>() as u64
        );
        for storage in source.storage.iter().flatten() {
            assert!(source.temporary.total().unwrap().host > storage.total_requested_bytes as u64);
            assert_eq!(storage.geometry.height, 4096);
            assert_eq!(storage.geometry.width, 517);
            assert!(storage.template_construction_bytes >= 2 * storage.template_retained_bytes);
        }
        assert_eq!(ledger.snapshot(), before);
    }
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn original_request_ledger_and_fixed_compiler_profile_are_required_before_planning() {
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = owner(&ledger, 137, 137);
    let identical = self::owner(&ledger, 137, 137);
    let before = ledger.snapshot();
    let mut group = plan(&owner, ShakeWrapperLayout::PairedV1, 0);
    assert!(matches!(
        group.source_shape_plan(&owner, &foreign),
        Err(Error::Authority)
    ));
    assert!(matches!(
        group.source_shape_plan(&identical, &ledger),
        Err(Error::Authority)
    ));
    group.limits.max_requested_program_bytes -= 1;
    assert!(matches!(
        group.source_shape_plan(&owner, &ledger),
        Err(Error::Unsupported)
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
}

#[test]
fn native_batches_are_refused_without_resegmenting_or_allocating_planner_storage() {
    let ledger = ledger();
    let owner = owner(&ledger, 272, 1);
    let group = plan(&owner, ShakeWrapperLayout::Singleton, 0);
    assert!(owner.request().segments()[0].units > 1);
    let before = ledger.snapshot();
    assert!(matches!(
        group.source_shape_plan(&owner, &ledger),
        Err(Error::Unsupported)
    ));
    assert_eq!(ledger.snapshot(), before);
}

fn active_hashx_owner(ledger: &Ledger) -> ReservedShakeRequest {
    // The source fixture is external test storage. A035 admits the immutable
    // copied request before construction; no graph authentication is asserted.
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
            child_memory_budget_bytes: 24u64 << 30,
            admission: crate::graph_crypto::Admission::Estimated,
        },
    )
    .unwrap();
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

#[test]
fn active_hashx_source_census_preserves_batches_padding_and_squeeze_tail() {
    let ledger = ledger();
    let owner = active_hashx_owner(&ledger);
    let segments = owner.request().segments();
    assert_eq!(segments.len(), 10);
    let before = ledger.snapshot();
    let mut next_segment = 0;
    let mut next_unit = 0;
    for (ordinal, expected_units) in [[16, 16], [16, 16], [16, 16], [16, 8], [1, 1]]
        .into_iter()
        .enumerate()
    {
        let group = plan(&owner, ShakeWrapperLayout::PairedV1, ordinal);
        let source = group
            .source_shape_plan_existing_batches_v1(&owner, &ledger)
            .unwrap();
        assert!(source.identity.is_for(&group, &ledger));
        assert_eq!(source.identity.span.first_segment, next_segment);
        assert_eq!(source.identity.span.first_unit, next_unit);
        assert_eq!(source.identity.span.segment_count, 2);
        assert_eq!(
            source.identity.span.units,
            expected_units.iter().sum::<usize>()
        );
        for (offset, count) in expected_units.into_iter().enumerate() {
            let NativeDescriptor::Shake {
                descriptor,
                first,
                count: actual_count,
            } = source.descriptors[offset].unwrap()
            else {
                panic!("exact existing SHAKE source required");
            };
            let segment = &segments[next_segment];
            let storage = source.storage[offset].unwrap();
            assert_eq!((descriptor.input_len, descriptor.output_len), (16_416, 137));
            assert_eq!((first, actual_count), (next_unit, count));
            assert_eq!((segment.first_unit, segment.units), (first, actual_count));
            assert_eq!(storage.geometry.width, if count == 1 { 517 } else { 518 });
            assert_eq!(storage.geometry.height, 4096 * count);
            assert_eq!(storage.geometry.public_values, 216);
            assert_eq!(storage.geometry.periodic_columns, 42);
            assert_eq!(storage.geometry.maximum_period, 128);
            assert!(
                source.temporary.get(Category::PhaseScratch).host
                    > storage.total_requested_bytes as u64
            );
            next_segment += 1;
            next_unit += count;
        }
        assert_eq!(source.requirements().total().unwrap().device, 0);
        if ordinal < 4 {
            assert!(matches!(
                group.source_shape_plan(&owner, &ledger),
                Err(Error::Unsupported)
            ));
        } else {
            // The actual padding and squeeze-tail native segments stay two
            // singletons; both explicit source entries have identical census.
            let ordinary = group.source_shape_plan(&owner, &ledger).unwrap();
            assert_eq!(source.storage, ordinary.storage);
            assert_eq!(source.requirements(), ordinary.requirements());
        }
        assert_eq!(ledger.snapshot(), before);
    }
    assert_eq!((next_segment, next_unit), (10, 122));
    assert_eq!((segments[8].first_unit, segments[8].units), (120, 1));
    assert_eq!((segments[9].first_unit, segments[9].units), (121, 1));
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn existing_batch_source_entry_refuses_foreign_identity_limits_and_other_batches() {
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = active_hashx_owner(&ledger);
    let identical = active_hashx_owner(&ledger);
    let before = ledger.snapshot();
    let mut group = plan(&owner, ShakeWrapperLayout::PairedV1, 3);
    assert!(matches!(
        group.source_shape_plan_existing_batches_v1(&owner, &foreign),
        Err(Error::Authority)
    ));
    assert!(matches!(
        group.source_shape_plan_existing_batches_v1(&identical, &ledger),
        Err(Error::Authority)
    ));
    group.limits.max_wires -= 1;
    assert!(matches!(
        group.source_shape_plan_existing_batches_v1(&owner, &ledger),
        Err(Error::Unsupported)
    ));
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);

    // A genuine existing batch2 remains unsupported in this version. It is
    // refused rather than split or substituted with a different policy.
    let unsupported = self::owner(&ledger, 272, 1);
    assert_eq!(unsupported.request().segments()[0].units, 2);
    let group = plan(&unsupported, ShakeWrapperLayout::Singleton, 0);
    let before = ledger.snapshot();
    assert!(matches!(
        group.source_shape_plan_existing_batches_v1(&unsupported, &ledger),
        Err(Error::Unsupported)
    ));
    assert_eq!(ledger.snapshot(), before);
    drop(unsupported);
    drop(identical);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
#[ignore = "bounded native batch source planning only; serialized source-planning guard required"]
fn active_hashx_existing_batches_have_admitted_pair_source_bounds() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_BATCH_SOURCE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let ledger = ledger();
    let owner = active_hashx_owner(&ledger);
    let baseline = ledger.snapshot().current;
    for ordinal in 0..5 {
        let group = plan(&owner, ShakeWrapperLayout::PairedV1, ordinal);
        let source = group
            .source_shape_plan_existing_batches_v1(&owner, &ledger)
            .unwrap();
        let original = ledger.admit_phase(source.requirements()).unwrap();
        let bound = source.inspect(original, &ledger).unwrap();
        assert!(bound.is_for(&group, &ledger));
        assert_eq!(
            ledger.snapshot().current.host,
            baseline.host + metadata_requirement().unwrap().total().unwrap().host
        );
        assert_eq!(ledger.snapshot().current.device, 0);
        let geometry = bound.geometry();
        assert!(geometry.selection_hint_words_upper_bound > 0);
        assert!(geometry.active_rows_upper_bound <= geometry.padded_rows_upper_bound);
        assert!(geometry.padded_rows_upper_bound <= MAX_ROWS);
        eprintln!("ringct_existing_batch_source ordinal={ordinal} first_segment={} native_segments={} first_unit={} units={} active_upper={} padded_upper={} wires_upper={} input_values={} hint_words_upper={} native_proofs=0 recursive_proofs=0 complete_ringct_workflow=false",
            group.span.first_segment, group.span.segment_count, group.span.first_unit, group.span.units,
            geometry.active_rows_upper_bound, geometry.padded_rows_upper_bound, geometry.wires_upper_bound,
            geometry.input_values, geometry.selection_hint_words_upper_bound);
        drop(bound);
        assert_eq!(ledger.snapshot().current, baseline);
    }
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn short_foreign_and_wrong_category_tokens_refuse_before_shape_compilation() {
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = owner(&ledger, 137, 137);
    let group = plan(&owner, ShakeWrapperLayout::PairedV1, 0);
    let baseline = ledger.snapshot().current;
    for variant in 0..3 {
        let source = group.source_shape_plan(&owner, &ledger).unwrap();
        let required = source.requirements();
        let token = match variant {
            0 => {
                let mut real = ledger.admit_phase(required).unwrap();
                let one = real
                    .split(Requirements::single(
                        Category::PhaseScratch,
                        Bytes { host: 1, device: 0 },
                    ))
                    .unwrap();
                drop(one);
                // No numeric correction or fresh receipt is accepted below.
                assert_ne!(real.requirements(), required);
                real
            }
            1 => foreign.admit_phase(required).unwrap(),
            _ => ledger
                .reserve(Category::PhaseScratch, required.total().unwrap())
                .unwrap(),
        };
        assert!(matches!(
            source.inspect(token, &ledger),
            Err(Error::Authority)
        ));
        assert_eq!(ledger.snapshot().current, baseline);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
}

fn core() -> NativeCoreCounts {
    NativeCoreCounts {
        quotient_chunks: 2,
        operations: OperationCounts::default(),
        wires: 216,
        input_values: 216,
        selection_hint_words: 0,
        planner_requested_program_bytes_peak: 0,
    }
}

#[test]
fn class_packing_overflow_and_fixed_row_wire_input_limits_are_checked() {
    assert!(Geometry::from_cores(&[None, None], 1).is_err());
    assert!(Geometry::from_cores(&[Some(core()), Some(core())], 1).is_err());
    let mut excessive = core();
    excessive.operations.poseidon = MAX_ROWS;
    assert_eq!(
        Geometry::from_cores(&[Some(excessive), None], 1),
        Err(Error::Capacity)
    );
    excessive = core();
    excessive.wires = MAX_WIRES;
    assert_eq!(
        Geometry::from_cores(&[Some(excessive), None], 1),
        Err(Error::Capacity)
    );
    excessive = core();
    excessive.input_values = INPUT_VALUES + 1;
    assert_eq!(
        Geometry::from_cores(&[Some(excessive), None], 1),
        Err(Error::Capacity)
    );
    excessive = core();
    excessive.selection_hint_words = usize::MAX;
    let mut second = core();
    second.selection_hint_words = 1;
    assert_eq!(
        Geometry::from_cores(&[Some(excessive), Some(second)], 2),
        Err(Error::Overflow)
    );
    excessive = core();
    excessive.operations.scalar = usize::MAX;
    assert_eq!(
        Geometry::from_cores(&[Some(excessive), None], 1),
        Err(Error::Overflow)
    );
}

#[test]
#[ignore = "bounded source planning and genuine native CPU fixtures; exact serialized owned SHAKE qualification guard required"]
fn source_bound_precedes_genuine_single_pair_and_odd_tail_compilation() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let ledger = ledger();
    let owner = owner(&ledger, 137, 137);
    let request_baseline = ledger.snapshot().current;
    for (layout, ordinal) in [
        (ShakeWrapperLayout::Singleton, 0),
        (ShakeWrapperLayout::PairedV1, 0),
        (ShakeWrapperLayout::PairedV1, 1),
    ] {
        let group = plan(&owner, layout, ordinal);
        let source = group.source_shape_plan(&owner, &ledger).unwrap();
        let original = ledger.admit_phase(source.requirements()).unwrap();
        let bound = source.inspect(original, &ledger).unwrap();
        assert!(bound.is_for(&group, &ledger));
        assert_eq!(
            ledger.snapshot().current.host,
            request_baseline.host + metadata_requirement().unwrap().total().unwrap().host
        );
        assert_eq!(ledger.snapshot().current.device, 0);
        let wrong_context = GroupCompilePlan::new(
            owner.request(),
            layout,
            ordinal,
            EndpointContext {
                context: [12; 32],
                ..context()
            },
        )
        .unwrap();
        assert!(!bound.is_for(&wrong_context, &ledger));
        let geometry = bound.geometry();
        assert!(geometry.selection_hint_words_upper_bound > 0);
        // The genuine compiler's original reservation is also issued before
        // either fixture proof; this is still CPU correctness qualification.
        let compiler = ledger.admit_phase(group.requirements()).unwrap();
        let mut children = [None, None];
        for (offset, destination) in children
            .iter_mut()
            .enumerate()
            .take(group.span.segment_count)
        {
            let index = group.span.first_segment + offset;
            let native = NativeProductionPlan::new(owner.request(), index).unwrap();
            let original = ledger.admit_phase(native.requirement()).unwrap();
            *destination = Some(
                native
                    .claim_for(owner.request(), index, original, &ledger)
                    .unwrap()
                    .produce_cpu_fixture()
                    .unwrap(),
            );
        }
        let mut output = group
            .compile_cpu_reference(children, compiler, &ledger)
            .unwrap();
        bound.check_compiled(&output, &ledger).unwrap();
        output.compiled.public[super::super::super::CONTEXT] += super::super::Val::ONE;
        assert_eq!(bound.check_compiled(&output, &ledger), Err(Error::Source));
        output.compiled.public[super::super::super::CONTEXT] -= super::super::Val::ONE;
        bound.check_compiled(&output, &ledger).unwrap();
        eprintln!("ringct_owned_shake_source_bound layout={layout:?} ordinal={ordinal} active_upper={} padded_upper={} wires_upper={} input_values={} hint_words_upper={} actual_active={} actual_padded={} source_precedes_native=true cpu_fixture_only=true complete_ringct_workflow=false",
            geometry.active_rows_upper_bound, geometry.padded_rows_upper_bound, geometry.wires_upper_bound,
            geometry.input_values, geometry.selection_hint_words_upper_bound, output.summary.active_rows, output.summary.padded_rows);
        drop(output);
        drop(bound);
        assert_eq!(ledger.snapshot().current, request_baseline);
    }
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
