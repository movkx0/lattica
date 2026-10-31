use super::*;
use crate::{
    component_tree::{Spec, Val},
    execution::retained_resources::WorkerAllowance,
    graph_crypto::{Admission, Policy, ShakeRequestPlan},
};
use p3_field::PrimeCharacteristicRing;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    })
}

fn active_plan(input: &[u8]) -> ShakeRequestPlan<'_> {
    ShakeRequestPlan::new_active_opt_validate_v1(
        [7; 32],
        9,
        0,
        input,
        137,
        Policy {
            maximum_aes_blocks: 64,
            maximum_shake_permutations: 32,
            child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated,
        },
    )
    .unwrap()
}

fn owner(ledger: &Ledger) -> ReservedShakeRequest {
    // External fixture storage is separate from the admitted immutable copy.
    let input = [23; 16_416];
    let plan = active_plan(&input);
    let original = ledger.admit_phase(plan.requirements()).unwrap();
    plan.construct(original, ledger).unwrap()
}

fn context() -> EndpointContext {
    EndpointContext {
        context: [11; 32],
        statement: [Val::from_u64(13); 4],
        input: [Val::from_u64(17); 4],
        output: [Val::from_u64(19); 4],
    }
}

fn group(
    owner: &ReservedShakeRequest,
    layout: ShakeWrapperLayout,
    ordinal: usize,
) -> GroupCompilePlan<'_> {
    GroupCompilePlan::new(owner.request(), layout, ordinal, context()).unwrap()
}

fn open<'a>(owner: &'a ReservedShakeRequest, ledger: &Ledger) -> ReservedRequestClosure<'a> {
    let plan = RequestClosurePlan::new(owner, context());
    let original = ledger.admit_phase(plan.requirements().unwrap()).unwrap();
    plan.open(original, ledger)
        .unwrap_or_else(|_| panic!("valid source metadata"))
}

fn refusal(request: ReservedRequestClosure<'_>) -> RefusedRequest<'_> {
    match request.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    }
}

#[test]
fn active_hashx_tree_matches_reference_merges_including_asymmetric_root() {
    let ledger = ledger();
    let owner = owner(&ledger);
    let initial = ledger.snapshot();
    let request = open(&owner, &ledger);
    let contract = owner.request().contract().unwrap();
    let mut specs: [Option<Spec>; LEAVES + PARENTS] = core::array::from_fn(|_| None);
    for (i, (span, interval)) in request
        .tree
        .spans
        .iter()
        .zip(request.tree.leaves)
        .enumerate()
    {
        let expected = owner
            .request()
            .shake_wrapper_schedule(ShakeWrapperLayout::PairedV1)
            .unwrap()
            .groups()
            .nth(i)
            .unwrap();
        assert_eq!(*span, expected);
        specs[i] = Some(contract.span(interval.first, interval.count).unwrap());
    }
    let slot = |node| match node {
        Node::Leaf(i) => i,
        Node::Parent(i) => LEAVES + i,
    };
    for (i, parent) in request.tree.parents.iter().enumerate() {
        let parent = parent.unwrap();
        let expected = Spec::merge(
            specs[slot(parent.left)].as_ref().unwrap(),
            specs[slot(parent.right)].as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(
            parent.interval,
            Interval {
                first: expected.first,
                count: expected.count,
                level: expected.level
            },
        );
        specs[LEAVES + i] = Some(expected);
    }
    let root = request.tree.parents[3].unwrap();
    assert_eq!((root.left, root.right), (Node::Parent(2), Node::Leaf(4)));
    assert_eq!(request.tree.interval(root.left).unwrap().level, 2);
    assert_eq!(request.tree.interval(root.right).unwrap().level, 0);
    assert_eq!(
        root.interval,
        Interval {
            first: 0,
            count: 122,
            level: 3
        }
    );
    let before_refusal = ledger.snapshot();
    let refused = refusal(request);
    assert_eq!(ledger.snapshot(), before_refusal);
    let report = refused.report();
    assert_eq!(
        (
            report.native_proofs_scheduled,
            report.recursive_leaves_scheduled,
            report.recursive_parents_scheduled
        ),
        (10, 5, 4)
    );
    assert_eq!(report.retained_original_leaf_sources, 0);
    assert!(report.missing.iter().all(Option::is_some));
    drop(refused);
    assert_eq!(ledger.snapshot().current, initial.current);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn request_identity_group_order_layout_and_context_cannot_be_substituted() {
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = owner(&ledger);
    let identical = self::owner(&ledger);
    let request = open(&owner, &ledger);
    let before = ledger.snapshot();
    let valid = group(&owner, ShakeWrapperLayout::PairedV1, 0);
    assert_eq!(request.check_group(&valid, &ledger), Ok(()));
    assert_eq!(request.check_group(&valid, &foreign), Err(Error::Authority));
    assert_eq!(
        request.check_group(&group(&identical, ShakeWrapperLayout::PairedV1, 0), &ledger),
        Err(Error::Authority)
    );
    assert_eq!(
        request.check_group(&group(&owner, ShakeWrapperLayout::PairedV1, 1), &ledger),
        Err(Error::Order)
    );
    assert_eq!(
        request.check_group(&group(&owner, ShakeWrapperLayout::Singleton, 0), &ledger),
        Err(Error::Order)
    );
    let mut changed = group(&owner, ShakeWrapperLayout::PairedV1, 0);
    changed.context.context[0] ^= 1;
    assert_eq!(request.check_group(&changed, &ledger), Err(Error::Context));
    changed = group(&owner, ShakeWrapperLayout::PairedV1, 0);
    changed.span.first_unit += 1;
    assert_eq!(request.check_group(&changed, &ledger), Err(Error::Order));
    assert_eq!(ledger.snapshot(), before);
    drop(request);
    drop((owner, identical));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
}

#[test]
fn incomplete_reordered_overflowing_and_wrong_level_trees_are_refused() {
    let ledger = ledger();
    let owner = owner(&ledger);
    let plan = RequestClosurePlan::new(&owner, context());
    let spans = plan.spans().unwrap();
    let mut changed = spans;
    changed.swap(0, 1);
    assert_eq!(Tree::derive(changed), Err(Error::Geometry));
    changed = spans;
    changed[4].units -= 1;
    assert_eq!(Tree::derive(changed), Err(Error::Geometry));
    changed = spans;
    changed[4].units = usize::MAX;
    assert_eq!(Tree::derive(changed), Err(Error::Overflow));
    changed = spans;
    changed[3] = changed[2];
    assert_eq!(Tree::derive(changed), Err(Error::Geometry));
    let a = Interval {
        first: 0,
        count: 120,
        level: u32::MAX,
    };
    let b = Interval {
        first: 120,
        count: 2,
        level: 0,
    };
    assert_eq!(Interval::merge(a, b), Err(Error::Overflow));
    assert_eq!(Interval::merge(b, a), Err(Error::Geometry));
    assert_eq!(
        Interval {
            first: u32::MAX,
            count: 1,
            level: 0
        }
        .end(),
        Err(Error::Overflow)
    );
}

#[test]
fn exact_metadata_category_and_ledger_are_required_and_refusal_retains_original() {
    let ledger = ledger();
    let foreign = self::ledger();
    let owner = owner(&ledger);
    let required = metadata_requirement().unwrap();
    let bytes = required.total().unwrap();
    assert_eq!(bytes.device, 0);
    assert_eq!(required.get(Category::RegisteredMetadata), bytes);
    assert!(bytes.host > size_of::<ReservedRequestClosure<'_>>() as u64);
    for category in Category::ALL {
        if category == Category::RegisteredMetadata {
            continue;
        }
        let original = ledger
            .admit_phase(Requirements::single(category, bytes))
            .unwrap();
        let before = ledger.snapshot();
        let rejected = match RequestClosurePlan::new(&owner, context()).open(original, &ledger) {
            Err(refused) => refused,
            Ok(_) => panic!("wrong category was accepted"),
        };
        assert_eq!(rejected.reason, Error::Authority);
        assert_eq!(rejected.original.requirements().get(category), bytes);
        assert_eq!(ledger.snapshot(), before);
        drop(rejected);
    }
    let original = foreign.admit_phase(required).unwrap();
    let before = foreign.snapshot();
    let rejected = match RequestClosurePlan::new(&owner, context()).open(original, &ledger) {
        Err(refused) => refused,
        Ok(_) => panic!("foreign reservation was accepted"),
    };
    assert_eq!(rejected.reason, Error::Authority);
    assert!(rejected.original.belongs_to(&foreign));
    assert_eq!(foreign.snapshot(), before);
    drop(rejected);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    for host in [bytes.host - 1, bytes.host + 1] {
        let original = ledger
            .admit_phase(Requirements::single(
                Category::RegisteredMetadata,
                Bytes { host, device: 0 },
            ))
            .unwrap();
        let before = ledger.snapshot();
        let rejected = match RequestClosurePlan::new(&owner, context()).open(original, &ledger) {
            Err(refused) => refused,
            Ok(_) => panic!("non-original envelope was accepted"),
        };
        assert_eq!(rejected.reason, Error::Authority);
        assert_eq!(ledger.snapshot(), before);
        drop(rejected);
    }
    let short = Ledger::new(WorkerAllowance {
        host: bytes.host - 1,
        device: 0,
    });
    let before = short.snapshot();
    assert!(short.admit_phase(required).is_err());
    assert_eq!(short.snapshot(), before);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn malformed_request_geometry_and_enlarged_allowance_cannot_open_gate() {
    let ledger = ledger();
    let input = [0; 137];
    let source = ShakeRequestPlan::new([7; 32], 9, 0, &input, 137, Policy::default()).unwrap();
    let original = ledger.admit_phase(source.requirements()).unwrap();
    let owner = source.construct(original, &ledger).unwrap();
    let original = ledger.admit_phase(metadata_requirement().unwrap()).unwrap();
    let before = ledger.snapshot();
    let rejected = match RequestClosurePlan::new(&owner, context()).open(original, &ledger) {
        Err(refused) => refused,
        Ok(_) => panic!("non-HashX source was accepted"),
    };
    assert_eq!(rejected.reason, Error::Geometry);
    assert_eq!(ledger.snapshot(), before);
    drop(rejected);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    for allowance in [
        WorkerAllowance {
            host: (32 << 30) + 1,
            device: 8 << 30,
        },
        WorkerAllowance {
            host: 32 << 30,
            device: (8 << 30) + 1,
        },
    ] {
        let ledger = Ledger::new(allowance);
        let input = [23; 16_416];
        let plan = active_plan(&input);
        let original = ledger.admit_phase(plan.requirements()).unwrap();
        // The immutable-owner constructor already rejects an enlarged
        // allowance. No valid owner exists for a later closure admission.
        assert!(plan.construct(original, &ledger).is_err());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
#[ignore = "serialized source-only planning; no proof or dispatch"]
fn five_original_leaf_sources_still_refuse_complete_request_and_release_all_owners() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_REQUEST_CLOSURE_QUALIFICATION").as_deref(),
        Ok("1")
    );
    let ledger = ledger();
    let owner = owner(&ledger);
    let initial = ledger.snapshot().current;
    let mut request = open(&owner, &ledger);
    for ordinal in 0..LEAVES {
        let group = GroupCompilePlan::new(
            owner.request(),
            ShakeWrapperLayout::PairedV1,
            ordinal,
            context(),
        )
        .unwrap();
        let source_plan = group
            .source_shape_plan_existing_batches_v1(&owner, &ledger)
            .unwrap();
        let original = ledger.admit_phase(source_plan.requirements()).unwrap();
        let source = source_plan.inspect(original, &ledger).unwrap();
        let before = ledger.snapshot();
        // Wrong-order metadata cannot consume either original owner.
        let other = GroupCompilePlan::new(
            owner.request(),
            ShakeWrapperLayout::PairedV1,
            (ordinal + 1) % LEAVES,
            context(),
        )
        .unwrap();
        let refused = match request.retain_source(&other, source, &ledger) {
            Err(refused) => refused,
            Ok(_) => panic!("wrong-order source handoff succeeded"),
        };
        assert_eq!(refused.reason, Error::Order);
        assert_eq!(ledger.snapshot(), before);
        request = refused
            .request
            .retain_source(&group, refused.source, &ledger)
            .unwrap_or_else(|_| panic!("exact original leaf source"));
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(request.check_group(&group, &ledger), Err(Error::Order));
    }
    let before = ledger.snapshot();
    let refused = refusal(request);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(refused.report().retained_original_leaf_sources, LEAVES);
    assert_eq!(refused.report().missing[0], None);
    assert!(refused.report().missing[1..].iter().all(Option::is_some));
    drop(refused);
    assert_eq!(ledger.snapshot().current, initial);
    drop(owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    for category in ledger.snapshot().categories {
        assert_eq!(category.current, Bytes::ZERO);
    }
}
