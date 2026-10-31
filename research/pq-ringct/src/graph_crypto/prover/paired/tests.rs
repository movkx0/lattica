use super::*;
use crate::{
    execution::retained_resources::{Bytes, WorkerAllowance},
    graph_crypto::{Admission, Payload, Policy, RequestDescriptor},
    shake_air::{Descriptor, RATE},
};
use p3_field::PrimeCharacteristicRing;

// This generic body must compile for every shorter borrow. A lifetime-bearing
// interior-mutable field in the plan makes it fail, without any source token.
fn covariant_plan_borrow<'short, 'request: 'short>(plan: &'short PairedRequestPlan<'request>)
    -> &'short PairedRequestPlan<'short>
{ plan }
fn covariant_plan_owner<'short, 'request: 'short>(plan: PairedRequestPlan<'request>)
    -> PairedRequestPlan<'short>
{ plan }

#[cfg(feature = "native-matrict")]
mod full_workflow;

fn request(input: usize, output: usize, maximum: usize) -> Request {
    Request::new([7; 32], 3, 0,
        RequestDescriptor::Shake(Descriptor { input_len: input, output_len: output }),
        Payload::Shake(vec![0; input]), Policy {
            maximum_aes_blocks: 8, maximum_shake_permutations: maximum,
            child_memory_budget_bytes: 24 << 30, admission: Admission::Estimated,
        }).unwrap()
}
fn context() -> GraphContext {
    GraphContext { context: [11; 32], statement: [crate::graph_crypto::Val::ZERO; 4],
        node_manifest: [crate::graph_crypto::Val::ONE; 4] }
}
fn ledger() -> Ledger { Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 }) }
fn derive<'a>(request: &'a Request, layout: ShakeWrapperLayout, ledger: &Ledger,
    scratch: &Reservation) -> PairedRequestPlan<'a> {
    let original = ledger.admit_phase(PairedRequestPlan::planning_requirements(request, layout).unwrap()).unwrap();
    PairedRequestPlan::derive_pre_reserved(request, context(), layout, original, scratch, ledger).unwrap()
}

#[cfg(feature = "identity-batch-experiment")]
#[test]
fn identity_cohort_source_plans_preserve_tree_and_bound_live_compilers() {
    use std::collections::BTreeSet;
    for layout in [ShakeWrapperLayout::Singleton, ShakeWrapperLayout::PairedV1] {
        let request = request(RATE * 2, RATE * 5, 1);
        let ledger = ledger();
        let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(&request, layout).unwrap()).unwrap();
        let baseline = derive(&request, layout, &ledger, &scratch);
        for width in [1, 2, 4, 8, 16] {
            let candidate = derive(&request, layout, &ledger, &scratch)
                .with_identity_limits(IdentityBatchLimits::batched(width).unwrap()).unwrap();
            assert_eq!(candidate.nodes, baseline.nodes);
            assert_eq!(candidate.root, baseline.root);
            assert_eq!(candidate.steps.len(), baseline.steps.len());
            let recursive = |plan: &PairedRequestPlan<'_>| plan.steps.iter().map(|s| s.kind)
                .filter(|s| matches!(s, RequestStepKind::Outer { .. } | RequestStepKind::Merge { .. }))
                .collect::<Vec<_>>();
            assert_eq!(recursive(&candidate), recursive(&baseline));
            let mut compiled = BTreeSet::new();
            let mut proved = BTreeSet::new();
            let mut natives = BTreeSet::new();
            let mut peak = 0;
            for step in &candidate.steps {
                match step.kind {
                    RequestStepKind::Endpoints => {}
                    RequestStepKind::Native { index } => { assert!(natives.insert(index)); }
                    RequestStepKind::Group { node } => {
                        let span = candidate.nodes[node].group.unwrap();
                        for index in span.first_segment..span.first_segment + span.segment_count {
                            assert!(natives.remove(&index));
                        }
                        assert!(compiled.insert(node));
                        assert!(step.facts.output.get(Category::RegisteredMetadata).host
                            >= lattica_prover_p3::block_v2::machine::backend::identity_batch::IDENTITY_PREFIX_HOST_BYTES);
                    }
                    RequestStepKind::Merge { node, left, right } => {
                        assert!(proved.remove(&left) && proved.remove(&right));
                        assert!(compiled.insert(node));
                    }
                    RequestStepKind::Outer { node } => {
                        let (nodes, count) = candidate.identity_cohort(node).unwrap();
                        assert!(nodes[..count].iter().all(|node| compiled.contains(node)));
                        assert!(compiled.remove(&node));
                        assert!(proved.insert(node));
                    }
                }
                peak = peak.max(compiled.len());
                assert!(compiled.len() <= width);
            }
            assert_eq!(proved.into_iter().collect::<Vec<_>>(), [candidate.root]);
            assert!(compiled.is_empty() && natives.is_empty());
            assert!(peak > 0);
        }
        drop(baseline);
        drop(scratch);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
fn source_endpoint_completion_is_required_before_native_preissue() {
    let request = request(1, 32, 8);
    let ledger = ledger();
    let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(
        &request, ShakeWrapperLayout::PairedV1).unwrap()).unwrap();
    let mut plan = derive(&request, ShakeWrapperLayout::PairedV1, &ledger, &scratch);
    let native = plan.ordered_steps().iter().position(|step|
        matches!(step.kind, RequestStepKind::Native { .. })).unwrap();
    assert_eq!(plan.ordered_steps()[0].facts.kind, PhaseKind::EndpointAttach);
    assert!(matches!(plan.native_source(native), Err(PairedFailure::Authority)));
    // A failed source attempt cannot be mistaken for completed endpoint work.
    plan.endpoint_attempted.set(true);
    assert!(matches!(plan.native_source(native), Err(PairedFailure::Authority)));
    let ctx = context();
    assert!(plan.source_endpoints.prepared.set(endpoints::PreparedSourceEndpoints {
        context: ctx.clone(),
        endpoints: crate::component_tree::EndpointContext { context: ctx.context, statement: ctx.statement,
            input: [crate::graph_crypto::Val::ZERO; 4], output: [crate::graph_crypto::Val::ZERO; 4] },
        elapsed_ns: 17,
    }).is_ok());
    assert!(plan.native_source(native).is_ok());
    assert_eq!(plan.prepared_endpoint_output().unwrap().elapsed_ns(), 17);
    // The fixed copy remains bound to the immutable graph context.
    plan.context.context[0] ^= 1;
    assert!(matches!(plan.native_source(native), Err(PairedFailure::Authority)));
}

#[test]
fn borrowed_shake_plan_retains_original_after_endpoint_attempt_unwinds() {
    let request = request(1, 32, 8);
    let ledger = ledger();
    let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(
        &request, ShakeWrapperLayout::PairedV1).unwrap()).unwrap();
    let plan = derive(&request, ShakeWrapperLayout::PairedV1, &ledger, &scratch);
    let native = plan.ordered_steps().iter().position(|step|
        matches!(step.kind, RequestStepKind::Native { .. })).unwrap();
    let held = ledger.snapshot();
    let borrowed = covariant_plan_borrow(&plan);
    let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        borrowed.endpoint_attempted.set(true);
        panic!("injected endpoint preparation failure after borrowing owner");
    }));
    assert!(failure.is_err());
    assert!(plan.endpoint_attempted.get());
    assert!(plan.source_endpoints.prepared.get().is_none());
    assert!(matches!(plan.native_source(native), Err(PairedFailure::Authority)));
    assert_eq!(ledger.snapshot(), held);
    assert_eq!(plan._metadata_original.requirements(), PairedRequestPlan::planning_requirements(
        &request, ShakeWrapperLayout::PairedV1).unwrap());
}

#[test]
fn source_endpoint_backend_is_charged_separately_from_report_and_payload() {
    let request = request(3, 32, 8);
    let ledger = ledger();
    let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(
        &request, ShakeWrapperLayout::Singleton).unwrap()).unwrap();
    let plan = derive(&request, ShakeWrapperLayout::Singleton, &ledger, &scratch);
    let before = ledger.snapshot().current;
    let (caller, backend) = plan.endpoint_preparation_requirements().unwrap();
    assert_eq!(backend, Bytes { host: (80 << 10) + 3 + 16 * 33, device: 8 << 30 });
    assert!(caller.get(Category::Report).host > 0);
    assert!(caller.get(Category::PhaseScratch).host >= 32 + (2 + 16) * 8);
    assert_eq!(caller.total().unwrap().device, 0);
    assert_eq!(ledger.snapshot().current, before);
}

#[test]
fn source_schedule_preserves_native_coverage_across_padding_squeezing_and_odd_tail() {
    // Both transition singleton AIRs and full absorb/squeeze batch AIRs occur
    // in this immutable partition. The plan never changes those boundaries.
    let request = request(8 * RATE + 1, 10 * RATE + 1, 8);
    let ledger = ledger();
    let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(
        &request, ShakeWrapperLayout::PairedV1).unwrap()).unwrap();
    let plan = derive(&request, ShakeWrapperLayout::PairedV1, &ledger, &scratch);
    let mut next_native = 0;
    let mut native_live = [None, None];
    let mut roots = [None; usize::BITS as usize];
    let mut compiled = None;
    let mut maximum_roots = 0;
    for step in plan.ordered_steps() {
        match step.kind {
            RequestStepKind::Endpoints => assert_eq!(next_native, 0),
            RequestStepKind::Native { index } => {
                assert_eq!(index, next_native);
                *native_live.iter_mut().find(|slot| slot.is_none()).unwrap() = Some(index);
                next_native += 1;
            }
            RequestStepKind::Group { node } => {
                let source = plan.node_sources()[node];
                let span = source.group.unwrap();
                assert_eq!(span.segment_count, native_live.iter().filter(|slot| slot.is_some()).count());
                assert_eq!(native_live[0], Some(span.first_segment));
                if span.segment_count == 2 { assert_eq!(native_live[1], Some(span.first_segment + 1)); }
                else { assert_eq!(span.first_segment + 1, request.segments().len()); }
                native_live = [None, None];
                assert!(compiled.replace(node).is_none());
            }
            RequestStepKind::Merge { node, left, right } => {
                for child in [left, right] {
                    roots.iter_mut().find(|slot| **slot == Some(child)).unwrap().take();
                }
                assert_eq!(plan.node_sources()[node].span,
                    ComponentSpan::merge(plan.node_sources()[left].span, plan.node_sources()[right].span).unwrap());
                assert!(compiled.replace(node).is_none());
            }
            RequestStepKind::Outer { node } => {
                assert_eq!(compiled.take(), Some(node));
                *roots.iter_mut().find(|slot| slot.is_none()).unwrap() = Some(node);
                maximum_roots = maximum_roots.max(roots.iter().filter(|slot| slot.is_some()).count());
            }
        }
        assert_eq!(step.facts.source_fingerprint, plan.source_fingerprint());
        assert_eq!(step.facts.compiled_source_fingerprint, crate::graph_proofs::compiled_source_fingerprint());
    }
    assert_eq!(next_native, request.segments().len());
    assert_eq!(roots.iter().flatten().copied().collect::<Vec<_>>(), vec![plan.root_id()]);
    assert_eq!(maximum_roots, plan.slot_requirements().frontier_slots);
    assert_eq!(plan.node_sources()[plan.root_id()].span.first, 0);
    assert_eq!(plan.node_sources()[plan.root_id()].span.count as usize, request.units());
    assert!(plan.root_source().maximum_padded_rows <= source::MAX_ROWS);
    let metadata = PairedRequestPlan::planning_requirements(&request, ShakeWrapperLayout::PairedV1).unwrap().total().unwrap();
    assert!(ledger.snapshot().current.host >= metadata.host);
    drop(plan);
    assert_eq!(ledger.snapshot().current, scratch.requirements().total().unwrap());
    drop(scratch);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn planner_rejects_wrong_original_and_byte_boundary_before_symbolic_allocation() {
    let request = request(2 * RATE, 32, 1);
    let ledger = ledger();
    let foreign = self::ledger();
    let required = PairedRequestPlan::planning_requirements(&request, ShakeWrapperLayout::PairedV1).unwrap();
    let scratch_required = PairedRequestPlan::planning_scratch_requirements(&request, ShakeWrapperLayout::PairedV1).unwrap();
    let scratch = ledger.admit_phase(scratch_required).unwrap();
    let other = foreign.admit_phase(required).unwrap();
    assert!(matches!(PairedRequestPlan::derive_pre_reserved(&request, context(), ShakeWrapperLayout::PairedV1,
        other, &scratch, &ledger), Err(PairedFailure::Authority)));
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    let mut one_less = Requirements::default();
    for category in Category::ALL {
        let mut value = required.get(category);
        if category == Category::Report { value.host -= 1; }
        one_less.add(category, value).unwrap();
    }
    let too_small = ledger.admit_phase(one_less).unwrap();
    assert!(matches!(PairedRequestPlan::derive_pre_reserved(&request, context(), ShakeWrapperLayout::PairedV1,
        too_small, &scratch, &ledger), Err(PairedFailure::Authority)));
    assert_eq!(ledger.snapshot().current, scratch_required.total().unwrap());
}

#[test]
fn malformed_source_partition_and_reversed_parent_are_rejected_before_dispatch() {
    let mut request = request(4 * RATE, 32, 1);
    request.segments.swap(0, 1);
    assert!(matches!(PairedRequestPlan::planning_requirements(&request, ShakeWrapperLayout::PairedV1),
        Err(PairedFailure::Coverage)));
    assert_eq!(ComponentSpan::merge(ComponentSpan { first: 4, count: 4, level: 0 },
        ComponentSpan { first: 0, count: 4, level: 0 }), Err(PairedFailure::Coverage));
    assert!(ShakeWrapperLayout::PairedV1.require_executable().is_err());
}

#[test]
fn endpoint_request_plan_remains_covariant_with_original_retained() {
    let request = request(1, 32, 8);
    let ledger = ledger();
    let scratch = ledger.admit_phase(PairedRequestPlan::planning_scratch_requirements(
        &request, ShakeWrapperLayout::PairedV1).unwrap()).unwrap();
    let plan = derive(&request, ShakeWrapperLayout::PairedV1, &ledger, &scratch);
    let held = ledger.snapshot();
    let plan = covariant_plan_owner(plan);
    let borrowed = covariant_plan_borrow(&plan);
    assert!(core::ptr::eq(&plan, borrowed));
    assert!(core::ptr::eq(borrowed.request(), &request));
    assert_eq!(ledger.snapshot(), held);
    let attach = borrowed.ordered_steps()[0].facts;
    assert_eq!(attach.kind, PhaseKind::EndpointAttach);
    assert_eq!(attach.scratch.get(Category::PhaseScratch).host,
        u64::try_from(endpoints::OUTPUT_COPY_FRAME_BYTES).unwrap());
    assert!(endpoints::OUTPUT_COPY_FRAME_BYTES >= 8 * core::mem::size_of::<Result<PairedEndpoints<'static>>>());
}
