use super::*;
use crate::{
    aes_lane_air::Descriptor,
    execution::retained_resources::{Bytes, WorkerAllowance},
    graph_crypto::{Admission, Payload, Policy},
};
use p3_field::PrimeCharacteristicRing;

// This generic body must compile for every shorter borrow. A lifetime-bearing
// interior-mutable field in the plan makes it fail, without any source token.
fn covariant_plan_borrow<'short, 'request: 'short>(plan: &'short OwnedAesRequestPlan<'request>)
    -> &'short OwnedAesRequestPlan<'short>
{ plan }
fn covariant_plan_owner<'short, 'request: 'short>(plan: OwnedAesRequestPlan<'request>)
    -> OwnedAesRequestPlan<'short>
{ plan }

fn request(output_len: usize, maximum: usize) -> Request {
    Request::new([7; 32], 3, 0,
        RequestDescriptor::Aes(Descriptor { domain: 0x4368, start_counter: u32::MAX, output_len }),
        Payload::Aes([11; 32]), Policy { maximum_aes_blocks: maximum,
            maximum_shake_permutations: 32, child_memory_budget_bytes: 24 << 30,
            admission: Admission::Estimated }).unwrap()
}
fn context() -> GraphContext {
    GraphContext { context: [11; 32], statement: [crate::graph_crypto::Val::ZERO; 4],
        node_manifest: [crate::graph_crypto::Val::ONE; 4] }
}

#[test]
fn source_endpoint_completion_is_required_before_aes_native_preissue() {
    let request = request(1, 64);
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let scratch = ledger.admit_phase(OwnedAesRequestPlan::planning_scratch_requirements(&request).unwrap()).unwrap();
    let metadata = ledger.admit_phase(OwnedAesRequestPlan::planning_requirements(&request).unwrap()).unwrap();
    let plan = OwnedAesRequestPlan::derive_pre_reserved(&request, context(), metadata, &scratch, &ledger).unwrap();
    let native = plan.ordered_steps().iter().position(|step|
        matches!(step.kind, OwnedAesStepKind::Native { .. })).unwrap();
    assert_eq!(plan.ordered_steps()[0].facts.kind, PhaseKind::EndpointAttach);
    assert!(matches!(plan.native_source(native), Err(PairedFailure::Authority)));
    let held = ledger.snapshot();
    // An attempted operation without a published endpoint is still refused;
    // testing this failure state creates no successful endpoint authority.
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
    assert_eq!(plan._metadata_original.requirements(), OwnedAesRequestPlan::planning_requirements(&request).unwrap());
}

#[test]
fn unchanged_aes_partition_keeps_one_leaf_per_native_and_closes_recursive_root() {
    let request = request(64 * 16 + 1, 64);
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let scratch = ledger.admit_phase(OwnedAesRequestPlan::planning_scratch_requirements(&request).unwrap()).unwrap();
    let metadata = ledger.admit_phase(OwnedAesRequestPlan::planning_requirements(&request).unwrap()).unwrap();
    let plan = OwnedAesRequestPlan::derive_pre_reserved(&request, context(), metadata, &scratch, &ledger).unwrap();
    let mut native_count = 0;
    let mut compiled_count = 0;
    let mut outer_count = 0;
    let mut covered = 0;
    for step in plan.ordered_steps() {
        match step.kind {
            OwnedAesStepKind::Native { index } => { assert_eq!(index, native_count); native_count += 1; }
            OwnedAesStepKind::Compile { node } => {
                let source = plan.node_sources()[node];
                assert_eq!(source.segment, Some(compiled_count));
                assert_eq!(source.span.first as usize, covered);
                covered += source.span.count as usize;
                compiled_count += 1;
            }
            OwnedAesStepKind::Outer { .. } => outer_count += 1,
            OwnedAesStepKind::Endpoints => assert_eq!(step.facts.kind, PhaseKind::EndpointAttach),
            OwnedAesStepKind::Merge { left, right, node } => assert_eq!(
                plan.node_sources()[node].span,
                ComponentSpan::merge(plan.node_sources()[left].span, plan.node_sources()[right].span).unwrap()),
        }
    }
    assert_eq!((native_count, compiled_count, outer_count, covered), (2, 2, 3, 65));
    assert_eq!(plan.node_sources()[plan.root_id()].span, ComponentSpan { first: 0, count: 65, level: 1 });
    assert!(plan.root_source().maximum_padded_rows <= 1 << 20);
}

#[test]
fn aes_native_source_and_endpoints_have_independent_original_census() {
    let request = request(64 * 16 + 1, 64);
    for index in 0..request.segments().len() {
        let source = OwnedAesNativeSource::new(&request, index).unwrap();
        let (output, scratch) = source.source_requirements().unwrap();
        assert!(output.get(Category::NativeProof).host > 0);
        assert!(output.get(Category::RegisteredMetadata).host > 0);
        assert!(scratch.get(Category::IndependentVerifier).host >= 64 << 20);
        assert_eq!(scratch.total().unwrap().device, 0);
    }
    assert!(matches!(OwnedAesNativeSource::new(&request, 2), Err(PairedFailure::Coverage)));
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let scratch = ledger.admit_phase(OwnedAesRequestPlan::planning_scratch_requirements(&request).unwrap()).unwrap();
    let metadata = ledger.admit_phase(OwnedAesRequestPlan::planning_requirements(&request).unwrap()).unwrap();
    let plan = OwnedAesRequestPlan::derive_pre_reserved(&request, context(), metadata, &scratch, &ledger).unwrap();
    let ordinal = plan.ordered_steps().iter().position(|step| matches!(step.kind, OwnedAesStepKind::Native { .. })).unwrap();
    assert!(matches!(plan.native_source(ordinal), Err(PairedFailure::Authority)));
    let (caller, backend) = plan.endpoint_preparation_requirements().unwrap();
    assert_eq!(backend, Bytes { host: (80 << 10) + 32 + 16 * (1025 + 1), device: 8 << 30 });
    assert!(caller.get(Category::Report).host > 0);
    assert!(caller.get(Category::PhaseScratch).host > 1025);
    assert_eq!(caller.total().unwrap().device, 0);
}

#[test]
fn endpoint_request_plan_remains_covariant_with_original_retained() {
    let request = request(1, 64);
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let scratch = ledger.admit_phase(OwnedAesRequestPlan::planning_scratch_requirements(&request).unwrap()).unwrap();
    let metadata = ledger.admit_phase(OwnedAesRequestPlan::planning_requirements(&request).unwrap()).unwrap();
    let plan = OwnedAesRequestPlan::derive_pre_reserved(&request, context(), metadata, &scratch, &ledger).unwrap();
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
    assert!(endpoints::OUTPUT_COPY_FRAME_BYTES >= 8 * core::mem::size_of::<Result<OwnedAesEndpoints<'static>>>());
}
