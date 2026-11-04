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
fn numeric_worker_preserves_request_plan_and_refuses_changed_binding() {
    use crate::component_tree::native_shape::cache;
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::HeightEnvelopeCacheScope;
    let source = crate::graph_proofs::compiled_source_fingerprint();
    let _native = cache::Scope::begin(source).unwrap();
    let _registered = HeightEnvelopeCacheScope::begin(source).unwrap();
    let request = request(64 * 16 + 1, 64);
    let ledger = Ledger::new(WorkerAllowance { host: 32 << 30, device: 8 << 30 });
    let scratch = ledger.admit_phase(OwnedAesRequestPlan::planning_scratch_requirements(&request).unwrap()).unwrap();
    let original = || ledger.admit_phase(OwnedAesRequestPlan::planning_requirements(&request).unwrap()).unwrap();
    let baseline = OwnedAesRequestPlan::derive_pre_reserved(&request, context(), original(), &scratch, &ledger).unwrap();
    let native = cache::snapshot().unwrap();
    let registered = HeightEnvelopeCacheScope::snapshot().unwrap();
    let key_plan = crate::graph_crypto::IdentityKeyPlan::new([&request].into_iter(), 4).unwrap();
    let key_admission = crate::metadata_parallel::Plan::new(4, key_plan.jobs(), usize::MAX,
        key_plan.retained_bytes(), 0).unwrap();
    let key_original = ledger.reserve(Category::PhaseScratch,
        Bytes { host: key_admission.host_bytes as u64, device: 0 }).unwrap();
    let keys = key_plan.derive(key_admission).unwrap();
    for width in [1, 2, 4, 8, 16] {
        let leaves_plan = crate::graph_crypto::NumericLeafPlan::new([&request].into_iter(), crate::graph_crypto::ShakeWrapperLayout::PairedV1, width).unwrap();
        let admission = crate::metadata_parallel::Plan::new(width, leaves_plan.jobs(), usize::MAX,
            leaves_plan.retained_bytes(), 8 << 20).unwrap();
        let _original = ledger.reserve(Category::PhaseScratch, Bytes { host: admission.host_bytes as u64, device: 0 }).unwrap();
        let leaves = leaves_plan.derive(admission, &native, &registered).unwrap();
        let chunked = OwnedAesRequestNumbers::derive_prepared(&request, context(), None, Some(keys.get(0).unwrap()), Some(leaves.get(0).unwrap())).unwrap();
        assert_eq!(chunked.nodes, baseline.nodes);
        assert_eq!(chunked.steps, baseline.steps);
        assert_eq!(chunked.slots, baseline.slots);
        assert_eq!(chunked.root, baseline.root);
        assert_eq!(chunked.source_fingerprint, baseline.source_fingerprint);
    }
    let numbers = || std::thread::scope(|threads| threads.spawn(|| {
        let _native = cache::Scope::begin_read_only(&native).unwrap();
        let _registered = HeightEnvelopeCacheScope::begin_read_only(&registered).unwrap();
        OwnedAesRequestNumbers::derive_with_keys(&request, context(), None, Some(keys.get(0).unwrap())).unwrap()
    }).join().unwrap());
    let candidate = OwnedAesRequestPlan::derive_pre_reserved_resolved(&request, context(),
        original(), &scratch, &ledger, Some(numbers())).unwrap();
    assert_eq!(candidate.nodes, baseline.nodes);
    assert_eq!(candidate.steps, baseline.steps);
    assert_eq!(candidate.slots, baseline.slots);
    assert_eq!(candidate.root, baseline.root);
    assert_eq!(candidate.source_fingerprint, baseline.source_fingerprint);
    assert_eq!(candidate._metadata_original.requirements(), baseline._metadata_original.requirements());
    assert!(candidate.source_endpoints.prepared.get().is_none());
    let mut wrong_context = context();
    wrong_context.context[0] ^= 1;
    assert!(matches!(OwnedAesRequestPlan::derive_pre_reserved_resolved(&request, wrong_context,
        original(), &scratch, &ledger, Some(numbers())), Err(PairedFailure::SourceDrift)));
    let mut stale = numbers();
    stale.compiled_source_fingerprint[0] ^= 1;
    assert!(matches!(OwnedAesRequestPlan::derive_pre_reserved_resolved(&request, context(),
        original(), &scratch, &ledger, Some(stale)), Err(PairedFailure::SourceDrift)));
    drop(candidate);
    drop(baseline);
    drop(scratch);
    drop(keys);
    drop(key_original);
    assert_eq!(ledger.snapshot().current, Bytes::default());
}
#[test]
fn aes_compiler_retains_only_source_bounded_packed_storage() {
    let request = request(64 * 16, 64);
    let blueprint = source::AesBlueprint::new(&request, 0).unwrap();
    let source = blueprint.inspect().unwrap();
    let retained = source.retained_program_host_bytes().unwrap();
    let (output, scratch) = blueprint.compiler_requirements(source).unwrap();
    assert!(retained < source::PROGRAM_BYTES);
    assert_eq!(output.get(Category::SymbolicCompiler).host,
        (retained + core::mem::size_of::<paired_runtime::PairedCompiled<'static>>() * 8) as u64);
    assert!(scratch.get(Category::PhaseScratch).host >= (source::PROGRAM_BYTES - retained) as u64);
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

#[test]
fn native_metadata_groups_cross_boundaries_without_duplicate_compilation() {
    use crate::component_tree::native_shape::cache;
    use lattica_prover_p3::block_v2::machine::verifier::batch::shape::{MetadataCpuOptions, MetadataPlanningScope};
    let _planner = MetadataPlanningScope::begin(MetadataCpuOptions::workers(4).unwrap()).unwrap();
    let cache = cache::Scope::begin(crate::graph_proofs::compiled_source_fingerprint()).unwrap();
    let request = request(16 * 64 * 16 + 1, 64);
    let ledger = Ledger::new(WorkerAllowance { host:32 << 30, device:8 << 30 });
    let scratch = ledger.admit_phase(OwnedAesRequestPlan::planning_scratch_requirements(&request).unwrap()).unwrap();
    let metadata = ledger.admit_phase(OwnedAesRequestPlan::planning_requirements(&request).unwrap()).unwrap();
    let plan = OwnedAesRequestPlan::derive_pre_reserved(&request,context(),metadata,&scratch,&ledger).unwrap();
    assert_eq!(request.segments().len(),17);
    assert_eq!(plan.node_sources().len(),33);
    assert_eq!(cache.statistics().jobs_started,17);
    assert_eq!(cache.statistics().entries,17);
    assert_eq!(cache.statistics().hits,0);
    assert_eq!(cache.statistics().periodic_preparations,1);
    assert!(cache.statistics().peak_workers <= 4);
    assert!(cache.statistics().admitted_host_bytes_peak <= scratch.requirements().get(Category::PhaseScratch).host as usize);
}
