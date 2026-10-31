use super::*;
use crate::component_tree::{
    owned_shake::{
        exact_retention::retain_exact,
        recursive_preflight::{Decision, Plan as PreflightPlan},
    },
    shake_verification_memory::observe_planner_allocations,
};

#[test]
#[ignore = "four fresh native CPU proofs and actual wrapper compilation; serialized process and allocation guard required"]
fn exact_owned_retention_preserves_payload_and_keeps_pair_preflight_incomplete() {
    assert_eq!(
        std::env::var("LATTICA_SHAKE_EXACT_RETENTION").as_deref(),
        Ok("1"),
        "requires explicit serialized process-guarded exact-retention qualification"
    );
    let context = ProvingContext::cpu(32 << 30).unwrap();
    let mut capability = context.endpoint_qualification_capability().unwrap();
    let ledger = capability.ledger().clone();
    let fixture = Fixture::new(&ledger);
    let fixture_bytes = Fixture::requirements().total().unwrap();
    let request_plan = ShakeRequestPlan::new(
        [7; 32],
        0,
        0,
        &fixture.input,
        fixture.output.len(),
        Policy {
            maximum_shake_permutations: 1,
            ..Policy::default()
        },
    )
    .unwrap();
    let request_requirements = request_plan.requirements();
    let token = ledger.admit_phase(request_requirements).unwrap();
    let request_owner = request_plan.construct(token, &ledger).unwrap();
    let request = request_owner.request();
    assert!(request_owner.belongs_to(&ledger));
    assert_eq!(request.segments().len(), 3);
    let mut fresh_native_proofs = 0;
    for (layout, ordinal) in [
        (ShakeWrapperLayout::Singleton, 0),
        (ShakeWrapperLayout::PairedV1, 0),
        (ShakeWrapperLayout::PairedV1, 1),
    ] {
        let plan =
            GroupCompilePlan::new(request, layout, ordinal, fixture.endpoints.clone()).unwrap();
        let span = plan.span();
        let requirements = plan.requirements();
        let children: [Option<crate::graph_crypto::ReservedNativeChild<'_>>; 2] =
            core::array::from_fn(|offset| {
                if offset >= span.segment_count {
                    return None;
                }
                let index = span.first_segment + offset;
                let native = NativeProductionPlan::new(request, index).unwrap();
                let token = ledger.admit_phase(native.requirement()).unwrap();
                fresh_native_proofs += 1;
                Some(
                    native
                        .claim_for(request, index, token, &ledger)
                        .unwrap()
                        .produce_cpu_fixture()
                        .unwrap(),
                )
            });
        let output = capability
            .compile_shake_endpoint_qualification(plan, children)
            .unwrap();
        assert_eq!(
            capability.status(),
            Status::Ready,
            "actual compiler cleanup precedes transfer"
        );
        assert!(output.is_for(request));
        let summary = output.summary();
        assert_eq!(summary.independent_native_verifications, span.segment_count);
        let before = ledger.snapshot();
        assert_eq!(
            before.current.host,
            fixture_bytes.host
                + request_requirements.total().unwrap().host
                + requirements.get(Category::SymbolicCompiler).host
                + requirements.get(Category::CompilerInputs).host
                + requirements.get(Category::Report).host
        );
        for category in [Category::NativeProof, Category::IndependentVerifier] {
            assert_eq!(before.categories[category as usize].current, Bytes::ZERO);
        }
        assert_eq!(
            before.categories[Category::PhaseScratch as usize].current,
            fixture_bytes
        );
        let conservative = observe_planner_allocations(0, || {
            PreflightPlan::new(&output, &ledger).unwrap().inspect()
        });
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(
            conservative.decision,
            if span.segment_count == 2 {
                Decision::RefusedUnderExistingLedgerCharges
            } else {
                Decision::IncompleteFullPhaseBound
            }
        );

        // These non-owning addresses are compared, never dereferenced. The
        // closed transfer must preserve the exact allocations and capacities;
        // no second program, input Vec, or native proof is constructed here.
        let program_address = Arc::as_ptr(&output.compiled.program);
        let public_address = output.compiled.public.as_ptr();
        let witness_address = output.compiled.witness.as_ptr();
        let capacities = (
            output.compiled.public.capacity(),
            output.compiled.witness.capacity(),
        );
        let retained = observe_planner_allocations(0, || retain_exact(output, &ledger).unwrap());
        let receipt = retained.receipt();
        assert_eq!(retained.output().summary(), summary);
        assert!(retained.output().is_for(request));
        assert_eq!(
            Arc::as_ptr(&retained.output().compiled.program),
            program_address
        );
        assert_eq!(retained.output().compiled.public.as_ptr(), public_address);
        assert_eq!(retained.output().compiled.witness.as_ptr(), witness_address);
        assert_eq!(
            (
                retained.output().compiled.public.capacity(),
                retained.output().compiled.witness.capacity()
            ),
            capacities
        );
        assert_eq!(
            receipt.construction_program_host,
            requirements.get(Category::SymbolicCompiler).host
        );
        assert_eq!(
            receipt.construction_input_host,
            requirements.get(Category::CompilerInputs).host
        );
        assert_eq!(
            receipt.source_input_host,
            (capacities.0 + capacities.1) as u64 * size_of::<Val>() as u64
        );
        assert_eq!(receipt.ledger_host_before, before.current.host);
        assert_eq!(receipt.ledger_host_after, ledger.snapshot().current.host);
        assert_eq!(
            ledger.snapshot().categories[Category::PhaseScratch as usize].current,
            fixture_bytes
        );
        assert_eq!(
            ledger.snapshot().categories[Category::Report as usize].current,
            before.categories[Category::Report as usize].current
        );
        let exact_snapshot = ledger.snapshot();
        let exact = observe_planner_allocations(0, || {
            PreflightPlan::new(retained.output(), &ledger)
                .unwrap()
                .inspect()
        });
        assert_eq!(ledger.snapshot(), exact_snapshot);
        assert_eq!(
            exact.geometry, conservative.geometry,
            "only charges changed"
        );
        assert_eq!(exact.decision, Decision::IncompleteFullPhaseBound);
        assert_eq!(
            exact.charged_program_host_bytes,
            receipt.retained_program_host
        );
        assert_eq!(exact.charged_input_host_bytes, receipt.retained_input_host);
        assert_eq!(
            exact.geometry.partial_lower_bound_bytes,
            if span.segment_count == 2 {
                32_749_125_568
            } else {
                16_374_562_752
            }
        );
        assert!(receipt.retained_program_host < receipt.construction_program_host);
        assert!(receipt.retained_input_host < receipt.construction_input_host);
        let mut queue = [Some(retained)];
        assert_eq!(ledger.snapshot(), exact_snapshot);
        let retained = queue[0].take().unwrap();
        drop(queue);
        assert_eq!(retained.receipt(), receipt);
        assert_eq!(ledger.snapshot(), exact_snapshot);
        eprintln!("shake_exact_retention layout={layout:?} ordinal={ordinal} members={} active_rows={} height={} construction_program_host={} construction_input_host={} source_program_host={} source_input_host={} retained_program_host={} retained_input_host={} scan_scratch_host={} ledger_host_before={} ledger_host_after={} prior_remaining_worker_host={} remaining_worker_host={} required_partial_lower_bound={} prior_reason={} reason={} same_payload=true same_request=true actual_compiler_cleanup_before_transfer=true scan_scratch_released=true report_charge_unchanged=true complete_footprint=false outer_registration_started=false outer_trace_started=false outer_proof_started=false full_transaction_graph_closed=false physical_memory_savings_claimed=false runtime_enabled=false gpu_work=false",
            span.segment_count, summary.active_rows, summary.padded_rows,
            receipt.construction_program_host, receipt.construction_input_host,
            receipt.source_program_host, receipt.source_input_host,
            receipt.retained_program_host, receipt.retained_input_host, receipt.scan_scratch_host,
            receipt.ledger_host_before, receipt.ledger_host_after,
            conservative.remaining_worker_host_bytes, exact.remaining_worker_host_bytes,
            exact.geometry.partial_lower_bound_bytes, conservative.decision.label(), exact.decision.label());
        drop(retained);
        assert_eq!(
            ledger.snapshot().current.host,
            fixture_bytes.host + request_requirements.total().unwrap().host
        );
    }
    assert_eq!(fresh_native_proofs, 4);
    drop(request_owner);
    assert_eq!(ledger.snapshot().current, fixture_bytes);
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    capability.retire().unwrap();
    assert_eq!(capability.status(), Status::Retired);
    eprintln!("shake_exact_retention_complete fresh_native_proofs={fresh_native_proofs} compiled_wrappers=3 exact_retention_transfers=3 incomplete_wrappers=3 full_ledger_cleanup=true context_retired=true recursive_proofs=0 outer_proof_started=false complete_footprint=false full_transaction_graph_closed=false runtime_enabled=false gpu_work=false");
}
