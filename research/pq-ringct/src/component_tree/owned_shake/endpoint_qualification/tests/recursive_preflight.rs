use super::*;
use crate::component_tree::owned_shake::recursive_preflight::{
    Decision, Error as PreflightError, Evidence, Plan,
};
use lattica_prover_p3::block_v2::machine::analysis::{
    analyze_bounded_cpu, BOUNDED_CPU_ANALYSIS_GRAPH_BYTES,
};

// The core graph quota is 192 MiB. The additional fixed 64 MiB covers the
// fixed-shape AIR/LogUp helpers, report/scalar metadata, and diagnostic backing
// listed in recursive_preflight/BOUNDS.md. This is charged to the same worker,
// not added to its allowance. No trace or outer proving operation is called.
const ANALYSIS_HOST_BYTES: usize = 256 << 20;
const SYMBOLIC_HANDLE_BYTES: usize = 256;
const UNPACKED_TUPLES: usize = 4 * 23 + 46;
// Pessimistically retain all 16 fractions' helper vectors concurrently, with
// old/new backing, plus four handle slots per maximum-depth stack frame and
// 1 MiB for scalar layout/report/diagnostic helpers. Graph Arc allocations are
// already in the core quota; this counts only handles and vector backing.
const ANALYSIS_HELPER_RECIPE: usize = 16
    * 2
    * ((8 * UNPACKED_TUPLES + 64) * SYMBOLIC_HANDLE_BYTES
        + (UNPACKED_TUPLES + 16) * size_of::<Vec<usize>>())
    + 4 * 512 * SYMBOLIC_HANDLE_BYTES
    + (1 << 20);

#[cfg(feature = "native-verification-allocation-audit")]
fn inspect_without_allocation(
    output: &OwnedCompiledShake<'_>,
    ledger: &Ledger,
) -> Result<Evidence, PreflightError> {
    crate::component_tree::shake_verification_memory::observe_planner_allocations(0, || {
        Plan::new(output, ledger).map(|plan| plan.inspect())
    })
}

#[cfg(feature = "native-verification-allocation-audit")]
fn check_preflight_boundaries(output: &mut OwnedCompiledShake<'_>, ledger: &Ledger) -> Evidence {
    let before = ledger.snapshot();
    let evidence = inspect_without_allocation(output, ledger).unwrap();
    assert_eq!(ledger.snapshot(), before, "inspection changes no counters");

    let foreign = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    });
    let foreign_before = foreign.snapshot();
    assert_eq!(
        inspect_without_allocation(output, &foreign),
        Err(PreflightError::Authority)
    );
    assert_eq!(foreign.snapshot(), foreign_before);
    assert_eq!(ledger.snapshot(), before);

    // A malformed summary cannot turn an owned program into another geometry;
    // the error must preserve the complete live output and its charges.
    let height = output.summary.padded_rows;
    output.summary.padded_rows = height * 2;
    assert_eq!(
        inspect_without_allocation(output, ledger),
        Err(PreflightError::Geometry)
    );
    output.summary.padded_rows = height;
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(
        inspect_without_allocation(output, ledger).unwrap(),
        evidence
    );

    if evidence.decision == Decision::IncompleteFullPhaseBound {
        // Equality still cannot issue admission: omitted allocations remain
        // unbounded. One byte less remaining must give the stronger refusal.
        let spare =
            evidence.remaining_worker_host_bytes - evidence.geometry.partial_lower_bound_bytes;
        for (extra, decision) in [
            (spare, Decision::IncompleteFullPhaseBound),
            (spare + 1, Decision::RefusedUnderExistingLedgerCharges),
        ] {
            let blocker = ledger
                .admit_phase(requirement(Category::RegisteredMetadata, extra as usize).unwrap())
                .unwrap();
            let blocked = ledger.snapshot();
            let changed = inspect_without_allocation(output, ledger).unwrap();
            assert_eq!(changed.decision, decision);
            assert_eq!(ledger.snapshot(), blocked);
            drop(blocker);
            assert_eq!(ledger.snapshot().current, before.current);
        }
    }
    evidence
}

#[test]
#[cfg(feature = "native-verification-allocation-audit")]
#[ignore = "four fresh native CPU proofs, actual wrapper compilation and bounded analysis; serialized process and allocation guard required"]
fn actual_owned_wrapper_geometry_refuses_pair_and_keeps_singletons_incomplete() {
    assert_eq!(
        std::env::var("LATTICA_SHAKE_RECURSIVE_PREFLIGHT").as_deref(),
        Ok("1"),
        "requires explicit serialized process-guarded preflight qualification"
    );
    assert_eq!(BOUNDED_CPU_ANALYSIS_GRAPH_BYTES, 192 << 20);
    assert_eq!(
        ANALYSIS_HOST_BYTES as u64 - BOUNDED_CPU_ANALYSIS_GRAPH_BYTES,
        64 << 20
    );
    assert!(ANALYSIS_HELPER_RECIPE < 64 << 20);
    assert!(
        size_of::<(p3_air::symbolic::SymbolicExpression<Val>, usize)>() <= SYMBOLIC_HANDLE_BYTES
    );
    assert!(
        size_of::<(
            p3_air::symbolic::SymbolicExpressionExt<
                Val,
                lattica_prover_p3::block_v2::profile::Challenge,
            >,
            usize
        )>() <= SYMBOLIC_HANDLE_BYTES
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
    assert!(request_owner.belongs_to(&ledger));
    let request = request_owner.request();
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
        assert_eq!(capability.status(), Status::Ready);
        assert!(output.is_for(request));
        let summary = output.summary();
        assert_eq!(summary.independent_native_verifications, span.segment_count);
        let retained = ledger.snapshot().current;
        assert_eq!(
            retained.host,
            fixture_bytes.host
                + request_requirements.total().unwrap().host
                + requirements.get(Category::SymbolicCompiler).host
                + requirements.get(Category::CompilerInputs).host
                + requirements.get(Category::Report).host
        );
        for category in [Category::NativeProof, Category::IndependentVerifier] {
            assert_eq!(
                ledger.snapshot().categories[category as usize].current,
                Bytes::ZERO
            );
        }
        assert_eq!(
            ledger.snapshot().categories[Category::PhaseScratch as usize].current,
            fixture_bytes
        );

        // Moving the owner through a fixed queue neither duplicates nor releases
        // the compiled program, witness, report, or their reservations.
        let mut queue = [Some(output)];
        assert_eq!(ledger.snapshot().current, retained);
        let mut output = queue[0].take().unwrap();
        drop(queue);
        assert_eq!(ledger.snapshot().current, retained);

        let scratch = ledger
            .admit_phase(requirement(Category::PhaseScratch, ANALYSIS_HOST_BYTES).unwrap())
            .unwrap();
        assert_eq!(
            ledger.snapshot().current.host,
            retained.host + ANALYSIS_HOST_BYTES as u64
        );
        let air = MachineAir::from_shared_program(Arc::clone(&output.compiled.program));
        // No legacy prepare()/geometry() path: those can build an unbounded
        // symbolic graph and their LDE test is not complete peak admission.
        let analysis = analyze_bounded_cpu(&air).unwrap();
        let physical_program = output.compiled.program.retained_host_bytes().unwrap();
        let physical_inputs = (output.compiled.public.capacity()
            + output.compiled.witness.capacity())
            * size_of::<Val>();
        assert!(physical_program as u64 <= requirements.get(Category::SymbolicCompiler).host);
        assert!(physical_inputs as u64 <= requirements.get(Category::CompilerInputs).host);
        drop(air);
        drop(scratch);
        assert_eq!(ledger.snapshot().current, retained);

        let evidence = check_preflight_boundaries(&mut output, &ledger);
        let geometry = evidence.geometry;
        assert_eq!(analysis.height, geometry.height);
        assert_eq!(analysis.main_width, geometry.main_width);
        assert_eq!(analysis.preprocessed_width, geometry.preprocessed_width);
        assert_eq!(
            analysis.permutation_width_base,
            geometry.permutation_width_base
        );
        assert_eq!(analysis.quotient_chunks, geometry.quotient_chunks);
        assert_eq!(analysis.max_constraint_degree, 8);
        assert_eq!(analysis.retained_lde_bytes, geometry.retained_lde_bytes);
        assert_eq!(
            geometry.height,
            if span.segment_count == 2 {
                262_144
            } else {
                131_072
            }
        );
        assert_eq!(
            evidence.decision,
            if span.segment_count == 2 {
                Decision::RefusedUnderExistingLedgerCharges
            } else {
                Decision::IncompleteFullPhaseBound
            }
        );
        assert_eq!(evidence.charged_worker_host_bytes, retained.host);
        assert!(evidence.charged_program_host_bytes >= 2 << 30);
        eprintln!("shake_outer_preflight layout={layout:?} ordinal={ordinal} members={} active_rows={} height={} main_width={} preprocessed_width={} packed_lookups={} permutation_width_base={} quotient_chunks={} lde_rows={} lde_columns={} retained_lde_lower_bound_bytes={} included_mmcs_trees={} retained_tree_lower_bound_bytes={} required_partial_lower_bound_bytes={} physical_program_bytes={physical_program} physical_input_bytes={physical_inputs} charged_program_host_bytes={} charged_input_host_bytes={} charged_report_host_bytes={} charged_worker_host_bytes={} worker_host_allowance={} remaining_worker_host_bytes={} reason={} geometry_checked_against_bounded_analysis=true complete_footprint=false outer_registration_started=false outer_trace_started=false outer_proof_started=false native_fixture_production_already_started=true transaction_context_authenticated=false full_transaction_graph_closed=false gpu_work=false",
            span.segment_count, summary.active_rows, geometry.height, geometry.main_width,
            geometry.preprocessed_width, geometry.packed_lookups, geometry.permutation_width_base,
            geometry.quotient_chunks, geometry.lde_rows, geometry.lde_columns,
            geometry.retained_lde_bytes, geometry.included_mmcs_trees, geometry.retained_tree_bytes,
            geometry.partial_lower_bound_bytes, evidence.charged_program_host_bytes,
            evidence.charged_input_host_bytes, evidence.charged_report_host_bytes,
            evidence.charged_worker_host_bytes, evidence.worker_host_allowance,
            evidence.remaining_worker_host_bytes, evidence.decision.label());
        drop(output);
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
    eprintln!("shake_outer_preflight_complete fresh_native_proofs={fresh_native_proofs} compiled_wrappers=3 refused_pairs=1 incomplete_singletons=2 full_ledger_cleanup=true context_retired=true recursive_proofs=0 outer_proof_started=false complete_footprint=false full_transaction_graph_closed=false gpu_work=false");
}
