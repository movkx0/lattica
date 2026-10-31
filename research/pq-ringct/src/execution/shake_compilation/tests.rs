use super::*;
use crate::{
    component_tree::{owned_shake::FailureKind, EndpointContext},
    execution::{
        phase_lifecycle::{CleanupFailure, Status},
        retained_resources::{Bytes, Category},
        ProvingContext,
    },
    graph_crypto::{NativeProductionPlan, Request, ShakeWrapperLayout},
};
use lattica_prover_p3::{
    block_v2::machine::{program::Val, ProgramBuilder},
    proving::Policy,
};
use p3_field::PrimeCharacteristicRing;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn request() -> Request {
    Request::owned_compiler_fixture(vec![31; 137], 137)
}

fn plan(request: &Request, layout: ShakeWrapperLayout) -> GroupCompilePlan<'_> {
    GroupCompilePlan::new(
        request,
        layout,
        0,
        EndpointContext {
            context: [17; 32],
            statement: [Val::from_u64(19); 4],
            input: [Val::from_u64(23); 4],
            output: [Val::from_u64(29); 4],
        },
    )
    .unwrap()
}

fn shape_child<'request>(
    request: &'request Request,
    index: usize,
    ledger: &Ledger,
) -> ReservedNativeChild<'request> {
    let plan = NativeProductionPlan::new(request, index).unwrap();
    let token = ledger.admit_phase(plan.requirement()).unwrap();
    plan.claim_for(request, index, token, ledger)
        .unwrap()
        .produce_shape_fixture()
        .unwrap()
}

fn current(ledger: &Ledger, category: Category) -> Bytes {
    ledger.snapshot().categories[category as usize].current
}

#[test]
fn admitted_handle_has_exact_plan_context_and_only_fixed_non_scratch_splits() {
    let request = request();
    let plan = plan(&request, ShakeWrapperLayout::PairedV1);
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let other = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let requirements = plan.requirements();
    let mut lease = capability.admit(requirements).unwrap();
    assert!(lease.belongs_to(&context));
    assert!(!lease.belongs_to(&other));
    let mut admitted = AdmittedShakeCompilation {
        plan: &plan,
        lease: &mut lease,
    };
    assert!(core::ptr::eq(admitted.plan(), &plan));
    let report = admitted.split_report().unwrap();
    let first = admitted.split_independent_verifier().unwrap();
    let second = admitted.split_independent_verifier().unwrap();
    assert!(admitted.split_independent_verifier().is_err());
    assert!(admitted.split_report().is_err());
    let program = admitted.split_program().unwrap();
    let inputs = admitted.split_inputs().unwrap();
    assert!(admitted.split_program().is_err());
    assert!(admitted.split_inputs().is_err());
    assert!(report.belongs_to(admitted.ledger()));
    assert_eq!(program.requirements(), plan.program_requirement());
    assert_eq!(inputs.requirements(), plan.input_requirement());
    drop(admitted);
    let scratch = requirements.get(Category::PhaseScratch);
    assert_ne!(scratch, Bytes::ZERO);
    assert_eq!(lease.backend_allowance().unwrap(), scratch);
    assert!(matches!(
        lease.split(super::super::retained_resources::Requirements::single(
            Category::PhaseScratch,
            scratch,
        )),
        Err(LifecycleError::BackendReservationCannotEscape)
    ));
    assert_eq!(ledger.snapshot().current, requirements.total().unwrap());
    drop((first, second));
    lease.complete_after_cleanup().unwrap();
    assert_eq!(current(&ledger, Category::PhaseScratch), Bytes::ZERO);
    assert_eq!(capability.status(), Status::Ready);
    assert_eq!(
        current(&ledger, Category::Report),
        requirements.get(Category::Report)
    );
    drop((report, program, inputs));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    capability.retire().unwrap();
}

#[test]
fn missing_or_foreign_children_clean_the_actual_admitted_phase() {
    let request = request();
    for foreign in [false, true] {
        let context = ProvingContext::cpu(8 << 30).unwrap();
        let other = ProvingContext::cpu(8 << 30).unwrap();
        let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
        let mut other_capability = other.phase_capability(Bytes::ZERO).unwrap();
        let ledger = capability.ledger().clone();
        let other_ledger = other_capability.ledger().clone();
        let plan = plan(&request, ShakeWrapperLayout::Singleton);
        let whole = plan.requirements().total().unwrap();
        let children = if foreign {
            [Some(shape_child(&request, 0, &other_ledger)), None]
        } else {
            [None, None]
        };
        let error = capability
            .compile_shake_cpu_reference(plan, children)
            .err()
            .expect("source ownership must refuse");
        let PhaseCompilationFailure::Compilation(mut failure) = error else {
            panic!("source rejection is followed by actual successful cleanup");
        };
        assert!(matches!(failure.kind(), FailureKind::Admission(_)));
        assert!(failure.encoded_report().is_none());
        assert_eq!(ledger.snapshot().peak, whole);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(other_ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(capability.status(), Status::Ready);
        capability.retire().unwrap();
        other_capability.retire().unwrap();
    }
}

#[test]
fn native_verification_failure_keeps_only_owned_report_after_real_cleanup() {
    let request = request();
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let children = [Some(shape_child(&request, 0, &ledger)), None];
    let error = capability
        .compile_shake_cpu_reference(plan(&request, ShakeWrapperLayout::Singleton), children)
        .err()
        .expect("deliberately invalid native fixture must refuse");
    let PhaseCompilationFailure::Compilation(mut failure) = error else {
        panic!("verification rejection must still clean the phase");
    };
    assert_eq!(failure.kind(), FailureKind::NativeVerification);
    assert!(!failure.encoded_report().unwrap().unwrap().is_empty());
    assert_eq!(
        ledger.snapshot().current,
        PhaseReportOwner::requirements().total().unwrap()
    );
    assert_eq!(capability.status(), Status::Ready);
    capability.retire().unwrap();
    drop(capability);
    assert_eq!(context.finish().unwrap()["session_closed"], true);
    assert!(!failure.encoded_report().unwrap().unwrap().is_empty());
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn source_derived_phase_refusal_precedes_verification_or_report_allocation() {
    let request = request();
    let plan = plan(&request, ShakeWrapperLayout::Singleton);
    let host = plan.requirements().total().unwrap().host;
    let context = ProvingContext::cpu(host - 1).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let error = capability
        .compile_shake_cpu_reference(plan, [None, None])
        .err()
        .expect("one-byte-short phase must refuse before compiler entry");
    assert!(matches!(
        error,
        PhaseCompilationFailure::Admission(LifecycleError::Reservation(_))
    ));
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(ledger.snapshot().peak, Bytes::ZERO);
    assert_eq!(capability.status(), Status::Ready);
    capability.retire().unwrap();
}

#[test]
fn reference_entry_refuses_gpu_policy_busy_context_and_baseline_work() {
    let request = request();
    for scenario in 0..3 {
        let mut context = ProvingContext::cpu(8 << 30).unwrap();
        if scenario == 0 {
            // Policy-only negative fixture: no GPU session or GPU work occurs.
            context.request.policy = Policy::GpuRequired;
        }
        let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
        let busy = (scenario == 1).then(|| context.registry.borrow_mut());
        if scenario == 2 {
            context.with_native_cpu(|| Ok(())).unwrap();
        }
        let error = capability
            .compile_shake_cpu_reference(
                plan(&request, ShakeWrapperLayout::Singleton),
                [None, None],
            )
            .err()
            .expect("reference-only preconditions must refuse");
        let expected = match scenario {
            0 => LifecycleError::CpuReferenceRequired,
            1 => LifecycleError::ContextBusy,
            _ => LifecycleError::WorkAlreadyStarted,
        };
        assert!(matches!(error, PhaseCompilationFailure::Admission(error) if error == expected));
        assert_eq!(capability.ledger().snapshot().peak, Bytes::ZERO);
        assert_eq!(capability.status(), Status::Ready);
        drop(busy);
        capability.retire().unwrap();
    }
}

#[test]
fn prepared_baseline_state_is_refused_before_compiler_phase_admission() {
    let request = request();
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let mut builder = ProgramBuilder::new(1).unwrap();
    let public = builder.public(0).unwrap();
    let input = builder.input();
    builder.assert_equal(public, input);
    context
        .with_registered(builder.finish(Some(8)).unwrap(), |_| Ok(()))
        .unwrap();
    let error = capability
        .compile_shake_cpu_reference(plan(&request, ShakeWrapperLayout::Singleton), [None, None])
        .err()
        .expect("prepared state belongs to a different unqualified phase");
    assert!(matches!(
        error,
        PhaseCompilationFailure::Admission(LifecycleError::PreparedStatePresent)
    ));
    assert_eq!(capability.ledger().snapshot().peak, Bytes::ZERO);
    assert_eq!(context.report()["prepared_entries"], 1);
    capability.retire().unwrap();
    assert_eq!(context.report()["prepared_entries"], 0);
}

#[test]
fn sealed_test_output_survives_actual_successful_cleanup_until_destroyed() {
    let request = request();
    let plan = plan(&request, ShakeWrapperLayout::Singleton);
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let mut lease = capability.admit(plan.requirements()).unwrap();
    let compiled = GroupCompilePlan::test_only_empty_compiler_output(AdmittedShakeCompilation {
        plan: &plan,
        lease: &mut lease,
    });
    let mut output = finish_compilation(lease, compiled).unwrap();
    assert!(output.is_for(&request));
    assert_eq!(output.summary().independent_native_verifications, 0);
    assert!(!output.encoded_report().unwrap().is_empty());
    assert_eq!(current(&ledger, Category::PhaseScratch), Bytes::ZERO);
    assert_eq!(
        current(&ledger, Category::SymbolicCompiler),
        plan.program_requirement().get(Category::SymbolicCompiler)
    );
    assert_eq!(
        current(&ledger, Category::CompilerInputs),
        plan.input_requirement().get(Category::CompilerInputs)
    );
    capability.retire().unwrap();
    assert!(!output.encoded_report().unwrap().is_empty());
    drop(output);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn cleanup_failure_discards_compiled_payload_retains_report_and_poisons_scope() {
    let request = request();
    let plan = plan(&request, ShakeWrapperLayout::Singleton);
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let scratch = plan.requirements().get(Category::PhaseScratch);
    let mut lease = capability.admit(plan.requirements()).unwrap();
    let compiled = GroupCompilePlan::test_only_empty_compiler_output(AdmittedShakeCompilation {
        plan: &plan,
        lease: &mut lease,
    });
    assert!(compiled.is_ok());
    // Exercise actual release_prepared failure, not a caller cleanup receipt.
    let busy_registry = context.registry.borrow_mut();
    let error = finish_compilation(lease, compiled)
        .err()
        .expect("compiled output cannot escape failed actual cleanup");
    let PhaseCompilationFailure::Cleanup {
        error: LifecycleError::Cleanup(CleanupFailure::PreparedRelease),
        compilation: Some(mut failure),
    } = error
    else {
        panic!("fixed cleanup code and existing report must survive");
    };
    assert_eq!(failure.kind(), FailureKind::Cleanup);
    let report: serde_json::Value =
        serde_json::from_slice(failure.encoded_report().unwrap().unwrap()).unwrap();
    assert_eq!(report["failure"]["stage"], "prepared_release");
    assert_eq!(current(&ledger, Category::SymbolicCompiler), Bytes::ZERO);
    assert_eq!(current(&ledger, Category::CompilerInputs), Bytes::ZERO);
    assert_eq!(current(&ledger, Category::PhaseScratch), scratch);
    assert_eq!(capability.status(), Status::Poisoned);
    assert!(matches!(
        capability.admit(plan.requirements()),
        Err(LifecycleError::NotReady(Status::Poisoned))
    ));
    drop(busy_registry);
    capability.retire().unwrap();
    assert_eq!(capability.status(), Status::Retired);
    assert_eq!(
        ledger.snapshot().current,
        PhaseReportOwner::requirements().total().unwrap()
    );
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn verification_error_and_actual_cleanup_error_keep_both_failure_codes() {
    let request = request();
    let plan = plan(&request, ShakeWrapperLayout::Singleton);
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let children = [Some(shape_child(&request, 0, &ledger)), None];
    let mut lease = capability.admit(plan.requirements()).unwrap();
    let compiled = GroupCompilePlan::compile_in_admitted_cpu_phase(
        AdmittedShakeCompilation {
            plan: &plan,
            lease: &mut lease,
        },
        children,
    );
    let busy_registry = context.registry.borrow_mut();
    let error = finish_compilation(lease, compiled).err().unwrap();
    let PhaseCompilationFailure::Cleanup {
        error: LifecycleError::Cleanup(CleanupFailure::PreparedRelease),
        compilation: Some(mut failure),
    } = error
    else {
        panic!("both compiler and cleanup evidence must survive");
    };
    assert_eq!(failure.kind(), FailureKind::NativeVerification);
    let report: serde_json::Value =
        serde_json::from_slice(failure.encoded_report().unwrap().unwrap()).unwrap();
    assert_eq!(report["failure"]["stage"], "native_verification");
    assert_eq!(
        current(&ledger, Category::PhaseScratch),
        plan.requirements().get(Category::PhaseScratch)
    );
    assert_eq!(capability.status(), Status::Poisoned);
    drop(failure);
    drop(busy_registry);
    capability.retire().unwrap();
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn abandoned_or_unwound_compiler_phase_retains_scratch_until_actual_retirement() {
    let request = request();
    for unwind in [false, true] {
        let plan = plan(&request, ShakeWrapperLayout::Singleton);
        let context = ProvingContext::cpu(8 << 30).unwrap();
        let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
        let ledger = capability.ledger().clone();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut lease = capability.admit(plan.requirements()).unwrap();
            let output =
                GroupCompilePlan::test_only_empty_compiler_output(AdmittedShakeCompilation {
                    plan: &plan,
                    lease: &mut lease,
                })
                .unwrap();
            if unwind {
                panic!("injected abandonment after sealed compiler output");
            }
            drop(output);
            drop(lease);
        }));
        assert_eq!(result.is_err(), unwind);
        assert_eq!(capability.status(), Status::Poisoned);
        assert_eq!(
            current(&ledger, Category::PhaseScratch),
            plan.requirements().get(Category::PhaseScratch)
        );
        assert_eq!(current(&ledger, Category::SymbolicCompiler), Bytes::ZERO);
        assert_eq!(current(&ledger, Category::CompilerInputs), Bytes::ZERO);
        capability.retire().unwrap();
        assert_eq!(capability.status(), Status::Retired);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
#[ignore = "fresh CPU native proofs and real compiler integration; serialized process guard required"]
fn fresh_native_pair_and_odd_tail_compile_through_actual_context_and_release_outputs() {
    use crate::graph_crypto::{Policy as NativePolicy, ShakeRequestPlan};

    assert_eq!(
        std::env::var("LATTICA_PHASE_SHAKE_QUALIFICATION").as_deref(),
        Ok("1"),
        "requires explicit serialized process-guarded native correctness qualification"
    );
    let input = vec![31; 137];
    let context = ProvingContext::cpu(8 << 30).unwrap();
    let mut capability = context.phase_capability(Bytes::ZERO).unwrap();
    let ledger = capability.ledger().clone();
    let request_plan = ShakeRequestPlan::new(
        [7; 32],
        0,
        0,
        &input,
        137,
        NativePolicy {
            maximum_shake_permutations: 1,
            ..NativePolicy::default()
        },
    )
    .unwrap();
    let request_requirements = request_plan.requirements();
    let token = ledger.admit_phase(request_requirements).unwrap();
    let request_owner = request_plan.construct(token, &ledger).unwrap();
    assert!(request_owner.belongs_to(&ledger));
    let request = request_owner.request();
    for (ordinal, indices) in [(0, [Some(0), Some(1)]), (1, [Some(2), None])] {
        let plan = GroupCompilePlan::new(
            request,
            ShakeWrapperLayout::PairedV1,
            ordinal,
            EndpointContext {
                context: [17; 32],
                statement: [Val::from_u64(19); 4],
                input: [Val::from_u64(23); 4],
                output: [Val::from_u64(29); 4],
            },
        )
        .unwrap();
        let requirements = plan.requirements();
        let children = indices.map(|index| {
            index.map(|index| {
                let native = NativeProductionPlan::new(request, index).unwrap();
                let token = ledger.admit_phase(native.requirement()).unwrap();
                // Fresh test producer, never a cached proof or production
                // native permit. Its CPU proof scratch is process guarded.
                native
                    .claim_for(request, index, token, &ledger)
                    .unwrap()
                    .produce_cpu_fixture()
                    .unwrap()
            })
        });
        let pre_compiler_host = ledger.snapshot().current.host;
        let mut output = capability
            .compile_shake_cpu_reference(plan, children)
            .unwrap();
        assert!(output.is_for(request));
        let summary = output.summary();
        assert_eq!(summary.ordinal, ordinal);
        assert_eq!(summary.layout, ShakeWrapperLayout::PairedV1);
        assert_eq!(summary.span.segment_count, indices.iter().flatten().count());
        assert_eq!(
            summary.independent_native_verifications,
            summary.span.segment_count
        );
        assert!(summary.active_rows > 0);
        assert!(summary.padded_rows <= 1 << 20);
        let retained_host = requirements.get(Category::SymbolicCompiler).host
            + requirements.get(Category::CompilerInputs).host
            + requirements.get(Category::Report).host
            + request_requirements.total().unwrap().host;
        assert_eq!(
            ledger.snapshot().current,
            Bytes {
                host: retained_host,
                device: 0,
            }
        );
        assert!(
            ledger.snapshot().peak.host >= pre_compiler_host + requirements.total().unwrap().host
        );
        for category in [
            Category::NativeProof,
            Category::IndependentVerifier,
            Category::PhaseScratch,
        ] {
            assert_eq!(current(&ledger, category), Bytes::ZERO);
        }
        assert_eq!(capability.status(), Status::Ready);
        let report = std::str::from_utf8(output.encoded_report().unwrap()).unwrap();
        assert!(report.contains("\"proving_reports\":[]"));
        assert!(report.contains("\"failure\":null"));
        eprintln!(
            "phase_shake_native ordinal={ordinal} members={} active_rows={} padded_rows={} wires={} inputs={} independent_native_verifications={} actual_cleanup=true outer_proofs_started=false gpu_work=false",
            summary.span.segment_count,
            summary.active_rows,
            summary.padded_rows,
            summary.wires,
            summary.input_values,
            summary.independent_native_verifications,
        );
        drop(output);
        assert_eq!(
            ledger.snapshot().current,
            request_requirements.total().unwrap()
        );
    }
    drop(request_owner);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    capability.retire().unwrap();
    assert_eq!(capability.status(), Status::Retired);
    drop(capability);
    assert_eq!(context.finish().unwrap()["session_closed"], true);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
