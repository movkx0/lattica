//! Serialized CPU ownership qualification, not a SHAKE or GPU proof producer.
//!
//! The fixed toy machine has the wrapper's public width but proves only one
//! witness/public equality. Its metadata and proofs come from the existing
//! registration API. The test never issues a dispatch/admission capability.
use super::*;
use crate::{
    component_tree::{
        owned_shake::{GroupCompilePlan, Summary},
        CompiledNode, EndpointContext,
    },
    execution::{
        phase_report::{PhaseIdentity, PhaseKind, PhaseReportOwner},
        ProvingContext,
    },
    graph_crypto::{Policy, ShakeRequestPlan, ShakeWrapperLayout},
};
use lattica_prover_p3::block_v2::machine::program::Program;
use std::sync::Arc;

const CPU_HOST_BYTES: u64 = 24 << 30;
// Test harness storage only: fixed input/context, stack moves, weak observers
// (including their still-live Arc headers/inline payload after strong drop),
// and the two deliberate, sub-KiB spare-capacity reallocations. This allowance
// is not a bound on registration, proving, or verifier scratch.
const FIXTURE_HOST_BYTES: u64 = 1 << 20;

fn require_serialized_cpu_qualification() {
    assert_eq!(
        std::env::var("LATTICA_PROVING_POLICY").as_deref(),
        Ok("cpu-required"),
        "requires the existing explicit CPU policy in a serialized process-guarded job"
    );
    for name in [
        "LATTICA_V2_GPU_HASH",
        "LATTICA_V2_GPU_RETAIN_TREES",
        "LATTICA_V2_GPU_QUERY_GATHER",
        "LATTICA_V2_GPU_RESIDENT_LDE",
        "LATTICA_V2_GPU_OPENINGS",
        "LATTICA_V2_QUOTIENT_FUSION",
        "LATTICA_V2_GPU_QUOTIENT_LDE",
        "LATTICA_V2_GPU_QUOTIENT_EVAL",
        "LATTICA_V2_GPU_QUOTIENT_RESIDENT",
        "LATTICA_V2_GPU_LOOKUP",
        "LATTICA_V2_GPU_OPENING_EVAL",
        "LATTICA_V2_GPU_FRI_RESIDENT",
        "LATTICA_V2_GPU_PCS_DEVICE_ONLY",
        "LATTICA_V2_GPU_WITNESS",
        "LATTICA_V2_GPU_RANDOMNESS",
        "LATTICA_V2_GPU_TRANSCRIPT",
        "LATTICA_V2_GPU_FRI_FOLD",
        "LATTICA_V2_GPU_PIPELINE",
        "LATTICA_V2_GPU_OPENING_DENOMINATOR_CACHE",
    ] {
        match std::env::var(name) {
            Err(std::env::VarError::NotPresent) => {}
            Ok(value) if value == "0" => {}
            _ => panic!("CPU ownership qualification requires {name} unset or 0"),
        }
    }
}

/// Private fixed fixture. It cannot stand in for a compiled SHAKE relation:
/// independent_native_verifications stays zero, so GPU preflight rejects it.
fn toy_compiled<'request>(
    request: &'request crate::graph_crypto::Request,
    ledger: &Ledger,
) -> OwnedCompiledShake<'request> {
    let plan = GroupCompilePlan::new(
        request,
        ShakeWrapperLayout::Singleton,
        0,
        EndpointContext {
            context: [17; 32],
            statement: [Val::ZERO; 4],
            input: [Val::ZERO; 4],
            output: [Val::ZERO; 4],
        },
    )
    .unwrap();
    // Reuse the actual compiler/input/report categories and keep construction
    // scratch live until both immutable program and inputs have their owners.
    let mut phase = ledger.admit_phase(plan.requirements()).unwrap();
    let program = phase.split(plan.program_requirement()).unwrap();
    let inputs = phase.split(plan.input_requirement()).unwrap();
    let report = PhaseReportOwner::from_reservation(
        phase.split(PhaseReportOwner::requirements()).unwrap(),
        ledger,
        PhaseIdentity {
            kind: PhaseKind::WrapperCompilation,
            ordinal: plan.ordinal as u64,
            first_segment: plan.span.first_segment as u64,
            segment_count: plan.span.segment_count as u8,
            profile: plan.contract.profile,
        },
    )
    .unwrap();
    let mut builder =
        ProgramBuilder::new_with_construction_limits(HEADER + 8, plan.limits).unwrap();
    let public = builder.public(0).unwrap();
    let witness = builder.input();
    builder.assert_equal(witness, public);
    let compiled = CompiledNode {
        spec: plan
            .contract
            .span(plan.span.first_unit as u32, plan.span.units as u32)
            .unwrap(),
        program: Arc::new(builder.finish(Some(64)).unwrap()),
        public: vec![Val::ZERO; HEADER + 8],
        witness: vec![Val::ZERO],
    };
    let summary = Summary {
        layout: plan.layout,
        ordinal: plan.ordinal,
        span: plan.span,
        active_rows: compiled.program.active_rows(),
        padded_rows: compiled.program.height(),
        wires: compiled.program.wire_count(),
        input_values: compiled.witness.len(),
        independent_native_verifications: 0,
    };
    let owner = OwnedCompiledShake {
        compiled,
        summary,
        request,
        report,
        _program: program,
        _inputs: inputs,
    };
    drop(phase);
    owner
}

/// The real CPU producer is reachable only in this ignored test module. Its
/// output claim already exists before registration, setup, proof, key copying,
/// or independent verification. CPU scratch has a separate enclosing token.
fn prove_cpu_under_claim(
    context: &ProvingContext,
    claim: &OutputClaim<'_, '_, '_>,
) -> (NodeKey, NodeProof) {
    let node = &claim.compiled.compiled;
    assert!(
        claim
            .token
            .requirements()
            .get(Category::RecursiveProof)
            .host
            > 0
    );
    assert!(
        claim
            .token
            .requirements()
            .get(Category::RegisteredMetadata)
            .host
            > 0
    );
    assert!(
        claim
            .token
            .requirements()
            .get(Category::IndependentVerifier)
            .host
            > 0
    );
    context
        .with_registered_shared(Arc::clone(&node.program), |registered| {
            let proof = registered.prove(&node.public, &node.witness)?;
            registered.verify(&proof, &node.public)?;
            Ok((
                NodeKey {
                    spec: node.spec.clone(),
                    height: registered.air().program().height(),
                    cap: registered.preprocessing_cap().roots().to_vec(),
                    verifier: registered.verifier(),
                },
                NodeProof {
                    public: node.public.clone(),
                    proof,
                },
            ))
        })
        .unwrap()
}

fn no_execution_authority(report: Report) {
    assert!(!report.independent_verification_complete);
    assert!(!report.authenticated_source_key);
    assert!(!report.transaction_context_authenticated);
    assert!(!report.native_production_admitted);
    assert!(!report.workflow_admitted);
    assert!(!report.footprint.enclosing_ownership_bound_complete);
    assert!(!report.footprint.dispatch_authority);
}

#[derive(Clone, Copy, Debug)]
enum Rejected {
    Spec,
    Height,
    PublicValue,
    PublicCapacity,
    KeyCapacity,
}

#[test]
#[ignore = "six fresh CPU toy-machine proofs and real registered metadata; serialized process guard required; not SHAKE/GPU qualification"]
fn genuine_key_retention_survives_context_retirement_and_rejects_mismatches() {
    require_serialized_cpu_qualification();
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 0,
    });
    let fixture = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: FIXTURE_HOST_BYTES,
                device: 0,
            },
        )
        .unwrap();
    // Weak observations retain Arc allocation headers after the last strong
    // owner drops. Keep the test fixture reservation until those observers die.
    assert!(
        4 * (size_of::<Program>()
            + size_of::<RegisteredVerifier>()
            + size_of::<NodeKey>()
            + size_of::<NodeProof>()
            + size_of::<RetainedNodeOutput<'_>>())
            < FIXTURE_HOST_BYTES as usize / 2
    );
    let input = [31; 137];
    let request_plan = ShakeRequestPlan::new(
        [7; 32],
        0,
        0,
        &input,
        137,
        Policy {
            maximum_shake_permutations: 1,
            ..Policy::default()
        },
    )
    .unwrap();
    let request_token = ledger.admit_phase(request_plan.requirements()).unwrap();
    let request = request_plan.construct(request_token, &ledger).unwrap();
    let request_bytes = ledger.snapshot().current.host - FIXTURE_HOST_BYTES;
    let compiled = toy_compiled(request.request(), &ledger);
    assert_eq!(compiled.summary.independent_native_verifications, 0);
    assert_eq!(compiled.compiled.program.height(), 64);
    let source_observer = Arc::downgrade(&compiled.compiled.program);
    let cpu = ledger
        .reserve(
            Category::PhaseScratch,
            Bytes {
                host: CPU_HOST_BYTES,
                device: 0,
            },
        )
        .unwrap();
    let context = ProvingContext::cpu(CPU_HOST_BYTES).unwrap();

    let before_output = ledger.snapshot().current;
    let claim = OutputClaim::reserve(&compiled, &request, &ledger).unwrap();
    let output_plan = claim.report();
    no_execution_authority(output_plan);
    let (key, proof) = prove_cpu_under_claim(&context, &claim);
    let retained = claim.retain(key, proof).unwrap();
    let key_observer = Arc::downgrade(&retained.key.verifier);
    assert!(core::ptr::eq(retained.request, &request));
    no_execution_authority(retained.report);
    let retained_bytes = retained.retained.requirements().total().unwrap();
    assert_eq!(retained_bytes.device, 0);
    assert_eq!(
        retained_bytes.host,
        retained.report.actual_recursive_host_bytes.unwrap()
            + retained.report.actual_key_host_bytes.unwrap()
            + retained.report.report_host_bytes
    );
    assert_eq!(
        retained
            .retained
            .requirements()
            .get(Category::IndependentVerifier),
        Bytes::ZERO
    );
    assert_eq!(
        ledger.snapshot().current.host,
        before_output.host + retained_bytes.host
    );

    // A live accepted output coexists with every new preclaim and fresh proof.
    // Mutations occur only after the genuine key/proof have been verified.
    for rejected in [
        Rejected::Spec,
        Rejected::Height,
        Rejected::PublicValue,
        Rejected::PublicCapacity,
        Rejected::KeyCapacity,
    ] {
        let before = ledger.snapshot().current;
        let strong = key_observer.strong_count();
        let claim = OutputClaim::reserve(&compiled, &request, &ledger).unwrap();
        let (mut key, mut proof) = prove_cpu_under_claim(&context, &claim);
        assert!(Arc::ptr_eq(&key.verifier, &retained.key.verifier));
        let expected = match rejected {
            Rejected::Spec => {
                key.spec.first += 1;
                Error::Identity
            }
            Rejected::Height => {
                key.height += 1;
                Error::Identity
            }
            Rejected::PublicValue => {
                proof.public[0] += Val::ONE;
                Error::Identity
            }
            Rejected::PublicCapacity => {
                proof.public.reserve_exact(1);
                assert_eq!(proof.public, compiled.compiled.public);
                assert!(proof.public.capacity() > compiled.compiled.public.capacity());
                Error::Capacity
            }
            Rejected::KeyCapacity => {
                key.cap.reserve_exact(1);
                assert_eq!(key.cap.len() as u64, output_plan.footprint.cap_roots);
                assert!(key.cap.capacity() > key.cap.len());
                Error::Capacity
            }
        };
        match claim.retain(key, proof) {
            Err(actual) => assert_eq!(actual, expected, "{rejected:?}"),
            Ok(_) => panic!("unexpected retained output for {rejected:?}"),
        }
        assert_eq!(ledger.snapshot().current, before, "{rejected:?}");
        assert_eq!(key_observer.strong_count(), strong, "{rejected:?}");
    }

    let report = context.close_without_completion().unwrap();
    assert_eq!(report["policy"], "cpu_required");
    assert_eq!(report["session_closed"], true);
    assert_eq!(report["completion_claimed"], false);
    for field in [
        "prove_calls",
        "prove_succeeded",
        "verify_calls",
        "verify_succeeded",
    ] {
        assert_eq!(report["operations"][field].as_u64(), Some(6), "{field}");
    }
    assert_eq!(report["operations"]["native_gpu_calls"].as_u64(), Some(0));
    drop(report);
    assert_eq!(key_observer.strong_count(), 1);
    drop(cpu);
    drop(compiled);
    assert!(source_observer.upgrade().is_none());
    assert_eq!(
        ledger.snapshot().current.host,
        FIXTURE_HOST_BYTES + request_bytes + retained_bytes.host
    );

    // The original output claim released verifier scratch. A fresh verifier
    // reservation is mandatory before verifying the moved, retained payload
    // after all original registration/preparation state has been destroyed.
    let verify = ledger
        .reserve(
            Category::IndependentVerifier,
            Bytes {
                host: output_plan.independent_verifier_host_bytes,
                device: 0,
            },
        )
        .unwrap();
    retained.key.verify(&retained.proof).unwrap();
    drop(verify);
    let mut moved = Some(retained);
    let retained = moved.take().unwrap();
    assert!(moved.is_none());
    drop(moved);
    assert_eq!(
        retained.retained.requirements().total().unwrap(),
        retained_bytes
    );
    drop(retained);
    assert!(key_observer.upgrade().is_none());
    drop(source_observer);
    drop(key_observer);
    drop(request);
    assert_eq!(
        ledger.snapshot().current,
        Bytes {
            host: FIXTURE_HOST_BYTES,
            device: 0
        }
    );
    drop(fixture);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    eprintln!("recursive_output_cpu_ownership_qualification cpu_only=true toy_machine=true fresh_proofs=6 retained_outputs=1 rejected_outputs=5 verified_after_retirement=true ledger_zero=true dispatch_authority=false workflow_admitted=false");
}
