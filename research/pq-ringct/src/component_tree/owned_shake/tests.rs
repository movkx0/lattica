use super::*;
use crate::execution::retained_resources::WorkerAllowance;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use sha3::{Digest, Sha3_256};

fn context() -> EndpointContext {
    EndpointContext {
        context: [17; 32],
        statement: [Val::from_u64(19); 4],
        input: [Val::from_u64(23); 4],
        output: [Val::from_u64(29); 4],
    }
}

fn request() -> Request {
    Request::owned_compiler_fixture(vec![31; 137], 137)
}

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 8 << 30,
        device: 0,
    })
}

fn child<'r>(
    request: &'r Request,
    index: usize,
    ledger: &Ledger,
    real: bool,
) -> ReservedNativeChild<'r> {
    let plan = NativeProductionPlan::new(request, index).unwrap();
    let token = ledger.admit_phase(plan.requirement()).unwrap();
    let pending = plan.claim_for(request, index, token, ledger).unwrap();
    if real {
        pending.produce_cpu_fixture().unwrap()
    } else {
        pending.produce_shape_fixture().unwrap()
    }
}

fn claim_failure<'request>(
    plan: GroupCompilePlan<'request>,
    children: [Option<ReservedNativeChild<'request>>; 2],
    token: Reservation,
    ledger: &Ledger,
) -> CompilationFailure {
    plan.compile_cpu_reference(children, token, ledger)
        .err()
        .expect("must refuse")
}

#[test]
fn closed_schedule_and_source_requirements_cover_pair_and_odd_tail() {
    let request = request();
    assert_eq!(request.segments().len(), 3);
    let pair = GroupCompilePlan::new(&request, ShakeWrapperLayout::PairedV1, 0, context()).unwrap();
    assert_eq!(
        pair.span(),
        ShakeWrapperSpan {
            first_segment: 0,
            segment_count: 2,
            first_unit: 0,
            units: 2,
        }
    );
    let tail = GroupCompilePlan::new(&request, ShakeWrapperLayout::PairedV1, 1, context()).unwrap();
    assert_eq!(
        tail.span(),
        ShakeWrapperSpan {
            first_segment: 2,
            segment_count: 1,
            first_unit: 2,
            units: 1,
        }
    );
    assert!(GroupCompilePlan::new(&request, ShakeWrapperLayout::PairedV1, 2, context()).is_err());
    for ordinal in 0..3 {
        let singleton =
            GroupCompilePlan::new(&request, ShakeWrapperLayout::Singleton, ordinal, context())
                .unwrap();
        assert_eq!(singleton.span().first_segment, ordinal);
        assert_eq!(singleton.span().segment_count, 1);
        assert_eq!(singleton.limits.max_requested_program_bytes, 2 << 30);
        assert_eq!(singleton.limits.max_input_values, 1 << 20);
    }
    let total = pair.requirements().total().unwrap();
    assert_eq!(total.device, 0);
    assert!(total.host < 3 << 30);
    assert_eq!(
        pair.requirements().get(Category::IndependentVerifier).host,
        128 << 20
    );
    assert_eq!(
        tail.requirements().get(Category::IndependentVerifier).host,
        64 << 20
    );
    assert_eq!(
        pair.requirements().get(Category::Report),
        PhaseReportOwner::requirements().get(Category::Report)
    );
    assert!(pair.requirements().get(Category::SymbolicCompiler).host > 2 << 30);
    assert!(pair.requirements().get(Category::CompilerInputs).host >= 16 << 20);
    assert!(pair.footprint.auxiliary_peak_bytes <= 512 << 20);
    assert!(ShakeWrapperLayout::PairedV1.require_executable().is_err());
}

#[test]
fn missing_reordered_foreign_and_wrong_arity_children_refuse_before_reports() {
    let request = request();
    let foreign = self::request(); // identical bytes still have different ownership identity
    let ledger = ledger();
    for variant in 0..5 {
        let plan =
            GroupCompilePlan::new(&request, ShakeWrapperLayout::PairedV1, 0, context()).unwrap();
        let children = match variant {
            0 => [None, None],
            1 => [Some(child(&request, 0, &ledger, false)), None],
            2 => [
                Some(child(&request, 1, &ledger, false)),
                Some(child(&request, 0, &ledger, false)),
            ],
            3 => [
                Some(child(&foreign, 0, &ledger, false)),
                Some(child(&request, 1, &ledger, false)),
            ],
            _ => [
                Some(child(&request, 0, &ledger, false)),
                Some(child(&request, 2, &ledger, false)),
            ],
        };
        let token = ledger.admit_phase(plan.requirements()).unwrap();
        let mut failure = claim_failure(plan, children, token, &ledger);
        assert_eq!(failure.kind(), FailureKind::Admission(IDENTITY));
        assert!(failure.encoded_report().is_none());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
    let plan = GroupCompilePlan::new(&request, ShakeWrapperLayout::PairedV1, 1, context()).unwrap();
    let children = [
        Some(child(&request, 2, &ledger, false)),
        Some(child(&request, 2, &ledger, false)),
    ];
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    assert_eq!(
        claim_failure(plan, children, token, &ledger).kind(),
        FailureKind::Admission(IDENTITY)
    );
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn wrong_phase_tokens_and_foreign_native_tokens_refuse_without_attachment() {
    let request = request();
    let ledger = ledger();
    let foreign = self::ledger();
    for variant in 0..3 {
        let plan =
            GroupCompilePlan::new(&request, ShakeWrapperLayout::Singleton, 0, context()).unwrap();
        let children = [Some(child(&request, 0, &ledger, false)), None];
        let token = match variant {
            0 => foreign.admit_phase(plan.requirements()).unwrap(),
            1 => {
                let mut required = plan.requirements();
                required
                    .add(Category::Report, Bytes { host: 1, device: 0 })
                    .unwrap();
                ledger.admit_phase(required).unwrap()
            }
            _ => ledger.admit_phase(plan.program).unwrap(),
        };
        let mut failure = claim_failure(plan, children, token, &ledger);
        assert_eq!(failure.kind(), FailureKind::Admission(AUTHORITY));
        assert!(failure.encoded_report().is_none());
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
        assert_eq!(foreign.snapshot().current, Bytes::ZERO);
    }
    let plan =
        GroupCompilePlan::new(&request, ShakeWrapperLayout::Singleton, 0, context()).unwrap();
    let children = [Some(child(&request, 0, &foreign, false)), None];
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    assert_eq!(
        claim_failure(plan, children, token, &ledger).kind(),
        FailureKind::Admission(IDENTITY)
    );
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    assert_eq!(foreign.snapshot().current, Bytes::ZERO);
}

#[test]
fn invalid_native_proof_retains_only_bounded_failure_report_until_drop() {
    let request = request();
    let ledger = ledger();
    let plan =
        GroupCompilePlan::new(&request, ShakeWrapperLayout::Singleton, 0, context()).unwrap();
    let children = [Some(child(&request, 0, &ledger, false)), None];
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let mut failure = claim_failure(plan, children, token, &ledger);
    assert_eq!(failure.kind(), FailureKind::NativeVerification);
    assert!(failure.resource_refusal().is_none());
    assert_eq!(
        ledger.snapshot().current,
        PhaseReportOwner::requirements().total().unwrap()
    );
    let bytes = failure.encoded_report().unwrap().unwrap();
    let encoded = std::str::from_utf8(bytes).unwrap();
    assert!(encoded.contains("\"stage\":\"native_verification\""));
    assert!(encoded.contains("\"retry_attempted\":false"));
    assert!(encoded.contains("\"dispatch_authorized\":false"));
    let moved = failure;
    drop(moved);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

fn admitted() {
    assert_eq!(
        std::env::var("LATTICA_OWNED_SHAKE_QUALIFICATION").as_deref(),
        Ok("1"),
        "requires explicit serialized process-guarded native correctness qualification"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct Signature {
    program: [u8; 32],
    inputs: [u8; 32],
    public: [Val; HEADER + 8],
    active: usize,
    padded: usize,
    wires: usize,
    input_count: usize,
}

fn signature(node: &CompiledNode) -> Signature {
    let mut program = Sha3_256::new();
    node.program
        .visit_manifest_fields(&mut |field| {
            program.update(field.to_le_bytes());
            Ok(())
        })
        .unwrap();
    let mut inputs = Sha3_256::new();
    for value in &node.witness {
        inputs.update(value.as_canonical_u64().to_le_bytes());
    }
    Signature {
        program: program.finalize().into(),
        inputs: inputs.finalize().into(),
        public: node.public.as_slice().try_into().unwrap(),
        active: node.program.active_rows(),
        padded: node.program.height(),
        wires: node.program.wire_count(),
        input_count: node.witness.len(),
    }
}

fn reference_signature(
    plan: &GroupCompilePlan<'_>,
    children: &[Option<ReservedNativeChild<'_>>; 2],
) -> Signature {
    let member = |offset: usize| {
        let child = children[offset].as_ref().unwrap();
        let info = &plan.request.segments()[child.index()];
        let proof = child.shake_artifact();
        ShakeGroupMember {
            first: info.first_unit as u32,
            count: info.units as u32,
            proof,
        }
    };
    let members = [
        member(0),
        member(if plan.span.segment_count == 2 { 1 } else { 0 }),
    ];
    // Existing reference comparator remains externally process guarded, outside
    // the new owner API's source accounting. Only its fixed digest survives;
    // never overlap two large compiled programs or claim a reference receipt.
    let reference = super::super::compile_shake_group_with_context(
        &plan.contract,
        &members[..plan.span.segment_count],
        &plan.context,
        None,
    )
    .unwrap();
    signature(&reference)
}

#[test]
#[ignore = "real CPU native children and recursive verifier compilation; serialized process guard required"]
fn real_native_pair_and_odd_tail_match_reference_and_release_owned_storage() {
    admitted();
    let request = request();
    let ledger = ledger();
    for (ordinal, indices) in [(0, [Some(0), Some(1)]), (1, [Some(2), None])] {
        let plan =
            GroupCompilePlan::new(&request, ShakeWrapperLayout::PairedV1, ordinal, context())
                .unwrap();
        let children =
            indices.map(|index| index.map(|index| child(&request, index, &ledger, true)));
        let expected = reference_signature(&plan, &children);
        let kept = combine(&[plan.program, plan.inputs, PhaseReportOwner::requirements()]).unwrap();
        let whole = plan.requirements();
        let native = ledger.snapshot().current.host;
        let token = ledger.admit_phase(whole).unwrap();
        let mut output = plan
            .compile_cpu_reference(children, token, &ledger)
            .unwrap();
        assert_eq!(signature(&output.compiled), expected);
        assert!(output.is_for(&request));
        assert_eq!(
            output.summary().independent_native_verifications,
            indices.into_iter().flatten().count()
        );
        assert_eq!(ledger.snapshot().current, kept.total().unwrap());
        assert!(ledger.snapshot().peak.host >= native + whole.total().unwrap().host);
        for category in [
            Category::NativeProof,
            Category::IndependentVerifier,
            Category::PhaseScratch,
        ] {
            assert_eq!(
                ledger.snapshot().categories[category as usize].current,
                Bytes::ZERO
            );
        }
        let report = std::str::from_utf8(output.encoded_report().unwrap()).unwrap();
        assert!(report.contains("\"proving_reports\":[]"));
        assert!(report.contains("\"failure\":null"));
        let summary = output.summary();
        eprintln!("owned_shake_reference ordinal={ordinal} members={} active_rows={} padded_rows={} wires={} inputs={} independent_native_verifications={} reference_match=true outer_proofs_started=false gpu_work=false",
            summary.span.segment_count, summary.active_rows, summary.padded_rows, summary.wires,
            summary.input_values, summary.independent_native_verifications);
        let moved = output;
        drop(moved);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}

#[test]
#[ignore = "real CPU native child and compiler refusal; serialized process guard required"]
fn real_native_child_compiler_refusal_retains_report_and_does_not_retry() {
    admitted();
    let request = Request::owned_compiler_fixture(Vec::new(), 32);
    let ledger = ledger();
    let mut plan =
        GroupCompilePlan::new(&request, ShakeWrapperLayout::Singleton, 0, context()).unwrap();
    // Test-only access to the private plan forces the real compiler refusal.
    // Production constructors never accept an arbitrary numeric limit/token.
    plan.limits.max_requested_program_bytes = 0;
    plan.derive_requirements().unwrap();
    let children = [Some(child(&request, 0, &ledger, true)), None];
    let token = ledger.admit_phase(plan.requirements()).unwrap();
    let mut failure = claim_failure(plan, children, token, &ledger);
    assert_eq!(failure.kind(), FailureKind::ResourceRefused);
    assert_eq!(
        failure.resource_refusal().unwrap().phase,
        super::super::ShakeGroupCompilePhase::Initialize
    );
    assert_eq!(
        ledger.snapshot().current,
        PhaseReportOwner::requirements().total().unwrap()
    );
    let report = std::str::from_utf8(failure.encoded_report().unwrap().unwrap()).unwrap();
    assert!(report.contains("\"stage\":\"compilation\""));
    assert!(report.contains("\"retry_attempted\":false"));
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
