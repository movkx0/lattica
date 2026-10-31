use super::*;
use crate::{
    component_tree::{owned_shake::Summary, CompiledNode, EndpointContext},
    execution::{
        phase_report::{PhaseIdentity, PhaseKind, PhaseReportOwner},
        retained_resources::WorkerAllowance,
    },
    graph_crypto::{Request, ShakeWrapperLayout},
};
use lattica_prover_p3::block_v2::machine::program::ProgramBuilder;
use p3_field::PrimeCharacteristicRing;
use std::sync::Arc;

fn ledger() -> Ledger {
    Ledger::new(WorkerAllowance {
        host: 8 << 30,
        device: 0,
    })
}

// A tiny private owner fixture for accounting tests only. This is not native
// proof verification or constraint/transaction acceptance. The separate ignored
// qualification uses real native proofs and the actual compiler/lifecycle.
fn owner<'r>(request: &'r Request, ledger: &Ledger) -> OwnedCompiledShake<'r> {
    let plan = GroupCompilePlan::new(
        request,
        ShakeWrapperLayout::Singleton,
        0,
        EndpointContext {
            context: [17; 32],
            statement: [Val::from_u64(19); 4],
            input: [Val::from_u64(23); 4],
            output: [Val::from_u64(29); 4],
        },
    )
    .unwrap();
    let mut phase = ledger.admit_phase(plan.requirements()).unwrap();
    let report_token = phase.split(PhaseReportOwner::requirements()).unwrap();
    let report = PhaseReportOwner::from_reservation(
        report_token,
        ledger,
        PhaseIdentity {
            kind: PhaseKind::WrapperCompilation,
            ordinal: 0,
            first_segment: 0,
            segment_count: 1,
            profile: plan.contract.profile,
        },
    )
    .unwrap();
    let program_token = phase.split(plan.program_requirement()).unwrap();
    let input_token = phase.split(plan.input_requirement()).unwrap();
    let mut builder =
        ProgramBuilder::new_with_construction_limits(HEADER + 8, plan.limits).unwrap();
    for _ in 0..4 {
        builder.input();
    }
    let program = Arc::new(builder.finish(Some(8)).unwrap());
    let mut public = Vec::with_capacity(64);
    public.resize(HEADER + 8, Val::ZERO);
    let mut witness = Vec::with_capacity(16);
    witness.resize(4, Val::ZERO);
    let summary = Summary {
        layout: ShakeWrapperLayout::Singleton,
        ordinal: 0,
        span: plan.span(),
        active_rows: program.active_rows(),
        padded_rows: program.height(),
        wires: program.wire_count(),
        input_values: witness.len(),
        independent_native_verifications: 1,
    };
    let compiled = CompiledNode {
        spec: plan
            .contract
            .span(plan.span.first_unit as u32, plan.span.units as u32)
            .unwrap(),
        program,
        public,
        witness,
    };
    let output = OwnedCompiledShake {
        compiled,
        summary,
        request,
        report,
        _program: program_token,
        _inputs: input_token,
    };
    drop(phase);
    output
}

#[test]
fn checked_capacity_recipe_rejects_overflow() {
    assert_eq!(input_bytes(64, 16), Ok(640));
    assert_eq!(input_bytes(usize::MAX, 1), Err(Error::Overflow));
    assert_eq!(
        input_bytes(usize::MAX / size_of::<Val>() + 1, 0),
        Err(Error::Overflow)
    );
    assert_eq!(program_bytes(usize::MAX), Err(Error::Overflow));
    assert_eq!(
        program_bytes(0),
        Ok(size_of::<ExactRetainedShake<'static>>() as u64)
    );
}

#[test]
fn exact_owner_counts_spare_capacity_and_retains_receipt_through_moves() {
    let ledger = ledger();
    let request = Request::owned_compiler_fixture(vec![31; 137], 137);
    let output = owner(&request, &ledger);
    let before = ledger.snapshot();
    let source_program = output.compiled.program.retained_host_bytes().unwrap();
    let source_inputs = input_bytes(
        output.compiled.public.capacity(),
        output.compiled.witness.capacity(),
    )
    .unwrap();
    assert!(
        source_inputs
            > ((output.compiled.public.len() + output.compiled.witness.len()) * size_of::<Val>())
                as u64
    );
    let exact = retain_exact(output, &ledger).unwrap();
    let receipt = exact.receipt();
    assert!(exact.output().is_for(&request));
    assert_eq!(receipt.source_program_host, source_program as u64);
    assert_eq!(receipt.source_input_host, source_inputs);
    assert_eq!(
        receipt.retained_program_host,
        source_program as u64 + size_of::<ExactRetainedShake<'static>>() as u64
    );
    assert_eq!(receipt.retained_input_host, source_inputs);
    assert_eq!(receipt.ledger_host_before, before.current.host);
    assert_eq!(receipt.ledger_host_after, ledger.snapshot().current.host);
    assert_eq!(
        receipt.construction_program_host - receipt.retained_program_host
            + receipt.construction_input_host
            - receipt.retained_input_host,
        receipt.ledger_host_before - receipt.ledger_host_after
    );
    assert_eq!(
        ledger.snapshot().categories[Category::PhaseScratch as usize].current,
        Bytes::ZERO
    );
    assert_eq!(
        ledger.snapshot().categories[Category::Report as usize].current,
        before.categories[Category::Report as usize].current
    );
    let retained = ledger.snapshot();
    let mut queue = [Some(exact)];
    assert_eq!(ledger.snapshot(), retained);
    let exact = queue[0].take().unwrap();
    drop(queue);
    assert_eq!(exact.receipt(), receipt);
    assert_eq!(ledger.snapshot(), retained);
    drop(exact);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn wrong_ledger_and_invalid_geometry_retain_original_owner_until_failure_drop() {
    let request = Request::owned_compiler_fixture(vec![31; 137], 137);
    let ledger = ledger();
    let foreign = Ledger::new(WorkerAllowance {
        host: 8 << 30,
        device: 0,
    });
    let output = owner(&request, &ledger);
    let before = ledger.snapshot();
    let foreign_before = foreign.snapshot();
    let failure = retain_exact(output, &foreign).err().unwrap();
    assert_eq!(failure.error(), Error::Authority);
    assert_eq!(ledger.snapshot(), before);
    assert_eq!(foreign.snapshot(), foreign_before);
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);

    let mut output = owner(&request, &ledger);
    output.summary.input_values += 1;
    let before = ledger.snapshot().current;
    let failure = retain_exact(output, &ledger).err().unwrap();
    assert_eq!(failure.error(), Error::Geometry);
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + SCAN_SCRATCH_BYTES as u64
    );
    assert_eq!(
        ledger.snapshot().categories[Category::PhaseScratch as usize]
            .current
            .host,
        SCAN_SCRATCH_BYTES as u64
    );
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn insufficient_scan_headroom_never_scans_or_splits_owner_tokens() {
    let request = Request::owned_compiler_fixture(vec![31; 137], 137);
    let ledger = ledger();
    let output = owner(&request, &ledger);
    let remaining = ledger.remaining().host;
    let blocker = ledger
        .reserve(
            Category::RegisteredMetadata,
            Bytes {
                host: remaining - SCAN_SCRATCH_BYTES as u64 + 1,
                device: 0,
            },
        )
        .unwrap();
    let before = ledger.snapshot();
    let failure = retain_exact(output, &ledger).err().unwrap();
    assert_eq!(failure.error(), Error::ScanAdmission);
    assert_eq!(ledger.snapshot(), before);
    assert!(failure.transfer.scratch.is_none());
    assert!(failure.transfer.program.is_none());
    assert!(failure.transfer.inputs.is_none());
    drop(failure);
    drop(blocker);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn insufficient_retained_capacity_refuses_without_unreserved_payload() {
    let request = Request::owned_compiler_fixture(vec![31; 137], 137);
    let ledger = ledger();
    let mut output = owner(&request, &ledger);
    let exact_input = input_bytes(
        output.compiled.public.capacity(),
        output.compiled.witness.capacity(),
    )
    .unwrap();
    let shortened = output
        ._inputs
        .split(Requirements::single(
            Category::CompilerInputs,
            Bytes {
                host: exact_input - 1,
                device: 0,
            },
        ))
        .unwrap();
    // This private malformed-owner fixture keeps the surplus reservation alive
    // while testing rejection; it does not manufacture uncharged source data.
    let surplus = core::mem::replace(&mut output._inputs, shortened);
    let before = ledger.snapshot().current;
    let failure = retain_exact(output, &ledger).err().unwrap();
    assert_eq!(failure.error(), Error::Capacity);
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + SCAN_SCRATCH_BYTES as u64
    );
    assert!(failure.transfer.program.is_none());
    assert!(failure.transfer.inputs.is_none());
    drop(failure);
    drop(surplus);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn mismatched_token_category_refuses_before_scan_admission() {
    let request = Request::owned_compiler_fixture(vec![31; 137], 137);
    let ledger = ledger();
    let mut output = owner(&request, &ledger);
    let bytes = output._inputs.requirements().get(Category::CompilerInputs);
    let incorrect = ledger.reserve(Category::RegisteredMetadata, bytes).unwrap();
    let original = core::mem::replace(&mut output._inputs, incorrect);
    let before = ledger.snapshot();
    let failure = retain_exact(output, &ledger).err().unwrap();
    assert_eq!(failure.error(), Error::Authority);
    assert_eq!(ledger.snapshot(), before);
    assert!(failure.transfer.scratch.is_none());
    drop(failure);
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn second_split_failure_and_unwind_keep_both_original_charges_live() {
    let request = Request::owned_compiler_fixture(vec![31; 137], 137);
    let ledger = ledger();
    let output = owner(&request, &ledger);
    let before = ledger.snapshot().current;
    let mut transfer = Transfer::new(output);
    transfer.scratch = Some(ledger.admit_phase(scan_requirement()).unwrap());
    let mut plan = Plan::scan(transfer.output.as_ref().unwrap(), before.host).unwrap();
    // Corrupt a private derived plan only in this test, after its checked scan,
    // to exercise the impossible second-split failure without a production hook.
    plan.inputs = Requirements::single(
        Category::CompilerInputs,
        Bytes {
            host: plan.receipt.construction_input_host + 1,
            device: 0,
        },
    );
    assert_eq!(transfer.split(&plan), Err(Error::Transfer));
    assert!(transfer.program.is_some());
    assert!(transfer.inputs.is_none());
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + SCAN_SCRATCH_BYTES as u64
    );
    let failure = Failure {
        transfer,
        error: Error::Transfer,
    };
    assert_eq!(
        ledger.snapshot().current.host,
        before.host + SCAN_SCRATCH_BYTES as u64
    );
    drop(failure);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);

    let output = owner(&request, &ledger);
    let before = ledger.snapshot().current;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut transfer = Transfer::new(output);
        transfer.scratch = Some(ledger.admit_phase(scan_requirement()).unwrap());
        let plan = Plan::scan(transfer.output.as_ref().unwrap(), before.host).unwrap();
        transfer.split(&plan).unwrap();
        assert_eq!(
            ledger.snapshot().current.host,
            before.host + SCAN_SCRATCH_BYTES as u64
        );
        panic!("test unwind after both retained splits");
    }));
    assert!(result.is_err());
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
