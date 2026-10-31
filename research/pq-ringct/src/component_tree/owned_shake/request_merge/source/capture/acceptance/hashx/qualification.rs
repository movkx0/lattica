//! Guarded component driver: ten unchanged native segments and only paired L0.
//! No parent, complete request, transaction or final aggregate is dispatched.
use super::*;
use crate::{
    component_tree::{
        owned_shake::{
            outer_producer::{FutureHashxLeaf, PreissuedHashxLeaf, PreparedHashxLeaf},
            output::OutputRecheck,
            request_merge::{
                source::{ParentSourcePlan, VerifierHeightEnvelope},
                OpenRefusal, RefusedRequest, RequestClosurePlan, ReservedRequestClosure,
                SourceRefusal,
            },
            source_shape::{Error as SourceError, SourceShapePlan},
            CompilationFailure, Summary,
        },
        EndpointContext,
    },
    execution::retained_resources::{Snapshot, WorkerAllowance},
    graph_crypto::{
        Admission, CompletedNativeHashx, PendingNativeHashx, Policy, PreparedNativeHashx,
        ProjectedHashxQuota, ReservedNativeChild, ReservedShakeRequest, ShakeRequestPlan,
    },
};
use core::mem::{size_of, size_of_val};
use lattica_prover_p3::proving::Report;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

type DriverResult<T> = core::result::Result<T, &'static str>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Capacity,
    Gpu,
}

// Function items are type witnesses only; none is invoked by this census.
fn result1<A, R>(_: fn(A) -> R) -> usize {
    size_of::<R>()
}
fn result2<A, B, R>(_: fn(A, B) -> R) -> usize {
    size_of::<R>()
}
fn result3<A, B, C, R>(_: fn(A, B, C) -> R) -> usize {
    size_of::<R>()
}
fn result4<A, B, C, D, R>(_: fn(A, B, C, D) -> R) -> usize {
    size_of::<R>()
}
fn result5<A, B, C, D, E, R>(_: fn(A, B, C, D, E) -> R) -> usize {
    size_of::<R>()
}
fn result6<A, B, C, D, E, F, R>(_: fn(A, B, C, D, E, F) -> R) -> usize {
    size_of::<R>()
}
fn unsafe_result1<A, R>(_: unsafe fn(A) -> R) -> usize {
    size_of::<R>()
}
fn unsafe_result2<A, B, R>(_: unsafe fn(A, B) -> R) -> usize {
    size_of::<R>()
}
fn unsafe_result3<A, B, C, R>(_: unsafe fn(A, B, C) -> R) -> usize {
    size_of::<R>()
}

fn caller_requirement() -> DriverResult<Requirements> {
    let parts = [
        size_of::<[u8; 16_416]>(),
        size_of::<[u8; 137]>(),
        size_of::<Shake256>(),
        size_of::<Shake256Reader>(),
        size_of::<EndpointContext>(),
        size_of::<ShakeRequestPlan<'static>>(),
        size_of::<DriverResult<ShakeRequestPlan<'static>>>(),
        result6(ShakeRequestPlan::new_active_opt_validate_v1),
        result3(ShakeRequestPlan::construct),
        size_of::<ReservedShakeRequest>(),
        size_of::<DriverResult<ReservedShakeRequest>>(),
        size_of::<RequestClosurePlan<'static>>(),
        result1(RequestClosurePlan::requirements),
        size_of::<ReservedRequestClosure<'static>>(),
        size_of::<core::result::Result<ReservedRequestClosure<'static>, OpenRefusal>>(),
        size_of::<core::result::Result<ReservedRequestClosure<'static>, SourceRefusal<'static>>>(),
        size_of::<RefusedRequest<'static>>(),
        size_of::<core::result::Result<core::convert::Infallible, RefusedRequest<'static>>>(),
        size_of::<ParentSourcePlan<'static, 'static>>(),
        size_of::<ParentSourceBound<'static, 'static>>(),
        size_of::<Result<ParentSourcePlan<'static, 'static>>>(),
        size_of::<Result<ParentSourceBound<'static, 'static>>>(),
        size_of::<VerifierHeightEnvelope>(),
        size_of::<GroupCompilePlan<'static>>(),
        size_of::<DriverResult<GroupCompilePlan<'static>>>(),
        size_of::<SourceShapePlan<'static>>(),
        size_of::<GroupSourceBound<'static>>(),
        size_of::<core::result::Result<SourceShapePlan<'static>, SourceError>>(),
        size_of::<core::result::Result<GroupSourceBound<'static>, SourceError>>(),
        size_of::<PreissuedLeafAcceptance<'static, 'static, 'static>>(),
        size_of::<Result<PreissuedLeafAcceptance<'static, 'static, 'static>>>(),
        size_of::<FutureHashxLeaf<'static, 'static, 'static, 'static>>(),
        size_of::<PreissuedHashxLeaf<'static, 'static, 'static, 'static>>(),
        size_of::<PreparedHashxLeaf<'static, 'static, 'static, 'static>>(),
        result5(FutureHashxLeaf::reserve_before_native),
        result2(FutureHashxLeaf::complete_before_native),
        unsafe_result2(PreissuedHashxLeaf::produce_native),
        unsafe_result3(PreissuedHashxLeaf::finish_native),
        unsafe_result1(PreparedHashxLeaf::produce_authenticated_leaf),
        size_of::<PendingNativeHashx<'static>>(),
        size_of::<PreparedNativeHashx<'static>>(),
        size_of::<CompletedNativeHashx<'static>>(),
        result2(PendingNativeHashx::reserve_before_native),
        result1(PendingNativeHashx::with_outer_bridge),
        result3(PendingNativeHashx::project_outer_quota),
        size_of::<ProjectedHashxQuota>(),
        unsafe_result1(PendingNativeHashx::prepare),
        result3(PreparedNativeHashx::check_outer_request),
        result3(CompletedNativeHashx::take_next_child),
        size_of::<OutputRecheck<'static>>(),
        result4(OutputRecheck::reserve_before_native),
        result3(OutputRecheck::verify_mutations),
        size_of::<OwnedCompiledShake<'static>>(),
        size_of::<core::result::Result<OwnedCompiledShake<'static>, CompilationFailure>>(),
        size_of::<CompilationFailure>(),
        size_of::<ReservedNativeChild<'static>>(),
        size_of::<[Option<ReservedNativeChild<'static>>; 10]>(),
        size_of::<[Option<ReservedNativeChild<'static>>; 2]>(),
        size_of::<AcceptedLeaf<'static, 'static, 'static>>(),
        size_of::<AcceptedHashxLeafCompletion<'static, 'static, 'static>>(),
        size_of::<RetiredHashxLeafOriginals<'static>>(),
        size_of::<(
            AcceptedLeaf<'static, 'static, 'static>,
            RetiredHashxLeafOriginals<'static>,
        )>(),
        result2(RetiredHashxLeafOriginals::source_authentication_retirement),
        size_of::<LeafAcceptanceReport>(),
        size_of::<crate::component_tree::owned_shake::output::Report>(),
        size_of::<Summary>(),
        size_of::<Snapshot>(),
        size_of::<Requirements>(),
        size_of::<core::result::Result<Bytes, crate::execution::retained_resources::Error>>(),
        size_of::<Mode>(),
        size_of::<Reservation>(),
        size_of::<Ledger>(),
        size_of::<DriverResult<Requirements>>(),
        size_of::<DriverResult<()>>(),
        size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(),
        size_of::<std::time::Instant>(),
        size_of::<Report>(),
        size_of::<&Report>(),
        size_of::<Option<&Report>>(),
        size_of::<serde_json::Serializer<std::io::StderrLock<'static>>>(),
        size_of::<core::result::Result<(), serde_json::Error>>(),
        size_of::<serde_json::Error>(),
        size_of::<std::io::Stderr>(),
        size_of::<std::io::StderrLock<'static>>(),
        size_of::<std::fmt::Arguments<'static>>(),
        size_of::<core::result::Result<String, std::env::VarError>>(),
        size_of::<[Val; 8]>(),
        size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>(),
        // Byte commitment helper backing and complete scalar/iterator/error
        // frames are additional to every enclosing owner above.
        32 << 10,
    ];
    let helper = size_of_val(&parts)
        .checked_mul(8)
        .ok_or("caller overflow")?;
    let host = parts.into_iter().try_fold(helper, |sum, part| {
        part.checked_mul(8)
            .and_then(|part| sum.checked_add(part))
            .ok_or("caller overflow")
    })?;
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: u64::try_from(host).map_err(|_| "caller overflow")?,
            device: 0,
        },
    ))
}

fn emit_native(report: &Report) -> DriverResult<()> {
    eprint!("proving_stage_report ");
    serde_json::to_writer(std::io::stderr().lock(), report).map_err(|_| "native report")?;
    eprintln!();
    Ok(())
}

fn request(input: &[u8], ledger: &Ledger) -> DriverResult<ReservedShakeRequest> {
    let plan = ShakeRequestPlan::new_active_opt_validate_v1(
        [96; 32],
        7,
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
    .map_err(|_| "request plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "request admission")?;
    plan.construct(original, ledger)
        .map_err(|_| "request construction")
}

/// All owners created here are destroyed before `run` checks terminal quota,
/// including every returned preflight, compilation, proof, and output error.
/// # Safety
/// Gpu mode requires the coordinator's exact source/binary/environment and
/// exclusive physical-device/process guard through terminal destruction.
unsafe fn exercise(mode: Mode, ledger: &Ledger) -> DriverResult<()> {
    let caller = ledger
        .admit_phase(caller_requirement()?)
        .map_err(|_| "caller admission")?;
    if mode == Mode::Gpu {
        for (key, expected) in [
            ("LATTICA_OWNED_HASHX_FIRST_LEAF_QUALIFICATION", "1"),
            ("LATTICA_PROVING_POLICY", "gpu-required"),
            ("LATTICA_V2_GPU_RETAINED_TREE_STORAGE", "host"),
            ("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES", "8589934592"),
        ] {
            if std::env::var(key).as_deref() != Ok(expected) {
                return Err("component guard");
            }
        }
    }
    let started = std::time::Instant::now();
    let input = [7u8; 16_416];
    let mut expected_output = [0u8; 137];
    let mut xof = Shake256::default();
    xof.update(&input);
    xof.finalize_xof().read(&mut expected_output);
    let context = EndpointContext {
        // Component-only statement; this never authenticates a transaction.
        context: [97; 32],
        statement: [Val::from_u64(19); 4],
        input: crate::shake_air::commit_bytes(crate::shake_air::SHAKE_INPUT_DOMAIN, &input),
        output: crate::shake_air::commit_bytes(
            crate::shake_air::SHAKE_OUTPUT_DOMAIN,
            &expected_output,
        ),
    };
    let owner = request(&input, &ledger)?;
    // Same contents/shape and ledger, but a different original owner pointer.
    let wrong_owner = request(&input, &ledger)?;
    let plan = RequestClosurePlan::new(&owner, context.clone());
    let original = ledger
        .admit_phase(plan.requirements().map_err(|_| "request source")?)
        .map_err(|_| "request source admission")?;
    let mut closure = plan
        .open(original, &ledger)
        .map_err(|_| "request source open")?;
    for ordinal in 0..5 {
        let group = GroupCompilePlan::new(
            owner.request(),
            ShakeWrapperLayout::PairedV1,
            ordinal,
            context.clone(),
        )
        .map_err(|_| "leaf source group")?;
        let plan = group
            .source_shape_plan_existing_batches_v1(&owner, &ledger)
            .map_err(|_| "leaf source plan")?;
        let original = ledger
            .admit_phase(plan.requirements())
            .map_err(|_| "leaf source admission")?;
        let source = plan
            .inspect(original, &ledger)
            .map_err(|_| "leaf source inspection")?;
        closure = closure
            .retain_source(&group, source, &ledger)
            .map_err(|_| "leaf source handoff")?;
    }
    let plan = ParentSourcePlan::new(&closure, &ledger).map_err(|_| "parent source plan")?;
    let original = ledger
        .admit_phase(plan.requirements())
        .map_err(|_| "parent source admission")?;
    let parent_source = plan
        .inspect(original, &ledger)
        .map_err(|_| "parent source inspection")?;
    let source0 = closure.sources[0]
        .as_ref()
        .ok_or("missing original source")?;
    let group = GroupCompilePlan::new(owner.request(), ShakeWrapperLayout::PairedV1, 0, context)
        .map_err(|_| "first leaf group")?;
    let compiler = ledger
        .admit_phase(group.requirements())
        .map_err(|_| "compiler admission")?;
    let acceptance = parent_source
        .preissue_leaf_acceptance(0, &ledger)
        .map_err(|_| "leaf acceptance admission")?;
    let future =
        FutureHashxLeaf::reserve_before_native(source0, &group, &owner, acceptance, &ledger)
            .map_err(|_| "first leaf admission")?;
    let recheck = OutputRecheck::reserve_before_native(source0, &group, &owner, &ledger)
        .map_err(|_| "mutation admission")?;
    let pending = PendingNativeHashx::reserve_before_native(&owner, &ledger)
        .and_then(PendingNativeHashx::with_outer_bridge)
        .map_err(|_| "native admission")?;
    let claimed = ledger.snapshot();
    eprintln!("ringct_hashx_first_leaf_source_claims native_outputs=10 native_attachments=10 retained_leaf_sources=5 compiler_claims=1 acceptance_claims=1 mutation_claims=1 host_bytes={} device_bytes={} mode={} native_dispatch_started=false complete_request_admitted=false",
        claimed.current.host, claimed.current.device,
        if mode == Mode::Gpu { "gpu" } else { "capacity" });
    if mode == Mode::Capacity {
        let foreign = Ledger::new(WorkerAllowance {
            host: 32 << 30,
            device: 8 << 30,
        });
        if pending.project_outer_quota(&wrong_owner, ledger).is_ok()
            || pending.project_outer_quota(&owner, &foreign).is_ok()
            || ledger.snapshot() != claimed
            || foreign.snapshot().current != Bytes::ZERO
        {
            return Err("projection original request refusal");
        }
        let projection_started = std::time::Instant::now();
        let projected = pending
            .project_outer_quota(&owner, ledger)
            .map_err(|_| "original quota projection")?;
        let projection_ns = projection_started.elapsed().as_nanos();
        let after = ledger.snapshot();
        if after.current != claimed.current
            || after
                .categories
                .iter()
                .zip(&claimed.categories)
                .any(|(after, before)| after.current != before.current)
            || projected.retained_tree_host_bytes != 8 << 30
        {
            return Err("projection original quota restoration");
        }
        let host = [
            claimed.current.host,
            projected.startup.host,
            projected.phase_wrappers.host,
            projected.pcs.host,
        ]
        .into_iter()
        .try_fold(0u64, |a, b| a.checked_add(b))
        .ok_or("projected host overflow")?;
        let device = [
            claimed.current.device,
            projected.startup.device,
            projected.phase_wrappers.device,
            projected.pcs.device,
        ]
        .into_iter()
        .try_fold(0u64, |a, b| a.checked_add(b))
        .ok_or("projected device overflow")?;
        if host > 32 << 30
            || device != 8 << 30
            || after.peak.host < host
            || after.peak.device < device
        {
            return Err("projection complete simultaneous quota");
        }
        eprintln!("ringct_hashx_first_leaf_capacity_complete native_proofs=0 recursive_proofs=0 original_claims_host_bytes={} startup_host_bytes={} startup_device_bytes={} phase_wrappers_host_bytes={} phase_wrappers_device_bytes={} pcs_host_bytes={} pcs_device_bytes={} simultaneous_host_bytes={} simultaneous_device_bytes={} projection_ns={} source_preissue_ns={} wrong_request_and_ledger_refused=true original_claims_preserved=true physical_backend_fit=false native_dispatch_started=false complete_ringct_workflow=false",
            claimed.current.host, projected.startup.host, projected.startup.device,
            projected.phase_wrappers.host, projected.phase_wrappers.device,
            projected.pcs.host, projected.pcs.device, host, device, projection_ns,
            started.elapsed().as_nanos());
        return Ok(());
    }
    let mut native = unsafe { pending.prepare() }.map_err(|_| "native preparation")?;
    let before = ledger.snapshot();
    let foreign = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    if native.check_outer_request(&wrong_owner, &ledger).is_ok()
        || native.check_outer_request(&owner, &foreign).is_ok()
        || ledger.snapshot() != before
        || foreign.snapshot().current != Bytes::ZERO
    {
        return Err("original native request refusal");
    }
    native
        .check_outer_request(&owner, &ledger)
        .map_err(|_| "original native request")?;
    let future = future
        .complete_before_native(&mut native)
        .map_err(|_| "outer source completion")?;
    let admitted = ledger.snapshot();
    if admitted.current.device != 8 << 30 {
        return Err("original device admission");
    }
    let source_preissue_ns = started.elapsed().as_nanos();
    eprintln!("ringct_hashx_first_leaf_preissued native_proofs_expected=10 recursive_proofs_expected=1 source_preissue_ns={} host_bytes={} device_bytes={} wrong_request_and_ledger_refused=true native_dispatch_started=false complete_request_admitted=false",
        source_preissue_ns, admitted.current.host, admitted.current.device);
    let mut native = unsafe { future.produce_native(native) }.map_err(|_| "native production")?;
    let mut children: [Option<ReservedNativeChild<'_>>; 10] = core::array::from_fn(|_| None);
    for (index, child) in children.iter_mut().enumerate() {
        emit_native(native.report(index).ok_or("native report missing")?)?;
        let before = ledger.snapshot();
        *child = Some(
            native
                .take_next_child(index, &ledger)
                .map_err(|_| "native child handoff")?,
        );
        if ledger.snapshot() != before {
            return Err("native child claim changed");
        }
    }
    if native.retained_native_count() != 0 {
        return Err("native children remain");
    }
    let compile_started = std::time::Instant::now();
    let compiled = group
        .compile_cpu_reference([children[0].take(), children[1].take()], compiler, &ledger)
        .map_err(|_| "first leaf compilation")?;
    let compiler_ns = compile_started.elapsed().as_nanos();
    let summary = compiled.summary();
    if summary.layout != ShakeWrapperLayout::PairedV1
        || summary.ordinal != 0
        || summary.span.first_segment != 0
        || summary.span.segment_count != 2
        || summary.span.first_unit != 0
        || summary.span.units != 32
        || summary.independent_native_verifications != 2
        || summary.active_rows == 0
        || summary.active_rows > summary.padded_rows
        || !summary.padded_rows.is_power_of_two()
        || summary.padded_rows > crate::component_tree::owned_shake::MAX_ROWS
    {
        return Err("first leaf compiler coverage");
    }
    let prepared =
        unsafe { future.finish_native(native, &compiled) }.map_err(|_| "first leaf binding")?;
    let completed =
        unsafe { prepared.produce_authenticated_leaf() }.map_err(|_| "first leaf production")?;
    let (mut leaf, originals) = completed.into_parts();
    let accepted = leaf.report();
    let receipt = originals
        .source_authentication_retirement(&ledger)
        .map_err(|_| "outer retirement")?;
    if receipt != accepted.retirement
        || accepted.leaf != 0
        || accepted.height != summary.padded_rows
        || accepted.cpu_heights_admitted != 18
        || !accepted.source_key_authenticated
        || accepted.transaction_context_authenticated
        || accepted.workflow_admitted
    {
        return Err("source acceptance");
    }
    // Compile-time proof that accepted output and actual retired originals have
    // no remaining compiler borrow. No freed capacity is readmitted or reused.
    drop(compiled);
    recheck
        .verify_mutations(&mut leaf.output, &ledger)
        .map_err(|_| "typed mutation rejection")?;
    let report = leaf.output.report();
    if !report.independent_verification_complete
        || !report.authenticated_source_key
        || report.transaction_context_authenticated
        || report.workflow_admitted
    {
        return Err("first leaf output report");
    }
    eprintln!("ringct_hashx_first_leaf_complete native_proofs=10 recursive_proofs=1 recursive_parent_proofs=0 active_rows={} padded_rows={} wires={} input_values={} compiler_ns={} setup_ns={} proving_ns={} output_cpu_verification_ns={} source_cpu_verification_ns={} mutation_rejections=2 component_including_mutations_ns={} source_key_authenticated=true transaction_context_authenticated=false complete_ringct_workflow=false",
        summary.active_rows, summary.padded_rows, summary.wires, summary.input_values,
        compiler_ns, report.setup_elapsed_ns.ok_or("setup timing")?,
        report.proving_elapsed_ns.ok_or("proving timing")?,
        report.cpu_verification_elapsed_ns.ok_or("verification timing")?,
        accepted.independent_verification_ns, started.elapsed().as_nanos());
    drop(leaf);
    drop(originals);
    drop(children);
    drop(parent_source);
    let refused = match closure.require_complete() {
        Err(refused) => refused,
        Ok(impossible) => match impossible {},
    };
    if refused.report().retained_original_leaf_sources != 5 {
        return Err("request source retention");
    }
    drop(refused);
    drop(wrong_owner);
    drop(owner);
    drop(caller);
    Ok(())
}

/// # Safety
/// Gpu mode requires the coordinator guard documented on `exercise`.
unsafe fn run(mode: Mode) -> DriverResult<()> {
    let started = std::time::Instant::now();
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let result = unsafe { exercise(mode, &ledger) };
    let terminal = ledger.snapshot();
    if terminal.current != Bytes::ZERO
        || terminal.categories.iter().any(|c| c.current != Bytes::ZERO)
    {
        return Err("terminal original quota");
    }
    eprintln!("ringct_hashx_first_leaf_terminal original_quota_released=true current_host_bytes={} current_device_bytes={} peak_host_bytes={} peak_device_bytes={} component_wall_ns={} component_success={} mode={} complete_ringct_workflow=false",
        terminal.current.host, terminal.current.device, terminal.peak.host, terminal.peak.device,
        started.elapsed().as_nanos(), result.is_ok(), if mode == Mode::Gpu { "gpu" } else { "capacity" });
    result
}

#[test]
#[ignore = "exact coordinator first-HashX-leaf source/binary/environment/device guard; component only"]
fn gpu_original_hashx_first_paired_leaf_source_authenticated() {
    unsafe { run(Mode::Gpu) }.unwrap();
}

#[test]
#[ignore = "source-only original first-leaf quota projection; no device or proofs"]
fn cpu_original_hashx_first_paired_leaf_capacity() {
    unsafe { run(Mode::Capacity) }.unwrap();
}

#[test]
fn component_driver_original_caller_claim_is_exact_and_releases() {
    let requirement = caller_requirement().unwrap();
    let bytes = requirement.total().unwrap();
    assert_eq!(bytes.device, 0);
    for (host, fits) in [(bytes.host, true), (bytes.host - 1, false)] {
        let ledger = Ledger::new(WorkerAllowance { host, device: 0 });
        let original = ledger.admit_phase(requirement);
        assert_eq!(original.is_ok(), fits);
        drop(original);
        assert_eq!(ledger.snapshot().current, Bytes::ZERO);
    }
}
