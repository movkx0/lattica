//! Exact fixed-fixture native successor qualification. Production PairedV1
//! remains disabled; all native segments precede every recursive wrapper.
use super::*;
use crate::{
    component_tree::{
        owned_shake::{
            source_shape::{GroupSourceBound, SourceShapePlan},
            CompilationFailure, Summary,
        },
        EndpointContext, Val,
    },
    execution::retained_resources::{Snapshot, WorkerAllowance},
    graph_crypto::{
        FutureNativeSingleton, OuterContinuationCapacity, Policy as ProofPolicy,
        PreparedNativeSingleton, PreparedNativeSingletonAttachment, ReadyNativeSingleton,
        ReservedNativeChild, ShakeRequestPlan, ShakeWrapperLayout, ShakeWrapperSpan,
        VerifiedNativeSingleton, VerifiedNativeSingletonWithOriginals,
    },
};
use p3_field::PrimeCharacteristicRing;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256, Shake256Reader,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SequenceShape {
    Pair,
    PairAndTail,
}

impl SequenceShape {
    fn native_count(self) -> usize {
        match self {
            Self::Pair => 2,
            Self::PairAndTail => 3,
        }
    }
    fn group_count(self) -> usize {
        self.native_count() - 1
    }
    fn input_len(self) -> usize {
        match self {
            Self::Pair => 1,
            Self::PairAndTail => 137,
        }
    }
    fn flag(self) -> &'static str {
        match self {
            Self::Pair => "LATTICA_OWNED_SHAKE_PAIR_SEQUENCE_QUALIFICATION",
            Self::PairAndTail => "LATTICA_OWNED_SHAKE_ODD_TAIL_SEQUENCE_QUALIFICATION",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Pair => "pair",
            Self::PairAndTail => "pair-and-tail",
        }
    }
    fn check(self, owner: &ReservedShakeRequest, ledger: &Ledger) -> Result<()> {
        if !owner.belongs_to(ledger) || owner.request().segments().len() != self.native_count() {
            return Err(Error::Authority);
        }
        for (index, segment) in owner.request().segments().iter().enumerate() {
            if segment.first_unit != index
                || segment.units != 1
                || segment.height != 4096
                || segment.width != 517
            {
                return Err(Error::Shape);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct GroupMetrics {
    active_rows: usize,
    padded_rows: usize,
    compiler_ns: u128,
    setup_ns: u128,
    proving_ns: u128,
    cpu_verification_ns: u128,
}

impl GroupMetrics {
    fn from_output(
        summary: Summary,
        compiler_ns: u128,
        output: &output::RetainedNodeOutput<'_>,
    ) -> Result<Self> {
        let report = output.report();
        if !report.independent_verification_complete {
            return Err(Error::Authority);
        }
        Ok(Self {
            active_rows: summary.active_rows,
            padded_rows: summary.padded_rows,
            compiler_ns,
            setup_ns: report.setup_elapsed_ns.ok_or(Error::Authority)?,
            proving_ns: report.proving_elapsed_ns.ok_or(Error::Authority)?,
            cpu_verification_ns: report.cpu_verification_elapsed_ns.ok_or(Error::Authority)?,
        })
    }
}

// Infer complete native Result layouts from the actual method signatures.
// Their error type is private to the native producer; no method is called.
fn native_constructor_result_bytes<R>(
    _: unsafe fn(&'static ReservedShakeRequest, usize, &Ledger) -> R,
) -> usize {
    size_of::<R>()
}

fn attachment_constructor_result_bytes<R>(
    _: fn(&'static ReservedShakeRequest, usize, &Ledger) -> R,
) -> usize {
    size_of::<R>()
}

fn native_producer_result_bytes<R>(_: unsafe fn(PreparedNativeSingleton<'static>) -> R) -> usize {
    size_of::<R>()
}

fn attachment_result_bytes<R>(
    _: fn(
        PreparedNativeSingletonAttachment<'static>,
        VerifiedNativeSingleton<'static>,
        &Ledger,
    ) -> R,
) -> usize {
    size_of::<R>()
}

fn sequence_requirement() -> Result<Requirements> {
    // Every fixed sequence owner is charged before the fixture or request is
    // constructed. Full owning Option/Result/tuple slots are additive; no
    // compiler move-elision or later native/outer release increases PCS.
    let mut host = FutureNativeSingleton::additional_sequence_caller_host_bytes(2)
        .map_err(|_| Error::Shape)?;
    for bytes in [
        8 * size_of::<SequenceShape>(),
        8 * size_of::<GroupMetrics>(),
        4 * size_of::<Result<GroupMetrics>>(),
        4 * size_of::<Option<GroupMetrics>>(),
        4 * size_of::<[Option<GroupMetrics>; 2]>(),
        2 * size_of::<std::array::IntoIter<Option<GroupMetrics>, 2>>(),
        4 * size_of::<[GroupMetrics; 2]>(),
        4 * size_of::<ShakeRequestPlan<'static>>(),
        4 * size_of::<Result<ShakeRequestPlan<'static>>>(),
        4 * size_of::<ReservedShakeRequest>(),
        4 * size_of::<Result<ReservedShakeRequest>>(),
        4 * size_of::<EndpointContext>(),
        4 * size_of::<GroupCompilePlan<'static>>(),
        4 * size_of::<Result<GroupCompilePlan<'static>>>(),
        4 * size_of::<Option<GroupCompilePlan<'static>>>(),
        4 * size_of::<core::result::Result<GroupCompilePlan<'static>, &'static str>>(),
        4 * size_of::<SourceShapePlan<'static>>(),
        4 * size_of::<Result<SourceShapePlan<'static>>>(),
        4 * size_of::<
            core::result::Result<
                SourceShapePlan<'static>,
                crate::component_tree::owned_shake::source_shape::Error,
            >,
        >(),
        4 * size_of::<
            core::result::Result<
                GroupSourceBound<'static>,
                crate::component_tree::owned_shake::source_shape::Error,
            >,
        >(),
        4 * size_of::<GroupSourceBound<'static>>(),
        4 * size_of::<Result<GroupSourceBound<'static>>>(),
        4 * size_of::<Option<GroupSourceBound<'static>>>(),
        4 * size_of::<FutureOuter<'static, 'static, 'static>>(),
        4 * size_of::<Option<FutureOuter<'static, 'static, 'static>>>(),
        4 * size_of::<Result<FutureOuter<'static, 'static, 'static>>>(),
        4 * size_of::<ReadyOuter<'static, 'static, 'static>>(),
        4 * size_of::<Option<ReadyOuter<'static, 'static, 'static>>>(),
        4 * size_of::<Result<ReadyOuter<'static, 'static, 'static>>>(),
        4 * size_of::<Option<Result<ReadyOuter<'static, 'static, 'static>>>>(),
        4 * size_of::<Result<Option<ReadyOuter<'static, 'static, 'static>>>>(),
        4 * size_of::<Continuation<'static, 'static, 'static>>(),
        4 * size_of::<Result<Continuation<'static, 'static, 'static>>>(),
        4 * size_of::<output::OutputRecheck<'static>>(),
        4 * size_of::<core::result::Result<output::OutputRecheck<'static>, output::Error>>(),
        4 * size_of::<Option<output::OutputRecheck<'static>>>(),
        4 * size_of::<output::RetainedNodeOutput<'static>>(),
        4 * size_of::<Result<output::RetainedNodeOutput<'static>>>(),
        4 * size_of::<OwnedCompiledShake<'static>>(),
        4 * size_of::<Result<OwnedCompiledShake<'static>>>(),
        4 * size_of::<Option<OwnedCompiledShake<'static>>>(),
        4 * size_of::<core::result::Result<OwnedCompiledShake<'static>, CompilationFailure>>(),
        4 * size_of::<PreparedNativeSingletonAttachment<'static>>(),
        4 * size_of::<Option<PreparedNativeSingletonAttachment<'static>>>(),
        4 * size_of::<ReservedNativeChild<'static>>(),
        4 * size_of::<Option<ReservedNativeChild<'static>>>(),
        4 * size_of::<Result<ReservedNativeChild<'static>>>(),
        4 * size_of::<[Option<ReservedNativeChild<'static>>; 2]>(),
        4 * size_of::<(
            ReservedNativeChild<'static>,
            Option<ReservedNativeChild<'static>>,
            RetiredNativeReservations,
        )>(),
        4 * size_of::<(VerifiedNativeSingleton<'static>, RetiredNativeReservations)>(),
        4 * size_of::<VerifiedNativeSingletonWithOriginals<'static>>(),
        4 * size_of::<(
            VerifiedNativeSingletonWithOriginals<'static>,
            Option<ReadyNativeSingleton<'static>>,
        )>(),
        4 * size_of::<outer_continuation::RetiredOuterOriginals<'static>>(),
        4 * size_of::<outer_continuation::ContinuedOuter<'static>>(),
        4 * size_of::<Result<outer_continuation::ContinuedOuter<'static>>>(),
        4 * size_of::<(
            output::RetainedNodeOutput<'static>,
            outer_continuation::RetiredOuterOriginals<'static>,
        )>(),
        4 * size_of::<(
            Option<GroupCompilePlan<'static>>,
            Option<Reservation>,
            Option<ReservedNativeChild<'static>>,
            Option<ReadyOuter<'static, 'static, 'static>>,
            Option<output::OutputRecheck<'static>>,
        )>(),
        4 * size_of::<OuterContinuationCapacity>(),
        4 * size_of::<FutureNativeSingleton<'static>>(),
        4 * size_of::<Option<FutureNativeSingleton<'static>>>(),
        4 * size_of::<Result<FutureNativeSingleton<'static>>>(),
        4 * size_of::<ReadyNativeSingleton<'static>>(),
        4 * size_of::<Option<ReadyNativeSingleton<'static>>>(),
        4 * size_of::<Result<ReadyNativeSingleton<'static>>>(),
        4 * size_of::<PreparedNativeSingleton<'static>>(),
        4 * size_of::<Result<PreparedNativeSingleton<'static>>>(),
        8 * size_of::<Result<VerifiedNativeSingletonWithOriginals<'static>>>(),
        8 * size_of::<
            Result<(
                VerifiedNativeSingleton<'static>,
                PreparedNativeSingleton<'static>,
            )>,
        >(),
        4 * native_constructor_result_bytes(PreparedNativeSingleton::new_outer_host_v1),
        4 * attachment_constructor_result_bytes(
            PreparedNativeSingletonAttachment::reserve_before_native,
        ),
        8 * native_producer_result_bytes(PreparedNativeSingleton::produce_retaining_originals),
        8 * attachment_result_bytes(PreparedNativeSingletonAttachment::attach),
        4 * size_of::<Result<PreparedNativeSingletonAttachment<'static>>>(),
        24 * size_of::<Snapshot>(),
        16 * size_of::<Requirements>(),
        16 * size_of::<Reservation>(),
        8 * size_of::<Option<Reservation>>(),
        8 * size_of::<Result<Reservation>>(),
        8 * size_of::<core::result::Result<Reservation, crate::execution::retained_resources::Error>>(
        ),
        16 * size_of::<usize>(),
        8 * size_of::<std::time::Instant>(),
        8 * size_of::<Summary>(),
        4 * size_of::<ShakeWrapperSpan>(),
        4 * size_of::<[u8; 273]>(),
        2 * size_of::<Shake256>(),
        2 * size_of::<Shake256Reader>(),
        (2 * 4 * 8 + 22) * size_of::<Val>(),
        size_of::<p3_goldilocks::Poseidon2Goldilocks<8>>(),
        4 * size_of::<[Val; 8]>(),
        4 * size_of::<serde_json::Serializer<std::io::StderrLock<'static>>>(),
        4 * size_of::<core::result::Result<(), serde_json::Error>>(),
        4 * size_of::<serde_json::Error>(),
        4 * size_of::<std::io::Stderr>(),
        4 * size_of::<std::io::StderrLock<'static>>(),
        8 * size_of::<std::fmt::Arguments<'static>>(),
    ] {
        host = host.checked_add(bytes).ok_or(Error::Shape)?;
    }
    Ok(Requirements::single(
        Category::PhaseScratch,
        Bytes {
            host: host as u64,
            device: 0,
        },
    ))
}

fn emit_native(verified: &VerifiedNativeSingleton<'_>) -> Result<()> {
    eprint!("proving_stage_report ");
    serde_json::to_writer(std::io::stderr().lock(), verified.report())
        .map_err(|_| Error::Report)?;
    eprintln!();
    Ok(())
}

fn attach<'request>(
    attachment: PreparedNativeSingletonAttachment<'request>,
    verified: VerifiedNativeSingleton<'request>,
    ledger: &Ledger,
) -> Result<ReservedNativeChild<'request>> {
    emit_native(&verified)?;
    let before = ledger.snapshot();
    let child = attachment
        .attach(verified, ledger)
        .map_err(|_| Error::Authority)?;
    if ledger.snapshot() != before {
        return Err(Error::Authority);
    }
    Ok(child)
}

/// # Safety
/// Same exact recorded immutable host profile and exclusive GPU process from
/// first source preissue through all native/outer actual runtime retirements.
unsafe fn run(shape: SequenceShape) -> Result<()> {
    for (name, value) in [
        (shape.flag(), "1"),
        ("LATTICA_PROVING_POLICY", "gpu-required"),
        ("LATTICA_V2_GPU_RETAINED_TREE_STORAGE", "host"),
        ("LATTICA_V2_GPU_RETAINED_TREE_HOST_BYTES", "8589934592"),
    ] {
        if std::env::var(name).as_deref() != Ok(value) {
            return Err(Error::Authority);
        }
    }
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let sequence = ledger
        .admit_phase(sequence_requirement()?)
        .map_err(|_| Error::Shape)?;
    let started = std::time::Instant::now();
    let input = [7u8; 137];
    let mut expected_output = [0u8; 137];
    let input = &input[..shape.input_len()];
    let mut xof = Shake256::default();
    xof.update(input);
    xof.finalize_xof().read(&mut expected_output);
    let endpoints = EndpointContext {
        // Component placeholders; byte endpoints are independently derived.
        context: [97; 32],
        statement: [Val::from_u64(19); 4],
        input: crate::shake_air::commit_bytes(crate::shake_air::SHAKE_INPUT_DOMAIN, input),
        output: crate::shake_air::commit_bytes(
            crate::shake_air::SHAKE_OUTPUT_DOMAIN,
            &expected_output,
        ),
    };
    let request = ShakeRequestPlan::new([96; 32], 7, 0, input, 137, ProofPolicy::default())
        .map_err(|_| Error::Shape)?;
    let request_claim = ledger
        .admit_phase(request.requirements())
        .map_err(|_| Error::Shape)?;
    let owner = request
        .construct(request_claim, &ledger)
        .map_err(|_| Error::Shape)?;
    shape.check(&owner, &ledger)?;
    let group0 = GroupCompilePlan::new(
        owner.request(),
        ShakeWrapperLayout::PairedV1,
        0,
        endpoints.clone(),
    )
    .map_err(|_| Error::Shape)?;
    let group1 = if shape == SequenceShape::PairAndTail {
        Some(
            GroupCompilePlan::new(owner.request(), ShakeWrapperLayout::PairedV1, 1, endpoints)
                .map_err(|_| Error::Shape)?,
        )
    } else {
        None
    };
    if group0.span()
        != (ShakeWrapperSpan {
            first_segment: 0,
            segment_count: 2,
            first_unit: 0,
            units: 2,
        })
        || group1.as_ref().is_some_and(|group| {
            group.span()
                != (ShakeWrapperSpan {
                    first_segment: 2,
                    segment_count: 1,
                    first_unit: 2,
                    units: 1,
                })
        })
    {
        return Err(Error::Shape);
    }
    let plan0 = group0
        .source_shape_plan(&owner, &ledger)
        .map_err(|_| Error::Shape)?;
    let claim0 = ledger
        .admit_phase(plan0.requirements())
        .map_err(|_| Error::Shape)?;
    let source0 = plan0.inspect(claim0, &ledger).map_err(|_| Error::Shape)?;
    let source1 = match group1.as_ref() {
        Some(group) => {
            let plan = group
                .source_shape_plan(&owner, &ledger)
                .map_err(|_| Error::Shape)?;
            let claim = ledger
                .admit_phase(plan.requirements())
                .map_err(|_| Error::Shape)?;
            Some(plan.inspect(claim, &ledger).map_err(|_| Error::Shape)?)
        }
        None => None,
    };
    let compiler0 = ledger
        .admit_phase(group0.requirements())
        .map_err(|_| Error::Shape)?;
    let compiler1 = match group1.as_ref() {
        Some(group) => Some(
            ledger
                .admit_phase(group.requirements())
                .map_err(|_| Error::Shape)?,
        ),
        None => None,
    };
    let attachment0 = PreparedNativeSingletonAttachment::reserve_before_native(&owner, 0, &ledger)
        .map_err(|_| Error::Shape)?;
    let attachment1 = PreparedNativeSingletonAttachment::reserve_before_native(&owner, 1, &ledger)
        .map_err(|_| Error::Shape)?;
    let attachment2 = if shape == SequenceShape::PairAndTail {
        Some(
            PreparedNativeSingletonAttachment::reserve_before_native(&owner, 2, &ledger)
                .map_err(|_| Error::Shape)?,
        )
    } else {
        None
    };
    let outer0 = FutureOuter::reserve_before_native(&source0, &group0, &owner, &ledger)?;
    let outer1 = match (source1.as_ref(), group1.as_ref()) {
        (Some(source), Some(group)) => Some(FutureOuter::reserve_before_native(
            source, group, &owner, &ledger,
        )?),
        (None, None) => None,
        _ => return Err(Error::Shape),
    };
    let recheck0 = output::OutputRecheck::reserve_before_native(&source0, &group0, &owner, &ledger)
        .map_err(Error::Output)?;
    let recheck1 = match (source1.as_ref(), group1.as_ref()) {
        (Some(source), Some(group)) => Some(
            output::OutputRecheck::reserve_before_native(source, group, &owner, &ledger)
                .map_err(Error::Output)?,
        ),
        (None, None) => None,
        _ => return Err(Error::Shape),
    };
    let successor1 = FutureNativeSingleton::reserve_before_native(&owner, 1, &ledger)
        .map_err(|_| Error::Shape)?;
    let successor2 = if shape == SequenceShape::PairAndTail {
        Some(
            FutureNativeSingleton::reserve_before_native(&owner, 2, &ledger)
                .map_err(|_| Error::Shape)?,
        )
    } else {
        None
    };
    // All future source/proof/compiler/output/verifier owners already exist.
    let first = unsafe { PreparedNativeSingleton::new_outer_host_v1(&owner, 0, &ledger) }
        .map_err(|_| Error::Runtime)?;
    let capacity = first
        .outer_continuation_capacity()
        .map_err(|_| Error::Shape)?;
    let successor1 = successor1
        .complete_before_native(&first)
        .map_err(|_| Error::Shape)?;
    let successor2 = match successor2 {
        Some(next) => Some(
            next.complete_before_native(&first)
                .map_err(|_| Error::Shape)?,
        ),
        None => None,
    };
    let outer0 = outer0.complete_before_native(
        capacity.startup,
        capacity.pcs,
        capacity.retained_tree_host_bytes,
    )?;
    let outer1 = outer1
        .map(|next| {
            next.complete_before_native(
                capacity.startup,
                capacity.pcs,
                capacity.retained_tree_host_bytes,
            )
        })
        .transpose()?;
    let admitted = ledger.snapshot();
    if admitted.current.device != 8 << 30 {
        return Err(Error::Authority);
    }
    eprintln!("ringct_native_sequence_preissued shape={} native_proofs_expected={} recursive_proofs_expected={} all_source_bounds_complete=true original_phase_owners_live=true native_dispatch_started=false host_bytes={} device_bytes={}",
        shape.name(), shape.native_count(), shape.group_count(), admitted.current.host, admitted.current.device);
    let source_preissue_ns = started.elapsed().as_nanos();
    let produced0 = unsafe { first.produce_retaining_originals() }.map_err(|_| Error::Proof)?;
    // A controlled typed-handoff refusal probe for the component qualifier:
    // native0 cannot enter preissued native2. This checks no proof dispatch,
    // plan or admission; it must return both complete owners unchanged.
    let (produced0, successor2) = match successor2 {
        Some(next) => {
            let before = ledger.snapshot();
            match next.finish_native(produced0) {
                Err((_, next, previous)) => {
                    if ledger.snapshot() != before {
                        return Err(Error::Authority);
                    }
                    eprintln!("ringct_native_sequence_handoff_refusal shape={} previous_index=0 refused_next_index=2 complete_owners_returned=true ledger_snapshot_unchanged=true proof_dispatch_attempted=false",
                        shape.name());
                    (previous, Some(next))
                }
                Ok(_) => return Err(Error::Authority),
            }
        }
        None => (produced0, None),
    };
    let before = ledger.snapshot();
    let (verified0, next1) = successor1
        .finish_native(produced0)
        .map_err(|_| Error::Runtime)?;
    if ledger.snapshot() != before {
        return Err(Error::Authority);
    }
    let child0 = attach(attachment0, verified0, &ledger)?;
    let produced1 = unsafe { next1.produce_retaining_originals() }.map_err(|_| Error::Proof)?;
    let (child1, child2, originals) = match (successor2, attachment2) {
        (Some(successor), Some(attachment)) => {
            let before = ledger.snapshot();
            let (verified1, next2) = successor
                .finish_native(produced1)
                .map_err(|_| Error::Runtime)?;
            if ledger.snapshot() != before {
                return Err(Error::Authority);
            }
            let child1 = attach(attachment1, verified1, &ledger)?;
            let produced2 =
                unsafe { next2.produce_retaining_originals() }.map_err(|_| Error::Proof)?;
            let (verified2, originals) = produced2.into_parts();
            let child2 = attach(attachment, verified2, &ledger)?;
            (child1, Some(child2), originals)
        }
        (None, None) => {
            let (verified1, originals) = produced1.into_parts();
            (attach(attachment1, verified1, &ledger)?, None, originals)
        }
        _ => return Err(Error::Authority),
    };
    let compile_started = std::time::Instant::now();
    let compiled0 = group0
        .compile_cpu_reference([Some(child0), Some(child1)], compiler0, &ledger)
        .map_err(|_| Error::Shape)?;
    let compiler0_ns = compile_started.elapsed().as_nanos();
    source0
        .check_compiled(&compiled0, &ledger)
        .map_err(|_| Error::Shape)?;
    let before = ledger.snapshot();
    let continuation0 = unsafe { outer0.finish_native(&compiled0, originals) }?;
    if ledger.snapshot() != before {
        return Err(Error::Authority);
    }
    let continued0 = unsafe { continuation0.produce_retaining_outer_originals() }?;
    let (mut output0, originals) = continued0.into_parts();
    recheck0
        .verify_mutations(&mut output0, &ledger)
        .map_err(Error::Output)?;
    let metrics0 = GroupMetrics::from_output(compiled0.summary(), compiler0_ns, &output0)?;
    let metrics1 = match (group1, compiler1, child2, outer1, recheck1) {
        (Some(group), Some(compiler), Some(child), Some(ready), Some(recheck)) => {
            let compile_started = std::time::Instant::now();
            let compiled = group
                .compile_cpu_reference([Some(child), None], compiler, &ledger)
                .map_err(|_| Error::Shape)?;
            let compiler_ns = compile_started.elapsed().as_nanos();
            source1
                .as_ref()
                .ok_or(Error::Authority)?
                .check_compiled(&compiled, &ledger)
                .map_err(|_| Error::Shape)?;
            // B047 checks complete unchanged restoration/bind snapshot and the
            // exact obsolete-support release delta. No new admission occurs.
            let continuation = unsafe { ready.finish_outer(&compiled, originals) }?;
            let mut output = unsafe { continuation.produce() }?;
            recheck
                .verify_mutations(&mut output, &ledger)
                .map_err(Error::Output)?;
            let metrics = GroupMetrics::from_output(compiled.summary(), compiler_ns, &output)?;
            drop(output);
            drop(compiled);
            Some(metrics)
        }
        (None, None, None, None, None) => {
            drop(originals);
            None
        }
        _ => return Err(Error::Authority),
    };
    for (ordinal, metrics) in [Some(metrics0), metrics1].into_iter().enumerate() {
        if let Some(metrics) = metrics {
            eprintln!("ringct_native_sequence_group shape={} ordinal={} active_rows={} padded_rows={} compiler_ns={} setup_ns={} proving_ns={} cpu_verification_ns={} independent_cpu_verified=true mutation_rejections=2",
                shape.name(), ordinal, metrics.active_rows, metrics.padded_rows, metrics.compiler_ns,
                metrics.setup_ns, metrics.proving_ns, metrics.cpu_verification_ns);
        }
    }
    eprintln!("ringct_native_sequence_complete shape={} native_proofs={} recursive_proofs={} mutation_rejections={} source_preissue_ns={} component_including_mutations_ns={} fresh_gpu_required=true compiler_backend=cpu public_endpoint_preprocessing=cpu original_startup_pcs_reused=true native_successor_and_attachment_snapshots_unchanged=true skipped_predecessor_handoff_refusals={} second_outer_dispatched={} request_aggregate_proofs=0 complete_ringct_workflow=false",
        shape.name(), shape.native_count(), shape.group_count(), 2 * shape.group_count(),
        source_preissue_ns, started.elapsed().as_nanos(), usize::from(shape == SequenceShape::PairAndTail), shape == SequenceShape::PairAndTail);
    drop(output0);
    drop(compiled0);
    drop(source1);
    drop(source0);
    drop(owner);
    drop(sequence);
    if ledger.snapshot().current != Bytes::ZERO {
        return Err(Error::Authority);
    }
    eprintln!("ringct_native_sequence_terminal shape={} original_quota_released=true complete_ringct_workflow=false", shape.name());
    Ok(())
}

#[test]
#[ignore = "exact coordinator original-native pair sequence guard; no production enablement"]
fn gpu_two_native_segments_pair_original_successors() {
    unsafe { run(SequenceShape::Pair) }.unwrap();
}

#[test]
#[ignore = "exact coordinator original-native odd-tail sequence guard; no production enablement"]
fn gpu_three_native_segments_pair_and_tail_original_successors() {
    unsafe { run(SequenceShape::PairAndTail) }.unwrap();
}

#[test]
fn sequence_source_counts_reject_cross_mode_before_any_runtime() {
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let original = ledger.admit_phase(sequence_requirement().unwrap()).unwrap();
    let input = [7u8; 137];
    for shape in [SequenceShape::Pair, SequenceShape::PairAndTail] {
        let plan = ShakeRequestPlan::new(
            [96; 32],
            7,
            0,
            &input[..shape.input_len()],
            137,
            ProofPolicy::default(),
        )
        .unwrap();
        let claim = ledger.admit_phase(plan.requirements()).unwrap();
        let owner = plan.construct(claim, &ledger).unwrap();
        assert!(shape.check(&owner, &ledger).is_ok());
        let wrong = match shape {
            SequenceShape::Pair => SequenceShape::PairAndTail,
            SequenceShape::PairAndTail => SequenceShape::Pair,
        };
        assert!(wrong.check(&owner, &ledger).is_err());
        let foreign = Ledger::new(WorkerAllowance {
            host: 32 << 30,
            device: 8 << 30,
        });
        assert!(shape.check(&owner, &foreign).is_err());
        drop(owner);
    }
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}

#[test]
fn sequence_refuses_existing_batched_segments_without_splitting() {
    let ledger = Ledger::new(WorkerAllowance {
        host: 32 << 30,
        device: 8 << 30,
    });
    let original = ledger.admit_phase(sequence_requirement().unwrap()).unwrap();
    let input = [7u8; 273];
    let plan = ShakeRequestPlan::new([96; 32], 7, 0, &input, 1, ProofPolicy::default()).unwrap();
    let claim = ledger.admit_phase(plan.requirements()).unwrap();
    let owner = plan.construct(claim, &ledger).unwrap();
    assert_eq!(owner.request().segments().len(), 2);
    assert_eq!(owner.request().segments()[0].units, 2);
    assert!(SequenceShape::Pair.check(&owner, &ledger).is_err());
    assert!(SequenceShape::PairAndTail.check(&owner, &ledger).is_err());
    assert_eq!(owner.request().segments().len(), 2);
    assert_eq!(owner.request().segments()[0].units, 2);
    drop(owner);
    drop(original);
    assert_eq!(ledger.snapshot().current, Bytes::ZERO);
}
