//! A closed ownership prerequisite for the singleton/paired SHAKE compiler.
//!
//! This is not a runtime admission or a dispatch permit. Produced native owners
//! retain their original production or fixture owner. The CPU reference entry
//! point is for serialized qualification; GPU endpoint preparation and original compiler
//! error/report transients need their own complete-phase admission before use
//! in a faithful workflow. No raw compiled program or proving API escapes.
//! Caller-supplied endpoint context is not authenticated against a transaction
//! statement or manifest here; compiler equivalence is not witness acceptance.

use super::shake_verification_memory::{
    Plan as VerificationPlan, VerificationFailure, VerificationReceipt,
};
use super::{
    compile_shake_group_bounded_with_context, CompiledNode, ConstructionLimits, Contract,
    EndpointContext, ShakeGroupCompileFootprint, ShakeGroupCompileOutcome, ShakeGroupMember,
    ShakeGroupResourceRefusal, Val, HEADER,
};
use crate::execution::{
    phase_lifecycle::CleanupFailure, shake_compilation::AdmittedShakeCompilation,
};
use crate::{
    execution::{
        phase_report::{
            Error as ReportError, FailureStage, PhaseIdentity, PhaseKind, PhaseReportOwner,
        },
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
    },
    graph_crypto::{
        NativeProductionPlan, Request, ReservedNativeChild, ShakeWrapperLayout, ShakeWrapperSpan,
    },
};
use core::mem::{size_of, size_of_val};
use lattica_prover_p3::block_v2::machine::program::{Program, MAX_WIRES};

const PROGRAM_BYTES: usize = 2 << 30;
const INPUT_VALUES: usize = 1 << 20;
const AUXILIARY_BYTES: usize = 512 << 20;
const MAX_ROWS: usize = 1 << 20;
const IDENTITY: &str = "owned SHAKE compiler request/span identity";
const AUTHORITY: &str = "owned SHAKE compiler reservation authority";
const SHAPE: &str = "owned SHAKE compiler source shape";
const CAPACITY: &str = "owned SHAKE compiler source storage bound";

type PlanResult<T> = core::result::Result<T, &'static str>;

fn add(a: usize, b: usize) -> PlanResult<usize> {
    a.checked_add(b).ok_or(CAPACITY)
}

fn requirement(category: Category, bytes: usize) -> PlanResult<Requirements> {
    Ok(Requirements::single(
        category,
        Bytes {
            host: u64::try_from(bytes).map_err(|_| CAPACITY)?,
            device: 0,
        },
    ))
}

fn combine(parts: &[Requirements]) -> PlanResult<Requirements> {
    let mut total = Requirements::default();
    for part in parts {
        for category in Category::ALL {
            total
                .add(category, part.get(category))
                .map_err(|_| CAPACITY)?;
        }
    }
    Ok(total)
}

// Private fixed-purpose access only. Neither implementation lets the compiler
// request arbitrary categories or move actual PhaseScratch out of its context.
trait CompilerAdmission {
    fn report_token(&mut self) -> PlanResult<Reservation>;
    fn verifier_token(&mut self) -> PlanResult<Reservation>;
    fn program_token(&mut self) -> PlanResult<Reservation>;
    fn input_token(&mut self) -> PlanResult<Reservation>;

    /// Default paths retain their existing terminal verifier ownership. Only
    /// the private compiler bank preserves verified originals.
    fn verify_child(
        &mut self,
        child: &ReservedNativeChild<'_>,
        original: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<(), VerificationFailure> {
        child.verify_pre_reserved(original, ledger).map(|_| ())
    }
}

fn verifier_dispatch_host_bytes() -> PlanResult<usize> {
    let parts = [
        size_of::<Reservation>(),
        size_of::<&ReservedNativeChild<'_>>(),
        size_of::<&Ledger>(),
        size_of::<&mut StandaloneAdmission<'_>>(),
        size_of::<core::result::Result<VerificationReceipt, VerificationFailure>>(),
        size_of::<core::result::Result<(), VerificationFailure>>(),
        size_of::<VerificationReceipt>(),
        size_of::<VerificationFailure>(),
    ];
    let sum = parts.into_iter().try_fold(size_of_val(&parts), add)?;
    sum.checked_mul(8).ok_or(CAPACITY)
}

struct StandaloneAdmission<'a> {
    reserved: &'a mut Reservation,
    program: Requirements,
    inputs: Requirements,
}
impl CompilerAdmission for StandaloneAdmission<'_> {
    fn report_token(&mut self) -> PlanResult<Reservation> {
        self.reserved
            .split(PhaseReportOwner::requirements())
            .map_err(|_| AUTHORITY)
    }
    fn verifier_token(&mut self) -> PlanResult<Reservation> {
        self.reserved
            .split(VerificationPlan::component_requirement())
            .map_err(|_| AUTHORITY)
    }
    fn program_token(&mut self) -> PlanResult<Reservation> {
        self.reserved.split(self.program).map_err(|_| AUTHORITY)
    }
    fn input_token(&mut self) -> PlanResult<Reservation> {
        self.reserved.split(self.inputs).map_err(|_| AUTHORITY)
    }
}
impl CompilerAdmission for AdmittedShakeCompilation<'_, '_, '_, '_> {
    fn report_token(&mut self) -> PlanResult<Reservation> {
        self.split_report().map_err(|_| AUTHORITY)
    }
    fn verifier_token(&mut self) -> PlanResult<Reservation> {
        self.split_independent_verifier().map_err(|_| AUTHORITY)
    }
    fn program_token(&mut self) -> PlanResult<Reservation> {
        self.split_program().map_err(|_| AUTHORITY)
    }
    fn input_token(&mut self) -> PlanResult<Reservation> {
        self.split_inputs().map_err(|_| AUTHORITY)
    }
}

/// No caller-supplied quotas or source proofs. The exact immutable request and
/// public schedule determine the arity, interval and source retention shape.
pub(crate) struct GroupCompilePlan<'request> {
    request: &'request Request,
    layout: ShakeWrapperLayout,
    ordinal: usize,
    span: ShakeWrapperSpan,
    contract: Contract,
    context: EndpointContext,
    limits: ConstructionLimits,
    footprint: ShakeGroupCompileFootprint,
    program: Requirements,
    inputs: Requirements,
    temporary: Requirements,
    whole: Requirements,
}

impl<'request> GroupCompilePlan<'request> {
    pub(crate) fn new(
        request: &'request Request,
        layout: ShakeWrapperLayout,
        ordinal: usize,
        context: EndpointContext,
    ) -> PlanResult<Self> {
        let schedule = request.shake_wrapper_schedule(layout).map_err(|_| SHAPE)?;
        let span = schedule.groups().nth(ordinal).ok_or(IDENTITY)?;
        if !(1..=2).contains(&span.segment_count) {
            return Err(SHAPE);
        }
        for index in span.first_segment..span.first_segment + span.segment_count {
            NativeProductionPlan::new(request, index)?;
        }
        let contract = request.contract().map_err(|_| SHAPE)?;
        let limits = ConstructionLimits {
            max_requested_program_bytes: PROGRAM_BYTES,
            max_wires: MAX_WIRES,
            max_input_values: INPUT_VALUES,
        };
        let footprint = ShakeGroupCompileFootprint::for_group(span.segment_count, limits)
            .map_err(|_| CAPACITY)?;
        let mut plan = Self {
            request,
            layout,
            ordinal,
            span,
            contract,
            context,
            limits,
            footprint,
            program: Requirements::default(),
            inputs: Requirements::default(),
            temporary: Requirements::default(),
            whole: Requirements::default(),
        };
        plan.derive_requirements()?;
        Ok(plan)
    }

    fn derive_requirements(&mut self) -> PlanResult<()> {
        self.footprint =
            ShakeGroupCompileFootprint::for_group(self.span.segment_count, self.limits)
                .map_err(|_| CAPACITY)?;
        if self.footprint.auxiliary_peak_bytes > AUXILIARY_BYTES {
            return Err(CAPACITY);
        }
        // Builder accounting excludes the Arc allocation and this owner. Keep
        // the full program ceiling live after compilation; do not shrink it to
        // an observed capacity. All fields below are fixed or separately owned.
        let header = add(size_of::<Program>(), 2 * size_of::<usize>())?;
        let header = add(header, size_of::<OwnedCompiledShake<'_>>())?;
        let header = add(header, size_of::<Self>())?;
        self.program = requirement(
            Category::SymbolicCompiler,
            add(self.limits.max_requested_program_bytes, header)?,
        )?;
        // ProofInputs includes old/new backing. Header public values are a
        // separate Vec; retain twice their logical storage plus its header.
        let public = add(2 * (HEADER + 8) * size_of::<Val>(), size_of::<Vec<Val>>())?;
        self.inputs = requirement(
            Category::CompilerInputs,
            add(self.footprint.input_backing_bytes, public)?,
        )?;
        let symbolic = add(
            self.footprint.symbolic.workspace_bytes,
            self.footprint.symbolic.retained_graph_bytes,
        )?;
        let helpers = add(
            self.footprint.returned_wire_bytes,
            self.footprint.helper_bytes,
        )?;
        let helpers = add(helpers, verifier_dispatch_host_bytes()?)?;
        self.temporary = requirement(Category::PhaseScratch, add(symbolic, helpers)?)?;
        let mut verification = Requirements::default();
        for _ in 0..self.span.segment_count {
            verification = combine(&[verification, VerificationPlan::component_requirement()])?;
        }
        self.whole = combine(&[
            self.program,
            self.inputs,
            self.temporary,
            verification,
            PhaseReportOwner::requirements(),
        ])?;
        Ok(())
    }

    pub(crate) fn requirements(&self) -> Requirements {
        self.whole
    }

    pub(crate) fn program_requirement(&self) -> Requirements {
        self.program
    }
    pub(crate) fn input_requirement(&self) -> Requirements {
        self.inputs
    }

    pub(crate) fn span(&self) -> ShakeWrapperSpan {
        self.span
    }

    /// All native output reservations predate proof production. This consumes
    /// exactly the compiler phase split from the same worker admission, checks
    /// every source owner before allocating a report, and never retries.
    pub(crate) fn compile_cpu_reference(
        self,
        children: [Option<ReservedNativeChild<'request>>; 2],
        mut reserved: Reservation,
        ledger: &Ledger,
    ) -> core::result::Result<OwnedCompiledShake<'request>, CompilationFailure> {
        if !reserved.belongs_to(ledger) || reserved.requirements() != self.whole {
            return Err(CompilationFailure::admission(AUTHORITY));
        }
        let mut access = StandaloneAdmission {
            reserved: &mut reserved,
            program: self.program,
            inputs: self.inputs,
        };
        let result = self.compile_owned(children, &mut access, ledger);
        if result.is_ok() {
            debug_assert_eq!(reserved.requirements(), self.temporary);
        }
        result
    }

    /// The execution-owned handle pins this exact plan and an actual active
    /// phase/context. It exposes only fixed output/verifier splits; compiler
    /// scratch remains in the context until actual cleanup completes.
    pub(crate) fn compile_in_admitted_cpu_phase(
        mut admission: AdmittedShakeCompilation<'_, '_, '_, 'request>,
        children: [Option<ReservedNativeChild<'request>>; 2],
    ) -> core::result::Result<OwnedCompiledShake<'request>, CompilationFailure> {
        let plan = admission.plan();
        let ledger = admission.ledger().clone();
        plan.compile_owned(children, &mut admission, &ledger)
    }

    fn compile_owned(
        &self,
        children: [Option<ReservedNativeChild<'request>>; 2],
        access: &mut impl CompilerAdmission,
        ledger: &Ledger,
    ) -> core::result::Result<OwnedCompiledShake<'request>, CompilationFailure> {
        let allowance = ledger.snapshot().allowance;
        if !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(allowance.host) || allowance.device > 8u64 << 30 {
            return Err(CompilationFailure::admission(AUTHORITY));
        }
        for (offset, child) in children.iter().enumerate() {
            let expected = offset < self.span.segment_count;
            if expected != child.is_some()
                || child.as_ref().is_some_and(|child| {
                    !child.is_for(self.request, self.span.first_segment + offset, ledger)
                })
            {
                return Err(CompilationFailure::admission(IDENTITY));
            }
        }
        let report_token = access
            .report_token()
            .map_err(CompilationFailure::admission)?;
        let identity = PhaseIdentity {
            kind: PhaseKind::WrapperCompilation,
            ordinal: self.ordinal as u64,
            first_segment: self.span.first_segment as u64,
            segment_count: self.span.segment_count as u8,
            profile: self.contract.profile,
        };
        let mut report = PhaseReportOwner::from_reservation(report_token, ledger, identity)
            .map_err(|_| CompilationFailure::admission(AUTHORITY))?;
        for child in children.iter().flatten() {
            let token = match access.verifier_token() {
                Ok(token) => token,
                Err(reason) => return Err(CompilationFailure::owned_admission(report, reason)),
            };
            if let Err(error) = access.verify_child(child, token, ledger) {
                let message = match &error {
                    VerificationFailure::Configuration(message) => *message,
                    VerificationFailure::InvalidProof(diagnostic) => diagnostic.as_str(),
                };
                report
                    .record_failure(FailureStage::NativeVerification, message)
                    .expect("fresh fixed compiler failure slot");
                return Err(CompilationFailure {
                    kind: FailureKind::NativeVerification,
                    report: Some(report),
                    refusal: None,
                });
            }
        }
        let member = |offset: usize| {
            let child = children[offset].as_ref().expect("exact scheduled child");
            let segment = &self.request.segments()[child.index()];
            let proof = child.shake_artifact();
            ShakeGroupMember {
                first: segment.first_unit as u32,
                count: segment.units as u32,
                proof,
            }
        };
        // The two-element stack array avoids allocating orchestration metadata.
        let first = member(0);
        let second = if self.span.segment_count == 2 {
            member(1)
        } else {
            member(0)
        };
        let members = [first, second];
        let result = compile_shake_group_bounded_with_context(
            &self.contract,
            &members[..self.span.segment_count],
            &self.context,
            None,
            self.limits,
            self.footprint.auxiliary_peak_bytes,
        );
        let compiled = match result {
            Ok(ShakeGroupCompileOutcome::Compiled(compiled)) => compiled,
            Ok(ShakeGroupCompileOutcome::ResourceRefused(refusal)) => {
                report
                    .record_failure(FailureStage::Compilation, refusal.reason)
                    .expect("fresh fixed compiler failure slot");
                return Err(CompilationFailure {
                    kind: FailureKind::ResourceRefused,
                    report: Some(report),
                    refusal: Some(refusal),
                });
            }
            Err(error) => {
                report
                    .record_failure(FailureStage::Compilation, &error.0)
                    .expect("fresh fixed compiler failure slot");
                // The source String must die before compiler temporary tokens.
                drop(error);
                return Err(CompilationFailure {
                    kind: FailureKind::Compilation,
                    report: Some(report),
                    refusal: None,
                });
            }
        };
        if compiled.program.height() > MAX_ROWS
            || compiled
                .witness
                .capacity()
                .checked_mul(size_of::<Val>())
                .is_none_or(|bytes| bytes > self.footprint.input_backing_bytes)
            || compiled.public.capacity() > 2 * (HEADER + 8)
            || compiled.witness.len() > self.limits.max_input_values
        {
            report
                .record_failure(FailureStage::Compilation, CAPACITY)
                .expect("fresh fixed compiler failure slot");
            drop(compiled);
            return Err(CompilationFailure {
                kind: FailureKind::OutputBound,
                report: Some(report),
                refusal: None,
            });
        }
        let summary = Summary {
            layout: self.layout,
            ordinal: self.ordinal,
            span: self.span,
            active_rows: compiled.program.active_rows(),
            padded_rows: compiled.program.height(),
            wires: compiled.program.wire_count(),
            input_values: compiled.witness.len(),
            independent_native_verifications: self.span.segment_count,
        };
        let program = match access.program_token() {
            Ok(token) => token,
            Err(reason) => {
                drop(compiled);
                return Err(CompilationFailure::owned_admission(report, reason));
            }
        };
        let inputs = match access.input_token() {
            Ok(token) => token,
            Err(reason) => {
                drop(compiled);
                drop(program);
                return Err(CompilationFailure::owned_admission(report, reason));
            }
        };
        // Child proof storage overlaps the full compiler/input/report phase,
        // and is released only after the witness owns every copied proof value.
        drop(children);
        Ok(OwnedCompiledShake {
            compiled,
            summary,
            request: self.request,
            report,
            _program: program,
            _inputs: inputs,
        })
    }

    /// Fixed non-proving fixture solely for actual lifecycle cleanup tests.
    /// It never accepts a raw CompiledNode or a caller-selected program.
    #[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn test_only_empty_compiler_output(
        mut admission: AdmittedShakeCompilation<'_, '_, '_, 'request>,
    ) -> core::result::Result<OwnedCompiledShake<'request>, CompilationFailure> {
        let plan = admission.plan();
        let ledger = admission.ledger().clone();
        let program = admission
            .program_token()
            .map_err(CompilationFailure::admission)?;
        let inputs = admission
            .input_token()
            .map_err(CompilationFailure::admission)?;
        let report_token = admission
            .report_token()
            .map_err(CompilationFailure::admission)?;
        let report = PhaseReportOwner::from_reservation(
            report_token,
            &ledger,
            PhaseIdentity {
                kind: PhaseKind::WrapperCompilation,
                ordinal: plan.ordinal as u64,
                first_segment: plan.span.first_segment as u64,
                segment_count: plan.span.segment_count as u8,
                profile: plan.contract.profile,
            },
        )
        .map_err(|_| CompilationFailure::admission(AUTHORITY))?;
        let builder = super::ProgramBuilder::new_with_construction_limits(HEADER + 8, plan.limits)
            .expect("fixed minimal test builder");
        let compiled = CompiledNode {
            spec: plan
                .contract
                .span(plan.span.first_unit as u32, plan.span.units as u32)
                .expect("closed test span"),
            program: std::sync::Arc::new(builder.finish(None).expect("fixed minimal test program")),
            public: vec![Val::default(); HEADER + 8],
            witness: Vec::new(),
        };
        let summary = Summary {
            layout: plan.layout,
            ordinal: plan.ordinal,
            span: plan.span,
            active_rows: compiled.program.active_rows(),
            padded_rows: compiled.program.height(),
            wires: compiled.program.wire_count(),
            input_values: 0,
            independent_native_verifications: 0,
        };
        Ok(OwnedCompiledShake {
            compiled,
            summary,
            request: plan.request,
            report,
            _program: program,
            _inputs: inputs,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Summary {
    pub(crate) layout: ShakeWrapperLayout,
    pub(crate) ordinal: usize,
    pub(crate) span: ShakeWrapperSpan,
    pub(crate) active_rows: usize,
    pub(crate) padded_rows: usize,
    pub(crate) wires: usize,
    pub(crate) input_values: usize,
    pub(crate) independent_native_verifications: usize,
}

/// Payload drops before both linear backing reservations, including on unwind.
/// No Clone, raw Program/CompiledNode extraction, registration or proof method.
pub(crate) struct OwnedCompiledShake<'request> {
    compiled: CompiledNode,
    summary: Summary,
    request: &'request Request,
    report: PhaseReportOwner,
    _program: Reservation,
    _inputs: Reservation,
}

impl OwnedCompiledShake<'_> {
    pub(crate) fn summary(&self) -> Summary {
        self.summary
    }

    pub(crate) fn is_for(&self, request: &Request) -> bool {
        core::ptr::eq(self.request, request)
    }

    pub(crate) fn encoded_report(&mut self) -> core::result::Result<&[u8], ReportError> {
        self.report.encode()
    }

    /// Failed actual cleanup never releases a successful output to its caller.
    /// Keep its bounded report, destroy the compiled payload before its tokens,
    /// and let the execution context retain/poison the unsatisfied phase charge.
    pub(crate) fn into_cleanup_failure(self, failure: CleanupFailure) -> CompilationFailure {
        let (stage, message) = match failure {
            CleanupFailure::PreparedRelease => (
                FailureStage::PreparedRelease,
                "owned SHAKE actual prepared release failed",
            ),
            CleanupFailure::QueueDrain => (
                FailureStage::QueueDrain,
                "owned SHAKE actual queue drain failed",
            ),
        };
        let Self {
            compiled,
            mut report,
            _program,
            _inputs,
            ..
        } = self;
        report
            .record_failure(stage, message)
            .expect("successful compiler report has no failure");
        drop(compiled);
        drop(_program);
        drop(_inputs);
        CompilationFailure {
            kind: FailureKind::Cleanup,
            report: Some(report),
            refusal: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Admission(&'static str),
    NativeVerification,
    ResourceRefused,
    Compilation,
    OutputBound,
    Cleanup,
}

pub(crate) struct CompilationFailure {
    kind: FailureKind,
    report: Option<PhaseReportOwner>,
    refusal: Option<ShakeGroupResourceRefusal>,
}

impl core::fmt::Debug for CompilationFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompilationFailure")
            .field("kind", &self.kind)
            .field("has_owned_report", &self.report.is_some())
            .field("refusal", &self.refusal)
            .finish()
    }
}

impl CompilationFailure {
    fn admission(reason: &'static str) -> Self {
        Self {
            kind: FailureKind::Admission(reason),
            report: None,
            refusal: None,
        }
    }

    fn owned_admission(mut report: PhaseReportOwner, reason: &'static str) -> Self {
        report
            .record_failure(FailureStage::Admission, reason)
            .expect("fresh fixed compiler failure slot");
        Self {
            kind: FailureKind::Admission(reason),
            report: Some(report),
            refusal: None,
        }
    }

    pub(crate) fn kind(&self) -> FailureKind {
        self.kind
    }

    pub(crate) fn resource_refusal(&self) -> Option<ShakeGroupResourceRefusal> {
        self.refusal
    }

    pub(crate) fn encoded_report(&mut self) -> Option<core::result::Result<&[u8], ReportError>> {
        self.report.as_mut().map(PhaseReportOwner::encode)
    }
}

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod tests;

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod endpoint_qualification;

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod recursive_preflight;

#[cfg(all(test, not(debug_assertions), target_arch = "x86_64"))]
mod exact_retention;

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "opencl"
))]
mod gpu_preflight;

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "opencl"
))]
mod output;

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "opencl"
))]
mod outer_producer;

#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(crate) mod source_shape;

#[cfg(all(
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
pub(crate) mod request_merge;

#[cfg(all(
    test,
    feature = "owned-native-shake",
    not(debug_assertions),
    target_os = "linux",
    target_arch = "x86_64"
))]
mod transport_shape;
