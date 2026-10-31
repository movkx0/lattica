//! Fresh, exact-source uniform sampling. Raw bytes remain borrowed from the
//! prepared auxiliary factory. Only the concrete owned native producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::{AuxiliaryRequest, Payload, Role};
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    uniform_air::{self, UniformAir},
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            uniform_output::{UniformOutputPlan, OwnedUniformProof},
            uniform_preparation::{UniformKind, UniformPreparationPlan},
            uniform_recording::{UniformRecorder, PreparedUniform},
            owned_uniform::{UniformInput, NativeUniformPhase},
        },
        native_uniform_proof::NativeUniformProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UniformFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, UniformFailure>;

/// Sealed immutable membership in one original PreparedWorkflowSources owner.
/// Copying this borrowed view never clones raw bytes, proofs or reservations.
#[derive(Clone, Copy)]
pub(crate) struct UniformSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    request: &'a AuxiliaryRequest,
    kind: UniformKind,
}
impl<'a> UniformSource<'a> {
    fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role) -> Result<Self> {
        let prepared = sources.get();
        let kind = match (role, prepared.graph().operations().get(operation)) {
            (Role::SampleGUniform, Some(Operation::SampleG { .. })) => UniformKind::SampleG4,
            (Role::AlphaUniform, Some(Operation::ExpandAlpha { .. })) => UniformKind::ExpandAlpha2,
            _ => return Err(UniformFailure::Source),
        };
        let mut matches = prepared.auxiliary_factory().requests.iter()
            .filter(|request| request.operation == operation && request.role == role);
        let request = matches.next().ok_or(UniformFailure::Source)?;
        if matches.next().is_some() { return Err(UniformFailure::Source); }
        let source = Self { sources, request, kind };
        let input = source.input()?;
        let air = source.air();
        if input.bytes.len() != kind.input_bytes()
            || (request.geometry.width, request.geometry.height) != (air.width(), air.height())
            || air.num_public_values() != 8 || air.num_periodic_columns() != 2
            || air.max_constraint_degree().is_some()
        { return Err(UniformFailure::Geometry); }
        Ok(source)
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn request(self) -> &'a AuxiliaryRequest { self.request }
    pub(crate) fn operation_index(self) -> usize { self.request.operation }
    pub(crate) fn role(self) -> Role { self.request.role }
    pub(crate) fn kind(self) -> UniformKind { self.kind }
    pub(crate) fn expected_public_values(self) -> [lattica_prover_p3::config::Val; 8] { self.request.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.request, other.request)
            && self.kind == other.kind
    }
    fn input(self) -> Result<UniformInput<'a>> {
        let Payload::Uniform(kind, bytes) = &self.request.payload else { return Err(UniformFailure::Source); };
        if *kind != self.air().kind() || bytes.len() != self.kind.input_bytes()
            || bytes.capacity() > 2 * self.kind.input_bytes()
        { return Err(UniformFailure::Geometry); }
        Ok(UniformInput { kind: self.kind, bytes })
    }
    fn air(self) -> UniformAir {
        UniformAir::new(match self.kind { UniformKind::SampleG4 => uniform_air::Kind::SampleG4,
            UniformKind::ExpandAlpha2 => uniform_air::Kind::ExpandAlpha2 })
    }
}

pub(crate) struct UniformProofPlan<'a> {
    source: UniformSource<'a>, preparation: UniformPreparationPlan, output: UniformOutputPlan,
}
impl<'a> UniformProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role)
        -> Result<Self>
    {
        let source = UniformSource::new(sources, operation, role)?;
        let preparation = UniformPreparationPlan::new(source.kind).map_err(|_| UniformFailure::Resource)?;
        let output = UniformOutputPlan::new(preparation).map_err(|_| UniformFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height(), air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(UniformFailure::Geometry); }
        Ok(Self { source, preparation, output })
    }
    pub(crate) fn source(&self) -> UniformSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> UniformPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> UniformOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<UniformSource<'static>>(),
            size_of::<PreparedUniformSource<'static, 'static>>(),
            size_of::<Result<PreparedUniformSource<'static, 'static>>>(),
            size_of::<UnverifiedUniformProof<'static>>(), size_of::<Result<UnverifiedUniformProof<'static>>>(),
            size_of::<UniformAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedUniformProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<UniformVerificationFailure>(),
            size_of::<UniformInput<'static>>(), size_of::<UniformOutputPlan>(),
            size_of::<UniformPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| UniformFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(UniformFailure::Resource))
    }
    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedUniformSource<'a, 'claim>>
    {
        let mut recorder = UniformRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| UniformFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| UniformFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| UniformFailure::VerificationBudget)?;
        Ok(PreparedUniformSource { source: self.source, recorded, verification })
    }
}

pub(crate) struct PreparedUniformSource<'a, 'claim> {
    source: UniformSource<'a>, recorded: PreparedUniform<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedUniformSource<'a, '_> {
    pub(crate) fn source(&self) -> UniformSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> UniformPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeUniformPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedUniformProof<'a>>
    {
        let input = self.source.input()?;
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| UniformFailure::Production)?;
        Ok(UnverifiedUniformProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedUniformProof<'a> {
    source: UniformSource<'a>, owned: OwnedUniformProof, verification: VerificationPlan,
}
impl<'a> UnverifiedUniformProof<'a> {
    pub(crate) fn source(&self) -> UniformSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeUniformProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedUniformProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (UniformVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values != self.source.expected_public_values()
        { return Err((UniformVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((UniformVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (UniformVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedUniformProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum UniformVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedUniformProof<'a>, Reservation),
    (UniformVerificationFailure, UnverifiedUniformProof<'a>, Reservation)>;
pub(crate) struct VerifiedUniformProof<'a> {
    original: UnverifiedUniformProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedUniformProof<'a> {
    pub(crate) fn source(&self) -> UniformSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeUniformProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedUniformProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
