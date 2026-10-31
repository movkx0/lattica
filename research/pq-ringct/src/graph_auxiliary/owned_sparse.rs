//! Fresh, exact-source sparse sampling. Raw bytes remain borrowed from the
//! prepared auxiliary factory. Only the concrete owned native producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::{AuxiliaryRequest, Payload, Role};
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    sparse_air::{self, SparseAir},
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            sparse_output::{SparseOutputPlan, OwnedSparseProof},
            sparse_preparation::{SparseKind, SparsePreparationPlan},
            sparse_recording::{SparseRecorder, PreparedSparse},
            owned_sparse::{SparseInput, NativeSparsePhase},
        },
        native_sparse_proof::NativeSparseProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SparseFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, SparseFailure>;

/// Sealed immutable membership in one original PreparedWorkflowSources owner.
/// Copying this borrowed view never clones raw bytes, proofs or reservations.
#[derive(Clone, Copy)]
pub(crate) struct SparseSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    request: &'a AuxiliaryRequest,
    kind: SparseKind,
}
impl<'a> SparseSource<'a> {
    fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role) -> Result<Self> {
        let prepared = sources.get();
        let kind = match (role, prepared.graph().operations().get(operation)) {
            (Role::AlphaSparse, Some(Operation::ExpandAlpha { .. })) => SparseKind::AlphaPrime39,
            (Role::HashXSparse, Some(Operation::HashX { .. })) => SparseKind::ChallengeX44,
            _ => return Err(SparseFailure::Source),
        };
        let mut matches = prepared.auxiliary_factory().requests.iter()
            .filter(|request| request.operation == operation && request.role == role);
        let request = matches.next().ok_or(SparseFailure::Source)?;
        if matches.next().is_some() { return Err(SparseFailure::Source); }
        let source = Self { sources, request, kind };
        let input = source.input()?;
        let air = source.air();
        if input.bytes.len() != kind.input_bytes()
            || (request.geometry.width, request.geometry.height) != (air.width(), sparse_air::HEIGHT)
            || air.num_public_values() != 8 || air.num_periodic_columns() != 82
            || air.max_constraint_degree().is_some()
        { return Err(SparseFailure::Geometry); }
        Ok(source)
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn request(self) -> &'a AuxiliaryRequest { self.request }
    pub(crate) fn operation_index(self) -> usize { self.request.operation }
    pub(crate) fn role(self) -> Role { self.request.role }
    pub(crate) fn kind(self) -> SparseKind { self.kind }
    pub(crate) fn expected_public_values(self) -> [lattica_prover_p3::config::Val; 8] { self.request.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.request, other.request)
            && self.kind == other.kind
    }
    fn input(self) -> Result<SparseInput<'a>> {
        let Payload::Sparse(kind, bytes) = &self.request.payload else { return Err(SparseFailure::Source); };
        if *kind != self.air().kind() || bytes.len() != self.kind.input_bytes()
            || bytes.capacity() > 2 * self.kind.input_bytes()
        { return Err(SparseFailure::Geometry); }
        Ok(SparseInput { kind: self.kind, bytes })
    }
    fn air(self) -> SparseAir {
        SparseAir::new(match self.kind { SparseKind::AlphaPrime39 => sparse_air::Kind::AlphaPrime39,
            SparseKind::ChallengeX44 => sparse_air::Kind::ChallengeX44 })
    }
}

pub(crate) struct SparseProofPlan<'a> {
    source: SparseSource<'a>, preparation: SparsePreparationPlan, output: SparseOutputPlan,
}
impl<'a> SparseProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role)
        -> Result<Self>
    {
        let source = SparseSource::new(sources, operation, role)?;
        let preparation = SparsePreparationPlan::new(source.kind).map_err(|_| SparseFailure::Resource)?;
        let output = SparseOutputPlan::new(preparation).map_err(|_| SparseFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (sparse_air::HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(SparseFailure::Geometry); }
        Ok(Self { source, preparation, output })
    }
    pub(crate) fn source(&self) -> SparseSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> SparsePreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> SparseOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<SparseSource<'static>>(),
            size_of::<PreparedSparseSource<'static, 'static>>(),
            size_of::<Result<PreparedSparseSource<'static, 'static>>>(),
            size_of::<UnverifiedSparseProof<'static>>(), size_of::<Result<UnverifiedSparseProof<'static>>>(),
            size_of::<SparseAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedSparseProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<SparseVerificationFailure>(),
            size_of::<SparseInput<'static>>(), size_of::<SparseOutputPlan>(),
            size_of::<SparsePreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| SparseFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(SparseFailure::Resource))
    }
    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedSparseSource<'a, 'claim>>
    {
        let mut recorder = SparseRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| SparseFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| SparseFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| SparseFailure::VerificationBudget)?;
        Ok(PreparedSparseSource { source: self.source, recorded, verification })
    }
}

pub(crate) struct PreparedSparseSource<'a, 'claim> {
    source: SparseSource<'a>, recorded: PreparedSparse<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedSparseSource<'a, '_> {
    pub(crate) fn source(&self) -> SparseSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> SparsePreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeSparsePhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedSparseProof<'a>>
    {
        let input = self.source.input()?;
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| SparseFailure::Production)?;
        Ok(UnverifiedSparseProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedSparseProof<'a> {
    source: SparseSource<'a>, owned: OwnedSparseProof, verification: VerificationPlan,
}
impl<'a> UnverifiedSparseProof<'a> {
    pub(crate) fn source(&self) -> SparseSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeSparseProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedSparseProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (SparseVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values != self.source.expected_public_values()
        { return Err((SparseVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((SparseVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (SparseVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedSparseProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum SparseVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedSparseProof<'a>, Reservation),
    (SparseVerificationFailure, UnverifiedSparseProof<'a>, Reservation)>;
pub(crate) struct VerifiedSparseProof<'a> {
    original: UnverifiedSparseProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedSparseProof<'a> {
    pub(crate) fn source(&self) -> SparseSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeSparseProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedSparseProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
