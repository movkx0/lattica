//! Fresh, exact-source transcript serialization. Part values remain borrowed from the
//! prepared auxiliary factory. Only the concrete owned native producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::{AuxiliaryRequest, Payload, Role};
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    transcript_air::{self, PartKind, PartValues, TranscriptAir},
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            transcript_output::{TranscriptOutputPlan, OwnedTranscriptProof},
            transcript_preparation::{TranscriptLayout, TranscriptPartKind, TranscriptPreparationPlan, MAX_PARTS},
            transcript_recording::{TranscriptRecorder, PreparedTranscript},
            owned_transcript::{TranscriptInput, NativeTranscriptPhase},
        },
        native_transcript_proof::NativeTranscriptProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TranscriptFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, TranscriptFailure>;

/// Sealed immutable membership in one original PreparedWorkflowSources owner.
/// Copying this borrowed view never clones raw bytes, proofs or reservations.
#[derive(Clone, Copy)]
pub(crate) struct TranscriptSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    request: &'a AuxiliaryRequest,
    air: &'a TranscriptAir,
    values: &'a [PartValues],
    kind: TranscriptLayout,
}

/// Bounded stack encoding of public part metadata; original AIR and values stay
/// in the retained request. This does not clone or serialize private parts.
pub(crate) fn layout_for_air(air: &TranscriptAir) -> Result<TranscriptLayout> {
    if air.parts().is_empty() || air.parts().len() > MAX_PARTS { return Err(TranscriptFailure::Geometry); }
    let mut kinds = [TranscriptPartKind::Bytes32; MAX_PARTS];
    for (slot, kind) in kinds.iter_mut().zip(air.parts()) {
        *slot = match kind { PartKind::Bytes32 => TranscriptPartKind::Bytes32,
            PartKind::PolynomialQ => TranscriptPartKind::PolynomialQ,
            PartKind::PolynomialQhat => TranscriptPartKind::PolynomialQhat };
    }
    TranscriptLayout::new(&kinds[..air.parts().len()]).map_err(|_| TranscriptFailure::Geometry)
}
impl<'a> TranscriptSource<'a> {
    fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role) -> Result<Self> {
        let prepared = sources.get();
        if !matches!((role, prepared.graph().operations().get(operation)),
            (Role::HashAlphaTranscript, Some(Operation::HashAlpha { .. }))
                | (Role::HashXTranscript, Some(Operation::HashX { .. }))) {
            return Err(TranscriptFailure::Source);
        }
        let mut matches = prepared.auxiliary_factory().requests.iter()
            .filter(|request| request.operation == operation && request.role == role);
        let request = matches.next().ok_or(TranscriptFailure::Source)?;
        if matches.next().is_some() { return Err(TranscriptFailure::Source); }
        let Payload::Transcript(air, values) = &request.payload else { return Err(TranscriptFailure::Source); };
        let kind = layout_for_air(air)?;
        if values.len() != kind.part_count() || values.capacity() > 2 * kind.part_count()
            || air.byte_len() != kind.byte_len()
            || (request.geometry.width, request.geometry.height) != (air.width(), air.height())
            || air.num_public_values() != 8 || air.num_periodic_columns() != 4
            || air.max_constraint_degree().is_some()
        { return Err(TranscriptFailure::Geometry); }
        let source = Self { sources, request, air, values, kind };
        // Validate typed references/canonical u32 encoding under the caller's
        // precharged fixed input frame before recording or runtime startup.
        drop(source.input()?);
        Ok(source)
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn request(self) -> &'a AuxiliaryRequest { self.request }
    pub(crate) fn operation_index(self) -> usize { self.request.operation }
    pub(crate) fn role(self) -> Role { self.request.role }
    pub(crate) fn kind(self) -> TranscriptLayout { self.kind }
    pub(crate) fn air(self) -> &'a TranscriptAir { self.air }
    pub(crate) fn expected_public_values(self) -> [lattica_prover_p3::config::Val; 8] { self.request.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.request, other.request)
            && core::ptr::eq(self.air, other.air) && core::ptr::eq(self.values, other.values)
            && self.kind == other.kind
    }
    fn input(self) -> Result<TranscriptInput<'a>> {
        use lattica_prover_p3::block_v2::native_gpu::TranscriptPart as DevicePart;
        const EMPTY: [u8; 32] = [0; 32];
        let mut parts = core::array::from_fn::<_, MAX_PARTS, _>(|_| DevicePart::Bytes32(&EMPTY));
        for (i, (slot, value)) in parts.iter_mut().zip(self.values).enumerate() {
            *slot = match (self.kind.part_kind(i), value) {
                (Some(TranscriptPartKind::Bytes32), PartValues::Bytes32(value)) => DevicePart::Bytes32(value),
                (Some(TranscriptPartKind::PolynomialQ), PartValues::Polynomial(value)) => DevicePart::PolynomialQ(value),
                (Some(TranscriptPartKind::PolynomialQhat), PartValues::Polynomial(value)) => DevicePart::PolynomialQhat(value),
                _ => return Err(TranscriptFailure::Geometry),
            };
        }
        TranscriptInput::new(self.kind, parts).map_err(|_| TranscriptFailure::Geometry)
    }
}

pub(crate) struct TranscriptProofPlan<'a> {
    source: TranscriptSource<'a>, preparation: TranscriptPreparationPlan, output: TranscriptOutputPlan,
}
impl<'a> TranscriptProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role)
        -> Result<Self>
    {
        let source = TranscriptSource::new(sources, operation, role)?;
        let preparation = TranscriptPreparationPlan::new(source.kind).map_err(|_| TranscriptFailure::Resource)?;
        let output = TranscriptOutputPlan::new(preparation).map_err(|_| TranscriptFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height(), air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(TranscriptFailure::Geometry); }
        Ok(Self { source, preparation, output })
    }
    pub(crate) fn source(&self) -> TranscriptSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> TranscriptPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> TranscriptOutputPlan { self.output }
    /// Metadata is admitted before new() can construct these fixed frames.
    /// Keep this separate from phase scratch: no future phase admission or
    /// unrelated preissue margin supplies construction credit.
    pub(crate) fn construction_host_bytes() -> Result<usize> {
        use lattica_prover_p3::block_v2::native_gpu::{TranscriptPart,
            owned_transcript::Error as NativeInputError};
        [size_of::<Self>(), size_of::<Result<Self>>(),
            size_of::<TranscriptSource<'static>>(), size_of::<Result<TranscriptSource<'static>>>(),
            size_of::<[TranscriptPart<'static>; MAX_PARTS]>(),
            size_of::<[TranscriptPartKind; MAX_PARTS]>(),
            size_of::<TranscriptInput<'static>>(), size_of::<Result<TranscriptInput<'static>>>(),
            size_of::<core::result::Result<TranscriptInput<'static>, NativeInputError>>(),
            size_of::<TranscriptLayout>(), size_of::<Result<TranscriptLayout>>(),
            size_of::<TranscriptPreparationPlan>(), size_of::<TranscriptOutputPlan>(),
            size_of::<SourceAir<'static>>(), size_of::<[usize; 32]>()]
            .into_iter().try_fold(0usize, |sum, bytes| bytes.checked_mul(8)
                .and_then(|bytes| sum.checked_add(bytes)).ok_or(TranscriptFailure::Resource))
    }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<TranscriptSource<'static>>(),
            size_of::<PreparedTranscriptSource<'static, 'static>>(),
            size_of::<Result<PreparedTranscriptSource<'static, 'static>>>(),
            size_of::<UnverifiedTranscriptProof<'static>>(), size_of::<Result<UnverifiedTranscriptProof<'static>>>(),
            size_of::<TranscriptAir>(), size_of::<SourceAir<'static>>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedTranscriptProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<TranscriptVerificationFailure>(),
            size_of::<TranscriptInput<'static>>(), size_of::<TranscriptOutputPlan>(),
            size_of::<[TranscriptPartKind; MAX_PARTS]>(), 2 * size_of::<TranscriptLayout>(),
            size_of::<TranscriptPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| TranscriptFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(TranscriptFailure::Resource))
    }
    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedTranscriptSource<'a, 'claim>>
    {
        let mut recorder = TranscriptRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| TranscriptFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| TranscriptFailure::Preparation)?;
        let air = SourceAir::new(self.source.air(), self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| TranscriptFailure::VerificationBudget)?;
        Ok(PreparedTranscriptSource { source: self.source, recorded, verification })
    }
}

pub(crate) struct PreparedTranscriptSource<'a, 'claim> {
    source: TranscriptSource<'a>, recorded: PreparedTranscript<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedTranscriptSource<'a, '_> {
    pub(crate) fn source(&self) -> TranscriptSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> TranscriptPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeTranscriptPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedTranscriptProof<'a>>
    {
        let input = self.source.input()?;
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| TranscriptFailure::Production)?;
        Ok(UnverifiedTranscriptProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedTranscriptProof<'a> {
    source: TranscriptSource<'a>, owned: OwnedTranscriptProof, verification: VerificationPlan,
}
impl<'a> UnverifiedTranscriptProof<'a> {
    pub(crate) fn source(&self) -> TranscriptSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeTranscriptProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedTranscriptProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (TranscriptVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values != self.source.expected_public_values()
        { return Err((TranscriptVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.air(), self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((TranscriptVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (TranscriptVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedTranscriptProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum TranscriptVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedTranscriptProof<'a>, Reservation),
    (TranscriptVerificationFailure, UnverifiedTranscriptProof<'a>, Reservation)>;
pub(crate) struct VerifiedTranscriptProof<'a> {
    original: UnverifiedTranscriptProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedTranscriptProof<'a> {
    pub(crate) fn source(&self) -> TranscriptSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeTranscriptProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedTranscriptProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
