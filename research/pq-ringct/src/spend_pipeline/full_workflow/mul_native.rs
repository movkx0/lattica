//! Concrete mul-source native operation. Every exact immutable algebra batch
//! enters whole-workflow preissue before proof zero; no cache/import path.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind,
            PhaseFailure, RetainedFailure, RetainedNative, SourceRetained},
        ProvingContext,
    },
    graph_proofs::owned_mul::{MulProofPlan,
        MulSource, PreparedMulSource, UnverifiedMulProof, VerifiedMulProof,
        verification_memory::Plan as VerificationPlan},
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            mul_preparation::MulDescriptor,
            mul_output::MulOutputPlan,
            owned_mul::{NativeMulPhase, NativeMulReservationPlan},
        },
    },
    proving::{Policy, Report},
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MulNativeOperationFailure {
    Authority, Resource, Source, SourceDrift, Preparation, Native, Verification, Overflow,
}
type Result<T> = core::result::Result<T, MulNativeOperationFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(MulNativeOperationFailure::Overflow)
}
fn requirement(category: Category, count: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes { host: u64::try_from(count)
        .map_err(|_| MulNativeOperationFailure::Overflow)?, device: 0 }))
}
fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| MulNativeOperationFailure::Overflow)?;
    } }
    Ok(result)
}

/// Exactly one source family. Native/outer/parent closure is separate.
pub(crate) struct MulNativeOperationPlan<'a> {
    context: &'a ProvingContext,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    native: MulProofPlan<'a>,
    verification: VerificationPlan,
    workflow_source: [u8; 32],
    facts: PhaseFacts,
    backend: Bytes,
    // Last owner: all source-plan and preissue-packet borrows end before the
    // exact original metadata claim can be released or returned for cleanup.
    metadata: Reservation,
}
impl<'a> MulNativeOperationPlan<'a> {
    fn recording_caller_host_bytes() -> Result<usize> {
        [
            size_of::<Self>(), size_of::<Result<Self>>(), size_of::<MulNativeOperation<'static, 'static>>(),
                size_of::<RecordedMul<'static, 'static, 'static>>(), size_of::<ProducedMul<'static>>(),
            size_of::<OwnedMulOutput<'static>>(), size_of::<VerificationPlan>(),
            size_of::<Result<VerificationPlan>>(), size_of::<MulNativeFailureOutcome<'static>>(),
            size_of::<[Reservation; 8]>(), size_of::<[Requirements; 8]>(),
            size_of::<PhaseFacts>(), size_of::<PhaseBinding>(), size_of::<Sha3_256>(),
            crate::graph_tree::metadata::GraphMetadata::construction_bytes(),
        ].into_iter().try_fold(0, add)?.checked_mul(8).ok_or(MulNativeOperationFailure::Overflow)
    }
    pub(crate) fn new(scope: &SourcePlanningPlan<'a>,
        sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize,
        original: Reservation, recording: &mut Reservation, ledger: &Ledger)
        -> core::result::Result<Self, (MulNativeOperationFailure, Reservation)>
    {
        let mut original = Some(original);
        let constructed = (|| -> Result<Self> {
        let held = original.as_ref().expect("unconsumed metadata original");
        if !held.belongs_to(ledger) || !sources.belongs_to(ledger)
            || held.requirements() != Self::metadata_requirements()? {
            return Err(MulNativeOperationFailure::Authority);
        }
        scope.validate_initial_source(sources.get().native_source())
            .map_err(|_| MulNativeOperationFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired
            || sources.source_fingerprint() != scope.source_fingerprint()
            || sources.compiled_source_fingerprint() != scope.compiled_source_fingerprint() {
            return Err(MulNativeOperationFailure::Authority);
        }
            let native = MulProofPlan::new(sources, batch, held, ledger)
            .map_err(|_| MulNativeOperationFailure::Source)?;
        // Close the actual unchanged symbolic replay under a separately
        // precharged preparation original before freezing phase facts. The
        // recording is destroyed here; only its immutable source census lives.
        if !recording.belongs_to(ledger)
            || recording.requirements() != Self::verification_planning_requirements(native.source().kind())? {
            return Err(MulNativeOperationFailure::Authority);
        }
        let verification = sources.get().metadata()
                .map_err(|_| MulNativeOperationFailure::Preparation)?
                .verifier_mul(native.source().kind(), || native.record(recording, ledger)
                    .map(|recorded| recorded.verification_plan()).map_err(|_| ()))
                .map_err(|_| MulNativeOperationFailure::Preparation)?;
        let reservations = NativeMulReservationPlan::outer_host_v1(native.preparation(), 1)
            .map_err(|_| MulNativeOperationFailure::Resource)?;
        let output = combine(&[native.output_plan().proof_requirement(), native.output_plan().report_requirement(),
            requirement(Category::RegisteredMetadata, 8 * (
                size_of::<ProducedMul<'static>>() + size_of::<OwnedMulOutput<'static>>()
                + size_of::<RetainedNative<OwnedMulOutput<'static>>>()))?])?;
        let frames = Self::recording_caller_host_bytes()?;
        let scratch = combine(&[reservations.preparation_requirement()
            .map_err(|_| MulNativeOperationFailure::Resource)?, verification.component_requirement(),
            requirement(Category::PhaseScratch, add(frames, MulProofPlan::caller_host_bytes()
                .map_err(|_| MulNativeOperationFailure::Resource)?)?)?,
            crate::execution::workflow_resources::mul_native_issuer_scratch_requirements()
                .map_err(|_| MulNativeOperationFailure::Resource)?,
        ])?;
        let failure = requirement(Category::Report, 8 * (
            size_of::<PhaseFailure<MulNativeOperationFailure>>()
            + size_of::<RetainedFailure<MulNativeOperationFailure>>()))?;
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/full-workflow/native-mul-source/v2-source-verifier");
        identity.update(u64::try_from(verification.bounds().component_reservation_bytes)
            .map_err(|_| MulNativeOperationFailure::Overflow)?.to_le_bytes());
        identity.update(scope.source_fingerprint());
        identity.update(scope.compiled_source_fingerprint());
        identity.update(sources.get().native_identity());
        identity.update(sources.get().plan().label());
        identity.update(sources.get().context().context);
        for word in sources.get().context().statement.iter().chain(&sources.get().context().node_manifest) {
            identity.update(word.as_canonical_u64().to_le_bytes());
        }
            let descriptor = native.source().kind();
            for value in [batch as u64, descriptor.modulus(), descriptor.count() as u64] {
                identity.update(value.to_le_bytes());
            }
            for &index in native.source().operation_indices() {
                identity.update(u64::try_from(index).map_err(|_| MulNativeOperationFailure::Overflow)?.to_le_bytes());
            }
            for value in native.source().expected_public_values() {
                identity.update(value.as_canonical_u64().to_le_bytes());
            }
        let g = native.preparation().geometry();
        for n in [g.rows(), g.width(), g.public_values(), g.periodic_columns(), g.raw_words(), g.period()] {
            identity.update(u64::try_from(n).map_err(|_| MulNativeOperationFailure::Overflow)?.to_le_bytes());
        }
        Ok(Self { context: scope.context(), sources, native, verification, workflow_source: scope.source_fingerprint(),
            facts: PhaseFacts { kind: PhaseKind::MulNative,
                compiled_source_fingerprint: scope.compiled_source_fingerprint(),
                source_fingerprint: identity.finalize().into(), output, failure, scratch },
            backend: Bytes { host: 24 << 30, device: 8 << 30 },
            metadata: original.take().expect("same admitted metadata original") })
        })();
        constructed.map_err(|error| (error, original.expect("refusal before metadata transfer")))
    }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.context }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.facts.source_fingerprint }
    pub(crate) fn workflow_source_fingerprint(&self) -> [u8; 32] { self.workflow_source }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.facts.compiled_source_fingerprint }
    pub(crate) fn backend_allowance(&self) -> Bytes { self.backend }
    pub(crate) fn phase_count(&self) -> usize { 1 }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { (ordinal == 0).then_some(self.facts) }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.sources.belongs_to(ledger) && self.metadata.belongs_to(ledger)
    }
    /// Retained closure/packet/caller owners, in addition to source input owners
    /// and phase output. The coordinator reserves this once per concrete source
    /// plan before constructing its preissue packet vector.
    pub(crate) fn metadata_requirements() -> Result<Requirements> {
        let core = lattica_prover_p3::block_v2::native_gpu::owned_mul::NativeMulReservationPlan::preissue_metadata_host_bytes()
            .map_err(|_| MulNativeOperationFailure::Resource)?;
        let issuer = crate::execution::workflow_resources::mul_native_packet_metadata_host_bytes()
            .map_err(|_| MulNativeOperationFailure::Resource)?;
        requirement(Category::RegisteredMetadata, add(add(add(core, issuer)?, MulProofPlan::metadata_host_bytes())?,
            8 * (size_of::<Self>() + size_of::<Result<Self>>() + size_of::<PhaseFacts>()
                + size_of::<core::result::Result<Self, (MulNativeOperationFailure, Reservation)>>()
                + size_of::<Option<Reservation>>() + size_of::<(MulNativeOperationFailure, Reservation)>()))?)
    }
    pub(crate) fn kind(&self) -> MulDescriptor { self.native.preparation().geometry().kind() }
    pub(crate) fn source(&self) -> MulSource<'a> { self.native.source() }
    pub(crate) fn batch(&self) -> &'a crate::graph_proofs::PlannedBatch { self.native.source().batch() }
    pub(crate) fn batch_ordinal(&self) -> usize { self.native.source().batch_ordinal() }
    pub(crate) fn operation_indices(&self) -> &'a [usize] { self.native.source().operation_indices() }
    pub(crate) fn policy(&self) -> ProofCachePolicy { ProofCachePolicy::FreshOnly }
    pub(crate) fn output_plan(&self) -> MulOutputPlan { self.native.output_plan() }
    pub(crate) fn source_requirements(&self) -> (Requirements, Requirements) { (self.facts.output, self.facts.scratch) }
    pub(crate) fn verifier_requirement(&self) -> Requirements { self.verification.component_requirement() }
    /// Source-only planning claim, split before constructing this plan. This
    /// starts no runtime/proof and does not authorize supplied verifier bytes.
    pub(crate) fn verification_planning_requirements(kind: MulDescriptor) -> Result<Requirements> {
        if kind.count() > crate::graph_proofs::owned_mul::verification_memory::MAX_VERIFIER_COUNT {
            return Err(MulNativeOperationFailure::Source);
        }
        let preparation = lattica_prover_p3::block_v2::native_gpu::mul_preparation::MulPreparationPlan::new(kind)
            .map_err(|_| MulNativeOperationFailure::Resource)?;
        let core = NativeMulReservationPlan::outer_host_v1(preparation, 1)
            .and_then(|plan| plan.preparation_requirement())
            .map_err(|_| MulNativeOperationFailure::Resource)?;
        let callers = add(Self::recording_caller_host_bytes()?, MulProofPlan::caller_host_bytes()
            .map_err(|_| MulNativeOperationFailure::Resource)?)?;
        combine(&[core, requirement(Category::PhaseScratch, callers)?])
    }
    pub(crate) fn reservation_plan_outer_host_v1(&self, operation_host: usize)
        -> Result<NativeMulReservationPlan>
    {
        NativeMulReservationPlan::outer_host_v1(self.native.preparation(), operation_host)
            .map_err(|_| MulNativeOperationFailure::Resource)
    }
    /// Source recording and verifier bound close during preissue, before proof
    /// zero. Dropping recorded returns the original exclusive preparation borrow.
    pub(crate) fn verification_preflight(&self, original: &mut Reservation, ledger: &Ledger)
        -> Result<VerificationPlan>
    {
        let recorded = self.native.record(original, ledger)
            .map_err(|_| MulNativeOperationFailure::Preparation)?;
        let verification = recorded.verification_plan();
        if !verification.same_census(self.verification) { return Err(MulNativeOperationFailure::SourceDrift); }
        Ok(verification)
    }
    pub(crate) fn operation(&self) -> Result<MulNativeOperation<'_, 'a>> {
        Ok(MulNativeOperation { plan: self,
            binding: PhaseBinding::for_mul_native(self, 0).map_err(|_| MulNativeOperationFailure::Authority)? })
    }
}

pub(crate) struct MulNativeOperation<'plan, 'a> {
    plan: &'plan MulNativeOperationPlan<'a>,
    binding: PhaseBinding,
}
pub(crate) struct RecordedMul<'plan, 'claim, 'a> {
    prepared: PreparedMulSource<'plan, 'a, 'claim>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
pub(crate) struct ProducedMul<'a> {
    proof: UnverifiedMulProof<'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl ProducedMul<'_> {
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    /// Exact immutable retained trace geometry and the actual proof degree.
    /// These numbers describe output already produced; they admit no work.
    pub(crate) fn actual_row_geometry(&self) -> (usize, usize) {
        (self.proof.owned().geometry().rows(), self.proof.artifact().proof().degree_bits)
    }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
type MulNativeFailureOutcome<'a> = core::result::Result<
    (OwnedMulOutput<'a>, Reservation),
    (MulNativeOperationFailure, ProducedMul<'a>, Reservation)>;

impl<'a> MulNativeOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn plan(&self) -> &MulNativeOperationPlan<'a> { self.plan }
    pub(crate) fn output_plan(&self) -> Result<MulOutputPlan> { Ok(self.plan.output_plan()) }
    pub(crate) fn source_requirements(&self) -> Result<(Requirements, Requirements)> { Ok(self.plan.source_requirements()) }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger,
        expected: VerificationPlan) -> Result<RecordedMul<'plan, 'claim, 'a>>
    {
        let prepared = self.plan.native.record(original, ledger)
            .map_err(|_| MulNativeOperationFailure::Preparation)?;
        if !prepared.verification_plan().same_census(expected) || !expected.same_census(self.plan.verification) {
            return Err(MulNativeOperationFailure::SourceDrift);
        }
        Ok(RecordedMul { prepared, sources: self.plan.sources, binding: self.binding })
    }
    /// # Safety
    /// The issuer retains the exact original Runtime/startup/phase and immutable
    /// process/device selection through actual runtime destruction.
    pub(crate) unsafe fn produce(&self, execution: &ExecutionAccess<'_>, phase: &mut NativeMulPhase,
        recorded: RecordedMul<'_, '_, 'a>, runtime: &Runtime, startup: &Reservation, verifier: &Reservation)
        -> Result<ProducedMul<'a>>
    {
        if execution.binding() != self.binding || recorded.binding != self.binding
            || !core::ptr::eq(execution.context(), self.plan.context)
            || execution.context().policy() != Policy::GpuRequired
            || !execution.owns_source(self.plan.sources)
            || !core::ptr::eq(recorded.sources, self.plan.sources)
            || !recorded.prepared.source().same_source(self.plan.native.source())
            || self.plan.policy() != ProofCachePolicy::FreshOnly {
            return Err(MulNativeOperationFailure::Authority);
        }
        let proof = unsafe { recorded.prepared.produce(phase, runtime, startup, verifier) }
            .map_err(|_| MulNativeOperationFailure::Native)?;
        Ok(ProducedMul { proof, sources: self.plan.sources, binding: self.binding })
    }
    pub(crate) fn verify_and_finish(self, produced: ProducedMul<'a>, original: Reservation,
        ledger: &Ledger) -> MulNativeFailureOutcome<'a>
    {
        if produced.binding != self.binding || !core::ptr::eq(produced.sources, self.plan.sources)
            || !produced.proof.source().same_source(self.plan.native.source())
            || produced.proof.owned().geometry() != self.plan.native.preparation().geometry() {
            return Err((MulNativeOperationFailure::Authority, produced, original));
        }
        let ProducedMul { proof, sources, binding } = produced;
        match proof.verify_retaining(original, ledger) {
            Ok((proof, original)) => Ok((OwnedMulOutput { proof, sources, binding }, original)),
            Err((_failure, proof, original)) => Err((MulNativeOperationFailure::Verification,
                ProducedMul { proof, sources, binding }, original)),
        }
    }
}

pub(crate) struct OwnedMulOutput<'a> {
    proof: VerifiedMulProof<'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl<'a> OwnedMulOutput<'a> {
    pub(crate) fn proof(&self) -> &VerifiedMulProof<'a> { &self.proof }
    pub(crate) fn artifact(&self) -> &lattica_prover_p3::block_v2::native_mul_proof::NativeMulProof { self.proof.artifact() }
    pub(crate) fn source(&self) -> MulSource<'a> { self.proof.source() }
    pub(crate) fn batch(&self) -> &'a crate::graph_proofs::PlannedBatch { self.proof.source().batch() }
    pub(crate) fn batch_ordinal(&self) -> usize { self.proof.source().batch_ordinal() }
    pub(crate) fn operation_indices(&self) -> &'a [usize] { self.proof.source().operation_indices() }
    pub(crate) fn kind(&self) -> MulDescriptor { self.proof.source().kind() }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
