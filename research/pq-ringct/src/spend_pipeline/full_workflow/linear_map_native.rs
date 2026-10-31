//! Concrete singleton LinearMap-source native operation. Every exact immutable algebra batch
//! enters whole-workflow preissue before proof zero; no cache/import path.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind,
            PhaseFailure, RetainedFailure, RetainedNative, SourceRetained},
        ProvingContext,
    },
    graph_proofs::owned_linear_map::{LinearMapProofPlan,
        LinearMapSource, PreparedLinearMapSource, UnverifiedLinearMapProof, VerifiedLinearMapProof,
        verification_memory::Plan as VerificationPlan},
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            linear_map_preparation::LinearMapDescriptor,
            linear_map_output::LinearMapOutputPlan,
            owned_linear_map::{NativeLinearMapPhase, NativeLinearMapReservationPlan},
        },
    },
    proving::{Policy, Report},
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinearMapNativeOperationFailure {
    Authority, Resource, Source, SourceDrift, Preparation, Native, Verification, Overflow,
}
type Result<T> = core::result::Result<T, LinearMapNativeOperationFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(LinearMapNativeOperationFailure::Overflow)
}
fn requirement(category: Category, count: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes { host: u64::try_from(count)
        .map_err(|_| LinearMapNativeOperationFailure::Overflow)?, device: 0 }))
}
fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| LinearMapNativeOperationFailure::Overflow)?;
    } }
    Ok(result)
}

/// Exactly one source family. Native/outer/parent closure is separate.
pub(crate) struct LinearMapNativeOperationPlan<'a> {
    context: &'a ProvingContext,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    native: LinearMapProofPlan<'a>,
    verification: VerificationPlan,
    workflow_source: [u8; 32],
    facts: PhaseFacts,
    backend: Bytes,
    // Last owner: all source-plan and preissue-packet borrows end before the
    // exact original metadata claim can be released or returned for cleanup.
    metadata: Reservation,
}
impl<'a> LinearMapNativeOperationPlan<'a> {
    fn recording_caller_host_bytes() -> Result<usize> {
        [
            size_of::<Self>(), size_of::<Result<Self>>(), size_of::<LinearMapNativeOperation<'static, 'static>>(),
                size_of::<RecordedLinearMap<'static, 'static, 'static>>(), size_of::<ProducedLinearMap<'static>>(),
            size_of::<OwnedLinearMapOutput<'static>>(), size_of::<VerificationPlan>(),
            size_of::<Result<VerificationPlan>>(), size_of::<LinearMapNativeFailureOutcome<'static>>(),
            size_of::<[Reservation; 8]>(), size_of::<[Requirements; 8]>(),
            size_of::<PhaseFacts>(), size_of::<PhaseBinding>(), size_of::<Sha3_256>(),
        ].into_iter().try_fold(0, add)?.checked_mul(8).ok_or(LinearMapNativeOperationFailure::Overflow)
    }
    pub(crate) fn new(scope: &SourcePlanningPlan<'a>,
        sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize,
        original: Reservation, recording: &mut Reservation, ledger: &Ledger)
        -> core::result::Result<Self, (LinearMapNativeOperationFailure, Reservation)>
    {
        let mut original = Some(original);
        let constructed = (|| -> Result<Self> {
        let held = original.as_ref().expect("unconsumed metadata original");
        if !held.belongs_to(ledger) || !sources.belongs_to(ledger)
            || held.requirements() != Self::metadata_requirements()? {
            return Err(LinearMapNativeOperationFailure::Authority);
        }
        scope.validate_initial_source(sources.get().native_source())
            .map_err(|_| LinearMapNativeOperationFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired
            || sources.source_fingerprint() != scope.source_fingerprint()
            || sources.compiled_source_fingerprint() != scope.compiled_source_fingerprint() {
            return Err(LinearMapNativeOperationFailure::Authority);
        }
            let native = LinearMapProofPlan::new(sources, batch, held, ledger)
            .map_err(|_| LinearMapNativeOperationFailure::Source)?;
        if !recording.belongs_to(ledger)
            || recording.requirements() != Self::verification_planning_requirements(native.source().kind())? {
            return Err(LinearMapNativeOperationFailure::Authority);
        }
        let verification = native.record(recording, ledger)
            .map_err(|_| LinearMapNativeOperationFailure::Preparation)?.verification_plan();
        let reservations = NativeLinearMapReservationPlan::outer_host_v1(native.preparation(), 1)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        let output = combine(&[native.output_plan().proof_requirement(), native.output_plan().report_requirement(),
            requirement(Category::RegisteredMetadata, 8 * (
                size_of::<ProducedLinearMap<'static>>() + size_of::<OwnedLinearMapOutput<'static>>()
                + size_of::<RetainedNative<OwnedLinearMapOutput<'static>>>()))?])?;
        let frames = Self::recording_caller_host_bytes()?;
        let scratch = combine(&[reservations.preparation_requirement()
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?, VerificationPlan::component_requirement(),
            requirement(Category::PhaseScratch, add(frames, LinearMapProofPlan::caller_host_bytes()
                .map_err(|_| LinearMapNativeOperationFailure::Resource)?)?)?,
            crate::execution::workflow_resources::linear_map_native_issuer_scratch_requirements()
                .map_err(|_| LinearMapNativeOperationFailure::Resource)?,
        ])?;
        let failure = requirement(Category::Report, 8 * (
            size_of::<PhaseFailure<LinearMapNativeOperationFailure>>()
            + size_of::<RetainedFailure<LinearMapNativeOperationFailure>>()))?;
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/full-workflow/native-linear_map-source/v2-frozen-verifier");
        identity.update(scope.source_fingerprint());
        identity.update(scope.compiled_source_fingerprint());
        identity.update(sources.get().native_identity());
        identity.update(sources.get().plan().label());
        identity.update(sources.get().context().context);
        for word in sources.get().context().statement.iter().chain(&sources.get().context().node_manifest) {
            identity.update(word.as_canonical_u64().to_le_bytes());
        }
            let descriptor = native.source().kind();
        identity.update(descriptor.identity());
            for value in [batch as u64, descriptor.inputs() as u64, 1] {
                identity.update(value.to_le_bytes());
            }
            for &index in native.source().operation_indices() {
                identity.update(u64::try_from(index).map_err(|_| LinearMapNativeOperationFailure::Overflow)?.to_le_bytes());
            }
            for value in native.source().expected_public_values() {
                identity.update(value.as_canonical_u64().to_le_bytes());
            }
        let g = native.preparation().geometry();
        for n in [g.rows(), g.width(), g.public_values(), g.periodic_columns(), g.raw_words(), g.period()] {
            identity.update(u64::try_from(n).map_err(|_| LinearMapNativeOperationFailure::Overflow)?.to_le_bytes());
        }
        Ok(Self { context: scope.context(), sources, native, verification, workflow_source: scope.source_fingerprint(),
            facts: PhaseFacts { kind: PhaseKind::LinearMapNative,
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
        let core = lattica_prover_p3::block_v2::native_gpu::owned_linear_map::NativeLinearMapReservationPlan::preissue_metadata_host_bytes()
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        let issuer = crate::execution::workflow_resources::linear_map_native_packet_metadata_host_bytes()
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        requirement(Category::RegisteredMetadata, add(add(add(core, issuer)?, LinearMapProofPlan::metadata_host_bytes())?,
            8 * (size_of::<Self>() + size_of::<Result<Self>>() + size_of::<PhaseFacts>()
                + size_of::<core::result::Result<Self, (LinearMapNativeOperationFailure, Reservation)>>()
                + size_of::<Option<Reservation>>() + size_of::<(LinearMapNativeOperationFailure, Reservation)>()))?)
    }
    pub(crate) fn kind(&self) -> LinearMapDescriptor { self.native.preparation().geometry().kind() }
    pub(crate) fn source(&self) -> LinearMapSource<'a> { self.native.source() }
    pub(crate) fn batch(&self) -> &'a crate::graph_proofs::PlannedBatch { self.native.source().batch() }
    pub(crate) fn batch_ordinal(&self) -> usize { self.native.source().batch_ordinal() }
    pub(crate) fn operation_indices(&self) -> &'a [usize] { self.native.source().operation_indices() }
    pub(crate) fn policy(&self) -> ProofCachePolicy { ProofCachePolicy::FreshOnly }
    pub(crate) fn output_plan(&self) -> LinearMapOutputPlan { self.native.output_plan() }
    pub(crate) fn source_requirements(&self) -> (Requirements, Requirements) { (self.facts.output, self.facts.scratch) }
    /// Pure preallocation query for constructor source recording. No runtime authority.
    pub(crate) fn verification_planning_requirements(kind: LinearMapDescriptor) -> Result<Requirements> {
        let preparation = lattica_prover_p3::block_v2::native_gpu::linear_map_preparation::LinearMapPreparationPlan::new(kind)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        let core = NativeLinearMapReservationPlan::outer_host_v1(preparation, 1)
            .and_then(|plan| plan.preparation_requirement())
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?;
        let callers = add(Self::recording_caller_host_bytes()?, LinearMapProofPlan::caller_host_bytes()
            .map_err(|_| LinearMapNativeOperationFailure::Resource)?)?;
        combine(&[core, requirement(Category::PhaseScratch, callers)?])
    }
    pub(crate) fn reservation_plan_outer_host_v1(&self, operation_host: usize)
        -> Result<NativeLinearMapReservationPlan>
    {
        NativeLinearMapReservationPlan::outer_host_v1(self.native.preparation(), operation_host)
            .map_err(|_| LinearMapNativeOperationFailure::Resource)
    }
    /// Source recording and verifier bound close during preissue, before proof
    /// zero. Dropping recorded returns the original exclusive preparation borrow.
    pub(crate) fn verification_preflight(&self, original: &mut Reservation, ledger: &Ledger)
        -> Result<VerificationPlan>
    {
        let recorded = self.native.record(original, ledger)
            .map_err(|_| LinearMapNativeOperationFailure::Preparation)?;
        let verification = recorded.verification_plan();
        if !verification.same_census(self.verification) { return Err(LinearMapNativeOperationFailure::SourceDrift); }
        Ok(verification)
    }
    pub(crate) fn operation(&self) -> Result<LinearMapNativeOperation<'_, 'a>> {
        Ok(LinearMapNativeOperation { plan: self,
            binding: PhaseBinding::for_linear_map_native(self, 0).map_err(|_| LinearMapNativeOperationFailure::Authority)? })
    }
}

pub(crate) struct LinearMapNativeOperation<'plan, 'a> {
    plan: &'plan LinearMapNativeOperationPlan<'a>,
    binding: PhaseBinding,
}
pub(crate) struct RecordedLinearMap<'plan, 'claim, 'a> {
    prepared: PreparedLinearMapSource<'plan, 'a, 'claim>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
pub(crate) struct ProducedLinearMap<'a> {
    proof: UnverifiedLinearMapProof<'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl ProducedLinearMap<'_> {
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    /// Exact immutable retained trace geometry and the actual proof degree.
    /// These numbers describe output already produced; they admit no work.
    pub(crate) fn actual_row_geometry(&self) -> (usize, usize) {
        (self.proof.owned().geometry().rows(), self.proof.artifact().proof().degree_bits)
    }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
type LinearMapNativeFailureOutcome<'a> = core::result::Result<
    (OwnedLinearMapOutput<'a>, Reservation),
    (LinearMapNativeOperationFailure, ProducedLinearMap<'a>, Reservation)>;

impl<'a> LinearMapNativeOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn plan(&self) -> &LinearMapNativeOperationPlan<'a> { self.plan }
    pub(crate) fn output_plan(&self) -> Result<LinearMapOutputPlan> { Ok(self.plan.output_plan()) }
    pub(crate) fn source_requirements(&self) -> Result<(Requirements, Requirements)> { Ok(self.plan.source_requirements()) }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger,
        expected: VerificationPlan) -> Result<RecordedLinearMap<'plan, 'claim, 'a>>
    {
        let prepared = self.plan.native.record(original, ledger)
            .map_err(|_| LinearMapNativeOperationFailure::Preparation)?;
        if !prepared.verification_plan().same_census(expected) {
            return Err(LinearMapNativeOperationFailure::SourceDrift);
        }
        Ok(RecordedLinearMap { prepared, sources: self.plan.sources, binding: self.binding })
    }
    /// # Safety
    /// The issuer retains the exact original Runtime/startup/phase and immutable
    /// process/device selection through actual runtime destruction.
    pub(crate) unsafe fn produce(&self, execution: &ExecutionAccess<'_>, phase: &mut NativeLinearMapPhase,
        recorded: RecordedLinearMap<'_, '_, 'a>, runtime: &Runtime, startup: &Reservation, verifier: &Reservation)
        -> Result<ProducedLinearMap<'a>>
    {
        if execution.binding() != self.binding || recorded.binding != self.binding
            || !core::ptr::eq(execution.context(), self.plan.context)
            || execution.context().policy() != Policy::GpuRequired
            || !execution.owns_source(self.plan.sources)
            || !core::ptr::eq(recorded.sources, self.plan.sources)
            || !recorded.prepared.source().same_source(self.plan.native.source())
            || self.plan.policy() != ProofCachePolicy::FreshOnly {
            return Err(LinearMapNativeOperationFailure::Authority);
        }
        let proof = unsafe { recorded.prepared.produce(phase, runtime, startup, verifier) }
            .map_err(|_| LinearMapNativeOperationFailure::Native)?;
        Ok(ProducedLinearMap { proof, sources: self.plan.sources, binding: self.binding })
    }
    pub(crate) fn verify_and_finish(self, produced: ProducedLinearMap<'a>, original: Reservation,
        ledger: &Ledger) -> LinearMapNativeFailureOutcome<'a>
    {
        if produced.binding != self.binding || !core::ptr::eq(produced.sources, self.plan.sources)
            || !produced.proof.source().same_source(self.plan.native.source())
            || produced.proof.owned().geometry() != self.plan.native.preparation().geometry() {
            return Err((LinearMapNativeOperationFailure::Authority, produced, original));
        }
        let ProducedLinearMap { proof, sources, binding } = produced;
        match proof.verify_retaining(original, ledger) {
            Ok((proof, original)) => Ok((OwnedLinearMapOutput { proof, sources, binding }, original)),
            Err((_failure, proof, original)) => Err((LinearMapNativeOperationFailure::Verification,
                ProducedLinearMap { proof, sources, binding }, original)),
        }
    }
}

pub(crate) struct OwnedLinearMapOutput<'a> {
    proof: VerifiedLinearMapProof<'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl<'a> OwnedLinearMapOutput<'a> {
    pub(crate) fn proof(&self) -> &VerifiedLinearMapProof<'a> { &self.proof }
    pub(crate) fn artifact(&self) -> &lattica_prover_p3::block_v2::native_linear_map_proof::NativeLinearMapProof { self.proof.artifact() }
    pub(crate) fn source(&self) -> LinearMapSource<'a> { self.proof.source() }
    pub(crate) fn batch(&self) -> &'a crate::graph_proofs::PlannedBatch { self.proof.source().batch() }
    pub(crate) fn batch_ordinal(&self) -> usize { self.proof.source().batch_ordinal() }
    pub(crate) fn operation_indices(&self) -> &'a [usize] { self.proof.source().operation_indices() }
    pub(crate) fn kind(&self) -> LinearMapDescriptor { self.proof.source().kind() }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
