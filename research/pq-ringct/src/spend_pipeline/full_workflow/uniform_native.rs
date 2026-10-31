//! Concrete uniform-source native operation. Every exact auxiliary request
//! enters whole-workflow preissue before proof zero; no cache/import path.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind,
            PhaseFailure, RetainedFailure, RetainedNative, SourceRetained},
        ProvingContext,
    },
    graph_auxiliary::{Role, AuxiliaryRequest, owned_uniform::{UniformProofPlan,
        UniformSource, PreparedUniformSource, UnverifiedUniformProof, VerifiedUniformProof,
        verification_memory::Plan as VerificationPlan}},
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            uniform_preparation::UniformKind,
            uniform_output::UniformOutputPlan,
            owned_uniform::{NativeUniformPhase, NativeUniformReservationPlan},
        },
    },
    proving::{Policy, Report},
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UniformNativeOperationFailure {
    Authority, Resource, Source, SourceDrift, Preparation, Native, Verification, Overflow,
}
type Result<T> = core::result::Result<T, UniformNativeOperationFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(UniformNativeOperationFailure::Overflow)
}
fn requirement(category: Category, count: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes { host: u64::try_from(count)
        .map_err(|_| UniformNativeOperationFailure::Overflow)?, device: 0 }))
}
fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| UniformNativeOperationFailure::Overflow)?;
    } }
    Ok(result)
}

/// Exactly one source family. Native/outer/parent closure is separate.
pub(crate) struct UniformNativeOperationPlan<'a> {
    context: &'a ProvingContext,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    native: UniformProofPlan<'a>,
    workflow_source: [u8; 32],
    facts: PhaseFacts,
    backend: Bytes,
    // Last owner: all source-plan and preissue-packet borrows end before the
    // exact original metadata claim can be released or returned for cleanup.
    metadata: Reservation,
}
impl<'a> UniformNativeOperationPlan<'a> {
    pub(crate) fn new(scope: &SourcePlanningPlan<'a>,
        sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, operation: usize, role: Role,
        original: Reservation, ledger: &Ledger)
        -> core::result::Result<Self, (UniformNativeOperationFailure, Reservation)>
    {
        let mut original = Some(original);
        let constructed = (|| -> Result<Self> {
        let held = original.as_ref().expect("unconsumed metadata original");
        if !held.belongs_to(ledger) || !sources.belongs_to(ledger)
            || held.requirements() != Self::metadata_requirements()? {
            return Err(UniformNativeOperationFailure::Authority);
        }
        scope.validate_initial_source(sources.get().native_source())
            .map_err(|_| UniformNativeOperationFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired
            || sources.source_fingerprint() != scope.source_fingerprint()
            || sources.compiled_source_fingerprint() != scope.compiled_source_fingerprint() {
            return Err(UniformNativeOperationFailure::Authority);
        }
        let native = UniformProofPlan::new(sources, operation, role)
            .map_err(|_| UniformNativeOperationFailure::Source)?;
        let reservations = NativeUniformReservationPlan::outer_host_v1(native.preparation(), 1)
            .map_err(|_| UniformNativeOperationFailure::Resource)?;
        let output = combine(&[native.output_plan().proof_requirement(), native.output_plan().report_requirement(),
            requirement(Category::RegisteredMetadata, 8 * (
                size_of::<ProducedUniform<'static>>() + size_of::<OwnedUniformOutput<'static>>()
                + size_of::<RetainedNative<OwnedUniformOutput<'static>>>()))?])?;
        let frames = [
            size_of::<Self>(), size_of::<Result<Self>>(), size_of::<UniformNativeOperation<'static, 'static>>(),
            size_of::<RecordedUniform<'static, 'static>>(), size_of::<ProducedUniform<'static>>(),
            size_of::<OwnedUniformOutput<'static>>(), size_of::<VerificationPlan>(),
            size_of::<Result<VerificationPlan>>(), size_of::<UniformNativeFailureOutcome<'static>>(),
            size_of::<[Reservation; 8]>(), size_of::<[Requirements; 8]>(),
            size_of::<PhaseFacts>(), size_of::<PhaseBinding>(), size_of::<Sha3_256>(),
        ].into_iter().try_fold(0, add)?.checked_mul(8).ok_or(UniformNativeOperationFailure::Overflow)?;
        let scratch = combine(&[reservations.preparation_requirement()
            .map_err(|_| UniformNativeOperationFailure::Resource)?, VerificationPlan::component_requirement(),
            requirement(Category::PhaseScratch, add(frames, UniformProofPlan::caller_host_bytes()
                .map_err(|_| UniformNativeOperationFailure::Resource)?)?)?,
            crate::execution::workflow_resources::uniform_native_issuer_scratch_requirements()
                .map_err(|_| UniformNativeOperationFailure::Resource)?,
        ])?;
        let failure = requirement(Category::Report, 8 * (
            size_of::<PhaseFailure<UniformNativeOperationFailure>>()
            + size_of::<RetainedFailure<UniformNativeOperationFailure>>()))?;
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/full-workflow/native-uniform-source/v1");
        identity.update(scope.source_fingerprint());
        identity.update(scope.compiled_source_fingerprint());
        identity.update(sources.get().native_identity());
        identity.update(sources.get().plan().label());
        identity.update(sources.get().context().context);
        for word in sources.get().context().statement.iter().chain(&sources.get().context().node_manifest) {
            identity.update(word.as_canonical_u64().to_le_bytes());
        }
        identity.update(native.source().request().cache_key());
        identity.update([role as u8]);
        identity.update(u64::try_from(operation).map_err(|_| UniformNativeOperationFailure::Overflow)?.to_le_bytes());
        identity.update([match native.source().kind() { UniformKind::SampleG4 => 0, UniformKind::ExpandAlpha2 => 1 }]);
        let g = native.preparation().geometry();
        for n in [g.rows(), g.width(), g.public_values(), g.periodic_columns(), g.raw_words(), g.period()] {
            identity.update(u64::try_from(n).map_err(|_| UniformNativeOperationFailure::Overflow)?.to_le_bytes());
        }
        Ok(Self { context: scope.context(), sources, native, workflow_source: scope.source_fingerprint(),
            facts: PhaseFacts { kind: PhaseKind::UniformNative,
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
        let core = lattica_prover_p3::block_v2::native_gpu::owned_uniform::NativeUniformReservationPlan::preissue_metadata_host_bytes()
            .map_err(|_| UniformNativeOperationFailure::Resource)?;
        let issuer = crate::execution::workflow_resources::uniform_native_packet_metadata_host_bytes()
            .map_err(|_| UniformNativeOperationFailure::Resource)?;
        requirement(Category::RegisteredMetadata, add(add(core, issuer)?,
            8 * (size_of::<Self>() + size_of::<Result<Self>>() + size_of::<PhaseFacts>()
                + size_of::<core::result::Result<Self, (UniformNativeOperationFailure, Reservation)>>()
                + size_of::<Option<Reservation>>() + size_of::<(UniformNativeOperationFailure, Reservation)>()))?)
    }
    pub(crate) fn kind(&self) -> UniformKind { self.native.preparation().geometry().kind() }
    pub(crate) fn source(&self) -> UniformSource<'a> { self.native.source() }
    pub(crate) fn request(&self) -> &'a AuxiliaryRequest { self.native.source().request() }
    pub(crate) fn operation_index(&self) -> usize { self.native.source().operation_index() }
    pub(crate) fn role(&self) -> Role { self.native.source().role() }
    pub(crate) fn policy(&self) -> ProofCachePolicy { ProofCachePolicy::FreshOnly }
    pub(crate) fn output_plan(&self) -> UniformOutputPlan { self.native.output_plan() }
    pub(crate) fn source_requirements(&self) -> (Requirements, Requirements) { (self.facts.output, self.facts.scratch) }
    pub(crate) fn reservation_plan_outer_host_v1(&self, operation_host: usize)
        -> Result<NativeUniformReservationPlan>
    {
        NativeUniformReservationPlan::outer_host_v1(self.native.preparation(), operation_host)
            .map_err(|_| UniformNativeOperationFailure::Resource)
    }
    /// Source recording and verifier bound close during preissue, before proof
    /// zero. Dropping recorded returns the original exclusive preparation borrow.
    pub(crate) fn verification_preflight(&self, original: &mut Reservation, ledger: &Ledger)
        -> Result<VerificationPlan>
    {
        let recorded = self.native.record(original, ledger)
            .map_err(|_| UniformNativeOperationFailure::Preparation)?;
        Ok(recorded.verification_plan())
    }
    pub(crate) fn operation(&self) -> Result<UniformNativeOperation<'_, 'a>> {
        Ok(UniformNativeOperation { plan: self,
            binding: PhaseBinding::for_uniform_native(self, 0).map_err(|_| UniformNativeOperationFailure::Authority)? })
    }
}

pub(crate) struct UniformNativeOperation<'plan, 'a> {
    plan: &'plan UniformNativeOperationPlan<'a>,
    binding: PhaseBinding,
}
pub(crate) struct RecordedUniform<'claim, 'a> {
    prepared: PreparedUniformSource<'a, 'claim>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
pub(crate) struct ProducedUniform<'a> {
    proof: UnverifiedUniformProof<'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl ProducedUniform<'_> {
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    /// Exact immutable retained trace geometry and the actual proof degree.
    /// These numbers describe output already produced; they admit no work.
    pub(crate) fn actual_row_geometry(&self) -> (usize, usize) {
        (self.proof.owned().geometry().rows(), self.proof.artifact().proof().degree_bits)
    }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
type UniformNativeFailureOutcome<'a> = core::result::Result<
    (OwnedUniformOutput<'a>, Reservation),
    (UniformNativeOperationFailure, ProducedUniform<'a>, Reservation)>;

impl<'a> UniformNativeOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn plan(&self) -> &UniformNativeOperationPlan<'a> { self.plan }
    pub(crate) fn output_plan(&self) -> Result<UniformOutputPlan> { Ok(self.plan.output_plan()) }
    pub(crate) fn source_requirements(&self) -> Result<(Requirements, Requirements)> { Ok(self.plan.source_requirements()) }
    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger,
        expected: VerificationPlan) -> Result<RecordedUniform<'claim, 'a>>
    {
        let prepared = self.plan.native.record(original, ledger)
            .map_err(|_| UniformNativeOperationFailure::Preparation)?;
        if !prepared.verification_plan().same_census(expected) {
            return Err(UniformNativeOperationFailure::SourceDrift);
        }
        Ok(RecordedUniform { prepared, sources: self.plan.sources, binding: self.binding })
    }
    /// # Safety
    /// The issuer retains the exact original Runtime/startup/phase and immutable
    /// process/device selection through actual runtime destruction.
    pub(crate) unsafe fn produce(&self, execution: &ExecutionAccess<'_>, phase: &mut NativeUniformPhase,
        recorded: RecordedUniform<'_, 'a>, runtime: &Runtime, startup: &Reservation, verifier: &Reservation)
        -> Result<ProducedUniform<'a>>
    {
        if execution.binding() != self.binding || recorded.binding != self.binding
            || !core::ptr::eq(execution.context(), self.plan.context)
            || execution.context().policy() != Policy::GpuRequired
            || !execution.owns_source(self.plan.sources)
            || !core::ptr::eq(recorded.sources, self.plan.sources)
            || !recorded.prepared.source().same_source(self.plan.native.source())
            || self.plan.policy() != ProofCachePolicy::FreshOnly {
            return Err(UniformNativeOperationFailure::Authority);
        }
        let proof = unsafe { recorded.prepared.produce(phase, runtime, startup, verifier) }
            .map_err(|_| UniformNativeOperationFailure::Native)?;
        Ok(ProducedUniform { proof, sources: self.plan.sources, binding: self.binding })
    }
    pub(crate) fn verify_and_finish(self, produced: ProducedUniform<'a>, original: Reservation,
        ledger: &Ledger) -> UniformNativeFailureOutcome<'a>
    {
        if produced.binding != self.binding || !core::ptr::eq(produced.sources, self.plan.sources)
            || !produced.proof.source().same_source(self.plan.native.source())
            || produced.proof.owned().geometry() != self.plan.native.preparation().geometry() {
            return Err((UniformNativeOperationFailure::Authority, produced, original));
        }
        let ProducedUniform { proof, sources, binding } = produced;
        match proof.verify_retaining(original, ledger) {
            Ok((proof, original)) => Ok((OwnedUniformOutput { proof, sources, binding }, original)),
            Err((_failure, proof, original)) => Err((UniformNativeOperationFailure::Verification,
                ProducedUniform { proof, sources, binding }, original)),
        }
    }
}

pub(crate) struct OwnedUniformOutput<'a> {
    proof: VerifiedUniformProof<'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl<'a> OwnedUniformOutput<'a> {
    pub(crate) fn proof(&self) -> &VerifiedUniformProof<'a> { &self.proof }
    pub(crate) fn artifact(&self) -> &lattica_prover_p3::block_v2::native_uniform_proof::NativeUniformProof { self.proof.artifact() }
    pub(crate) fn source(&self) -> UniformSource<'a> { self.proof.source() }
    pub(crate) fn request(&self) -> &'a AuxiliaryRequest { self.proof.source().request() }
    pub(crate) fn operation_index(&self) -> usize { self.proof.source().operation_index() }
    pub(crate) fn role(&self) -> Role { self.proof.source().role() }
    pub(crate) fn kind(&self) -> UniformKind { self.proof.source().kind() }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
