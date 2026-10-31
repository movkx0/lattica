//! Concrete one-source native operation, with no cache/import path. Both
//! sources must be included in whole-workflow preissue before proof zero.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind,
            PhaseFailure, RetainedFailure, RetainedNative, SourceRetained},
        ProvingContext,
    },
    graph_sources::{
        owned_native::{SourceNativePlan, PreparedSource, UnverifiedSourceProof, VerifiedSourceProof},
        verification_memory::Plan as VerificationPlan,
    },
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            graph_source_preparation::GraphSourceKind,
            graph_source_output::GraphSourceOutputPlan,
            owned_graph_source::{NativeGraphSourcePhase, NativeGraphSourceReservationPlan},
        },
    },
    proving::{Policy, Report},
};
use p3_field::PrimeField64;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceNativeOperationFailure {
    Authority, Resource, Source, SourceDrift, Preparation, Native, Verification, Overflow,
}
type Result<T> = core::result::Result<T, SourceNativeOperationFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(SourceNativeOperationFailure::Overflow)
}
fn requirement(category: Category, count: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes { host: u64::try_from(count)
        .map_err(|_| SourceNativeOperationFailure::Overflow)?, device: 0 }))
}
fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| SourceNativeOperationFailure::Overflow)?;
    } }
    Ok(result)
}

/// Exactly one source family. Native/outer/parent closure is separate.
pub(crate) struct SourceNativeOperationPlan<'a> {
    context: &'a ProvingContext,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    native: SourceNativePlan<'a, 'a>,
    workflow_source: [u8; 32],
    facts: PhaseFacts,
    backend: Bytes,
    // Last owner: all source-plan and preissue-packet borrows end before the
    // exact original metadata claim can be released or returned for cleanup.
    metadata: Reservation,
}
impl<'a> SourceNativeOperationPlan<'a> {
    pub(crate) fn new(scope: &SourcePlanningPlan<'a>,
        sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, kind: GraphSourceKind,
        original: Reservation, ledger: &Ledger)
        -> core::result::Result<Self, (SourceNativeOperationFailure, Reservation)>
    {
        let mut original = Some(original);
        let constructed = (|| -> Result<Self> {
        let held = original.as_ref().expect("unconsumed metadata original");
        if !held.belongs_to(ledger) || !sources.belongs_to(ledger)
            || held.requirements() != Self::metadata_requirements()? {
            return Err(SourceNativeOperationFailure::Authority);
        }
        scope.validate_initial_source(sources.get().native_source())
            .map_err(|_| SourceNativeOperationFailure::Authority)?;
        if scope.context().policy() != Policy::GpuRequired
            || sources.source_fingerprint() != scope.source_fingerprint()
            || sources.compiled_source_fingerprint() != scope.compiled_source_fingerprint() {
            return Err(SourceNativeOperationFailure::Authority);
        }
        let native = SourceNativePlan::new(sources.get().source_factory(), kind)
            .map_err(|_| SourceNativeOperationFailure::Source)?;
        let reservations = NativeGraphSourceReservationPlan::outer_host_v1(native.preparation(), 1)
            .map_err(|_| SourceNativeOperationFailure::Resource)?;
        let output = combine(&[native.output_plan().proof_requirement(), native.output_plan().report_requirement(),
            requirement(Category::RegisteredMetadata, 8 * (
                size_of::<ProducedSourceNative<'static>>() + size_of::<OwnedSourceNativeOutput<'static>>()
                + size_of::<RetainedNative<OwnedSourceNativeOutput<'static>>>()))?])?;
        let frames = [
            size_of::<Self>(), size_of::<Result<Self>>(), size_of::<SourceNativeOperation<'static, 'static>>(),
            size_of::<RecordedSourceNative<'static, 'static>>(), size_of::<ProducedSourceNative<'static>>(),
            size_of::<OwnedSourceNativeOutput<'static>>(), size_of::<VerificationPlan>(),
            size_of::<Result<VerificationPlan>>(), size_of::<SourceNativeFailureOutcome<'static>>(),
            size_of::<[Reservation; 8]>(), size_of::<[Requirements; 8]>(),
            size_of::<PhaseFacts>(), size_of::<PhaseBinding>(), size_of::<Sha3_256>(),
        ].into_iter().try_fold(0, add)?.checked_mul(8).ok_or(SourceNativeOperationFailure::Overflow)?;
        let scratch = combine(&[reservations.preparation_requirement()
            .map_err(|_| SourceNativeOperationFailure::Resource)?, VerificationPlan::component_requirement(),
            requirement(Category::PhaseScratch, add(frames, SourceNativePlan::caller_host_bytes()
                .map_err(|_| SourceNativeOperationFailure::Resource)?)?)?,
            crate::execution::workflow_resources::source_native_issuer_scratch_requirements()
                .map_err(|_| SourceNativeOperationFailure::Resource)?,
        ])?;
        let failure = requirement(Category::Report, 8 * (
            size_of::<PhaseFailure<SourceNativeOperationFailure>>()
            + size_of::<RetainedFailure<SourceNativeOperationFailure>>()))?;
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/full-workflow/native-graph-source/v1");
        identity.update(scope.source_fingerprint());
        identity.update(scope.compiled_source_fingerprint());
        identity.update(sources.get().native_identity());
        identity.update(sources.get().plan().label());
        identity.update(sources.get().context().context);
        for word in sources.get().context().statement.iter().chain(&sources.get().context().node_manifest) {
            identity.update(word.as_canonical_u64().to_le_bytes());
        }
        identity.update([match kind { GraphSourceKind::Statement => 0, GraphSourceKind::PrivateProof => 1 }]);
        let g = native.preparation().geometry();
        for n in [g.rows(), g.width(), g.public_values(), g.periodic_columns(), g.raw_words(), g.geometry_words()] {
            identity.update(u64::try_from(n).map_err(|_| SourceNativeOperationFailure::Overflow)?.to_le_bytes());
        }
        Ok(Self { context: scope.context(), sources, native, workflow_source: scope.source_fingerprint(),
            facts: PhaseFacts { kind: PhaseKind::SourceNative,
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
        let core = lattica_prover_p3::block_v2::native_gpu::owned_graph_source::NativeGraphSourceReservationPlan::preissue_metadata_host_bytes()
            .map_err(|_| SourceNativeOperationFailure::Resource)?;
        let issuer = crate::execution::workflow_resources::source_native_packet_metadata_host_bytes()
            .map_err(|_| SourceNativeOperationFailure::Resource)?;
        requirement(Category::RegisteredMetadata, add(add(core, issuer)?,
            8 * (size_of::<Self>() + size_of::<Result<Self>>() + size_of::<PhaseFacts>()
                + size_of::<core::result::Result<Self, (SourceNativeOperationFailure, Reservation)>>()
                + size_of::<Option<Reservation>>() + size_of::<(SourceNativeOperationFailure, Reservation)>()))?)
    }
    pub(crate) fn kind(&self) -> GraphSourceKind { self.native.preparation().geometry().kind() }
    pub(crate) fn policy(&self) -> ProofCachePolicy { ProofCachePolicy::FreshOnly }
    pub(crate) fn output_plan(&self) -> GraphSourceOutputPlan { self.native.output_plan() }
    pub(crate) fn source_requirements(&self) -> (Requirements, Requirements) { (self.facts.output, self.facts.scratch) }
    pub(crate) fn reservation_plan_outer_host_v1(&self, operation_host: usize)
        -> Result<NativeGraphSourceReservationPlan>
    {
        NativeGraphSourceReservationPlan::outer_host_v1(self.native.preparation(), operation_host)
            .map_err(|_| SourceNativeOperationFailure::Resource)
    }
    /// Source recording and verifier bound close during preissue, before proof
    /// zero. Dropping recorded returns the original exclusive preparation borrow.
    pub(crate) fn verification_preflight(&self, original: &mut Reservation, ledger: &Ledger)
        -> Result<VerificationPlan>
    {
        let recorded = self.native.record(original, ledger)
            .map_err(|_| SourceNativeOperationFailure::Preparation)?;
        Ok(recorded.verification_plan())
    }
    pub(crate) fn operation(&self) -> Result<SourceNativeOperation<'_, 'a>> {
        Ok(SourceNativeOperation { plan: self,
            binding: PhaseBinding::for_source_native(self, 0).map_err(|_| SourceNativeOperationFailure::Authority)? })
    }
}

pub(crate) struct SourceNativeOperation<'plan, 'a> {
    plan: &'plan SourceNativeOperationPlan<'a>,
    binding: PhaseBinding,
}
pub(crate) struct RecordedSourceNative<'claim, 'a> {
    prepared: PreparedSource<'a, 'a, 'claim>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
pub(crate) struct ProducedSourceNative<'a> {
    proof: UnverifiedSourceProof<'a, 'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl ProducedSourceNative<'_> {
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    /// Exact immutable retained trace geometry and the actual proof degree.
    /// These numbers describe output already produced; they admit no work.
    pub(crate) fn actual_row_geometry(&self) -> (usize, usize) {
        (self.proof.owned().geometry().rows(), self.proof.artifact().proof().degree_bits)
    }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
type SourceNativeFailureOutcome<'a> = core::result::Result<
    (OwnedSourceNativeOutput<'a>, Reservation),
    (SourceNativeOperationFailure, ProducedSourceNative<'a>, Reservation)>;

impl<'a> SourceNativeOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn plan(&self) -> &SourceNativeOperationPlan<'a> { self.plan }
    pub(crate) fn output_plan(&self) -> Result<GraphSourceOutputPlan> { Ok(self.plan.output_plan()) }
    pub(crate) fn source_requirements(&self) -> Result<(Requirements, Requirements)> { Ok(self.plan.source_requirements()) }
    pub(crate) fn record<'claim>(&self, original: &'claim mut Reservation, ledger: &'claim Ledger,
        expected: VerificationPlan) -> Result<RecordedSourceNative<'claim, 'a>>
    {
        let prepared = self.plan.native.record(original, ledger)
            .map_err(|_| SourceNativeOperationFailure::Preparation)?;
        if !prepared.verification_plan().same_census(expected) {
            return Err(SourceNativeOperationFailure::SourceDrift);
        }
        Ok(RecordedSourceNative { prepared, sources: self.plan.sources, binding: self.binding })
    }
    /// # Safety
    /// The issuer retains the exact original Runtime/startup/phase and immutable
    /// process/device selection through actual runtime destruction.
    pub(crate) unsafe fn produce(&self, execution: &ExecutionAccess<'_>, phase: &mut NativeGraphSourcePhase,
        recorded: RecordedSourceNative<'_, 'a>, runtime: &Runtime, startup: &Reservation, verifier: &Reservation)
        -> Result<ProducedSourceNative<'a>>
    {
        if execution.binding() != self.binding || recorded.binding != self.binding
            || !core::ptr::eq(execution.context(), self.plan.context)
            || execution.context().policy() != Policy::GpuRequired
            || !execution.owns_source(self.plan.sources)
            || !core::ptr::eq(recorded.sources, self.plan.sources)
            || !core::ptr::eq(recorded.prepared.source(), self.plan.sources.get().source_factory())
            || self.plan.policy() != ProofCachePolicy::FreshOnly {
            return Err(SourceNativeOperationFailure::Authority);
        }
        let proof = unsafe { recorded.prepared.produce(phase, runtime, startup, verifier) }
            .map_err(|_| SourceNativeOperationFailure::Native)?;
        Ok(ProducedSourceNative { proof, sources: self.plan.sources, binding: self.binding })
    }
    pub(crate) fn verify_and_finish(self, produced: ProducedSourceNative<'a>, original: Reservation,
        ledger: &Ledger) -> SourceNativeFailureOutcome<'a>
    {
        if produced.binding != self.binding || !core::ptr::eq(produced.sources, self.plan.sources)
            || !core::ptr::eq(produced.proof.source(), self.plan.sources.get().source_factory())
            || produced.proof.owned().geometry() != self.plan.native.preparation().geometry() {
            return Err((SourceNativeOperationFailure::Authority, produced, original));
        }
        let ProducedSourceNative { proof, sources, binding } = produced;
        match proof.verify_retaining(original, ledger) {
            Ok((proof, original)) => Ok((OwnedSourceNativeOutput { proof, sources, binding }, original)),
            Err((_failure, proof, original)) => Err((SourceNativeOperationFailure::Verification,
                ProducedSourceNative { proof, sources, binding }, original)),
        }
    }
}

pub(crate) struct OwnedSourceNativeOutput<'a> {
    proof: VerifiedSourceProof<'a, 'a>,
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    binding: PhaseBinding,
}
impl<'a> OwnedSourceNativeOutput<'a> {
    pub(crate) fn proof(&self) -> &VerifiedSourceProof<'a, 'a> { &self.proof }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn report(&self) -> &Report { self.proof.owned().report() }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.proof.into_originals() }
}
