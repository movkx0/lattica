//! Fresh, exact-source ntt arithmetic. Serialized operands remain in the
//! original-owned plan until native runtime retirement. Only the concrete producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::Val;
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    ntt_air::NttAir,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            ntt_output::{NttOutputPlan, OwnedNttProof},
            ntt_preparation::{NttDescriptor, NttGeometry, NttPreparationPlan},
            ntt_recording::{NttRecorder, PreparedNtt},
            owned_ntt::{NttInput, NativeNttPhase},
        },
        native_ntt_proof::NativeNttProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NttFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, NttFailure>;

/// Sealed immutable membership in one exact algebra batch of prepared sources.
#[derive(Clone, Copy)]
pub(crate) struct NttSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    batch: &'a super::PlannedBatch,
    ordinal: usize,
    kind: NttDescriptor,
    expected: &'a [Val],
}
impl<'a> NttSource<'a> {
    /// Allocation-free original source view for bootstrap planning. It owns no
    /// witness buffer, recording, proof, reservation or execution authority.
    /// The enclosing planner precharges planning_view_host_bytes() before use.
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize) -> Result<Self> {
        let prepared = sources.get();
        let algebra = prepared.algebra();
        if !core::ptr::eq(algebra.graph, prepared.graph()) { return Err(NttFailure::Source); }
        let batch = algebra.batches.get(ordinal).ok_or(NttFailure::Source)?;
        let super::ComponentKind::Ntt { modulus } = batch.kind() else { return Err(NttFailure::Source); };
        let descriptor = NttDescriptor::new(*modulus, batch.indices.len()).map_err(|_| NttFailure::Geometry)?;
        if descriptor.count() > verification_memory::MAX_VERIFIER_COUNT { return Err(NttFailure::Geometry); }
        if batch.indices.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(NttFailure::Source); }
        for &index in &batch.indices {
            if !matches!(prepared.graph().operations().get(index),
                Some(Operation::Ntt {modulus,..}) if *modulus == descriptor.modulus()) {
                return Err(NttFailure::Source);
            }
        }
        let expected = batch.expected_public.as_deref().ok_or(NttFailure::Source)?;
        if expected.len() != 8 * descriptor.count() { return Err(NttFailure::Geometry); }
        let source = Self { sources, batch, ordinal, kind: descriptor, expected };
        let air = source.air();
        if (air.height, air.width(), air.num_public_values(), air.num_periodic_columns()) != descriptor.geometry_tuple()
            || air.max_constraint_degree().is_some()
        { return Err(NttFailure::Geometry); }
        Ok(source)
    }
    pub(crate) const fn planning_view_host_bytes() -> usize {
        8 * (size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<NttDescriptor>() + size_of::<Result<NttDescriptor>>()
            + size_of::<NttAir>()
            + size_of::<[usize;32]>())
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn batch(self) -> &'a super::PlannedBatch { self.batch }
    pub(crate) fn batch_ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn kind(self) -> NttDescriptor { self.kind }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.batch, other.batch)
            && core::ptr::eq(self.expected, other.expected) && self.ordinal == other.ordinal && self.kind == other.kind
    }
    fn air(self) -> NttAir {
        NttAir::new(self.kind.modulus(), self.kind.count()).expect("validated NTT source")
    }
    fn serialize(self) -> Result<WipedRaw> {
        let words = NttGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| NttFailure::Resource)?;
        if raw.0.capacity() != words { return Err(NttFailure::Resource); }
        let algebra = self.sources.get().algebra();
        for &index in &self.batch.indices {
            let Operation::Ntt { modulus, input, .. } = algebra.graph.operations()[index]
                else { return Err(NttFailure::Source); };
            if modulus != self.kind.modulus() { return Err(NttFailure::Source); }
            let node = algebra.graph.polynomial(input);
            if node.kind != (crate::rust_verify::committed_backend::PolynomialKind::Canonical { modulus }) {
                return Err(NttFailure::Source);
            }
            let crate::rust_verify::committed_backend::PolynomialValues::Canonical(values) = &node.values
                else { return Err(NttFailure::Source); };
            if values.iter().any(|&word| word >= modulus) { return Err(NttFailure::Source); }
            raw.0.extend_from_slice(values);
        }
        if raw.0.len() != words { return Err(NttFailure::Source); }
        Ok(raw)
    }
}
struct WipedRaw(Vec<u64>);
impl Drop for WipedRaw {
    fn drop(&mut self) {
        for word in &mut self.0 { unsafe { core::ptr::write_volatile(word, 0); } }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub(crate) struct NttProofPlan<'a> {
    source: NttSource<'a>, preparation: NttPreparationPlan, output: NttOutputPlan, raw: WipedRaw,
}
impl<'a> NttProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize, original: &Reservation, ledger: &Ledger)
        -> Result<Self>
    {
        if !original.belongs_to(ledger) || !sources.belongs_to(ledger)
            || original.requirements().get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < Self::metadata_host_bytes() as u64
        { return Err(NttFailure::Resource); }
        let source = NttSource::from_original(sources, batch)?;
        let preparation = NttPreparationPlan::new(source.kind).map_err(|_| NttFailure::Resource)?;
        let output = NttOutputPlan::new(preparation).map_err(|_| NttFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(NttFailure::Geometry); }
        let raw = source.serialize()?;
        Ok(Self { source, preparation, output, raw })
    }
    // Two maximum raw buffers plus descriptors/caller frames. Admission is
    // required before serialize; the raw owner lives in the operation plan.
    pub(crate) const fn metadata_host_bytes() -> usize {
        NttSource::planning_view_host_bytes() + 2 * 128 * 256 * 8 + (64 << 10) }
    pub(crate) fn source(&self) -> NttSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> NttPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> NttOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<NttSource<'static>>(),
            size_of::<PreparedNttSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedNttSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedNttProof<'static>>(), size_of::<Result<UnverifiedNttProof<'static>>>(),
            size_of::<NttAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedNttProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<NttVerificationFailure>(),
            size_of::<NttInput<'static>>(), size_of::<NttOutputPlan>(),
            size_of::<NttPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(0usize, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(NttFailure::Resource))
    }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedNttSource<'plan, 'a, 'claim>>
    {
        let mut recorder = NttRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| NttFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| NttFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| NttFailure::VerificationBudget)?;
        Ok(PreparedNttSource { source: self.source, raw: &self.raw.0, recorded, verification })
    }
}

pub(crate) struct PreparedNttSource<'plan, 'a, 'claim> {
    source: NttSource<'a>, raw: &'plan [u64], recorded: PreparedNtt<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedNttSource<'_, 'a, '_> {
    pub(crate) fn source(&self) -> NttSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> NttPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeNttPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedNttProof<'a>>
    {
        let input = NttInput { kind: self.source.kind, words: self.raw };
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| NttFailure::Production)?;
        Ok(UnverifiedNttProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedNttProof<'a> {
    source: NttSource<'a>, owned: OwnedNttProof, verification: VerificationPlan,
}
impl<'a> UnverifiedNttProof<'a> {
    pub(crate) fn source(&self) -> NttSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeNttProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedNttProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (NttVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values() != self.source.expected_public_values()
        { return Err((NttVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((NttVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (NttVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedNttProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum NttVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedNttProof<'a>, Reservation),
    (NttVerificationFailure, UnverifiedNttProof<'a>, Reservation)>;
pub(crate) struct VerifiedNttProof<'a> {
    original: UnverifiedNttProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedNttProof<'a> {
    pub(crate) fn source(&self) -> NttSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeNttProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedNttProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
