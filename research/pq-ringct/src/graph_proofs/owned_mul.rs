//! Fresh, exact-source mul arithmetic. Serialized operands remain in the
//! original-owned plan until native runtime retirement. Only the concrete producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::Val;
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    poly_air::MulAir,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            mul_output::{MulOutputPlan, OwnedMulProof},
            mul_preparation::{MulDescriptor, MulGeometry, MulPreparationPlan},
            mul_recording::{MulRecorder, PreparedMul},
            owned_mul::{MulInput, NativeMulPhase},
        },
        native_mul_proof::NativeMulProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MulFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, MulFailure>;

/// Sealed immutable membership in one exact algebra batch of prepared sources.
#[derive(Clone, Copy)]
pub(crate) struct MulSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    batch: &'a super::PlannedBatch,
    ordinal: usize,
    kind: MulDescriptor,
    expected: &'a [Val],
}
impl<'a> MulSource<'a> {
    /// Allocation-free original source view for bootstrap planning. It owns no
    /// witness buffer, recording, proof, reservation or execution authority.
    /// The enclosing planner precharges planning_view_host_bytes() before use.
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize) -> Result<Self> {
        let prepared = sources.get();
        let algebra = prepared.algebra();
        if !core::ptr::eq(algebra.graph, prepared.graph()) { return Err(MulFailure::Source); }
        let batch = algebra.batches.get(ordinal).ok_or(MulFailure::Source)?;
        let super::ComponentKind::Mul { modulus } = batch.kind() else { return Err(MulFailure::Source); };
        let descriptor = MulDescriptor::new(*modulus, batch.indices.len()).map_err(|_| MulFailure::Geometry)?;
        if descriptor.count() > verification_memory::MAX_VERIFIER_COUNT { return Err(MulFailure::Geometry); }
        if batch.indices.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(MulFailure::Source); }
        for &index in &batch.indices {
            if !matches!(prepared.graph().operations().get(index),
                Some(Operation::Mul { modulus, .. }) if *modulus == descriptor.modulus())
            { return Err(MulFailure::Source); }
        }
        let expected = batch.expected_public.as_deref().ok_or(MulFailure::Source)?;
        if expected.len() != 12 * descriptor.count() { return Err(MulFailure::Geometry); }
        let source = Self { sources, batch, ordinal, kind: descriptor, expected };
        let air = source.air();
        if (air.height, air.width(), air.num_public_values(), air.num_periodic_columns()) != descriptor.geometry_tuple()
            || air.max_constraint_degree().is_some()
        { return Err(MulFailure::Geometry); }
        Ok(source)
    }
    /// Fixed source inspection/forwarding frames, including refused lookups.
    /// This query allocates nothing; the bootstrap charges its caller separately.
    pub(crate) const fn planning_view_host_bytes() -> usize {
        8 * (size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<MulDescriptor>() + size_of::<Result<MulDescriptor>>()
            + size_of::<MulAir>()
            + size_of::<core::result::Result<MulAir, crate::poly_air::Error>>()
            + size_of::<Option<&'static Operation>>()
            + size_of::<Option<&'static super::PlannedBatch>>()
            + size_of::<Option<&'static [Val]>>() + size_of::<&'static [usize]>()
            + size_of::<[usize; 32]>())
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn batch(self) -> &'a super::PlannedBatch { self.batch }
    pub(crate) fn batch_ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn kind(self) -> MulDescriptor { self.kind }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.batch, other.batch)
            && core::ptr::eq(self.expected, other.expected) && self.ordinal == other.ordinal && self.kind == other.kind
    }
    fn air(self) -> MulAir {
        MulAir::new(self.kind.modulus(), self.kind.count()).expect("validated MUL source")
    }
    fn serialize(self) -> Result<WipedRaw> {
        let words = MulGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| MulFailure::Resource)?;
        if raw.0.capacity() != words { return Err(MulFailure::Resource); }
        let algebra = self.sources.get().algebra();
        for &index in &self.batch.indices {
            let Operation::Mul { modulus, left, right, .. } = algebra.graph.operations()[index]
                else { return Err(MulFailure::Source); };
            if modulus != self.kind.modulus() { return Err(MulFailure::Source); }
            for id in [left, right] {
                let node = algebra.graph.polynomial(id);
                if node.kind != (crate::rust_verify::committed_backend::PolynomialKind::Canonical { modulus }) {
                    return Err(MulFailure::Source);
                }
                let crate::rust_verify::committed_backend::PolynomialValues::Canonical(values) = &node.values
                    else { return Err(MulFailure::Source); };
                if values.iter().any(|&word| word >= modulus) { return Err(MulFailure::Source); }
                raw.0.extend_from_slice(values);
            }
        }
        if raw.0.len() != words { return Err(MulFailure::Source); }
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
pub(crate) struct MulProofPlan<'a> {
    source: MulSource<'a>, preparation: MulPreparationPlan, output: MulOutputPlan, raw: WipedRaw,
}
impl<'a> MulProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize, original: &Reservation, ledger: &Ledger)
        -> Result<Self>
    {
        if !original.belongs_to(ledger) || !sources.belongs_to(ledger)
            || original.requirements().get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < Self::metadata_host_bytes() as u64
        { return Err(MulFailure::Resource); }
        let source = MulSource::from_original(sources, batch)?;
        let preparation = MulPreparationPlan::new(source.kind).map_err(|_| MulFailure::Resource)?;
        let output = MulOutputPlan::new(preparation).map_err(|_| MulFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(MulFailure::Geometry); }
        let raw = source.serialize()?;
        Ok(Self { source, preparation, output, raw })
    }
    // Two maximum raw buffers plus descriptors/caller frames. Admission is
    // required before serialize; the raw owner lives in the operation plan.
    pub(crate) const fn metadata_host_bytes() -> usize {
        // Exact-capacity serialization plus its transfer inventory; all fixed
        // constructor/forwarding frames precede source serialization as well.
        2 * 128 * 512 * size_of::<u64>() + 8 * (
            size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<MulSource<'static>>() + size_of::<Result<MulSource<'static>>>()
            + size_of::<MulAir>() + size_of::<SourceAir>()
            + size_of::<MulPreparationPlan>() + size_of::<Result<MulPreparationPlan>>()
            + size_of::<MulOutputPlan>() + size_of::<Result<MulOutputPlan>>()
            + size_of::<WipedRaw>() + size_of::<Result<WipedRaw>>()
            + size_of::<MulDescriptor>() + size_of::<Result<MulDescriptor>>()
            + size_of::<[usize; 32]>() + size_of::<Reservation>()) + MulSource::planning_view_host_bytes()
    }
    pub(crate) fn source(&self) -> MulSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> MulPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> MulOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<MulSource<'static>>(),
            size_of::<PreparedMulSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedMulSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedMulProof<'static>>(), size_of::<Result<UnverifiedMulProof<'static>>>(),
            size_of::<MulAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedMulProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<MulVerificationFailure>(),
            size_of::<MulInput<'static>>(), size_of::<MulOutputPlan>(),
            size_of::<MulPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(0usize, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(MulFailure::Resource))
    }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedMulSource<'plan, 'a, 'claim>>
    {
        let mut recorder = MulRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| MulFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| MulFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| MulFailure::VerificationBudget)?;
        Ok(PreparedMulSource { source: self.source, raw: &self.raw.0, recorded, verification })
    }
}

pub(crate) struct PreparedMulSource<'plan, 'a, 'claim> {
    source: MulSource<'a>, raw: &'plan [u64], recorded: PreparedMul<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedMulSource<'_, 'a, '_> {
    pub(crate) fn source(&self) -> MulSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> MulPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeMulPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedMulProof<'a>>
    {
        let input = MulInput { kind: self.source.kind, words: self.raw };
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| MulFailure::Production)?;
        Ok(UnverifiedMulProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedMulProof<'a> {
    source: MulSource<'a>, owned: OwnedMulProof, verification: VerificationPlan,
}
impl<'a> UnverifiedMulProof<'a> {
    pub(crate) fn source(&self) -> MulSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeMulProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedMulProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (MulVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values() != self.source.expected_public_values()
        { return Err((MulVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((MulVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (MulVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedMulProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum MulVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedMulProof<'a>, Reservation),
    (MulVerificationFailure, UnverifiedMulProof<'a>, Reservation)>;
pub(crate) struct VerifiedMulProof<'a> {
    original: UnverifiedMulProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedMulProof<'a> {
    pub(crate) fn source(&self) -> MulSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeMulProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedMulProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
