//! Fresh, exact-source GBound integer-convolution obligations. Serialized operands remain in the
//! original-owned plan until native runtime retirement. Only the concrete producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::Val;
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    g_bound_air::GBoundAir,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            g_bound_output::{GBoundOutputPlan, OwnedGBoundProof},
            g_bound_preparation::{GBoundDescriptor, GBoundGeometry, GBoundPreparationPlan},
            g_bound_recording::{GBoundRecorder, PreparedGBound},
            owned_g_bound::{GBoundInput, NativeGBoundPhase},
        },
        native_g_bound_proof::NativeGBoundProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GBoundFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, GBoundFailure>;

/// Sealed immutable membership in one exact algebra batch of prepared sources.
#[derive(Clone, Copy)]
pub(crate) struct GBoundSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    batch: &'a super::PlannedBatch,
    ordinal: usize,
    kind: GBoundDescriptor,
    expected: &'a [Val],
}
impl<'a> GBoundSource<'a> {
    /// Allocation-free original source view for bootstrap planning. It owns no
    /// witness buffer, recording, proof, reservation or execution authority.
    /// The enclosing planner precharges planning_view_host_bytes() before use.
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize) -> Result<Self> {
        let prepared = sources.get();
        let algebra = prepared.algebra();
        if !core::ptr::eq(algebra.graph, prepared.graph()) { return Err(GBoundFailure::Source); }
        let batch = algebra.batches.get(ordinal).ok_or(GBoundFailure::Source)?;
        let super::ComponentKind::GBound { bound } = batch.kind() else { return Err(GBoundFailure::Source); };
        if batch.indices.len() != 1 { return Err(GBoundFailure::Source); }
        let descriptor = GBoundDescriptor::new(*bound).map_err(|_| GBoundFailure::Geometry)?;
        if batch.indices.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(GBoundFailure::Source); }
        for &index in &batch.indices {
            if !matches!(prepared.graph().operations().get(index),
                Some(Operation::GBound { bound, .. }) if *bound == descriptor.g_bound())
            { return Err(GBoundFailure::Source); }
        }
        let expected = batch.expected_public.as_deref().ok_or(GBoundFailure::Source)?;
        if expected.len() != 8 { return Err(GBoundFailure::Geometry); }
        let source = Self { sources, batch, ordinal, kind: descriptor, expected };
        let air = source.air();
        if (crate::g_bound_air::HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns()) != descriptor.geometry_tuple()
            || air.max_constraint_degree().is_some()
        { return Err(GBoundFailure::Geometry); }
        Ok(source)
    }
    /// Fixed source inspection/forwarding frames, including refused lookups.
    /// This query allocates nothing; the bootstrap charges its caller separately.
    pub(crate) const fn planning_view_host_bytes() -> usize {
        8 * (size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<GBoundDescriptor>() + size_of::<Result<GBoundDescriptor>>()
            + size_of::<GBoundAir>()
            + size_of::<core::result::Result<GBoundAir, crate::g_bound_air::Error>>()
            + size_of::<Option<&'static Operation>>()
            + size_of::<Option<&'static super::PlannedBatch>>()
            + size_of::<Option<&'static [Val]>>() + size_of::<&'static [usize]>()
            + size_of::<[usize; 32]>())
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn batch(self) -> &'a super::PlannedBatch { self.batch }
    pub(crate) fn batch_ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn kind(self) -> GBoundDescriptor { self.kind }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.batch, other.batch)
            && core::ptr::eq(self.expected, other.expected) && self.ordinal == other.ordinal && self.kind == other.kind
    }
    fn air(self) -> GBoundAir {
        GBoundAir::new(self.kind.g_bound()).expect("validated GBOUND source")
    }
    fn serialize(self) -> Result<WipedRaw> {
        let words = GBoundGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| GBoundFailure::Resource)?;
        if raw.0.capacity() != words { return Err(GBoundFailure::Resource); }
        let algebra = self.sources.get().algebra();
        for &index in &self.batch.indices {
            let Operation::GBound { f, x, bound } = algebra.graph.operations()[index]
                else { return Err(GBoundFailure::Source); };
            if bound != self.kind.g_bound() { return Err(GBoundFailure::Source); }
            for (id, input_bound) in [(f, self.kind.f_bound()), (x, 1)] {
                let node = algebra.graph.polynomial(id);
                serialize_signed_input(&mut raw.0, &node.kind, &node.values, input_bound)?;
            }
        }
        if raw.0.len() != words { return Err(GBoundFailure::Source); }
        Ok(raw)
    }
}
// Exactly the original signed input encoding, including the two's-complement
// raw words consumed by the pinned device kernel. No convolution is computed.
fn serialize_signed_input(raw: &mut Vec<u64>,
    kind: &crate::rust_verify::committed_backend::PolynomialKind,
    values: &crate::rust_verify::committed_backend::PolynomialValues, bound: u32) -> Result<()>
{
    use crate::rust_verify::committed_backend::{PolynomialKind, PolynomialValues};
    if *kind != (PolynomialKind::Signed { bound }) { return Err(GBoundFailure::Source); }
    let PolynomialValues::Signed(values) = values else { return Err(GBoundFailure::Source); };
    if values.iter().any(|word| word.unsigned_abs() > u64::from(bound)) {
        return Err(GBoundFailure::Source);
    }
    if raw.len().checked_add(values.len()).is_none_or(|end| end > raw.capacity()) {
        return Err(GBoundFailure::Resource);
    }
    raw.extend(values.iter().map(|word| *word as u64));
    Ok(())
}
struct WipedRaw(Vec<u64>);
impl Drop for WipedRaw {
    fn drop(&mut self) {
        for word in &mut self.0 { unsafe { core::ptr::write_volatile(word, 0); } }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub(crate) struct GBoundProofPlan<'a> {
    source: GBoundSource<'a>, preparation: GBoundPreparationPlan, output: GBoundOutputPlan, raw: WipedRaw,
}
impl<'a> GBoundProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize, original: &Reservation, ledger: &Ledger)
        -> Result<Self>
    {
        if !original.belongs_to(ledger) || !sources.belongs_to(ledger)
            || original.requirements().get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < Self::metadata_host_bytes() as u64
        { return Err(GBoundFailure::Resource); }
        let source = GBoundSource::from_original(sources, batch)?;
        let preparation = GBoundPreparationPlan::new(source.kind).map_err(|_| GBoundFailure::Resource)?;
        let output = GBoundOutputPlan::new(preparation).map_err(|_| GBoundFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (crate::g_bound_air::HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(GBoundFailure::Geometry); }
        let raw = source.serialize()?;
        Ok(Self { source, preparation, output, raw })
    }
    // Two maximum raw buffers plus descriptors/caller frames. Admission is
    // required before serialize; the raw owner lives in the operation plan.
    pub(crate) const fn metadata_host_bytes() -> usize {
        // Exact-capacity serialization plus its transfer inventory; all fixed
        // constructor/forwarding frames precede source serialization as well.
        2 * 512 * size_of::<u64>() + 8 * (
            size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<GBoundSource<'static>>() + size_of::<Result<GBoundSource<'static>>>()
            + size_of::<GBoundAir>() + size_of::<SourceAir>()
            + size_of::<GBoundPreparationPlan>() + size_of::<Result<GBoundPreparationPlan>>()
            + size_of::<GBoundOutputPlan>() + size_of::<Result<GBoundOutputPlan>>()
            + size_of::<WipedRaw>() + size_of::<Result<WipedRaw>>()
            + size_of::<GBoundDescriptor>() + size_of::<Result<GBoundDescriptor>>()
            + size_of::<[usize; 32]>() + size_of::<Reservation>()) + GBoundSource::planning_view_host_bytes()
    }
    pub(crate) fn source(&self) -> GBoundSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> GBoundPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> GBoundOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<GBoundSource<'static>>(),
            size_of::<PreparedGBoundSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedGBoundSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedGBoundProof<'static>>(), size_of::<Result<UnverifiedGBoundProof<'static>>>(),
            size_of::<GBoundAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedGBoundProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<GBoundVerificationFailure>(),
            size_of::<GBoundInput<'static>>(), size_of::<GBoundOutputPlan>(),
            size_of::<GBoundPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| GBoundFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(GBoundFailure::Resource))
    }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedGBoundSource<'plan, 'a, 'claim>>
    {
        let mut recorder = GBoundRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| GBoundFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| GBoundFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| GBoundFailure::VerificationBudget)?;
        Ok(PreparedGBoundSource { source: self.source, raw: &self.raw.0, recorded, verification })
    }
}

pub(crate) struct PreparedGBoundSource<'plan, 'a, 'claim> {
    source: GBoundSource<'a>, raw: &'plan [u64], recorded: PreparedGBound<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedGBoundSource<'_, 'a, '_> {
    pub(crate) fn source(&self) -> GBoundSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> GBoundPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeGBoundPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedGBoundProof<'a>>
    {
        let input = GBoundInput { kind: self.source.kind, words: self.raw };
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| GBoundFailure::Production)?;
        Ok(UnverifiedGBoundProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedGBoundProof<'a> {
    source: GBoundSource<'a>, owned: OwnedGBoundProof, verification: VerificationPlan,
}
impl<'a> UnverifiedGBoundProof<'a> {
    pub(crate) fn source(&self) -> GBoundSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeGBoundProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedGBoundProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (GBoundVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values() != self.source.expected_public_values()
        { return Err((GBoundVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((GBoundVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (GBoundVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedGBoundProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum GBoundVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedGBoundProof<'a>, Reservation),
    (GBoundVerificationFailure, UnverifiedGBoundProof<'a>, Reservation)>;
pub(crate) struct VerifiedGBoundProof<'a> {
    original: UnverifiedGBoundProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedGBoundProof<'a> {
    pub(crate) fn source(&self) -> GBoundSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeGBoundProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedGBoundProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}

#[cfg(all(test, not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod tests;
