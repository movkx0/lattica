//! Fresh, exact-source Permutation obligations. Serialized operands remain in the
//! original-owned plan until native runtime retirement. Only the concrete producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::Val;
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    permutation_air::PermutationAir,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            permutation_output::{PermutationOutputPlan, OwnedPermutationProof},
            permutation_preparation::{PermutationDescriptor, PermutationOperation, PermutationGeometry, PermutationPreparationPlan},
            permutation_recording::{PermutationRecorder, PreparedPermutation},
            owned_permutation::{PermutationInput, NativePermutationPhase},
        },
        native_permutation_proof::NativePermutationProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermutationFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, PermutationFailure>;

/// Sealed immutable membership in one exact algebra batch of prepared sources.
#[derive(Clone, Copy)]
pub(crate) struct PermutationSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    batch: &'a super::PlannedBatch,
    ordinal: usize,
    kind: PermutationDescriptor,
    expected: &'a [Val],
}
impl<'a> PermutationSource<'a> {
    /// Allocation-free original source view for bootstrap planning. It owns no
    /// witness buffer, recording, proof, reservation or execution authority.
    /// The enclosing planner precharges planning_view_host_bytes() before use.
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize) -> Result<Self> {
        let prepared = sources.get();
        let algebra = prepared.algebra();
        if !core::ptr::eq(algebra.graph, prepared.graph()) { return Err(PermutationFailure::Source); }
        let batch = algebra.batches.get(ordinal).ok_or(PermutationFailure::Source)?;
        let super::ComponentKind::Permutation { kind } = batch.kind() else { return Err(PermutationFailure::Source); };
        if batch.indices.len() != 1 { return Err(PermutationFailure::Source); }
        let descriptor = descriptor_for_kind(*kind);
        if batch.indices.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(PermutationFailure::Source); }
        for &index in &batch.indices {
            let (actual,_,_) = crate::permutation_air::graph::graph_operation(prepared.graph(),index)
                .map_err(|_| PermutationFailure::Source)?;
            if descriptor_for_kind(actual) != descriptor { return Err(PermutationFailure::Source); }
        }
        let expected = batch.expected_public.as_deref().ok_or(PermutationFailure::Source)?;
        if expected.len() != 8 { return Err(PermutationFailure::Geometry); }
        let source = Self { sources, batch, ordinal, kind: descriptor, expected };
        let air = source.air();
        if (crate::permutation_air::HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns()) != descriptor.geometry_tuple()
            || air.max_constraint_degree().is_some()
        { return Err(PermutationFailure::Geometry); }
        Ok(source)
    }
    pub(crate) const fn planning_view_host_bytes() -> usize {
        8 * (size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<PermutationDescriptor>() + size_of::<Result<PermutationDescriptor>>()
            + size_of::<PermutationAir>()
            + size_of::<[usize;32]>())
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn batch(self) -> &'a super::PlannedBatch { self.batch }
    pub(crate) fn batch_ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn kind(self) -> PermutationDescriptor { self.kind }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.batch, other.batch)
            && core::ptr::eq(self.expected, other.expected) && self.ordinal == other.ordinal && self.kind == other.kind
    }
    fn air(self) -> PermutationAir {
        air_for_descriptor(self.kind)
    }
    fn serialize(self) -> Result<WipedRaw> {
        let words = PermutationGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| PermutationFailure::Resource)?;
        if raw.0.capacity() != words { return Err(PermutationFailure::Resource); }
        let algebra = self.sources.get().algebra();
        let [index] = self.batch.indices.as_slice() else { return Err(PermutationFailure::Source); };
        let (kind, input, _) = crate::permutation_air::graph::graph_operation(algebra.graph, *index)
            .map_err(|_| PermutationFailure::Source)?;
        if descriptor_for_kind(kind) != self.kind { return Err(PermutationFailure::Source); }
        let node = algebra.graph.polynomial(input);
        serialize_input(&mut raw.0, &node.kind, &node.values, self.kind)?;
        if raw.0.len() != words { return Err(PermutationFailure::Source); }
        Ok(raw)
    }
}
pub(crate) fn descriptor_for_kind(kind: crate::permutation_air::PermutationKind) -> PermutationDescriptor {
    use crate::permutation_air::PermutationKind;
    PermutationDescriptor::new(match kind {
        PermutationKind::AutomorphismQ => PermutationOperation::AutomorphismQ,
        PermutationKind::InverseChallenge => PermutationOperation::InverseChallenge,
    })
}
pub(crate) fn air_for_descriptor(kind: PermutationDescriptor) -> PermutationAir {
    use crate::permutation_air::PermutationKind;
    PermutationAir::new(match kind.operation() {
        PermutationOperation::AutomorphismQ => PermutationKind::AutomorphismQ,
        PermutationOperation::InverseChallenge => PermutationKind::InverseChallenge,
    })
}
// The canonical or original two's-complement input words only. Never compute
// or accept a permutation result here, and never grow past admitted backing.
fn serialize_input(raw: &mut Vec<u64>,
    kind: &crate::rust_verify::committed_backend::PolynomialKind,
    values: &crate::rust_verify::committed_backend::PolynomialValues,
    descriptor: PermutationDescriptor) -> Result<()>
{
    use crate::rust_verify::committed_backend::{PolynomialKind, PolynomialValues};
    if raw.len().checked_add(256).is_none_or(|end| end > raw.capacity()) {
        return Err(PermutationFailure::Resource);
    }
    match (descriptor.operation(), kind, values) {
        (PermutationOperation::AutomorphismQ, PolynomialKind::Canonical { modulus }, PolynomialValues::Canonical(values))
            if *modulus == crate::rust_verify::Q && values.iter().all(|&v| v < *modulus) => raw.extend_from_slice(values),
        (PermutationOperation::InverseChallenge, PolynomialKind::Signed { bound: 1 }, PolynomialValues::Signed(values))
            if values.iter().all(|v| v.unsigned_abs() <= 1) => raw.extend(values.iter().map(|v| *v as u64)),
        _ => return Err(PermutationFailure::Source),
    }
    Ok(())
}
struct WipedRaw(Vec<u64>);
impl Drop for WipedRaw {
    fn drop(&mut self) {
        for word in &mut self.0 { unsafe { core::ptr::write_volatile(word, 0); } }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}
pub(crate) struct PermutationProofPlan<'a> {
    source: PermutationSource<'a>, preparation: PermutationPreparationPlan, output: PermutationOutputPlan, raw: WipedRaw,
}
impl<'a> PermutationProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize, original: &Reservation, ledger: &Ledger)
        -> Result<Self>
    {
        if !original.belongs_to(ledger) || !sources.belongs_to(ledger)
            || original.requirements().get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < Self::metadata_host_bytes() as u64
        { return Err(PermutationFailure::Resource); }
        let source = PermutationSource::from_original(sources, batch)?;
        let preparation = PermutationPreparationPlan::new(source.kind).map_err(|_| PermutationFailure::Resource)?;
        let output = PermutationOutputPlan::new(preparation).map_err(|_| PermutationFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (crate::permutation_air::HEIGHT, air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(PermutationFailure::Geometry); }
        let raw = source.serialize()?;
        Ok(Self { source, preparation, output, raw })
    }
    // Two maximum raw buffers plus descriptors/caller frames. Admission is
    // required before serialize; the raw owner lives in the operation plan.
    pub(crate) const fn metadata_host_bytes() -> usize {
        PermutationSource::planning_view_host_bytes() +
        // Exact-capacity serialization plus its transfer inventory; all fixed
        // constructor/forwarding frames precede source serialization as well.
        2 * 256 * size_of::<u64>() + 8 * (
            size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<PermutationSource<'static>>() + size_of::<Result<PermutationSource<'static>>>()
            + size_of::<PermutationAir>() + size_of::<SourceAir>()
            + size_of::<PermutationPreparationPlan>() + size_of::<Result<PermutationPreparationPlan>>()
            + size_of::<PermutationOutputPlan>() + size_of::<Result<PermutationOutputPlan>>()
            + size_of::<WipedRaw>() + size_of::<Result<WipedRaw>>()
            + size_of::<PermutationDescriptor>() + size_of::<Result<PermutationDescriptor>>()
            + size_of::<[usize; 32]>() + size_of::<Reservation>())
    }
    pub(crate) fn source(&self) -> PermutationSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> PermutationPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> PermutationOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<PermutationSource<'static>>(),
            size_of::<PreparedPermutationSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedPermutationSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedPermutationProof<'static>>(), size_of::<Result<UnverifiedPermutationProof<'static>>>(),
            size_of::<PermutationAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedPermutationProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<PermutationVerificationFailure>(),
            size_of::<PermutationInput<'static>>(), size_of::<PermutationOutputPlan>(),
            size_of::<PermutationPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| PermutationFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(PermutationFailure::Resource))
    }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedPermutationSource<'plan, 'a, 'claim>>
    {
        let mut recorder = PermutationRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| PermutationFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| PermutationFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| PermutationFailure::VerificationBudget)?;
        Ok(PreparedPermutationSource { source: self.source, raw: &self.raw.0, recorded, verification })
    }
}

pub(crate) struct PreparedPermutationSource<'plan, 'a, 'claim> {
    source: PermutationSource<'a>, raw: &'plan [u64], recorded: PreparedPermutation<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedPermutationSource<'_, 'a, '_> {
    pub(crate) fn source(&self) -> PermutationSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> PermutationPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativePermutationPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedPermutationProof<'a>>
    {
        let input = PermutationInput { kind: self.source.kind, words: self.raw };
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| PermutationFailure::Production)?;
        Ok(UnverifiedPermutationProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedPermutationProof<'a> {
    source: PermutationSource<'a>, owned: OwnedPermutationProof, verification: VerificationPlan,
}
impl<'a> UnverifiedPermutationProof<'a> {
    pub(crate) fn source(&self) -> PermutationSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativePermutationProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedPermutationProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (PermutationVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values() != self.source.expected_public_values()
        { return Err((PermutationVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((PermutationVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (PermutationVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedPermutationProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum PermutationVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedPermutationProof<'a>, Reservation),
    (PermutationVerificationFailure, UnverifiedPermutationProof<'a>, Reservation)>;
pub(crate) struct VerifiedPermutationProof<'a> {
    original: UnverifiedPermutationProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedPermutationProof<'a> {
    pub(crate) fn source(&self) -> PermutationSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativePermutationProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedPermutationProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}

#[cfg(all(test, not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod tests;
