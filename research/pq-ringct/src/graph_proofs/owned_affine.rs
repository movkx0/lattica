//! Fresh, exact-source affine arithmetic. Serialized operands remain in the
//! original-owned plan until native runtime retirement. Only the concrete producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::Val;
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    affine_air::AffineAir,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            affine_output::{AffineOutputPlan, OwnedAffineProof},
            affine_preparation::{AffineDescriptor, AffineGeometry, AffineOperation, AffinePreparationPlan},
            affine_recording::{AffineRecorder, PreparedAffine},
            owned_affine::{AffineInput, NativeAffinePhase},
        },
        native_affine_proof::NativeAffineProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AffineFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, AffineFailure>;

/// Sealed immutable membership in one exact algebra batch of prepared sources.
#[derive(Clone, Copy)]
pub(crate) struct AffineSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    batch: &'a super::PlannedBatch,
    ordinal: usize,
    kind: AffineDescriptor,
    expected: &'a [Val; 4],
}
impl<'a> AffineSource<'a> {
    /// Allocation-free original source view for bootstrap planning. It owns no
    /// witness buffer, recording, proof, reservation or execution authority.
    /// The enclosing planner precharges planning_view_host_bytes() before use.
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize) -> Result<Self> {
        let prepared = sources.get();
        let algebra = prepared.algebra();
        if !core::ptr::eq(algebra.graph, prepared.graph()) { return Err(AffineFailure::Source); }
        let batch = algebra.batches.get(ordinal).ok_or(AffineFailure::Source)?;
        let super::ComponentKind::Affine { kind, modulus } = batch.kind() else { return Err(AffineFailure::Source); };
        let operation = match *kind {
            crate::affine_air::AffineKind::Add => AffineOperation::Add,
            crate::affine_air::AffineKind::Sub => AffineOperation::Subtract,
            crate::affine_air::AffineKind::SignedToCanonical { bound } => AffineOperation::SignedToCanonical { bound },
        };
        let descriptor = AffineDescriptor::new(operation, *modulus, batch.indices.len()).map_err(|_| AffineFailure::Geometry)?;
        if batch.indices.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(AffineFailure::Source); }
        for &index in &batch.indices {
            let matches = match prepared.graph().operations().get(index) {
                Some(Operation::Add { modulus, .. }) => descriptor.operation() == AffineOperation::Add
                    && *modulus == descriptor.modulus(),
                Some(Operation::Sub { modulus, .. }) => descriptor.operation() == AffineOperation::Subtract
                    && *modulus == descriptor.modulus(),
                Some(Operation::SignedToCanonical { modulus, bound, .. }) =>
                    descriptor.operation() == (AffineOperation::SignedToCanonical { bound: *bound })
                        && *modulus == descriptor.modulus(),
                _ => false,
            };
            if !matches { return Err(AffineFailure::Source); }
        }
        let expected = batch.expected_public.as_deref().ok_or(AffineFailure::Source)?
            .try_into().map_err(|_| AffineFailure::Geometry)?;
        let source = Self { sources, batch, ordinal, kind: descriptor, expected };
        let air = source.air();
        if (air.height(), air.width(), air.num_public_values(), air.num_periodic_columns()) != descriptor.geometry_tuple()
            || air.max_constraint_degree().is_some()
        { return Err(AffineFailure::Geometry); }
        Ok(source)
    }
    /// Fixed source inspection/forwarding frames, including refused lookups.
    /// This query allocates nothing; the bootstrap charges its caller separately.
    pub(crate) const fn planning_view_host_bytes() -> usize {
        8 * (size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<AffineDescriptor>() + size_of::<Result<AffineDescriptor>>()
            + size_of::<AffineAir>()
            + size_of::<core::result::Result<AffineAir, crate::affine_air::Error>>()
            + size_of::<Option<&'static Operation>>()
            + size_of::<Option<&'static super::PlannedBatch>>()
            + size_of::<Option<&'static [Val]>>() + size_of::<&'static [usize]>()
            + size_of::<[usize; 32]>())
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn batch(self) -> &'a super::PlannedBatch { self.batch }
    pub(crate) fn batch_ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn kind(self) -> AffineDescriptor { self.kind }
    pub(crate) fn expected_public_values(self) -> &'a [Val; 4] { self.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.batch, other.batch)
            && core::ptr::eq(self.expected, other.expected) && self.ordinal == other.ordinal && self.kind == other.kind
    }
    fn air(self) -> AffineAir {
        let operation = match self.kind.operation() {
            AffineOperation::Add => crate::affine_air::AffineKind::Add,
            AffineOperation::Subtract => crate::affine_air::AffineKind::Sub,
            AffineOperation::SignedToCanonical { bound } => crate::affine_air::AffineKind::SignedToCanonical { bound },
        };
        AffineAir::new(operation, self.kind.modulus(), self.kind.count()).expect("validated affine source")
    }
    fn serialize(self) -> Result<WipedRaw> {
        let words = AffineGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| AffineFailure::Resource)?;
        if raw.0.capacity() != words { return Err(AffineFailure::Resource); }
        let algebra = self.sources.get().algebra();
        for &index in &self.batch.indices {
            match algebra.graph.operations()[index] {
                Operation::Add { left, right, .. } | Operation::Sub { left, right, .. } => {
                    for id in [left, right] {
                        let node = algebra.graph.polynomial(id);
                        if node.kind != (crate::rust_verify::committed_backend::PolynomialKind::Canonical { modulus: self.kind.modulus() }) {
                            return Err(AffineFailure::Source);
                        }
                        let crate::rust_verify::committed_backend::PolynomialValues::Canonical(values) = &node.values else {
                            return Err(AffineFailure::Source);
                        };
                        if values.iter().any(|&word| word >= self.kind.modulus()) { return Err(AffineFailure::Source); }
                        raw.0.extend_from_slice(values);
                    }
                }
                Operation::SignedToCanonical { input, bound, .. } => {
                    let node = algebra.graph.polynomial(input);
                    if node.kind != (crate::rust_verify::committed_backend::PolynomialKind::Signed { bound }) {
                        return Err(AffineFailure::Source);
                    }
                    let crate::rust_verify::committed_backend::PolynomialValues::Signed(values) = &node.values else {
                        return Err(AffineFailure::Source);
                    };
                    if values.iter().any(|word| word.unsigned_abs() > u64::from(bound)) { return Err(AffineFailure::Source); }
                    raw.0.extend(values.iter().map(|&word| word as u64));
                }
                _ => return Err(AffineFailure::Source),
            }
        }
        if raw.0.len() != words { return Err(AffineFailure::Source); }
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
pub(crate) struct AffineProofPlan<'a> {
    source: AffineSource<'a>, preparation: AffinePreparationPlan, output: AffineOutputPlan, raw: WipedRaw,
}
impl<'a> AffineProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize, original: &Reservation, ledger: &Ledger)
        -> Result<Self>
    {
        if !original.belongs_to(ledger) || !sources.belongs_to(ledger)
            || original.requirements().get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < Self::metadata_host_bytes() as u64
        { return Err(AffineFailure::Resource); }
        let source = AffineSource::from_original(sources, batch)?;
        let preparation = AffinePreparationPlan::new(source.kind).map_err(|_| AffineFailure::Resource)?;
        let output = AffineOutputPlan::new(preparation).map_err(|_| AffineFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height(), air.width(), air.num_public_values(), air.num_periodic_columns())
        { return Err(AffineFailure::Geometry); }
        let raw = source.serialize()?;
        Ok(Self { source, preparation, output, raw })
    }
    // Two maximum raw buffers plus descriptors/caller frames. Admission is
    // required before serialize; the raw owner lives in the operation plan.
    pub(crate) const fn metadata_host_bytes() -> usize {
        2 * 64 * 2 * 256 * 8 + 8192 + AffineSource::planning_view_host_bytes()
    }
    pub(crate) fn source(&self) -> AffineSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> AffinePreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> AffineOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<AffineSource<'static>>(),
            size_of::<PreparedAffineSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedAffineSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedAffineProof<'static>>(), size_of::<Result<UnverifiedAffineProof<'static>>>(),
            size_of::<AffineAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedAffineProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<AffineVerificationFailure>(),
            size_of::<AffineInput<'static>>(), size_of::<AffineOutputPlan>(),
            size_of::<AffinePreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| AffineFailure::Resource)?, |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(AffineFailure::Resource))
    }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedAffineSource<'plan, 'a, 'claim>>
    {
        let mut recorder = AffineRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| AffineFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| AffineFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| AffineFailure::VerificationBudget)?;
        Ok(PreparedAffineSource { source: self.source, raw: &self.raw.0, recorded, verification })
    }
}

pub(crate) struct PreparedAffineSource<'plan, 'a, 'claim> {
    source: AffineSource<'a>, raw: &'plan [u64], recorded: PreparedAffine<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedAffineSource<'_, 'a, '_> {
    pub(crate) fn source(&self) -> AffineSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> AffinePreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeAffinePhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedAffineProof<'a>>
    {
        let input = AffineInput { kind: self.source.kind, words: self.raw };
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| AffineFailure::Production)?;
        Ok(UnverifiedAffineProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedAffineProof<'a> {
    source: AffineSource<'a>, owned: OwnedAffineProof, verification: VerificationPlan,
}
impl<'a> UnverifiedAffineProof<'a> {
    pub(crate) fn source(&self) -> AffineSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeAffineProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedAffineProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (AffineVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values != *self.source.expected_public_values()
        { return Err((AffineVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((AffineVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (AffineVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedAffineProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum AffineVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedAffineProof<'a>, Reservation),
    (AffineVerificationFailure, UnverifiedAffineProof<'a>, Reservation)>;
pub(crate) struct VerifiedAffineProof<'a> {
    original: UnverifiedAffineProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedAffineProof<'a> {
    pub(crate) fn source(&self) -> AffineSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeAffineProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedAffineProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}
