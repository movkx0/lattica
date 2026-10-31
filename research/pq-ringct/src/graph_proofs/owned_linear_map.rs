//! Fresh, exact-source LinearMap obligations. Serialized operands remain in the
//! original-owned plan until native runtime retirement. Only the concrete producer can
//! fill proof/report originals; no legacy cache or artifact attachment enters.
use super::Val;
use crate::{
    execution::workflow_resources::SourceRetained,
    rust_verify::committed_backend::Operation,
    spend_pipeline::full_workflow::PreparedWorkflowSources,
    linear_map_air::LinearMapAir,
};
use core::mem::size_of;
use lattica_prover_p3::{
    block_v2::{
        gpu_hash::device::ringct_runtime::Runtime,
        native_gpu::{
            linear_map_output::{LinearMapOutputPlan, OwnedLinearMapProof},
            linear_map_preparation::{LinearMapDescriptor, LinearMapGeometry, LinearMapPreparationPlan},
            linear_map_recording::{LinearMapRecorder, PreparedLinearMap},
            owned_linear_map::{LinearMapInput, NativeLinearMapPhase},
        },
        native_linear_map_proof::NativeLinearMapProof,
    },
    ringct_research_quota::{Ledger, Reservation},
};
use p3_air::{Air, BaseAir};
use p3_field::PrimeCharacteristicRing;
pub(crate) mod verification_memory;
use verification_memory::{Plan as VerificationPlan, SourceAir, VerificationReceipt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinearMapFailure { Source, Geometry, Preparation, Production, Resource, VerificationBudget }
type Result<T> = core::result::Result<T, LinearMapFailure>;

/// Sealed immutable membership in one exact algebra batch of prepared sources.
#[derive(Clone, Copy)]
pub(crate) struct LinearMapSource<'a> {
    sources: &'a SourceRetained<PreparedWorkflowSources<'a>>,
    batch: &'a super::PlannedBatch,
    ordinal: usize,
    kind: LinearMapDescriptor,
    expected: &'a [Val],
}
impl<'a> LinearMapSource<'a> {
    /// Allocation-free original source view for bootstrap planning. It owns no
    /// witness buffer, recording, proof, reservation or execution authority.
    /// The enclosing planner precharges planning_view_host_bytes() before use.
    pub(crate) fn from_original(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, ordinal: usize) -> Result<Self> {
        let prepared = sources.get();
        let algebra = prepared.algebra();
        if !core::ptr::eq(algebra.graph, prepared.graph()) { return Err(LinearMapFailure::Source); }
        let batch = algebra.batches.get(ordinal).ok_or(LinearMapFailure::Source)?;
        let super::ComponentKind::LinearMap { descriptor } = batch.kind() else { return Err(LinearMapFailure::Source); };
        if batch.indices.len() != 1 { return Err(LinearMapFailure::Source); }
        let layout = descriptor.planning_layout().map_err(|_| LinearMapFailure::Geometry)?;
        let descriptor = descriptor.owned_descriptor().map_err(|_| LinearMapFailure::Geometry)?;
        if batch.indices.windows(2).any(|pair| pair[0] >= pair[1]) { return Err(LinearMapFailure::Source); }
        let [index] = batch.indices.as_slice() else { return Err(LinearMapFailure::Source); };
        // This original batch was already recognized from the same immutable graph.
        // Reuse its validated descriptor rather than allocate another expression DAG.
        match prepared.graph().operations().get(*index) {
            Some(Operation::CanonicalMap { inputs, .. }) | Some(Operation::SignedMap { inputs, .. })
                if inputs.len() == descriptor.inputs() => {},
            _ => return Err(LinearMapFailure::Source),
        }
        let expected = batch.expected_public.as_deref().ok_or(LinearMapFailure::Source)?;
        if expected.len() != descriptor.public_values() { return Err(LinearMapFailure::Geometry); }
        let source = Self { sources, batch, ordinal, kind: descriptor, expected };
        if (layout.height,layout.width,layout.public_values,layout.periodic_columns) != descriptor.geometry_tuple() {
            return Err(LinearMapFailure::Geometry);
        }
        Ok(source)
    }
    pub(crate) const fn planning_view_host_bytes() -> usize {
        8 * (size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<LinearMapDescriptor>() + size_of::<Result<LinearMapDescriptor>>()
            + size_of::<core::result::Result<LinearMapDescriptor,crate::linear_map_air::Error>>()
            + size_of::<core::result::Result<LinearMapDescriptor,lattica_prover_p3::block_v2::native_gpu::linear_map_preparation::Error>>()
            + size_of::<[[u64;2];17]>() + size_of::<sha3::Sha3_256>()
            + size_of::<crate::linear_map_air::LinearMapPlanningLayout>()
            + size_of::<core::result::Result<crate::linear_map_air::LinearMapPlanningLayout,crate::linear_map_air::Error>>()
            + size_of::<[usize;32]>())
    }
    pub(crate) fn sources(self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.sources }
    pub(crate) fn batch(self) -> &'a super::PlannedBatch { self.batch }
    pub(crate) fn batch_ordinal(self) -> usize { self.ordinal }
    pub(crate) fn operation_indices(self) -> &'a [usize] { &self.batch.indices }
    pub(crate) fn kind(self) -> LinearMapDescriptor { self.kind }
    pub(crate) fn expected_public_values(self) -> &'a [Val] { self.expected }
    pub(crate) fn same_source(self, other: Self) -> bool {
        core::ptr::eq(self.sources, other.sources) && core::ptr::eq(self.batch, other.batch)
            && core::ptr::eq(self.expected, other.expected) && self.ordinal == other.ordinal && self.kind == other.kind
    }
    fn air(self) -> LinearMapAir {
        air_for_descriptor(self.kind)
    }
    fn serialize(self) -> Result<WipedRaw> {
        let words = LinearMapGeometry::for_kind(self.kind).raw_words();
        let mut raw = WipedRaw(Vec::new());
        raw.0.try_reserve_exact(words).map_err(|_| LinearMapFailure::Resource)?;
        if raw.0.capacity() != words { return Err(LinearMapFailure::Resource); }
        let algebra = self.sources.get().algebra();
        let [index] = self.batch.indices.as_slice() else { return Err(LinearMapFailure::Source); };
        let inputs = match algebra.graph.operations().get(*index) {
            Some(Operation::CanonicalMap {inputs,..}) | Some(Operation::SignedMap {inputs,..}) => inputs,
            _ => return Err(LinearMapFailure::Source),
        };
        if inputs.len()!=self.kind.inputs() { return Err(LinearMapFailure::Source); }
        for (id, kind) in inputs.iter().zip(self.kind.kinds()) {
            let node = algebra.graph.polynomial(*id);
            serialize_input(&mut raw.0, &node.kind, &node.values, *kind)?;
        }
        if raw.0.len() != words { return Err(LinearMapFailure::Source); }
        Ok(raw)
    }
}
pub(crate) fn air_for_descriptor(kind: LinearMapDescriptor) -> LinearMapAir {
    LinearMapAir::new(crate::linear_map_air::LinearMapDescriptor::from_owned(&kind))
}
// Serialize original canonical/two's-complement input words only. Never compute
// or accept a linear-map result, and never grow past admitted backing.
fn serialize_input(raw: &mut Vec<u64>,
    kind: &crate::rust_verify::committed_backend::PolynomialKind,
    values: &crate::rust_verify::committed_backend::PolynomialValues,
    expected: [u64;2]) -> Result<()>
{
    use crate::rust_verify::committed_backend::{PolynomialKind,PolynomialValues};
    if raw.len().checked_add(256).is_none_or(|end| end>raw.capacity()) { return Err(LinearMapFailure::Resource); }
    match (kind,values) {
        (PolynomialKind::Canonical {modulus},PolynomialValues::Canonical(values))
            if expected==[*modulus,0] && values.iter().all(|v| *v<*modulus) => raw.extend_from_slice(values),
        (PolynomialKind::Signed {bound},PolynomialValues::Signed(values))
            if expected==[0,u64::from(*bound)] && values.iter().all(|v| v.unsigned_abs()<=u64::from(*bound)) =>
                raw.extend(values.iter().map(|v| *v as u64)),
        _ => return Err(LinearMapFailure::Source),
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
pub(crate) struct LinearMapProofPlan<'a> {
    source: LinearMapSource<'a>, preparation: LinearMapPreparationPlan, output: LinearMapOutputPlan, raw: WipedRaw,
}
impl<'a> LinearMapProofPlan<'a> {
    pub(crate) fn new(sources: &'a SourceRetained<PreparedWorkflowSources<'a>>, batch: usize, original: &Reservation, ledger: &Ledger)
        -> Result<Self>
    {
        if !original.belongs_to(ledger) || !sources.belongs_to(ledger)
            || original.requirements().get(crate::execution::retained_resources::Category::RegisteredMetadata).host
                < Self::metadata_host_bytes() as u64
        { return Err(LinearMapFailure::Resource); }
        let source = LinearMapSource::from_original(sources, batch)?;
        let preparation = LinearMapPreparationPlan::new(source.kind).map_err(|_| LinearMapFailure::Resource)?;
        let output = LinearMapOutputPlan::new(preparation).map_err(|_| LinearMapFailure::Resource)?;
        let geometry = preparation.geometry(); let air = source.air();
        if (geometry.rows(), geometry.width(), geometry.public_values(), geometry.periodic_columns())
            != (air.height(), air.width(), air.num_public_values(), air.num_periodic_columns())
            || air.max_constraint_degree().is_some()
        { return Err(LinearMapFailure::Geometry); }
        let raw = source.serialize()?;
        Ok(Self { source, preparation, output, raw })
    }
    // Two maximum raw buffers plus descriptors/caller frames. Admission is
    // required before serialize; the raw owner lives in the operation plan.
    pub(crate) const fn metadata_host_bytes() -> usize {
        LinearMapSource::planning_view_host_bytes() +
        // Exact-capacity serialization plus its transfer inventory; all fixed
        // constructor/forwarding frames precede source serialization as well.
        2 * 16 * 256 * size_of::<u64>() + 8 * crate::linear_map_air::LinearMapDescriptor::maximum_owned_clone_backing_bytes() + 8 * (
            size_of::<Self>() + size_of::<Result<Self>>()
            + size_of::<LinearMapSource<'static>>() + size_of::<Result<LinearMapSource<'static>>>()
            + size_of::<LinearMapAir>() + size_of::<SourceAir>()
            + size_of::<LinearMapPreparationPlan>() + size_of::<Result<LinearMapPreparationPlan>>()
            + size_of::<LinearMapOutputPlan>() + size_of::<Result<LinearMapOutputPlan>>()
            + size_of::<WipedRaw>() + size_of::<Result<WipedRaw>>()
            + size_of::<LinearMapDescriptor>() + size_of::<Result<LinearMapDescriptor>>()
            + size_of::<[[u64;2];17]>() + size_of::<sha3::Sha3_256>()
            + size_of::<[usize; 32]>() + size_of::<Reservation>())
    }
    pub(crate) fn source(&self) -> LinearMapSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> LinearMapPreparationPlan { self.preparation }
    pub(crate) fn output_plan(&self) -> LinearMapOutputPlan { self.output }
    pub(crate) fn caller_host_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(), size_of::<LinearMapSource<'static>>(),
            size_of::<PreparedLinearMapSource<'static, 'static, 'static>>(),
            size_of::<Result<PreparedLinearMapSource<'static, 'static, 'static>>>(),
            size_of::<UnverifiedLinearMapProof<'static>>(), size_of::<Result<UnverifiedLinearMapProof<'static>>>(),
            size_of::<LinearMapAir>(), size_of::<SourceAir>(), size_of::<VerificationPlan>(),
            size_of::<VerificationReceipt>(), size_of::<VerifiedLinearMapProof<'static>>(),
            size_of::<VerificationOutcome<'static>>(), size_of::<LinearMapVerificationFailure>(),
            size_of::<LinearMapInput<'static>>(), size_of::<LinearMapOutputPlan>(),
            size_of::<LinearMapPreparationPlan>(), size_of::<[usize; 8]>()]
            .into_iter().try_fold(VerificationPlan::retaining_original_caller_host_bytes()
                .map_err(|_| LinearMapFailure::Resource)? + 8 * crate::linear_map_air::LinearMapDescriptor::maximum_owned_clone_backing_bytes(), |sum, part|
                part.checked_mul(8).and_then(|part| sum.checked_add(part)).ok_or(LinearMapFailure::Resource))
    }
    pub(crate) fn record<'plan, 'claim>(&'plan self, original: &'claim mut Reservation, ledger: &'claim Ledger)
        -> Result<PreparedLinearMapSource<'plan, 'a, 'claim>>
    {
        let mut recorder = LinearMapRecorder::begin(self.preparation, original, ledger)
            .map_err(|_| LinearMapFailure::Preparation)?;
        self.source.air().eval(recorder.builder_mut());
        let recorded = recorder.finish().map_err(|_| LinearMapFailure::Preparation)?;
        let air = SourceAir::new(self.source.kind);
        let verification = VerificationPlan::for_recorded(&air, recorded.symbolic_replay_census())
            .map_err(|_| LinearMapFailure::VerificationBudget)?;
        Ok(PreparedLinearMapSource { source: self.source, raw: &self.raw.0, recorded, verification })
    }
}

pub(crate) struct PreparedLinearMapSource<'plan, 'a, 'claim> {
    source: LinearMapSource<'a>, raw: &'plan [u64], recorded: PreparedLinearMap<'claim>, verification: VerificationPlan,
}
impl<'a> PreparedLinearMapSource<'_, 'a, '_> {
    pub(crate) fn source(&self) -> LinearMapSource<'a> { self.source }
    pub(crate) fn preparation(&self) -> LinearMapPreparationPlan { self.recorded.census() }
    pub(crate) fn verification_plan(&self) -> VerificationPlan { self.verification }
    /// # Safety
    /// The execution issuer retains the exact source/preparation/startup/phase
    /// owners and immutable process selection through this runtime's retirement.
    pub(crate) unsafe fn produce(self, phase: &mut NativeLinearMapPhase, runtime: &Runtime,
        startup: &Reservation, verifier: &Reservation) -> Result<UnverifiedLinearMapProof<'a>>
    {
        let input = LinearMapInput { kind: self.source.kind, words: self.raw };
        let owned = unsafe { phase.produce(self.recorded, input, runtime, startup, verifier) }
            .map_err(|_| LinearMapFailure::Production)?;
        Ok(UnverifiedLinearMapProof { source: self.source, owned, verification: self.verification })
    }
}
pub(crate) struct UnverifiedLinearMapProof<'a> {
    source: LinearMapSource<'a>, owned: OwnedLinearMapProof, verification: VerificationPlan,
}
impl<'a> UnverifiedLinearMapProof<'a> {
    pub(crate) fn source(&self) -> LinearMapSource<'a> { self.source }
    pub(crate) fn artifact(&self) -> &NativeLinearMapProof { self.owned.artifact() }
    pub(crate) fn owned(&self) -> &OwnedLinearMapProof { &self.owned }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.owned.into_originals() }
    fn verify_borrowed_preserving(&self, original: Reservation, ledger: &Ledger)
        -> core::result::Result<(VerificationReceipt, Reservation), (LinearMapVerificationFailure, Reservation)>
    {
        let artifact = self.owned.artifact();
        if !self.owned.belongs_to(ledger) || artifact.kind != self.source.kind
            || artifact.public_values() != self.source.expected_public_values()
            || artifact.public_values[artifact.kind.public_values()..].iter().any(|v| *v != Val::ZERO)
        { return Err((LinearMapVerificationFailure::Source, original)); }
        let air = SourceAir::new(self.source.kind);
        let admission = match self.verification.admit_pre_reserved_preserving(
            &air, artifact.proof(), artifact.public_values(), self.owned.proof_reservation(), original, ledger)
        {
            Ok(admission) => admission,
            Err((error, original)) => return Err((LinearMapVerificationFailure::Admission(error), original)),
        };
        admission.verify_retaining_original()
            .map_err(|(error, original)| (LinearMapVerificationFailure::Proof(error), original))
    }
    /// Only the execution lifecycle invokes this after the actual runtime has
    /// retired. The returned receipt verifies a proof; it is never retirement.
    pub(crate) fn verify_retaining(self, original: Reservation, ledger: &Ledger) -> VerificationOutcome<'a> {
        match self.verify_borrowed_preserving(original, ledger) {
            Ok((receipt, original)) => Ok((VerifiedLinearMapProof { original: self, receipt }, original)),
            Err((error, original)) => Err((error, self, original)),
        }
    }
}
#[derive(Debug)]
pub(crate) enum LinearMapVerificationFailure {
    Source, Admission(&'static str), Proof(verification_memory::VerificationFailure),
}
type VerificationOutcome<'a> = core::result::Result<(VerifiedLinearMapProof<'a>, Reservation),
    (LinearMapVerificationFailure, UnverifiedLinearMapProof<'a>, Reservation)>;
pub(crate) struct VerifiedLinearMapProof<'a> {
    original: UnverifiedLinearMapProof<'a>, receipt: VerificationReceipt,
}
impl<'a> VerifiedLinearMapProof<'a> {
    pub(crate) fn source(&self) -> LinearMapSource<'a> { self.original.source() }
    pub(crate) fn artifact(&self) -> &NativeLinearMapProof { self.original.artifact() }
    pub(crate) fn owned(&self) -> &OwnedLinearMapProof { self.original.owned() }
    pub(crate) fn receipt(&self) -> &VerificationReceipt { &self.receipt }
    pub(crate) fn into_originals(self) -> (Reservation, Reservation) { self.original.into_originals() }
}

#[cfg(all(test, not(debug_assertions), target_os = "linux", target_arch = "x86_64"))]
mod tests;
