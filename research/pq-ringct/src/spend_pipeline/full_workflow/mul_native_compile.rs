//! Named compiler phase for exactly one independently verified native source.
//! Original output ownership is issued only by the execution child; this plan
//! never reserves replacement quota or extracts a raw native artifact.
use super::{PreparedWorkflowSources, mul_native::{MulNativeOperationPlan, OwnedMulOutput}};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind, PhaseFailure,
            RetainedFailure, RetainedNative, SlotId, SourceRetained},
        ProvingContext,
    },
    graph_tree::mul_sources::{MulLeafBlueprint, MulLeafCompiler,
        MulLeafFacts, MulLeafFailure},
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::proving::Policy;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MulNativeCompileFailure {
    Authority, Resource, Source, Overflow, Compile(MulLeafFailure),
}
type Result<T> = core::result::Result<T, MulNativeCompileFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(MulNativeCompileFailure::Overflow)
}
fn requirement(category: Category, count: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes { host: u64::try_from(count)
        .map_err(|_| MulNativeCompileFailure::Overflow)?, device: 0 }))
}
fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| MulNativeCompileFailure::Overflow)?;
    } }
    Ok(result)
}
fn contains(have: Requirements, need: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let a = have.get(category); let b = need.get(category);
        a.host >= b.host && a.device >= b.device
    })
}

/// The complete closure keeps this plan, its native plan, blueprint and source
/// owner borrowed through all consumers. Metadata has a separate original;
/// phase output is exactly the low-level compiler's original, without a second
/// charge for the payload inside RetainedOriginal.
pub(crate) struct MulNativeCompilePlan<'a> {
    native: &'a MulNativeOperationPlan<'a>,
    compiler: MulLeafCompiler<'a, 'a, 'a>,
    facts: PhaseFacts,
    metadata: Reservation,
}
impl<'a> MulNativeCompilePlan<'a> {
    /// Runs only during whole-workflow planning before proof zero. Both the
    /// exact metadata original and bounded template scratch already exist.
    /// Refusal returns the unconsumed metadata original to its issuer.
    pub(crate) fn new(native: &'a MulNativeOperationPlan<'a>,
        blueprint: &'a MulLeafBlueprint<'a, 'a>, original: Reservation,
        planning: &Reservation, ledger: &Ledger,
        resolved: crate::component_tree::native_shape::cohort::ResolvedBound)
        -> core::result::Result<Self, (MulNativeCompileFailure, Reservation)>
    {
        let mut original = Some(original);
        let constructed = (|| -> Result<Self> {
            let held = original.as_ref().expect("unconsumed compiler metadata original");
            let sources = native.sources();
            let prepared = sources.get();
            if !native.belongs_to(ledger) || !held.belongs_to(ledger)
                || !planning.belongs_to(ledger) || core::ptr::eq(held, planning)
                || held.requirements() != Self::metadata_requirements()?
                || !contains(planning.requirements(), Self::planning_requirements(blueprint)?)
                || native.context().policy() != Policy::GpuRequired
                || native.policy() != ProofCachePolicy::FreshOnly
                || native.workflow_source_fingerprint() != sources.source_fingerprint()
                || native.compiled_source_fingerprint() != sources.compiled_source_fingerprint()
                || native.kind() != blueprint.kind()
                || !core::ptr::eq(blueprint.graph_plan(), prepared.plan())
                || !core::ptr::eq(blueprint.relation_graph(), prepared.graph())
                || !core::ptr::eq(blueprint.context(), prepared.context())
                || !blueprint.source().same_source(native.source())
                || !crate::host_memory_profile::HostMemoryProfile::valid_worker_ceiling(ledger.snapshot().allowance.host)
                || ledger.snapshot().allowance.device > 8 << 30
            { return Err(MulNativeCompileFailure::Authority); }
            let compiler = blueprint.inspect_resolved(planning, ledger, resolved).map_err(MulNativeCompileFailure::Compile)?;
            let (output, compiler_scratch) = compiler.compiler_requirements();
            let scratch = combine(&[compiler_scratch, Self::frame_requirements()?,
                crate::execution::workflow_resources::mul_native_compile_issuer_scratch_requirements()
                    .map_err(|_| MulNativeCompileFailure::Resource)?])?;
            let failure = requirement(Category::Report, 8 * (
                size_of::<PhaseFailure<MulNativeCompileFailure>>()
                + size_of::<RetainedFailure<MulNativeCompileFailure>>()))?;
            let mut identity = Sha3_256::new();
            identity.update(b"lattica/full-workflow/source-native-compile/v1");
            identity.update(native.source_fingerprint());
            identity.update(native.workflow_source_fingerprint());
            identity.update(native.compiled_source_fingerprint());
            let f = compiler.facts();
            for value in [blueprint.ordinal(), f.operations.scalar, f.operations.cubic,
                f.operations.poseidon, f.maximum_active_rows, f.maximum_padded_rows,
                f.maximum_wires, f.input_values, f.selection_hint_words]
            {
                identity.update(u64::try_from(value).map_err(|_| MulNativeCompileFailure::Overflow)?.to_le_bytes());
            }
            for part in [output, failure, scratch] { for category in Category::ALL {
                let bytes = part.get(category);
                identity.update(bytes.host.to_le_bytes()); identity.update(bytes.device.to_le_bytes());
            } }
            Ok(Self { native, compiler, facts: PhaseFacts { kind: PhaseKind::AlgebraCompile,
                source_fingerprint: identity.finalize().into(),
                compiled_source_fingerprint: native.compiled_source_fingerprint(), output, failure, scratch },
                metadata: original.take().expect("same admitted compiler metadata original") })
        })();
        constructed.map_err(|error| (error, original.expect("refusal before metadata transfer")))
    }
    fn frame_bytes() -> Result<usize> {
        [size_of::<Self>(), size_of::<Result<Self>>(),
            size_of::<crate::component_tree::native_shape::cohort::ResolvedBound>(),
            size_of::<core::result::Result<Self, (MulNativeCompileFailure, Reservation)>>(),
            size_of::<MulNativeCompileOperation<'static, 'static>>(),
            size_of::<MulLeafBlueprint<'static, 'static>>(),
            size_of::<MulLeafCompiler<'static, 'static, 'static>>(),
            size_of::<MulLeafFacts>(), size_of::<PhaseFacts>(), size_of::<PhaseBinding>(),
            size_of::<Sha3_256>(), size_of::<[Requirements; 4]>(), size_of::<[usize; 9]>(),
            size_of::<Option<Reservation>>(), size_of::<(MulNativeCompileFailure, Reservation)>(),
        ].into_iter().try_fold(0, add)?.checked_mul(8).ok_or(MulNativeCompileFailure::Overflow)
    }
    fn frame_requirements() -> Result<Requirements> {
        requirement(Category::PhaseScratch, Self::frame_bytes()?)
    }
    pub(crate) fn metadata_requirements() -> Result<Requirements> {
        // This descriptor owns only inline fields and borrowed source views.
        // Construction and runtime both require the complete frame census in
        // their separate, original PhaseScratch reservation.
        requirement(Category::RegisteredMetadata, size_of::<Self>())
    }
    pub(crate) fn planning_requirements(blueprint: &MulLeafBlueprint<'_, '_>) -> Result<Requirements> {
        combine(&[blueprint.planning_requirements(), Self::frame_requirements()?])
    }
    pub(crate) fn source_compile_plan(&self) -> &MulLeafCompiler<'a, 'a, 'a> { &self.compiler }
    pub(crate) fn native_plan(&self) -> &'a MulNativeOperationPlan<'a> { self.native }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.native.context() }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.native.sources() }
    pub(crate) fn binding(&self) -> Result<PhaseBinding> {
        PhaseBinding::for_mul_native_compile(self, 0).map_err(|_| MulNativeCompileFailure::Authority)
    }
    pub(crate) fn phase_count(&self) -> usize { 1 }
    pub(crate) fn phase_facts(&self, ordinal: usize) -> Option<PhaseFacts> { (ordinal == 0).then_some(self.facts) }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.facts.source_fingerprint }
    pub(crate) fn workflow_source_fingerprint(&self) -> [u8; 32] { self.native.workflow_source_fingerprint() }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.facts.compiled_source_fingerprint }
    pub(crate) fn backend_allowance(&self) -> Bytes { Bytes::ZERO }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool {
        self.native.belongs_to(ledger) && self.metadata.belongs_to(ledger)
    }
    pub(crate) fn operation(&self, native: RetainedNative<OwnedMulOutput<'a>>)
        -> core::result::Result<MulNativeCompileOperation<'_, 'a>,
            (MulNativeCompileFailure, RetainedNative<OwnedMulOutput<'a>>)>
    {
        let binding = match self.binding() { Ok(binding) => binding, Err(error) => return Err((error, native)) };
        let operation = MulNativeCompileOperation { plan: self, native, binding };
        match operation.check_child() {
            Ok(()) => Ok(operation),
            Err(error) => Err((error, operation.native)),
        }
    }
}

pub(crate) struct MulNativeCompileOperation<'plan, 'a> {
    plan: &'plan MulNativeCompilePlan<'a>,
    native: RetainedNative<OwnedMulOutput<'a>>,
    binding: PhaseBinding,
}
impl<'a> MulNativeCompileOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn plan(&self) -> &MulNativeCompilePlan<'a> { self.plan }
    pub(crate) fn input_slot(&self) -> SlotId { self.native.slot_id() }
    pub(crate) fn native_output(&self) -> &OwnedMulOutput<'a> { self.native.get() }
    fn check_child(&self) -> Result<()> {
        let expected = PhaseBinding::for_mul_native(self.plan.native, 0)
            .map_err(|_| MulNativeCompileFailure::Authority)?;
        let child = self.native.get();
        if self.native.binding() != expected || child.binding() != expected
            || !core::ptr::eq(child.sources(), self.plan.sources())
            || !child.proof().source().same_source(self.plan.compiler.blueprint().source())
            || child.proof().owned().geometry().kind() != self.plan.native.kind()
        { return Err(MulNativeCompileFailure::Authority); }
        Ok(())
    }
    pub(crate) fn validate(&self, execution: &ExecutionAccess<'_>, ledger: &Ledger) -> Result<()> {
        if execution.binding() != self.binding || self.plan.binding()? != self.binding
            || !core::ptr::eq(execution.context(), self.plan.context())
            || execution.context().policy() != Policy::GpuRequired
            || !execution.owns_source(self.plan.sources()) || !self.native.belongs_to(execution)
            || !self.plan.belongs_to(ledger) || !self.native.get().proof().owned().belongs_to(ledger)
            || self.plan.native.policy() != ProofCachePolicy::FreshOnly
        { return Err(MulNativeCompileFailure::Authority); }
        self.check_child()
    }
}

#[cfg(test)]
mod metadata_storage_tests {
    use super::*;
    #[test]
    fn retained_descriptor_excludes_separately_admitted_forwarding_frames() {
        let retained = MulNativeCompilePlan::metadata_requirements().unwrap();
        let scratch = MulNativeCompilePlan::frame_requirements().unwrap();
        assert!(retained.get(Category::RegisteredMetadata).host > 0);
        assert!(scratch.get(Category::PhaseScratch).host > retained.get(Category::RegisteredMetadata).host);
    }
}
