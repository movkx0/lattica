//! Named compiler phase for exactly one independently verified native source.
//! Original output ownership is issued only by the execution child; this plan
//! never reserves replacement quota or extracts a raw native artifact.
use super::{PreparedWorkflowSources, permutation_native::{PermutationNativeOperationPlan, OwnedPermutationOutput}};
use crate::{
    execution::{
        retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{ExecutionAccess, PhaseBinding, PhaseFacts, PhaseKind, PhaseFailure,
            RetainedFailure, RetainedNative, SlotId, SourceRetained},
        ProvingContext,
    },
    graph_tree::permutation_sources::{PermutationLeafBlueprint, PermutationLeafCompiler,
        PermutationLeafFacts, PermutationLeafFailure},
    proof_cache_policy::ProofCachePolicy,
};
use core::mem::size_of;
use lattica_prover_p3::proving::Policy;
use sha3::{Digest, Sha3_256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermutationNativeCompileFailure {
    Authority, Resource, Source, Overflow, Compile(PermutationLeafFailure),
}
type Result<T> = core::result::Result<T, PermutationNativeCompileFailure>;
fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(PermutationNativeCompileFailure::Overflow)
}
fn requirement(category: Category, count: usize) -> Result<Requirements> {
    Ok(Requirements::single(category, Bytes { host: u64::try_from(count)
        .map_err(|_| PermutationNativeCompileFailure::Overflow)?, device: 0 }))
}
fn combine(parts: &[Requirements]) -> Result<Requirements> {
    let mut result = Requirements::default();
    for part in parts { for category in Category::ALL {
        result.add(category, part.get(category)).map_err(|_| PermutationNativeCompileFailure::Overflow)?;
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
pub(crate) struct PermutationNativeCompilePlan<'a> {
    native: &'a PermutationNativeOperationPlan<'a>,
    compiler: PermutationLeafCompiler<'a, 'a, 'a>,
    facts: PhaseFacts,
    metadata: Reservation,
}
impl<'a> PermutationNativeCompilePlan<'a> {
    /// Runs only during whole-workflow planning before proof zero. Both the
    /// exact metadata original and bounded template scratch already exist.
    /// Refusal returns the unconsumed metadata original to its issuer.
    pub(crate) fn new(native: &'a PermutationNativeOperationPlan<'a>,
        blueprint: &'a PermutationLeafBlueprint<'a, 'a>, original: Reservation,
        planning: &Reservation, ledger: &Ledger)
        -> core::result::Result<Self, (PermutationNativeCompileFailure, Reservation)>
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
            { return Err(PermutationNativeCompileFailure::Authority); }
            let compiler = blueprint.inspect(planning, ledger).map_err(PermutationNativeCompileFailure::Compile)?;
            let (output, compiler_scratch) = blueprint.compiler_requirements();
            let scratch = combine(&[compiler_scratch, Self::frame_requirements()?,
                crate::execution::workflow_resources::permutation_native_compile_issuer_scratch_requirements()
                    .map_err(|_| PermutationNativeCompileFailure::Resource)?])?;
            let failure = requirement(Category::Report, 8 * (
                size_of::<PhaseFailure<PermutationNativeCompileFailure>>()
                + size_of::<RetainedFailure<PermutationNativeCompileFailure>>()))?;
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
                identity.update(u64::try_from(value).map_err(|_| PermutationNativeCompileFailure::Overflow)?.to_le_bytes());
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
            size_of::<core::result::Result<Self, (PermutationNativeCompileFailure, Reservation)>>(),
            size_of::<PermutationNativeCompileOperation<'static, 'static>>(),
            size_of::<PermutationLeafBlueprint<'static, 'static>>(),
            size_of::<PermutationLeafCompiler<'static, 'static, 'static>>(),
            size_of::<PermutationLeafFacts>(), size_of::<PhaseFacts>(), size_of::<PhaseBinding>(),
            size_of::<Sha3_256>(), size_of::<[Requirements; 4]>(), size_of::<[usize; 9]>(),
            size_of::<Option<Reservation>>(), size_of::<(PermutationNativeCompileFailure, Reservation)>(),
        ].into_iter().try_fold(0, add)?.checked_mul(8).ok_or(PermutationNativeCompileFailure::Overflow)
    }
    fn frame_requirements() -> Result<Requirements> {
        requirement(Category::PhaseScratch, Self::frame_bytes()?)
    }
    pub(crate) fn metadata_requirements() -> Result<Requirements> {
        requirement(Category::RegisteredMetadata, Self::frame_bytes()?)
    }
    pub(crate) fn planning_requirements(blueprint: &PermutationLeafBlueprint<'_, '_>) -> Result<Requirements> {
        combine(&[blueprint.planning_requirements(), Self::frame_requirements()?])
    }
    pub(crate) fn source_compile_plan(&self) -> &PermutationLeafCompiler<'a, 'a, 'a> { &self.compiler }
    pub(crate) fn native_plan(&self) -> &'a PermutationNativeOperationPlan<'a> { self.native }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.native.context() }
    pub(crate) fn sources(&self) -> &'a SourceRetained<PreparedWorkflowSources<'a>> { self.native.sources() }
    pub(crate) fn binding(&self) -> Result<PhaseBinding> {
        PhaseBinding::for_permutation_native_compile(self, 0).map_err(|_| PermutationNativeCompileFailure::Authority)
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
    pub(crate) fn operation(&self, native: RetainedNative<OwnedPermutationOutput<'a>>)
        -> core::result::Result<PermutationNativeCompileOperation<'_, 'a>,
            (PermutationNativeCompileFailure, RetainedNative<OwnedPermutationOutput<'a>>)>
    {
        let binding = match self.binding() { Ok(binding) => binding, Err(error) => return Err((error, native)) };
        let operation = PermutationNativeCompileOperation { plan: self, native, binding };
        match operation.check_child() {
            Ok(()) => Ok(operation),
            Err(error) => Err((error, operation.native)),
        }
    }
}

pub(crate) struct PermutationNativeCompileOperation<'plan, 'a> {
    plan: &'plan PermutationNativeCompilePlan<'a>,
    native: RetainedNative<OwnedPermutationOutput<'a>>,
    binding: PhaseBinding,
}
impl<'a> PermutationNativeCompileOperation<'_, 'a> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn plan(&self) -> &PermutationNativeCompilePlan<'a> { self.plan }
    pub(crate) fn input_slot(&self) -> SlotId { self.native.slot_id() }
    pub(crate) fn native_output(&self) -> &OwnedPermutationOutput<'a> { self.native.get() }
    fn check_child(&self) -> Result<()> {
        let expected = PhaseBinding::for_permutation_native(self.plan.native, 0)
            .map_err(|_| PermutationNativeCompileFailure::Authority)?;
        let child = self.native.get();
        if self.native.binding() != expected || child.binding() != expected
            || !core::ptr::eq(child.sources(), self.plan.sources())
            || !child.proof().source().same_source(self.plan.compiler.blueprint().source())
            || child.proof().owned().geometry().kind() != self.plan.native.kind()
        { return Err(PermutationNativeCompileFailure::Authority); }
        Ok(())
    }
    pub(crate) fn validate(&self, execution: &ExecutionAccess<'_>, ledger: &Ledger) -> Result<()> {
        if execution.binding() != self.binding || self.plan.binding()? != self.binding
            || !core::ptr::eq(execution.context(), self.plan.context())
            || execution.context().policy() != Policy::GpuRequired
            || !execution.owns_source(self.plan.sources()) || !self.native.belongs_to(execution)
            || !self.plan.belongs_to(ledger) || !self.native.get().proof().owned().belongs_to(ledger)
            || self.plan.native.policy() != ProofCachePolicy::FreshOnly
        { return Err(PermutationNativeCompileFailure::Authority); }
        self.check_child()
    }
}
