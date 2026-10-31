//! Pure whole-case inventory and metadata closure, before any proof exists.
//! Missing concrete producers are counted from the real graph. A source count
//! never manufactures a producer, phase binding, or proof-execution capability.
use super::{PreparedWorkflowSources, SourcePlanningPlan};
use crate::{
    execution::{retained_resources::{Bytes, Category, Ledger, Requirements, Reservation},
        workflow_resources::{controller_bytes, SourceRetained}, ProvingContext},
    graph_crypto::{OwnedAesRequestPlan, PairedRequestPlan, RequestDescriptor},
    graph_proofs::ComponentKind,
    graph_tree::LeafKind,
    ordered_aggregation::source::FinalAggregationPlan,
};
use core::mem::size_of;

pub(super) type Result<T> = core::result::Result<T, ClosureError>;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UnavailableProducers {
    pub(crate) source_native: usize,
    pub(crate) algebra_native: usize,
    pub(crate) auxiliary_native: usize,
    pub(crate) graph_leaf: usize,
    pub(crate) graph_parent: usize,
    pub(crate) final_compile: usize,
    pub(crate) final_outer: usize,
    pub(crate) final_verifier: usize,
}
impl UnavailableProducers {
    pub(crate) fn require_complete(self) -> Result<()> {
        if self == Self::default() { Ok(()) } else { Err(ClosureError::MissingProducers(self)) }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosureError {
    Identity, Source, Resource, Overflow, Allocation, Order, Coverage,
    MissingProducers(UnavailableProducers),
}

pub(super) fn add(a: usize, b: usize) -> Result<usize> {
    a.checked_add(b).ok_or(ClosureError::Overflow)
}
pub(super) fn mul(a: usize, b: usize) -> Result<usize> {
    a.checked_mul(b).ok_or(ClosureError::Overflow)
}
pub(super) fn host(n: usize) -> Result<Bytes> {
    Ok(Bytes { host: u64::try_from(n).map_err(|_| ClosureError::Overflow)?, device: 0 })
}
pub(super) fn sum(a: Requirements, b: Requirements) -> Result<Requirements> {
    let mut result = a;
    for category in Category::ALL { result.add(category, b.get(category)).map_err(|_| ClosureError::Overflow)?; }
    Ok(result)
}
pub(super) fn maximum(a: Requirements, b: Requirements) -> Requirements {
    let mut result = Requirements::default();
    for category in Category::ALL {
        let a = a.get(category); let b = b.get(category);
        result.add(category, Bytes { host: a.host.max(b.host), device: a.device.max(b.device) })
            .expect("one category maximum cannot overflow");
    }
    result
}
pub(super) fn contains(a: Requirements, b: Requirements) -> bool {
    Category::ALL.into_iter().all(|category| {
        let a = a.get(category); let b = b.get(category);
        a.host >= b.host && a.device >= b.device
    })
}

/// This diagnostic has no original claim and cannot enter WorkflowAdmission.
/// Known byte counts exclude unavailable producers; they are explicitly not a
/// complete workflow memory bound until every required typed family exists.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ClosureInspection {
    pub(crate) transactions: usize,
    pub(crate) crypto_requests: usize,
    pub(crate) native_crypto_proofs: usize,
    pub(crate) recursive_crypto_proofs: usize,
    pub(crate) known_steps: usize,
    pub(crate) unavailable: UnavailableProducers,
    pub(crate) known_metadata: Requirements,
    pub(crate) known_planning_scratch: Requirements,
}

/// Source planning can replace its bootstrap only with this checked complete
/// envelope. It is intentionally unavailable for a faithful case while one of
/// the actual required producer families has no concrete typed plan.
pub(crate) struct SourceClosurePlanningPlan<'a> {
    scope: &'a SourcePlanningPlan<'a>,
    members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>],
    ledger: Ledger,
    inspection: ClosureInspection,
    planning: Requirements,
    scratch: Requirements,
}

impl<'a> SourceClosurePlanningPlan<'a> {
    /// These fixed descriptors can outlive replacement of bootstrap scratch.
    /// Root includes them in the permanent enclosing deduction before binding
    /// the first phase capability; no replacement reservation is inferred.
    pub(crate) fn enclosing_host_bytes() -> Result<usize> {
        mul(8, [size_of::<Self>(), size_of::<ClosureInspection>(),
            size_of::<[&SourceRetained<PreparedWorkflowSources<'a>>; 4]>(),
            size_of::<Result<Self>>()].into_iter().try_fold(0, add)?)
    }

    /// Root adds this to SourcePlanningPlan's bootstrap scratch BEFORE calling
    /// inspect/new. This counts source inspection frames, not compiler backing.
    pub(crate) fn inspection_requirements() -> Result<Requirements> {
        let frames = mul(8, [size_of::<Self>(), size_of::<ClosureInspection>(),
            size_of::<UnavailableProducers>(), size_of::<Result<Self>>(),
            size_of::<Result<ClosureInspection>>(), size_of::<Ledger>(),
            size_of::<Requirements>(), size_of::<Bytes>(),
            size_of::<[usize; 16]>(), size_of::<[&SourceRetained<PreparedWorkflowSources<'a>>; 4]>(),
        ].into_iter().try_fold(0, add)?)?;
        // Source descriptor helpers use bounded static/enum/arithmetic errors;
        // no supplied String crosses this boundary. Keep their formatting
        // overlap separate from the permanent returned-descriptor census.
        Ok(Requirements::single(Category::PhaseScratch, host(add(frames, 64 << 10)?)?))
    }

    pub(crate) fn inspect(scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>],
        ledger: &Ledger, inspection_original: &Reservation) -> Result<ClosureInspection>
    {
        if !inspection_original.belongs_to(ledger)
            || !contains(inspection_original.requirements(), Self::inspection_requirements()?)
            || !matches!(members.len(), 3 | 4) || members.len() != scope.natives().len()
        { return Err(ClosureError::Identity); }
        let mut result = ClosureInspection { transactions: members.len(), crypto_requests: 0,
            native_crypto_proofs: 0, recursive_crypto_proofs: 0, known_steps: members.len(),
            unavailable: UnavailableProducers::default(),
            known_metadata: FinalAggregationPlan::planning_requirements().map_err(|_| ClosureError::Resource)?,
            known_planning_scratch: FinalAggregationPlan::planning_scratch_requirements().map_err(|_| ClosureError::Resource)?,
        };
        for (index, owner) in members.iter().enumerate() {
            let prepared = owner.get();
            scope.validate_initial_source(prepared.native_source()).map_err(|_| ClosureError::Identity)?;
            if !owner.belongs_to(ledger) || owner.source_fingerprint() != scope.source_fingerprint()
                || owner.compiled_source_fingerprint() != scope.compiled_source_fingerprint()
                || !core::ptr::eq(prepared.native_source(), &scope.natives()[index])
                || members[..index].iter().any(|prior| core::ptr::eq(*prior, *owner))
                || prepared.context().context != *scope.natives()[index].context()
                || prepared.plan().label() != members[0].get().plan().label()
            { return Err(ClosureError::Identity); }
            let leaves = prepared.plan().leaves();
            if leaves.len() < 3 || !matches!(leaves[0].kind(), LeafKind::FixedSources)
                || !matches!(leaves[1].kind(), LeafKind::Statement)
                || !matches!(leaves[2].kind(), LeafKind::PrivateProof)
                || leaves[3..].iter().any(|leaf| !matches!(leaf.kind(), LeafKind::Operations(_)))
            { return Err(ClosureError::Coverage); }
            result.unavailable.source_native = add(result.unavailable.source_native, 2)?;
            result.unavailable.graph_leaf = add(result.unavailable.graph_leaf, leaves.len())?;
            result.unavailable.graph_parent = add(result.unavailable.graph_parent, leaves.len() - 1)?;
            result.unavailable.algebra_native = add(result.unavailable.algebra_native,
                prepared.algebra().batches().iter().filter(|batch| !matches!(batch.kind(), ComponentKind::External)).count())?;
            result.unavailable.auxiliary_native = add(result.unavailable.auxiliary_native,
                prepared.auxiliary_factory().requests().len())?;
            for request in prepared.crypto().requests() {
                let (metadata, scratch, native, recursive) = match request.descriptor() {
                    RequestDescriptor::Shake(_) => {
                        let counts = request.shake_wrapper_schedule(scope.layout()).map_err(|_| ClosureError::Source)?.counts();
                        (PairedRequestPlan::planning_requirements(request, scope.layout()).map_err(|_| ClosureError::Resource)?,
                         PairedRequestPlan::planning_scratch_requirements(request, scope.layout()).map_err(|_| ClosureError::Resource)?,
                         counts.native_proofs, add(counts.recursive_leaves, counts.recursive_parents)?)
                    }
                    RequestDescriptor::Aes(_) => {
                        let native = request.segments().len();
                        if native == 0 { return Err(ClosureError::Coverage); }
                        (OwnedAesRequestPlan::planning_requirements(request).map_err(|_| ClosureError::Resource)?,
                         OwnedAesRequestPlan::planning_scratch_requirements(request).map_err(|_| ClosureError::Resource)?,
                         native, mul(native, 2)?.checked_sub(1).ok_or(ClosureError::Overflow)?)
                    }
                };
                result.crypto_requests = add(result.crypto_requests, 1)?;
                result.native_crypto_proofs = add(result.native_crypto_proofs, native)?;
                result.recursive_crypto_proofs = add(result.recursive_crypto_proofs, recursive)?;
                result.known_steps = add(result.known_steps, add(1, add(native, mul(recursive, 2)?)?)?)?;
                result.known_metadata = sum(result.known_metadata, metadata)?;
                result.known_planning_scratch = maximum(result.known_planning_scratch, scratch);
            }
        }
        result.unavailable.final_compile = members.len() - 1;
        result.unavailable.final_outer = members.len() - 1;
        result.unavailable.final_verifier = 1;
        let scheduler = super::closed_plan::schedule_metadata_requirements(result.known_steps, result.crypto_requests)?;
        result.known_metadata = sum(result.known_metadata, scheduler)?;
        // The upper bound is metadata only: allocating one slot per step is
        // never used to preissue proof payload storage. Liveness packs that
        // pool before complete memory admission.
        result.known_metadata = sum(result.known_metadata, Requirements::single(Category::RegisteredMetadata,
            Bytes { host: controller_bytes(add(result.known_steps, 1)?).map_err(|_| ClosureError::Resource)?, device: 0 }))?;
        result.known_planning_scratch = maximum(result.known_planning_scratch, Self::inspection_requirements()?);
        Ok(result)
    }

    pub(crate) fn new(scope: &'a SourcePlanningPlan<'a>,
        members: &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>],
        ledger: &Ledger, inspection_original: &Reservation) -> Result<Self>
    {
        let inspection = Self::inspect(scope, members, ledger, inspection_original)?;
        // This is an actual required-versus-implemented inventory comparison.
        // In particular a final source geometry is not a final proof producer.
        inspection.unavailable.require_complete()?;
        let scratch = inspection.known_planning_scratch;
        let planning = sum(inspection.known_metadata, scratch)?;
        Ok(Self { scope, members, ledger: ledger.clone(), inspection, planning, scratch })
    }
    pub(crate) fn context(&self) -> &'a ProvingContext { self.scope.context() }
    pub(crate) fn source_fingerprint(&self) -> [u8; 32] { self.scope.source_fingerprint() }
    pub(crate) fn compiled_source_fingerprint(&self) -> [u8; 32] { self.scope.compiled_source_fingerprint() }
    pub(crate) fn enclosing_bytes(&self) -> Bytes { self.scope.enclosing_bytes() }
    pub(crate) fn belongs_to(&self, ledger: &Ledger) -> bool { self.members.iter().all(|owner| owner.belongs_to(ledger)) }
    pub(crate) fn planning_requirements(&self) -> Requirements { self.planning }
    pub(crate) fn planning_scratch_requirements(&self) -> Requirements { self.scratch }
    pub(super) fn scope(&self) -> &'a SourcePlanningPlan<'a> { self.scope }
    pub(super) fn members(&self) -> &'a [&'a SourceRetained<PreparedWorkflowSources<'a>>] { self.members }
    pub(super) fn ledger(&self) -> &Ledger { &self.ledger }
    pub(super) fn inspection(&self) -> ClosureInspection { self.inspection }
}
