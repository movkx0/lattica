use super::*;
use crate::execution::workflow_resources::{OuterPreissueAccess, OwnedOuterScope};
use lattica_prover_p3::{
    block_v2::machine::{OuterBackendAdmission, OuterSourceEnvelope, OuterSourceFootprint,
        PreissuedOuterBackend, RegisteredGpuLimits},
    proving::Policy,
};

pub(crate) struct PreissuedAuxiliaryOuter<'plan, 'source, 'graph> {
    plan: &'plan AuxiliaryGraphPlan<'source, 'graph>,
    binding: PhaseBinding,
    backend: PreissuedOuterBackend,
}
pub(crate) struct BoundAuxiliaryOuter<'operation, 'plan, 'source, 'graph> {
    operation: &'operation AuxiliaryOuterOperation<'plan, 'source, 'graph>,
    binding: PhaseBinding,
    source: OuterSourceFootprint,
    backend: OuterBackendAdmission<'operation>,
    attempted: core::cell::Cell<bool>,
}
impl PreissuedAuxiliaryOuter<'_, '_, '_> {
    pub(crate) fn metadata_host_bytes() -> OwnedResult<usize> {
        [OuterSourceEnvelope::additional_metadata_host_bytes().map_err(|_| GraphParentFailure::Resource)?,
            bytes::<Self>(8)?, bytes::<Option<Self>>(8)?,
            bytes::<BoundAuxiliaryOuter<'static, 'static, 'static, 'static>>(8)?,
            bytes::<OuterBackendAdmission<'static>>(8)?, bytes::<PreissuedOuterBackend>(8)?,
            bytes::<OuterSourceFootprint>(8)?, bytes::<PhaseBinding>(8)?,
            bytes::<RegisteredGpuLimits>(8)?, bytes::<OwnedResult<Self>>(8)?,
        ].into_iter().try_fold(64 << 10, add)
    }
    pub(crate) fn planning_scratch_requirement() -> OwnedResult<Requirements> {
        requirement(Category::PhaseScratch,
            usize::try_from(crate::execution::retained_resources::OUTER_PLANNING_HOST_BYTES)
                .map_err(|_| GraphParentFailure::Overflow)?)
    }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn footprint(&self) -> OuterSourceFootprint { self.backend.footprint() }
    pub(crate) fn check_before_native(&self) -> OwnedResult<()> {
        if self.plan.cache.policy() != ProofCachePolicy::FreshOnly || self.binding != self.plan.binding(1)? {
            return Err(GraphParentFailure::Authority);
        }
        self.backend.check_execution_selection().map_err(|_| GraphParentFailure::Authority)
    }
}
impl<'plan, 'source, 'graph> PreissuedAuxiliaryOuter<'plan, 'source, 'graph> {
    pub(crate) fn new(plan: &'plan AuxiliaryGraphPlan<'source, 'graph>, access: &OuterPreissueAccess<'_>)
        -> OwnedResult<Self>
    {
        let binding = plan.binding(1)?;
        let backend_bytes = access.backend_bytes();
        let pcs_host = access.pcs_host_bytes();
        access.require_planning_scratch(Self::planning_scratch_requirement()?)
            .map_err(|_| GraphParentFailure::Authority)?;
        if plan.cache.policy() != ProofCachePolicy::FreshOnly || access.binding() != binding
            || !plan.belongs_to(access.ledger())
            || plan.original.requirements() != AuxiliaryGraphPlan::planning_requirements()?
            || access.context().policy() != Policy::GpuRequired
            || pcs_host == 0 || pcs_host > 24u64 << 30 || pcs_host > backend_bytes.host
            || backend_bytes.device > 8u64 << 30
        {
            return Err(GraphParentFailure::Authority);
        }
        let limits = access.limits().map_err(|_| GraphParentFailure::Resource)?;
        let backend = OuterSourceEnvelope::inspect(plan.source.outer_shape()?, limits, pcs_host)
            .and_then(OuterSourceEnvelope::preissue).map_err(|_| GraphParentFailure::Resource)?;
        Ok(Self { plan, binding, backend })
    }
    pub(crate) fn bind<'operation>(self,
        operation: &'operation AuxiliaryOuterOperation<'plan, 'source, 'graph>,
        access: &ExecutionAccess<'_>) -> OwnedResult<BoundAuxiliaryOuter<'operation, 'plan, 'source, 'graph>>
    {
        if operation.binding() != self.binding || access.binding() != self.binding
            || self.plan.binding(1)? != self.binding
        { return Err(GraphParentFailure::Authority); }
        let (program, public, witness) = operation.borrowed_parts(access)?;
        let source = self.backend.footprint();
        let backend = self.backend.bind(program, public, witness).map_err(|_| GraphParentFailure::Source)?;
        Ok(BoundAuxiliaryOuter { operation, binding: self.binding, source, backend,
            attempted: core::cell::Cell::new(false) })
    }
}
impl<'operation, 'plan, 'source, 'graph> BoundAuxiliaryOuter<'operation, 'plan, 'source, 'graph> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn source_footprint(&self) -> OuterSourceFootprint { self.source }
    pub(crate) fn admission(&self) -> &OuterBackendAdmission<'operation> { &self.backend }
    pub(crate) fn operation(&self) -> &'operation AuxiliaryOuterOperation<'plan, 'source, 'graph> { self.operation }
    pub(crate) fn prove_registered(&self, scope: &mut OwnedOuterScope<'_, '_>, registered: RegisteredProgram)
        -> OwnedResult<OwnedGraphNode<'graph>>
    {
        if self.attempted.replace(true) || scope.binding() != self.binding
            || !scope.matches_program(self.backend.program()) || !scope.matches_backend(&self.backend)
        { return Err(GraphParentFailure::Authority); }
        self.operation.prove_registered(scope, registered, &self.backend)
    }
}
