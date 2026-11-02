//! Source backend packets are fixed before native0 under the closed workflow's
//! original claims. They can bind only their exact immutable outer operation.
use super::*;
use crate::execution::workflow_resources::{ExecutionAccess, OuterPreissueAccess, OwnedOuterScope, PhaseBinding};
use lattica_prover_p3::block_v2::machine::{
    OuterBackendAdmission, OuterSourceEnvelope, OuterSourceFootprint,
    PreissuedOuterBackend, RegisteredGpuLimits,
};

/// No Clone, raw constructor, backend extraction, or numeric admission path.
pub(crate) struct PreissuedAesOuter<'plan, 'request> {
    plan: &'plan OwnedAesRequestPlan<'request>,
    binding: PhaseBinding,
    backend: PreissuedOuterBackend,
}

/// Keeps the exact compiled operation borrowed through registration, proving,
/// independent verification and runtime retirement in the enclosing driver.
pub(crate) struct BoundAesOuter<'operation, 'plan, 'request> {
    operation: &'operation OwnedAesOuterOperation<'plan, 'request>,
    binding: PhaseBinding,
    source: OuterSourceFootprint,
    backend: OuterBackendAdmission<'operation>,
    attempted: core::cell::Cell<bool>,
}

impl PreissuedAesOuter<'_, '_> {
    /// The packet contains only inline fields and borrows its source owner.
    pub(crate) fn metadata_host_bytes() -> Result<usize> {
        Ok(core::mem::size_of::<Self>())
    }
    // One complete construction/bind census stays in the serial phase owner.
    // Packet originals keep the returned inline payload until consumption.
    fn forwarding_host_bytes() -> Result<usize> {
        [
            OuterSourceEnvelope::additional_metadata_host_bytes().map_err(|_| PairedFailure::Resource)?,
            bytes::<PreissuedAesOuter<'static, 'static>>(8)?,
            bytes::<Option<PreissuedAesOuter<'static, 'static>>>(8)?,
            bytes::<Vec<PreissuedAesOuter<'static, 'static>>>(8)?,
            bytes::<BoundAesOuter<'static, 'static, 'static>>(8)?,
            bytes::<Result<PreissuedAesOuter<'static, 'static>>>(8)?,
            bytes::<Result<BoundAesOuter<'static, 'static, 'static>>>(8)?,
            bytes::<OuterBackendAdmission<'static>>(8)?,
            bytes::<PreissuedOuterBackend>(8)?,
            bytes::<OuterSourceFootprint>(8)?,
            bytes::<PhaseBinding>(16)?, bytes::<RegisteredGpuLimits>(8)?,
            bytes::<Requirements>(8)?, bytes::<crate::execution::retained_resources::Bytes>(8)?,
            bytes::<String>(8)?, bytes::<Result<()>>(8)?,
        ].into_iter().try_fold(64 << 10, add)
    }

    /// The maintained source planner's separate shared helper/frame bound.
    /// A retains the same original scratch through all preissue calls.
    pub(crate) fn planning_scratch_requirement() -> Result<Requirements> {
        requirement(Category::PhaseScratch,
            add(usize::try_from(crate::execution::retained_resources::OUTER_PLANNING_HOST_BYTES)
                .map_err(|_| PairedFailure::Overflow)?, Self::forwarding_host_bytes()?)?)
    }
}

impl<'plan, 'request> PreissuedAesOuter<'plan, 'request> {
    pub(crate) fn new(plan: &'plan OwnedAesRequestPlan<'request>, ordinal: usize,
        access: &OuterPreissueAccess<'_>) -> Result<Self> {
        plan.check_prepared_endpoints()?;
        let OwnedAesStepKind::Outer { node } = plan.ordered_steps().get(ordinal)
            .ok_or(PairedFailure::Order)?.kind else { return Err(PairedFailure::Order); };
        let binding = PhaseBinding::for_aes(plan, ordinal).map_err(|_| PairedFailure::Authority)?;
        let backend_bytes = access.backend_bytes();
        let pcs_host = access.pcs_host_bytes();
        access.require_planning_scratch(Self::planning_scratch_requirement()?)
            .map_err(|_| PairedFailure::Authority)?;
        if access.binding() != binding || !plan.belongs_to(access.ledger())
            || plan._metadata_original.requirements() != OwnedAesRequestPlan::planning_requirements(plan.request)?
            || access.context().policy() != lattica_prover_p3::proving::Policy::GpuRequired
            || pcs_host == 0 || pcs_host > 24u64 << 30 || pcs_host > backend_bytes.host
            || backend_bytes.device > 8u64 << 30 {
            return Err(PairedFailure::Authority);
        }
        let shape = plan.nodes.get(node).ok_or(PairedFailure::Order)?.source.outer_shape()?;
        let limits = access.limits().map_err(|_| PairedFailure::Resource)?;
        let backend = OuterSourceEnvelope::inspect(shape, limits, pcs_host)
            .and_then(OuterSourceEnvelope::preissue).map_err(|_| PairedFailure::Resource)?;
        Ok(Self { plan, binding, backend })
    }

    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn footprint(&self) -> OuterSourceFootprint { self.backend.footprint() }
    pub(crate) fn check_before_native(&self) -> Result<()> {
        self.plan.check_prepared_endpoints()?;
        self.backend.check_execution_selection().map_err(|_| PairedFailure::Authority)
    }

    /// Runs only after actual previous runtime retirement. Binding admits no
    /// storage and cannot reconstruct a source plan from observed proof rows.
    pub(crate) fn bind<'operation>(self,
        operation: &'operation OwnedAesOuterOperation<'plan, 'request>,
        access: &ExecutionAccess<'_>) -> Result<BoundAesOuter<'operation, 'plan, 'request>> {
        if operation.binding() != self.binding || access.binding() != self.binding
            || PhaseBinding::for_aes(self.plan, self.binding.ordinal())
                .map_err(|_| PairedFailure::Authority)? != self.binding {
            return Err(PairedFailure::Authority);
        }
        let (program, public, witness) = operation.borrowed_parts(access)?;
        let source = self.backend.footprint();
        let backend = self.backend.bind(program, public, witness).map_err(|_| PairedFailure::SourceDrift)?;
        Ok(BoundAesOuter { operation, binding: self.binding, source, backend,
            attempted: core::cell::Cell::new(false) })
    }
}

impl<'operation, 'plan, 'request> BoundAesOuter<'operation, 'plan, 'request> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn source_footprint(&self) -> OuterSourceFootprint { self.source }
    pub(crate) fn admission(&self) -> &OuterBackendAdmission<'operation> { &self.backend }
    pub(crate) fn operation(&self) -> &'operation OwnedAesOuterOperation<'plan, 'request> { self.operation }
    pub(crate) fn prove_registered(&self, scope: &mut OwnedOuterScope<'_, '_>,
        registered: lattica_prover_p3::block_v2::machine::backend::RegisteredProgram)
        -> Result<PairedNode<'request>> {
        // Latch before every refusal. A failure is terminal; no repeated proof
        // attempt can use the same original packet, output slot, or scope.
        if self.attempted.replace(true) || scope.binding() != self.binding
            || !scope.matches_program(self.backend.program())
            || !scope.matches_backend(&self.backend) {
            return Err(PairedFailure::Authority);
        }
        self.operation.prove_registered(scope, registered, &self.backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_census_is_additive_to_the_shared_source_planner() {
        assert_eq!(PreissuedAesOuter::metadata_host_bytes().unwrap(), core::mem::size_of::<PreissuedAesOuter>());
        assert_eq!(PreissuedAesOuter::planning_scratch_requirement().unwrap()
            .get(Category::PhaseScratch).host, (1 << 20) + PreissuedAesOuter::forwarding_host_bytes().unwrap() as u64);
    }
}
