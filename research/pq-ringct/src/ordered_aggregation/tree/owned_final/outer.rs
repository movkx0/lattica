//! Preissued final PCS packets bind only the original compiled merge owner.
//! No numeric admission, cache hit, fallback or second proof attempt is exposed.
use super::*;
use crate::execution::workflow_resources::{OuterPreissueAccess, OwnedOuterScope};
use lattica_prover_p3::{
    block_v2::machine::{OuterBackendAdmission, OuterSourceEnvelope, OuterSourceFootprint,
        PreissuedOuterBackend, RegisteredGpuLimits},
    proving::{CoverageScope, Policy, Request},
};

pub(crate) struct PreissuedFinalOuter<'plan, 'source> {
    plan: &'plan FinalPhasePlan<'source>,
    binding: PhaseBinding,
    backend: PreissuedOuterBackend,
}
pub(crate) struct BoundFinalOuter<'operation, 'plan, 'source> {
    operation: &'operation FinalOuterOperation<'plan, 'source>,
    binding: PhaseBinding,
    backend: OuterBackendAdmission<'operation>,
    attempted: core::cell::Cell<bool>,
}
impl PreissuedFinalOuter<'_, '_> {
    pub(crate) fn metadata_host_bytes() -> OwnedResult<usize> {
        [
            OuterSourceEnvelope::additional_metadata_host_bytes().map_err(|_| FinalFailure::Source)?,
            bytes::<PreissuedFinalOuter<'static, 'static>>(8)?,
            bytes::<Option<PreissuedFinalOuter<'static, 'static>>>(8)?,
            bytes::<[Option<PreissuedFinalOuter<'static, 'static>>; 3]>(8)?,
            bytes::<BoundFinalOuter<'static, 'static, 'static>>(8)?,
            bytes::<OwnedResult<PreissuedFinalOuter<'static, 'static>>>(8)?,
            bytes::<OwnedResult<BoundFinalOuter<'static, 'static, 'static>>>(8)?,
            bytes::<OuterBackendAdmission<'static>>(8)?, bytes::<PreissuedOuterBackend>(8)?,
            bytes::<OuterSourceFootprint>(8)?, bytes::<RegisteredGpuLimits>(8)?,
            bytes::<Requirements>(8)?, bytes::<PhaseBinding>(8)?, bytes::<String>(8)?,
        ].into_iter().try_fold(64 << 10, add)
    }
    pub(crate) fn planning_scratch_requirement() -> OwnedResult<Requirements> {
        requirement(Category::PhaseScratch,
            usize::try_from(crate::execution::retained_resources::OUTER_PLANNING_HOST_BYTES)
                .map_err(|_| FinalFailure::Overflow)?)
    }
}
impl<'plan, 'source> PreissuedFinalOuter<'plan, 'source> {
    pub(crate) fn new(plan: &'plan FinalPhasePlan<'source>, ordinal: usize,
        access: &OuterPreissueAccess<'_>) -> OwnedResult<Self>
    {
        let Some(FinalStepKind::Outer(merge)) = plan.step_kind(ordinal)
            else { return Err(FinalFailure::Order); };
        let binding = plan.binding(ordinal, FinalStepKind::Outer(merge))?;
        access.require_planning_scratch(Self::planning_scratch_requirement()?)
            .map_err(|_| FinalFailure::Authority)?;
        if access.binding() != binding || !plan.belongs_to(access.ledger())
            || !plan.fresh_only() || access.context().policy() != Policy::GpuRequired
            || access.pcs_host_bytes() == 0 || access.pcs_host_bytes() > 24 << 30
            || access.pcs_host_bytes() > access.backend_bytes().host
            || access.backend_bytes().device != 8 << 30
        { return Err(FinalFailure::Authority); }
        let shape = plan.source.merge(merge).ok_or(FinalFailure::Order)?
            .outer_shape().map_err(|_| FinalFailure::Source)?;
        let limits = access.limits().map_err(|_| FinalFailure::Source)?;
        let backend = OuterSourceEnvelope::inspect(shape, limits, access.pcs_host_bytes())
            .and_then(OuterSourceEnvelope::preissue).map_err(|_| FinalFailure::Source)?;
        Ok(Self { plan, binding, backend })
    }
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn check_before_native(&self) -> OwnedResult<()> {
        if !self.plan.fresh_only() { return Err(FinalFailure::Authority); }
        self.backend.check_execution_selection().map_err(|_| FinalFailure::Authority)
    }
    pub(crate) fn bind<'operation>(self,
        operation: &'operation FinalOuterOperation<'plan, 'source>,
        execution: &ExecutionAccess<'_>)
        -> OwnedResult<BoundFinalOuter<'operation, 'plan, 'source>>
    {
        if !core::ptr::eq(operation.plan, self.plan)
            || operation.binding() != self.binding || execution.binding() != self.binding
        { return Err(FinalFailure::Authority); }
        let (program, public, witness) = operation.borrowed_parts(execution)?;
        let backend = self.backend.bind_fixed_public(program, public, witness)
            .map_err(|_| FinalFailure::Source)?;
        Ok(BoundFinalOuter { operation, binding: self.binding, backend,
            attempted: core::cell::Cell::new(false) })
    }
}
impl<'operation, 'plan, 'source> BoundFinalOuter<'operation, 'plan, 'source> {
    pub(crate) fn admission(&self) -> &OuterBackendAdmission<'operation> { &self.backend }
    pub(crate) fn prove_registered(&self, scope: &mut OwnedOuterScope<'_, '_>,
        registered: RegisteredProgram) -> OwnedResult<FinalNode<'source>>
    {
        // Latch before validating. Even a refused request consumes this epoch.
        if self.attempted.replace(true) || scope.binding() != self.binding
            || !scope.matches_backend(&self.backend)
            || !scope.matches_program(self.backend.program())
        { return Err(FinalFailure::Authority); }
        self.operation.prove_registered(scope, registered, &self.backend)
    }
}
impl<'source> FinalOuterOperation<'_, 'source> {
    fn prove_registered(&self, scope: &mut OwnedOuterScope<'_, '_>,
        registered: RegisteredProgram, backend: &OuterBackendAdmission<'_>)
        -> OwnedResult<FinalNode<'source>>
    {
        let (program, public, witness) = self.borrowed_parts(scope.execution())?;
        if !scope.matches_program(program) || !scope.matches_backend(backend)
            || !Arc::ptr_eq(program, backend.program())
            || !core::ptr::eq(registered.air().program(), program.as_ref())
            || !core::ptr::eq(backend.public(), public.as_slice())
            || !core::ptr::eq(backend.witness(), witness.as_slice())
            || !self.plan.fresh_only()
        { return Err(FinalFailure::Authority); }
        let compiled = self.compiled.get();
        let roots = memory::cap_roots(program.height())?;
        if registered.preprocessing_cap().roots().len() != roots {
            return Err(FinalFailure::Source);
        }
        let mut cap = Vec::new();
        cap.try_reserve_exact(roots).map_err(|_| FinalFailure::Capacity)?;
        if cap.capacity() > roots { return Err(FinalFailure::Capacity); }
        cap.extend_from_slice(registered.preprocessing_cap().roots());
        let key = BatchKey { spec: compiled.node.spec.clone(), height: program.height(),
            cap, verifier: Arc::new(registered.verifier()) };
        let key_bytes = [
            bytes::<[Val; 4]>(key.cap.capacity())?, key.verifier.cached_metadata_bytes(),
            bytes::<std::sync::atomic::AtomicUsize>(2)?,
            core::mem::align_of::<RegisteredVerifier>(), size_of::<FinalNode<'_>>(),
        ].into_iter().try_fold(0, add)?;
        if key_bytes as u64 > self.binding.facts().output.get(Category::RegisteredMetadata).host {
            return Err(FinalFailure::Capacity);
        }
        self.plan.cache.proof_attempt();
        let (proof, report) = registered.into_prove_outer_with_request_and_report(backend,
            Request { policy: Policy::GpuRequired, emit_report: false })
            .map_err(|_| FinalFailure::Proof)?;
        scope.record_report(&report, CoverageScope::RegisteredProof)
            .map_err(|_| FinalFailure::Report)?;
        let (setup_ns, proving_ns) = scope.timings().map_err(|_| FinalFailure::Report)?;
        if proving_ns != report.elapsed_ns { return Err(FinalFailure::Authority); }
        drop(report);
        let mut output = FinalNode {
            node: BatchNode { key, proof: BatchProof { public: compiled.node.public, proof } },
            source: compiled.source, merge: compiled.merge, report: compiled.report,
        };
        memory::check_node(&output, self.plan, self.merge)?;
        let started = Instant::now();
        output.node.key.verify(&output.node.proof).map_err(|_| FinalFailure::Verification)?;
        output.report.cpu_verification_ns = started.elapsed().as_nanos();
        output.report.setup_ns = setup_ns;
        output.report.proving_ns = proving_ns;
        output.report.recursive_proofs = 1;
        self.plan.cache.fresh_proof();
        Ok(output)
    }
}
