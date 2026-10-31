use super::*;
use crate::execution::workflow_resources::{OuterPreissueAccess, OwnedOuterScope};
use lattica_prover_p3::{
    block_v2::machine::{OuterBackendAdmission, OuterSourceEnvelope, OuterSourceFootprint,
        PreissuedOuterBackend, RegisteredGpuLimits},
    proving::{CoverageScope, Policy, Report, Request},
};

pub(crate) struct PreissuedGraphParentOuter<'plan, 'source, 'graph> {
    plan: &'plan GraphParentPlan<'source, 'graph>,
    binding: PhaseBinding,
    backend: PreissuedOuterBackend,
}
pub(crate) struct BoundGraphParentOuter<'operation, 'plan, 'source, 'graph> {
    operation: &'operation GraphParentOuterOperation<'plan, 'source, 'graph>,
    binding: PhaseBinding,
    source: OuterSourceFootprint,
    backend: OuterBackendAdmission<'operation>,
    attempted: core::cell::Cell<bool>,
}
impl PreissuedGraphParentOuter<'_, '_, '_> {
    pub(crate) fn metadata_host_bytes() -> OwnedResult<usize> {
        [OuterSourceEnvelope::additional_metadata_host_bytes().map_err(|_| GraphParentFailure::Resource)?,
            bytes::<Self>(8)?, bytes::<Option<Self>>(8)?,
            bytes::<BoundGraphParentOuter<'static, 'static, 'static, 'static>>(8)?,
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
impl<'plan, 'source, 'graph> PreissuedGraphParentOuter<'plan, 'source, 'graph> {
    pub(crate) fn new(plan: &'plan GraphParentPlan<'source, 'graph>, access: &OuterPreissueAccess<'_>)
        -> OwnedResult<Self>
    {
        let binding = plan.binding(1)?;
        let backend_bytes = access.backend_bytes();
        let pcs_host = access.pcs_host_bytes();
        access.require_planning_scratch(Self::planning_scratch_requirement()?)
            .map_err(|_| GraphParentFailure::Authority)?;
        if plan.cache.policy() != ProofCachePolicy::FreshOnly || access.binding() != binding
            || !plan.belongs_to(access.ledger())
            || plan.original.requirements() != GraphParentPlan::planning_requirements()?
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
        operation: &'operation GraphParentOuterOperation<'plan, 'source, 'graph>,
        access: &ExecutionAccess<'_>) -> OwnedResult<BoundGraphParentOuter<'operation, 'plan, 'source, 'graph>>
    {
        if operation.binding() != self.binding || access.binding() != self.binding
            || self.plan.binding(1)? != self.binding
        { return Err(GraphParentFailure::Authority); }
        let (program, public, witness) = operation.borrowed_parts(access)?;
        let source = self.backend.footprint();
        let backend = self.backend.bind(program, public, witness).map_err(|_| GraphParentFailure::Source)?;
        Ok(BoundGraphParentOuter { operation, binding: self.binding, source, backend,
            attempted: core::cell::Cell::new(false) })
    }
}
impl<'operation, 'plan, 'source, 'graph> BoundGraphParentOuter<'operation, 'plan, 'source, 'graph> {
    pub(crate) fn binding(&self) -> PhaseBinding { self.binding }
    pub(crate) fn source_footprint(&self) -> OuterSourceFootprint { self.source }
    pub(crate) fn admission(&self) -> &OuterBackendAdmission<'operation> { &self.backend }
    pub(crate) fn operation(&self) -> &'operation GraphParentOuterOperation<'plan, 'source, 'graph> { self.operation }
    pub(crate) fn prove_registered(&self, scope: &mut OwnedOuterScope<'_, '_>, registered: RegisteredProgram)
        -> OwnedResult<OwnedGraphNode<'graph>>
    {
        if self.attempted.replace(true) || scope.binding() != self.binding
            || !scope.matches_program(self.backend.program()) || !scope.matches_backend(&self.backend)
        { return Err(GraphParentFailure::Authority); }
        self.operation.prove_registered(scope, registered, &self.backend)
    }
}

pub(super) fn caller_requirements() -> OwnedResult<Requirements> {
    let frames = [bytes::<RegisteredProgram>(8)?, bytes::<RegisteredVerifier>(8)?,
        bytes::<OuterBackendAdmission<'static>>(8)?, bytes::<OwnedOuterScope<'static, 'static>>(8)?,
        bytes::<Report>(8)?, bytes::<Request>(8)?, bytes::<p3_batch_stark::BatchProof<Config>>(8)?,
        bytes::<OwnedResult<OwnedGraphNode<'static>>>(8)?, bytes::<CompiledBorrow<'static, 'static>>(8)?,
        bytes::<core::result::Result<(p3_batch_stark::BatchProof<Config>, Report),
            lattica_prover_p3::block_v2::machine::program::ExecutionError>>(8)?,
        bytes::<Vec<[Val; 4]>>(8)?, bytes::<Vec<Val>>(8)?, bytes::<Requirements>(8)?,
        usize::try_from(crate::execution::workflow_resources::owned_outer_forwarding_host_bytes()
            .map_err(|_| GraphParentFailure::Resource)?).map_err(|_| GraphParentFailure::Overflow)?,
        memory::caller_frames()?,
    ].into_iter().try_fold(64 << 10, add)?;
    combine(&[
        requirement(Category::PhaseScratch, frames)?,
        requirement(Category::Report, usize::try_from(crate::execution::outer_report::required_host_bytes()
            .map_err(|_| GraphParentFailure::Resource)?).map_err(|_| GraphParentFailure::Overflow)?)?,
    ])
}
fn key_bytes(key: &NodeKey) -> OwnedResult<usize> {
    add(add(bytes::<[Val; 4]>(key.cap.capacity())?, key.verifier.cached_metadata_bytes())?,
        add(2 * size_of::<usize>() + core::mem::align_of::<RegisteredVerifier>(), size_of::<OwnedGraphNode<'_>>())?)
}
pub(super) fn check_retained(node: &OwnedGraphNode<'_>, reserved: Requirements) -> OwnedResult<()> {
    let actual = source::registered_shape(node.key.height)?;
    if node.key.cap.len() != actual.preprocessing_cap_roots || node.key.cap.capacity() > actual.preprocessing_cap_roots
        || node.proof.public.len() != PUBLIC_VALUES || node.proof.public.capacity() > PUBLIC_VALUES
    { return Err(GraphParentFailure::Capacity); }
    let proof_limit = usize::try_from(reserved.get(Category::RecursiveProof).host)
        .map_err(|_| GraphParentFailure::Overflow)?;
    let extra = add(bytes::<Val>(node.proof.public.capacity())?, size_of::<OwnedGraphNode<'_>>())?;
    let available = proof_limit.checked_sub(extra).ok_or(GraphParentFailure::Capacity)?;
    lattica_prover_p3::block_v2::machine::backend::retained_proof_capacity_bytes(&node.proof.proof,
        available.min(64 << 20)).map_err(|_| GraphParentFailure::Capacity)?;
    if key_bytes(&node.key)? as u64 > reserved.get(Category::RegisteredMetadata).host {
        return Err(GraphParentFailure::Capacity);
    }
    Ok(())
}
/// A private borrowed view lets concrete leaf producers preserve their original
/// compiled owner. No caller can detach/re-attach a raw graph source or proof.
struct CompiledBorrow<'compiled, 'graph> {
    node: &'compiled CompiledNode,
    source: GraphNodeSource<'graph>,
    report: GraphNodeReport,
}

pub(super) fn produce<'graph>(compiled: &OwnedGraphCompiled<'graph>, cache: &OuterProofCache,
    scope: &mut OwnedOuterScope<'_, '_>, registered: RegisteredProgram,
    backend: &OuterBackendAdmission<'_>) -> OwnedResult<OwnedGraphNode<'graph>>
{
    produce_borrowed(&compiled.node, compiled.source, compiled.report, cache, scope, registered, backend)
}

pub(super) fn produce_borrowed<'graph>(node: &CompiledNode, source: GraphNodeSource<'graph>,
    report: GraphNodeReport, cache: &OuterProofCache, scope: &mut OwnedOuterScope<'_, '_>,
    registered: RegisteredProgram, backend: &OuterBackendAdmission<'_>) -> OwnedResult<OwnedGraphNode<'graph>>
{
    let compiled = CompiledBorrow { node, source, report };
    if cache.policy() != ProofCachePolicy::FreshOnly
        || scope.execution().context().policy() != Policy::GpuRequired
        || !scope.matches_program(&compiled.node.program) || !scope.matches_backend(backend)
        || !Arc::ptr_eq(backend.program(), &compiled.node.program)
        || !core::ptr::eq(registered.air().program(), compiled.node.program.as_ref())
        || !core::ptr::eq(backend.public(), compiled.node.public.as_slice())
        || !core::ptr::eq(backend.witness(), compiled.node.witness.as_slice())
    { return Err(GraphParentFailure::Authority); }
    compiled.source.check_compiled(&compiled.node)?;
    let actual = source::registered_shape(compiled.node.program.height())?;
    if registered.preprocessing_cap().roots().len() != actual.preprocessing_cap_roots { return Err(GraphParentFailure::Source); }
    let started = Instant::now();
    let mut cap = Vec::new();
    cap.try_reserve_exact(actual.preprocessing_cap_roots).map_err(|_| GraphParentFailure::Capacity)?;
    if cap.capacity() > actual.preprocessing_cap_roots { return Err(GraphParentFailure::Capacity); }
    cap.extend_from_slice(registered.preprocessing_cap().roots());
    let key = NodeKey { spec: compiled.node.spec.clone(), height: compiled.node.program.height(),
        cap, verifier: Arc::new(registered.verifier()) };
    let requirements = compiled.source.output_requirements()?.0;
    if key_bytes(&key)? as u64 > requirements.get(Category::RegisteredMetadata).host {
        return Err(GraphParentFailure::Capacity);
    }
    cache.proof_attempt();
    let (proof, report) = registered.into_prove_outer_with_request_and_report(backend,
        Request { policy: Policy::GpuRequired, emit_report: false }).map_err(|_| GraphParentFailure::Proof)?;
    scope.record_report(&report, CoverageScope::RegisteredProof).map_err(|_| GraphParentFailure::Report)?;
    let (setup_ns, proving_ns) = scope.timings().map_err(|_| GraphParentFailure::Report)?;
    if proving_ns != report.elapsed_ns { return Err(GraphParentFailure::Authority); }
    drop(report);
    let mut public = Vec::new();
    public.try_reserve_exact(PUBLIC_VALUES).map_err(|_| GraphParentFailure::Capacity)?;
    if public.capacity() > PUBLIC_VALUES { return Err(GraphParentFailure::Capacity); }
    public.extend_from_slice(&compiled.node.public);
    let mut output = OwnedGraphNode { key, proof: NodeProof { public, proof }, source: compiled.source,
        report: compiled.report };
    check_retained(&output, requirements)?;
    let verification = Instant::now();
    output.key.verifier.verify(&output.proof.proof, &output.proof.public).map_err(|_| GraphParentFailure::Verification)?;
    output.report.cpu_verification_ns = verification.elapsed().as_nanos();
    output.report.setup_ns = setup_ns; output.report.proving_ns = proving_ns;
    output.report.registered_phase_ns = setup_ns.checked_add(started.elapsed().as_nanos())
        .ok_or(GraphParentFailure::Overflow)?;
    cache.fresh_proof();
    Ok(output)
}
