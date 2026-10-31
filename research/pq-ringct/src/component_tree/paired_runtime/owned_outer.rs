//! Concrete source-bound outer production. The root issuer owns the exact
//! runtime, original phase partitions, and intact output/failure slots.
use super::*;
use crate::execution::workflow_resources::OwnedOuterScope;
use crate::execution::retained_resources::{Category, Requirements};
use lattica_prover_p3::{
    block_v2::machine::OuterBackendAdmission,
    proving::{CoverageScope, Policy, Report, Request as ProvingRequest},
};

pub(crate) fn owned_outer_requirements() -> Result<Requirements> {
    let frames = [
        source::bytes::<RegisteredProgram>(8)?, source::bytes::<RegisteredVerifier>(8)?,
        source::bytes::<OuterBackendAdmission<'static>>(8)?,
        source::bytes::<OwnedOuterScope<'static, 'static>>(8)?,
        source::bytes::<Report>(8)?, source::bytes::<ProvingRequest>(8)?,
        source::bytes::<BatchProof<Config>>(8)?, source::bytes::<Result<PairedNode<'static>>>(8)?,
        source::bytes::<core::result::Result<(BatchProof<Config>, Report), ExecutionError>>(8)?,
        source::bytes::<Vec<[Val; 4]>>(8)?, source::bytes::<Vec<Val>>(8)?,
        source::bytes::<Requirements>(8)?, source::bytes::<[u128; 4]>(8)?,
        usize::try_from(crate::execution::workflow_resources::owned_outer_forwarding_host_bytes()
            .map_err(|_| PairedFailure::Resource)?).map_err(|_| PairedFailure::Overflow)?,
        caller_bytes()?,
    ].into_iter().try_fold(64 << 10, source::add)?;
    source::combine(&[
        source::requirement(Category::Report,
            usize::try_from(crate::execution::outer_report::required_host_bytes()
                .map_err(|_| PairedFailure::Resource)?).map_err(|_| PairedFailure::Overflow)?)?,
        source::requirement(Category::PhaseScratch, frames)?,
    ])
}

pub(crate) fn produce_owned_outer<'request>(
    compiled: &PairedCompiled<'request>, cache: &OuterProofCache,
    scope: &mut OwnedOuterScope<'_, '_>, registered: RegisteredProgram,
    backend: &OuterBackendAdmission<'_>,
) -> Result<PairedNode<'request>> {
    if cache.policy() != ProofCachePolicy::FreshOnly
        || scope.execution().context().policy() != Policy::GpuRequired
        || !scope.matches_program(&compiled.node.program)
        || !scope.matches_backend(backend)
        || !Arc::ptr_eq(backend.program(), &compiled.node.program)
        || !core::ptr::eq(registered.air().program(), compiled.node.program.as_ref())
        || !core::ptr::eq(backend.public(), compiled.node.public.as_slice())
        || !core::ptr::eq(backend.witness(), compiled.node.witness.as_slice()) {
        return Err(PairedFailure::Authority);
    }
    compiled.source.check_compiled(&compiled.node)?;
    let actual = source::registered_shape(compiled.node.program.height())?;
    if registered.preprocessing_cap().roots().len() != actual.preprocessing_cap_roots {
        return Err(PairedFailure::SourceDrift);
    }
    let started = Instant::now();
    let mut cap = Vec::new();
    cap.try_reserve_exact(actual.preprocessing_cap_roots).map_err(|_| PairedFailure::Capacity)?;
    if cap.capacity() > actual.preprocessing_cap_roots { return Err(PairedFailure::Capacity); }
    cap.extend_from_slice(registered.preprocessing_cap().roots());
    let key = NodeKey { spec: compiled.node.spec.clone(), height: compiled.node.program.height(),
        cap, verifier: Arc::new(registered.verifier()) };
    let (requirements, _) = compiled.source.output_requirements()?;
    let proof_ceiling = usize::try_from(requirements.get(Category::RecursiveProof).host)
        .map_err(|_| PairedFailure::Overflow)?;
    let key_ceiling = usize::try_from(requirements.get(Category::RegisteredMetadata).host)
        .map_err(|_| PairedFailure::Overflow)?;
    let key_bytes = key.retained_reservation_bytes().map_err(|_| PairedFailure::Capacity)?;
    if source::add(key_bytes, size_of::<PairedNode<'_>>())? > key_ceiling {
        return Err(PairedFailure::Capacity);
    }
    cache.proof_attempt();
    let (proof, proving_report) = registered.into_prove_outer_with_request_and_report(backend,
        ProvingRequest { policy: Policy::GpuRequired, emit_report: false })
        .map_err(|_| PairedFailure::Proof)?;
    scope.record_report(&proving_report, CoverageScope::RegisteredProof)
        .map_err(|_| PairedFailure::Proof)?;
    let (setup_elapsed_ns, proving_ns) = scope.timings().map_err(|_| PairedFailure::Proof)?;
    if proving_ns != proving_report.elapsed_ns { return Err(PairedFailure::Authority); }
    drop(proving_report);
    let mut public = Vec::new();
    public.try_reserve_exact(source::PUBLICS).map_err(|_| PairedFailure::Capacity)?;
    if public.capacity() > source::PUBLICS { return Err(PairedFailure::Capacity); }
    public.extend_from_slice(&compiled.node.public);
    let proof = NodeProof { public, proof };
    // Original output and verifier claims precede registration and proof.
    // Inspect the actual nested output capacities before numerical verification.
    let proof_bytes = proof.retained_backing_bytes(proof_ceiling).map_err(|_| PairedFailure::Capacity)?;
    if source::add(proof_bytes, size_of::<PairedNode<'_>>())? > proof_ceiling
        || !compiled.span.agrees(&key.spec) || key.height > compiled.source.maximum_padded_rows {
        return Err(PairedFailure::Capacity);
    }
    let verification = Instant::now();
    key.verifier.verify(&proof.proof, &proof.public).map_err(|_| PairedFailure::Verification)?;
    let cpu_verification_ns = verification.elapsed().as_nanos();
    cache.fresh_proof();
    let mut report = compiled.report;
    report.setup_ns = setup_elapsed_ns;
    report.proving_ns = proving_ns;
    report.cpu_verification_ns = cpu_verification_ns;
    report.registered_phase_ns = setup_elapsed_ns.checked_add(started.elapsed().as_nanos())
        .ok_or(PairedFailure::Overflow)?;
    Ok(PairedNode { key, proof, request: compiled.request, context: compiled.context.clone(),
        endpoints: compiled.endpoints.clone(), span: compiled.span, source: compiled.source, report })
}
