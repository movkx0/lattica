//! Closed fixed-source continuation. Every dynamic error is mapped while the
//! original phase/configuration/output owners are still live.
use super::*;
use crate::block_v2::{
    gpu_hash::device::{DeviceSession, Extension, MatrixSpec, RowOrder},
    gpu_quotient_prover::uni,
    native_gpu::TraceContext,
    native_linear_map_proof::{NativeLinearMapProof, LINEAR_MAP_MAX_PUBLIC_VALUES},
    native_gpu::linear_map_preparation::LinearMapDescriptor,
    profile,
};
use crate::config::Val;
use crate::proving::{Policy, Request, Run};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::StarkGenericConfig;
use rand::TryRng;

struct SourcePublic { kind: LinearMapDescriptor, values: [Val; LINEAR_MAP_MAX_PUBLIC_VALUES] }
pub(super) const fn additional_host_bytes() -> usize {
    8 * (size_of::<LinearMapInput<'static>>() + size_of::<SourcePublic>()
        + size_of::<Result<SourcePublic>>() + size_of::<Result<[Val; LINEAR_MAP_MAX_PUBLIC_VALUES]>>()
        + size_of::<Result<OwnedLinearMapProof>>() + size_of::<NativeLinearMapProof>())
}
impl SourcePublic {
    fn values(&self) -> &[Val] { &self.values[..self.kind.public_values()] }
    fn artifact(self, proof: p3_uni_stark::Proof<profile::Config>) -> NativeLinearMapProof {
        NativeLinearMapProof { kind: self.kind, public_values: self.values, proof }
    }
}
fn public_values(kind: LinearMapDescriptor, words: Vec<u64>) -> Result<SourcePublic> {
    if words.len() != kind.public_values() || words.iter().any(|&word| word >= Val::ORDER_U64) {
        return Err(Error::Public);
    }
    let mut values = [Val::ZERO; LINEAR_MAP_MAX_PUBLIC_VALUES];
    for (value, word) in values.iter_mut().zip(words) { *value = Val::from_u64(word); }
    Ok(SourcePublic { kind, values })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linear_map_public_roots_require_exact_width_canonical_words_and_zero_tail() {
        for inputs in [1,3,16] {
            let descriptor = LinearMapDescriptor::new(&vec![[0,3];inputs+1],&vec![[1;256];inputs],&[0;256]).unwrap();
            let width=descriptor.public_values();
            let roots=public_values(descriptor,vec![7;width]).unwrap();
            assert_eq!(roots.values(),vec![Val::from_u64(7);width].as_slice());
            assert!(roots.values[width..].iter().all(|v|*v==Val::ZERO));
            assert!(public_values(descriptor,vec![0;width-1]).is_err());
            assert!(public_values(descriptor,vec![0;width+1]).is_err());
            assert!(public_values(descriptor,vec![Val::ORDER_U64;width]).is_err());
        }
    }
}

pub(super) fn produce(
    phase: &mut NativeLinearMapPhase,
    recorded: PreparedLinearMap<'_>,
    input: LinearMapInput<'_>,
    runtime: &Runtime,
    runtime_owner: &Reservation,
    verifier: &Reservation,
) -> Result<OwnedLinearMapProof> {
    // Capture cleanup identity before any source/claim validation can refuse.
    // This Weak grants no dispatch authority and holds no strong engine lease.
    // Every subsequent failure can therefore retire this exact Runtime epoch
    // without permitting a new attempt or accepting a copied cleanup receipt.
    phase.retirement_binding = Some(runtime.bind_original().map_err(|_| Error::Runtime)?);
    check_ledger(&phase.ledger)?;
    let census = recorded.census();
    let geometry = census.geometry();
    if !phase.attempted
        || census != phase.preparation
        || input.kind() != geometry.kind()
        || input.words.len() != geometry.raw_words()
        || !phase.pcs_owner.belongs_to(recorded.ledger())
    {
        return Err(Error::Geometry);
    }
    check_preparation(census, recorded.reservation(), &phase.ledger)?;
    check_verifier(verifier, &phase.ledger)?;
    phase
        .output
        .as_ref()
        .ok_or(Error::Output)?
        .check(census, &phase.ledger)
        .map_err(|_| Error::Output)?;
    let startup_device = phase
        .tree_profile
        .check_runtime(runtime, runtime_owner, &phase.ledger)?;
    let footprint = phase.pcs.footprint();
    phase.tree_profile.check_plan(footprint)?;
    if phase.trace != NativeLinearMapTraceFootprint::for_plan(census, footprint)? {
        return Err(Error::Admission);
    }
    if only(&phase.wrappers, Category::PhaseScratch, &phase.ledger)?
        != (Bytes {
            host: phase.tree_profile.phase_wrapper_host_bytes()? as u64,
            device: 0,
        })
        || only(&phase.pcs_owner, Category::PhaseScratch, &phase.ledger)?
            != (Bytes {
                host: footprint.operation_host_budget_bytes as u64,
                device: MANAGED_DEVICE
                    .checked_sub(startup_device as u64)
                    .ok_or(Error::Authority)?,
            })
    {
        return Err(Error::Authority);
    }
    let trace_spec = MatrixSpec::new(
        geometry.rows().ilog2(),
        geometry.width(),
        Extension::Base,
        RowOrder::Natural,
        1,
    )
    .map_err(|_| Error::Geometry)?;
    let public_spec = MatrixSpec::new(0, geometry.public_values(), Extension::Base, RowOrder::Natural, 1)
        .map_err(|_| Error::Geometry)?;

    // Retain the original exclusive preparation borrow after consuming its
    // opaque data. Its source owner survives all runtime cleanup in research.
    let (prepared, preparation_owner) = recorded
        .into_prepared(footprint.operation_host_budget_bytes)
        .map_err(|_| Error::Preparation)?;
    let operation_host = prepared
        .operation_host_allowance()
        .map_err(|_| Error::Preparation)?;
    if operation_host != footprint.operation_host_budget_bytes {
        return Err(Error::Preparation);
    }
    let minimum = prepared.minimum().map_err(|_| Error::Preparation)?;
    let owner = DeviceSession::new().map_err(|_| Error::Runtime)?;
    let mut capacity = phase
        .pcs
        .acquire_device(
            census,
            minimum,
            &owner,
            runtime,
            &phase.ledger,
            preparation_owner,
            runtime_owner,
            &phase.pcs_owner,
        )
        .map_err(|_| Error::Admission)?;
    let run = Run::new(
        super::super::linear_map_output::ENTRY_POINT,
        Request {
            policy: Policy::GpuRequired,
            emit_report: false,
        },
        super::super::capabilities(),
    )
    .map_err(|_| Error::Report)?;

    // Capacity checks the exact runtime epoch and makes configuration one-shot
    // before OS entropy is requested. No caller seed, rand TLS or reused RNG
    // enters this source. Partial failure cannot draw again in this phase.
    capacity
        .begin_configuration()
        .map_err(|_| Error::Configuration)?;
    let mut entropy = rand::rngs::SysRng;
    let mut seeds = [[0u8; 32]; 3];
    for seed in &mut seeds {
        entropy.try_fill_bytes(seed).map_err(|_| Error::Entropy)?;
    }
    let construct = || {
        profile::make_gpu_proving_config_from_owned_seeds::<profile::Challenge>(
            operation_host,
            seeds[0],
            seeds[1],
            seeds[2],
        )
    };
    #[cfg(test)]
    let config = {
        // This observes the real, single constructor invocation. It is an
        // allocation-request oracle for the source bound, never admission.
        let (config, requests) = crate::spill_alloc::allocation_requests::measure(construct);
        let bound = census.configuration().required_host_bytes();
        assert!(!requests.overflow);
        assert!(requests.calls > 0);
        assert!(requests.bytes <= bound);
        eprintln!(
            "ringct_owned_config calls={} bytes={} largest={} source_bound={}",
            requests.calls, requests.bytes, requests.largest, bound
        );
        config
    };
    #[cfg(not(test))]
    let config = construct();
    let config = config.map_err(|_| Error::Configuration)?;
    if config.pcs().host_output_budget() != operation_host || config.is_zk() != 1 {
        return Err(Error::Configuration);
    }
    let session = config
        .pcs()
        .quotient_session()
        .map_err(|_| Error::Configuration)?;
    capacity
        .bind_proof_session(&session)
        .map_err(|_| Error::Configuration)?;
    capacity
        .check_session(&session)
        .map_err(|_| Error::Runtime)?;

    // Actual normalized degree/program validation precedes private trace work.
    let normalized = uni::native_linear_map::normalize(&config, geometry, prepared, &run)
        .map_err(|_| Error::Normalization)?;
    capacity
        .check_session(&session)
        .map_err(|_| Error::Runtime)?;
    let context = TraceContext {
        session: &session,
        run: &run,
        host_allowance: operation_host,
        rows: geometry.rows(),
        width: geometry.width(),
        public_count: geometry.public_values(),
    };
    let descriptor = geometry.kind();
    // Fixed public schedule construction and descriptor growth remain charged
    // inside the original preparation claim. No supplied schedule is accepted.
    let spec = crate::block_v2::native_gpu::arithmetic::ArithmeticSpec::linear_map(
        descriptor.kinds(), descriptor.coefficients(), descriptor.constant(),
        descriptor.bits(), descriptor.quotient_bound())
        .map_err(|_| Error::Preparation)?;
    context.admit_arithmetic_raw(&spec).map_err(|_| Error::Preparation)?;
    let generated = context.arithmetic_trace(&spec, input.words)
        .map_err(|_| Error::Trace)?;
    if generated.trace.spec() != trace_spec || generated.public.spec() != public_spec {
        return Err(Error::Trace);
    }
    capacity
        .check_session(&session)
        .map_err(|_| Error::Runtime)?;
    drop(
        session
            .alias_private(&generated.trace)
            .map_err(|_| Error::Trace)?,
    );
    let public_bytes = geometry.public_values() * size_of::<Val>();
    let before = session.stats().downloaded_bytes;
    let words = session
        .read(&generated.public, public_bytes)
        .map_err(|_| Error::Public)?;
    let transferred = session
        .stats()
        .downloaded_bytes
        .checked_sub(before)
        .ok_or(Error::Public)?;
    if transferred != public_bytes as u64 {
        return Err(Error::Public);
    }
    let public_values = public_values(geometry.kind(), words)?;
    drop(generated.public);
    let proof = uni::native_linear_map::prove(
        &config,
        geometry,
        normalized,
        generated.trace,
        public_values.values(),
        &run,
    )
    .map_err(|_| Error::Proof)?;
    capacity
        .check_session(&session)
        .map_err(|_| Error::Runtime)?;
    let report = run.finish(true).map_err(|_| Error::Report)?;

    // The output can leave this function only after every temporary config,
    // proof session and capacity owner has been destroyed. Phase claims stay
    // in phase through the research caller's exact runtime retirement.
    drop(session);
    drop(config);
    drop(capacity);
    drop(owner);
    if !preparation_owner.belongs_to(&phase.ledger) {
        return Err(Error::Authority);
    }
    PendingLinearMapOutput::finish_retaining(&mut phase.output, public_values.artifact(proof), report)
        .map_err(|_| Error::Output)
}
