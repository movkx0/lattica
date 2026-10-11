//! Real hiding cubic-extension JoinSplit proofs for the feasibility gate only.
//! Not a recursive leaf wrapper, wallet wire upgrade, or network parsing boundary.
//! Context is appended to public inputs and absorbed by P3's Fiat-Shamir transcript.

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify, Proof};

use super::commitment::Context;
use super::profile::{self, Config};
use crate::config::Val;
use crate::joinsplit_air::{self as js, JoinSplitAir, Witness};

const MAGIC: &[u8; 8] = b"LBV2JS01";
const HEADER_BYTES: usize = 8 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafError {
    WrongProfile,
    WrongContext,
    WrongPublicValueCount,
    IssuanceNotSupported,
    SizeLimit,
    InvalidEncoding,
    InvalidShape,
    VerificationFailed,
    ProvingPolicy,
    GpuFailure,
}

/// v1's spend constraints, plus mint=0. Issuance requires its own typed leaf and
/// node policy; it must not sneak through a JoinSplit leaf. No v1 AIR is modified.
pub(crate) struct ContextJoinSplitAir;

impl BaseAir<Val> for ContextJoinSplitAir {
    fn width(&self) -> usize {
        js::WIDTH
    }
    fn num_public_values(&self) -> usize {
        js::N_PUBLIC + 16
    }
    fn num_periodic_columns(&self) -> usize {
        js::N_PERIODIC
    }
    fn periodic_columns(&self) -> Vec<Vec<Val>> {
        js::periodic()
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for ContextJoinSplitAir {
    fn eval(&self, builder: &mut AB) {
        JoinSplitAir.eval(builder);
        let mint: AB::Expr = builder.public_values()[js::PI_MINT].into();
        builder.assert_zero(mint);
    }
}

fn public_values(context: &Context, statement: &[Val]) -> Result<Vec<Val>, LeafError> {
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile);
    }
    if statement.len() != js::N_PUBLIC {
        return Err(LeafError::WrongPublicValueCount);
    }
    if statement[js::PI_MINT] != Val::ZERO {
        return Err(LeafError::IssuanceNotSupported);
    }
    let mut pis = statement.to_vec();
    // Match commitment::Context's injective u32-limb encoding without reduction.
    pis.extend(context.to_fields().map(Val::from_u64));
    Ok(pis)
}

pub fn security() -> Result<profile::AirSecurity, profile::SecurityError> {
    profile::base_air_security(&ContextJoinSplitAir, js::HEIGHT)
}

/// Local proving probe. As in the existing witness builder, inconsistent local
/// witnesses can panic; do not expose this function as an untrusted RPC endpoint.
pub fn prove_joinsplit_research(
    witness: &Witness,
    context: &Context,
) -> Result<Vec<u8>, LeafError> {
    prove_joinsplit_with_request(
        witness,
        context,
        crate::proving::Request::from_env().map_err(|_| LeafError::ProvingPolicy)?,
    )
}

pub fn prove_joinsplit_with_request(
    witness: &Witness,
    context: &Context,
    request: crate::proving::Request,
) -> Result<Vec<u8>, LeafError> {
    #[cfg(feature = "gpu")]
    if gpu_wallet_selected() {
        return prove_joinsplit_on_gpu(witness, context, request);
    }
    use crate::proving::{Backend, Run, Stage};
    let capabilities = profile::proving_capabilities(false);
    let backend = if capabilities
        .stages()
        .iter()
        .all(|s| s.backend == Backend::Cpu)
    {
        Backend::Cpu
    } else {
        Backend::Mixed
    };
    let run = Run::new("block_v2_joinsplit", request, capabilities)
        .map_err(|_| LeafError::ProvingPolicy)?;
    if witness.mint != 0 {
        return Err(LeafError::IssuanceNotSupported);
    }
    let pis = run
        .measure(Stage::PublicValues, Backend::Cpu, || {
            public_values(context, &js::public_values(witness))
        })
        .map_err(|_| LeafError::ProvingPolicy)??;
    let trace = run
        .measure(Stage::WitnessTrace, Backend::Cpu, || {
            js::build_trace(witness)
        })
        .map_err(|_| LeafError::ProvingPolicy)?;
    finish_joinsplit_trace(context, pis, trace, run, backend)
}

fn finish_joinsplit_trace(
    context: &Context,
    pis: Vec<Val>,
    trace: p3_matrix::dense::RowMajorMatrix<Val>,
    run: crate::proving::Run,
    backend: crate::proving::Backend,
) -> Result<Vec<u8>, LeafError> {
    use crate::proving::Stage;
    let proof = run
        .measure(Stage::UpstreamProver, backend, || {
            prove(&profile::make_config(), &ContextJoinSplitAir, trace, &pis)
        })
        .map_err(|_| LeafError::ProvingPolicy)?;
    let bytes = encode_proof(context, &proof)?;
    run.finish(true).map_err(|_| LeafError::ProvingPolicy)?;
    Ok(bytes)
}

fn encode_proof(context: &Context, proof: &Proof<Config>) -> Result<Vec<u8>, LeafError> {
    let payload = postcard::to_allocvec(&proof).map_err(|_| LeafError::InvalidEncoding)?;
    if payload.len() > profile::MAX_PROOF_BYTES - HEADER_BYTES {
        return Err(LeafError::SizeLimit);
    }
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&context.profile_id);
    bytes.extend_from_slice(&context.chain_id);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Opt-in device witness/public-value arithmetic with an explicit readback into
/// the existing single-AIR prover. Initialize the bounded OpenCL engine first.
/// `host_trace_bytes` reserves both raw readback and decoded field buffers;
/// the CPU prover still has its separate memory requirement. GPU-required whole proofs still reject
/// before work because the downstream proving stages are not yet GPU-owned.
#[cfg(feature = "gpu")]
pub fn prove_joinsplit_with_gpu_witness(
    witness: &Witness,
    context: &Context,
    request: crate::proving::Request,
    host_trace_bytes: usize,
) -> Result<Vec<u8>, LeafError> {
    use crate::proving::{Backend, Run, Stage};
    let mut capabilities = profile::proving_capabilities(false);
    capabilities.set(Stage::PublicValues, Backend::OpenCl);
    capabilities.set(Stage::WitnessTrace, Backend::OpenCl);
    let run = Run::new("block_v2_joinsplit_gpu_witness", request, capabilities)
        .map_err(|_| LeafError::ProvingPolicy)?;
    if witness.mint != 0 {
        return Err(LeafError::IssuanceNotSupported);
    }
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile);
    }
    // Pool assignments authorize public recursive jobs, not private wallet
    // inputs or this CPU readback/proving allocation. Keep that boundary explicit.
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some() || super::wallet_worker::is_assigned()
    {
        return Err(LeafError::GpuFailure);
    }
    let required = 2 * (js::HEIGHT * js::WIDTH + js::N_PUBLIC) * core::mem::size_of::<u64>();
    if host_trace_bytes < required {
        return Err(LeafError::GpuFailure);
    }
    let session =
        super::gpu_hash::device::DeviceSession::new().map_err(|_| LeafError::GpuFailure)?;
    let frame = session
        .joinsplit_witness(witness, host_trace_bytes, &run)
        .map_err(|_| LeafError::GpuFailure)?;
    let (trace, statement) = frame
        .readback(&session, host_trace_bytes)
        .map_err(|_| LeafError::GpuFailure)?;
    drop(frame);
    drop(session);
    // These are canonical byte decoding and the existing injective context
    // encoding; all wallet field arithmetic above was executed on the device.
    let trace = p3_matrix::dense::RowMajorMatrix::new(
        trace.into_iter().map(Val::from_u64).collect(),
        js::WIDTH,
    );
    let statement: Vec<_> = statement.into_iter().map(Val::from_u64).collect();
    let pis = public_values(context, &statement)?;
    eprintln!("wallet_gpu_trace_bridge trace_readback_bytes={} public_readback_bytes={} downstream_prover=host", js::HEIGHT * js::WIDTH * 8, js::N_PUBLIC * 8);
    finish_joinsplit_trace(context, pis, trace, run, Backend::Mixed)
}

#[cfg(feature = "gpu")]
pub(crate) fn gpu_wallet_selected() -> bool {
    use super::{gpu_hash, quotient_pcs};
    gpu_hash::is_enabled()
        && quotient_pcs::gpu_pcs_device_only_enabled()
        && quotient_pcs::gpu_quotient_resident_enabled()
        && quotient_pcs::gpu_randomness_enabled()
        && quotient_pcs::gpu_transcript_enabled()
}

#[cfg(feature = "gpu")]
pub(crate) fn gpu_wallet_run(
    entry_point: &'static str,
    request: crate::proving::Request,
) -> Result<crate::proving::Run, LeafError> {
    use super::resident_pcs;
    use crate::proving::{Backend, Capabilities, Profile, Run, Stage};
    if !gpu_wallet_selected() {
        return Err(LeafError::GpuFailure);
    }
    // Selection persists after shutdown. Reject a missing engine before the
    // infallible profile constructor can attempt to create a resident PCS.
    super::gpu_hash::require_resident_backend().map_err(|_| LeafError::GpuFailure)?;
    // The wallet AIRs have periodic columns but no lookup argument. Every
    // actual arithmetic stage still requires its own completed device receipt.
    let mut capabilities = Capabilities::cpu(Profile::BlockV2Cubic, true, false);
    for stage in Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::Lookup)
    {
        capabilities.set(stage, Backend::OpenCl);
    }
    #[cfg(debug_assertions)]
    let capabilities = capabilities.with_constraint_audit();
    let run = Run::new(entry_point, request, capabilities).map_err(|_| LeafError::ProvingPolicy)?;
    // Existing pool assignments are for public recursive work. Private wallet
    // transport and whole-proof resource admission require their own contract.
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some()
        || resident_pcs::host_output_budget() < super::machine::symbolic::HOST_BYTES as usize
    {
        return Err(LeafError::GpuFailure);
    }
    super::wallet_worker::admit(request).map_err(|_| LeafError::GpuFailure)?;
    Ok(run)
}

/// Opt-in owned OpenCL proving of the existing cubic wallet leaf. Initialize
/// the complete owned PCS/randomness/transcript path and its memory limits
/// first. The private trace stays on GPU; public/proof output is serialized on
/// the host. Debug builds retain a reported CPU constraint audit and therefore
/// reject GPU-required requests before private work.
#[cfg(feature = "gpu")]
pub fn prove_joinsplit_on_gpu(
    witness: &Witness,
    context: &Context,
    request: crate::proving::Request,
) -> Result<Vec<u8>, LeafError> {
    use super::resident_pcs;
    use p3_uni_stark::StarkGenericConfig;
    let run = gpu_wallet_run("block_v2_joinsplit_gpu", request)?;
    if witness.mint != 0 {
        return Err(LeafError::IssuanceNotSupported);
    }
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile);
    }
    let config = profile::make_proving_config();
    let session = config
        .pcs()
        .quotient_session()
        .map_err(|_| LeafError::GpuFailure)?;
    let frame = session
        .joinsplit_witness(witness, resident_pcs::host_output_budget(), &run)
        .map_err(|_| LeafError::GpuFailure)?;
    let before = session.stats();
    let (trace, statement) = frame
        .into_proving_parts(&session, resident_pcs::host_output_budget())
        .map_err(|_| LeafError::GpuFailure)?;
    let readback = session.stats().downloaded_bytes - before.downloaded_bytes;
    if readback != (js::N_PUBLIC * 8) as u64 {
        return Err(LeafError::GpuFailure);
    }
    let statement: Vec<_> = statement.into_iter().map(Val::from_u64).collect();
    let pis = public_values(context, &statement)?;
    eprintln!("wallet_gpu_owned_handoff trace_readback_bytes=0 public_readback_bytes={readback}");
    let proof =
        super::gpu_quotient_prover::uni::prove(&config, &ContextJoinSplitAir, trace, &pis, &run)
            .map_err(|_| LeafError::GpuFailure)?;
    let bytes = encode_proof(context, &proof)?;
    run.finish(true).map_err(|_| LeafError::ProvingPolicy)?;
    Ok(bytes)
}

/// Standalone *transaction* verification for local experiments, not a block
/// verifier. Exact profile, context, trace height, canonical encoding and byte cap;
/// never falls back to v1. Production needs a bounded hostile-input decoder audit.
pub fn verify_joinsplit_research(
    bytes: &[u8],
    context: &Context,
    statement: &[Val],
) -> Result<(), LeafError> {
    let pis = public_values(context, statement)?;
    if bytes.len() > profile::MAX_PROOF_BYTES {
        return Err(LeafError::SizeLimit);
    }
    if bytes.len() <= HEADER_BYTES || &bytes[..8] != MAGIC {
        return Err(LeafError::InvalidEncoding);
    }
    if bytes[8..40] != context.profile_id {
        return Err(LeafError::WrongProfile);
    }
    if bytes[40..72] != context.chain_id {
        return Err(LeafError::WrongContext);
    }
    let payload = &bytes[HEADER_BYTES..];
    let (proof, rest): (Proof<Config>, &[u8]) =
        postcard::take_from_bytes(payload).map_err(|_| LeafError::InvalidEncoding)?;
    if !rest.is_empty()
        || postcard::to_allocvec(&proof).map_err(|_| LeafError::InvalidEncoding)? != payload
    {
        return Err(LeafError::InvalidEncoding);
    }
    if proof.degree_bits != js::HEIGHT.trailing_zeros() as usize + 1
        || proof.opening_proof.1.query_proofs.len() != profile::NUM_QUERIES
        || proof.commitments.random.is_none()
        || proof.opening_proof.1.query_proofs.iter().any(|query| {
            query
                .commit_phase_openings
                .iter()
                .any(|opening| opening.log_arity != 1)
        })
    {
        return Err(LeafError::InvalidShape);
    }
    verify(&profile::make_config(), &ContextJoinSplitAir, &proof, &pis)
        .map_err(|_| LeafError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> Context {
        Context {
            profile_id: profile::CANDIDATE_PROFILE_ID,
            chain_id: [0x5a; 32],
        }
    }

    #[test]
    fn candidate_leaf_security_and_height_checks() {
        let s = security().unwrap();
        eprintln!("candidate JoinSplit security: {s:?}");
        assert_eq!(s.constraints, 82);
        assert_eq!(s.max_constraint_degree, 8);
        assert_eq!(s.hiding_degree_bits, 13);
        // Conditional leaf allowance only; missing recursive AIRs cannot inherit this bound.
        assert!(
            profile::composition_bits(s.proven_bits, profile::MAX_TREE_PROOF_STATEMENTS).unwrap()
                >= profile::MIN_TREE_SECURITY_BITS
        );
        for height in [0, 3, 1 << 28] {
            assert_eq!(
                profile::base_air_security(&ContextJoinSplitAir, height),
                Err(profile::SecurityError::InvalidHeight)
            );
        }
    }

    #[test]
    fn malformed_inputs_reject_before_verification() {
        let ctx = context();
        let pis = js::public_values(&js::demo_witness());
        assert_eq!(
            verify_joinsplit_research(&[], &ctx, &pis),
            Err(LeafError::InvalidEncoding)
        );
        assert_eq!(
            verify_joinsplit_research(&vec![0; profile::MAX_PROOF_BYTES + 1], &ctx, &pis),
            Err(LeafError::SizeLimit)
        );
        assert_eq!(
            verify_joinsplit_research(&[], &ctx, &pis[..1]),
            Err(LeafError::WrongPublicValueCount)
        );
        let mut wrong = ctx;
        wrong.profile_id[0] ^= 1;
        assert_eq!(
            verify_joinsplit_research(&[], &wrong, &pis),
            Err(LeafError::WrongProfile)
        );
        let mut issuance = js::demo_witness();
        issuance.mint = 1;
        assert_eq!(
            prove_joinsplit_research(&issuance, &ctx),
            Err(LeafError::IssuanceNotSupported)
        );
    }

    #[test]
    fn cubic_hiding_leaf_roundtrip_and_tamper_rejection() {
        let ctx = context();
        let w = js::demo_witness();
        let pis = js::public_values(&w);
        let first = prove_joinsplit_research(&w, &ctx).unwrap();
        let second = prove_joinsplit_research(&w, &ctx).unwrap();
        assert_ne!(first, second, "fresh blinding must change proof bytes");
        assert_eq!(verify_joinsplit_research(&first, &ctx, &pis), Ok(()));
        assert_eq!(verify_joinsplit_research(&second, &ctx, &pis), Ok(()));
        eprintln!(
            "candidate cubic leaf bytes: {}, {}",
            first.len(),
            second.len()
        );
        for i in 0..pis.len() {
            let mut wrong = pis.clone();
            wrong[i] += Val::ONE;
            assert!(
                verify_joinsplit_research(&first, &ctx, &wrong).is_err(),
                "unbound statement field {i}"
            );
        }
        let mut appended = first.clone();
        appended.push(0);
        assert_eq!(
            verify_joinsplit_research(&appended, &ctx, &pis),
            Err(LeafError::InvalidEncoding)
        );
        assert!(verify_joinsplit_research(&first[..first.len() - 1], &ctx, &pis).is_err());

        let mut other_chain = ctx;
        other_chain.chain_id[0] ^= 1;
        let mut relabeled = first.clone();
        relabeled[40..72].copy_from_slice(&other_chain.chain_id);
        assert_eq!(
            verify_joinsplit_research(&relabeled, &other_chain, &pis),
            Err(LeafError::VerificationFailed),
            "context must bind transcript, not just the envelope"
        );

        let mut proof: Proof<Config> = postcard::from_bytes(&first[HEADER_BYTES..]).unwrap();
        proof.degree_bits += 1;
        let mut wrong_height = first[..HEADER_BYTES].to_vec();
        wrong_height.extend(postcard::to_allocvec(&proof).unwrap());
        assert_eq!(
            verify_joinsplit_research(&wrong_height, &ctx, &pis),
            Err(LeafError::InvalidShape)
        );
        // Neither envelope nor cubic payload can be silently interpreted as v1.
        assert!(!js::verify_bytes(&first, &pis));
        assert!(!js::verify_bytes(&first[HEADER_BYTES..], &pis));
        let v1 = js::prove_to_bytes(&w);
        assert_eq!(
            verify_joinsplit_research(&v1, &ctx, &pis),
            Err(LeafError::InvalidEncoding)
        );
        let mut wrapped_v1 = first[..HEADER_BYTES].to_vec();
        wrapped_v1.extend(v1);
        assert!(verify_joinsplit_research(&wrapped_v1, &ctx, &pis).is_err());
    }
}
