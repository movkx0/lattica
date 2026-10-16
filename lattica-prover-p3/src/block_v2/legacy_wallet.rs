//! Owned GPU proving for the existing quadratic wallet proof format.
//! Selection is explicit research initialization, shared with the owned PCS;
//! serialization and the legacy CPU verifier remain unchanged.
use crate::block_v2::{
    gpu_hash::{
        self,
        device::{DeviceSession, WalletTrace},
    },
    gpu_quotient_prover::uni,
    leaf,
    machine::symbolic,
    resident_pcs,
};
use crate::config::{Challenge, Val};
use crate::proving::{Backend, Capabilities, Error, Profile, Report, Request, Run, Stage};
use p3_air::{Air, DebugConstraintBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::StarkGenericConfig;

pub(crate) fn is_selected() -> bool {
    leaf::gpu_wallet_selected()
}

pub(super) fn capabilities() -> Capabilities {
    // Periodic columns require preprocessing; these wallet AIRs have no lookup argument.
    let mut capabilities = Capabilities::cpu(Profile::LegacyQuadratic, true, false);
    for stage in Stage::ARITHMETIC
        .into_iter()
        .filter(|s| *s != Stage::Lookup)
    {
        capabilities.set(stage, Backend::OpenCl);
    }
    #[cfg(debug_assertions)]
    let capabilities = capabilities.with_constraint_audit();
    capabilities
}

fn gpu_admission() -> Result<DeviceSession, Error> {
    let context =
        super::wallet_worker::retain_gpu_context().map_err(|_| Error::ComponentRejected)?;
    super::wallet_worker::require_gpu_resources().map_err(|_| Error::ComponentRejected)?;
    Ok(context)
}

fn admission(request: Request) -> Result<DeviceSession, Error> {
    super::wallet_worker::admit_gpu(request).map_err(|_| Error::ComponentRejected)
}

// Native startup validates and pins the wallet-owned assignment only after all
// GPU configuration succeeds. No private witness is admitted by this predicate.
pub(super) fn startup_admitted() -> bool {
    Request::from_env()
        .and_then(|request| request.admit(&capabilities()))
        .and_then(|_| gpu_admission())
        .is_ok()
}

pub(crate) fn abi_admission() -> Result<DeviceSession, Error> {
    Request::from_env().and_then(|request| {
        request.admit(&capabilities())?;
        admission(request)
    })
}

fn wallet_run<A: Air<symbolic::Builder> + super::machine::verifier::periodic::Source>(
    entry: &'static str,
    request: Request,
    air: &A,
    rows: usize,
) -> Result<(Run, gpu_hash::device::ProofCapacity, uni::Prepared), Error> {
    // Keep failed resource requests in the execution report; ABI preflight uses
    // the same checks before parsing witness bytes, without creating a run.
    let run = Run::new(entry, request, capabilities())?;
    let context = admission(request)?;
    let prepared = uni::Prepared::new(
        air, rows, gpu_hash::device::Extension::Quadratic, resident_pcs::host_output_budget(),
    ).map_err(component)?;
    let capacity = context.reserve_wallet_proof_capacity(prepared.minimum().map_err(component)?)
        .map_err(|_| Error::ComponentRejected)?;
    Ok((run, capacity, prepared))
}

pub(crate) struct WalletProof {
    pub(crate) proof: Vec<u8>,
    pub(crate) public: Vec<Val>,
    pub(crate) report: Report,
}

fn component(_error: String) -> Error {
    // Explicit fixture diagnostics only; never log component internals in a
    // non-test library handling private wallet requests.
    #[cfg(test)]
    if std::env::var("LATTICA_TEST_GPU_ERROR_DETAIL").as_deref() == Ok("1") {
        eprintln!("legacy_gpu_fixture_component_rejected reason={_error}");
    }
    Error::ComponentRejected
}

fn prove<A>(
    entry: &'static str,
    request: Request,
    air: &A,
    rows: usize,
    public_count: usize,
    generate: impl FnOnce(&DeviceSession, &Run, usize) -> Result<WalletTrace, String>,
) -> Result<WalletProof, Error>
where
    A: Air<symbolic::Builder>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>
        + super::machine::verifier::periodic::Source,
{
    let (run, _context, prepared) = wallet_run(entry, request, air, rows)?;
    let config = prepared.config::<Challenge>().map_err(component)?;
    let host_allowance = config.pcs().host_output_budget();
    let session = config.pcs().quotient_session().map_err(component)?;
    let frame = generate(&session, &run, host_allowance).map_err(component)?;
    let before = session.stats();
    let (trace, public) = frame
        .into_proving_parts(&session, host_allowance)
        .map_err(component)?;
    let readback = session.stats().downloaded_bytes - before.downloaded_bytes;
    if public.len() != public_count || readback != (public_count * 8) as u64 {
        return Err(Error::ComponentRejected);
    }
    let public: Vec<_> = public.into_iter().map(Val::from_u64).collect();
    eprintln!("legacy_gpu_owned_handoff entry={entry} trace_readback_bytes=0 public_readback_bytes={readback}");
    let proof = uni::prove(&config, air, trace, &public, &run, prepared).map_err(component)?;
    let bytes = run
        .measure(Stage::Serialization, Backend::Cpu, || {
            // Legacy Rust encoding has no additional protocol byte cap here.
            // Retained proof/public storage and output share the operation cap.
            super::wallet_output::serialize(
                &proof,
                &[&public],
                &[],
                host_allowance,
                host_allowance,
            )
        })?
        .map_err(|_| Error::ComponentRejected)?;
    Ok(WalletProof {
        proof: bytes,
        public,
        report: run.finish(true)?,
    })
}

pub(crate) fn prove_joinsplit_with_public(
    witness: &crate::joinsplit_air::Witness,
    request: Request,
) -> Result<WalletProof, Error> {
    prove_joinsplit_entry(witness, request, "legacy_joinsplit_gpu")
}

pub(crate) fn prove_joinsplit_entry(
    witness: &crate::joinsplit_air::Witness,
    request: Request,
    entry: &'static str,
) -> Result<WalletProof, Error> {
    // Preserve legacy issuance semantics: the public mint amount is constrained
    // by JoinSplitAir, while authorization remains the caller's responsibility.
    prove(
        entry,
        request,
        &crate::joinsplit_air::JoinSplitAir,
        crate::joinsplit_air::HEIGHT,
        crate::joinsplit_air::N_PUBLIC,
        |session, run, host_allowance| session.joinsplit_witness(witness, host_allowance, run),
    )
}

pub(crate) fn prove_htlc_with_public(
    witness: &crate::htlc_air::Witness,
    request: Request,
) -> Result<WalletProof, Error> {
    prove_htlc_entry(witness, request, "legacy_htlc_gpu")
}

pub(crate) fn prove_htlc_entry(
    witness: &crate::htlc_air::Witness,
    request: Request,
    entry: &'static str,
) -> Result<WalletProof, Error> {
    prove(
        entry,
        request,
        &crate::htlc_air::HtlcAir,
        crate::htlc_air::HEIGHT,
        crate::htlc_air::N_PUBLIC,
        |session, run, host_allowance| session.htlc_witness(witness, host_allowance, run),
    )
}

/// CPU verification is separate from the completed GPU proving-stage report.
/// Explicit verifier inputs may differ from the device-derived statement for
/// binding tests; no host public-value or trace construction is needed.
pub(crate) fn verify_on_cpu(
    output: WalletProof,
    public: Option<&[Val]>,
    verify: fn(&[u8], &[Val]) -> bool,
) -> Result<(), String> {
    let accepted = verify(&output.proof, public.unwrap_or(&output.public));
    eprintln!(
        "legacy_wallet_cpu_verification entry={} accepted={accepted}",
        output.report.entry_point
    );
    if accepted {
        Ok(())
    } else {
        Err("independent CPU wallet verification rejected".to_owned())
    }
}

pub(crate) fn prove_joinsplit(
    witness: &crate::joinsplit_air::Witness,
    request: Request,
) -> Result<(Vec<u8>, Report), Error> {
    let output = prove_joinsplit_with_public(witness, request)?;
    Ok((output.proof, output.report))
}

pub(crate) fn prove_htlc(
    witness: &crate::htlc_air::Witness,
    request: Request,
) -> Result<(Vec<u8>, Report), Error> {
    let output = prove_htlc_with_public(witness, request)?;
    Ok((output.proof, output.report))
}

#[cfg(test)]
mod tests;
mod tree;
pub(crate) use tree::{prove_joinsplit_tree, tree_abi_admission};

pub(crate) fn prove_joinsplit_batch_with_public(
    witnesses: &[crate::joinsplit_air::Witness],
    request: Request,
) -> Result<WalletProof, Error> {
    if witnesses.len() > crate::batch_common::MAX_BATCH_TILES {
        return Err(Error::ComponentRejected);
    }
    prove(
        "legacy_joinsplit_batch_gpu",
        request,
        &crate::batch_joinsplit_air::JoinSplitBatchAir,
        witnesses.len().max(1).next_power_of_two()
            * crate::batch_joinsplit_air::device_batch_geometry().height,
        4,
        |session, run, host_allowance| {
            session.joinsplit_batch_witness(witnesses, host_allowance, run)
        },
    )
}

pub(crate) fn prove_htlc_batch_with_public(
    witnesses: &[crate::htlc_air::Witness],
    request: Request,
) -> Result<WalletProof, Error> {
    if witnesses.len() > crate::batch_common::MAX_BATCH_TILES {
        return Err(Error::ComponentRejected);
    }
    prove(
        "legacy_htlc_batch_gpu",
        request,
        &crate::batch_htlc_air::HtlcBatchAir,
        witnesses.len().max(1).next_power_of_two()
            * crate::batch_htlc_air::device_batch_geometry().height,
        4,
        |session, run, host_allowance| {
            session.htlc_batch_witness(witnesses, host_allowance, run)
        },
    )
}
