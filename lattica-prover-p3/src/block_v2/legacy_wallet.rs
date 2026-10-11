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
    profile, resident_pcs,
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

fn gpu_admission() -> Result<(), Error> {
    if !is_selected() {
        return Err(Error::ComponentRejected);
    }
    gpu_hash::require_resident_backend().map_err(|_| Error::ComponentRejected)?;
    // Existing workers admit public recursive tasks, not private wallet input.
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some()
        || resident_pcs::host_output_budget() < symbolic::HOST_BYTES as usize
    {
        return Err(Error::ComponentRejected);
    }
    Ok(())
}

fn admission(request: Request) -> Result<(), Error> {
    gpu_admission()?;
    super::wallet_worker::admit(request).map_err(|_| Error::ComponentRejected)
}

// Native startup validates and pins the wallet-owned assignment only after all
// GPU configuration succeeds. No private witness is admitted by this predicate.
pub(super) fn startup_admitted() -> bool {
    Request::from_env()
        .and_then(|request| request.admit(&capabilities()))
        .and_then(|_| gpu_admission())
        .is_ok()
}

pub(crate) fn abi_admitted() -> bool {
    Request::from_env()
        .and_then(|request| {
            request.admit(&capabilities())?;
            admission(request)
        })
        .is_ok()
}

fn wallet_run(entry: &'static str, request: Request) -> Result<Run, Error> {
    // Keep failed resource requests in the execution report; ABI preflight uses
    // the same checks before parsing witness bytes, without creating a run.
    let run = Run::new(entry, request, capabilities())?;
    admission(request)?;
    Ok(run)
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
    public_count: usize,
    generate: impl FnOnce(&DeviceSession, &Run) -> Result<WalletTrace, String>,
) -> Result<WalletProof, Error>
where
    A: Air<symbolic::Builder> + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let run = wallet_run(entry, request)?;
    let config = profile::make_gpu_proving_config::<Challenge>()?;
    let session = config.pcs().quotient_session().map_err(component)?;
    let frame = generate(&session, &run).map_err(component)?;
    let before = session.stats();
    let (trace, public) = frame
        .into_proving_parts(&session, resident_pcs::host_output_budget())
        .map_err(component)?;
    let readback = session.stats().downloaded_bytes - before.downloaded_bytes;
    if public.len() != public_count || readback != (public_count * 8) as u64 {
        return Err(Error::ComponentRejected);
    }
    let public: Vec<_> = public.into_iter().map(Val::from_u64).collect();
    eprintln!("legacy_gpu_owned_handoff entry={entry} trace_readback_bytes=0 public_readback_bytes={readback}");
    let proof = uni::prove(&config, air, trace, &public, &run).map_err(component)?;
    let bytes = run
        .measure(Stage::Serialization, Backend::Cpu, || {
            postcard::to_allocvec(&proof)
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
    // Preserve legacy issuance semantics: the public mint amount is constrained
    // by JoinSplitAir, while authorization remains the caller's responsibility.
    prove(
        "legacy_joinsplit_gpu",
        request,
        &crate::joinsplit_air::JoinSplitAir,
        crate::joinsplit_air::N_PUBLIC,
        |session, run| session.joinsplit_witness(witness, resident_pcs::host_output_budget(), run),
    )
}

pub(crate) fn prove_htlc_with_public(
    witness: &crate::htlc_air::Witness,
    request: Request,
) -> Result<WalletProof, Error> {
    prove(
        "legacy_htlc_gpu",
        request,
        &crate::htlc_air::HtlcAir,
        crate::htlc_air::N_PUBLIC,
        |session, run| session.htlc_witness(witness, resident_pcs::host_output_budget(), run),
    )
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
pub(crate) use tree::{prove_joinsplit_tree, tree_abi_admitted};

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
        4,
        |session, run| {
            session.joinsplit_batch_witness(witnesses, resident_pcs::host_output_budget(), run)
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
        4,
        |session, run| {
            session.htlc_batch_witness(witnesses, resident_pcs::host_output_budget(), run)
        },
    )
}
