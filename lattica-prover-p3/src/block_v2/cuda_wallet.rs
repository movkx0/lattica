//! Process-local, explicitly assigned CUDA wallet service. Private inputs never
//! enter the public recursive worker protocol. One caller owns admission from
//! input decoding through output export; nested wrappers on that thread share it.
use super::{
    commitment::Context,
    leaf::{LeafError, ProvedLeaf},
    profile, typed_leaf, wallet_worker,
};
use crate::{
    cuda_compute::{wallet, Runtime, StarkField},
    proving::{Error, Profile, Report, Request},
};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{Arc, Mutex},
    thread::ThreadId,
};
mod batch;
mod tree;
pub(crate) use batch::{batch_abi_admission, prove_htlc_batch_with_public, prove_joinsplit_batch_with_public};
pub(crate) use tree::{prove_joinsplit_tree, tree_abi_admission};

enum State {
    Unselected,
    Starting,
    Ready(Arc<Session>),
    Retired,
    Failed,
}
static STATE: Mutex<State> = Mutex::new(State::Unselected);

struct Engines {
    prover: Arc<wallet::WalletProver>,
    batch: Option<wallet::BatchProver>,
    joinsplit: wallet::JoinSplitProver,
    htlc: wallet::HtlcProver,
    context_joinsplit: wallet::ContextJoinSplitProver,
    context_htlc: wallet::ContextHtlcProver,
    issuance: wallet::IssuanceProver,
}
struct Session {
    runtime: Runtime,
    engine: Mutex<Engines>,
    owner: Mutex<Owner>,
    host_bytes: usize,
}

#[derive(Default)]
struct Owner {
    thread: Option<ThreadId>,
    depth: usize,
}
impl Owner {
    fn acquire(&mut self, thread: ThreadId) -> Result<(), String> {
        if self.thread.is_some_and(|owner| owner != thread) {
            return Err("CUDA wallet already has an admitted caller".into());
        }
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or("CUDA wallet admission depth overflow")?;
        self.thread = Some(thread);
        Ok(())
    }
    fn release(&mut self, thread: ThreadId) {
        assert_eq!(self.thread, Some(thread));
        self.depth = self
            .depth
            .checked_sub(1)
            .expect("CUDA wallet admission underflow");
        if self.depth == 0 {
            self.thread = None;
        }
    }
}

#[must_use = "retain admission through private decoding and output export"]
pub(crate) struct Admission {
    session: Arc<Session>,
    // Nested admission belongs to one OS thread, including during unwinding.
    _thread: PhantomData<Rc<()>>,
}
impl Admission {
    pub(crate) fn host_output_bytes(&self) -> usize {
        self.session.host_bytes
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.session
            .owner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(std::thread::current().id());
    }
}

pub(crate) fn is_selected() -> bool {
    // Also route forbidden public-worker wallet calls into admission rejection,
    // even if a caller changes policy to compatible before native startup.
    std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some()
        || wallet_worker::is_assigned()
        || STATE
            .lock()
            .map_or(true, |state| !matches!(*state, State::Unselected))
}

pub(crate) fn has_context() -> bool {
    STATE
        .lock()
        .map_or(true, |state| matches!(*state, State::Ready(_)))
}

pub(crate) fn capabilities(profile: Profile) -> crate::proving::Capabilities {
    wallet::capabilities(profile)
}

pub(crate) fn initialize() -> Result<(), String> {
    // Preflight is resource metadata only. A public worker assignment cannot
    // authorize this path, even when both assignment variables are present.
    let prepared = wallet_worker::prepare()?;
    let settings = prepared.cuda_settings()?;
    Request::from_env()
        .and_then(|r| r.admit(&capabilities(Profile::LegacyQuadratic)))
        .map_err(|e| e.to_string())?;
    if cfg!(debug_assertions) {
        return Err("CUDA wallet service requires a release build".into());
    }
    {
        let mut state = STATE.lock().map_err(|_| "CUDA wallet lifecycle poisoned")?;
        match &*state {
            State::Ready(_) => {
                return wallet_worker::admit(Request::from_env().map_err(|e| e.to_string())?)
            }
            State::Unselected => *state = State::Starting,
            _ => {
                return Err(
                    "CUDA wallet startup requires a fresh process after retirement or failure"
                        .into(),
                )
            }
        }
    }
    // Allocator ceilings are irreversible. Pin failure even if a constructor
    // panics; a caller must dispose of the process, never downgrade to CPU.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prepared.initialize_runtime()?;
        let session = Session::new(settings)?;
        if let Err(error) = wallet_worker::finish(prepared) {
            session.retire()?;
            return Err(error);
        }
        Ok(Arc::new(session))
    }))
    .unwrap_or_else(|_| Err("CUDA wallet startup panicked".into()));
    let mut state = STATE.lock().map_err(|_| "CUDA wallet lifecycle poisoned")?;
    match result {
        Ok(session) => {
            *state = State::Ready(session);
            Ok(())
        }
        Err(error) => {
            *state = State::Failed;
            Err(error)
        }
    }
}

impl Session {
    fn new(settings: wallet_worker::CudaSettings) -> Result<Self, String> {
        let runtime = Runtime::new(&settings.uuid, settings.limits)?;
        let built = (|| {
            // All five AIRs share the same modules and random-stream engine.
            // Only public code/tables persist between private proof attempts.
            let prover = wallet::WalletProver::new(&runtime)?;
            Ok(Engines {
                prover: prover.clone(),
                batch: None,
                joinsplit: prover.prepare_joinsplit(settings.host_bytes)?,
                htlc: prover.prepare_htlc(settings.host_bytes)?,
                context_joinsplit: prover.prepare_context_joinsplit(settings.host_bytes)?,
                context_htlc: prover.prepare_context_htlc(settings.host_bytes)?,
                issuance: prover.prepare_issuance(settings.host_bytes)?,
            })
        })();
        match built {
            Ok(engine) => Ok(Self {
                runtime,
                engine: Mutex::new(engine),
                owner: Mutex::new(Owner::default()),
                host_bytes: settings.host_bytes,
            }),
            Err(error) => {
                runtime.retire()?;
                Err(error)
            }
        }
    }
    fn retire(self) -> Result<(), String> {
        drop(self.engine.into_inner().unwrap_or_else(|p| p.into_inner()));
        let snapshot = self.runtime.retire()?;
        eprintln!(
            "bounded_cuda_wallet_retired {}",
            serde_json::to_string(&snapshot).map_err(|e| e.to_string())?
        );
        Ok(())
    }
}

pub(crate) fn admit(request: Request) -> Result<Admission, Error> {
    request.admit(&capabilities(Profile::LegacyQuadratic))?;
    wallet_worker::admit(request).map_err(component)?;
    let state = STATE.lock().map_err(|_| Error::ComponentRejected)?;
    let State::Ready(session) = &*state else {
        return Err(Error::ComponentRejected);
    };
    session
        .owner
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?
        .acquire(std::thread::current().id())
        .map_err(component)?;
    Ok(Admission {
        session: session.clone(),
        _thread: PhantomData,
    })
}

pub(crate) fn abi_admission() -> Result<Admission, Error> {
    admit(Request::from_env()?)
}

pub(crate) fn drain() -> Result<(), String> {
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some() {
        return Err("CUDA private lifecycle cannot control a public worker".into());
    }
    let state = STATE.lock().map_err(|_| "CUDA wallet lifecycle poisoned")?;
    let State::Ready(session) = &*state else {
        return Err("CUDA wallet is not running".into());
    };
    // Do not interfere with a proof's reporting/submission scope.
    if Arc::strong_count(session) != 1 {
        return Err("CUDA wallet still has admitted callers".into());
    }
    session.runtime.finish()
}

pub(crate) fn shutdown() -> Result<(), String> {
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some() {
        return Err("CUDA private lifecycle cannot control a public worker".into());
    }
    let mut state = STATE.lock().map_err(|_| "CUDA wallet lifecycle poisoned")?;
    match &*state {
        State::Retired => return Ok(()),
        State::Ready(session) if Arc::strong_count(session) == 1 => (),
        _ => return Err("CUDA wallet is unavailable or still has admitted callers".into()),
    }
    let State::Ready(session) = std::mem::replace(&mut *state, State::Failed) else {
        unreachable!()
    };
    let session = Arc::try_unwrap(session).map_err(|_| "CUDA wallet retained admission")?;
    session.retire()?;
    *state = State::Retired;
    Ok(())
}

fn component(_error: String) -> Error {
    #[cfg(test)]
    if std::env::var("LATTICA_TEST_GPU_ERROR_DETAIL").as_deref() == Ok("1") {
        eprintln!("cuda_wallet_fixture_rejected reason={_error}");
    }
    Error::ComponentRejected
}

pub(crate) struct WalletProof {
    pub(crate) proof: Vec<u8>,
    pub(crate) public: Vec<crate::config::Val>,
    pub(crate) report: Report,
}

fn encode<F: StarkField>(
    output: wallet::WalletProof<F>,
    prefix: &[&[u8]],
    limit: usize,
    allowance: usize,
) -> Result<WalletProof, Error> {
    // Move the existing wire fields into the bounded serializer's config type.
    // There is no encode/decode copy or additional proof allocation here.
    let proof: p3_uni_stark::Proof<super::pcs_field::ProvingConfig<F>> = p3_uni_stark::Proof {
        commitments: p3_uni_stark::Commitments {
            trace: output.proof.commitments.trace,
            quotient_chunks: output.proof.commitments.quotient_chunks,
            random: output.proof.commitments.random,
        },
        opened_values: output.proof.opened_values,
        opening_proof: output.proof.opening_proof,
        degree_bits: output.proof.degree_bits,
    };
    let bytes =
        super::wallet_output::serialize(&proof, &[&output.public_values], prefix, limit, allowance)
            .map_err(|_| Error::ComponentRejected)?;
    Ok(WalletProof {
        proof: bytes,
        public: output.public_values,
        report: output.report,
    })
}

pub(crate) fn prove_joinsplit_with_public(
    witness: &crate::joinsplit_air::Witness,
    request: Request,
) -> Result<WalletProof, Error> {
    let admission = admit(request)?;
    let session = &admission.session;
    let engine = session
        .engine
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?;
    encode(
        engine
            .joinsplit
            .prove(witness, request, session.host_bytes)
            .map_err(component)?,
        &[],
        session.host_bytes,
        session.host_bytes,
    )
}

pub(crate) fn prove_htlc_with_public(
    witness: &crate::htlc_air::Witness,
    request: Request,
) -> Result<WalletProof, Error> {
    let admission = admit(request)?;
    let session = &admission.session;
    let engine = session
        .engine
        .try_lock()
        .map_err(|_| Error::ComponentRejected)?;
    encode(
        engine
            .htlc
            .prove(witness, request, session.host_bytes)
            .map_err(component)?,
        &[],
        session.host_bytes,
        session.host_bytes,
    )
}

fn context_output(
    output: wallet::WalletProof<profile::Challenge>,
    magic: &[u8; 8],
    context: &Context,
    allowance: usize,
) -> Result<ProvedLeaf, LeafError> {
    let output = encode(
        output,
        &[magic, &context.profile_id, &context.chain_id],
        profile::MAX_PROOF_BYTES,
        allowance,
    )
    .map_err(|_| LeafError::GpuFailure)?;
    Ok(ProvedLeaf {
        envelope: output.proof,
        public: output.public,
    })
}

pub(crate) fn prove_context_joinsplit(
    witness: &crate::joinsplit_air::Witness,
    context: &Context,
    request: Request,
) -> Result<ProvedLeaf, LeafError> {
    let admission = admit(request).map_err(|_| LeafError::ProvingPolicy)?;
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile);
    }
    if witness.mint != 0 {
        return Err(LeafError::IssuanceNotSupported);
    }
    let session = &admission.session;
    let engine = session
        .engine
        .try_lock()
        .map_err(|_| LeafError::GpuFailure)?;
    let output = engine
        .context_joinsplit
        .prove(witness, context, request, session.host_bytes)
        .map_err(|e| {
            component(e);
            LeafError::GpuFailure
        })?;
    context_output(output, b"LBV2JS01", context, session.host_bytes)
}

pub(crate) fn prove_context_htlc(
    witness: &crate::htlc_air::Witness,
    context: &Context,
    request: Request,
) -> Result<ProvedLeaf, typed_leaf::Error> {
    let admission = admit(request).map_err(|_| LeafError::ProvingPolicy)?;
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile.into());
    }
    if witness.mint != 0 {
        return Err(typed_leaf::Error::UnauthorizedIssuance);
    }
    let session = &admission.session;
    let engine = session
        .engine
        .try_lock()
        .map_err(|_| LeafError::GpuFailure)?;
    let output = engine
        .context_htlc
        .prove(witness, context, request, session.host_bytes)
        .map_err(|e| {
            component(e);
            LeafError::GpuFailure
        })?;
    Ok(context_output(
        output,
        b"LBV2HT01",
        context,
        session.host_bytes,
    )?)
}

pub(crate) fn prove_issuance(
    witness: &crate::joinsplit_air::Witness,
    context: &Context,
    authorized_mint: u64,
    request: Request,
) -> Result<ProvedLeaf, typed_leaf::Error> {
    let admission = admit(request).map_err(|_| LeafError::ProvingPolicy)?;
    if context.profile_id != profile::CANDIDATE_PROFILE_ID {
        return Err(LeafError::WrongProfile.into());
    }
    if witness.mint != authorized_mint
        || authorized_mint == 0
        || authorized_mint >= 1u64 << crate::joinsplit_air::BITS
    {
        return Err(typed_leaf::Error::UnauthorizedIssuance);
    }
    let session = &admission.session;
    let engine = session
        .engine
        .try_lock()
        .map_err(|_| LeafError::GpuFailure)?;
    let output = engine
        .issuance
        .prove(
            witness,
            context,
            authorized_mint,
            request,
            session.host_bytes,
        )
        .map_err(|e| {
            component(e);
            LeafError::GpuFailure
        })?;
    Ok(context_output(
        output,
        b"LBV2CB01",
        context,
        session.host_bytes,
    )?)
}

#[cfg(test)]
pub(crate) mod tests;
