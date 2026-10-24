//! Serial, process-local execution of immutable registered programs.
//!
//! Only one prepared program is retained. Private inputs, randomness and graph
//! coverage keys belong to the current caller, never this registry. Public
//! verifier metadata and opaque identity receipts use separate LRUs sharing one
//! bounded public byte allowance; neither is a disk trust mechanism.
use lattica_prover_p3::{
    block_v2::{
        machine::{
            analysis::MachineAnalysis,
            backend::{RegisteredIdentityReceipt, RegisteredProgram, RegisteredVerifier},
            program::Val,
            MachineAir, Program,
        },
        profile::{self, Config},
    },
    proving::{Policy, Request},
};
use p3_batch_stark::BatchProof;
use p3_field::PrimeField64;
use serde_json::{json, Value};
use sha3::{Digest, Sha3_256};
use std::{
    cell::RefCell,
    collections::VecDeque,
    path::PathBuf,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

mod diagnostics;
pub(crate) mod retained_resources;
mod telemetry;
pub use telemetry::RegistrationTelemetry;
use telemetry::{AccessOutcome, RegistrationTrace, ReleaseReason};
#[cfg(feature = "opencl")]
mod native;
#[cfg(feature = "opencl")]
mod private_spend;
use diagnostics::Diagnostics;
#[cfg(test)]
mod shared_program_tests;
#[cfg(test)]
mod tests;

pub const PUBLIC_METADATA_LIMIT_BYTES: usize = 64 << 20;
const MAX_METADATA_ENTRIES: usize = 256;
/// Entry experiments share exactly the same public byte and receipt limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MetadataCapacity {
    #[default]
    Entries256,
    Entries512,
}
impl MetadataCapacity {
    fn entries(self) -> usize {
        match self {
            Self::Entries256 => MAX_METADATA_ENTRIES,
            Self::Entries512 => 512,
        }
    }
}
// The receipt cache shares PUBLIC_METADATA_LIMIT_BYTES with verifier metadata;
// it does not add to the worker's public metadata allowance.
const MAX_IDENTITY_HINT_ENTRIES: usize = 4096;
const IDENTITY_HINT_LIMIT_BYTES: usize = 1 << 20;
static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn error(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    manifest: [u8; 32],
    registration: [u8; 32],
}
impl Identity {
    fn public_details(self) -> Value {
        json!({"program_identity_sha3_256": hex(&self.registration),
               "canonical_manifest_sha3_256": hex(&self.manifest)})
    }
}

fn check_cached_cap(
    diagnostics: &Diagnostics,
    identity: Identity,
    expected: &[[Val; 4]],
    observed: &[[Val; 4]],
) -> Result<(), String> {
    if expected == observed {
        return Ok(());
    }
    let mut details = identity.public_details();
    details["expected_preprocessing_cap"] = json!(expected
        .iter()
        .map(|r| r.map(|v| v.as_canonical_u64()))
        .collect::<Vec<_>>());
    details["preprocessing_cap"] = json!(observed
        .iter()
        .map(|r| r.map(|v| v.as_canonical_u64()))
        .collect::<Vec<_>>());
    let message = "same program identity produced different preprocessing cap";
    diagnostics.failure("registration_cap_mismatch", details, message, None);
    Err(message.into())
}

fn manifest(program: &Program) -> Result<[u8; 32], String> {
    let mut hash = Sha3_256::new();
    hash.update(b"lattica/public-program-manifest/le-u64/v1");
    let mut count = 0u64;
    program.visit_manifest_fields(&mut |word| {
        count = count
            .checked_add(1)
            .ok_or("program manifest length overflow")?;
        hash.update(word.to_le_bytes());
        Ok(())
    })?;
    hash.update(count.to_le_bytes());
    Ok(hash.finalize().into())
}

/// Immutable proving state. The callback cannot extract or clone its owner.
/// `prove` always supplies the context's explicit policy and fresh proof RNGs.
pub struct RegisteredTemplate {
    registered: RegisteredProgram,
    host_allowance_bytes: u64,
    verifier: Arc<RegisteredVerifier>,
    request: Request,
    identity: Identity,
    diagnostics: Rc<Diagnostics>,
    telemetry_access: Option<usize>,
    metadata_payload_bytes: usize,
}
impl RegisteredTemplate {
    /// Allowance used to prepare this immutable backend owner.
    pub fn host_allowance_bytes(&self) -> u64 {
        self.host_allowance_bytes
    }
    pub fn id(&self) -> [u64; 4] {
        self.registered.id()
    }
    pub fn program_identity(&self) -> [u8; 32] {
        self.identity.registration
    }
    pub fn canonical_manifest_digest(&self) -> [u8; 32] {
        self.identity.manifest
    }
    pub fn air(&self) -> &MachineAir {
        self.registered.air()
    }
    pub fn analysis(&self) -> &MachineAnalysis {
        self.registered.analysis()
    }
    pub fn preprocessing_cap(&self) -> &p3_batch_stark::Commitment<Config> {
        self.registered.preprocessing_cap()
    }
    pub fn verifier(&self) -> Arc<RegisteredVerifier> {
        Arc::clone(&self.verifier)
    }

    fn public_identity(&self) -> Value {
        json!({"program_identity_sha3_256": hex(&self.identity.registration),
               "canonical_manifest_sha3_256": hex(&self.identity.manifest),
               "registered_program_id": self.id(),
               "preprocessing_cap": self.preprocessing_cap().roots().iter()
                    .map(|r| r.map(|v| v.as_canonical_u64())).collect::<Vec<_>>()})
    }
    pub fn prove(&self, public: &[Val], witness: &[Val]) -> Result<BatchProof<Config>, String> {
        let started = Instant::now();
        let result = self
            .registered
            .prove_with_request(public, witness, self.request)
            .map_err(error);
        self.diagnostics.prove_finished(
            started.elapsed().as_secs_f64(),
            result.is_ok(),
            self.air().program().active_rows(),
            self.air().program().height(),
        );
        if let Err(ref message) = result {
            self.diagnostics
                .failure("prove", self.public_identity(), message, None);
        }
        result
    }
    pub fn verify(&self, proof: &BatchProof<Config>, public: &[Val]) -> Result<(), String> {
        let started = Instant::now();
        let result = self.verifier.verify(proof, public);
        self.diagnostics
            .verify_finished(started.elapsed().as_secs_f64(), result.is_ok());
        if let Err(ref message) = result {
            self.diagnostics.failure(
                "verify",
                self.public_identity(),
                message,
                Some((public, proof)),
            );
        }
        result
    }
}

struct Metadata {
    identity: Identity,
    cap: Vec<[Val; 4]>,
    verifier: Arc<RegisteredVerifier>,
    payload_bytes: usize,
}

/// Small fixed-capacity LRU, independent of the much larger verifier entries.
/// Production R is an opaque, fixed-size receipt with no owned heap or device
/// storage. The generic payload lets unit tests exercise eviction without GPU
/// registration or any way to mint a production receipt.
struct IdentityHintCache<R> {
    entries: VecDeque<(Identity, R)>,
    max_entries: usize,
    evictions: u64,
}
impl<R> IdentityHintCache<R> {
    fn new() -> Self {
        let max_entries = MAX_IDENTITY_HINT_ENTRIES
            .min(IDENTITY_HINT_LIMIT_BYTES / std::mem::size_of::<(Identity, R)>());
        let entries = VecDeque::with_capacity(max_entries);
        // Actual backing capacity is charged below. Refuse a library allocation
        // strategy that would violate this cache's explicit physical subcap.
        assert!(
            entries.capacity() * std::mem::size_of::<(Identity, R)>() <= IDENTITY_HINT_LIMIT_BYTES
        );
        Self {
            entries,
            max_entries,
            evictions: 0,
        }
    }
    fn backing_bytes(&self) -> usize {
        self.entries.capacity() * std::mem::size_of::<(Identity, R)>()
    }
    fn get(&self, identity: Identity) -> Option<&R> {
        // Nomination never promotes an entry: only successful registration and
        // the independent verifier-cap check authorize retention/promotion.
        self.entries
            .iter()
            .find(|(candidate, _)| *candidate == identity)
            .map(|(_, receipt)| receipt)
    }
    fn remove(&mut self, identity: Identity) {
        if let Some(index) = self
            .entries
            .iter()
            .position(|(candidate, _)| *candidate == identity)
        {
            let _ = self.entries.remove(index);
            self.evictions += 1;
        }
    }
    fn remember(&mut self, identity: Identity, receipt: R) {
        if self.max_entries == 0 {
            return;
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|(candidate, _)| *candidate == identity)
        {
            let _ = self.entries.remove(index);
        } else if self.entries.len() == self.max_entries {
            let _ = self.entries.pop_front();
            self.evictions += 1;
        }
        self.entries.push_back((identity, receipt));
    }
}

struct Registry {
    prepared: Option<RegisteredTemplate>,
    metadata: VecDeque<Metadata>,
    identity_hints: IdentityHintCache<RegisteredIdentityReceipt>,
    // Both backing allocations and all verifier/cap heap payloads are charged.
    metadata_bytes: usize,
    maximum_metadata_entries: usize,
    trace: RegistrationTrace,
    registrations: u64,
    prepared_hits: u64,
    metadata_hits: u64,
    identity_hints_supplied: u64,
    identity_hint_hits: u64,
    prepared_evictions: u64,
    metadata_evictions: u64,
    metadata_capacity_evictions: u64,
    metadata_byte_evictions: u64,
    metadata_identity_evictions: u64,
    metadata_oversized_rejections: u64,
    registration_seconds: f64,
    registration_setup_seconds: f64,
    registered_active_rows: u64,
    registered_padded_rows: u64,
}
impl Registry {
    fn new() -> Self {
        Self::with_options(
            MetadataCapacity::Entries256,
            RegistrationTelemetry::Disabled,
        )
    }
    fn with_options(capacity: MetadataCapacity, telemetry: RegistrationTelemetry) -> Self {
        let maximum_metadata_entries = capacity.entries();
        let metadata = VecDeque::with_capacity(maximum_metadata_entries);
        let identity_hints = IdentityHintCache::new();
        let trace = RegistrationTrace::new(telemetry);
        let metadata_bytes = metadata.capacity() * std::mem::size_of::<Metadata>()
            + identity_hints.backing_bytes()
            + trace.accounted_bytes();
        assert!(metadata_bytes <= PUBLIC_METADATA_LIMIT_BYTES);
        Self {
            prepared: None,
            metadata,
            identity_hints,
            metadata_bytes,
            maximum_metadata_entries,
            trace,
            registrations: 0,
            prepared_hits: 0,
            metadata_hits: 0,
            identity_hints_supplied: 0,
            identity_hint_hits: 0,
            prepared_evictions: 0,
            metadata_evictions: 0,
            metadata_capacity_evictions: 0,
            metadata_byte_evictions: 0,
            metadata_identity_evictions: 0,
            metadata_oversized_rejections: 0,
            registration_seconds: 0.0,
            registration_setup_seconds: 0.0,
            registered_active_rows: 0,
            registered_padded_rows: 0,
        }
    }
    fn release(&mut self, reason: ReleaseReason) {
        if let Some(prepared) = self.prepared.take() {
            self.prepared_evictions += 1;
            self.trace.release(prepared.telemetry_access, reason);
        }
    }
    fn identity_hint(&self, identity: Identity) -> Option<&RegisteredIdentityReceipt> {
        // This is only a candidate lookup. Core registration must independently
        // validate the complete identity stream and freshly computed cap. Do
        // not promote the LRU until cached_verifier also validates that cap.
        self.identity_hints.get(identity)
    }
    fn cached_verifier(
        &mut self,
        identity: Identity,
        cap: &[[Val; 4]],
        diagnostics: &Diagnostics,
    ) -> Result<Option<Arc<RegisteredVerifier>>, String> {
        let Some(index) = self.metadata.iter().position(|m| m.identity == identity) else {
            return Ok(None);
        };
        let entry = self.metadata.remove(index).expect("located metadata");
        if let Err(message) = check_cached_cap(diagnostics, identity, &entry.cap, cap) {
            self.metadata_bytes -= entry.payload_bytes;
            self.metadata_evictions += 1;
            self.metadata_identity_evictions += 1;
            self.identity_hints.remove(identity);
            return Err(message);
        }
        let verifier = Arc::clone(&entry.verifier);
        self.metadata.push_back(entry);
        self.metadata_hits += 1;
        Ok(Some(verifier))
    }
    fn remember(
        &mut self,
        identity: Identity,
        cap: &[[Val; 4]],
        verifier: Arc<RegisteredVerifier>,
    ) -> Result<usize, String> {
        let cap = cap.to_vec();
        let payload_bytes = verifier
            .cached_metadata_bytes()
            .checked_add(
                cap.capacity()
                    .checked_mul(std::mem::size_of::<[Val; 4]>())
                    .ok_or("cap size overflow")?,
            )
            .and_then(|n| {
                n.checked_add(
                    2 * std::mem::size_of::<usize>() + std::mem::align_of::<RegisteredVerifier>(),
                )
            })
            .ok_or("verifier cache size overflow")?;
        let container_bytes = self.metadata.capacity() * std::mem::size_of::<Metadata>()
            + self.identity_hints.backing_bytes()
            + self.trace.accounted_bytes();
        if payload_bytes > PUBLIC_METADATA_LIMIT_BYTES.saturating_sub(container_bytes) {
            self.metadata_oversized_rejections += 1;
            return Ok(payload_bytes);
        }
        while self.metadata.len() == self.maximum_metadata_entries
            || self.metadata_bytes + payload_bytes > PUBLIC_METADATA_LIMIT_BYTES
        {
            if self.metadata.len() == self.maximum_metadata_entries {
                self.metadata_capacity_evictions += 1;
            } else {
                self.metadata_byte_evictions += 1;
            }
            let old = self
                .metadata
                .pop_front()
                .ok_or("metadata accounting inconsistency")?;
            self.metadata_bytes -= old.payload_bytes;
            self.metadata_evictions += 1;
        }
        self.metadata_bytes += payload_bytes;
        self.metadata.push_back(Metadata {
            identity,
            cap,
            verifier,
            payload_bytes,
        });
        Ok(payload_bytes)
    }
}

/// One serial worker lifetime. Checked interior borrowing rejects reentrant
/// work; Rc also prevents sending this context to another OS thread.
pub struct ProvingContext {
    // Drop prepared handles before the owned Session, including on unwinding.
    registry: RefCell<Registry>,
    diagnostics: Rc<Diagnostics>,
    host_bytes: u64,
    request: Request,
    identity_seed: [u8; 32],
    session_id: u64,
    device: Value,
    #[cfg(feature = "opencl")]
    session: Option<crate::opencl::Session>,
}
impl ProvingContext {
    pub fn cpu(host_bytes: u64) -> Result<Self, String> {
        Self::new(
            host_bytes,
            Request {
                policy: Policy::CpuRequired,
                emit_report: true,
            },
            Value::Null,
            #[cfg(feature = "opencl")]
            None,
        )
    }
    #[cfg(feature = "opencl")]
    pub fn opencl(limits: crate::opencl::Limits) -> Result<Self, String> {
        let session = crate::opencl::Session::start(limits)?;
        let device = serde_json::to_value(session.device_identity()).map_err(error)?;
        Self::new(
            limits.host_bytes,
            crate::opencl::strict_request(),
            device,
            Some(session),
        )
    }
    fn new(
        host_bytes: u64,
        request: Request,
        device: Value,
        #[cfg(feature = "opencl")] session: Option<crate::opencl::Session>,
    ) -> Result<Self, String> {
        if host_bytes == 0 || host_bytes > 32u64 << 30 {
            return Err("context host allowance must be in 1..=32GiB".into());
        }
        let session_id = NEXT_SESSION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| "session identity exhausted")?;
        let mut identity = Sha3_256::new();
        identity.update(b"lattica/worker/registered-template/v1");
        identity.update(crate::graph_proofs::compiled_source_fingerprint());
        identity.update(profile::CANDIDATE_PROFILE_ID);
        for value in [
            profile::NUM_QUERIES as u64,
            profile::LOG_BLOWUP as u64,
            profile::CAP_HEIGHT as u64,
            profile::NUM_RANDOM_CODEWORDS as u64,
            profile::QUERY_POW_BITS as u64,
            session_id,
        ] {
            identity.update(value.to_le_bytes());
        }
        identity.update([match request.policy {
            Policy::CpuRequired => 0,
            Policy::GpuRequired => 1,
            Policy::Compatible => return Err("compatible worker context forbidden".into()),
        }]);
        identity.update(serde_json::to_vec(&device).map_err(error)?);
        let identity_seed = identity.finalize().into();
        let diagnostics = Rc::new(Diagnostics::new(session_id, request.policy, device.clone()));
        Ok(Self {
            registry: RefCell::new(Registry::new()),
            diagnostics,
            host_bytes,
            request,
            identity_seed,
            session_id,
            device,
            #[cfg(feature = "opencl")]
            session,
        })
    }
    pub fn host_bytes(&self) -> u64 {
        self.host_bytes
    }
    pub fn policy(&self) -> Policy {
        self.request.policy
    }
    pub fn set_failure_directory(&self, path: impl Into<PathBuf>) -> Result<(), String> {
        self.diagnostics.set_directory(path.into())
    }
    /// Select an experiment before any execution work. Detailed observations
    /// reserve backing and report scratch inside the shared 64 MiB allowance.
    pub fn configure_registration(
        &self,
        capacity: MetadataCapacity,
        telemetry: RegistrationTelemetry,
    ) -> Result<(), String> {
        let mut state = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant worker configuration")?;
        if self.diagnostics.has_work_attempted() || state.trace.attempted() != 0 {
            return Err("registration configuration must precede all execution work".into());
        }
        *state = Registry::with_options(capacity, telemetry);
        Ok(())
    }
    #[cfg(any(feature = "opencl", test))]
    fn drain_prepared(
        &self,
        state: &Registry,
        next: Option<Identity>,
        drain: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        drain().map_err(|message| {
            // Drain concerns the current prepared allocation. Preserve both
            // its cap and the next program identity when replacing it.
            let mut details = state
                .prepared
                .as_ref()
                .map(RegisteredTemplate::public_identity)
                .unwrap_or_else(|| json!({"prepared_program":null,"preprocessing_cap":null}));
            details["next_program"] = next.map(Identity::public_details).unwrap_or(Value::Null);
            let stage = if next.is_some() {
                "registration_drain"
            } else {
                "release_drain"
            };
            self.diagnostics.failure(stage, details, &message, None);
            message
        })
    }
    #[cfg(feature = "opencl")]
    fn check_row_admission(
        &self,
        identity: Identity,
        rows: usize,
        limits: crate::opencl::Limits,
    ) -> Result<(), String> {
        limits.check_rows(rows).map_err(|message| {
            let mut details = identity.public_details();
            details["program_height"] = json!(rows);
            details["maximum_rows"] = json!(limits.max_rows);
            // Registration has not produced a cap at this stage.
            details["preprocessing_cap"] = Value::Null;
            self.diagnostics
                .failure("registration_admission", details, &message, None);
            message
        })
    }
    pub fn release_prepared(&self) -> Result<(), String> {
        self.release_prepared_with_reason(ReleaseReason::PhaseBoundary)
    }
    fn release_prepared_with_reason(&self, reason: ReleaseReason) -> Result<(), String> {
        let mut state = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant worker operation")?;
        #[cfg(feature = "opencl")]
        if self.session.is_some() {
            self.drain_prepared(&state, None, lattica_prover_p3::block_v2::gpu_hash::drain)?;
        }
        state.release(reason);
        Ok(())
    }
    /// Legacy CPU-only boundary; GPU-required workers reject before any work.
    /// The closure must use profile::make_cpu_config at each native proof site.
    /// This releases retained proving state; it does not alter global policy.
    pub fn with_native_cpu<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        self.diagnostics.mark_stark_work_attempted();
        if self.policy() == Policy::GpuRequired {
            return Err("GPU-required worker rejects native CPU proving".into());
        }
        self.release_prepared()?;
        let _serial = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant native operation")?;
        let started = Instant::now();
        let result = f();
        self.diagnostics
            .native_finished(started.elapsed().as_secs_f64(), result.is_ok());
        if let Err(ref message) = result {
            self.diagnostics
                .failure("native_cpu", Value::Null, message, None);
        }
        result
    }
    pub fn with_registered<T>(
        &self,
        program: Program,
        f: impl FnOnce(&RegisteredTemplate) -> Result<T, String>,
    ) -> Result<T, String> {
        self.with_registered_shared(Arc::new(program), f)
    }

    /// Reuse immutable program storage without a deep compiler-data copy.
    /// Full manifest and program equality checks still govern prepared reuse.
    pub fn with_registered_shared<T>(
        &self,
        program: Arc<Program>,
        f: impl FnOnce(&RegisteredTemplate) -> Result<T, String>,
    ) -> Result<T, String> {
        self.with_registered_shared_inner(program, self.host_bytes, f)
    }

    /// Reserve a smaller GPU backend allowance after accounting for caller-owned
    /// siblings and other live data. This is not a total process peak bound.
    /// Eviction prevents reuse of a preparation admitted under a larger limit.
    /// Failure after registration starts must propagate, never trigger a retry.
    pub fn with_registered_shared_with_host_budget<T>(
        &self,
        program: Arc<Program>,
        host_bytes: u64,
        f: impl FnOnce(&RegisteredTemplate) -> Result<T, String>,
    ) -> Result<T, String> {
        if host_bytes == 0 || host_bytes > self.host_bytes {
            return Err(
                "registered remaining-host allowance must be nonzero and within context allowance"
                    .into(),
            );
        }
        if self.request.policy != Policy::GpuRequired {
            return Err(
                "registered remaining-host allowance requires GPU-required execution".into(),
            );
        }
        self.release_prepared_with_reason(ReleaseReason::HostBudgetChanged)?;
        self.with_registered_shared_inner(program, host_bytes, f)
    }

    fn with_registered_shared_inner<T>(
        &self,
        program: Arc<Program>,
        host_bytes: u64,
        f: impl FnOnce(&RegisteredTemplate) -> Result<T, String>,
    ) -> Result<T, String> {
        self.diagnostics.mark_stark_work_attempted();
        let mut state = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant registered operation")?;
        let canonical = manifest(&program)?;
        let mut hash = Sha3_256::new();
        hash.update(self.identity_seed);
        hash.update(canonical);
        let identity = Identity {
            manifest: canonical,
            registration: hash.finalize().into(),
        };
        let access = state.trace.begin(identity, host_bytes, &program);
        let hit = state.prepared.as_ref().is_some_and(|p| {
            p.identity == identity
                && p.host_allowance_bytes == host_bytes
                && p.air().program() == program.as_ref()
        });
        let (metadata_payload_bytes, metadata_hit, receipt_hit);
        if hit {
            state.prepared_hits += 1;
            state.trace.outcome(access, AccessOutcome::PreparedHit, 0.0);
            let prepared = state.prepared.as_mut().expect("prepared cache hit");
            prepared.telemetry_access = access;
            metadata_payload_bytes = prepared.metadata_payload_bytes;
            metadata_hit = false;
            receipt_hit = false;
        } else {
            let reason = state
                .prepared
                .as_ref()
                .map(|p| {
                    if p.identity != identity {
                        ReleaseReason::IdentityChanged
                    } else if p.host_allowance_bytes != host_bytes {
                        ReleaseReason::HostBudgetChanged
                    } else {
                        ReleaseReason::ProgramMismatch
                    }
                })
                .unwrap_or(ReleaseReason::IdentityChanged);
            // Drain and evict before the next registration allocates device state.
            #[cfg(feature = "opencl")]
            if self.session.is_some() {
                if let Err(message) = self.drain_prepared(
                    &state,
                    Some(identity),
                    lattica_prover_p3::block_v2::gpu_hash::drain,
                ) {
                    state.trace.outcome(access, AccessOutcome::DrainFailed, 0.0);
                    return Err(message);
                }
            }
            state.release(reason);
            #[cfg(feature = "opencl")]
            if let Some(session) = &self.session {
                if let Err(message) =
                    self.check_row_admission(identity, program.height(), session.limits())
                {
                    state
                        .trace
                        .outcome(access, AccessOutcome::AdmissionFailed, 0.0);
                    return Err(message);
                }
            }
            let active_rows = program.active_rows() as u64;
            let padded_rows = program.height() as u64;
            let identity_hint = state.identity_hint(identity).cloned();
            state.identity_hints_supplied += u64::from(identity_hint.is_some());
            let started = Instant::now();
            let result = (|| -> Result<(RegisteredTemplate, bool, bool), String> {
                let registered = RegisteredProgram::new_with_request_and_identity_hint(
                    MachineAir::from_shared_program(program),
                    host_bytes,
                    self.request,
                    identity_hint.as_ref(),
                )
                .map_err(|e| {
                    let message = error(e);
                    self.diagnostics.failure(
                        "registration",
                        identity.public_details(),
                        &message,
                        None,
                    );
                    message
                })?;
                state.registration_seconds += started.elapsed().as_secs_f64();
                state.registrations += 1;
                state.registered_active_rows += active_rows;
                state.registered_padded_rows += padded_rows;
                let receipt_hit = registered.identity_hint_hit();
                state.identity_hint_hits += u64::from(receipt_hit);
                let (verifier, payload, metadata_hit) = match state.cached_verifier(
                    identity,
                    registered.preprocessing_cap().roots(),
                    &self.diagnostics,
                )? {
                    Some(cached) => (
                        cached,
                        state
                            .metadata
                            .back()
                            .expect("promoted metadata")
                            .payload_bytes,
                        true,
                    ),
                    None => {
                        let verifier = Arc::new(registered.verifier());
                        let payload = state.remember(
                            identity,
                            registered.preprocessing_cap().roots(),
                            Arc::clone(&verifier),
                        )?;
                        (verifier, payload, false)
                    }
                };
                if let Some(receipt) = registered.identity_receipt() {
                    state.identity_hints.remember(identity, receipt.clone());
                }
                Ok((
                    RegisteredTemplate {
                        registered,
                        host_allowance_bytes: host_bytes,
                        verifier,
                        request: self.request,
                        identity,
                        diagnostics: Rc::clone(&self.diagnostics),
                        telemetry_access: access,
                        metadata_payload_bytes: payload,
                    },
                    metadata_hit,
                    receipt_hit,
                ))
            })();
            let setup_seconds = started.elapsed().as_secs_f64();
            state.registration_setup_seconds += setup_seconds;
            let (prepared, hit_metadata, hit_receipt) = match result {
                Ok(value) => value,
                Err(message) => {
                    state
                        .trace
                        .outcome(access, AccessOutcome::SetupFailed, setup_seconds);
                    return Err(message);
                }
            };
            metadata_payload_bytes = prepared.metadata_payload_bytes;
            metadata_hit = hit_metadata;
            receipt_hit = hit_receipt;
            state.prepared = Some(prepared);
            state
                .trace
                .outcome(access, AccessOutcome::Registered, setup_seconds);
        }
        let public_bytes = state.metadata_bytes;
        let managed_device_bytes = if state.trace.enabled() {
            self.observed_device_live_bytes()
        } else {
            None
        };
        state.trace.retained(
            access,
            public_bytes,
            managed_device_bytes,
            metadata_payload_bytes,
            metadata_hit,
            receipt_hit,
        );
        let prepared = state
            .prepared
            .as_ref()
            .expect("registered template present");
        let result = f(prepared);
        if let Err(ref message) = result {
            self.diagnostics.failure(
                "registered_callback",
                prepared.public_identity(),
                message,
                None,
            );
        }
        state.trace.callback(access, result.is_ok());
        result
    }

    fn observed_device_live_bytes(&self) -> Option<u64> {
        #[cfg(feature = "opencl")]
        if self.session.is_some() {
            return lattica_prover_p3::block_v2::gpu_hash::report("registration observation")
                .map(|stats| stats.managed_live_bytes as u64);
        }
        None
    }
    pub fn report(&self) -> Value {
        let Ok(state) = self.registry.try_borrow() else {
            return json!({"schema":"pq-serial-proving-context-v1", "session_id":self.session_id,
                "policy":self.request.policy, "busy":true, "session_closed":false});
        };
        let mut value = json!({"schema":"pq-serial-proving-context-v1", "session_id":self.session_id,
            "busy":false, "session_closed":false,
            "policy":self.request.policy, "device":self.device, "host_allowance_bytes":self.host_bytes,
            "prepared_entries":usize::from(state.prepared.is_some()), "maximum_prepared_entries":1,
            "registrations":state.registrations, "prepared_cache_hits":state.prepared_hits,
            "metadata_cache_hits":state.metadata_hits, "prepared_evictions":state.prepared_evictions,
            "identity_hints_supplied":state.identity_hints_supplied,
            "identity_hint_hits":state.identity_hint_hits,
            "identity_receipt_entries":state.identity_hints.entries.len(),
            "identity_receipt_maximum_entries":state.identity_hints.max_entries,
            "identity_receipt_evictions":state.identity_hints.evictions,
            "identity_receipt_cache_bytes":state.identity_hints.backing_bytes(),
            "identity_receipt_cache_limit_bytes":IDENTITY_HINT_LIMIT_BYTES,
            "identity_receipt_retained_bytes":state.identity_hints.entries.iter().map(|(_, receipt)| receipt.accounted_bytes()).sum::<usize>()});
        let cache = json!({
            "verifier_metadata_cache_bytes":state.metadata_bytes-state.identity_hints.backing_bytes()-state.trace.accounted_bytes(),
            "metadata_evictions":state.metadata_evictions, "metadata_entries":state.metadata.len(),
            "maximum_metadata_entries":state.maximum_metadata_entries,
            "metadata_entry_size_bytes":std::mem::size_of::<Metadata>(),
            "metadata_backing_bytes":state.metadata.capacity()*std::mem::size_of::<Metadata>(),
            "metadata_eviction_reasons":{"entry_capacity":state.metadata_capacity_evictions,
                "shared_byte_limit":state.metadata_byte_evictions,"identity_cap_mismatch":state.metadata_identity_evictions},
            "metadata_oversized_rejections":state.metadata_oversized_rejections,
            "metadata_cache_payload_bytes":state.metadata_bytes,
            "metadata_cache_payload_limit_bytes":PUBLIC_METADATA_LIMIT_BYTES,
            "registration_telemetry_reserved_bytes":state.trace.accounted_bytes(),
            "prepared_reuse_mode":"single_entry",
            "registration_setup_seconds":state.registration_setup_seconds,
            "registration_setup_scope":"core registration plus verifier metadata lookup/construction; excludes callback proving and verification",
            "registered_active_rows":state.registered_active_rows,
            "registered_padded_rows":state.registered_padded_rows,
            "registered_row_scope":"successful core registrations, excluding prepared hits and native proofs",
            "cache_accounting_includes":"combined verifier and GPU identity-receipt backing capacities, caps, public verifier payload and bounded telemetry backing/report reservation",
            "cache_accounting_excludes":"caller-owned keys and retained report snapshots, active prover, verification scratch, allocator and driver overhead",
            "registration_seconds":state.registration_seconds, "operations":self.diagnostics.report()});
        if let Value::Object(fields) = cache {
            value
                .as_object_mut()
                .expect("context report object")
                .extend(fields);
        }
        value["registration_telemetry"] = state.trace.report();
        #[cfg(feature = "opencl")]
        if self.session.is_some() {
            value["gpu"] = lattica_prover_p3::block_v2::gpu_hash::report("worker context observation")
                .map(|s| json!({"managed_live_bytes":s.managed_live_bytes,"managed_peak_bytes":s.managed_peak_bytes,
                    "allocations":s.allocations,"commits":s.commits})).unwrap_or(Value::Null);
        }
        value
    }
    pub fn finish(self) -> Result<Value, String> {
        self.release_prepared_with_reason(ReleaseReason::SessionRetired)?;
        let mut report = self.report();
        #[cfg(feature = "opencl")]
        if let Some(session) = self.session {
            let native_spend_reports = self.diagnostics.native_spend_only_complete_reports();
            report["session_finish"] = if native_spend_reports > 0 {
                session.finish_native_spend(native_spend_reports)?
            } else {
                session.finish()?
            };
        }
        report["session_closed"] = json!(true);
        Ok(report)
    }

    /// Drain and close the worker after refusal, exhaustion or cancellation.
    /// This returns cleanup telemetry without claiming successful proof or
    /// native-spend completion. Use `finish` for a completed operation receipt.
    pub fn close_without_completion(self) -> Result<Value, String> {
        self.release_prepared_with_reason(ReleaseReason::Cleanup)?;
        let mut report = self.report();
        #[cfg(feature = "opencl")]
        if let Some(session) = self.session {
            report["session_cleanup"] = session.cleanup_only()?;
        }
        report["session_closed"] = json!(true);
        report["completion_claimed"] = json!(false);
        Ok(report)
    }
}

#[cfg(test)]
mod admission_diagnostics_tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn cap_mismatch_and_drain_failure_record_public_identity_without_retry() {
        let context = ProvingContext::cpu(1 << 30).unwrap();
        let identity = Identity {
            manifest: [3; 32],
            registration: [7; 32],
        };
        let expected = [[Val::ONE; 4]];
        let observed = [[Val::ZERO; 4]];
        check_cached_cap(&context.diagnostics, identity, &expected, &expected).unwrap();
        assert!(context.diagnostics.report()["failures"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(check_cached_cap(&context.diagnostics, identity, &expected, &observed).is_err());

        let calls = std::cell::Cell::new(0);
        assert!(context
            .drain_prepared(&Registry::new(), Some(identity), || {
                calls.set(calls.get() + 1);
                Err("injected drain failure".into())
            })
            .is_err());
        assert_eq!(calls.get(), 1);
        let report = context.diagnostics.report();
        let events = report["failures"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["stage"], "registration_cap_mismatch");
        assert_eq!(
            events[0]["identity"]["program_identity_sha3_256"],
            hex(&identity.registration)
        );
        assert_eq!(
            events[0]["identity"]["expected_preprocessing_cap"],
            json!([[1, 1, 1, 1]])
        );
        assert_eq!(
            events[0]["identity"]["preprocessing_cap"],
            json!([[0, 0, 0, 0]])
        );
        assert_eq!(events[1]["stage"], "registration_drain");
        assert_eq!(
            events[1]["identity"]["next_program"],
            identity.public_details()
        );
        for event in events {
            assert_eq!(event["session_id"], context.session_id);
            assert_eq!(event["returned_proof"], false);
            assert_eq!(event["retry_attempted"], false);
        }
        assert_eq!(report["failure_artifact_attempted"], false);
        assert_eq!(context.report()["registrations"], 0);
    }

    #[cfg(feature = "opencl")]
    #[test]
    fn row_admission_failure_records_geometry_before_any_gpu_work() {
        let context = ProvingContext::cpu(1 << 30).unwrap();
        let identity = Identity {
            manifest: [5; 32],
            registration: [9; 32],
        };
        let limits = crate::opencl::Limits {
            host_bytes: 1 << 30,
            device_bytes: 1 << 30,
            max_rows: 32,
        };
        context.check_row_admission(identity, 32, limits).unwrap();
        assert!(context.check_row_admission(identity, 64, limits).is_err());
        let report = context.diagnostics.report();
        let events = report["failures"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["stage"], "registration_admission");
        assert_eq!(events[0]["identity"]["program_height"], 64);
        assert_eq!(events[0]["identity"]["maximum_rows"], 32);
        assert_eq!(events[0]["identity"]["preprocessing_cap"], Value::Null);
        assert_eq!(
            events[0]["identity"]["canonical_manifest_sha3_256"],
            hex(&identity.manifest)
        );
        assert_eq!(context.report()["registrations"], 0);
    }
}

#[cfg(feature = "opencl")]
mod preparation;
