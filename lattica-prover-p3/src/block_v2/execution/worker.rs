//! Public-proof-only CPU adapter for an already leased local DAG job.
//!
//! This is synchronous proving, not a process supervisor or cancellation API.
//! The runtime must enforce the lease's OS resource budget and stop/drain work
//! before acknowledging worker termination. Returned bytes are not a completion
//! ticket: the owner must independently CPU-verify and journal their acceptance.
use std::{sync::Arc, time::Instant};

use super::{
    dag::Lease,
    job::{
        ArtifactKind, ArtifactRef, Job, JobId, Operation, RegistryPin, VerifiedNode,
        VerifiedWallet, WALLET_MAGIC,
    },
    resources::Resources,
};
use crate::block_v2::{
    codec,
    commitment::NodeSummary,
    machine::programs,
    recursive::{CacheStats, ConstructionSession, Error, NodeProof, Registry, WalletProof},
};

/// Immutable, bounded copy of a current lease's exact public input contract.
/// Only the scheduler can construct this. It is not a wire or consensus format.
/// Arc-backed inputs keep the scheduler's frozen bytes without another copy.
pub struct Assignment {
    lease: Lease,
    resources: Resources,
    job: Job,
    dependencies: Vec<Job>,
    manifest: Vec<ArtifactRef>,
    inputs: Vec<Arc<[u8]>>,
}

impl Assignment {
    pub(super) fn new(
        lease: Lease,
        resources: Resources,
        job: Job,
        dependencies: Vec<Job>,
        manifest: Vec<ArtifactRef>,
        inputs: Vec<Arc<[u8]>>,
    ) -> Result<Self, Error> {
        let assignment = Self {
            lease,
            resources,
            job,
            dependencies,
            manifest,
            inputs,
        };
        assignment.validate()?;
        Ok(assignment)
    }
    pub fn lease(&self) -> Lease {
        self.lease
    }
    pub fn resources(&self) -> Resources {
        self.resources
    }
    pub fn job(&self) -> &Job {
        &self.job
    }
    pub fn manifest(&self) -> &[ArtifactRef] {
        &self.manifest
    }

    fn validate(&self) -> Result<(), Error> {
        self.resources.validate_request()?;
        if self.lease.job() != self.job.id()
            || self.inputs.len() > 2
            || self.inputs.len() != self.manifest.len()
            || self.dependencies.len() != self.job.dependencies().len()
            || self.dependencies.len() > 2
        {
            return Err("worker assignment identity or input bound".into());
        }
        for (id, bytes) in self.manifest.iter().zip(&self.inputs) {
            id.check_bytes(bytes)?;
        }
        for (job, id) in self.dependencies.iter().zip(self.job.dependencies()) {
            if job.id() != *id || job.pin() != self.job.pin() {
                return Err("worker ordered dependency identity".into());
            }
        }
        let (wallets, children) = match self.job.operation() {
            Operation::Wrap => (1, 0),
            Operation::WrapPair => (2, 0),
            Operation::Empty => (0, 0),
            Operation::Merge => (0, 2),
        };
        if self.job.wallet_inputs().len() != wallets
            || self.dependencies.len() != children
            || self.inputs.len() != wallets + children
        {
            return Err("worker operation arity".into());
        }
        if wallets != 0 && self.manifest != self.job.wallet_inputs() {
            return Err("worker frozen wallet manifest".into());
        }
        if children != 0 {
            if self.manifest.iter().any(|a| a.kind() != ArtifactKind::Node)
                || Job::merge(&self.dependencies[0], &self.dependencies[1])? != self.job
            {
                return Err("worker merge statement/dependencies".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timings {
    pub input_verification_ms: u128,
    pub proving_ms: u128,
    pub serialization_ms: u128,
}

/// A worker report, never proof-validity or current-attempt authority. The local
/// adapter checks its generated statement; the coordinator still verifies bytes
/// against its own leased Job before DurableDag::finish_verification.
pub struct Output {
    lease: Lease,
    job: JobId,
    bytes: Vec<u8>,
    timings: Timings,
    stats: CacheStats,
}
impl Output {
    pub fn lease(&self) -> Lease {
        self.lease
    }
    pub fn job(&self) -> JobId {
        self.job
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn timings(&self) -> Timings {
        self.timings
    }
    pub fn stats(&self) -> CacheStats {
        self.stats
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

enum Inputs {
    Wallet(WalletProof),
    Pair([WalletProof; 2]),
    Empty,
    Merge([NodeProof; 2]),
}

fn prove_inputs(
    session: &mut ConstructionSession,
    inputs: Inputs,
    expected: NodeSummary,
) -> Result<NodeProof, Error> {
    match inputs {
        Inputs::Wallet(wallet) => session.wrap(&wallet),
        Inputs::Pair([left, right]) => session.wrap_pair(&left, &right),
        Inputs::Empty => session.empty(expected.context.chain_id, expected.level),
        Inputs::Merge([left, right]) => session.merge(&left, &right),
    }
}

/// Explicit CPU reference backend. No private wallet witness API is exposed.
/// Each execute call owns and drops one preprocessing workspace before returning;
/// retaining that memory across released leases would evade admission accounting.
/// Warm workspace reuse needs a separately reserved persistent worker lifecycle.
pub struct CpuWorker {
    registry: Registry,
    pin: RegistryPin,
}

fn cpu_switch(value: Option<&std::ffi::OsStr>) -> Result<(), Error> {
    match value {
        None => Ok(()),
        Some(v) if v == "0" => Ok(()),
        _ => Err("CPU worker rejects alternate proving switch".into()),
    }
}
fn require_cpu_backend() -> Result<(), Error> {
    if cfg!(feature = "gpu") || crate::block_v2::quotient_pcs::research_enabled() {
        return Err("CPU reference worker requires a CPU-only, unfused build/runtime".into());
    }
    for name in [
        "LATTICA_V2_GPU_HASH",
        "LATTICA_V2_GPU_PIPELINE",
        "LATTICA_V2_GPU_RETAIN_TREES",
        "LATTICA_V2_GPU_RESIDENT_LDE",
        "LATTICA_V2_GPU_OPENINGS",
        "LATTICA_V2_QUOTIENT_FUSION",
    ] {
        cpu_switch(std::env::var_os(name).as_deref())?;
    }
    Ok(())
}

impl CpuWorker {
    pub fn new(registry: Registry, pin: RegistryPin) -> Result<Self, Error> {
        require_cpu_backend()?;
        RegistryPin::new(&registry, pin.profile(), pin.construction())?;
        Ok(Self { registry, pin })
    }

    fn prepare(&self, assignment: &Assignment) -> Result<Inputs, Error> {
        require_cpu_backend()?;
        assignment.validate()?;
        let job = &assignment.job;
        if job.pin() != self.pin {
            return Err("worker assignment registry/construction".into());
        }
        let chain = job.expected().context.chain_id;
        let decode_wallet = |index: usize| -> Result<(VerifiedWallet, WalletProof), Error> {
            let bytes = &assignment.inputs[index];
            let ticket = VerifiedWallet::verify(self.pin, &self.registry, chain, bytes)?;
            let wallet = codec::decode(&bytes[WALLET_MAGIC.len()..])?;
            Ok((ticket, wallet))
        };
        let (derived, inputs) = match job.operation() {
            Operation::Wrap => {
                let (ticket, wallet) = decode_wallet(0)?;
                (Job::wrap(job.start(), ticket)?, Inputs::Wallet(wallet))
            }
            Operation::WrapPair => {
                let (left, lw) = decode_wallet(0)?;
                let (right, rw) = decode_wallet(1)?;
                (
                    Job::wrap_pair(job.start(), left, right)?,
                    Inputs::Pair([lw, rw]),
                )
            }
            Operation::Empty => (
                Job::empty(self.pin, chain, job.start(), job.expected().level)?,
                Inputs::Empty,
            ),
            Operation::Merge => {
                for (child, bytes) in assignment.dependencies.iter().zip(&assignment.inputs) {
                    VerifiedNode::verify(child, &self.registry, bytes)?;
                }
                (
                    Job::merge(&assignment.dependencies[0], &assignment.dependencies[1])?,
                    Inputs::Merge([
                        codec::decode_node(&assignment.inputs[0])?,
                        codec::decode_node(&assignment.inputs[1])?,
                    ]),
                )
            }
        };
        if derived != *job {
            return Err("worker reconstructed job differs from lease".into());
        }
        Ok(inputs)
    }

    #[cfg(target_os = "linux")]
    pub fn execute(
        &mut self,
        gate: &super::launch::WorkerGate,
        assignment: Assignment,
    ) -> Result<Output, Error> {
        let packet = packet::encode_request(&assignment)?;
        self.check_assignment_gate(gate, &packet, assignment.job.expected().context.chain_id)?;
        let started = Instant::now();
        let inputs = self.prepare(&assignment)?;
        let input_verification_ms = started.elapsed().as_millis();
        let (bytes, proving_ms, serialization_ms, stats) = self.prove(
            inputs,
            assignment.job.expected(),
            assignment.job.operation(),
        )?;
        Ok(Output {
            lease: assignment.lease,
            job: assignment.job.id(),
            bytes,
            timings: Timings {
                input_verification_ms,
                proving_ms,
                serialization_ms,
            },
            stats,
        })
    }

    fn prove(
        &self,
        inputs: Inputs,
        expected: NodeSummary,
        operation: Operation,
    ) -> Result<(Vec<u8>, u128, u128, CacheStats), Error> {
        require_cpu_backend()?;
        let started = Instant::now();
        // A local session ensures both success and unwinding release its workspace.
        // ProverSession uses fresh CSPRNG material for every proof; no RNG is cached.
        let mut session = ConstructionSession::new(
            self.pin.construction(),
            self.registry.clone(),
            self.pin.profile(),
        )?;
        let proof = prove_inputs(&mut session, inputs, expected);
        let stats = session.stats();
        session.clear();
        let proof = proof?;
        let proving_ms = started.elapsed().as_millis();
        if proof.public != programs::statement(expected, operation.proof_mode()) {
            return Err("worker generated unexpected statement".into());
        }
        let started = Instant::now();
        let bytes = codec::encode_node(&proof)?;
        // The canonical codec bounds the complete encoded proof. The recipient
        // independently performs CPU verification; this report carries no ticket.
        let serialization_ms = started.elapsed().as_millis();
        Ok((bytes, proving_ms, serialization_ms, stats))
    }
}

#[cfg(target_os = "linux")]
#[path = "worker_packet.rs"]
pub mod packet;

#[cfg(all(target_os = "linux", feature = "stream"))]
#[path = "worker_cached.rs"]
pub mod cached;

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
