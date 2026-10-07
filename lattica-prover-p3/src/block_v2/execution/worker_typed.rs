//! Typed public-proof worker with one reusable registered-program workspace.
//!
//! The runtime owns device initialization and must reserve and enforce `resources`
//! for this worker's entire lifetime, including idle cached preprocessing. A
//! result is neither proof acceptance nor a worker-stop receipt. In particular,
//! GPU shutdown/drain and OS reconciliation remain the runtime's responsibility.

use super::packet::{Request, RequestInfo};
use super::*;
use crate::block_v2::{
    execution::{
        job::TYPED_WALLET_MAGIC,
        launch::{self, WorkerGate},
    },
    typed_recursive::{Policy, Registry as TypedRegistry, Session},
};

enum TypedInputs {
    Pair([WalletProof; 2], [Policy; 2], u8),
    Empty,
    Merge([NodeProof; 2]),
    Finalize(NodeProof),
}

pub struct TypedWorker {
    registry: TypedRegistry<12>,
    pin: RegistryPin,
    resources: Resources,
    request_resources: Resources,
    session: Option<Session<12>>,
}

impl TypedWorker {
    /// Does not initialize a GPU or register preprocessing. Resource ownership
    /// must already be established by the enclosing runtime before proving.
    pub fn new(
        registry: TypedRegistry<12>,
        pin: RegistryPin,
        resources: Resources,
    ) -> Result<Self, Error> {
        pin.check_typed(&registry)?;
        resources.validate_capacity()?;
        let session = Session::new(registry.clone(), pin.profile(), resources.ram_bytes)?;
        Ok(Self {
            registry,
            pin,
            resources,
            request_resources: resources,
            session: Some(session),
        })
    }

    pub fn stats(&self) -> Result<CacheStats, Error> {
        Ok(self
            .session
            .as_ref()
            .ok_or("typed worker is closed or poisoned")?
            .stats())
    }

    fn drain(&self) -> Result<(), Error> {
        drain_backend(self.resources)
    }

    fn bound_packet(
        &self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
    ) -> Result<Request, Error> {
        self.stats()?;
        gate.token().check_request(bytes)?;
        let request = Request::decode(bytes, self.pin, chain)?;
        request.bind(gate.token(), bytes)?;
        if request.resources != self.request_resources {
            return Err("typed worker resource assignment changed".into());
        }
        Ok(request)
    }

    fn prepare(
        &self,
        request: &Request,
        policy: &mut impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    ) -> Result<TypedInputs, Error> {
        request.validate()?;
        if request.pin != self.pin || request.resources != self.request_resources {
            return Err("typed worker registry/resource mismatch".into());
        }
        let chain = request.expected.context.chain_id;
        let mut wallet = |index: usize| -> Result<(VerifiedWallet, WalletProof, Policy), Error> {
            let bytes = &request.inputs[index];
            let policy = policy(request.manifest[index])?;
            let ticket =
                VerifiedWallet::verify_typed(self.pin, &self.registry, chain, policy, bytes)?;
            Ok((
                ticket,
                codec::decode(&bytes[TYPED_WALLET_MAGIC.len()..])?,
                policy,
            ))
        };
        let (derived, inputs) = match request.operation {
            Operation::TypedPair { padded, .. } => {
                let (left, left_proof, left_policy) = wallet(0)?;
                let (right, right_proof, right_policy) = wallet(1)?;
                let job =
                    Job::typed_pair(request.start, left, if padded { None } else { Some(right) })?;
                (
                    Some(job),
                    TypedInputs::Pair(
                        [left_proof, right_proof],
                        [left_policy, right_policy],
                        request.expected.count,
                    ),
                )
            }
            Operation::Empty => (
                Some(Job::empty(
                    self.pin,
                    chain,
                    request.start,
                    request.expected.level,
                )?),
                TypedInputs::Empty,
            ),
            Operation::Merge | Operation::Finalize => {
                let mut proofs = Vec::with_capacity(request.children.len());
                for (child, bytes) in request.children.iter().zip(&request.inputs) {
                    let proof = codec::decode_node(bytes)?;
                    self.registry.verify(
                        self.pin.profile(),
                        &proof,
                        &programs::statement(child.expected, child.operation.proof_mode()),
                    )?;
                    proofs.push(proof);
                }
                let inputs = if request.operation == Operation::Finalize {
                    TypedInputs::Finalize(proofs.pop().ok_or("missing finalizer child")?)
                } else {
                    let right = proofs.pop().ok_or("missing right child")?;
                    let left = proofs.pop().ok_or("missing left child")?;
                    TypedInputs::Merge([left, right])
                };
                (None, inputs)
            }
            _ => return Err("typed worker rejects legacy wrappers".into()),
        };
        if let Some(job) = derived {
            if job.id() != request.job
                || job.operation() != request.operation
                || job.expected() != request.expected
                || job.wallet_inputs() != request.manifest
            {
                return Err("typed packet differs from verified wallet/empty job".into());
            }
        }
        Ok(inputs)
    }

    /// Reverify public inputs under the host's independently supplied policy.
    /// The packet cannot supply its own height or issuance authorization.
    pub fn check_packet(
        &self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
        mut policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    ) -> Result<RequestInfo, Error> {
        let request = self.bound_packet(gate, bytes, chain)?;
        self.prepare(&request, &mut policy)?;
        Ok(RequestInfo {
            process_key: request.key,
            job: request.job,
            resources: request.resources,
            expected: request.expected,
        })
    }

    /// The caller keeps the single-use launch guard through result publication.
    /// Success retains preprocessing for the next packet. An error or unwind
    /// during proving poisons this worker; it must be drained and discarded.
    pub fn execute_packet(
        &mut self,
        gate: &WorkerGate,
        bytes: &[u8],
        chain: [u8; 32],
        mut policy: impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    ) -> Result<Vec<u8>, Error> {
        let started = Instant::now();
        let request = self.bound_packet(gate, bytes, chain)?;
        let inputs = self.prepare(&request, &mut policy)?;
        self.drain()?;
        let input_verification_ms = started.elapsed().as_millis();
        let mut session = self
            .session
            .take()
            .ok_or("typed worker is closed or poisoned")?;
        let before = session.stats();
        let _spill = crate::spill_alloc::SpillScope::arm();
        let started = Instant::now();
        let proof = match inputs {
            TypedInputs::Pair(wallets, policies, count) => {
                session.wrap_pair([&wallets[0], &wallets[1]], policies, count)?
            }
            TypedInputs::Empty => session.empty(chain, request.expected.level)?,
            TypedInputs::Merge(children) => session.merge(&children[0], &children[1])?,
            TypedInputs::Finalize(child) => session.finalize(&child)?,
        };
        let proving_ms = started.elapsed().as_millis();
        if proof.public != programs::statement(request.expected, request.operation.proof_mode()) {
            return Err("typed worker generated unexpected statement".into());
        }
        let serialized = Instant::now();
        let proof = codec::encode_node(&proof)?;
        let after = session.stats();
        let result = packet::encode_result_for(
            true,
            request.key,
            request.job,
            launch::request_digest(bytes)?,
            &proof,
            Timings {
                input_verification_ms,
                proving_ms,
                serialization_ms: serialized.elapsed().as_millis(),
            },
            CacheStats {
                setups: after.setups - before.setups,
                hits: after.hits - before.hits,
            },
        )?;
        self.session = Some(session);
        Ok(result)
    }

    /// Drops retained preprocessing. This does not establish GPU/OS termination.
    pub fn close(&mut self) {
        self.session = None;
    }
}

fn drain_backend(resources: Resources) -> Result<(), Error> {
    if resources.vram_bytes == 0 {
        return require_cpu_backend();
    }
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    return crate::block_v2::gpu_hash::drain().map_err(Into::into);
    #[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
    Err("typed GPU worker requires a GPU build and initialized backend".into())
}

#[path = "worker_typed_cached.rs"]
pub mod cached;

#[path = "worker_typed_process.rs"]
pub mod process;
