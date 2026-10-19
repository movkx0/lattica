//! Typed public-proof worker with one reusable registered-program workspace.
//!
//! The runtime owns device initialization and must reserve and enforce `resources`
//! for this worker's entire lifetime, including idle cached preprocessing. A
//! result is neither proof acceptance nor a worker-stop receipt. In particular,
//! GPU shutdown/drain and OS reconciliation remain the runtime's responsibility.

use super::packet::{Request, RequestInfo};
use super::*;
use crate::block_v2::{
    execution::launch::{self, WorkerGate},
    typed_recursive::{Policy, Registry as TypedRegistry, Session},
};

enum TypedInputs {
    Pair([WalletProof; 2], [Policy; 2], u8),
    Empty,
    Merge([crate::block_v2::typed_recursive::VerifiedNodeInput; 2]),
    Finalize(crate::block_v2::typed_recursive::VerifiedNodeInput),
}

struct PreparedInputs {
    // Fields drop in declaration order: all proofs precede their allowance.
    values: TypedInputs,
    _storage: codec::proofs::Storage,
}

impl PreparedInputs {
    fn with<T>(self, body: impl FnOnce(TypedInputs) -> Result<T, Error>) -> Result<T, Error> {
        // Keep the cumulative decode allowance alive until the owned inputs
        // have been consumed and the entire proving call has returned.
        let result = body(self.values);
        drop(self._storage);
        result
    }
}

#[path = "worker_typed_coordinator.rs"]
pub(crate) mod coordinator;

#[path = "worker_typed_storage.rs"]
pub(crate) mod storage;

#[cfg(test)]
#[path = "worker_typed_registry_tests.rs"]
mod registry_tests;

pub struct TypedWorker {
    pin: RegistryPin,
    resources: Resources,
    request_resources: Resources,
    session: Option<Session<12>>,
    // Retain the fence even when a failed proving call poisons the session.
    #[cfg(feature = "gpu-cuda")]
    cuda: Option<crate::cuda_compute::Runtime>,
}

impl TypedWorker {
    /// Does not initialize a GPU or register preprocessing. Resource ownership
    /// must already be established by the enclosing runtime before proving.
    pub fn new(
        registry: TypedRegistry<12>,
        pin: RegistryPin,
        resources: Resources,
    ) -> Result<Self, Error> {
        resources.validate_capacity()?;
        storage::admit_startup(resources.ram_bytes, resources.threads)?;
        let registry = crate::block_v2::typed_recursive::CheckedRegistry::new(registry)?;
        Self::from_checked(registry, pin, resources)
    }

    fn from_checked(
        registry: crate::block_v2::typed_recursive::CheckedRegistry,
        pin: RegistryPin,
        resources: Resources,
    ) -> Result<Self, Error> {
        resources.validate_capacity()?;
        storage::admit_startup(resources.ram_bytes, resources.threads)?;
        pin.check_typed_approved(&registry.as_ref())?;
        let session = Session::from_checked(
            registry,
            storage::session_memory_bytes(resources.ram_bytes, resources.threads)?,
        )?;
        Ok(Self {
            pin,
            resources,
            request_resources: resources,
            session: Some(session),
            #[cfg(feature = "gpu-cuda")]
            cuda: None,
        })
    }

    #[cfg(feature = "gpu-cuda")]
    fn from_checked_cuda(
        registry: crate::block_v2::typed_recursive::CheckedRegistry,
        pin: RegistryPin,
        resources: Resources,
        runtime: &crate::cuda_compute::Runtime,
        limits: crate::block_v2::typed_recursive::CudaLimits,
        host_output_bytes: u64,
    ) -> Result<Self, Error> {
        resources.validate_capacity()?;
        storage::admit_startup(resources.ram_bytes, resources.threads)?;
        pin.check_typed_approved(&registry.as_ref())?;
        if resources.vram_bytes != runtime.limits().managed_bytes as u64 {
            return Err("CUDA worker device allowance differs from assignment".into());
        }
        let session = Session::from_checked_cuda(
            registry,
            storage::session_memory_bytes(resources.ram_bytes, resources.threads)?
                .min(host_output_bytes),
            runtime,
            limits,
        )?;
        Ok(Self {
            pin,
            resources,
            request_resources: resources,
            session: Some(session),
            cuda: Some(runtime.clone()),
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
        #[cfg(feature = "gpu-cuda")]
        if let Some(runtime) = &self.cuda {
            return runtime.finish().map_err(Into::into);
        }
        drain_backend(self.resources)
    }

    fn bound_packet<'a>(
        &self,
        gate: &WorkerGate,
        bytes: &'a [u8],
        chain: [u8; 32],
    ) -> Result<Request<&'a [u8]>, Error> {
        self.stats()?;
        storage::check_buffers(bytes.len(), packet::MAX_RESULT_BYTES)?;
        gate.token().check_request(bytes)?;
        let request = Request::decode(bytes, self.pin, chain)?;
        request.bind(gate.token(), bytes)?;
        if request.resources != self.request_resources {
            return Err("typed worker resource assignment changed".into());
        }
        let metadata_bytes = request.children.capacity()
            * std::mem::size_of::<super::packet::Child>()
            + request.manifest.capacity() * std::mem::size_of::<ArtifactRef>()
            + request.inputs.capacity() * std::mem::size_of::<&[u8]>();
        let metadata_limit_bytes = 2
            * (std::mem::size_of::<super::packet::Child>()
                + std::mem::size_of::<ArtifactRef>()
                + std::mem::size_of::<&[u8]>());
        eprintln!("borrowed_request_packet packet_bytes={} borrowed_proof_bytes={} metadata_bytes={} metadata_limit_bytes={} proof_copies=0",
            bytes.len(), request.inputs.iter().map(|proof| proof.len()).sum::<usize>(), metadata_bytes, metadata_limit_bytes);
        Ok(request)
    }

    fn prepare(
        &self,
        request: &Request<&[u8]>,
        policy: &mut impl FnMut(ArtifactRef) -> Result<Policy, Error>,
    ) -> Result<PreparedInputs, Error> {
        request.validate()?;
        if request.pin != self.pin || request.resources != self.request_resources {
            return Err("typed worker registry/resource mismatch".into());
        }
        let storage = codec::proofs::Storage::new(
            self.resources
                .ram_bytes
                .min(codec::proofs::INPUT_STORAGE_LIMIT as u64) as usize,
        );
        let chain = request.expected.context.chain_id;
        let registry = self
            .session
            .as_ref()
            .ok_or("typed worker is poisoned")?
            .registry_approval()?;
        let mut wallet = |index: usize| -> Result<(VerifiedWallet, WalletProof, Policy), Error> {
            let bytes = &request.inputs[index];
            let policy = policy(request.manifest[index])?;
            let (ticket, proof) = VerifiedWallet::verify_typed_owned_approved(
                self.pin, &registry, chain, policy, bytes, &storage,
            )?;
            Ok((ticket, proof, policy))
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
                let child = |index: usize| {
                    let child = &request.children[index];
                    let proof = storage.node(&request.inputs[index])?;
                    crate::block_v2::typed_recursive::VerifiedNodeInput::verify(
                        &registry,
                        proof,
                        &programs::statement(child.expected, child.operation.proof_mode()),
                    )
                };
                let inputs = if request.operation == Operation::Finalize {
                    TypedInputs::Finalize(child(0)?)
                } else {
                    TypedInputs::Merge([child(0)?, child(1)?])
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
        Ok(PreparedInputs {
            values: inputs,
            _storage: storage,
        })
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
        let proof = inputs.with(|inputs| match inputs {
            TypedInputs::Pair(wallets, policies, count) => {
                session.wrap_pair([&wallets[0], &wallets[1]], policies, count)
            }
            TypedInputs::Empty => session.empty(chain, request.expected.level),
            TypedInputs::Merge([left, right]) => session.merge_verified(left, right),
            TypedInputs::Finalize(child) => session.finalize_verified(child),
        })?;
        let proving_ms = started.elapsed().as_millis();
        if proof.public != programs::statement(request.expected, request.operation.proof_mode()) {
            return Err("typed worker generated unexpected statement".into());
        }
        let serialized = Instant::now();
        let result = packet::ResultPacket::node(&proof)?;
        drop(proof);
        let after = session.stats();
        let result = result.finish(
            true,
            request.key,
            request.job,
            launch::request_digest(bytes)?,
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
        storage::check_buffers(bytes.len(), result.capacity())?;
        self.session = Some(session);
        Ok(result)
    }

    /// Drops retained preprocessing. This does not establish GPU/OS termination.
    pub fn close(&mut self) {
        self.session = None;
        #[cfg(feature = "gpu-cuda")]
        {
            self.cuda = None;
        }
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
