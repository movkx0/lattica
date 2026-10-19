//! Local native bootstrap for the existing typed public-worker protocol.
//!
//! The host supplies independently approved public registry/policy data. This
//! encoding is not a worker packet, a network authentication scheme, or registry
//! approval. The runtime assignment remains a separate, independently supplied
//! file whose complete contents are included in the initial protocol identity.

use super::{
    job::TypedRegistryContext,
    policy_context::PolicyContext,
    transport,
    worker::typed::process::{self, Config},
};
use crate::block_v2::{profile, recursive::Error, typed_recursive::Registry};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const MAX_BOOTSTRAP_BYTES: usize = crate::native_gpu::PUBLIC_WORKER_BOOTSTRAP_MAX_BYTES;
const VERSION: u32 = 1;

#[cfg(feature = "gpu-cuda")]
#[path = "native_worker_cuda.rs"]
mod cuda;

#[cfg(feature = "gpu-cuda")]
pub(crate) use cuda::serve;

#[cfg(feature = "gpu-cuda")]
pub use crate::cuda_compute::{Identity as CudaDevice, Snapshot as CudaSnapshot};
#[cfg(feature = "gpu-cuda")]
pub use cuda::serve_owned as serve_owned_cuda;

/// Bounded CUDA discovery for an explicit controller inventory request. This
/// creates no worker runtime and confers no resource or timing approval.
/// Workers must enter their startup fence before calling any device discovery.
#[cfg(feature = "gpu-cuda")]
pub fn cuda_inventory() -> Result<Vec<CudaDevice>, Error> {
    Ok(crate::cuda_compute::inventory()?)
}

#[path = "native_worker_decode.rs"]
mod decode;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    version: u32,
    #[serde(deserialize_with = "decode::registry")]
    registry: Registry<12>,
    profile: [u8; 32],
    chain: [u8; 32],
    executable: [u8; 32],
    #[serde(deserialize_with = "decode::path")]
    launches: PathBuf,
    #[serde(deserialize_with = "decode::policy")]
    policy_context: Vec<u8>,
}

#[cfg(any(test, feature = "gpu", feature = "gpu-cuda"))]
struct WorkerBootstrap {
    config: Config,
    policy: PolicyContext,
    launches: PathBuf,
}

impl Bootstrap {
    /// The caller must approve these values independently of the worker and
    /// input proofs. Constructing a bootstrap confers no chain acceptance.
    pub fn new(
        registry: Registry<12>,
        profile: [u8; 32],
        chain: [u8; 32],
        executable: [u8; 32],
        launches: PathBuf,
        policy_context: &PolicyContext,
    ) -> Result<Self, Error> {
        let value = Self {
            version: VERSION,
            registry,
            profile,
            chain,
            executable,
            launches,
            policy_context: policy_context.encode(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), Error> {
        if self.version != VERSION || self.executable == [0; 32] {
            return Err("native public bootstrap version/executable".into());
        }
        transport::absolute_path(&self.launches)?;
        if self
            .registry
            .caps
            .iter()
            .any(|cap| cap.len() != 1 << profile::CAP_HEIGHT)
        {
            return Err("native public registry cap shape".into());
        }
        Ok(())
    }

    fn validate(&self) -> Result<(TypedRegistryContext<'_>, PolicyContext), Error> {
        self.validate_shape()?;
        let context = TypedRegistryContext::new(&self.registry, self.profile)?;
        let policy = PolicyContext::decode(&self.policy_context)?;
        Ok((context, policy))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > MAX_BOOTSTRAP_BYTES {
            return Err("native public bootstrap exceeds bound".into());
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let value = Self::parse_fields(bytes)?;
        value.validate()?;
        Ok(value)
    }

    // Parsing grants no registry authority. Native startup consumes these
    // fields through into_worker before it can initialize the GPU.
    fn parse_fields(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_BOOTSTRAP_BYTES {
            return Err("native public bootstrap size".into());
        }
        decode::layout()?;
        Ok(serde_json::from_slice(bytes)?)
    }

    // The independently checked assignment must cover decoding before the
    // bootstrap can allocate. Registry approval still happens in into_worker.
    #[cfg(any(test, feature = "gpu", feature = "gpu-cuda"))]
    fn parse_for_worker(bytes: &[u8], assignment: &serde_json::Value) -> Result<Self, Error> {
        decode::admit(assignment)?;
        Self::parse_fields(bytes)
    }

    fn identity(&self, assignment: &serde_json::Value) -> Result<[u8; 32], Error> {
        let bytes = self.identity_bytes(assignment)?;
        process::configuration_digest(&bytes)
    }

    fn identity_bytes(&self, assignment: &serde_json::Value) -> Result<Vec<u8>, Error> {
        // Preserve the sorted object keys of the original serde_json::Value
        // encoding without cloning its assignment, caps or policy backing.
        // This is the existing protocol identity, not a new bootstrap codec.
        #[derive(Serialize)]
        struct RegistryFields<'a> {
            caps: &'a crate::block_v2::machine::programs::Caps<12>,
            height: usize,
        }
        #[derive(Serialize)]
        struct BootstrapFields<'a> {
            chain: &'a [u8; 32],
            executable: &'a [u8; 32],
            launches: &'a std::path::Path,
            policy_context: &'a [u8],
            profile: &'a [u8; 32],
            registry: RegistryFields<'a>,
            version: u32,
        }
        #[derive(Serialize)]
        struct IdentityFields<'a> {
            assignment: &'a serde_json::Value,
            native_bootstrap: BootstrapFields<'a>,
        }
        identity_encoding(&IdentityFields {
            assignment,
            native_bootstrap: BootstrapFields {
                chain: &self.chain,
                executable: &self.executable,
                launches: &self.launches,
                policy_context: &self.policy_context,
                profile: &self.profile,
                registry: RegistryFields {
                    caps: &self.registry.caps,
                    height: self.registry.height,
                },
                version: self.version,
            },
        })
    }

    /// Both coordinator and worker derive the same existing HELLO prefix from
    /// independently supplied bootstrap and assignment data.
    pub fn config(&self, assignment: &serde_json::Value) -> Result<Config, Error> {
        Ok(self.config_and_policy(assignment)?.0)
    }

    fn config_and_policy(
        &self,
        assignment: &serde_json::Value,
    ) -> Result<(Config, PolicyContext), Error> {
        let (peak, _) = super::worker_budget::resources(assignment)?;
        super::worker::typed::storage::admit_startup(peak.ram_bytes, peak.threads)?;
        let (context, policy) = self.validate()?;
        let config = Config::from_checked_assignment(
            context.to_owned_registry(),
            context.pin(),
            self.chain,
            self.executable,
            self.identity(assignment)?,
            assignment,
        )?;
        Ok((config, policy))
    }

    #[cfg(any(test, feature = "gpu", feature = "gpu-cuda"))]
    fn into_worker(self, assignment: &serde_json::Value) -> Result<WorkerBootstrap, Error> {
        let (peak, _) = super::worker_budget::resources(assignment)?;
        super::worker::typed::storage::admit_startup(peak.ram_bytes, peak.threads)?;
        self.validate_shape()?;
        let identity = self.identity(assignment)?;
        let registry = crate::block_v2::typed_recursive::CheckedRegistry::new(self.registry)?;
        let context = TypedRegistryContext::from_approved(registry.as_ref(), self.profile)?;
        let pin = context.pin();
        let policy = PolicyContext::decode(&self.policy_context)?;
        let config = Config::from_checked_assignment(
            registry,
            pin,
            self.chain,
            self.executable,
            identity,
            assignment,
        )?;
        // Move the checked registry and launch path. The original policy byte
        // backing is dropped here, before GPU setup and the persistent loop.
        Ok(WorkerBootstrap {
            config,
            policy,
            launches: self.launches,
        })
    }
}

/// Reject an oversized identity before allocating output. Both passes borrow
/// immutable input; the second writes into the exact admitted capacity. Caller
/// input ownership, JSON decoding and process RSS need enclosing reservations.
fn identity_encoding(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .filter(|&length| length <= process::CONFIGURATION_IDENTITY_MAX_BYTES)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "typed process configuration size",
                    )
                })?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Counter(0);
    serde_json::to_writer(&mut count, value)?;
    let mut bytes =
        super::bounded_io::byte_capacity(count.0, process::CONFIGURATION_IDENTITY_MAX_BYTES)?;
    bytes.resize(count.0, 0);
    let mut cursor = std::io::Cursor::new(bytes.as_mut_slice());
    serde_json::to_writer(&mut cursor, value)?;
    if cursor.position() != count.0 as u64 {
        return Err("native public identity length changed".into());
    }
    Ok(bytes)
}

#[cfg(feature = "gpu")]
pub(crate) fn serve(socket: std::os::unix::net::UnixStream, bytes: &[u8]) -> Result<u64, Error> {
    use crate::block_v2::{gpu_hash, native_public_gpu};
    let prepared = native_public_gpu::Prepared::from_env()?;
    let bootstrap = Bootstrap::parse_for_worker(bytes, prepared.assignment())?;
    bootstrap.validate_shape()?;
    super::worker::typed::storage::check_native_inputs(bytes.len(), bootstrap.launches.capacity())?;
    if transport::running_image_fingerprint()? != bootstrap.executable {
        return Err("native public worker executable differs from trusted bootstrap".into());
    }
    let metadata = std::fs::symlink_metadata(&bootstrap.launches)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("native public worker launch directory is not a directory".into());
    }
    let WorkerBootstrap {
        config,
        policy,
        launches,
    } = bootstrap.into_worker(prepared.assignment())?;
    #[cfg(target_env = "gnu")]
    crate::spill_alloc::host_backing::report("native_bootstrap", 0);
    prepared.initialize()?;
    let mut shutdown = Shutdown(true);
    process::serve(
        socket,
        config,
        &launches,
        |artifact| policy.policy(artifact),
        || {
            gpu_hash::shutdown()?;
            shutdown.0 = false;
            Ok(())
        },
    )
}

#[cfg(feature = "gpu")]
struct Shutdown(bool);

#[cfg(feature = "gpu")]
impl Drop for Shutdown {
    fn drop(&mut self) {
        if self.0 {
            if let Err(error) = crate::block_v2::gpu_hash::shutdown() {
                eprintln!("public worker cleanup rejected: {error}");
            }
        }
    }
}

/// Serve the existing public-worker protocol after independently trusted,
/// bounded CLI preparation. Admission precedes CPU preparation (which may use
/// Rayon); device creation follows it. Only configuration and fixed policy
/// slots survive preparation. This preserves the caller's protocol identity
/// and grants neither registry approval nor permission to apply a result.
///
/// The enclosing runtime must fence this exact service and keep its assignment,
/// environment and cgroup fixed until exit. A returned error is not evidence
/// that a coordinator may release its workspace reservation.
#[cfg(feature = "gpu")]
pub fn serve_owned(
    socket: std::os::unix::net::UnixStream,
    launches: &std::path::Path,
    prepare: impl FnOnce(&serde_json::Value) -> Result<(Config, PolicyContext), Error>,
) -> Result<(u64, crate::block_v2::gpu_hash::Snapshot), Error> {
    use crate::block_v2::{gpu_hash, native_public_gpu};
    let prepared = native_public_gpu::Prepared::from_env()?;
    transport::absolute_path(launches)?;
    let metadata = std::fs::symlink_metadata(launches)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("public worker launch directory is not a directory".into());
    }
    // Reject files, listeners and disconnected descriptors before admission
    // starts threads or creates a device. Ownership stays with this function.
    socket.peer_addr()?;
    let (config, policy) = prepared.initialize_with(|assignment| {
        let (config, policy) = prepare(assignment)?;
        config.check_admitted_assignment(assignment)?;
        Ok((config, policy))
    })?;
    let mut shutdown = Shutdown(true);
    let mut stats = None;
    let count = process::serve(
        socket,
        config,
        launches,
        |artifact| policy.policy(artifact),
        || {
            stats = gpu_hash::report("owned public GPU workspace");
            gpu_hash::shutdown()?;
            shutdown.0 = false;
            Ok(())
        },
    )?;
    Ok((count, stats.ok_or("missing owned public GPU telemetry")?))
}

/// Duplicate a connected Unix stream without consuming the caller's descriptor.
/// A regular file, pipe, listener or non-Unix socket rejects before GPU setup.
#[cfg(any(feature = "gpu", feature = "gpu-cuda"))]
pub(crate) fn duplicate_socket(
    fd: std::os::fd::RawFd,
) -> Result<std::os::unix::net::UnixStream, Error> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    for (option, expected) in [
        (libc::SO_DOMAIN, libc::AF_UNIX),
        (libc::SO_TYPE, libc::SOCK_STREAM),
    ] {
        let mut value: libc::c_int = 0;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&mut value as *mut libc::c_int).cast(),
                &mut size,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if size as usize != std::mem::size_of_val(&value) || value != expected {
            return Err("native public service requires a Unix stream socket".into());
        }
    }
    let socket = std::os::unix::net::UnixStream::from(owned);
    socket.peer_addr()?;
    Ok(socket)
}

#[cfg(test)]
#[path = "native_worker_tests.rs"]
mod tests;

#[cfg(all(test, feature = "gpu"))]
#[path = "native_worker_gpu_tests.rs"]
mod gpu_tests;
