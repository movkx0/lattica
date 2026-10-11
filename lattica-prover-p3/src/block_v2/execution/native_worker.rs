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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    version: u32,
    registry: Registry<12>,
    profile: [u8; 32],
    chain: [u8; 32],
    executable: [u8; 32],
    launches: PathBuf,
    policy_context: Vec<u8>,
}

#[cfg(any(test, feature = "gpu"))]
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
        Ok(serde_json::from_slice(bytes)?)
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
        super::worker::typed::storage::admit_startup(peak.ram_bytes)?;
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

    #[cfg(any(test, feature = "gpu"))]
    fn into_worker(self, assignment: &serde_json::Value) -> Result<WorkerBootstrap, Error> {
        let (peak, _) = super::worker_budget::resources(assignment)?;
        super::worker::typed::storage::admit_startup(peak.ram_bytes)?;
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
    let bootstrap = Bootstrap::parse_fields(bytes)?;
    bootstrap.validate_shape()?;
    if transport::running_image_fingerprint()? != bootstrap.executable {
        return Err("native public worker executable differs from trusted bootstrap".into());
    }
    let metadata = std::fs::symlink_metadata(&bootstrap.launches)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("native public worker launch directory is not a directory".into());
    }
    let prepared = native_public_gpu::Prepared::from_env()?;
    let WorkerBootstrap {
        config,
        policy,
        launches,
    } = bootstrap.into_worker(prepared.assignment())?;
    prepared.initialize()?;
    struct Shutdown(bool);
    impl Drop for Shutdown {
        fn drop(&mut self) {
            if self.0 {
                if let Err(error) = gpu_hash::shutdown() {
                    eprintln!("native public worker cleanup rejected: {error}");
                }
            }
        }
    }
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

/// Duplicate a connected Unix stream without consuming the caller's descriptor.
/// A regular file, pipe, listener or non-Unix socket rejects before GPU setup.
#[cfg(feature = "gpu")]
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
