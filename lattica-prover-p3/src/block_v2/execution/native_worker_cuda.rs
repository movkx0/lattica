//! Explicit CUDA selection for the existing native public-worker service.
//! The independently supplied assignment is part of the unchanged HELLO
//! identity. Device handles never enter a packet or coordinator configuration.

use super::*;
use crate::{
    block_v2::{
        execution::{gpu_admission::Admission, worker::typed::storage, worker_budget},
        machine::compiler_constants::ConstructionLimits,
        typed_recursive::{storage as session_storage, CudaLimits},
    },
    cuda_compute::{Limits as DeviceLimits, Runtime},
    proving::{Policy, Request},
};

struct Settings {
    device: DeviceLimits,
    session: CudaLimits,
    host_output_bytes: u64,
}

impl Settings {
    /// Pure admission: no threads, driver calls or runtime state are created.
    fn from_assignment(assignment: &serde_json::Value) -> Result<Self, Error> {
        if assignment["backend"].as_str() != Some("cuda") {
            return Err("CUDA public worker requires an explicit cuda assignment".into());
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Construction {
            version: u32,
            program_host_bytes: usize,
            wires: usize,
            input_values: usize,
        }
        let construction = Construction::deserialize(&assignment["cuda"])?;
        if construction.version != 1 {
            return Err("unsupported CUDA worker construction assignment".into());
        }
        let session = CudaLimits {
            construction: ConstructionLimits {
                program_host_bytes: construction.program_host_bytes,
                wires: construction.wires,
                input_values: construction.input_values,
            }
            .validate()?,
        };
        let number = |key: &str| -> Result<u64, Error> {
            assignment["gpu"][key]
                .as_u64()
                .ok_or_else(|| format!("missing CUDA GPU budget {key}").into())
        };
        let device = DeviceLimits {
            managed_bytes: usize::try_from(number("managed_bytes")?)?,
            max_allocation_bytes: usize::try_from(number("max_allocation_bytes")?)?,
            context_reserve_bytes: usize::try_from(number("context_bytes")?)?,
            headroom_bytes: usize::try_from(number("headroom_bytes")?)?,
            ..DeviceLimits::default()
        };
        device.validate()?;
        let uuid = assignment["gpu"]["uuid"]
            .as_str()
            .ok_or("missing CUDA UUID")?;
        crate::gpu_lease::normalized_uuid(uuid)?;
        let (peak, _) = worker_budget::resources(assignment)?;
        storage::admit_startup(peak.ram_bytes, peak.threads)?;
        let (_, cache) = worker_budget::preprocessing_cache(assignment)?;
        let host_output_bytes = number("host_output_bytes")?;
        let session_bytes =
            storage::session_memory_bytes(peak.ram_bytes, peak.threads)?.min(host_output_bytes);
        let active = session_storage::active_memory_bytes(session_bytes, cache)?;
        if session.construction.workspace_bytes()? as u64 > active {
            return Err("CUDA construction exceeds admitted active worker RAM".into());
        }
        Ok(Self {
            device,
            session,
            host_output_bytes,
        })
    }
}

pub(crate) fn serve(socket: std::os::unix::net::UnixStream, bytes: &[u8]) -> Result<u64, Error> {
    if Request::from_env()?.policy != Policy::GpuRequired || cfg!(debug_assertions) {
        return Err("CUDA public worker requires release mode and gpu-required".into());
    }
    let admission = Admission::from_env()?;
    let settings = Settings::from_assignment(admission.assignment())?;
    let bootstrap = Bootstrap::parse_for_worker(bytes, admission.assignment())?;
    bootstrap.validate_shape()?;
    storage::check_native_inputs(bytes.len(), bootstrap.launches.capacity())?;
    if transport::running_image_fingerprint()? != bootstrap.executable {
        return Err("native CUDA worker executable differs from trusted bootstrap".into());
    }
    let metadata = std::fs::symlink_metadata(&bootstrap.launches)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("native CUDA worker launch directory is not a directory".into());
    }
    socket.peer_addr()?;
    // Establish actual process/allocator limits before bounded registry work.
    // A failed preparation never creates a device or sends READY.
    admission.initialize_rayon()?;
    let WorkerBootstrap {
        config,
        policy,
        launches,
    } = bootstrap.into_worker(admission.assignment())?;
    let runtime = Runtime::new(
        admission.assignment()["gpu"]["uuid"]
            .as_str()
            .ok_or("missing CUDA UUID")?,
        settings.device,
    )?;
    // Do not retain assignment parsing backing alongside the proof workspace.
    drop(admission);
    process::serve_cuda(
        socket,
        config,
        &launches,
        |artifact| policy.policy(artifact),
        runtime,
        settings.session,
        settings.host_output_bytes,
    )
}

#[cfg(test)]
#[path = "native_worker_cuda_tests.rs"]
mod tests;
