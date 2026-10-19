//! Persistent child dispatch using the enclosing qualified GPU service's caps.
use super::*;
use lattica_prover_p3::block_v2::execution::{
    transport::image_fingerprint,
    worker::typed::process::{self as worker_process, Config},
};
use std::{os::fd::AsFd, os::unix::net::UnixStream};

pub(super) fn config(prepared: &Prepared, worker_bytes: u64) -> Result<Config, Error> {
    let assignment: serde_json::Value =
        read_json(Path::new(&std::env::var("LATTICA_V2_WORKER_BUDGET")?))?;
    if assignment["host"]["worker_bytes"].as_u64() != Some(worker_bytes) {
        return Err("typed process host budget mismatch".into());
    }
    assigned_config(prepared, &assignment)
}

pub(super) fn assigned_config(
    prepared: &Prepared,
    assignment: &serde_json::Value,
) -> Result<Config, Error> {
    let identity =
        serde_json::to_vec(&json!({"expected":prepared.expected,"assignment":assignment}))?;
    Config::from_assignment(
        prepared.registry.clone(),
        prepared.pin,
        prepared.expected.chain,
        image_fingerprint(&std::env::current_exe()?)?,
        worker_process::configuration_digest(&identity)?,
        assignment,
    )
}

pub(in super::super) fn prove(
    dir: &Path,
    pinned: &Path,
    out: &Path,
    worker_bytes: u64,
) -> Result<(), Error> {
    let prepared = prepare_for_backend(dir, pinned, true)?;
    proving::run(
        prepared,
        out,
        worker_bytes,
        true,
        Some((dir, pinned)),
        || Ok(()),
    )
}

pub(in super::super) fn serve(
    dir: &Path,
    pinned: &Path,
    launches: &Path,
    worker_bytes: u64,
    shutdown: impl FnMut() -> Result<(), Error>,
) -> Result<u64, Error> {
    let prepared = prepare_for_backend(dir, pinned, true)?;
    let config = config(&prepared, worker_bytes)?;
    let socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    worker_process::serve(
        socket,
        config,
        launches,
        |identity| {
            prepared
                .policies
                .iter()
                .find(|(a, _)| *a == identity)
                .map(|(_, p)| *p)
                .ok_or_else(|| "wallet absent from independent child policy".into())
        },
        shutdown,
    )
}

#[cfg(feature = "gpu")]
pub(in super::super) fn serve_owned(
    dir: &Path,
    pinned: &Path,
    launches: &Path,
    worker_bytes: u64,
) -> Result<(u64, lattica_prover_p3::block_v2::gpu_hash::Snapshot), Error> {
    use lattica_prover_p3::block_v2::execution::{native_worker, policy_context::PolicyContext};
    let socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    native_worker::serve_owned(socket, launches, |assignment| {
        super::super::typed_gpu::validate_owned_assignment(assignment, worker_bytes)?;
        super::super::typed_gpu::require_owned_geometry(dir)?;
        let prepared = prepare_for_backend(dir, pinned, true)?;
        let config = assigned_config(&prepared, assignment)?;
        let policy =
            PolicyContext::new(prepared.selection.root().id().to_bytes(), prepared.policies)?;
        // Do not retain Selection, wallet proof backing or a second registry
        // during GPU startup or the persistent loop.
        Ok((config, policy))
    })
}

#[cfg(feature = "gpu-cuda")]
pub(in super::super) fn serve_owned(
    dir: &Path,
    pinned: &Path,
    launches: &Path,
    worker_bytes: u64,
    arguments: &[String],
) -> Result<
    (
        u64,
        lattica_prover_p3::block_v2::execution::native_worker::CudaSnapshot,
        u64,
    ),
    Error,
> {
    use lattica_prover_p3::block_v2::execution::{
        native_worker, policy_context::PolicyContext, startup,
    };
    let socket = UnixStream::from(std::io::stdin().as_fd().try_clone_to_owned()?);
    let mut limit = 0;
    let (count, stats) = native_worker::serve_owned_cuda(socket, launches, |assignment| {
        super::super::typed_gpu::validate_owned_assignment(assignment, worker_bytes)?;
        limit = assignment["pool_job_limit"]
            .as_u64()
            .ok_or("missing CUDA job bound")?;
        // Admission and Rayon setup precede this callback. Discovery remains
        // inside serve_owned_cuda, after this exact one-use fence is consumed.
        startup::enter_until_process_exit(
            Path::new(
                assignment["startup_guard"]
                    .as_str()
                    .ok_or("missing CUDA startup fence")?,
            ),
            arguments,
            assignment,
        )?;
        super::super::typed_gpu::require_owned_geometry(dir)?;
        let prepared = prepare_for_backend(dir, pinned, true)?;
        let config = assigned_config(&prepared, assignment)?;
        let policy =
            PolicyContext::new(prepared.selection.root().id().to_bytes(), prepared.policies)?;
        Ok((config, policy))
    })?;
    Ok((count, stats, limit))
}
