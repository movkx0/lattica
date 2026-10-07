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
    let (peak, jobs) = budget::resources(assignment)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CacheAdmission {
        entries: usize,
        reserve_bytes: u64,
    }
    let cache = match assignment.get("preprocessing_cache") {
        Some(value) => serde_json::from_value::<CacheAdmission>(value.clone())?,
        None => CacheAdmission {
            entries: 1,
            reserve_bytes: 0,
        },
    };
    let identity =
        serde_json::to_vec(&json!({"expected":prepared.expected,"assignment":assignment}))?;
    Config::new(
        prepared.registry.clone(),
        prepared.pin,
        prepared.expected.chain,
        peak,
        jobs,
        image_fingerprint(&std::env::current_exe()?)?,
        worker_process::configuration_digest(&identity)?,
    )?
    .with_preprocessing_cache(cache.entries, cache.reserve_bytes)
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
