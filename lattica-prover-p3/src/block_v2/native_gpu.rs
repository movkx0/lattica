//! Startup for native callers of the existing wallet proving ABI.

use super::{gpu_hash, gpu_startup, legacy_wallet, wallet_worker};
use crate::proving::Request;

pub(crate) fn initialize() -> Result<(), String> {
    initialize_with(finish_startup)
}

fn initialize_with(complete: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    if std::env::var_os("LATTICA_V2_WORKER_BUDGET").is_some() {
        return Err("native private wallet startup does not admit worker assignments".into());
    }
    let worker = wallet_worker::prepare()?;
    Request::from_env()
        .and_then(|request| request.admit(&legacy_wallet::capabilities()))
        .map_err(|e| e.to_string())?;
    gpu_startup::preflight()?;
    worker.initialize_runtime()?;
    gpu_startup::select()?;
    let mut created = gpu_startup::Startup::begin()?;
    let result = complete().and_then(|_| wallet_worker::finish(worker));
    if result.is_ok() {
        created.accept();
    }
    result
}

#[cfg(test)]
pub(crate) fn reject_after_engine_for_test(panic: bool) -> Result<(), String> {
    initialize_with(|| {
        assert!(!panic, "native startup fixture after engine allocation");
        Err("native startup fixture rejected after engine allocation".into())
    })
}

fn finish_startup() -> Result<(), String> {
    if !gpu_hash::initialize_resident_from_env()? || !legacy_wallet::startup_admitted() {
        return Err("native GPU proving admission failed".into());
    }
    Ok(())
}
