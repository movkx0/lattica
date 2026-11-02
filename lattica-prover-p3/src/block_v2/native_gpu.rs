//! Startup for native callers of the existing wallet proving ABI.

use super::{gpu_hash, gpu_startup, legacy_wallet, wallet_worker};
use crate::proving::Request;

pub mod arithmetic;
mod crypto;
mod research;
pub use crypto::{AesTraceSpec, ShakeTraceSpec};
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream"))]
pub use research::shake_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream"))]
pub use research::aes_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::graph_source_preparation;

pub use research::{
    prove, GeneratedTrace, NativeAir, NativeAirBuilder, PeriodicSource, ProvedNative, TraceContext,
};

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

mod sources;
pub use sources::TranscriptPart;

pub mod sampling;

#[cfg(feature = "native-trace-audit")]
mod trace_audit;
#[cfg(feature = "native-trace-audit")]
pub use trace_audit::audit_generated_trace;

mod operations;
pub use operations::{with_operations, OperationContext, RawPreparationWorkspaceStorage, WITNESS_PREPARATION_ENTRY};
pub(crate) mod operations_hash;
pub mod operations_batch;
pub use operations_batch::{NodeCommitment, FieldCommitment, RawCommitmentBatchStorage};

mod operations_crypto;
pub use operations_crypto::{UniformProfile, SparseProfile};
pub mod operations_arithmetic;

/// Native private-spend creation, distinct from native AIR/STARK proving.
pub mod private_spend;

#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "gpu"))]
pub use super::gpu_hash::engine::device::raw_graph_resources::RawGraphOperationStorage;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::shake_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::aes_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::graph_source_recording;


#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::shake_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::aes_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::graph_source_output;


#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_shake;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_aes;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_graph_source;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::uniform_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::transcript_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::sparse_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::uniform_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::transcript_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::sparse_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::uniform_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::transcript_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::sparse_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_uniform;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_transcript;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::affine_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::affine_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::affine_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_affine;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_sparse;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::ntt_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::ntt_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::ntt_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_ntt;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::mul_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::mul_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::mul_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_mul;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::g_bound_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::g_bound_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::g_bound_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_g_bound;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::permutation_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::permutation_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::permutation_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_permutation;

#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::linear_map_preparation;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::linear_map_recording;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::linear_map_output;
#[cfg(all(not(debug_assertions), target_os = "linux", target_arch = "x86_64", feature = "gpu-bounded-info", feature = "stream", feature = "ringct-research-quota"))]
pub use research::owned_linear_map;
