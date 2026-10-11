//! CLI logging around the shared, process-local GPU worker admission.
use super::Error;
use serde_json::Value;

pub(crate) fn validate<T>(additional: impl FnOnce(&Value) -> Result<T, Error>) -> Result<T, Error> {
    #[cfg(target_os = "linux")]
    {
        let admitted =
            lattica_prover_p3::block_v2::execution::gpu_admission::Admission::from_env()?;
        let result = additional(admitted.assignment())?;
        admitted.initialize_rayon()?;
        println!(
            "adaptive_worker_budget={} actual_rayon_threads={} actual_cpu_max={:?}",
            serde_json::to_string(admitted.assignment())?,
            admitted.rayon_threads(),
            admitted.cpu_max(),
        );
        Ok(result)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = additional;
        Err("public GPU worker admission requires Linux cgroup v2".into())
    }
}
