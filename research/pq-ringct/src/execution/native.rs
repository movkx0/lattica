//! Serial native OpenCL boundary and bounded receipt composition.
use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{
        self, GeneratedTrace, NativeAir, PeriodicSource, ProvedNative, TraceContext,
    },
    proving::{Backend, CoverageScope, Report, Stage},
};

fn validate_native_report(report: &Report) -> Result<(), String> {
    if report.policy != Policy::GpuRequired
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || !report.components.is_empty()
        || report.capabilities.scope() != CoverageScope::ProofRequest
    {
        return Err("native GPU callback returned an incomplete proof report".into());
    }
    let required = Stage::ARITHMETIC
        .into_iter()
        .filter(|stage| *stage != Stage::Lookup);
    if report.capabilities.stages().len() != Stage::ARITHMETIC.len() - 1 {
        return Err("native GPU report has a different single-AIR stage inventory".into());
    }
    for stage in required {
        if report
            .capabilities
            .stages()
            .iter()
            .filter(|c| c.stage == stage && c.backend == Backend::OpenCl)
            .count()
            != 1
            || report
                .observations
                .iter()
                .filter(|o| o.stage == stage)
                .count()
                != 1
            || !report.observations.iter().any(|o| {
                o.stage == stage
                    && o.backend == Backend::OpenCl
                    && o.calls == o.completed_calls
                    && o.completed_calls > 0
                    && o.device_calls > 0
            })
        {
            return Err("native GPU report lacks a completed OpenCL stage receipt".into());
        }
    }
    if report.observations.iter().any(|o| {
        o.calls != o.completed_calls
            || (o.stage == Stage::Serialization && o.backend != Backend::Cpu)
            || (o.stage != Stage::Serialization
                && (!Stage::ARITHMETIC.contains(&o.stage) || o.stage == Stage::Lookup))
    }) {
        return Err("native GPU report contains an unaccounted stage".into());
    }
    Ok(())
}

impl ProvingContext {
    /// Release the prepared program, serialize native GPU work, and retain only
    /// bounded public receipt totals. The caller keeps the full returned report
    /// for higher-level composition and independently verifies the native proof.
    pub fn with_native_gpu<T>(
        &self,
        f: impl FnOnce(Request) -> Result<(T, Report), String>,
    ) -> Result<(T, Report), String> {
        self.diagnostics.mark_stark_work_attempted();
        if self.policy() != Policy::GpuRequired || self.session.is_none() {
            return Err("native GPU operation requires an owned OpenCL context".into());
        }
        self.release_prepared()?;
        let _serial = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant native GPU operation")?;
        let started = Instant::now();
        let result = f(self.request).and_then(|(value, report)| {
            validate_native_report(&report)
                .map_err(|message| format!("native GPU entry {}: {message}", report.entry_point))?;
            Ok((value, report))
        });
        self.diagnostics.native_gpu_finished(
            started.elapsed().as_secs_f64(),
            result.as_ref().ok().map(|(_, report)| report),
        );
        if let Err(ref message) = result {
            self.diagnostics
                .failure("native_gpu", Value::Null, message, None);
        }
        result
    }

    /// Convenience adapter with this worker's policy and a separately declared
    /// native host allowance no greater than the worker allowance.
    pub fn prove_native_on_gpu<A: NativeAir, S: PeriodicSource + ?Sized>(
        &self,
        entry: &'static str,
        air: &A,
        periodic: &S,
        rows: usize,
        host_bytes: usize,
        generate: impl FnOnce(&TraceContext<'_>) -> Result<GeneratedTrace, String>,
    ) -> Result<ProvedNative, String> {
        self.diagnostics.mark_stark_work_attempted();
        if host_bytes as u64 > self.host_bytes {
            return Err("native host allowance exceeds worker allowance".into());
        }
        let session = self
            .session
            .as_ref()
            .ok_or("native GPU operation requires an owned OpenCL context")?;
        session.check_rows(rows).map_err(|message| {
            self.diagnostics.failure(
                "native_gpu_admission",
                json!({"entry":entry,
                "rows":rows,"maximum_rows":session.limits().max_rows}),
                &message,
                None,
            );
            message
        })?;
        let ((proof, public_values), report) = self.with_native_gpu(|request| {
            let proved =
                native_gpu::prove(entry, air, periodic, rows, host_bytes, request, generate)
                    .map_err(|message| format!("native GPU entry {entry}: {message}"))?;
            Ok(((proved.proof, proved.public_values), proved.report))
        })?;
        Ok(ProvedNative {
            proof,
            public_values,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_worker_rejects_native_gpu_before_running_callback() {
        let context = ProvingContext::cpu(1 << 30).unwrap();
        let result: Result<((), Report), String> = context.with_native_gpu(|_| {
            panic!("CPU worker must reject before native GPU callback");
        });
        assert!(result.is_err());
        let report = context.report();
        assert_eq!(report["operations"]["native_cpu_calls"], 0);
        assert_eq!(report["operations"]["native_gpu_calls"], 0);
        assert_eq!(report["prepared_entries"], 0);
    }
}
