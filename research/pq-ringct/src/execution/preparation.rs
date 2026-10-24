//! Graph witness preparation is serialized and accounted separately from proofs.
use super::*;
use lattica_prover_p3::{
    block_v2::native_gpu::{self, OperationContext, WITNESS_PREPARATION_ENTRY},
    proving::{Backend, CoverageScope, Report, Stage},
};

fn validate_preparation_report(report: &Report) -> Result<(), String> {
    if report.entry_point != WITNESS_PREPARATION_ENTRY
        || report.policy != Policy::GpuRequired
        || !report.succeeded
        || !report.stage_coverage_complete
        || report.completion_rejected
        || report.observation_errors != 0
        || !report.components.is_empty()
        || report.capabilities.scope() != CoverageScope::Operation
        || report.capabilities.stages().len() != 1
        || report.observations.len() != 1
    {
        return Err("raw GPU preparation returned an incomplete operation report".into());
    }
    let capability = &report.capabilities.stages()[0];
    let observation = &report.observations[0];
    if capability.stage != Stage::WitnessTrace
        || capability.backend != Backend::OpenCl
        || observation.stage != Stage::WitnessTrace
        || observation.backend != Backend::OpenCl
        || observation.calls == 0
        || observation.calls != observation.completed_calls
        || observation.device_calls == 0
        || observation.device_calls > observation.calls
    {
        return Err("raw GPU preparation lacks completed witness-operation receipts".into());
    }
    Ok(())
}

impl ProvingContext {
    /// Prepare raw graph values and node roots under one bounded GPU scope.
    /// These receipts prove device execution, not relation validity. Source,
    /// component and recursive proofs must still be generated and verified.
    pub fn with_witness_preparation<T>(
        &self,
        host_bytes: usize,
        operation: impl FnOnce(&OperationContext<'_>) -> Result<T, String>,
    ) -> Result<(T, Report), String> {
        if self.policy() != Policy::GpuRequired || self.session.is_none() {
            return Err("witness preparation requires an owned GPU-required context".into());
        }
        if host_bytes == 0 || host_bytes as u64 > self.host_bytes {
            return Err("witness preparation host allowance exceeds worker allowance".into());
        }
        self.release_prepared()?;
        let _serial = self
            .registry
            .try_borrow_mut()
            .map_err(|_| "reentrant witness preparation operation")?;
        let started = Instant::now();
        let result = native_gpu::with_operations(host_bytes, self.request, operation).and_then(
            |(value, report)| {
                validate_preparation_report(&report)?;
                Ok((value, report))
            },
        );
        self.diagnostics.witness_preparation_finished(
            started.elapsed().as_secs_f64(),
            result.as_ref().ok().map(|(_, report)| report),
        );
        if let Err(ref message) = result {
            self.diagnostics
                .failure("witness_preparation", Value::Null, message, None);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_worker_cannot_enter_raw_gpu_preparation() {
        let worker = ProvingContext::cpu(1 << 30).unwrap();
        let result = worker.with_witness_preparation(8192, |_| -> Result<(), String> {
            panic!("CPU worker reached raw GPU preparation")
        });
        assert!(result.is_err());
        let report = worker.report();
        assert_eq!(report["operations"]["native_gpu_calls"], 0);
        assert_eq!(report["operations"]["native_cpu_calls"], 0);
        assert_eq!(report["operations"]["witness_preparation_calls"], 0);
    }

    #[test]
    #[ignore = "requires an exclusive admitted OpenCL window; raw node roots only"]
    fn raw_node_commitments_match_existing_cpu_framing_and_keep_separate_counts() {
        use crate::rust_verify::{committed_backend, constraints_ntt, Q, QHAT};
        use p3_field::PrimeField64;
        let worker = ProvingContext::opencl(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: 2048,
        })
        .unwrap();
        let (_, receipt) = worker
            .with_witness_preparation(8192, |operation| {
                for modulus in [Q, QHAT] {
                    let values = std::array::from_fn(|i| [0, 1, modulus - 1, modulus / 2][i % 4]);
                    let expected = constraints_ntt::commit_values(
                        constraints_ntt::POLYNOMIAL_DOMAIN,
                        modulus,
                        &values,
                    )
                    .map(|v| v.as_canonical_u64());
                    assert_eq!(operation.commit_canonical_node(&values, modulus)?, expected);
                }
                let signed = std::array::from_fn(|i| [-2147483647, 2147483647, -1, 0, 1][i % 5]);
                let expected =
                    constraints_ntt::commit_signed_values(&signed).map(|v| v.as_canonical_u64());
                assert_eq!(operation.commit_signed_node(&signed)?, expected);
                let bytes = std::array::from_fn(|i| (i * 7) as u8);
                let expected =
                    crate::shake_air::commit_bytes(committed_backend::BYTES32_DOMAIN, &bytes)
                        .map(|v| v.as_canonical_u64());
                assert_eq!(operation.commit_bytes32_node(&bytes)?, expected);
                Ok(())
            })
            .unwrap();
        assert_eq!(receipt.observations[0].completed_calls, 4);
        let before = worker.report();
        assert_eq!(before["operations"]["native_gpu_calls"], 0);
        assert_eq!(before["operations"]["prove_calls"], 0);
        assert_eq!(before["operations"]["witness_preparation_calls"], 1);
        assert_eq!(
            before["operations"]["witness_preparation_complete_reports"],
            1
        );

        // A GPU range failure must poison the scope even if a caller ignores
        // the first returned error. It must not produce another complete report.
        let rejected = worker.with_witness_preparation(8192, |operation| {
            assert!(operation.commit_signed_node(&[i64::MIN; 256]).is_err());
            assert!(operation.commit_canonical_node(&[0; 256], Q).is_err());
            Ok(())
        });
        assert!(rejected.is_err());
        let after = worker.report();
        assert_eq!(after["operations"]["native_gpu_calls"], 0);
        assert_eq!(after["operations"]["witness_preparation_calls"], 2);
        assert_eq!(
            after["operations"]["witness_preparation_complete_reports"],
            1
        );
        // Preparation-only work has no PCS commitments; Drop closes the owner
        // without claiming proof-only Session::finish acceptance.
        drop(worker);
    }
}
