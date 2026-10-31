use super::*;
use lattica_prover_p3::block_v2::native_gpu::PeriodicSource;
impl PeriodicSource for ProofAir {
    fn column_count(&self) -> usize {
        PERIODIC
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < PERIODIC).then_some(SCHEDULE_PERIOD)
    }
    fn fill_column(&self, index: usize, out: &mut [Val]) -> Result<(), String> {
        if index >= PERIODIC || out.len() != SCHEDULE_PERIOD {
            return Err("private periodic shape".into());
        }
        for (row, value) in out.iter_mut().enumerate() {
            *value = Val::from_bool(match index {
                PERIODIC_START => row == 0,
                PERIODIC_END => row == 63,
                _ => row < 2,
            });
        }
        Ok(())
    }
}
impl ProofAir {
    pub(crate) fn prove_gpu(
        &self,
        context: &crate::execution::ProvingContext,
        input: &ProofValues,
        host_bytes: usize,
    ) -> Result<join::ProofArtifact, String> {
        let result = context.prove_native_on_gpu(
            "pq_private_source",
            self,
            self,
            HEIGHT,
            host_bytes,
            |trace| trace.private_source(&input.polynomials, &input.alpha),
        )?;
        Ok(join::ProofArtifact {
            proof: result.proof,
            public_values: result
                .public_values
                .try_into()
                .map_err(|_| "private GPU public width")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_periodic_source_matches_air_schedule() {
        let air = ProofAir;
        let expected = air.periodic_columns();
        assert_eq!(air.column_count(), expected.len());
        for (index, column) in expected.iter().enumerate() {
            assert_eq!(air.column_len(index), Some(column.len()));
            let mut got = vec![Val::ZERO; column.len()];
            air.fill_column(index, &mut got).unwrap();
            assert_eq!(&got, column);
            assert!(air.fill_column(index, &mut []).is_err());
        }
        assert_eq!(air.column_len(expected.len()), None);
    }

    #[cfg(feature = "native-trace-audit")]
    #[test]
    #[ignore = "requires exclusive admitted OpenCL resources; full CPU/GPU trace differential"]
    fn private_gpu_full_trace_matches_cpu() {
        let session = crate::opencl::Session::start(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: HEIGHT,
        })
        .unwrap();
        let input = ProofValues {
            polynomials: (0..POLYNOMIALS)
                .map(|p| {
                    core::array::from_fn(|j| match class(p) {
                        0 | 1 => (j * 17 + p) as i64,
                        2 => ((j + p) % 3) as i64 - 1,
                        _ => ((j + p) % 251) as i64 - 125,
                    })
                })
                .collect(),
            alpha: core::array::from_fn(|i| (i * 23 + 7) as u8),
        };
        let expected = ProofAir.generate(&input).unwrap();
        lattica_prover_p3::block_v2::native_gpu::audit_generated_trace(
            "pq_private_source_trace_parity",
            HEIGHT,
            WIDTH,
            4,
            1 << 30,
            &expected.trace.values,
            &expected.public_values,
            |trace| trace.private_source(&input.polynomials, &input.alpha),
        )
        .unwrap();
        drop(session);
    }
}
