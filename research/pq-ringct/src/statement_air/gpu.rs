use super::*;
use lattica_prover_p3::block_v2::native_gpu::PeriodicSource;
impl PeriodicSource for StatementAir {
    fn column_count(&self) -> usize { 2 }
    fn column_len(&self, index: usize) -> Option<usize> { (index < 2).then_some(64) }
    fn fill_column(&self, index: usize, out: &mut [Val]) -> Result<(), String> {
        if index >= 2 || out.len() != 64 { return Err("statement periodic shape".into()); }
        let phase = if index == 0 { 3 } else { 2 };
        for (row, value) in out.iter_mut().enumerate() { *value = Val::from_bool(row == phase); }
        Ok(())
    }
}

impl StatementAir {
    pub(crate) fn prove_gpu(
        &self,
        context: &crate::execution::ProvingContext,
        bytes: &[u8],
        host_bytes: usize,
    ) -> Result<bundle::StatementProof, String> {
        let result = context.prove_native_on_gpu(
            "pq_statement",
            self,
            self,
            HEIGHT,
            host_bytes,
            |trace| trace.statement_source(bytes, &self.setup_seed),
        )?;
        Ok(bundle::StatementProof {
            proof: result.proof,
            public_values: result
                .public_values
                .try_into()
                .map_err(|_| "statement GPU public width")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_periodic_source_matches_air_schedule() {
        let air = StatementAir {
            setup_seed: core::array::from_fn(|i| (i * 7 + 11) as u8),
        };
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
    fn statement_gpu_full_trace_matches_cpu() {
        let session = crate::opencl::Session::start(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: HEIGHT,
        })
        .unwrap();
        let bytes: Vec<u8> = [0x11, 0x22, 0x33, 0x44].repeat(STATEMENT_BYTES / 4);
        let air = StatementAir {
            setup_seed: bytes[..32].try_into().unwrap(),
        };
        // Malformed coefficients/serials are deliberately retained as hints,
        // exactly like the CPU generator; AIR acceptance is a separate check.
        let expected = air.generate(&bytes).unwrap();
        lattica_prover_p3::block_v2::native_gpu::audit_generated_trace(
            "pq_statement_trace_parity",
            HEIGHT,
            WIDTH,
            8,
            2 << 30,
            &expected.trace.values,
            &expected.public_values,
            |trace| trace.statement_source(&bytes, &air.setup_seed),
        )
        .unwrap();
        drop(session);
    }
}
