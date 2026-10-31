use super::*;
use lattica_prover_p3::block_v2::native_gpu::{PeriodicSource, TranscriptPart as DevicePart};
impl PeriodicSource for TranscriptAir {
    fn column_count(&self) -> usize {
        PERIODIC
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        if index >= PERIODIC {
            None
        } else {
            Some(if index == P_EVEN { 2 } else { ROWS_PER_PART })
        }
    }
    fn fill_column(&self, index: usize, out: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(out.len()) {
            return Err("transcript periodic shape".into());
        }
        for (row, value) in out.iter_mut().enumerate() {
            *value = Val::from_bool(match index {
                P_START => row == 0,
                P_END => row == 127,
                P_EVEN => row == 0,
                _ => row < 4,
            });
        }
        Ok(())
    }
}
impl TranscriptAir {
    pub(crate) fn prove_gpu(
        &self,
        context: &crate::execution::ProvingContext,
        values: &[PartValues],
        host_bytes: usize,
    ) -> Result<join::TranscriptArtifact, String> {
        if values.len() != self.parts.len() {
            return Err("transcript source count".into());
        }
        let parts = self
            .parts
            .iter()
            .zip(values)
            .map(|(kind, value)| match (kind, value) {
                (PartKind::Bytes32, PartValues::Bytes32(v)) => Ok(DevicePart::Bytes32(v)),
                (PartKind::PolynomialQ, PartValues::Polynomial(v)) => {
                    Ok(DevicePart::PolynomialQ(v))
                }
                (PartKind::PolynomialQhat, PartValues::Polynomial(v)) => {
                    Ok(DevicePart::PolynomialQhat(v))
                }
                _ => Err("transcript source kind"),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = context.prove_native_on_gpu(
            "pq_transcript_source",
            self,
            self,
            self.height,
            host_bytes,
            |trace| trace.transcript_source(&parts),
        )?;
        Ok(join::TranscriptArtifact {
            proof: result.proof,
            public_values: result
                .public_values
                .try_into()
                .map_err(|_| "transcript GPU public width")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_periodic_source_matches_air_schedule() {
        let air = TranscriptAir::new(vec![
            PartKind::Bytes32,
            PartKind::PolynomialQ,
            PartKind::PolynomialQhat,
        ])
        .unwrap();
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
    fn transcript_gpu_full_trace_matches_cpu() {
        let session = crate::opencl::Session::start(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: 32768,
        })
        .unwrap();
        let air = TranscriptAir::new(vec![
            PartKind::Bytes32,
            PartKind::PolynomialQ,
            PartKind::PolynomialQhat,
        ])
        .unwrap();
        let bytes = core::array::from_fn(|i| (i * 29 + 3) as u8);
        let q = core::array::from_fn(|i| (i as u64 * 65537) % Q);
        let qhat = core::array::from_fn(|i| QHAT - 1 - i as u64);
        let values = vec![
            PartValues::Bytes32(bytes),
            PartValues::Polynomial(q),
            PartValues::Polynomial(qhat),
        ];
        let expected = air.generate(&values).unwrap();
        let parts = [
            DevicePart::Bytes32(&bytes),
            DevicePart::PolynomialQ(&q),
            DevicePart::PolynomialQhat(&qhat),
        ];
        lattica_prover_p3::block_v2::native_gpu::audit_generated_trace(
            "pq_transcript_source_trace_parity",
            air.height,
            air.width(),
            8,
            1 << 30,
            &expected.trace.values,
            &expected.public_values,
            |trace| trace.transcript_source(&parts),
        )
        .unwrap();
        drop(session);
    }
}
