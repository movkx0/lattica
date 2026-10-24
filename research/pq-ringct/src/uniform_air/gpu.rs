use super::*;
use lattica_prover_p3::block_v2::native_gpu::{sampling::UniformKind, PeriodicSource};

fn gpu_kind(kind: Kind) -> UniformKind {
    match kind {
        Kind::SampleG4 => UniformKind::SampleG4,
        Kind::ExpandAlpha2 => UniformKind::ExpandAlpha2,
    }
}

impl PeriodicSource for UniformAir {
    fn column_count(&self) -> usize {
        2
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        (index < 2).then(|| self.height())
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("uniform periodic geometry".into());
        }
        for (row, value) in output.iter_mut().enumerate() {
            *value = Val::from_bool(match index {
                P_DRAW => row < self.kind.draws(),
                P_BYTE_HASH => row % 2 == 1 && row < self.kind.draws().div_ceil(2) * 2,
                _ => unreachable!(),
            });
        }
        Ok(())
    }
}

impl UniformAir {
    pub fn prove_gpu(
        &self,
        context: &crate::execution::ProvingContext,
        bytes: &[u8],
        host_bytes: usize,
    ) -> Result<join::UniformArtifact, String> {
        let kind = gpu_kind(self.kind);
        let proved = context.prove_native_on_gpu(
            "pq_uniform_gpu",
            self,
            self,
            self.height(),
            host_bytes,
            |trace| trace.uniform_trace(kind, bytes),
        )?;
        let artifact = join::UniformArtifact {
            public_values: proved
                .public_values
                .try_into()
                .map_err(|_| "uniform GPU public count")?,
            proof: proved.proof,
        };
        join::verify_native(self.kind, &artifact)
            .map_err(|error| format!("uniform GPU independent verification: {error:?}"))?;
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_uniform_periodics_and_device_layout_match_reference() {
        for kind in [Kind::SampleG4, Kind::ExpandAlpha2] {
            let air = UniformAir::new(kind);
            let device = gpu_kind(kind);
            assert_eq!(device.width(), WIDTH);
            assert_eq!(device.rows(), air.height());
            assert_eq!(device.input_bytes(), kind.draws() * 4);
            let expected = air.periodic_columns();
            for (index, column) in expected.iter().enumerate() {
                let mut output = vec![Val::ZERO; air.column_len(index).unwrap()];
                air.fill_column(index, &mut output).unwrap();
                assert_eq!(&output, column);
            }
            assert!(air.fill_column(0, &mut []).is_err());
            assert_eq!(air.column_len(2), None);
        }
    }

    #[cfg(feature = "native-trace-audit")]
    #[test]
    #[ignore = "requires exclusive admitted OpenCL resources; reads private fixture traces for differential testing"]
    fn uniform_gpu_full_trace_matches_cpu_for_rejections_and_padding() {
        let session = crate::opencl::Session::start(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: 2048,
        })
        .unwrap();
        for kind in [Kind::SampleG4, Kind::ExpandAlpha2] {
            let air = UniformAir::new(kind);
            let bytes: Vec<u8> = (0..kind.draws())
                .flat_map(|index| {
                    let value = if index % 13 == 0 {
                        u32::MAX
                    } else {
                        ((index as u64 * 65537) % Q) as u32
                    };
                    value.to_le_bytes()
                })
                .collect();
            let expected = air.generate(&bytes).unwrap();
            lattica_prover_p3::block_v2::native_gpu::audit_generated_trace(
                "pq_uniform_trace_parity",
                air.height(),
                WIDTH,
                8,
                1 << 30,
                &expected.trace.values,
                &expected.public_values,
                |trace| trace.uniform_trace(gpu_kind(kind), &bytes),
            )
            .unwrap();
        }
        // Trace-only audits intentionally have no commitment work; Drop closes
        // the session rather than claiming Session::finish proof acceptance.
        drop(session);
    }
}
