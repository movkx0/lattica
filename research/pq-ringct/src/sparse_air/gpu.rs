use super::*;
use lattica_prover_p3::block_v2::native_gpu::{sampling::SparseKind, PeriodicSource};

fn gpu_kind(kind: Kind) -> SparseKind {
    match kind {
        Kind::AlphaPrime39 => SparseKind::AlphaPrime39,
        Kind::ChallengeX44 => SparseKind::ChallengeX44,
    }
}

impl PeriodicSource for SparseAir {
    fn column_count(&self) -> usize {
        PERIODIC
    }
    fn column_len(&self, index: usize) -> Option<usize> {
        if index < P_BUFFER {
            Some(HEIGHT)
        } else if index < P_POLY {
            Some(8)
        } else if index < PERIODIC {
            Some(64)
        } else {
            None
        }
    }
    fn fill_column(&self, index: usize, output: &mut [Val]) -> Result<(), String> {
        if self.column_len(index) != Some(output.len()) {
            return Err("sparse periodic geometry".into());
        }
        for (row, value) in output.iter_mut().enumerate() {
            *value = Val::from_bool(match index {
                P_RAW => row < self.kind.input_len(),
                P_DRAW => row >= self.kind.sign_bytes() && row < self.kind.input_len(),
                P_BYTE_HASH => row < self.kind.input_len().div_ceil(8) * 8 && row % 8 == 7,
                P_POLY_HASH => row >= 192,
                _ if index < P_BUFFER => {
                    index - P_SIGN < self.kind.sign_bytes() && row == index - P_SIGN
                }
                _ if index < P_POLY => row == index - P_BUFFER,
                _ => row == index - P_POLY,
            });
        }
        Ok(())
    }
}

impl SparseAir {
    pub fn prove_gpu(
        &self,
        context: &crate::execution::ProvingContext,
        bytes: &[u8],
        host_bytes: usize,
    ) -> Result<join::SparseArtifact, String> {
        let kind = gpu_kind(self.kind);
        let proved = context.prove_native_on_gpu(
            "pq_sparse_gpu",
            self,
            self,
            HEIGHT,
            host_bytes,
            |trace| trace.sparse_trace(kind, bytes),
        )?;
        let artifact = join::SparseArtifact {
            public_values: proved
                .public_values
                .try_into()
                .map_err(|_| "sparse GPU public count")?,
            proof: proved.proof,
        };
        join::verify_native(self.kind, &artifact)
            .map_err(|error| format!("sparse GPU independent verification: {error:?}"))?;
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_sparse_periodics_and_device_layout_match_reference() {
        for kind in [Kind::AlphaPrime39, Kind::ChallengeX44] {
            let air = SparseAir::new(kind);
            let device = gpu_kind(kind);
            assert_eq!(device.width(), WIDTH);
            assert_eq!(device.rows(), HEIGHT);
            assert_eq!(device.input_bytes(), kind.input_len());
            let expected = air.periodic_columns();
            assert_eq!(expected.len(), air.column_count());
            for (index, column) in expected.iter().enumerate() {
                let mut output = vec![Val::ZERO; air.column_len(index).unwrap()];
                air.fill_column(index, &mut output).unwrap();
                assert_eq!(&output, column);
            }
            assert!(air.fill_column(0, &mut []).is_err());
            assert_eq!(air.column_len(PERIODIC), None);
        }
    }

    #[cfg(feature = "native-trace-audit")]
    #[test]
    #[ignore = "requires exclusive admitted OpenCL resources; reads private fixture traces for differential testing"]
    fn sparse_gpu_full_trace_matches_cpu_for_signs_duplicates_and_padding() {
        let session = crate::opencl::Session::start(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: 256,
        })
        .unwrap();
        for kind in [Kind::AlphaPrime39, Kind::ChallengeX44] {
            let air = SparseAir::new(kind);
            let mut bytes = vec![0u8; kind.input_len()];
            for (index, byte) in bytes.iter_mut().take(kind.sign_bytes()).enumerate() {
                *byte = (0xa5u8).rotate_left(index as u32);
            }
            for (index, byte) in bytes.iter_mut().skip(kind.sign_bytes()).enumerate() {
                // Repeated index pairs force rejection while enough unique
                // samples remain to satisfy both fixed sampler predicates.
                *byte = (index / 2) as u8;
            }
            let expected = air.generate(&bytes).unwrap();
            lattica_prover_p3::block_v2::native_gpu::audit_generated_trace(
                "pq_sparse_trace_parity",
                HEIGHT,
                WIDTH,
                PUBLIC_VALUES,
                1 << 30,
                &expected.trace.values,
                &expected.public_values,
                |trace| trace.sparse_trace(gpu_kind(kind), &bytes),
            )
            .unwrap();
        }
        drop(session);
    }
}
