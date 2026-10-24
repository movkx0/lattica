//! GPU preparation of variable producer commitments. Descriptor and circuit
//! registration hashes remain host control metadata.
use super::*;
use crate::execution::ProvingContext;
#[cfg(feature = "opencl")]
use lattica_prover_p3::block_v2::native_gpu::OperationContext;
use lattica_prover_p3::proving::Policy;

pub(super) fn validate_manifest(
    plan: &graph_tree::Plan,
    graph: &UnprovedRelationGraph,
    context: &graph_tree::GraphContext,
    execution: Option<&ProvingContext>,
) -> Result<()> {
    let manifest = if let Some(execution) = execution.filter(|e| e.policy() == Policy::GpuRequired)
    {
        #[cfg(not(feature = "opencl"))]
        {
            let _ = execution;
            return Err(Error("GPU producer preparation requires OpenCL".into()));
        }
        #[cfg(feature = "opencl")]
        {
            let host = usize::try_from(execution.host_bytes()).map_err(err)?;
            let (manifest, _) = execution
                .with_witness_preparation(host, |operations| {
                    plan.node_manifest_hint_on_gpu(graph, operations)
                        .map_err(|e| e.to_string())
                })
                .map_err(err)?;
            manifest
        }
    } else {
        plan.node_manifest_hint(graph).map_err(err)?
    };
    require(
        manifest == context.node_manifest,
        "producer graph manifest mismatch",
    )
}

impl Factory<'_> {
    pub(super) fn gpu_required(&self) -> bool {
        self.execution
            .is_some_and(|e| e.policy() == Policy::GpuRequired)
    }

    #[cfg(feature = "opencl")]
    fn prepare_on_gpu<T>(
        &self,
        prepare: impl FnOnce(&OperationContext<'_>) -> Result<T>,
    ) -> Result<T> {
        let execution = self
            .execution
            .filter(|e| e.policy() == Policy::GpuRequired)
            .ok_or_else(|| Error("GPU producer preparation requires an explicit context".into()))?;
        let host = usize::try_from(execution.host_bytes()).map_err(err)?;
        let (prepared, _) = execution
            .with_witness_preparation(host, |operations| {
                prepare(operations).map_err(|e| e.to_string())
            })
            .map_err(err)?;
        Ok(prepared)
    }

    pub(super) fn alpha_roots_with_gpu(
        &self,
        operation: usize,
        descriptor: &Descriptor,
    ) -> Result<[[Val; 4]; 2]> {
        #[cfg(not(feature = "opencl"))]
        {
            let _ = (operation, descriptor);
            Err(Error("GPU producer preparation requires OpenCL".into()))
        }
        #[cfg(feature = "opencl")]
        self.prepare_on_gpu(|operations| {
            let Some(Operation::ExpandAlpha {
                seed,
                canonical,
                signed,
            }) = self.graph.operations().get(operation)
            else {
                return Err(Error("producer operation is not ExpandAlpha".into()));
            };
            let bytes = descriptor
                .aes()?
                .input_bytes(&self.graph.byte_string(*seed).values);
            operations
                .admit_field_chunks(bytes.len().div_ceil(2))
                .map_err(err)?;
            let words = bytes
                .chunks(2)
                .map(|pair| u64::from(pair[0]) | (u64::from(*pair.get(1).unwrap_or(&0)) << 8))
                .collect::<Vec<_>>();
            let input = operations
                .commit_field_chunks(
                    [crate::aes_air::AES_INPUT_DOMAIN, bytes.len() as u64, 0, 0],
                    &words,
                )
                .map_err(err)?
                .map(Val::from_u64);
            let output = match descriptor {
                Descriptor::AlphaUniform => {
                    let roots = [
                        self.polynomial_root(
                            operation,
                            canonical[0],
                            PolynomialKind::Canonical { modulus: Q },
                        )?,
                        self.polynomial_root(
                            operation,
                            canonical[1],
                            PolynomialKind::Canonical { modulus: Q },
                        )?,
                    ];
                    let initial = UniformAir::new(uniform_air::Kind::ExpandAlpha2)
                        .bundle_initial()
                        .map(|v| v.as_canonical_u64());
                    operations.admit_field_chunks(8).map_err(err)?;
                    let words = roots
                        .iter()
                        .flatten()
                        .map(|v| v.as_canonical_u64())
                        .collect::<Vec<_>>();
                    operations
                        .commit_field_chunks(initial, &words)
                        .map_err(err)?
                        .map(Val::from_u64)
                }
                Descriptor::AlphaSparse => {
                    self.polynomial_root(operation, *signed, PolynomialKind::Signed { bound: 1 })?
                }
                _ => return Err(Error("wrong Alpha branch descriptor".into())),
            };
            Ok([input, output])
        })
    }

    pub(super) fn transcript_bundle(
        &self,
        air: &TranscriptAir,
        roots: &[[Val; 4]],
    ) -> Result<[Val; 4]> {
        if !self.gpu_required() {
            return air.bundle(roots).map_err(err);
        }
        #[cfg(not(feature = "opencl"))]
        {
            Err(Error("GPU producer preparation requires OpenCL".into()))
        }
        #[cfg(feature = "opencl")]
        self.prepare_on_gpu(|operations| {
            require(
                roots.len() == air.parts().len(),
                "transcript ordered root count",
            )?;
            let count = roots
                .len()
                .checked_mul(8)
                .ok_or_else(|| Error("transcript bundle length overflow".into()))?;
            operations.admit_field_chunks(count).map_err(err)?;
            let mut words = Vec::with_capacity(count);
            for (index, (&kind, root)) in air.parts().iter().zip(roots).enumerate() {
                let tag = match kind {
                    PartKind::Bytes32 => 1,
                    PartKind::PolynomialQ => 2,
                    PartKind::PolynomialQhat => 3,
                };
                words.extend([tag, kind.byte_len() as u64, index as u64, 0]);
                words.extend(root.iter().map(|v| v.as_canonical_u64()));
            }
            operations
                .commit_field_chunks(
                    [
                        crate::transcript_air::BUNDLE_DOMAIN,
                        roots.len() as u64,
                        air.byte_len() as u64,
                        1,
                    ],
                    &words,
                )
                .map(|root| root.map(Val::from_u64))
                .map_err(err)
        })
    }
}
