use super::*;
use crate::{
    affine_air::{AffineInput, AffineRoots, RegisteredAffineAir},
    g_bound_air::join::RegisteredGBoundAir,
    linear_map_air::RegisteredLinearMapAir,
    ntt_air::RegisteredNttAir,
    permutation_air::{PermutationInput, RegisteredPermutationAir},
    poly_air::RegisteredMulAir,
};

pub(super) fn estimate(kind: &ComponentKind, count: usize) -> Result<Option<ResourceEstimate>> {
    let (width, height, public_values) = match kind {
        ComponentKind::Affine { kind, modulus } => {
            let key = RegisteredAffineAir::new(*kind, *modulus, count).map_err(component_error)?;
            (key.air().width(), key.air().height(), 4)
        }
        ComponentKind::Ntt { modulus } => {
            let key = RegisteredNttAir::new(*modulus, count).map_err(component_error)?;
            (
                key.air().width(),
                key.air().height,
                key.air().public_values(),
            )
        }
        ComponentKind::Mul { modulus } => {
            let key = RegisteredMulAir::new(*modulus, count).map_err(component_error)?;
            (
                key.air().width(),
                key.air().height,
                key.air().public_values(),
            )
        }
        ComponentKind::GBound { bound } => {
            RegisteredGBoundAir::new(*bound).map_err(component_error)?;
            (
                crate::g_bound_air::WIDTH,
                crate::g_bound_air::HEIGHT,
                crate::g_bound_air::PUBLIC_VALUES,
            )
        }
        ComponentKind::Permutation { kind } => (
            RegisteredPermutationAir::new(*kind).air().width(),
            crate::permutation_air::HEIGHT,
            8,
        ),
        ComponentKind::LinearMap { descriptor } => {
            let key = RegisteredLinearMapAir::new(descriptor.clone());
            (
                key.air().width(),
                key.air().height(),
                key.air().public_values(),
            )
        }
        ComponentKind::External => return Ok(None),
    };
    let trace_bytes = (width as u64)
        .checked_mul(height as u64)
        .and_then(|cells| cells.checked_mul(8))
        .ok_or_else(|| error("trace size overflow"))?;
    let estimated_prover_bytes = trace_bytes
        .checked_mul(2 << profile::LOG_BLOWUP)
        .and_then(|bytes| bytes.checked_add(256 << 20))
        .ok_or_else(|| error("prover size overflow"))?;
    Ok(Some(ResourceEstimate {
        width,
        height,
        public_values,
        trace_bytes,
        estimated_prover_bytes,
    }))
}

impl GraphProofPlan<'_> {
    pub(super) fn expected_public_values(&self, batch: &PlannedBatch) -> Result<Vec<Val>> {
        batch
            .expected_public
            .clone()
            .ok_or_else(|| error("batch has no prepared algebra public roots"))
    }

    pub(super) fn collect_expected_public_values(
        &self,
        batch: &PlannedBatch,
        affine_bundle: impl FnOnce(AffineKind, u64, usize, &[AffineRoots]) -> Result<[Val; 4]>,
    ) -> Result<Vec<Val>> {
        if batch.kind == ComponentKind::External {
            return Err(error("external operation has no algebra proof"));
        }
        let mut public = Vec::new();
        let mut affine_roots = Vec::new();
        for &index in &batch.indices {
            if classify(self.graph, index)? != batch.kind {
                return Err(error("heterogeneous batch"));
            }
            match (&batch.kind, &self.graph.operations()[index]) {
                (ComponentKind::Affine { kind, modulus }, operation) => {
                    let canonical = PolynomialKind::Canonical { modulus: *modulus };
                    let (left, right, output, input_kind) = match *operation {
                        Operation::Add {
                            left,
                            right,
                            output,
                            ..
                        }
                        | Operation::Sub {
                            left,
                            right,
                            output,
                            ..
                        } => (left, Some(right), output, canonical),
                        Operation::SignedToCanonical {
                            input,
                            output,
                            bound,
                            ..
                        } => (input, None, output, PolynomialKind::Signed { bound }),
                        _ => return Err(error("affine operation")),
                    };
                    if kind.is_conversion() != right.is_none() {
                        return Err(error("affine operand shape"));
                    }
                    affine_roots.push(AffineRoots {
                        left: self.root(left, input_kind)?,
                        right: right.map(|id| self.root(id, canonical)).transpose()?,
                        output: self.output_root(index, output, canonical)?,
                    });
                }
                (ComponentKind::Ntt { modulus }, Operation::Ntt { input, output, .. }) => {
                    let kind = PolynomialKind::Canonical { modulus: *modulus };
                    public.extend(self.root(*input, kind)?);
                    public.extend(self.output_root(index, *output, kind)?);
                }
                (
                    ComponentKind::Mul { modulus },
                    Operation::Mul {
                        left,
                        right,
                        output,
                        ..
                    },
                ) => {
                    let kind = PolynomialKind::Canonical { modulus: *modulus };
                    public.extend(self.root(*left, kind)?);
                    public.extend(self.root(*right, kind)?);
                    public.extend(self.output_root(index, *output, kind)?);
                }
                (ComponentKind::GBound { bound }, Operation::GBound { f, x, .. }) => {
                    let key = RegisteredGBoundAir::new(*bound).map_err(component_error)?;
                    public.extend(self.root(
                        *f,
                        PolynomialKind::Signed {
                            bound: key.air().f_bound(),
                        },
                    )?);
                    public.extend(self.root(*x, PolynomialKind::Signed { bound: 1 })?);
                }
                (ComponentKind::Permutation { kind }, _) => {
                    let (_, input, output) =
                        crate::permutation_air::graph::graph_operation(self.graph, index)
                            .map_err(|e| error(format!("permutation descriptor: {e:?}")))?;
                    let kind = match kind {
                        PermutationKind::AutomorphismQ => PolynomialKind::Canonical {
                            modulus: crate::rust_verify::Q,
                        },
                        PermutationKind::InverseChallenge => PolynomialKind::Signed { bound: 1 },
                    };
                    public.extend(self.root(input, kind)?);
                    public.extend(self.output_root(index, output, kind)?);
                }
                (ComponentKind::LinearMap { descriptor }, _) => {
                    let map = crate::linear_map_air::graph_operation(self.graph, index)
                        .map_err(|e| error(format!("linear map descriptor: {e:?}")))?;
                    for (&id, &kind) in map.inputs.iter().zip(descriptor.inputs()) {
                        public.extend(self.root(id, kind)?);
                    }
                    public.extend(self.output_root(index, map.output, descriptor.output())?);
                }
                _ => return Err(error("operation/component mismatch")),
            }
        }
        if let ComponentKind::Affine { kind, modulus } = batch.kind {
            public = affine_bundle(kind, modulus, batch.indices.len(), &affine_roots)?.to_vec();
        }
        Ok(public)
    }

    /// Generate one actual component proof from native witness hints, then
    /// verify it and its exact ordered roots. This does not mark graph coverage.
    pub fn prove_batch(&self, batch_index: usize) -> Result<ComponentArtifact> {
        let batch = self.batch(batch_index)?;
        let first = batch.indices[0];
        let artifact = match &batch.kind {
            ComponentKind::Affine { kind, modulus } => {
                let inputs = batch
                    .indices
                    .iter()
                    .map(|&index| match self.graph.operations()[index] {
                        Operation::Add { left, right, .. } | Operation::Sub { left, right, .. } => {
                            Ok(AffineInput::Binary {
                                left: self.canonical(left)?,
                                right: self.canonical(right)?,
                            })
                        }
                        Operation::SignedToCanonical { input, .. } => {
                            Ok(AffineInput::Signed(self.signed(input)?))
                        }
                        _ => Err(error("affine operation")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                ComponentArtifact::Affine(
                    RegisteredAffineAir::new(*kind, *modulus, inputs.len())
                        .map_err(component_error)?
                        .prove(&inputs)
                        .map_err(component_error)?,
                )
            }
            ComponentKind::Ntt { modulus } => {
                let inputs = batch
                    .indices
                    .iter()
                    .map(|&index| match self.graph.operations()[index] {
                        Operation::Ntt { input, .. } => self.canonical(input),
                        _ => Err(error("NTT operation")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                ComponentArtifact::Ntt(
                    RegisteredNttAir::new(*modulus, inputs.len())
                        .map_err(component_error)?
                        .prove(&inputs)
                        .map_err(component_error)?,
                )
            }
            ComponentKind::Mul { modulus } => {
                let mut left = Vec::new();
                let mut right = Vec::new();
                for &index in &batch.indices {
                    let Operation::Mul {
                        left: a, right: b, ..
                    } = self.graph.operations()[index]
                    else {
                        return Err(error("product operation"));
                    };
                    left.push(self.canonical(a)?);
                    right.push(self.canonical(b)?);
                }
                ComponentArtifact::Mul(
                    RegisteredMulAir::new(*modulus, left.len())
                        .map_err(component_error)?
                        .prove(&left, &right)
                        .map_err(component_error)?,
                )
            }
            ComponentKind::GBound { bound } => {
                let Operation::GBound { f, x, .. } = self.graph.operations()[first] else {
                    return Err(error("GBound operation"));
                };
                ComponentArtifact::GBound(
                    RegisteredGBoundAir::new(*bound)
                        .map_err(component_error)?
                        .prove(&self.signed(f)?, &self.signed(x)?)
                        .map_err(component_error)?,
                )
            }
            ComponentKind::Permutation { kind } => {
                let (_, input, _) =
                    crate::permutation_air::graph::graph_operation(self.graph, first)
                        .map_err(|e| error(format!("permutation descriptor: {e:?}")))?;
                let input = match kind {
                    PermutationKind::AutomorphismQ => {
                        PermutationInput::Canonical(self.canonical(input)?)
                    }
                    PermutationKind::InverseChallenge => {
                        PermutationInput::Signed(self.signed(input)?)
                    }
                };
                ComponentArtifact::Permutation(
                    RegisteredPermutationAir::new(*kind)
                        .prove(&input)
                        .map_err(component_error)?,
                )
            }
            ComponentKind::LinearMap { descriptor } => {
                let map = crate::linear_map_air::graph_operation(self.graph, first)
                    .map_err(|e| error(format!("linear map descriptor: {e:?}")))?;
                let inputs: Vec<_> = map
                    .inputs
                    .iter()
                    .map(|&id| self.graph.polynomial(id).values.clone())
                    .collect();
                ComponentArtifact::LinearMap(
                    RegisteredLinearMapAir::new(descriptor.clone())
                        .prove(&inputs)
                        .map_err(component_error)?,
                )
            }
            ComponentKind::External => {
                return Err(error("external operation needs its real producer"))
            }
        };
        self.verify_batch(batch_index, &artifact)?;
        Ok(artifact)
    }

    /// Explicit policy handoff. GPU-required workers never enter a native CPU
    /// proving boundary; independent verification remains the unchanged CPU path.
    pub fn prove_batch_with_context(
        &self,
        batch_index: usize,
        execution: Option<&crate::execution::ProvingContext>,
    ) -> Result<ComponentArtifact> {
        let Some(execution) = execution else {
            return self.prove_batch(batch_index);
        };
        if execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired {
            #[cfg(feature = "opencl")]
            return self.prove_batch_gpu(batch_index, execution);
            #[cfg(not(feature = "opencl"))]
            return Err(error("GPU-required algebra proving requires OpenCL"));
        }
        execution
            .with_native_cpu(|| self.prove_batch(batch_index).map_err(|e| format!("{e:?}")))
            .map_err(error)
    }

    #[cfg(feature = "opencl")]
    fn prove_batch_gpu(
        &self,
        batch_index: usize,
        execution: &crate::execution::ProvingContext,
    ) -> Result<ComponentArtifact> {
        let batch = self.batch(batch_index)?;
        let first = batch.indices[0];
        let host_bytes = usize::try_from(self.native_host_limit_bytes.min(execution.host_bytes()))
            .map_err(|_| error("native host allowance overflow"))?;
        // The adapter composes only completed native GPU receipts. No private
        // trace is constructed or downloaded while packing these raw inputs.
        macro_rules! prove {
            ($entry:literal,$key:expr,$rows:expr,$generate:expr,$artifact:ident,$variant:path) => {{
                let key = $key;
                let air = key.air();
                let proved = execution
                    .prove_native_on_gpu($entry, air, air, $rows, host_bytes, $generate)
                    .map_err(error)?;
                let artifact = $artifact {
                    public_values: proved
                        .public_values
                        .try_into()
                        .map_err(|_| error("native algebra public width"))?,
                    proof: proved.proof,
                };
                $variant(artifact)
            }};
        }
        let artifact = match &batch.kind {
            ComponentKind::Affine { kind, modulus } => {
                let inputs = batch
                    .indices
                    .iter()
                    .map(|&index| match self.graph.operations()[index] {
                        Operation::Add { left, right, .. } | Operation::Sub { left, right, .. } => {
                            Ok(AffineInput::Binary {
                                left: self.canonical(left)?,
                                right: self.canonical(right)?,
                            })
                        }
                        Operation::SignedToCanonical { input, .. } => {
                            Ok(AffineInput::Signed(self.signed(input)?))
                        }
                        _ => Err(error("affine operation")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let key = RegisteredAffineAir::new(*kind, *modulus, inputs.len())
                    .map_err(component_error)?;
                let air = key.air();
                let rows = air.height();
                prove!(
                    "matrict_affine_gpu",
                    &key,
                    rows,
                    |ctx| air.generate_gpu(ctx, &inputs),
                    AffineBatchProof,
                    ComponentArtifact::Affine
                )
            }
            ComponentKind::Ntt { modulus } => {
                let inputs = batch
                    .indices
                    .iter()
                    .map(|&index| match self.graph.operations()[index] {
                        Operation::Ntt { input, .. } => self.canonical(input),
                        _ => Err(error("NTT operation")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let key = RegisteredNttAir::new(*modulus, inputs.len()).map_err(component_error)?;
                let air = key.air();
                let rows = air.height;
                prove!(
                    "matrict_ntt_gpu",
                    &key,
                    rows,
                    |ctx| air.generate_gpu(ctx, &inputs),
                    NttBatchProof,
                    ComponentArtifact::Ntt
                )
            }
            ComponentKind::Mul { modulus } => {
                let mut left = Vec::with_capacity(batch.indices.len());
                let mut right = Vec::with_capacity(batch.indices.len());
                for &index in &batch.indices {
                    let Operation::Mul {
                        left: a, right: b, ..
                    } = self.graph.operations()[index]
                    else {
                        return Err(error("product operation"));
                    };
                    left.push(self.canonical(a)?);
                    right.push(self.canonical(b)?);
                }
                let key = RegisteredMulAir::new(*modulus, left.len()).map_err(component_error)?;
                let air = key.air();
                let rows = air.height;
                prove!(
                    "matrict_mul_gpu",
                    &key,
                    rows,
                    |ctx| air.generate_gpu(ctx, &left, &right),
                    MulBatchProof,
                    ComponentArtifact::Mul
                )
            }
            ComponentKind::GBound { bound } => {
                let Operation::GBound { f, x, .. } = self.graph.operations()[first] else {
                    return Err(error("GBound operation"));
                };
                let f = self.signed(f)?;
                let x = self.signed(x)?;
                let key = RegisteredGBoundAir::new(*bound).map_err(component_error)?;
                let air = key.air();
                prove!(
                    "matrict_g_bound_gpu",
                    &key,
                    crate::g_bound_air::HEIGHT,
                    |ctx| air.generate_gpu(ctx, &f, &x),
                    GBoundArtifact,
                    ComponentArtifact::GBound
                )
            }
            ComponentKind::Permutation { kind } => {
                let (_, input, _) =
                    crate::permutation_air::graph::graph_operation(self.graph, first)
                        .map_err(|e| error(format!("permutation descriptor: {e:?}")))?;
                let input = match kind {
                    PermutationKind::AutomorphismQ => {
                        PermutationInput::Canonical(self.canonical(input)?)
                    }
                    PermutationKind::InverseChallenge => {
                        PermutationInput::Signed(self.signed(input)?)
                    }
                };
                let key = RegisteredPermutationAir::new(*kind);
                let air = key.air();
                prove!(
                    "matrict_permutation_gpu",
                    &key,
                    crate::permutation_air::HEIGHT,
                    |ctx| air.generate_gpu(ctx, &input),
                    PermutationProof,
                    ComponentArtifact::Permutation
                )
            }
            ComponentKind::LinearMap { descriptor } => {
                let map = crate::linear_map_air::graph_operation(self.graph, first)
                    .map_err(|e| error(format!("linear map descriptor: {e:?}")))?;
                let inputs: Vec<_> = map
                    .inputs
                    .iter()
                    .map(|&id| self.graph.polynomial(id).values.clone())
                    .collect();
                let key = RegisteredLinearMapAir::new(descriptor.clone());
                let air = key.air();
                let rows = air.height();
                prove!(
                    "matrict_linear_map_gpu",
                    &key,
                    rows,
                    |ctx| air.generate_gpu(ctx, &inputs),
                    LinearMapProof,
                    ComponentArtifact::LinearMap
                )
            }
            ComponentKind::External => {
                return Err(error("external operation needs its real producer"))
            }
        };
        self.verify_batch(batch_index, &artifact)?;
        Ok(artifact)
    }

    /// Validate a fresh or cached artifact under this exact registered batch.
    /// The verifier circuit remains mandatory before graph coverage is cleared.
    pub fn verify_batch(&self, batch_index: usize, artifact: &ComponentArtifact) -> Result<()> {
        let batch = self.batch(batch_index)?;
        let estimate = batch
            .estimate
            .ok_or_else(|| error("external operation has no algebra proof"))?;
        if artifact.public_values() != self.expected_public_values(batch)?
            || artifact.proof().degree_bits != estimate.height.ilog2() as usize + 1
        {
            return Err(error("child proof degree or ordered public roots"));
        }
        match (&batch.kind, artifact) {
            (ComponentKind::Affine { kind, modulus }, ComponentArtifact::Affine(p)) => {
                RegisteredAffineAir::new(*kind, *modulus, batch.indices.len())
                    .map_err(component_error)?
                    .verify(p)
            }
            (ComponentKind::Ntt { modulus }, ComponentArtifact::Ntt(p)) => {
                RegisteredNttAir::new(*modulus, batch.indices.len())
                    .map_err(component_error)?
                    .verify(p)
            }
            (ComponentKind::Mul { modulus }, ComponentArtifact::Mul(p)) => {
                RegisteredMulAir::new(*modulus, batch.indices.len())
                    .map_err(component_error)?
                    .verify(p)
            }
            (ComponentKind::GBound { bound }, ComponentArtifact::GBound(p)) => {
                RegisteredGBoundAir::new(*bound)
                    .map_err(component_error)?
                    .verify(p)
            }
            (ComponentKind::Permutation { kind }, ComponentArtifact::Permutation(p)) => {
                RegisteredPermutationAir::new(*kind).verify(p)
            }
            (ComponentKind::LinearMap { descriptor }, ComponentArtifact::LinearMap(p)) => {
                RegisteredLinearMapAir::new(descriptor.clone()).verify(p)
            }
            _ => return Err(error("cached component type differs from registered batch")),
        }
        .map_err(component_error)
    }
}
