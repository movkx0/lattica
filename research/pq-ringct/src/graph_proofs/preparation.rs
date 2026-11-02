//! GPU endpoint preparation. Cache lookup and verification subsequently read
//! these immutable public roots without recomputing witness commitments on CPU.
use super::*;
use crate::affine_air::{AffineRoots, BUNDLE_DOMAIN};
use lattica_prover_p3::block_v2::native_gpu::OperationContext;
use p3_field::PrimeCharacteristicRing;

fn affine_bundle_on_gpu(
    operations: &OperationContext<'_>,
    kind: AffineKind,
    modulus: u64,
    count: usize,
    roots: &[AffineRoots],
) -> Result<[Val; 4]> {
    let (initial, words) = affine_fields(operations, kind, modulus, count, roots)?;
    operations.commit_field_chunks(initial, &words).map(|root| root.map(Val::from_u64)).map_err(error)
}

fn affine_fields(operations: &OperationContext<'_>, kind: AffineKind, modulus: u64,
    count: usize, roots: &[AffineRoots]) -> Result<([u64; 4], Vec<u64>)> {
    // Descriptor validation is public metadata, not witness computation.
    crate::affine_air::RegisteredAffineAir::new(kind, modulus, count).map_err(component_error)?;
    if roots.len() != count
        || roots
            .iter()
            .any(|r| r.right.is_some() == kind.is_conversion())
    {
        return Err(error("affine root framing length"));
    }
    let count_words = 4 + count * if kind.is_conversion() { 8 } else { 12 };
    operations.admit_field_chunks(count_words).map_err(error)?;
    let mut words = Vec::with_capacity(count_words);
    // The existing initial permutation absorbs bound,D,0,0 after the public
    // domain/kind/modulus/count prefix. It must also be performed on device.
    words.extend_from_slice(&[u64::from(kind.bound()), crate::rust_verify::D as u64, 0, 0]);
    for roots in roots {
        words.extend(roots.left.map(|v| v.as_canonical_u64()));
        if let Some(right) = roots.right {
            words.extend(right.map(|v| v.as_canonical_u64()));
        }
        words.extend(roots.output.map(|v| v.as_canonical_u64()));
    }
    Ok(([BUNDLE_DOMAIN, kind.code(), modulus, count as u64], words))
}

impl<'a> GraphProofPlan<'a> {
    pub(crate) fn new_with_batched_operations(registered: &RegisteredGraphShape, graph: &'a UnprovedRelationGraph,
        limits: ResourceLimits, operations: &OperationContext<'_>) -> Result<Self> {
        Self::prepare_batched(Self::topology(registered, graph, limits)?, operations)
    }
    pub(crate) fn new_prepared_operations(
        structure: &crate::rust_verify::committed_backend::source_binding::prepared::PreparedGraphStructure<'a>,
        limits: ResourceLimits, operations: &OperationContext<'_>, batched: bool,
    ) -> Result<Self> {
        let plan = Self::topology_prepared(structure, limits)?;
        if batched { Self::prepare_batched(plan, operations) } else { Self::prepare_scalar(plan, operations) }
    }
    fn prepare_batched(mut plan: Self, operations: &OperationContext<'_>) -> Result<Self> {
        let count = plan.batches.iter().filter(|b| matches!(b.kind, ComponentKind::Affine { .. })).count();
        let mut hashes = crate::graph_tree::commitment_batches::FieldBatch::new(operations, count, true).map_err(error)?;
        let mut patches = Vec::with_capacity(count);
        for index in 0..plan.batches.len() {
            if plan.batches[index].kind == ComponentKind::External { continue; }
            let mut pending = None;
            let public = plan.collect_expected_public_values(&plan.batches[index], |kind, modulus, count, roots| {
                let (initial, words) = affine_fields(operations, kind, modulus, count, roots)?;
                pending = Some(hashes.push(initial, words).map_err(error)?);
                Ok([Val::ZERO; 4])
            })?;
            if let Some(slot) = pending {
                if public.len() != 4 { return Err(error("affine batch public framing")); }
                patches.push((index, slot));
            }
            plan.batches[index].expected_public = Some(public);
        }
        let roots = hashes.finish().map_err(error)?;
        for (index, slot) in patches { plan.batches[index].expected_public.as_mut().unwrap().copy_from_slice(&roots[slot]); }
        Ok(plan)
    }
    pub fn new_with_operations(
        registered: &RegisteredGraphShape,
        graph: &'a UnprovedRelationGraph,
        limits: ResourceLimits,
        operations: &OperationContext<'_>,
    ) -> Result<Self> {
        Self::prepare_scalar(Self::topology(registered, graph, limits)?, operations)
    }
    fn prepare_scalar(mut plan: Self, operations: &OperationContext<'_>) -> Result<Self> {
        for index in 0..plan.batches.len() {
            if plan.batches[index].kind == ComponentKind::External {
                continue;
            }
            let public = plan.collect_expected_public_values(
                &plan.batches[index],
                |kind, modulus, count, roots| {
                    affine_bundle_on_gpu(operations, kind, modulus, count, roots)
                },
            )?;
            plan.batches[index].expected_public = Some(public);
        }
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "real GPU affine endpoint framing parity; exclusive admitted OpenCL session"]
    fn gpu_affine_endpoint_bundles_match_cpu_for_all_kinds_and_moduli() {
        assert!(!cfg!(debug_assertions));
        let execution = crate::execution::ProvingContext::opencl(crate::opencl::Limits {
            host_bytes: 8 << 30,
            device_bytes: 8 << 30,
            max_rows: 4096,
        })
        .unwrap();
        execution
            .with_witness_preparation(1 << 20, |operations| {
                for modulus in [crate::rust_verify::Q, crate::rust_verify::QHAT] {
                    for count in [1, 2, 8, 128] {
                        for kind in [
                            AffineKind::Add,
                            AffineKind::Sub,
                            AffineKind::SignedToCanonical { bound: 565 },
                        ] {
                            let roots: Vec<_> = (0..count)
                                .map(|i| AffineRoots {
                                    left: core::array::from_fn(|j| {
                                        Val::from_u64((i * 17 + j) as u64)
                                    }),
                                    right: (!kind.is_conversion()).then(|| {
                                        core::array::from_fn(|j| Val::from_u64((i * 31 + j) as u64))
                                    }),
                                    output: [Val::NEG_ONE; 4],
                                })
                                .collect();
                            let expected =
                                crate::affine_air::RegisteredAffineAir::new(kind, modulus, count)
                                    .unwrap()
                                    .air()
                                    .bundle_roots(&roots)
                                    .unwrap();
                            let actual =
                                affine_bundle_on_gpu(operations, kind, modulus, count, &roots)
                                    .map_err(|e| e.to_string())?;
                            assert_eq!(actual, expected);
                        }
                    }
                }
                Ok(())
            })
            .unwrap();
        drop(execution);
    }
}
