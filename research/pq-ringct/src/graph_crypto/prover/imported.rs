//! Explicit native import. This route never invokes a native prover.
use super::*;
use crate::component_tree::paired_runtime::source;
use crate::component_tree::paired_runtime::PairedFailure;
use crate::gpu_aggregation::{self, Deadline};

pub(crate) fn group_spans(
    request: &Request,
    maximum: usize,
    max_rows: usize,
) -> Result<Vec<ShakeWrapperSpan>> {
    require(
        matches!(maximum, 1 | 2 | 4 | 8),
        "invalid imported wrapper group size",
    )?;
    if !matches!(request.descriptor(), RequestDescriptor::Shake(_)) {
        return Ok(Vec::new());
    }
    // Validate full original coverage before considering any contraction.
    request.shake_wrapper_schedule(ShakeWrapperLayout::Singleton)?;
    let mut spans = Vec::new();
    let mut first = 0;
    while first < request.segments().len() {
        let mut count = maximum.min(request.segments().len() - first);
        loop {
            let start = &request.segments()[first];
            let last = &request.segments()[first + count - 1];
            let span = ShakeWrapperSpan {
                first_segment: first,
                segment_count: count,
                first_unit: start.first_unit,
                units: last.first_unit + last.units - start.first_unit,
            };
            let facts = source::GroupBlueprint::new(request, span)
                .and_then(|blueprint| blueprint.inspect())
                .and_then(|facts| {
                    if facts.maximum_padded_rows <= max_rows {
                        Ok(facts)
                    } else {
                        Err(PairedFailure::Rows)
                    }
                });
            match facts {
                Ok(_) => {
                    spans.push(span);
                    first += count;
                    break;
                }
                Err(PairedFailure::Rows | PairedFailure::Capacity) if count > 1 => {
                    count = count.div_ceil(2)
                }
                Err(reason) => {
                    return Err(err(format!("imported SHAKE source preflight: {reason:?}")))
                }
            }
        }
    }
    Ok(spans)
}

#[cfg(test)]
mod imported_group_layout_tests {
    use super::*;
    #[test]
    fn odd_tail_partition_preserves_every_original_boundary_and_rejects_gaps() {
        let mut request = Request::new(
            [17; 32],
            5,
            0,
            RequestDescriptor::Shake(shake_air::Descriptor {
                input_len: 1088,
                output_len: 32,
            }),
            Payload::Shake(vec![7; 1088]),
            Policy {
                maximum_shake_permutations: 1,
                admission: Admission::ValidatedLocal,
                ..Policy::default()
            },
        )
        .unwrap();
        for maximum in [1, 2, 4, 8] {
            let spans = group_spans(&request, maximum, source::MAX_ROWS).unwrap();
            let (mut segment, mut unit) = (0, 0);
            for span in spans {
                assert_eq!(span.first_segment, segment);
                assert_eq!(span.first_unit, unit);
                assert!(span.segment_count <= maximum);
                segment += span.segment_count;
                unit += span.units;
            }
            assert_eq!(segment, request.segments().len());
            assert_eq!(unit, request.units());
        }
        request.segments[1].first_unit += 1;
        assert!(group_spans(&request, 8, source::MAX_ROWS).is_err());
    }
}
impl RequestProver<'_> {
    pub(crate) fn prove_imported(
        &self,
        request: &Request,
        context: &graph_tree::GraphContext,
        spans: &[ShakeWrapperSpan],
        parallel: bool,
        gpu_identity: bool,
        deadline: &Deadline,
    ) -> Result<CompleteRequestProof> {
        let execution = self
            .execution
            .ok_or_else(|| err("imported recursion requires explicit GPU context"))?;
        require(
            execution.policy() == lattica_prover_p3::proving::Policy::GpuRequired,
            "imported recursion requires GPU proofs",
        )?;
        require(
            self.outer_cache.policy() == crate::proof_cache_policy::ProofCachePolicy::FreshOnly,
            "imported recursion must produce fresh outer proofs",
        )?;
        let endpoints = request.endpoint_context_hint(context);
        let is_shake = matches!(request.descriptor(), RequestDescriptor::Shake(_));
        let count = if is_shake {
            spans.len()
        } else {
            request.segments().len()
        };
        let native_cache = self.native_cache;
        let prepare = |index: usize| -> std::result::Result<_, String> {
            deadline.check()?;
            if is_shake {
                let span = spans[index];
                let mut children = Vec::with_capacity(span.segment_count);
                for index in span.first_segment..span.first_segment + span.segment_count {
                    children.push(
                        native_cache
                            .load(request, index)
                            .map_err(gpu_aggregation::error)?
                            .ok_or("missing imported SHAKE component")?,
                    );
                }
                let mut members = Vec::with_capacity(children.len());
                for (offset, artifact) in children.iter().enumerate() {
                    let SegmentArtifact::Shake(proof) = artifact else {
                        return Err("imported SHAKE artifact family".into());
                    };
                    let segment = &request.segments()[span.first_segment + offset];
                    members.push(component_tree::ShakeGroupMember {
                        first: segment
                            .first_unit
                            .try_into()
                            .map_err(gpu_aggregation::error)?,
                        count: segment.units.try_into().map_err(gpu_aggregation::error)?,
                        proof,
                    });
                }
                let outcome = component_tree::compile_shake_group_bounded_with_context(
                    &request.contract().map_err(gpu_aggregation::error)?,
                    &members,
                    &endpoints,
                    None,
                    gpu_aggregation::construction(),
                    source::AUXILIARY_BYTES,
                )
                .map_err(gpu_aggregation::error)?;
                match outcome {
                    component_tree::ShakeGroupCompileOutcome::Compiled(compiled) => {
                        Ok((span.first_unit, span.units, span.segment_count, compiled))
                    }
                    component_tree::ShakeGroupCompileOutcome::ResourceRefused(reason) => Err(
                        format!("admitted SHAKE compiler refused: {}", reason.reason),
                    ),
                }
            } else {
                let artifact = native_cache
                    .load(request, index)
                    .map_err(gpu_aggregation::error)?
                    .ok_or("missing imported AES component")?;
                let compiled = request
                    .compile_segment_leaf_with_endpoints(index, &endpoints, &artifact, None)
                    .map_err(gpu_aggregation::error)?;
                let segment = &request.segments()[index];
                Ok((segment.first_unit, segment.units, 1, compiled))
            }
        };
        let mut report = RequestProvingReport::default();
        let mut nodes = Vec::new();
        if execution.consuming_aggregation() {
            let node = gpu_aggregation::pipeline::tree_programs(
                count,
                execution,
                prepare,
                |left: &ActualNode, right: &ActualNode| {
                    deadline.check()?;
                    if left.first.checked_add(left.units) != Some(right.first) {
                        return Err("nonadjacent imported request children".into());
                    }
                    let compiled = component_tree::compile_imported_merge(
                        &left.key,
                        &right.key,
                        [&left.proof, &right.proof],
                    )
                    .map_err(gpu_aggregation::error)?;
                    Ok((
                        left.first,
                        left.units
                            .checked_add(right.units)
                            .ok_or("request size overflow")?,
                        0,
                        compiled,
                    ))
                },
                |(_, _, _, node)| node.shared_program(),
                |(first, units, children, compiled)| {
                    deadline.check()?;
                    let geometry = compiled.geometry().map_err(gpu_aggregation::error)?;
                    if geometry.padded_rows > execution.aggregation_row_limit()
                        || compiled.program().construction_host_bytes() > source::PROGRAM_BYTES
                    {
                        return Err("imported component exceeds source compiler/row ceiling".into());
                    }
                    report.native_children += children;
                    report.native_cache_hits += children;
                    self.prove_node_with_admission(
                        if children == 0 {
                            "parent"
                        } else {
                            "imported leaf"
                        },
                        first,
                        units,
                        compiled,
                        &mut report,
                        true,
                    )
                    .map_err(gpu_aggregation::error)
                },
            )
            .map_err(err)?;
            nodes.push(node);
        } else {
            gpu_aggregation::pipeline::programs(
                count,
                parallel,
                gpu_identity,
                execution,
                prepare,
                |(_, _, _, node)| node.shared_program(),
                |cohort| {
                    for (_, (first, units, children, compiled)) in cohort {
                        deadline.check()?;
                        let geometry = compiled.geometry().map_err(gpu_aggregation::error)?;
                        if geometry.padded_rows > execution.aggregation_row_limit()
                            || compiled.program().construction_host_bytes() > source::PROGRAM_BYTES
                        {
                            return Err(
                                "imported component exceeds source compiler/row ceiling".into()
                            );
                        }
                        report.native_children += children;
                        report.native_cache_hits += children;
                        let node = self
                            .prove_node_with_admission(
                                "imported leaf",
                                first,
                                units,
                                compiled,
                                &mut report,
                                true,
                            )
                            .map_err(gpu_aggregation::error)?;
                        nodes.push(node);
                    }
                    Ok(())
                },
            )
            .map_err(err)?;
            while nodes.len() > 1 {
                let mut next = Vec::new();
                gpu_aggregation::pipeline::programs(
                    nodes.len() / 2,
                    parallel,
                    gpu_identity,
                    execution,
                    |index| {
                        deadline.check()?;
                        let left = &nodes[2 * index];
                        let right = &nodes[2 * index + 1];
                        if left.first.checked_add(left.units) != Some(right.first) {
                            return Err("nonadjacent imported request children".into());
                        }
                        let compiled = component_tree::compile_imported_merge(
                            &left.key,
                            &right.key,
                            [&left.proof, &right.proof],
                        )
                        .map_err(gpu_aggregation::error)?;
                        Ok((
                            left.first,
                            left.units
                                .checked_add(right.units)
                                .ok_or("request size overflow")?,
                            compiled,
                        ))
                    },
                    |(_, _, node)| node.shared_program(),
                    |cohort| {
                        for (_, (first, units, compiled)) in cohort {
                            deadline.check()?;
                            next.push(
                                self.prove_node_with_admission(
                                    "parent",
                                    first,
                                    units,
                                    compiled,
                                    &mut report,
                                    true,
                                )
                                .map_err(gpu_aggregation::error)?,
                            );
                        }
                        Ok(())
                    },
                )
                .map_err(err)?;
                if nodes.len() % 2 == 1 {
                    next.push(nodes.pop().unwrap());
                }
                nodes = next;
            }
        }
        let node = nodes.pop().ok_or_else(|| err("empty imported request"))?;
        require(
            node.first == 0 && node.units == request.units(),
            "incomplete imported request coverage",
        )?;
        node.key
            .verify_request(&node.proof, &endpoints)
            .map_err(err)?;
        Ok(CompleteRequestProof {
            key: node.key,
            proof: node.proof,
            report,
        })
    }
}
