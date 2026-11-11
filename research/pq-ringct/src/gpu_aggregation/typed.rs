//! Default AES/SHAKE recursion: independent native batches share a global CPU
//! preparation window, then the sole GPU owner proves and reduces their roots.
use super::*;
use crate::component_tree::recursion::{compile_proven, ProvenNode};
use lattica_prover_p3::block_v2::machine::program::ConstructionLimits;
use std::collections::BTreeMap;

const RETAINED_ROOT_BYTES: usize = 2 << 30;
// The eight-child graph-parent profile required 14.23 GiB of fixed device
// allocations before transform scratch. Four children fit the 10.5 GiB
// managed default; native proof groups keep their independently checked width.
pub(crate) const REDUCTION_FAN_IN: usize = 4;
pub(crate) fn proof_count(mut leaves: usize) -> usize {
    let mut count = leaves;
    while leaves > 1 {
        count += leaves / REDUCTION_FAN_IN + usize::from(leaves % REDUCTION_FAN_IN > 1);
        leaves = leaves.div_ceil(REDUCTION_FAN_IN);
    }
    count
}
pub(crate) struct Root {
    pub node: ProvenNode,
    pub leaves: usize,
    pub parents: usize,
}
struct Job {
    transaction: usize,
    request: usize,
    span: graph_crypto::ShakeWrapperSpan,
    limits: ConstructionLimits,
}

pub(crate) fn job_limits(members: usize) -> Result<(ConstructionLimits, usize)> {
    ensure(
        (1..=16).contains(&members),
        "typed preparation native count",
    )?;
    let mut limits = construction();
    limits.max_requested_program_bytes = limits
        .max_requested_program_bytes
        .min((members * (384 << 20)).max(512 << 20));
    limits.max_input_values = limits.max_input_values.min(members.max(2) * (1 << 19));
    // Native JSON entries are capped at 64 MiB. Reserve two complete entry
    // sizes per retained child plus one decoder, separately from the bounded
    // compiler's public symbolic/ProofInputs workspace.
    let weight = limits.max_requested_program_bytes
        + component_tree::paired_runtime::source::AUXILIARY_BYTES
        + (members + 1) * (128 << 20);
    Ok((limits, weight))
}

pub(crate) fn prove_all(
    cases: &[Arc<inputs::Case>],
    caches: &bundle::Caches,
    options: &Options,
    deadline: &Deadline,
) -> Result<(BTreeMap<(usize, usize), Root>, serde_json::Value)> {
    let mut jobs = Vec::new();
    let mut weights = Vec::new();
    let mut children: BTreeMap<(usize, usize), Vec<ProvenNode>> = BTreeMap::new();
    for (transaction, case) in cases.iter().enumerate() {
        for (index, request) in case.plan.requests().iter().enumerate() {
            children.insert((transaction, index), Vec::new());
            for span in architecture::direct_spans(request, options.group_width)? {
                let (limits, weight) = job_limits(span.segment_count)?;
                jobs.push(Job {
                    transaction,
                    request: index,
                    span,
                    limits,
                });
                weights.push(weight);
            }
        }
    }
    let policy = policy::current();
    // Equal request positions in independent transactions commonly have the
    // same exact program. Preserve span order within each request while making
    // those candidates adjacent; the cache still requires the full identity.
    jobs.sort_by_key(|job| (job.request, job.span.first_segment, job.transaction));
    weights.clear();
    for job in &jobs {
        weights.push(job_limits(job.span.segment_count)?.1);
    }
    let mut cache = lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache::default();
    let capacity = policy.program_bytes * policy.live_jobs + policy.symbolic_bytes as usize;
    let started = Instant::now();
    let mut retained = 0usize;
    let mut measurements = Vec::new();
    let stats = weighted::run(
        &weights,
        capacity,
        if options.parallel {
            options.preparation_workers
        } else {
            1
        },
        |index| {
            deadline.check()?;
            let job = &jobs[index];
            let case = &cases[job.transaction];
            let request = &case.plan.requests()[job.request];
            compile(request, &case.context, job.span, job.limits, |i| {
                caches
                    .crypto
                    .load(request, i)
                    .map_err(error)?
                    .ok_or_else(|| "missing typed native component".into())
            })
        },
        |index, node, permit| {
            deadline.check()?;
            let job = &jobs[index];
            let (node, setup, measurement) =
                ProvenNode::prove_gpu(node, &mut cache, architecture::gpu_limits(), || {
                    drop(permit)
                })
                .map_err(error)?;
            retained += node
                .retained_bytes(RETAINED_ROOT_BYTES - retained)
                .map_err(error)?;
            children
                .get_mut(&(job.transaction, job.request))
                .ok_or("typed request schedule")?
                .push(node);
            measurements.push(serde_json::json!({"transaction":job.transaction,"request":job.request,
            "native_components":job.span.segment_count,"setup_seconds":setup,"measurement":measurement}));
            Ok(())
        },
    )?;
    let mut roots = BTreeMap::new();
    let mut requests = children.into_iter().collect::<Vec<_>>();
    requests.sort_by_key(|(key, _)| (key.1, key.0));
    for (key, mut nodes) in requests {
        let leaves = nodes.len();
        let mut parents = 0;
        while nodes.len() > 1 {
            let mut next = Vec::new();
            let mut remaining = nodes.into_iter();
            loop {
                let children = remaining
                    .by_ref()
                    .take(REDUCTION_FAN_IN)
                    .collect::<Vec<_>>();
                if children.is_empty() {
                    break;
                }
                if children.len() == 1 {
                    next.extend(children);
                    continue;
                }
                deadline.check()?;
                let node = compile_proven(&children.iter().collect::<Vec<_>>(), construction())
                    .map_err(error)?;
                for child in &children {
                    retained -= child.retained_bytes(RETAINED_ROOT_BYTES).map_err(error)?;
                }
                drop(children);
                let (node, setup, measurement) =
                    ProvenNode::prove_gpu(node, &mut cache, architecture::gpu_limits(), || {})
                        .map_err(error)?;
                retained += node
                    .retained_bytes(RETAINED_ROOT_BYTES - retained)
                    .map_err(error)?;
                next.push(node);
                parents += 1;
                measurements.push(
                    serde_json::json!({"transaction":key.0,"request":key.1,"parent":true,
                    "setup_seconds":setup,"measurement":measurement}),
                );
            }
            nodes = next;
        }
        let node = nodes.pop().ok_or("empty typed request")?;
        let request = &cases[key.0].plan.requests()[key.1];
        node.verify_request(
            &request.contract().map_err(error)?,
            &request.endpoint_context_hint(&cases[key.0].context),
        )
        .map_err(error)?;
        roots.insert(
            key,
            Root {
                node,
                leaves,
                parents,
            },
        );
    }
    Ok((
        roots,
        serde_json::json!({"seconds":started.elapsed().as_secs_f64(), "preparation":stats,
            "preparation_capacity_bytes":capacity,"retained_root_bytes":retained,"measurements":measurements,"public_template_cache":cache.stats(),
        "source_retired_before_gpu":true,"independent_cpu_verification":true}),
    ))
}

pub(crate) fn compile(
    request: &graph_crypto::Request,
    context: &crate::graph_tree::GraphContext,
    span: graph_crypto::ShakeWrapperSpan,
    limits: ConstructionLimits,
    mut load: impl FnMut(usize) -> Result<graph_crypto::SegmentArtifact>,
) -> Result<component_tree::CompiledNode> {
    let children = (span.first_segment..span.first_segment + span.segment_count)
        .map(&mut load)
        .collect::<Result<Vec<_>>>()?;
    if matches!(
        request.descriptor(),
        graph_crypto::RequestDescriptor::Aes(_)
    ) {
        let members = children
            .iter()
            .enumerate()
            .map(|(offset, artifact)| {
                let graph_crypto::SegmentArtifact::Aes(proof) = artifact else {
                    return Err("typed AES native family".into());
                };
                let segment = request
                    .segments()
                    .get(span.first_segment + offset)
                    .ok_or("typed AES native index")?;
                Ok(component_tree::aes_group::Member {
                    first: segment.first_unit.try_into().map_err(error)?,
                    count: segment.units.try_into().map_err(error)?,
                    proof,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        return component_tree::aes_group::compile(
            &request.contract().map_err(error)?,
            &members,
            &request.endpoint_context_hint(context),
            limits,
        )
        .map_err(error);
    }
    let members = children
        .iter()
        .enumerate()
        .map(|(offset, artifact)| {
            let graph_crypto::SegmentArtifact::Shake(proof) = artifact else {
                return Err("typed native family".into());
            };
            let segment = request
                .segments()
                .get(span.first_segment + offset)
                .ok_or("typed native index")?;
            Ok(component_tree::ShakeGroupMember {
                first: segment.first_unit.try_into().map_err(error)?,
                count: segment.units.try_into().map_err(error)?,
                proof,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    match component_tree::compile_shake_group_bounded_with_context(
        &request.contract().map_err(error)?,
        &members,
        &request.endpoint_context_hint(context),
        None,
        limits,
        component_tree::paired_runtime::source::AUXILIARY_BYTES,
    )
    .map_err(error)?
    {
        component_tree::ShakeGroupCompileOutcome::Compiled(node) => Ok(node),
        component_tree::ShakeGroupCompileOutcome::ResourceRefused(r) => {
            Err(format!("typed compiler admission: {}", r.reason))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multi_child_reductions_skip_singleton_wrappers() {
        for (leaves, proofs) in [
            (1, 1),
            (2, 3),
            (7, 10),
            (8, 11),
            (9, 12),
            (16, 21),
            (65, 87),
        ] {
            assert_eq!(proof_count(leaves), proofs);
        }
        assert!(job_limits(0).is_err());
        assert!(job_limits(17).is_err());
        let small = job_limits(1).unwrap();
        let large = job_limits(4).unwrap();
        assert!(small.1 < large.1);
        assert!(large.1 >= large.0.max_requested_program_bytes + (512 << 20));
    }
}
