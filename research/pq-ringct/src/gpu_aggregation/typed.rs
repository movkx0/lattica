//! Default AES/SHAKE recursion: independent native batches share a global CPU
//! preparation window, then the sole GPU owner proves and reduces their roots.
use super::*;
use crate::component_tree::recursion::ProvenNode;
use lattica_prover_p3::block_v2::machine::program::ConstructionLimits;
use std::collections::BTreeMap;

pub(crate) const RETAINED_ROOT_BYTES: usize = 2 << 30;
pub(crate) mod parents;
// The expanded N4 compiler can admit eight compact recursion-v5 children.
// Standard construction retains four: its input and program caps are smaller.
// Every parent still passes exact geometry and memory admission before proving.
fn fan_in_for(policy: policy::Policy) -> usize {
    if policy.name == "typed-batch" {
        8
    } else {
        4
    }
}
pub(crate) fn reduction_fan_in() -> usize {
    fan_in_for(policy::current())
}
pub(crate) fn proof_count(leaves: usize) -> usize {
    count_with_fan_in(leaves, reduction_fan_in())
}
fn count_with_fan_in(mut leaves: usize, fan_in: usize) -> usize {
    let mut count = leaves;
    while leaves > 1 {
        count += leaves / fan_in + usize::from(leaves % fan_in > 1);
        leaves = leaves.div_ceil(fan_in);
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

pub(crate) fn preparation_weight(
    limits: ConstructionLimits,
    compiler_bytes: usize,
) -> Result<usize> {
    use lattica_prover_p3::block_v2::machine::recursion::RecursionTemplate;
    // Native decoding/compiler scratch is gone before template construction.
    // Keep the larger phase charged until source retirement; include returned
    // input capacity separately from the immutable source and lowering scratch.
    let template_bytes = limits
        .max_input_values
        .checked_mul(16)
        .and_then(|n| n.checked_add(limits.max_requested_program_bytes))
        .and_then(|n| n.checked_add(RecursionTemplate::CONSTRUCTION_WORKSPACE_BYTES))
        .and_then(|n| n.checked_add(64 << 10))
        .ok_or("typed template preparation weight overflow")?;
    Ok(compiler_bytes.max(template_bytes))
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
    Ok((limits, preparation_weight(limits, weight)?))
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
            let node = compile(request, &case.context, job.span, job.limits, |i| {
                caches
                    .crypto
                    .load(request, i)
                    .map_err(error)?
                    .ok_or_else(|| "missing typed native component".into())
            })?;
            let start = Instant::now();
            let template = lattica_prover_p3::block_v2::machine::recursion::RecursionTemplate::new(
                node.shared_program(),
                crate::graph_proofs::compiled_source_fingerprint(),
            )?;
            let template_seconds = start.elapsed().as_secs_f64();
            let witness = template.prepare_gpu_witness(
                node.public_values(),
                node.witness_values(),
                weights[index],
            )?;
            Ok((node, template, witness, template_seconds))
        },
        |index, (node, template, witness, template_seconds), permit| {
            deadline.check()?;
            let job = &jobs[index];
            let (node, setup, measurement) = ProvenNode::prove_prepared_witness_gpu(
                node,
                template,
                witness,
                &mut cache,
                architecture::gpu_limits(),
                || drop(permit),
            )
            .map_err(error)?;
            retained += node
                .retained_bytes(RETAINED_ROOT_BYTES - retained)
                .map_err(error)?;
            children
                .get_mut(&(job.transaction, job.request))
                .ok_or("typed request schedule")?
                .push(node);
            measurements.push(serde_json::json!({"transaction":job.transaction,"request":job.request,
            "native_components":job.span.segment_count,"template_preparation_seconds":template_seconds,
            "setup_seconds":setup,"measurement":measurement}));
            Ok(())
        },
    )?;
    let mut roots = BTreeMap::new();
    let mut requests = children.into_iter().collect::<Vec<_>>();
    requests.sort_by_key(|(key, _)| (key.1, key.0));
    let keys = requests.iter().map(|(key, _)| *key).collect::<Vec<_>>();
    let leaves = requests
        .iter()
        .map(|(_, nodes)| nodes.len())
        .collect::<Vec<_>>();
    let reduced = parents::reduce(
        requests.into_iter().map(|(_, nodes)| nodes).collect(),
        reduction_fan_in(),
        options,
        deadline,
        &mut cache,
        retained,
        |index, node| {
            let key = keys[index];
            let contract = cases[key.0].plan.requests()[key.1]
                .contract()
                .map_err(error)?;
            component_tree::recursion::require_complete(node, &contract).map_err(error)
        },
        |index, node| {
            let key = keys[index];
            let request = &cases[key.0].plan.requests()[key.1];
            node.verify_request(
                &request.contract().map_err(error)?,
                &request.endpoint_context_hint(&cases[key.0].context),
            )
            .map_err(error)
        },
    )?;
    retained = reduced.retained_bytes;
    for (index, node) in reduced.roots.into_iter().enumerate() {
        let key = keys[index];
        let request = &cases[key.0].plan.requests()[key.1];
        if leaves[index] == 1 {
            node.verify_request(
                &request.contract().map_err(error)?,
                &request.endpoint_context_hint(&cases[key.0].context),
            )
            .map_err(error)?;
        }
        let parents = reduced.measurements[index].len();
        ensure(
            leaves[index] + parents == proof_count(leaves[index]),
            "typed request proof count changed",
        )?;
        for mut row in reduced.measurements[index].iter().cloned() {
            row["transaction"] = serde_json::json!(key.0);
            row["request"] = serde_json::json!(key.1);
            measurements.push(row);
        }
        roots.insert(
            key,
            Root {
                node,
                leaves: leaves[index],
                parents,
            },
        );
    }
    Ok((
        roots,
        serde_json::json!({"seconds":started.elapsed().as_secs_f64(), "preparation":stats,"reduction_fan_in":reduction_fan_in(),
            "preparation_capacity_bytes":capacity,"retained_root_bytes":retained,
"parent_preparation":reduced.preparation,"parent_schedule":"position-before-request",
"retained_peak_bytes":reduced.peak_retained_bytes,"measurements":measurements,"public_template_cache":cache.stats(),
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
        let standard = fan_in_for(policy::Policy::parse("standard").unwrap());
        let expanded = fan_in_for(policy::Policy::parse("typed-batch").unwrap());
        assert_eq!((standard, expanded), (4, 8));
        for (leaves, proofs) in [
            (1, 1),
            (2, 3),
            (7, 8),
            (8, 9),
            (9, 11),
            (16, 19),
            (64, 73),
            (65, 75),
        ] {
            assert_eq!(count_with_fan_in(leaves, expanded), proofs);
        }
        for (leaves, proofs) in [
            (1, 1),
            (2, 3),
            (7, 10),
            (8, 11),
            (9, 12),
            (16, 21),
            (65, 87),
        ] {
            assert_eq!(count_with_fan_in(leaves, standard), proofs);
        }
        assert!(job_limits(0).is_err());
        assert!(job_limits(17).is_err());
        let mut limits = ConstructionLimits {
            max_requested_program_bytes: 6 << 30,
            max_wires: 1 << 26,
            max_input_values: 8 << 20,
        };
        let template_weight = preparation_weight(limits, 1).unwrap();
        assert!(template_weight > 8 << 30 && template_weight < 9 << 30);
        assert_eq!(preparation_weight(limits, 9 << 30).unwrap(), 9 << 30);
        limits.max_input_values = usize::MAX;
        assert!(preparation_weight(limits, 1).is_err());
        let small = job_limits(1).unwrap();
        let large = job_limits(4).unwrap();
        assert!(small.1 < large.1);
        assert!(large.1 >= large.0.max_requested_program_bytes + (512 << 20));
    }
}
