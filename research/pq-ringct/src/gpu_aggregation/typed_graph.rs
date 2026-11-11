//! Stream checked native graph groups directly into typed proofs, then reduce
//! up to four adjacent children. No singleton dry compilation or bridge proof.
use super::*;
use crate::graph_tree::{
    self,
    recursion::{compile_merge, ProvenNode},
};
use lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache;
const ROOT_BYTES: usize = 2 << 30;

pub(crate) fn groups(first: usize, count: usize, maximum: usize) -> Result<Vec<(usize, usize)>> {
    ensure(
        count != 0 && matches!(maximum, 1 | 2 | 4 | 8),
        "typed graph group shape",
    )?;
    let end = first
        .checked_add(count)
        .ok_or("typed graph range overflow")?;
    Ok((first..end)
        .step_by(maximum)
        .map(|i| (i, maximum.min(end - i)))
        .collect())
}
pub(crate) fn prove(
    groups: &[(usize, usize)],
    plan: &graph_tree::Plan,
    context: &graph_tree::GraphContext,
    options: &Options,
    deadline: &Deadline,
    cache: &mut GpuRecursionCache,
    prepare: impl Fn(usize, usize) -> Result<graph_tree::CompiledNode> + Sync,
) -> Result<(ProvenNode, serde_json::Value)> {
    ensure(!groups.is_empty(), "empty typed graph")?;
    for pair in groups.windows(2) {
        ensure(
            pair[0].0.checked_add(pair[0].1) == Some(pair[1].0),
            "typed graph schedule adjacency",
        )?;
    }
    let started = Instant::now();
    let policy = policy::current();
    let weights = groups
        .iter()
        .map(|(_, count)| {
            ensure((1..=8).contains(count), "typed graph native count")?;
            // Bound compiler, symbolic/returned-input workspace and two complete
            // 64 MiB cache-entry backings per child, plus one decoder. Native graph
            // sources use the same bounded compiler and cache caps as the old path.
            Ok(policy.program_bytes + (512 << 20) + (count + 1) * (128 << 20))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut nodes = Vec::new();
    let mut rows = Vec::new();
    let mut retained = 0usize;
    let prep = weighted::run(
        &weights,
        policy.program_bytes * policy.live_jobs + policy.symbolic_bytes as usize,
        if options.parallel {
            options.preparation_workers
        } else {
            1
        },
        |i| {
            deadline.check()?;
            let start = Instant::now();
            Ok((
                prepare(groups[i].0, groups[i].1)?,
                start.elapsed().as_secs_f64(),
            ))
        },
        |i, (node, compile_seconds), permit| {
            deadline.check()?;
            let (node, setup_seconds, measurement) =
                ProvenNode::prove_gpu(node, cache, architecture::gpu_limits(), || drop(permit))
                    .map_err(error)?;
            node.verify(plan, context).map_err(error)?;
            ensure(node.span() == groups[i], "typed graph compiled span")?;
            retained += node.retained_bytes(ROOT_BYTES - retained).map_err(error)?;
            rows.push(serde_json::json!({"first":groups[i].0,"count":groups[i].1,"parent":false,
                "compile_seconds":compile_seconds,"setup_seconds":setup_seconds,"measurement":measurement}));
            nodes.push(node);
            Ok(())
        },
    )?;
    let leaves = nodes.len();
    let mut order_rejected = false;
    while nodes.len() > 1 {
        let mut next = Vec::new();
        let mut iter = nodes.into_iter();
        loop {
            let children = iter
                .by_ref()
                .take(super::typed::REDUCTION_FAN_IN)
                .collect::<Vec<_>>();
            if children.is_empty() {
                break;
            }
            if children.len() == 1 {
                next.extend(children);
                continue;
            }
            deadline.check()?;
            let start = Instant::now();
            let mut refs = children.iter().collect::<Vec<_>>();
            let node = compile_merge(&refs, construction()).map_err(error)?;
            refs.swap(0, 1);
            ensure(
                compile_merge(&refs, construction()).is_err(),
                "typed graph accepted reordered children",
            )?;
            order_rejected = true;
            for child in &children {
                retained -= child.retained_bytes(ROOT_BYTES).map_err(error)?;
            }
            let child_count = refs.len();
            drop(refs);
            drop(children);
            let compile_seconds = start.elapsed().as_secs_f64();
            let (node, setup_seconds, measurement) =
                ProvenNode::prove_gpu(node, cache, architecture::gpu_limits(), || {})
                    .map_err(error)?;
            node.verify(plan, context).map_err(error)?;
            retained += node.retained_bytes(ROOT_BYTES - retained).map_err(error)?;
            rows.push(serde_json::json!({"parent":true,"children":child_count,"compile_seconds":compile_seconds,
                "setup_seconds":setup_seconds,"measurement":measurement}));
            next.push(node);
        }
        nodes = next;
    }
    let root = nodes.pop().ok_or("missing typed graph root")?;
    let total = groups.iter().map(|g| g.1).sum();
    ensure(
        root.span() == (groups[0].0, total),
        "typed graph coverage changed",
    )?;
    ensure(
        root.rejects_altered_public(),
        "typed graph accepted altered statement",
    )?;
    Ok((
        root,
        serde_json::json!({"seconds":started.elapsed().as_secs_f64(),"leaves":leaves,
        "recursive_proofs":rows.len(),"measurements":rows,"preparation":prep,
        "retained_root_bytes":retained,"public_template_cache":cache.stats(),"source_retired_before_gpu":true,
        "public_mutation_rejected":true,"order_mutation_rejected":order_rejected,
        "independent_cpu_verification":true,"gpu_backend_only":true,"singleton_dry_compilations":0}),
    ))
}
