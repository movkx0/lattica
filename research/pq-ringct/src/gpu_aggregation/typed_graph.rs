//! Stream checked native graph groups directly into typed proofs, then reduce
//! up to eight adjacent children within the selected construction policy.
use super::*;
use crate::graph_tree::{
    self,
    recursion::{compile_merge, ProvenNode},
};
use lattica_prover_p3::block_v2::machine::recursion::{
    GpuProofMeasurement, GpuRecursionCache, RecursionTemplate,
};
const ROOT_BYTES: usize = 2 << 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_native_groups_keep_exact_coverage_and_bounded_policy() {
        assert_eq!(groups(4, 16, 16).unwrap(), vec![(4, 16)]);
        assert_eq!(groups(4, 17, 16).unwrap(), vec![(4, 16), (20, 1)]);
        assert_eq!(
            groups(0, 91, 16).unwrap(),
            vec![(0, 16), (16, 16), (32, 16), (48, 16), (64, 16), (80, 11)]
        );
        assert!(groups(usize::MAX - 7, 16, 16).is_err());
        assert!(groups(0, 1, 32).is_err());
        let parse = |case: &str, command: &str, policy: &str, leaves: &str| {
            Options::parse(
                [
                    command,
                    "--case",
                    case,
                    "--input-bundle",
                    "/tmp/graph-wide",
                    "--screen-family",
                    "graph",
                    "--compiler-policy",
                    policy,
                    "--native-source",
                    if command == "prepare-inputs" {
                        "current"
                    } else {
                        "revalidate-archive"
                    },
                    "--leaves",
                    leaves,
                ]
                .into_iter()
                .map(String::from),
            )
        };
        let wide = parse("n4", "architecture-graph", "typed-batch", "16").unwrap();
        assert_eq!(native_group_limit(&wide), 16);
        assert!(parse("n4", "architecture-graph", "standard", "16").is_err());
        assert!(parse("n3", "architecture-graph", "standard", "16").is_err());
        assert!(parse("n4", "architecture-graph", "typed-batch", "17").is_err());
        assert!(parse("n4", "prepare-inputs", "standard", "16").is_ok());
    }
}

pub(crate) fn native_group_limit(options: &Options) -> usize {
    if options.typed_recursion() && options.compiler_policy == "typed-batch" {
        16
    } else {
        8
    }
}

pub(crate) fn groups(first: usize, count: usize, maximum: usize) -> Result<Vec<(usize, usize)>> {
    ensure(
        count != 0 && matches!(maximum, 1 | 2 | 4 | 8 | 16),
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
struct PreparedNative {
    node: graph_tree::CompiledNode,
    template: Option<RecursionTemplate>,
    compile_seconds: f64,
    template_seconds: f64,
    started: Instant,
}

fn prepare_native(
    groups: &[(usize, usize)],
    options: &Options,
    deadline: &Deadline,
    prepare: impl Fn(usize, usize) -> Result<graph_tree::CompiledNode> + Sync,
    consume: impl FnMut(usize, PreparedNative, weighted::Permit) -> Result<()>,
) -> Result<weighted::Stats> {
    let policy = policy::current();
    let weights = groups
        .iter()
        .map(|(_, count)| {
            ensure(
                (1..=native_group_limit(options)).contains(count),
                "typed graph native count",
            )?;
            super::typed::preparation_weight(
                construction(),
                policy.program_bytes + (512 << 20) + (count + 1) * (128 << 20),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    weighted::run(
        &weights,
        policy.program_bytes * policy.live_jobs + policy.symbolic_bytes as usize,
        if options.parallel {
            options.preparation_workers
        } else {
            1
        },
        |i| {
            deadline.check()?;
            let started = Instant::now();
            let node = prepare(groups[i].0, groups[i].1)?;
            let compile_seconds = started.elapsed().as_secs_f64();
            let lowering = Instant::now();
            let template = if options.template_preparation == "worker" {
                Some(RecursionTemplate::new(
                    node.shared_program(),
                    crate::graph_proofs::compiled_source_fingerprint(),
                )?)
            } else {
                None
            };
            Ok(PreparedNative {
                node,
                template,
                compile_seconds,
                template_seconds: lowering.elapsed().as_secs_f64(),
                started,
            })
        },
        consume,
    )
}

fn prove_native(
    node: graph_tree::CompiledNode,
    template: Option<RecursionTemplate>,
    cache: &mut GpuRecursionCache,
    release: impl FnOnce(),
) -> Result<(ProvenNode, f64, GpuProofMeasurement)> {
    match template {
        Some(template) => ProvenNode::prove_prepared_gpu(
            node,
            template,
            cache,
            architecture::gpu_limits(),
            release,
        ),
        None => ProvenNode::prove_gpu(node, cache, architecture::gpu_limits(), release),
    }
    .map_err(error)
}

/// Repeated independent proofs exercise the same preparation/GPU pipeline as
/// ordinary native groups. Report its makespan separately from request latency.
pub(crate) fn prove_repeated_direct(
    group: (usize, usize),
    plan: &graph_tree::Plan,
    context: &graph_tree::GraphContext,
    options: &Options,
    deadline: &Deadline,
    cache: &mut GpuRecursionCache,
    prepare: impl Fn(usize, usize) -> Result<graph_tree::CompiledNode> + Sync,
) -> Result<(Vec<serde_json::Value>, serde_json::Value)> {
    let started = Instant::now();
    let groups = vec![group; options.repetitions];
    let mut samples = Vec::new();
    let stats = prepare_native(&groups, options, deadline, prepare, |i, job, permit| {
        deadline.check()?;
        let (root, setup_seconds, measurement) =
            prove_native(job.node, job.template, cache, || drop(permit)).map_err(error)?;
        root.verify(plan, context).map_err(error)?;
        ensure(root.span() == group, "independent graph coverage changed")?;
        ensure(
            root.rejects_altered_public(),
            "independent graph accepted altered statement",
        )?;
        let retained = root.retained_bytes(ROOT_BYTES).map_err(error)?;
        let sample = serde_json::json!({"repetition":i,"seconds":job.started.elapsed().as_secs_f64(),
            "timing_scope":"prepare-to-verified latency; independent samples overlap",
            "leaves":1,"reduction_fan_in":super::typed::reduction_fan_in(),"recursive_proofs":1,
            "measurements":[{"first":group.0,"count":group.1,"parent":false,
                "compile_seconds":job.compile_seconds,"template_preparation_seconds":job.template_seconds,
                "setup_seconds":setup_seconds,"measurement":measurement}],
            "retained_root_bytes":retained,"public_template_cache":cache.stats(),
            "verified":true,"public_mutation_rejected":true,"order_mutation_rejected":false,
            "independent_cpu_verification":true,"gpu_backend_only":true,
            "source_retired_before_gpu":true,"singleton_dry_compilations":0});
        eprintln!("GPU_AGGREGATION_GRAPH_ARCHITECTURE {sample}");
        samples.push(sample);
        Ok(())
    })?;
    Ok((
        samples,
        serde_json::json!({"seconds":started.elapsed().as_secs_f64(),
        "repetitions_pipelined":true,"repetitions":groups.len(),"preparation":stats,
        "template_preparation":options.template_preparation,
        "timing_scope":"all independent proofs complete, including CPU preparation and verification"}),
    ))
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
    let mut nodes = Vec::new();
    let mut rows = Vec::new();
    let mut retained = 0usize;
    let prep = prepare_native(groups, options, deadline, prepare, |i, job, permit| {
        deadline.check()?;
        let (node, setup_seconds, measurement) =
            prove_native(job.node, job.template, cache, || drop(permit)).map_err(error)?;
        node.verify(plan, context).map_err(error)?;
        ensure(node.span() == groups[i], "typed graph compiled span")?;
        retained += node.retained_bytes(ROOT_BYTES - retained).map_err(error)?;
        rows.push(serde_json::json!({"first":groups[i].0,"count":groups[i].1,"parent":false,
                "compile_seconds":job.compile_seconds,"template_preparation_seconds":job.template_seconds,
                "setup_seconds":setup_seconds,"measurement":measurement}));
        nodes.push(node);
        Ok(())
    })?;
    let leaves = nodes.len();
    let mut order_rejected = false;
    while nodes.len() > 1 {
        let mut next = Vec::new();
        let mut iter = nodes.into_iter();
        loop {
            let children = iter
                .by_ref()
                .take(super::typed::reduction_fan_in())
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
        serde_json::json!({"seconds":started.elapsed().as_secs_f64(),"leaves":leaves,"reduction_fan_in":super::typed::reduction_fan_in(),
        "recursive_proofs":rows.len(),"measurements":rows,"preparation":prep,
        "retained_root_bytes":retained,"public_template_cache":cache.stats(),"source_retired_before_gpu":true,
        "public_mutation_rejected":true,"order_mutation_rejected":order_rejected,
        "independent_cpu_verification":true,"gpu_backend_only":true,"singleton_dry_compilations":0}),
    ))
}
