//! Stream checked native graph groups directly into typed proofs, then reduce
//! up to eight adjacent children within the selected construction policy.
use super::*;
use crate::graph_tree::{
    self,
    recursion::{compile_merge, ProvenNode},
};
use lattica_prover_p3::block_v2::machine::recursion::{
    GpuProofMeasurement, GpuRecursionCache, PreparedRecursionWitness, RecursionTemplate,
};
pub(super) const ROOT_BYTES: usize = 2 << 30;

mod batch;
pub(crate) use batch::{prove_many, GraphWork};

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
struct PreparedNode {
    node: graph_tree::CompiledNode,
    template: Option<RecursionTemplate>,
    witness: Option<PreparedRecursionWitness>,
    compile_seconds: f64,
    template_seconds: f64,
    started: Instant,
}

fn prepare_indexed(
    counts: &[usize],
    options: &Options,
    deadline: &Deadline,
    prepare: impl Fn(usize) -> Result<graph_tree::CompiledNode> + Sync,
    consume: impl FnMut(usize, PreparedNode, weighted::Permit) -> Result<()>,
) -> Result<weighted::Stats> {
    let policy = policy::current();
    let weights = counts
        .iter()
        .map(|count| {
            ensure(
                (1..=native_group_limit(options)).contains(count),
                "typed graph preparation count",
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
            let node = prepare(i)?;
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
            let template_seconds = lowering.elapsed().as_secs_f64();
            let witness = match &template {
                Some(template) => template.prepare_gpu_witness(
                    node.public_values(),
                    node.witness_values(),
                    weights[i],
                )?,
                None => None,
            };
            Ok(PreparedNode {
                node,
                template,
                witness,
                compile_seconds,
                template_seconds,
                started,
            })
        },
        consume,
    )
}

fn prove_prepared(
    node: graph_tree::CompiledNode,
    template: Option<RecursionTemplate>,
    witness: Option<PreparedRecursionWitness>,
    cache: &mut GpuRecursionCache,
    release: impl FnOnce(),
) -> Result<(ProvenNode, f64, GpuProofMeasurement)> {
    match template {
        Some(template) => ProvenNode::prove_prepared_witness_gpu(
            node,
            template,
            witness,
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
pub(crate) fn prove_repeated(
    groups: &[(usize, usize)],
    plan: &graph_tree::Plan,
    context: &graph_tree::GraphContext,
    options: &Options,
    deadline: &Deadline,
    cache: &mut GpuRecursionCache,
    prepare: impl Fn(usize, usize) -> Result<graph_tree::CompiledNode> + Sync,
) -> Result<(Vec<serde_json::Value>, serde_json::Value)> {
    let works = (0..options.repetitions)
        .map(|_| GraphWork {
            plan,
            context,
            groups,
        })
        .collect::<Vec<_>>();
    let batch::BatchResult {
        roots,
        mut reports,
        mut pipeline,
    } = prove_many(&works, options, deadline, cache, 0, |_, first, count| {
        prepare(first, count)
    })?;
    drop(roots);
    for (repetition, sample) in reports.iter_mut().enumerate() {
        sample["repetition"] = serde_json::json!(repetition);
        sample["verified"] = serde_json::json!(true);
        eprintln!("GPU_AGGREGATION_GRAPH_ARCHITECTURE {sample}");
    }
    pipeline["repetitions_pipelined"] = serde_json::json!(true);
    pipeline["repetitions"] = serde_json::json!(reports.len());
    Ok((reports, pipeline))
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
    let work = GraphWork {
        plan,
        context,
        groups,
    };
    let mut result = prove_many(&[work], options, deadline, cache, 0, |_, first, count| {
        prepare(first, count)
    })?;
    let mut report = result.reports.pop().ok_or("missing typed graph report")?;
    report["seconds"] = result.pipeline["seconds"].clone();
    Ok((
        result.roots.pop().ok_or("missing typed graph root")?,
        report,
    ))
}
