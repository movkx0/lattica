//! One bounded CPU preparation window and GPU owner for all crypto parents.
//! Positions are interleaved across requests; exact template identities still
//! decide cache reuse, and every parent contains its own fresh child proofs.
use super::*;
use crate::component_tree::recursion::compile_proven;
use lattica_prover_p3::block_v2::machine::recursion::{GpuRecursionCache, RecursionTemplate};
use std::sync::Mutex;

pub(crate) struct Reduced {
    pub roots: Vec<ProvenNode>,
    pub measurements: Vec<Vec<serde_json::Value>>,
    pub preparation: Vec<weighted::Stats>,
    pub completed: Vec<Option<Instant>>,
    pub retained_bytes: usize,
    pub peak_retained_bytes: usize,
}

struct Job {
    request: usize,
    count: usize,
    retired_bytes: usize,
    root: bool,
    children: Mutex<Option<Vec<ProvenNode>>>,
}

pub(crate) fn reduce(
    mut nodes: Vec<Vec<ProvenNode>>,
    fan_in: usize,
    options: &Options,
    deadline: &Deadline,
    cache: &mut GpuRecursionCache,
    mut retained: usize,
    check_complete: impl Fn(usize, &component_tree::CompiledNode) -> Result<()> + Sync,
    verify_complete: impl Fn(usize, &ProvenNode) -> Result<()>,
) -> Result<Reduced> {
    ensure(matches!(fan_in, 4 | 8), "typed parent fan-in")?;
    ensure(
        nodes.iter().all(|n| !n.is_empty()),
        "empty typed parent request",
    )?;
    ensure(
        retained <= RETAINED_ROOT_BYTES,
        "typed parent input retention",
    )?;
    let mut measurements: Vec<Vec<serde_json::Value>> =
        (0..nodes.len()).map(|_| Vec::new()).collect();
    let mut completed = vec![None; nodes.len()];
    let mut preparation = Vec::new();
    let mut peak_retained = retained;
    let policy = policy::current();
    while nodes.iter().any(|n| n.len() > 1) {
        let lengths = nodes.iter().map(Vec::len).collect::<Vec<_>>();
        let mut next: Vec<Vec<ProvenNode>> = (0..nodes.len()).map(|_| Vec::new()).collect();
        let mut tails = Vec::new();
        let mut jobs = Vec::new();
        let mut weights = Vec::new();
        for (request, children) in weighted::parent_groups(nodes, fan_in) {
            if children.len() == 1 {
                tails.push((request, children));
                continue;
            }
            let retired_bytes = children.iter().try_fold(0usize, |total, child| {
                Ok::<_, String>(
                    total
                        + child
                            .retained_bytes(RETAINED_ROOT_BYTES - total)
                            .map_err(error)?,
                )
            })?;
            let count = children.len();
            weights.push(preparation_weight(
                construction(),
                policy.program_bytes + (512 << 20) + (count + 1) * (128 << 20),
            )?);
            jobs.push(Job {
                request,
                count,
                retired_bytes,
                root: lengths[request] <= fan_in,
                children: Mutex::new(Some(children)),
            });
        }
        let stats = weighted::run(
            &weights,
            policy.program_bytes * policy.live_jobs + policy.symbolic_bytes as usize,
            if options.parallel {
                options.preparation_workers
            } else {
                1
            },
            |index| {
                deadline.check()?;
                let job = &jobs[index];
                let children = job
                    .children
                    .lock()
                    .map_err(error)?
                    .take()
                    .ok_or("typed parent consumed twice")?;
                let compile = Instant::now();
                let mut refs = children.iter().collect::<Vec<_>>();
                let node = compile_proven(&refs, construction()).map_err(error)?;
                refs.swap(0, 1);
                ensure(
                    compile_proven(&refs, construction()).is_err(),
                    "typed parent accepted reordered children",
                )?;
                if job.root {
                    check_complete(job.request, &node)?;
                }
                drop(refs);
                drop(children);
                let compile_seconds = compile.elapsed().as_secs_f64();
                let lowering = Instant::now();
                let template = RecursionTemplate::new(
                    node.shared_program(),
                    crate::graph_proofs::compiled_source_fingerprint(),
                )?;
                let template_seconds = lowering.elapsed().as_secs_f64();
                let witness = template.prepare_gpu_witness(
                    node.public_values(),
                    node.witness_values(),
                    weights[index],
                )?;
                Ok((node, template, witness, compile_seconds, template_seconds))
            },
            |index, (node, template, witness, compile_seconds, template_seconds), permit| {
                deadline.check()?;
                let job = &jobs[index];
                retained = retained
                    .checked_sub(job.retired_bytes)
                    .ok_or("typed parent retention underflow")?;
                let identity = template.identity();
                let (node, setup, measurement) = ProvenNode::prove_prepared_witness_gpu(
                    node,
                    template,
                    witness,
                    cache,
                    architecture::gpu_limits(),
                    || drop(permit),
                )
                .map_err(error)?;
                ensure(
                    node.rejects_altered_statement(),
                    "typed parent accepted altered statement",
                )?;
                retained += node
                    .retained_bytes(RETAINED_ROOT_BYTES - retained)
                    .map_err(error)?;
                peak_retained = peak_retained.max(retained);
                measurements[job.request].push(serde_json::json!({"parent":true,"children":job.count,
                    "compile_seconds":compile_seconds,"template_preparation_seconds":template_seconds,
                    "template_identity":hex(&identity),"setup_seconds":setup,"measurement":measurement,
                    "order_mutation_rejected":true,"public_mutation_rejected":true}));
                if job.root {
                    verify_complete(job.request, &node)?;
                    completed[job.request] = Some(Instant::now());
                }
                next[job.request].push(node);
                Ok(())
            },
        )?;
        for (request, children) in tails {
            next[request].extend(children);
        }
        preparation.push(stats);
        nodes = next;
    }
    let roots = nodes
        .into_iter()
        .map(|mut n| n.pop().ok_or("missing typed request root".into()))
        .collect::<Result<Vec<_>>>()?;
    Ok(Reduced {
        roots,
        measurements,
        preparation,
        completed,
        retained_bytes: retained,
        peak_retained_bytes: peak_retained,
    })
}
