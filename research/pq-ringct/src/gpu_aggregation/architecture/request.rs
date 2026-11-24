//! Complete AES/SHAKE requests use the same parent pipeline as the full workflow.
use super::super::typed::{parents, RETAINED_ROOT_BYTES};
use super::*;
use crate::component_tree::recursion::ProvenNode;

pub(super) fn profile(
    weights: &[usize],
    contract: &component_tree::Contract,
    context: &component_tree::EndpointContext,
    options: &Options,
    deadline: &Deadline,
    prepare: impl Fn(usize) -> Result<(component_tree::CompiledNode, bool)> + Sync,
) -> Result<serde_json::Value> {
    let groups = weights.len();
    ensure(
        (1..=8).contains(&groups),
        "request screen requires one to eight native groups",
    )?;
    let repetitions = options.repetitions;
    ensure((1..=3).contains(&repetitions), "request screen repetitions")?;
    let direct = groups == 1;
    let started = Instant::now();
    let jobs = (0..groups)
        .flat_map(|group| (0..repetitions).map(move |repetition| (group, repetition)))
        .collect::<Vec<_>>();
    let weights = jobs
        .iter()
        .map(|(group, _)| weights[*group])
        .collect::<Vec<_>>();
    let mut starts = vec![None; repetitions];
    let mut completed = vec![None; repetitions];
    let mut proven: Vec<Vec<ProvenNode>> = (0..repetitions).map(|_| Vec::new()).collect();
    let mut leaves: Vec<Vec<serde_json::Value>> = (0..repetitions).map(|_| Vec::new()).collect();
    let mut native_seconds = vec![0.0; repetitions];
    let mut native_order_rejected = vec![false; repetitions];
    let mut root_identity = None;
    let mut root_geometry = None;
    let mut cache = lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache::default();
    let mut retained = 0usize;
    let mut peak_retained = 0usize;
    let policy = policy::current();
    let preparation_stats = super::super::weighted::run(
        &weights,
        policy.program_bytes * policy.live_jobs + policy.symbolic_bytes as usize,
        if options.parallel {
            options.preparation_workers
        } else {
            1
        },
        |index| {
            deadline.check()?;
            let start = Instant::now();
            let (node, order_rejected) = prepare(jobs[index].0)?;
            let seconds = start.elapsed().as_secs_f64();
            if direct {
                component_tree::recursion::require_complete(&node, contract).map_err(error)?;
            }
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
            Ok((
                node,
                template,
                witness,
                order_rejected,
                start,
                seconds,
                template_seconds,
            ))
        },
        |index,
         (node, template, witness, order_rejected, start, seconds, template_seconds),
         permit| {
            deadline.check()?;
            let (group, repetition) = jobs[index];
            ensure(
                proven[repetition].len() == group,
                "request native result order",
            )?;
            starts[repetition].get_or_insert(start);
            native_order_rejected[repetition] |= order_rejected;
            native_seconds[repetition] += seconds;
            if direct {
                let id = hex(&template.identity());
                if let Some(expected) = &root_identity {
                    ensure(expected == &id, "direct template changed between samples")?;
                }
                root_identity = Some(id);
                root_geometry = Some(serde_json::to_value(template.geometry()?).map_err(error)?);
            }
            let (node, setup_seconds, measurement) = ProvenNode::prove_prepared_witness_gpu(
                node,
                template,
                witness,
                &mut cache,
                gpu_limits(),
                || drop(permit),
            )
            .map_err(error)?;
            retained += node
                .retained_bytes(RETAINED_ROOT_BYTES - retained)
                .map_err(error)?;
            peak_retained = peak_retained.max(retained);
            if direct {
                node.verify_request(contract, context).map_err(error)?;
                ensure(
                    node.rejects_altered_statement(),
                    "direct request accepted altered statement",
                )?;
                completed[repetition] = Some(Instant::now());
            }
            proven[repetition].push(node);
            leaves[repetition].push(
                serde_json::json!({"template_preparation_seconds":template_seconds,
                "setup_seconds":setup_seconds,"measurement":measurement}),
            );
            Ok(())
        },
    )?;
    // Preserve the screen's existing single parent for up to eight groups.
    let reduced = parents::reduce(
        proven,
        8,
        options,
        deadline,
        &mut cache,
        retained,
        |_, node| component_tree::recursion::require_complete(node, contract).map_err(error),
        |_, node| node.verify_request(contract, context).map_err(error),
    )?;
    peak_retained = peak_retained.max(reduced.peak_retained_bytes);
    let mut samples = Vec::new();
    for (repetition, root) in reduced.roots.into_iter().enumerate() {
        let root_measurement = if direct {
            ensure(
                reduced.measurements[repetition].is_empty(),
                "direct request gained a parent",
            )?;
            None
        } else {
            ensure(
                reduced.measurements[repetition].len() == 1,
                "request parent count changed",
            )?;
            let row = reduced.measurements[repetition][0].clone();
            let identity = row["template_identity"]
                .as_str()
                .ok_or("missing parent identity")?
                .to_owned();
            if let Some(expected) = &root_identity {
                ensure(expected == &identity, "fresh proofs changed root template")?;
            }
            root_identity = Some(identity);
            root_geometry = Some(row["measurement"]["geometry"].clone());
            completed[repetition] = reduced.completed[repetition];
            Some(row)
        };
        drop(root);
        let seconds = completed[repetition]
            .ok_or("request incomplete verification")?
            .duration_since(starts[repetition].ok_or("request missing preparation")?)
            .as_secs_f64();
        let sample = serde_json::json!({"repetition":repetition,"seconds":seconds,
            "timing_scope":"prepare-to-verified latency; independent samples overlap",
            "native_preparation_seconds":native_seconds[repetition],"preparation":preparation_stats,
            "shared_preparation":repetitions>1,"leaves":leaves[repetition],"root":root_measurement,
            "direct_native_batch":direct,"public_mutation_rejected":true,
            "order_mutation_rejected":!direct || native_order_rejected[repetition],"complete_request":true});
        eprintln!("GPU_AGGREGATION_ARCHITECTURE_REQUEST {sample}");
        samples.push(sample);
    }
    let peak_jobs = reduced
        .preparation
        .iter()
        .map(|s| s.peak_jobs)
        .chain(std::iter::once(preparation_stats.peak_jobs))
        .max()
        .unwrap_or(0);
    Ok(
        serde_json::json!({"scope":"complete-crypto-request-gpu-proof","backend":"typed","complete_aggregation":false,
        "complete_request":true,"production_qualified":false,"native_groups":groups,
        "proofs_per_sample":groups+usize::from(!direct),"direct_native_batch":direct,
        "samples":samples,"root_geometry":root_geometry,"root_template_identity":root_identity,
        "independent_cpu_verification":true,"gpu_backend_only":true,
        "native_preparation_included":true,"maximum_live_native_programs":preparation_stats.peak_jobs,
        "maximum_live_preparation_jobs":peak_jobs,
        "public_preprocessing_retained_across_samples":true,"public_template_cache":cache.stats(),"source_retired_before_gpu":true,
        "pipeline":{"seconds":started.elapsed().as_secs_f64(),"repetitions":repetitions,
            "repetitions_pipelined":repetitions>1,"parent_preparation":reduced.preparation,
            "schedule":"position-before-request","retained_peak_bytes":peak_retained,"retained_limit_bytes":RETAINED_ROOT_BYTES,
            "timing_scope":"all independent requests complete, including CPU preparation and verification"}}),
    )
}
