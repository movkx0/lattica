//! Complete bounded AES/SHAKE request screen; sources are streamed one group at a time.
use super::*;
use crate::component_tree::recursion::{compile_proven, ProvenNode};

pub(super) fn profile(
    weights: &[usize],
    contract: &component_tree::Contract,
    options: &Options,
    deadline: &Deadline,
    prepare: impl Fn(usize) -> Result<(component_tree::CompiledNode, bool)> + Sync,
) -> Result<serde_json::Value> {
    let groups = weights.len();
    ensure(
        (1..=8).contains(&groups),
        "request screen requires one to eight native groups",
    )?;
    let direct = groups == 1;
    let mut samples = Vec::new();
    let mut root_identity = None;
    let mut root_geometry = None;
    let mut cache = lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache::default();
    for repetition in 0..options.repetitions {
        let started = Instant::now();
        let mut proven = Vec::new();
        let mut leaves = Vec::new();
        let mut native_preparation_seconds = 0.0;
        let mut native_order_rejected = false;
        let policy = policy::current();
        let preparation_stats = super::super::weighted::run(
            weights,
            policy.program_bytes * policy.live_jobs + policy.symbolic_bytes as usize,
            options.preparation_workers,
            |index| {
                deadline.check()?;
                let preparation = Instant::now();
                let (node, order_rejected) = prepare(index)?;
                let preparation_seconds = preparation.elapsed().as_secs_f64();
                let started = Instant::now();
                let template = RecursionTemplate::new(
                    node.shared_program(),
                    crate::graph_proofs::compiled_source_fingerprint(),
                )?;
                Ok((
                    node,
                    template,
                    order_rejected,
                    preparation_seconds,
                    started.elapsed().as_secs_f64(),
                ))
            },
            |_, (node, template, order_rejected, seconds, template_seconds), permit| {
                native_order_rejected |= order_rejected;
                native_preparation_seconds += seconds;
                if direct {
                    component_tree::recursion::require_complete(&node, contract).map_err(error)?;
                }
                let setup = Instant::now();
                if direct {
                    if let Some(id) = root_identity {
                        ensure(
                            id == template.identity(),
                            "direct template changed between samples",
                        )?;
                    }
                    root_identity = Some(template.identity());
                    root_geometry = Some(template.geometry()?);
                }
                let owner = cache.prepare(template, gpu_limits())?;
                let setup_seconds = setup.elapsed().as_secs_f64();
                let (node, measurement) =
                    ProvenNode::from_cached_gpu(node, owner, || drop(permit)).map_err(error)?;
                if direct {
                    ensure(
                        node.rejects_altered_statement(),
                        "direct request accepted altered statement",
                    )?;
                }
                proven.push(node);
                leaves.push(
                    serde_json::json!({"template_preparation_seconds":template_seconds,
                        "setup_seconds":setup_seconds,"measurement":measurement}),
                );
                // Compact keys retain neither SSA programs nor public GPU trees.
                Ok(())
            },
        )?;
        let root_measurement = if direct {
            None
        } else {
            let mut children = proven.iter().collect::<Vec<_>>();
            let compile = Instant::now();
            let root = compile_proven(&children, construction()).map_err(error)?;
            component_tree::recursion::require_complete(&root, contract).map_err(error)?;
            let compile_seconds = compile.elapsed().as_secs_f64();
            children.swap(0, 1);
            ensure(
                compile_proven(&children, construction()).is_err(),
                "request accepted reordered children",
            )?;
            deadline.check()?;
            let setup = Instant::now();
            let template = RecursionTemplate::new(
                root.shared_program(),
                crate::graph_proofs::compiled_source_fingerprint(),
            )?;
            if let Some(id) = root_identity {
                ensure(
                    id == template.identity(),
                    "fresh proofs changed root template",
                )?;
            }
            root_identity = Some(template.identity());
            root_geometry = Some(template.geometry()?);
            eprintln!(
                "GPU_AGGREGATION_ARCHITECTURE_REQUEST_GEOMETRY {}",
                serde_json::to_string(root_geometry.as_ref().unwrap()).map_err(error)?
            );
            let owner = cache.prepare(template, gpu_limits())?;
            let setup_seconds = setup.elapsed().as_secs_f64();
            let (root, measurement) =
                ProvenNode::from_cached_gpu(root, owner, || {}).map_err(error)?;
            ensure(
                root.rejects_altered_statement(),
                "request accepted altered statement",
            )?;
            Some(
                serde_json::json!({"compile_seconds":compile_seconds,"setup_seconds":setup_seconds,"measurement":measurement}),
            )
        };
        let sample = serde_json::json!({"repetition":repetition,"seconds":started.elapsed().as_secs_f64(),
            "native_preparation_seconds":native_preparation_seconds,"preparation":preparation_stats,"leaves":leaves,"root":root_measurement,
            "direct_native_batch":direct,"public_mutation_rejected":true,
            "order_mutation_rejected":!direct || native_order_rejected,"complete_request":true});
        eprintln!("GPU_AGGREGATION_ARCHITECTURE_REQUEST {sample}");
        samples.push(sample);
    }
    Ok(
        serde_json::json!({"scope":"complete-crypto-request-gpu-proof","backend":"typed","complete_aggregation":false,
        "complete_request":true,"production_qualified":false,"native_groups":groups,
        "proofs_per_sample":groups+usize::from(!direct),"direct_native_batch":direct,
        "samples":samples,"root_geometry":root_geometry,"root_template_identity":root_identity.map(|id|hex(&id)),
        "independent_cpu_verification":true,"gpu_backend_only":true,
        "native_preparation_included":true,"maximum_live_native_programs":samples.iter().filter_map(|s| s["preparation"]["peak_jobs"].as_u64()).max(),
        "public_preprocessing_retained_across_samples":true,"public_template_cache":cache.stats(),"source_retired_before_gpu":true}),
    )
}
