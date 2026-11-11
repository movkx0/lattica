//! Fresh singleton/binary MachineAir reference using the production CPU lookahead.
use super::*;

pub(super) fn profile(
    groups: usize,
    endpoints: &component_tree::EndpointContext,
    options: &Options,
    deadline: &Deadline,
    execution: &crate::execution::ProvingContext,
    prepare: impl Fn(usize) -> Result<(component_tree::CompiledNode, bool)> + Sync,
) -> Result<serde_json::Value> {
    use p3_field::PrimeCharacteristicRing;
    ensure(
        options.family == "aes" && options.group_width == 1 && (1..=8).contains(&groups),
        "machine reference requires one to eight singleton AES leaves",
    )?;
    let control = crate::proof_cache_policy::Control::new(
        crate::proof_cache_policy::ProofCachePolicy::FreshOnly,
    );
    let outer = component_tree::OuterProofCache::fresh_without_storage(&control);
    let preflight = execution.aggregation_backend_limits()?;
    let mut samples = Vec::new();
    for repetition in 0..options.repetitions {
        let start = Instant::now();
        let mut leaves = Vec::new();
        let mut parents = Vec::new();
        let native_preparation_seconds = std::sync::Mutex::new(0.0);
        let mut root = super::super::pipeline::tree_programs(
            groups,
            execution,
            |index| {
                deadline.check()?;
                let prepared = Instant::now();
                let (node, _) = prepare(index)?;
                let seconds = prepared.elapsed().as_secs_f64();
                *native_preparation_seconds.lock().map_err(error)? += seconds;
                Ok((true, node, seconds))
            },
            |left: &component_tree::CacheOutcome, right: &component_tree::CacheOutcome| {
                deadline.check()?;
                let started = Instant::now();
                ensure(
                    component_tree::compile_imported_merge(
                        &right.key,
                        &left.key,
                        [&right.proof, &left.proof],
                    )
                    .is_err(),
                    "reference accepted reordered children",
                )?;
                let node = component_tree::compile_imported_merge(
                    &left.key,
                    &right.key,
                    [&left.proof, &right.proof],
                )
                .map_err(error)?;
                node.preflight_imported(preflight)?;
                Ok((false, node, started.elapsed().as_secs_f64()))
            },
            |(_, node, _)| node.shared_program(),
            |(leaf, node, compile_seconds)| {
                deadline.check()?;
                ensure(
                    node.geometry().map_err(error)?.padded_rows
                        <= execution.aggregation_row_limit()
                        && node.program().construction_host_bytes()
                            <= component_tree::paired_runtime::source::PROGRAM_BYTES,
                    "machine reference source compiler/row ceiling",
                )?;
                let started = Instant::now();
                let proof = node
                    .prove_imported_with_context(execution, &outer)
                    .map_err(error)?;
                ensure(!proof.cache_hit, "reference unexpectedly reused a proof")?;
                let measure = serde_json::json!({"seconds":started.elapsed().as_secs_f64(),
                    "compile_seconds":compile_seconds,"verified":true});
                if leaf {
                    leaves.push(measure);
                } else {
                    parents.push(measure);
                }
                Ok(proof)
            },
        )?;
        root.key
            .verify_request(&root.proof, endpoints)
            .map_err(error)?;
        root.proof.public[component_tree::STATEMENT] += Val::ONE;
        ensure(
            root.key.verify(&root.proof).is_err(),
            "reference accepted altered statement",
        )?;
        let sample = serde_json::json!({"repetition":repetition,"seconds":start.elapsed().as_secs_f64(),
            "native_preparation_seconds":*native_preparation_seconds.lock().map_err(error)?,"leaves":leaves,"parents":parents,
            "complete_request":true,"public_mutation_rejected":true,"order_mutation_rejected":groups>1});
        eprintln!("GPU_AGGREGATION_ARCHITECTURE_REFERENCE {sample}");
        samples.push(sample);
    }
    Ok(
        serde_json::json!({"scope":"complete-crypto-request-gpu-proof","backend":"machine",
        "complete_aggregation":false,"complete_request":true,"production_qualified":false,
        "native_groups":groups,"proofs_per_sample":2*groups-1,"samples":samples,
        "production_cpu_lookahead":true,"native_preparation_included":true,
        "independent_cpu_verification":true,"gpu_backend_only":true}),
    )
}
