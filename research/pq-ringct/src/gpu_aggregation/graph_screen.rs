//! A real contiguous graph subtree comparison, never complete graph acceptance.
use super::*;
use crate::{
    graph_auxiliary, graph_sources,
    graph_tree::{self, LeafKind, OperationFamily},
    proof_cache_policy::ProofCachePolicy,
};

fn range(case: &inputs::Case, options: &Options) -> Result<std::ops::Range<usize>> {
    let end = options
        .first_leaf
        .checked_add(options.leaves)
        .ok_or("graph screen range overflow")?;
    ensure(
        end <= case.tree.leaves().len(),
        "graph screen outside trusted schedule",
    )?;
    for leaf in &case.tree.leaves()[options.first_leaf..end] {
        ensure(
            !matches!(
                leaf.kind(),
                LeafKind::Operations(
                    OperationFamily::ParametersPp
                        | OperationFamily::SampleG
                        | OperationFamily::ExpandAlpha
                        | OperationFamily::HashAlpha
                        | OperationFamily::HashX
                )
            ),
            "graph screen requires native/source leaves without recursive dependencies",
        )?;
    }
    Ok(options.first_leaf..end)
}
pub(super) fn prepare(
    case: &inputs::Case,
    options: &Options,
    caches: &bundle::Caches,
    execution: &crate::execution::ProvingContext,
    deadline: &Deadline,
    generated: &mut usize,
) -> Result<usize> {
    let sources = graph_sources::SourceFactory::new(
        &case.tree,
        &case.graph,
        &case.context,
        &case.statement,
        &case.private_proof,
        24 << 30,
    )
    .map_err(error)?;
    let algebra = case.algebra()?;
    let mut count = 0;
    for index in range(case, options)? {
        deadline.check()?;
        if *generated == options.max_components {
            break;
        }
        let leaf = &case.tree.leaves()[index];
        match leaf.kind() {
            LeafKind::FixedSources | LeafKind::Operations(OperationFamily::Equality) => (),
            LeafKind::Statement => {
                if sources
                    .load_statement(&caches.sources)
                    .map_err(error)?
                    .is_none()
                {
                    let proof = sources
                        .prove_statement_with_context(Some(execution))
                        .map_err(error)?;
                    sources
                        .store_statement(&caches.sources, &proof)
                        .map_err(error)?;
                    *generated += 1;
                }
                count += 1;
            }
            LeafKind::PrivateProof => {
                if sources
                    .load_private(&caches.sources)
                    .map_err(error)?
                    .is_none()
                {
                    let proof = sources
                        .prove_private_with_context(Some(execution))
                        .map_err(error)?;
                    sources
                        .store_private(&caches.sources, &proof)
                        .map_err(error)?;
                    *generated += 1;
                }
                count += 1;
            }
            LeafKind::Operations(_) => {
                let batch = algebra
                    .batches()
                    .iter()
                    .position(|b| b.operation_indices() == leaf.operation_indices())
                    .ok_or("native graph leaf missing batch")?;
                if caches
                    .algebra
                    .load(&algebra, batch)
                    .map_err(error)?
                    .is_none()
                {
                    let proof = algebra
                        .prove_batch_with_context(batch, Some(execution))
                        .map_err(error)?;
                    caches
                        .algebra
                        .store(&algebra, batch, &proof)
                        .map_err(error)?;
                    *generated += 1;
                }
                count += 1;
            }
        }
    }
    Ok(count)
}
pub(super) fn screen(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    bundle::validate(options, false)?;
    let (cases, input_sha3) = inputs::load(options)?;
    let case = &cases[0];
    let selected = range(case, options)?;
    let caches = bundle::Caches::new(&options.bundle, false)?;
    let sources = graph_sources::SourceFactory::new(
        &case.tree,
        &case.graph,
        &case.context,
        &case.statement,
        &case.private_proof,
        24 << 30,
    )
    .map_err(error)?;
    let aux =
        graph_auxiliary::AuxiliaryFactory::new(&case.tree, &case.graph, &case.context, 24 << 30)
            .map_err(error)?;
    let algebra = case.algebra()?;
    // Detect every missing or malformed native child before creating a GPU.
    for index in selected.clone() {
        deadline.check()?;
        graph::load_leaf(case, index, &caches, &sources, &aux, &algebra)?;
    }
    let execution = context(options)?;
    let control = crate::proof_cache_policy::Control::new(ProofCachePolicy::FreshOnly);
    let outer = graph_crypto::OuterProofCache::fresh_without_storage(&control);
    let outcome: Result<serde_json::Value> = (|| {
        let prover = graph_tree::GraphProver::new_with_context(
            &case.tree,
            &case.context,
            &outer,
            execution.host_bytes(),
            &execution,
        )
        .map_err(error)?;
        let roots = Vec::new();
        let branches = std::collections::BTreeMap::new();
        let mut samples = Vec::new();
        let width = if options.profile == "legacy" {
            1
        } else {
            options.group_width
        };
        let count = selected.len().div_ceil(width);
        for repetition in 0..options.repetitions {
            let started = Instant::now();
            let mut nodes = Vec::new();
            pipeline::programs(
                count,
                options.parallel,
                options.identity == "gpu-batched",
                &execution,
                |i| {
                    deadline.check()?;
                    let first = selected.start + i * width;
                    let end = selected.end.min(first + width);
                    let loaded = (first..end)
                        .map(|i| graph::load_leaf(case, i, &caches, &sources, &aux, &algebra))
                        .collect::<Result<Vec<_>>>()?;
                    let artifacts = loaded
                        .iter()
                        .map(|l| l.artifact(&roots, &branches))
                        .collect::<Result<Vec<_>>>()?;
                    let compiled = graph_tree::compile_group_bounded(
                        &case.tree,
                        &case.graph,
                        first,
                        &case.context,
                        artifacts,
                        construction(),
                    )
                    .map_err(error)?;
                    ensure(
                        compiled.geometry().map_err(error)?.padded_rows <= MAX_RECURSIVE_ROWS,
                        "graph screen exceeds height ceiling",
                    )?;
                    Ok(compiled)
                },
                |node| node.shared_program(),
                |cohort| {
                    for (_, compiled) in cohort {
                        deadline.check()?;
                        nodes.push(prover.prove_imported_node(compiled).map_err(error)?);
                    }
                    Ok(())
                },
            )?;
            let root = prover
                .aggregate_imported(
                    nodes,
                    options.parallel,
                    options.identity == "gpu-batched",
                    deadline,
                )
                .map_err(error)?;
            ensure(
                root.key().span() == (selected.start, selected.len()),
                "graph screen coverage changed",
            )?;
            root.key().verify(root.proof()).map_err(error)?;
            samples.push(serde_json::json!({"repetition":repetition,"process_state":if repetition==0 {"first-request"}else{"warm-request"},
                "seconds":started.elapsed().as_secs_f64(),"recursive_proofs":2*count-1,"verified":true}));
            eprintln!("GPU_AGGREGATION_SAMPLE {}", samples.last().unwrap());
            execution.release_prepared()?;
        }
        Ok(
            serde_json::json!({"scope":"native-graph-subtree-screen","complete_aggregation":false,"verified":true,
            "first_leaf":selected.start,"leaves":selected.len(),"width":width,"samples":samples,"input_sha3":input_sha3,
            "source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),"identity":execution.aggregation_identity_report()?}),
        )
    })();
    let cleanup = match &outcome {
        Ok(_) => execution.finish(),
        Err(_) => execution.close_without_completion(),
    }?;
    let mut report = outcome?;
    report["session"] = cleanup;
    Ok(report)
}
