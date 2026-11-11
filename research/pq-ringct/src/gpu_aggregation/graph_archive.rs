//! Bounded graph subtree comparison on revalidated unchanged native proofs.
use super::*;
use crate::{
    graph_tree,
    proof_cache_policy::{Control, ProofCachePolicy},
};

pub(crate) fn run(options: &Options, deadline: &Deadline) -> Result<serde_json::Value> {
    let (source, inventory) = bundle::validate_archive(options)?;
    let (cases, input_sha3) = inputs::load(options)?;
    let case = &cases[0];
    let end = options
        .first_leaf
        .checked_add(options.leaves)
        .ok_or("graph archive range overflow")?;
    ensure(
        end <= case.tree.leaves().len(),
        "graph archive schedule range",
    )?;
    let algebra = case.algebra()?;
    let mut indices = Vec::new();
    for leaf in &case.tree.leaves()[options.first_leaf..end] {
        ensure(
            matches!(leaf.kind(), graph_tree::LeafKind::Operations(_)),
            "graph archive requires algebra leaves",
        )?;
        let index = algebra
            .batches()
            .iter()
            .position(|b| b.operation_indices() == leaf.operation_indices())
            .ok_or("graph archive leaf has no native algebra batch")?;
        let key = algebra.cache_key_at_source(index, source).map_err(error)?;
        let path = format!("algebra/{}.json", hex(&key));
        ensure(
            inventory.contains_key(&path),
            "graph archive component absent from inventory",
        )?;
        indices.push((index, key, path));
    }
    let caches = bundle::Caches::new(&options.bundle, false)?;
    let width = options.group_width.min(8);
    let groups = typed_graph::groups(options.first_leaf, options.leaves, width)?;
    let imports = std::sync::Mutex::new(std::collections::BTreeMap::new());
    let execution = context(options)?;
    let result: Result<serde_json::Value> = (|| {
        let limits = execution.aggregation_backend_limits()?;
        let prepare = |first: usize, count: usize| -> Result<graph_tree::CompiledNode> {
            deadline.check()?;
            let mut artifacts = Vec::new();
            for i in first..first + count {
                let (index, key, path) = &indices[i - options.first_leaf];
                let native = caches
                    .algebra
                    .reverify_archived_entry(&algebra, *index, options.bundle.join(path))
                    .map_err(error)?;
                ensure(
                    native.archived_key == hex(key)
                        && hex(&native.archive_sha3_256) == inventory[path],
                    "graph archive changed during revalidation",
                )?;
                imports.lock().map_err(error)?.insert(i,serde_json::json!({"leaf":i,"archive_key":hex(key),
                    "archive_sha3":hex(&native.archive_sha3_256),"current_key":hex(&native.current_key),
                    "verified_against_current_contract":true}));
                artifacts.push(native.artifact);
            }
            let node = graph_tree::compile_group_bounded(
                &case.tree,
                &case.graph,
                first,
                &case.context,
                artifacts.iter().map(|a| a.as_leaf_artifact()).collect(),
                construction(),
            )
            .map_err(error)?;
            if !options.typed_recursion() {
                node.preflight_imported(limits)?;
            }
            Ok(node)
        };
        let control = Control::new(ProofCachePolicy::FreshOnly);
        let outer = graph_crypto::OuterProofCache::fresh_without_storage(&control);
        let prover = graph_tree::GraphProver::new_with_context(
            &case.tree,
            &case.context,
            &outer,
            execution.host_bytes(),
            &execution,
        )
        .map_err(error)?;
        let mut cache =
            lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache::default();
        let mut samples = Vec::new();
        for repetition in 0..options.repetitions {
            deadline.check()?;
            let start = Instant::now();
            let mut sample = if options.typed_recursion() {
                let (root, report) = typed_graph::prove(
                    &groups,
                    &case.tree,
                    &case.context,
                    options,
                    deadline,
                    &mut cache,
                    &prepare,
                )?;
                ensure(
                    root.span() == (options.first_leaf, options.leaves),
                    "typed graph screen coverage",
                )?;
                root.verify(&case.tree, &case.context).map_err(error)?;
                report
            } else {
                let root = prover
                    .prove_imported_tree(
                        groups.len(),
                        |i| prepare(groups[i].0, groups[i].1),
                        deadline,
                    )
                    .map_err(error)?;
                ensure(
                    root.key().span() == (options.first_leaf, options.leaves),
                    "machine graph screen coverage",
                )?;
                root.key().verify(root.proof()).map_err(error)?;
                let (key, mut proof) = root.into_parts();
                use p3_field::PrimeCharacteristicRing;
                proof.public[graph_tree::STATEMENT] += Val::ONE;
                ensure(
                    key.verify(&proof).is_err(),
                    "machine graph accepted altered statement",
                )?;
                serde_json::json!({"recursive_proofs":2*groups.len()-1,"public_mutation_rejected":true,
                    "independent_cpu_verification":true,"gpu_backend_only":true,"production_cpu_lookahead":true})
            };
            sample["seconds"] = serde_json::json!(start.elapsed().as_secs_f64());
            sample["repetition"] = serde_json::json!(repetition);
            sample["verified"] = serde_json::json!(true);
            eprintln!("GPU_AGGREGATION_GRAPH_ARCHITECTURE {sample}");
            samples.push(sample);
        }
        Ok(
            serde_json::json!({"scope":"recursion-graph-subtree-screen","complete_aggregation":false,
            "complete_graph":false,"verified":true,"backend":options.recursion_backend,
            "first_leaf":options.first_leaf,"leaves":options.leaves,"width":width,"groups":groups,
            "samples":samples,"imports":imports,"native_proofs_generated":0,"archive_files_rewritten":0,
            "current_cache_entries_created":0,"source_sha3":hex(&crate::graph_proofs::compiled_source_fingerprint()),
            "input_sha3":input_sha3,"archive_source_sha3":hex(&source)}),
        )
    })();
    let cleanup = execution.close_without_completion()?;
    let mut report = result?;
    report["session"] = cleanup;
    Ok(report)
}
