//! All transactions share one graph preparation window and exact GPU cache.
use super::super::typed_graph::{self, GraphWork};
use super::*;

pub(super) struct Inputs {
    pub roots: Roots,
    pub branches: Branches,
}

pub(super) fn request_bytes(
    roots: &BTreeMap<(usize, usize), super::super::typed::Root>,
) -> Result<usize> {
    roots.values().try_fold(0usize, |total, root| {
        let bytes = root
            .node
            .retained_bytes(typed_graph::ROOT_BYTES - total)
            .map_err(error)?;
        Ok(total + bytes)
    })
}

pub(super) fn add_branches(mut total: usize, branches: &Branches) -> Result<usize> {
    for branch in branches.values() {
        total += branch
            .retained_bytes(typed_graph::ROOT_BYTES - total)
            .map_err(error)?;
    }
    Ok(total)
}

pub(super) fn prove_all(
    cases: &[Arc<inputs::Case>],
    inputs: &[Inputs],
    retained_inputs: usize,
    caches: &bundle::Caches,
    execution: &crate::execution::ProvingContext,
    options: &Options,
    width: usize,
    deadline: &Deadline,
) -> Result<(Vec<GraphRoot>, Vec<serde_json::Value>, serde_json::Value)> {
    ensure(cases.len() == inputs.len(), "shared graph input count")?;
    let groups = cases
        .iter()
        .map(|case| typed_graph::groups(0, case.tree.leaves().len(), width))
        .collect::<Result<Vec<_>>>()?;
    let works = cases
        .iter()
        .zip(&groups)
        .map(|(case, groups)| GraphWork {
            plan: &case.tree,
            context: &case.context,
            groups,
        })
        .collect::<Vec<_>>();
    execution.release_prepared()?;
    let mut cache = lattica_prover_p3::block_v2::machine::recursion::GpuRecursionCache::default();
    let result = typed_graph::prove_many(
        &works,
        options,
        deadline,
        &mut cache,
        retained_inputs,
        |transaction, first, count| {
            let case = &cases[transaction];
            let input = &inputs[transaction];
            // Factory/decoder backing is local to this already-admitted CPU
            // job. It is gone before template lowering and never cached.
            let sources = graph_sources::SourceFactory::new(
                &case.tree,
                &case.graph,
                &case.context,
                &case.statement,
                &case.private_proof,
                24 << 30,
            )
            .map_err(error)?;
            let auxiliary = graph_auxiliary::AuxiliaryFactory::new(
                &case.tree,
                &case.graph,
                &case.context,
                24 << 30,
            )
            .map_err(error)?;
            let algebra = case.algebra()?;
            let loaded = (first..first + count)
                .map(|i| load_leaf(case, i, caches, &sources, &auxiliary, &algebra))
                .collect::<Result<Vec<_>>>()?;
            let artifacts = loaded
                .iter()
                .map(|leaf| leaf.artifact(&input.roots, &input.branches))
                .collect::<Result<Vec<_>>>()?;
            graph_tree::compile_group_bounded(
                &case.tree,
                &case.graph,
                first,
                &case.context,
                artifacts,
                construction(),
            )
            .map_err(error)
        },
    )?;
    let roots = result
        .roots
        .into_iter()
        .zip(cases)
        .map(|(root, case)| {
            root.verify_complete(&case.context).map_err(error)?;
            Ok(GraphRoot::Typed(root))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((roots, result.reports, result.pipeline))
}
