//! Keep matching graph positions adjacent across independent transactions.
//! Sharing is only a scheduling hint: the GPU cache still compares the exact
//! trusted template identity, and every proof is checked against its own graph.
use super::super::weighted::parent_groups;
use super::*;
use std::sync::Mutex;

pub(crate) struct GraphWork<'a> {
    pub plan: &'a graph_tree::Plan,
    pub context: &'a graph_tree::GraphContext,
    pub groups: &'a [(usize, usize)],
}

pub(crate) struct BatchResult {
    pub roots: Vec<ProvenNode>,
    pub reports: Vec<serde_json::Value>,
    pub pipeline: serde_json::Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    graph: usize,
    group: usize,
    span: (usize, usize),
}

fn schedule(groups: &[&[(usize, usize)]]) -> Result<Vec<Slot>> {
    ensure((1..=4).contains(&groups.len()), "typed graph batch count")?;
    let mut slots = Vec::new();
    for (graph, groups) in groups.iter().enumerate() {
        ensure(!groups.is_empty(), "empty typed graph")?;
        for pair in groups.windows(2) {
            ensure(
                pair[0].0.checked_add(pair[0].1) == Some(pair[1].0),
                "typed graph schedule adjacency",
            )?;
        }
        for (group, &span) in groups.iter().enumerate() {
            ensure(
                span.1 != 0 && span.0.checked_add(span.1).is_some(),
                "typed graph schedule span",
            )?;
            ensure(slots.len() < 65536, "typed graph schedule size")?;
            slots.push(Slot { graph, group, span });
        }
    }
    slots.sort_by_key(|s| (s.group, s.span, s.graph));
    Ok(slots)
}

fn check_root(root: &ProvenNode, work: &GraphWork<'_>) -> Result<()> {
    root.verify(work.plan, work.context).map_err(error)?;
    let first = work.groups[0].0;
    let last = work.groups.last().unwrap();
    let end = last
        .0
        .checked_add(last.1)
        .ok_or("typed graph coverage overflow")?;
    ensure(
        root.span() == (first, end - first),
        "typed graph coverage changed",
    )?;
    ensure(
        root.rejects_altered_public(),
        "typed graph accepted altered statement",
    )
}

pub(crate) fn prove_many(
    works: &[GraphWork<'_>],
    options: &Options,
    deadline: &Deadline,
    cache: &mut GpuRecursionCache,
    retained_inputs: usize,
    prepare: impl Fn(usize, usize, usize) -> Result<graph_tree::CompiledNode> + Sync,
) -> Result<BatchResult> {
    ensure(retained_inputs <= ROOT_BYTES, "typed graph input retention")?;
    let spans = works.iter().map(|w| w.groups).collect::<Vec<_>>();
    let slots = schedule(&spans)?;
    let counts = slots.iter().map(|s| s.span.1).collect::<Vec<_>>();
    let started = Instant::now();
    let mut nodes: Vec<Vec<ProvenNode>> = (0..works.len()).map(|_| Vec::new()).collect();
    let mut rows: Vec<Vec<serde_json::Value>> = (0..works.len()).map(|_| Vec::new()).collect();
    let mut first_started = vec![None; works.len()];
    let mut completed = vec![None; works.len()];
    let mut cache_at_completion = vec![cache.stats(); works.len()];
    let mut order_rejected = vec![false; works.len()];
    let mut retained = retained_inputs;
    let mut peak_retained = retained;
    let prep = prepare_indexed(
        &counts,
        options,
        deadline,
        |index| {
            let slot = slots[index];
            prepare(slot.graph, slot.span.0, slot.span.1)
        },
        |index, job, permit| {
            deadline.check()?;
            let slot = slots[index];
            let work = &works[slot.graph];
            ensure(
                nodes[slot.graph].len() == slot.group,
                "typed graph result order",
            )?;
            first_started[slot.graph].get_or_insert(job.started);
            let (node, setup_seconds, measurement) =
                prove_prepared(job.node, job.template, job.witness, cache, || drop(permit))?;
            node.verify(work.plan, work.context).map_err(error)?;
            ensure(node.span() == slot.span, "typed graph compiled span")?;
            retained += node.retained_bytes(ROOT_BYTES - retained).map_err(error)?;
            peak_retained = peak_retained.max(retained);
            rows[slot.graph].push(serde_json::json!({"first":slot.span.0,"count":slot.span.1,"parent":false,
                "compile_seconds":job.compile_seconds,"template_preparation_seconds":job.template_seconds,
                "setup_seconds":setup_seconds,"measurement":measurement}));
            if work.groups.len() == 1 {
                check_root(&node, work)?;
                completed[slot.graph] = Some(Instant::now());
                cache_at_completion[slot.graph] = cache.stats();
            }
            nodes[slot.graph].push(node);
            Ok(())
        },
    )?;

    // Prepare the next parent while the preceding parent is on the GPU.
    // A single ownership slot moves each child's proof into its admitted job;
    // all children are gone before template lowering or GPU preparation.
    let mut parent_preparation = Vec::new();
    while nodes.iter().any(|n| n.len() > 1) {
        let lengths = nodes.iter().map(Vec::len).collect::<Vec<_>>();
        let mut next: Vec<Vec<ProvenNode>> = (0..works.len()).map(|_| Vec::new()).collect();
        let mut jobs = Vec::new();
        let mut counts = Vec::new();
        let mut tails = Vec::new();
        for (graph, children) in parent_groups(nodes, super::super::typed::reduction_fan_in()) {
            if children.len() == 1 {
                tails.push((graph, children));
                continue;
            }
            let bytes = children.iter().try_fold(0usize, |bytes, child| {
                Ok::<_, String>(bytes + child.retained_bytes(ROOT_BYTES - bytes).map_err(error)?)
            })?;
            counts.push(children.len());
            jobs.push((graph, bytes, Mutex::new(Some(children))));
        }
        let stats = prepare_indexed(
            &counts,
            options,
            deadline,
            |index| {
                let children = jobs[index]
                    .2
                    .lock()
                    .map_err(error)?
                    .take()
                    .ok_or("typed graph parent consumed twice")?;
                let mut refs = children.iter().collect::<Vec<_>>();
                let node = compile_merge(&refs, construction()).map_err(error)?;
                refs.swap(0, 1);
                ensure(
                    compile_merge(&refs, construction()).is_err(),
                    "typed graph accepted reordered children",
                )?;
                drop(refs);
                drop(children);
                Ok(node)
            },
            |index, job, permit| {
                deadline.check()?;
                let (graph, retired, _) = &jobs[index];
                let graph = *graph;
                retained = retained
                    .checked_sub(*retired)
                    .ok_or("typed graph retention underflow")?;
                let (node, setup_seconds, measurement) =
                    prove_prepared(job.node, job.template, job.witness, cache, || drop(permit))?;
                node.verify(works[graph].plan, works[graph].context)
                    .map_err(error)?;
                retained += node.retained_bytes(ROOT_BYTES - retained).map_err(error)?;
                peak_retained = peak_retained.max(retained);
                order_rejected[graph] = true;
                rows[graph].push(serde_json::json!({"parent":true,"children":counts[index],
                    "compile_seconds":job.compile_seconds,"template_preparation_seconds":job.template_seconds,
                    "setup_seconds":setup_seconds,"measurement":measurement}));
                if lengths[graph] <= super::super::typed::reduction_fan_in() {
                    check_root(&node, &works[graph])?;
                    completed[graph] = Some(Instant::now());
                    cache_at_completion[graph] = cache.stats();
                }
                next[graph].push(node);
                Ok(())
            },
        )?;
        // Unmerged odd tails follow every parent of their own graph.
        for (graph, children) in tails {
            next[graph].extend(children);
        }
        parent_preparation.push(stats);
        nodes = next;
    }
    let mut roots = Vec::new();
    let mut reports = Vec::new();
    let prep = serde_json::to_value(prep).map_err(error)?;
    for (graph, mut nodes) in nodes.into_iter().enumerate() {
        ensure(nodes.len() == 1, "typed graph final root count")?;
        let root = nodes.pop().unwrap();
        let seconds = completed[graph]
            .ok_or("typed graph incomplete verification")?
            .duration_since(first_started[graph].ok_or("typed graph missing preparation")?)
            .as_secs_f64();
        ensure(
            rows[graph].len() == super::super::typed::proof_count(works[graph].groups.len()),
            "typed graph proof count changed",
        )?;
        reports.push(serde_json::json!({"seconds":seconds,"leaves":works[graph].groups.len(),
            "timing_scope":"prepare-to-verified latency; independent samples overlap",
            "reduction_fan_in":super::super::typed::reduction_fan_in(),"recursive_proofs":rows[graph].len(),
            "measurements":rows[graph],"preparation":prep,"shared_preparation":works.len()>1,
            "retained_root_bytes":root.retained_bytes(ROOT_BYTES).map_err(error)?,
            "public_template_cache":cache_at_completion[graph],"source_retired_before_gpu":true,
            "public_mutation_rejected":true,"order_mutation_rejected":order_rejected[graph],
            "independent_cpu_verification":true,"gpu_backend_only":true,"singleton_dry_compilations":0}));
        roots.push(root);
    }
    Ok(BatchResult {
        roots,
        reports,
        pipeline: serde_json::json!({
            "seconds":started.elapsed().as_secs_f64(),"graphs":works.len(),"preparation":prep,
            "parent_preparation":parent_preparation,
        "template_preparation":options.template_preparation,"public_template_cache":cache.stats(),
        "retained_inputs_bytes":retained_inputs,"retained_peak_bytes":peak_retained,
        "retained_limit_bytes":ROOT_BYTES,"schedule":"position-before-transaction",
        "timing_scope":"all independent graphs complete, including CPU preparation and verification"}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn graph_positions_share_a_window_without_changing_each_graph_order() {
        let a = [(0, 16), (16, 16), (32, 3)];
        let b = [(0, 16), (16, 5)];
        let c = [(4, 8)];
        let schedules: [&[(usize, usize)]; 3] = [&a, &b, &c];
        let slots = schedule(&schedules).unwrap();
        assert_eq!(
            slots.iter().map(|s| s.graph).collect::<Vec<_>>(),
            [0, 1, 2, 1, 0, 0]
        );
        for (graph, expected) in schedules.iter().enumerate() {
            assert_eq!(
                slots
                    .iter()
                    .filter(|s| s.graph == graph)
                    .map(|s| s.span)
                    .collect::<Vec<_>>(),
                *expected
            );
        }
    }
    #[test]
    fn parent_positions_preserve_uneven_graphs_and_odd_tails() {
        for fan_in in [4, 8] {
            let nodes = vec![(0..17).collect::<Vec<_>>(), (100..103).collect(), vec![200]];
            let expected = nodes.clone();
            let groups = parent_groups(nodes, fan_in).collect::<Vec<_>>();
            assert_eq!(
                groups
                    .iter()
                    .take(3)
                    .map(|(graph, _)| *graph)
                    .collect::<Vec<_>>(),
                [0, 1, 2]
            );
            for (graph, expected) in expected.iter().enumerate() {
                let actual = groups
                    .iter()
                    .filter(|(i, _)| *i == graph)
                    .flat_map(|(_, children)| children.iter().copied())
                    .collect::<Vec<_>>();
                assert_eq!(&actual, expected);
                assert!(groups
                    .iter()
                    .filter(|(i, _)| *i == graph)
                    .all(|(_, children)| !children.is_empty() && children.len() <= fan_in));
            }
        }
        assert_eq!(parent_groups::<usize>(vec![], 4).count(), 0);
    }
    #[test]
    fn shared_graph_schedule_rejects_gaps_overlap_empty_and_overflow() {
        assert!(schedule(&[]).is_err());
        assert!(schedule(&[&[]]).is_err());
        assert!(schedule(&[&[(0, 0)]]).is_err());
        assert!(schedule(&[&[(0, 2), (3, 2)]]).is_err());
        assert!(schedule(&[&[(0, 2), (1, 2)]]).is_err());
        assert!(schedule(&[&[(usize::MAX, 1)]]).is_err());
        let singleton: &[(usize, usize)] = &[(0, 1)];
        assert!(schedule(&[singleton; 5]).is_err());
        assert_eq!(schedule(&[singleton; 4]).unwrap().len(), 4);
    }
}
