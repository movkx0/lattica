//! FRI retains each folded input through its layer queries. Leaves are aliases,
//! not new allocations. Initial commitment queries run before layers are freed.
use super::*;
use crate::{gpu_fri, gpu_matrix::query::QueryPlan, transcript_limits};

fn grind(schedule: &mut Schedule, bits: usize) -> Result<()> {
    if bits == 0 {
        return Ok(());
    }
    schedule.scratch([
        transcript_limits::GRIND_BATCH,
        transcript_limits::GRIND_BATCH.div_ceil(transcript_limits::GRIND_TILE),
        2,
    ])
}

fn salts(schedule: &mut Schedule, log_rows: u32, queries: usize) -> Result<()> {
    let pending = schedule.hold([queries, queries * 4])?;
    let output = schedule.sample((1usize << log_rows) * 4)?;
    schedule.release(output);
    schedule.release(pending);
    Ok(())
}

fn paths(
    schedule: &mut Schedule,
    log_rows: usize,
    cap_height: usize,
    queries: usize,
) -> Result<()> {
    let len = log_rows - log_rows.min(cap_height);
    if len != 0 {
        schedule.scratch([queries, queries * len * 4])?;
    }
    Ok(())
}

pub(super) fn plan(
    schedule: &mut Schedule,
    params: FriParameters,
    rounds: &[RoundShape],
    pcs: &PcsPlan,
) -> Result<()> {
    schedule.phase("fri_commit_and_fold");
    let mut inputs = pcs
        .heights
        .iter()
        .map(|&log| schedule.hold([(1usize << log) * 3]).map(Some))
        .collect::<Result<Vec<_>>>()?;
    let mut folded = inputs[0].take().unwrap();
    let mut height = pcs.heights[0];
    let mut next = 1;
    let mut retained = vector(pcs.fri.layers.len())?;
    for layer in &pcs.fri.layers {
        let input = matrix(height as u32, 1, Extension::Cubic, RowOrder::BitReversed, 1)?;
        let leaves = gpu_fri::leaves(input, layer.log_arity)?;
        let stream = StreamPlan::new(&[leaves], params.cap_height)?;
        let tree = schedule.hold([stream.words[0]])?;
        let sponge = schedule.hold([stream.words[1]])?;
        let sampled = schedule.sample(leaves.rows() * 4)?;
        schedule.release(sampled);
        schedule.release(sponge);
        schedule.scratch([(layer.cap_bytes / 8).min(transcript_limits::BATCH_WORDS)])?;
        grind(schedule, params.commit_proof_of_work_bits)?;
        schedule.scratch([3, 3])?; // sampled beta and its owned copy
        let beta = schedule.hold([3])?;
        let output = gpu_fri::fold_output(input, layer.log_arity)?;
        let mut output_live = schedule.hold([output.words()])?;
        height = output.log_rows as usize;
        if pcs.heights.get(next) == Some(&height) {
            let mixed = schedule.hold([output.words()])?;
            schedule.release(output_live);
            schedule.release(inputs[next].take().unwrap());
            output_live = mixed;
            next += 1;
        }
        retained.push((folded, tree, leaves));
        folded = output_live;
        schedule.release(beta);
    }
    if next != inputs.len() {
        return Err("CUDA request FRI left an input unconsumed".into());
    }
    schedule.phase("fri_final_polynomial");
    let input = matrix(height as u32, 1, Extension::Cubic, RowOrder::BitReversed, 1)?;
    let final_shape = gpu_fri::FinalShape::new(
        input,
        params.log_blowup,
        params.log_final_poly_len,
        pcs.fri.final_bytes,
    )?;
    let final_plan = final_shape.plan(
        schedule.state.live_bytes,
        schedule.limits.managed_bytes,
        schedule.limits.max_allocation_bytes,
    )?;
    schedule.peak(
        final_plan.peak_bytes,
        if params.log_final_poly_len == 0 { 1 } else { 3 },
    )?;
    schedule.release(folded);
    // Coefficients are observed resident and released before grinding/sampling.
    grind(schedule, params.query_proof_of_work_bits)?;
    schedule.scratch([params.num_queries])?;

    schedule.phase("initial_commitment_queries");
    for (batch, round) in rounds.iter().enumerate() {
        for &(shape, _) in round {
            let query = QueryPlan::new(
                shape.prefix,
                shape.lde.log_rows,
                params.num_queries,
                schedule.limits.managed_bytes - schedule.state.live_bytes,
                schedule.limits.max_allocation_bytes,
                pcs.initial[batch].0,
            )?;
            schedule.peak(schedule.state.live_bytes + query.workspace_bytes, 7)?;
            salts(schedule, shape.lde.log_rows, params.num_queries)?;
        }
        let height = round
            .iter()
            .map(|(s, _)| s.lde.log_rows as usize)
            .max()
            .unwrap();
        paths(schedule, height, params.cap_height, params.num_queries)?;
    }
    schedule.phase("fri_layer_queries");
    for (input, tree, leaves) in retained {
        let gather = gpu_fri::GatherShape::new(leaves, params.num_queries, usize::MAX)?.plan(
            schedule.state.live_bytes,
            schedule.limits.managed_bytes,
            schedule.limits.max_allocation_bytes,
        )?;
        schedule.peak(gather.peak_bytes, 2)?;
        salts(schedule, leaves.log_rows, params.num_queries)?;
        paths(
            schedule,
            leaves.log_rows as usize,
            params.cap_height,
            params.num_queries,
        )?;
        schedule.release(input);
        schedule.release(tree);
    }
    Ok(())
}
