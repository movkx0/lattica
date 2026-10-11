//! Owned FRI with the two pinned extension bases and Plonky3's arity schedule.
use super::*;
use crate::block_v2::gpu_hash::{FriData, FriExtension, FriExtensionMmcs};
use p3_commit::BatchOpening;
use p3_field::PrimeField64;
mod storage;

#[cfg(test)]
mod tests;

fn words<F: FriExtension>(value: F) -> Vec<u64> {
    value
        .as_basis_coefficients_slice()
        .iter()
        .map(|v| v.as_canonical_u64())
        .collect()
}

pub(in crate::block_v2::opening_pcs) fn prove<F: FriExtension>(
    session: &DeviceSession,
    mmcs: &CandidateMmcs,
    params: &FriParameters<FriExtensionMmcs<F>>,
    inputs: Vec<DeviceMatrix>,
    challenger: &mut Challenger,
    max_height: usize,
    rounds: &[&ProverData],
) -> Result<FriProof<F, FriExtensionMmcs<F>, Val, Vec<BatchOpening<Val, CandidateMmcs>>>, String> {
    prove_with_query_allowance(
        session,
        mmcs,
        params,
        inputs,
        challenger,
        max_height,
        rounds,
        HOST_QUERY_ALLOWANCE,
    )
}

fn prove_with_query_allowance<F: FriExtension>(
    session: &DeviceSession,
    mmcs: &CandidateMmcs,
    params: &FriParameters<FriExtensionMmcs<F>>,
    inputs: Vec<DeviceMatrix>,
    challenger: &mut Challenger,
    max_height: usize,
    rounds: &[&ProverData],
    query_allowance: usize,
) -> Result<FriProof<F, FriExtensionMmcs<F>, Val, Vec<BatchOpening<Val, CandidateMmcs>>>, String> {
    let final_height = params
        .log_blowup
        .checked_add(params.log_final_poly_len)
        .ok_or("FRI final height overflow")?;
    if params.log_blowup != crate::config::LOG_BLOWUP
        || params.log_final_poly_len > 16
        || !(1..=4).contains(&params.max_log_arity)
        || ![crate::config::NUM_QUERIES, profile::NUM_QUERIES].contains(&params.num_queries)
        || params.commit_proof_of_work_bits != 0
        || params.query_proof_of_work_bits != crate::config::QUERY_POW_BITS
        || inputs.is_empty()
        || inputs.len() > 26
        || max_height > 25
        || inputs[0].spec().rows().ilog2() as usize != max_height
        || inputs
            .windows(2)
            .any(|p| p[0].spec().rows() <= p[1].spec().rows())
        || inputs.iter().any(|v| {
            v.spec().extension() != F::DEVICE_EXTENSION
                || (v.spec().rows().ilog2() as usize) < final_height
                || (params.log_final_poly_len > 0
                    && v.spec().rows().ilog2() as usize == final_height)
        })
    {
        return Err("unsupported owned FRI parameters, extension or input ordering".into());
    }
    if rounds.len() > 256 {
        return Err("resident PCS query round count exceeds bound".into());
    }
    let query_host_peak = rounds.iter().try_fold(0usize, |total, data| {
        total
            .checked_add(mmcs.owned_query_host_bytes(data, params.num_queries)?)
            .ok_or_else(|| "resident PCS query host size overflow".to_string())
    })?;
    let mut heights = [0usize; 26];
    for (height, input) in heights.iter_mut().zip(&inputs) {
        *height = input.spec().rows().ilog2() as usize;
    }
    let plan = storage::Plan::new::<F>(
        storage::Geometry {
            input_heights: &heights[..inputs.len()],
            log_blowup: params.log_blowup,
            log_final_len: params.log_final_poly_len,
            max_log_arity: params.max_log_arity,
            queries: params.num_queries,
            initial_rounds: rounds.len(),
        },
        query_host_peak,
        query_allowance,
    )?;
    for input in &inputs {
        session.fri_leaves_with_arity(input, 1)?;
    }
    let before = session.stats();
    let mut inputs = inputs.into_iter().peekable();
    let mut folded = inputs.next().unwrap();
    let mut commits = FriData::proof_vector(plan.layer_count)?;
    let mut layers = FriData::proof_vector(plan.layer_count)?;
    let mut witnesses = FriData::proof_vector(plan.layer_count)?;
    while folded.spec().rows().ilog2() as usize > final_height {
        let layer = plan
            .layers()
            .get(layers.len())
            .ok_or("FRI schedule exceeds storage plan")?;
        let log_arity = layer.log_arity;
        if folded.spec().rows().ilog2() as usize != layer.log_height + log_arity {
            return Err("FRI schedule differs from storage plan".into());
        }
        let (commitment, data) = params.mmcs.inner().commit_fri_device_arity(
            session,
            &folded,
            log_arity,
            HOST_SALT_ALLOWANCE,
        )?;
        challenger.observe(commitment.clone());
        commits.push(commitment);
        witnesses.push(challenger.grind(params.commit_proof_of_work_bits));
        let beta: F = challenger.sample_algebra_element();
        folded = session.fold_fri(&folded, log_arity, &words(beta))?;
        layers.push((data, log_arity));
        if let Some(input) = inputs.next_if(|v| v.spec().rows() == folded.spec().rows()) {
            folded = session.mix_fri_with_arity(&folded, &input, log_arity, &words(beta))?;
        }
    }
    if inputs.next().is_some() || layers.len() != plan.layer_count {
        return Err("resident FRI failed to consume every input height".into());
    }
    let coefficients = session.final_polynomial_with_len(
        &folded,
        params.log_blowup,
        params.log_final_poly_len,
        HOST_QUERY_ALLOWANCE,
    )?;
    if coefficients.len() != (1 << params.log_final_poly_len) * F::DIMENSION {
        return Err("FRI final coefficient count differs from storage plan".into());
    }
    let mut final_poly = FriData::proof_vector(1 << params.log_final_poly_len)?;
    for value in coefficients.chunks_exact(F::DIMENSION) {
        final_poly.push(F::from_basis_coefficients_fn(|i| Val::from_u64(value[i])));
    }
    drop(coefficients);
    drop(folded);
    challenger.observe_algebra_slice(&final_poly);
    for (_, log_arity) in &layers {
        challenger.observe(Val::from_usize(*log_arity));
    }
    let query_pow_witness = challenger.grind(params.query_proof_of_work_bits);
    let indices = challenger.sample_bits_vec(max_height, params.num_queries);
    let mut input_proofs = FriData::proof_vector(params.num_queries)?;
    for _ in 0..params.num_queries {
        input_proofs.push(FriData::proof_vector(rounds.len())?);
    }
    for data in rounds {
        let dimensions = data.owned_dimensions()?;
        let shift = max_height
            .checked_sub(log2_strict_usize(dimensions[0].height))
            .ok_or("PCS input height exceeds resident FRI")?;
        let mut local = FriData::proof_vector(indices.len())?;
        local.extend(indices.iter().map(|i| i >> shift));
        let openings = mmcs.open_owned_queries(session, data, &local, HOST_QUERY_ALLOWANCE)?;
        for (query, opening) in openings.into_iter().enumerate() {
            input_proofs[query].push(opening);
        }
    }
    let mut steps: Vec<Vec<CommitPhaseProofStep<F, FriExtensionMmcs<F>>>> =
        FriData::proof_vector(params.num_queries)?;
    for _ in 0..params.num_queries {
        steps.push(FriData::proof_vector(layers.len())?);
    }
    let mut reduced_bits = 0;
    for (data, log_arity) in &layers {
        let mut local = FriData::proof_vector(indices.len())?;
        local.extend(indices.iter().map(|i| i >> (reduced_bits + log_arity)));
        let queries = data.open_rows_extension::<F>(session, &local)?;
        for (query, opening) in queries.into_iter().enumerate() {
            let (mut rows, proof) = opening.unpack();
            let mut row = rows.pop().ok_or("missing resident FRI query row")?;
            let arity = 1 << log_arity;
            if !rows.is_empty() || row.len() != arity {
                return Err("invalid resident FRI query width".into());
            }
            let selected = (indices[query] >> reduced_bits) & (arity - 1);
            // Keep the admitted arity-sized backing array, without a second
            // sibling allocation or dependence on collect's reuse behavior.
            row.remove(selected);
            steps[query].push(CommitPhaseProofStep {
                log_arity: *log_arity as u8,
                sibling_values: row,
                opening_proof: proof,
            });
        }
        reduced_bits += log_arity;
    }
    let mut query_proofs = FriData::proof_vector(params.num_queries)?;
    for (input_proof, commit_phase_openings) in input_proofs.into_iter().zip(steps) {
        query_proofs.push(QueryProof {
            input_proof,
            commit_phase_openings,
        });
    }
    plan.report();
    let after = session.stats();
    let final_coefficient_bytes = final_poly.len() * F::DIMENSION * core::mem::size_of::<u64>();
    let initial_query_backend = if rounds.is_empty() {
        "not_requested"
    } else {
        "gpu"
    };
    eprintln!("bounded_owned_fri rounds={} folds={} mixes={} gathered_value_bytes={} final_coefficient_bytes={final_coefficient_bytes} layer_upload_bytes=0 layer_readback_bytes=0 transcript_backend={} initial_pcs_query_backend={initial_query_backend} pcs_query_matrices={} pcs_query_tiles={} pcs_query_value_bytes={} pcs_query_prefix_upload_bytes=0 pcs_query_prefix_readback_bytes=0 pcs_query_host_peak_bytes={query_host_peak}",
        commits.len(), after.cubic_folds + after.general_fri_folds - before.cubic_folds - before.general_fri_folds,
        after.fri_mixes - before.fri_mixes, after.gathered_value_bytes - before.gathered_value_bytes,
        challenger.backend_name(), after.query_reconstructions - before.query_reconstructions,
        after.query_reconstruction_tiles - before.query_reconstruction_tiles, after.query_value_bytes - before.query_value_bytes);
    Ok(FriProof {
        commit_phase_commits: commits,
        commit_pow_witnesses: witnesses,
        query_proofs,
        final_poly,
        query_pow_witness,
    })
}
