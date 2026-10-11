//! Device opening arithmetic with either a resident FRI consumer or an explicit
//! temporary host FRI-vector boundary, selected before proving begins.
//! No prefix is uploaded here: all inputs come from the original commitments.
use super::*;
use crate::block_v2::gpu_hash::device::{DeviceMatrix, DeviceSession, Extension, RowOrder};
use crate::block_v2::gpu_hash::FriExtension;
use p3_field::{BasedVectorSpace, PrimeField64};

#[cfg(test)]
mod tests;
use std::collections::BTreeSet;

const HOST_ALLOWANCE: usize = 4 << 30;

pub(super) fn words<F: FriExtension>(value: F) -> Vec<u64> {
    value
        .as_basis_coefficients_slice()
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}

pub(super) fn challenge<F: FriExtension>(value: &[u64]) -> F {
    F::from_basis_coefficients_fn(|i| Val::from_u64(value[i]))
}

pub(super) enum FriInputs<F> {
    Host(Vec<Vec<F>>),
    Device(Vec<DeviceMatrix>),
}

pub(super) fn evaluate_and_reduce<F: FriExtension>(
    session: &DeviceSession,
    _mmcs: &CandidateMmcs,
    log_blowup: usize,
    rounds: &[(&ProverData, Vec<Vec<F>>)],
    challenger: &mut Challenger,
) -> Result<(OpenedValues<F>, FriInputs<F>, usize), String> {
    let resident_fri = crate::block_v2::quotient_pcs::gpu_fri_resident_enabled();
    if log_blowup != crate::block_v2::profile::LOG_BLOWUP || rounds.is_empty() {
        return Err("owned opening requires the fixed block-v2 profile and nonempty rounds".into());
    }
    // Admit the complete host boundary before observing any claimed values.
    // The live GPU prefixes are aliases of private buffers or imported public
    // preprocessing; device operations recheck their aggregate memory peaks.
    let mut inputs = Vec::new();
    let mut heights = BTreeSet::new();
    let mut opened_bytes = 0usize;
    for (data, points) in rounds {
        let matrices = data.owned_dimensions()?;
        if matrices.is_empty() || matrices.len() != points.len() {
            return Err("owned opening matrix/point count".into());
        }
        for (index, (matrix, points)) in matrices.iter().zip(points).enumerate() {
            let height = matrix.height;
            let prefix = data.owned_matrix(session, index)?;
            let spec = prefix.spec();
            if inputs.len() >= 256
                || points.is_empty()
                || points.len() > 32
                || points.contains(&F::ZERO)
                || !height.is_power_of_two()
                || height > 1 << 25
                || spec.rows() != height >> log_blowup
                || spec.columns() != matrix.width
                || spec.columns() > 4096
                || spec.extension() != Extension::Base
                || spec.order() != RowOrder::BitReversed
                || spec.shift() != Val::GENERATOR.as_canonical_u64()
            {
                return Err("owned opening prefix does not match committed geometry".into());
            }
            heights.insert(height.ilog2());
            opened_bytes = opened_bytes
                .checked_add(points.len() * spec.columns() * (F::DIMENSION * 8))
                .ok_or("owned opening value size overflow")?;
            inputs.push((prefix, points, height.ilog2()));
        }
    }
    let fri_bytes = heights
        .iter()
        .try_fold(0usize, |n, h| {
            n.checked_add((1usize << h) * (F::DIMENSION * 8))
        })
        .ok_or("owned opening FRI size overflow")?;
    let host_peak = opened_bytes
        .checked_add(if resident_fri { 0 } else { fri_bytes })
        .and_then(|n| n.checked_mul(2))
        .and_then(|n| n.checked_add(1 << 20))
        .ok_or("owned opening host size overflow")?;
    if host_peak > HOST_ALLOWANCE {
        return Err("owned opening host boundary exceeds allowance".into());
    }
    let before = session.stats();
    let mut prepared = Vec::with_capacity(inputs.len());
    let mut opened = Vec::with_capacity(rounds.len());
    let mut input_iter = inputs.into_iter();
    for (_, matrices) in rounds {
        let mut round = Vec::with_capacity(matrices.len());
        for _ in matrices {
            let (prefix, points, height) = input_iter.next().unwrap();
            let opening = session.evaluate_opening_extension(
                &prefix,
                F::DEVICE_EXTENSION,
                &points
                    .iter()
                    .copied()
                    .flat_map(words::<F>)
                    .collect::<Vec<_>>(),
            )?;
            let values = session.opening_values_words(&opening, opened_bytes)?;
            let values: Vec<Vec<_>> = values
                .chunks_exact(prefix.spec().columns() * F::DIMENSION)
                .map(|point| {
                    point
                        .chunks_exact(F::DIMENSION)
                        .map(challenge::<F>)
                        .collect()
                })
                .collect();
            for point in &values {
                challenger.observe_algebra_slice(point);
            }
            round.push(values);
            prepared.push((height, opening));
        }
        opened.push(round);
    }
    let alpha = words::<F>(challenger.sample_algebra_element());
    let max_height = *heights.last().ok_or("empty owned opening inputs")? as usize;
    let mut fri_inputs = Vec::with_capacity(heights.len());
    let mut device_inputs = Vec::with_capacity(heights.len());
    // One height at a time bounds active accumulators. The resident consumer
    // retains finished inputs. Within each height the
    // original round/matrix/point order determines every alpha exponent.
    for height in heights.into_iter().rev() {
        let mut accumulator =
            session.opening_accumulator_extension(height, F::DEVICE_EXTENSION, &alpha)?;
        for (_, opening) in prepared.iter().filter(|(h, _)| *h == height) {
            accumulator = accumulator.append(opening)?;
        }
        let output = accumulator.finish()?;
        if resident_fri {
            device_inputs.push(output);
            continue;
        }
        let raw = session.read(&output, fri_bytes)?;
        fri_inputs.push(raw.chunks_exact(F::DIMENSION).map(challenge::<F>).collect());
    }
    let after = session.stats();
    let fri_bytes = if resident_fri { 0 } else { fri_bytes };
    eprintln!("bounded_owned_opening_proof matrices={} evaluations={} reductions={} claimed_value_readback_bytes={} fri_vector_readback_bytes={fri_bytes} prefix_upload_bytes=0 prefix_readback_bytes=0 host_peak_plan_bytes={host_peak}",
        prepared.len(), after.opening_evaluations - before.opening_evaluations,
        after.opening_reductions - before.opening_reductions,
        after.opening_value_bytes - before.opening_value_bytes);
    let input = if resident_fri {
        FriInputs::Device(device_inputs)
    } else {
        FriInputs::Host(fri_inputs)
    };
    Ok((opened, input, max_height))
}
