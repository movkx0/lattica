//! Device opening arithmetic with either a resident FRI consumer or an explicit
//! temporary host FRI-vector boundary, selected before proving begins.
//! No prefix is uploaded here: all inputs come from the original commitments.
use super::*;
use crate::block_v2::gpu_hash::device::{DeviceMatrix, DeviceSession, Extension, RowOrder};
use crate::block_v2::gpu_hash::{FriData, FriExtension};
use p3_field::{BasedVectorSpace, PrimeField64};

mod storage;
#[cfg(test)]
mod tests;

const HOST_ALLOWANCE: usize = 4 << 30;

// Kept for the independent conformance fixtures in owned_fri::tests.
pub(super) fn words<F: FriExtension>(value: F) -> Vec<u64> {
    value
        .as_basis_coefficients_slice()
        .iter()
        .map(PrimeField64::as_canonical_u64)
        .collect()
}

fn fill_words<F: FriExtension>(values: &[F], output: &mut [u64]) {
    assert_eq!(output.len(), values.len() * F::DIMENSION);
    for (value, words) in values.iter().zip(output.chunks_exact_mut(F::DIMENSION)) {
        for (coefficient, word) in value.as_basis_coefficients_slice().iter().zip(words) {
            *word = coefficient.as_canonical_u64();
        }
    }
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
    rounds: &Vec<(&ProverData, Vec<Vec<F>>)>,
    challenger: &mut Challenger,
    host_allowance: usize,
) -> Result<(OpenedValues<F>, FriInputs<F>, usize), String> {
    let resident_fri = crate::block_v2::quotient_pcs::gpu_fri_resident_enabled();
    if log_blowup != crate::block_v2::profile::LOG_BLOWUP || rounds.is_empty() {
        return Err("owned opening requires the fixed block-v2 profile and nonempty rounds".into());
    }
    // Admit the complete host boundary before observing any claimed values.
    // The live GPU prefixes are aliases of private buffers or imported public
    // preprocessing; device operations recheck their aggregate memory peaks.
    let mut shapes = [storage::Shape::default(); 256];
    let mut matrix_count = 0;
    for (data, points) in rounds {
        let matrices = data.owned_dimensions()?;
        if matrices.is_empty() || matrices.len() != points.len() {
            return Err("owned opening matrix/point count".into());
        }
        for (index, (matrix, points)) in matrices.iter().zip(points).enumerate() {
            let height = matrix.height;
            let prefix = data.owned_matrix(session, index)?;
            let spec = prefix.spec();
            if matrix_count >= shapes.len()
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
            shapes[matrix_count] = storage::Shape {
                width: spec.columns(),
                points: points.len(),
                log_height: height.ilog2(),
            };
            matrix_count += 1;
        }
    }
    let plan = storage::Plan::new(
        rounds,
        &shapes[..matrix_count],
        resident_fri,
        host_allowance,
    )?;
    plan.report();
    let before = session.stats();
    let mut prepared = FriData::proof_vector(matrix_count)?;
    let mut opened = FriData::proof_vector(rounds.len())?;
    for (data, matrices) in rounds {
        let mut round = FriData::proof_vector(matrices.len())?;
        for (index, points) in matrices.iter().enumerate() {
            let prefix = data.owned_matrix(session, index)?;
            let height = data.owned_dimensions()?[index].height.ilog2();
            let mut point_words = [0u64; 32 * 3];
            let point_words = &mut point_words[..points.len() * F::DIMENSION];
            fill_words(points, point_words);
            let opening =
                session.evaluate_opening_extension(&prefix, F::DEVICE_EXTENSION, point_words)?;
            let raw = session.opening_values_words(&opening, plan.raw_opening_bytes)?;
            if raw.len() != points.len() * prefix.spec().columns() * F::DIMENSION {
                return Err("opening readback differs from admitted geometry".into());
            }
            let mut values = FriData::proof_vector(points.len())?;
            for point in raw.chunks_exact(prefix.spec().columns() * F::DIMENSION) {
                let mut value = FriData::proof_vector(prefix.spec().columns())?;
                value.extend(point.chunks_exact(F::DIMENSION).map(challenge::<F>));
                values.push(value);
            }
            drop(raw);
            for point in &values {
                challenger.observe_algebra_slice(point);
            }
            round.push(values);
            prepared.push((height, opening));
        }
        opened.push(round);
    }
    let alpha: F = challenger.sample_algebra_element();
    let mut alpha_words = [0u64; 3];
    let alpha_words = &mut alpha_words[..F::DIMENSION];
    fill_words(&[alpha], alpha_words);
    let max_height = (u32::BITS - 1 - plan.heights.leading_zeros()) as usize;
    let mut fri_inputs = FriData::proof_vector(if resident_fri { 0 } else { plan.height_count })?;
    let mut device_inputs =
        FriData::proof_vector(if resident_fri { plan.height_count } else { 0 })?;
    // One height at a time bounds active accumulators. The resident consumer
    // retains finished inputs. Within each height the
    // original round/matrix/point order determines every alpha exponent.
    for height in (0..=max_height as u32)
        .rev()
        .filter(|h| plan.heights & (1 << h) != 0)
    {
        let mut accumulator =
            session.opening_accumulator_extension(height, F::DEVICE_EXTENSION, alpha_words)?;
        for (_, opening) in prepared.iter().filter(|(h, _)| *h == height) {
            accumulator = accumulator.append(opening)?;
        }
        let output = accumulator.finish()?;
        if resident_fri {
            device_inputs.push(output);
            continue;
        }
        let raw = session.read(&output, plan.raw_fri_bytes)?;
        if raw.len() != (1usize << height) * F::DIMENSION {
            return Err("FRI readback differs from admitted opening geometry".into());
        }
        let mut values = FriData::proof_vector(1usize << height)?;
        values.extend(raw.chunks_exact(F::DIMENSION).map(challenge::<F>));
        fri_inputs.push(values);
    }
    let after = session.stats();
    let fri_bytes = fri_inputs
        .iter()
        .map(|values| values.len() * F::DIMENSION * 8)
        .sum::<usize>();
    let host_peak = plan.total_bytes;
    eprintln!("bounded_owned_opening_proof matrices={} evaluations={} reductions={} claimed_value_readback_bytes={} fri_vector_readback_bytes={fri_bytes} prefix_upload_bytes=0 prefix_readback_bytes=0 host_peak_plan_bytes={host_peak} host_allowance_bytes={host_allowance}",
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
