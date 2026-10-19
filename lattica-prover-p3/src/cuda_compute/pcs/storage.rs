//! Admission covers captured openings, reduction peaks and the coexistence of
//! returned public/masking openings with FRI proof assembly. FRI device stages
//! retain their own allocation checks and the outer attempt retires on errors.
use super::*;

pub(super) struct Plan {
    pub matrices: usize,
    pub heights: Vec<usize>,
    pub fri_host_bytes: usize,
    #[cfg(test)]
    pub host_peak: usize,
}

fn add(total: &mut usize, bytes: usize) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or("CUDA PCS storage overflow")?;
    Ok(())
}

impl PcsOpenings {
    pub(super) fn plan<F: FriField>(
        &self,
        params: FriParameters,
        rounds: &[OpeningRound<'_>],
        public_preprocessing: bool,
        host_bytes: usize,
    ) -> Result<Plan> {
        if rounds.is_empty() || rounds.len() > 256 {
            return Err("CUDA PCS commitment count exceeds admission".into());
        }
        let mut height_counts = [0usize; 26];
        let mut matrices = 0;
        let mut point_count = 0;
        let mut value_bytes = 0;
        let mut captured_bytes = 0;
        let mut captured_allocations = 0;
        let mut originals = vector(rounds.len())?;
        for (batch, round) in rounds.iter().enumerate() {
            round.commitment.check_runtime(&self.runtime)?;
            if round.points.is_empty()
                || round.points.len() != round.commitment.specs().len()
                || round.points.len() > 256
            {
                return Err("CUDA PCS matrix/point shape differs from its commitment".into());
            }
            originals.push(round.commitment);
            for (matrix, points) in round.points.iter().enumerate() {
                let shape = round.commitment.opening_shape(matrix)?;
                let spec = shape.lde;
                let random_columns = if public_preprocessing && batch == PREPROCESSED_ROUND {
                    0
                } else {
                    crate::config::NUM_RANDOM_CODEWORDS
                };
                if !(1..=32).contains(&points.count)
                    || spec.log_rows > 25
                    || shape
                        .prefix
                        .log_rows
                        .checked_add(params.log_blowup as u32)
                        .is_none_or(|h| h > spec.log_rows)
                    || params.log_blowup > 25
                    || spec.extension != Extension::Base
                    || spec.order != RowOrder::BitReversed
                    || spec.shift != 7
                    || shape.random_columns != random_columns
                    || shape.random_columns >= spec.columns
                {
                    return Err("CUDA PCS opening or hiding geometry is unsupported".into());
                }
                let height = spec.log_rows as usize;
                height_counts[height] += 1;
                if height_counts[height] > 256 {
                    return Err("CUDA PCS reductions exceed matrices per height".into());
                }
                round.commitment.preflight_retained_opening(
                    &self.openings,
                    matrix,
                    F::EXTENSION,
                    points.values,
                    points.count,
                    captured_bytes,
                    captured_allocations,
                )?;
                let values = points.count * spec.columns * F::DIMENSION * 8;
                add(&mut value_bytes, values)?;
                add(
                    &mut captured_bytes,
                    values + points.count * F::DIMENSION * 8,
                )?;
                add(&mut captured_allocations, 2)?;
                add(&mut matrices, 1)?;
                add(&mut point_count, points.count)?;
            }
        }
        let mut heights = vector(26)?;
        for (height, &count) in height_counts.iter().enumerate().rev() {
            if count != 0 {
                heights.push(height);
            }
        }
        let fri_host_bytes = self
            .fri
            .proof_host_bytes::<F>(params, &heights, &originals)?;
        // Includes raw/typed opening coexistence and all nested vector and
        // retained-handle metadata, even as execution releases handles early.
        let mut opened_host = value_bytes
            .checked_mul(2)
            .ok_or("CUDA PCS opening host bytes overflow")?;
        add(
            &mut opened_host,
            matrices * 512 + point_count * 128 + rounds.len() * 128 + (64 << 10),
        )?;
        let host_peak = opened_host
            .checked_add(fri_host_bytes)
            .ok_or("CUDA PCS aggregate host bytes overflow")?;
        if host_peak > host_bytes {
            return Err("CUDA PCS openings and FRI exceed aggregate host allowance".into());
        }

        // Conservatively admit reductions with every evaluated opening, every
        // accumulator and alpha simultaneously live, before mutating the transcript.
        let limits = self.runtime.state.budget.limits;
        let mut reduction_bytes = captured_bytes;
        let mut reduction_allocations = captured_allocations;
        add(&mut reduction_bytes, F::DIMENSION * 8)?;
        add(&mut reduction_allocations, 1)?;
        for &height in &heights {
            let bytes = (1usize << height) * F::DIMENSION * 8;
            if bytes > limits.max_allocation_bytes || F::DIMENSION * 8 > limits.max_allocation_bytes
            {
                return Err("CUDA PCS reduction vector exceeds allocation allowance".into());
            }
            add(&mut reduction_bytes, bytes + F::DIMENSION * 8)?;
            add(&mut reduction_allocations, 2)?;
        }
        for round in rounds {
            for (matrix, points) in round.points.iter().enumerate() {
                let shape = round.commitment.opening_shape(matrix)?;
                let output = MatrixSpec::new(
                    shape.lde.log_rows,
                    1,
                    F::EXTENSION,
                    RowOrder::BitReversed,
                    shape.lde.shift,
                )?;
                self.openings.preflight_reduction(
                    shape.prefix,
                    output,
                    points.count,
                    reduction_bytes,
                    reduction_allocations,
                )?;
            }
        }
        Ok(Plan {
            matrices,
            heights,
            fri_host_bytes,
            #[cfg(test)]
            host_peak,
        })
    }
}
