//! Pure opening/host admission shared by live PCS and whole-request planning.
use super::*;
use crate::cuda_compute::fri::protocol::storage as fri_storage;
use crate::cuda_compute::{
    hiding::{query_host_bytes, OpeningShape},
    opening::{reduce::ReductionPlan, EvaluationPlan},
    storage::Schedule,
    Limits, Snapshot,
};

pub(in crate::cuda_compute) type RoundShape = Vec<(OpeningShape, usize)>;

pub(in crate::cuda_compute) struct Plan {
    pub matrices: usize,
    pub heights: Vec<usize>,
    pub fri_host_bytes: usize,
    pub host_peak: usize,
    pub device_peak: usize,
    pub allocation_peak: usize,
    pub initial: Vec<(usize, usize)>,
    pub fri: fri_storage::Plan,
}

fn add(total: &mut usize, bytes: usize) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or("CUDA PCS storage overflow")?;
    Ok(())
}

impl Plan {
    pub(in crate::cuda_compute) fn new<F: FriField>(
        params: FriParameters,
        rounds: &[RoundShape],
        public_preprocessing: bool,
        state: Snapshot,
        limits: Limits,
        host_bytes: usize,
    ) -> Result<Self> {
        if rounds.is_empty() || rounds.len() > 256 {
            return Err("CUDA PCS commitment count exceeds admission".into());
        }
        let mut schedule = Schedule::new(state, limits)?;
        schedule.phase("pcs_evaluation");
        let mut height_counts = [0usize; 26];
        let mut matrices = 0;
        let mut point_count = 0;
        let mut value_bytes = 0;
        let mut initial = vector(rounds.len())?;
        for (batch, round) in rounds.iter().enumerate() {
            if round.is_empty() || round.len() > 256 {
                return Err("CUDA PCS matrix count exceeds admission".into());
            }
            let mut shapes = vector(round.len())?;
            for &(shape, points) in round {
                let spec = shape.lde;
                let random_columns = if public_preprocessing && batch == PREPROCESSED_ROUND {
                    0
                } else {
                    crate::config::NUM_RANDOM_CODEWORDS
                };
                if !(1..=32).contains(&points)
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
                    || shape.prefix.columns != spec.columns
                {
                    return Err("CUDA PCS opening or hiding geometry unsupported".into());
                }
                let height = spec.log_rows as usize;
                height_counts[height] += 1;
                if height_counts[height] > 256 {
                    return Err("CUDA PCS reductions exceed matrices per height".into());
                }
                let plan = EvaluationPlan::new(
                    shape.prefix,
                    F::EXTENSION,
                    points,
                    schedule.state,
                    limits,
                )?;
                schedule.peak(plan.peak, 6)?;
                // Each immutable opening retains its copied points and values.
                schedule.hold([points * F::DIMENSION, points * spec.columns * F::DIMENSION])?;
                add(&mut value_bytes, points * spec.columns * F::DIMENSION * 8)?;
                add(&mut matrices, 1)?;
                add(&mut point_count, points)?;
                shapes.push(shape);
            }
            let height = shapes
                .iter()
                .map(|s| s.lde.log_rows as usize)
                .max()
                .unwrap();
            initial.push((
                query_host_bytes(
                    &shapes,
                    height - params.cap_height.min(height),
                    params.num_queries,
                )?,
                shapes.len(),
            ));
        }
        let mut heights = vector(26)?;
        for (height, &count) in height_counts.iter().enumerate().rev() {
            if count != 0 {
                heights.push(height);
            }
        }
        let fri = fri_storage::Plan::new(params, &heights, F::DIMENSION, &initial, host_bytes)?;
        let fri_host_bytes = fri.host_peak;
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
        // Match live PCS admission: all captures, accumulators and alpha are
        // charged simultaneously, even though execution releases captures early.
        schedule.phase("pcs_reduction");
        schedule.hold([F::DIMENSION])?;
        for &height in &heights {
            schedule.hold([(1usize << height) * F::DIMENSION, F::DIMENSION])?;
        }
        for round in rounds {
            for &(shape, points) in round {
                let output = MatrixSpec::new(
                    shape.lde.log_rows,
                    1,
                    F::EXTENSION,
                    RowOrder::BitReversed,
                    shape.lde.shift,
                )?;
                let plan =
                    ReductionPlan::new(shape.prefix, output, points, schedule.state, limits)?;
                schedule.peak(plan.peak, 7)?;
            }
        }
        Ok(Self {
            matrices,
            heights,
            fri_host_bytes,
            host_peak,
            initial,
            fri,
            device_peak: schedule.phases.iter().map(|p| p.peak_bytes).max().unwrap(),
            allocation_peak: schedule
                .phases
                .iter()
                .map(|p| p.peak_allocations)
                .max()
                .unwrap(),
        })
    }
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
        let mut shapes = vector(rounds.len())?;
        for round in rounds {
            round.commitment.check_runtime(&self.runtime)?;
            if round.points.len() != round.commitment.specs().len()
                || round.points.is_empty()
                || round.points.len() > 256
            {
                return Err("CUDA PCS matrix/point shape differs from its commitment".into());
            }
            let mut shape = vector(round.points.len())?;
            for (matrix, points) in round.points.iter().enumerate() {
                // Also authenticate resident point ownership/ranges. The pure
                // schedule below adds all previous retained evaluations.
                round.commitment.preflight_retained_opening(
                    &self.openings,
                    matrix,
                    F::EXTENSION,
                    points.values,
                    points.count,
                    0,
                    0,
                )?;
                shape.push((round.commitment.opening_shape(matrix)?, points.count));
            }
            shapes.push(shape);
        }
        Plan::new::<F>(
            params,
            &shapes,
            public_preprocessing,
            self.runtime.snapshot(),
            self.runtime.state.budget.limits,
            host_bytes,
        )
    }
}
