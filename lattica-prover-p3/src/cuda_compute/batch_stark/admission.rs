//! Whole registered proof admission from immutable public geometry. This mirrors
//! prove_inner's allocation lifetimes and calls the same component planners.
//! It does not allocate device memory, import seeds, or touch the transcript.
use super::*;
use crate::{
    cuda_compute::{
        commitment::stream::StreamPlan,
        hiding::{plan::TilePlan, OpeningShape},
        pcs::storage::{Plan as PcsPlan, RoundShape},
        storage::{Phase, Schedule},
        Limits, Snapshot,
    },
    gpu_hiding::{QuotientCommitShape, TraceCommitShape},
    gpu_matrix::{MatrixSpec, RowOrder},
};
use serde::Serialize;
mod fri;

#[derive(Debug, Serialize)]
pub(crate) struct ProofPlan {
    pub starting_live_bytes: usize,
    pub managed_peak_bytes: usize,
    pub allocation_peak: usize,
    pub host_peak_bytes: usize,
    pub additional_random_states: usize,
    pub phases: Vec<Phase>,
}

fn matrix(
    log: u32,
    width: usize,
    extension: Extension,
    order: RowOrder,
    shift: u64,
) -> Result<MatrixSpec> {
    MatrixSpec::new(log, width, extension, order, shift)
}

fn opening(tile: TilePlan, random_columns: usize) -> Result<OpeningShape> {
    Ok(OpeningShape {
        prefix: matrix(
            tile.input_log + u32::from(tile.quotient),
            tile.width,
            Extension::Base,
            RowOrder::BitReversed,
            7,
        )?,
        lde: matrix(
            tile.output_log,
            tile.width,
            Extension::Base,
            RowOrder::BitReversed,
            7,
        )?,
        random_columns,
    })
}

fn observe_cap(schedule: &mut Schedule) -> Result<()> {
    schedule.scratch([(CAP_BYTES / 8).min(crate::transcript_limits::BATCH_WORDS)])
}

/// All prefixes and the Merkle tree survive. Only one row-sponge and one
/// producer tile/sampler coexist, exactly as in commit_with_salts.
fn commit(
    schedule: &mut Schedule,
    tiles: &[TilePlan],
    cap_height: usize,
) -> Result<Vec<OpeningShape>> {
    if tiles.is_empty() || tiles.len() > 256 {
        return Err("CUDA request commitment exceeds 256 matrices".into());
    }
    let shapes = tiles
        .iter()
        .map(|&p| opening(p, crate::config::NUM_RANDOM_CODEWORDS))
        .collect::<Result<Vec<_>>>()?;
    let specs = shapes
        .iter()
        .map(|s| {
            matrix(
                s.lde.log_rows,
                s.lde.columns + 4,
                Extension::Base,
                RowOrder::BitReversed,
                7,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let stream = StreamPlan::new(&specs, cap_height)?;
    schedule.hold(shapes.iter().map(|s| s.prefix.words()))?;
    schedule.hold([stream.words[0]])?;
    let sponge = schedule.hold([stream.words[1]])?;
    for &tile in tiles {
        schedule.scratch(tile.scratch()?)?;
        let salts = schedule.sample((1usize << tile.output_log) * 4)?;
        schedule.release(salts);
    }
    schedule.release(sponge);
    Ok(shapes)
}

fn commit_traces(
    schedule: &mut Schedule,
    specs: &[MatrixSpec],
    prepared: &PreparedBatch,
) -> Result<Vec<OpeningShape>> {
    let mut samples = vector(specs.len())?;
    let mut tiles = vector(specs.len())?;
    for (&spec, instance) in specs.iter().zip(&prepared.instances) {
        let shape = TraceCommitShape::new(spec, crate::config::NUM_RANDOM_CODEWORDS)?;
        let tile = TilePlan::new(
            shape.height.ilog2(),
            shape.width,
            instance.log_lde(parameters()),
            16,
            false,
        )?;
        samples.push(schedule.sample(shape.random_words)?);
        schedule.scratch(tile.scratch()?)?;
        tiles.push(tile);
    }
    let shapes = commit(schedule, &tiles, parameters().cap_height)?;
    for samples in samples {
        schedule.release(samples);
    }
    observe_cap(schedule)?;
    Ok(shapes)
}

impl BatchStarks {
    pub(super) fn proof_plan(
        &self,
        prepared: &PreparedBatch,
        pcs_host: usize,
        imports: usize,
    ) -> Result<ProofPlan> {
        self.plan_at(
            prepared,
            pcs_host,
            imports,
            self.runtime.snapshot(),
            self.runtime.state.budget.limits,
        )
    }

    pub(super) fn plan_at(
        &self,
        prepared: &PreparedBatch,
        pcs_host: usize,
        imports: usize,
        state: Snapshot,
        limits: Limits,
    ) -> Result<ProofPlan> {
        let mut schedule = Schedule::new(state, limits)?;
        let params = parameters();
        let count = prepared.instances.len();
        schedule.phase("seeds_and_transcript");
        schedule.hold(std::iter::repeat_n(4, imports))?;
        schedule.hold([crate::transcript_limits::STATE_WORDS])?;
        schedule.scratch([3])?;

        schedule.phase("witness");
        let mut traces = vector(count)?;
        let mut trace_specs = vector(count)?;
        let mut publics = vector(count)?;
        let mut generation_host = 0;
        for i in &prepared.instances {
            let words = i.witness.generation_words()?;
            generation_host = generation_host.max(words[2] * 8 + 8);
            schedule.scratch(words)?;
            traces.push(schedule.hold([words[0]])?);
            publics.push(schedule.hold([words[4]])?);
            trace_specs.push(matrix(
                i.log_rows,
                i.layout.main_width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?);
        }
        if generation_host > pcs_host {
            return Err("CUDA request witness staging exceeds host allowance".into());
        }
        schedule.phase("main_commitment");
        let main = commit_traces(&mut schedule, &trace_specs, prepared)?;

        schedule.phase("lookup");
        let mut mappings = vector(count)?;
        let mut challenges = vector(count)?;
        for ids in &prepared.bus_ids {
            mappings.push(schedule.hold([ids.len()])?);
            challenges.push(schedule.hold([ids.len() * 6])?);
        }
        schedule.scratch([6])?;
        for mapping in mappings {
            schedule.release(mapping);
        }
        let mut permutations = vector(count)?;
        let mut permutation_specs = vector(count)?;
        for i in &prepared.instances {
            let spec = matrix(
                i.log_rows,
                i.layout.permutation_width,
                Extension::Cubic,
                RowOrder::Natural,
                1,
            )?;
            let plan = i
                .lookup
                .generation_plan(spec, schedule.state.live_bytes, limits)?;
            schedule.peak(plan.peak, 7 + plan.scan_rows.len())?;
            permutations.push(schedule.hold([spec.words()])?);
            schedule.hold([3])?; // terminal remains live until final proof assembly
            permutation_specs.push(spec);
        }
        schedule.phase("permutation_commitment");
        let permutation = commit_traces(&mut schedule, &permutation_specs, prepared)?;
        for p in permutations {
            schedule.release(p);
        }
        let alpha = schedule.hold([3])?;
        for trace in traces {
            schedule.release(trace);
        }

        schedule.phase("quotient");
        let mut quotient_inputs = vector(count * 4)?;
        let mut quotient_tiles = vector(count)?;
        for (index, i) in prepared.instances.iter().enumerate() {
            let values = schedule.hold([
                i.layout.num_public_values + 3 * (i.layout.num_permutation_challenges + 1)
            ])?;
            let prep = prepared.preprocessing.opening_shape(index)?;
            let specs = [
                matrix(
                    main[index].prefix.log_rows,
                    i.layout.main_width,
                    Extension::Base,
                    RowOrder::BitReversed,
                    7,
                )?,
                matrix(
                    prep.prefix.log_rows,
                    i.layout.preprocessed_width,
                    Extension::Base,
                    RowOrder::BitReversed,
                    7,
                )?,
                matrix(
                    permutation[index].prefix.log_rows,
                    i.layout.permutation_width,
                    Extension::Cubic,
                    RowOrder::BitReversed,
                    7,
                )?,
            ];
            let extracted = schedule.hold(specs.iter().map(|s| s.words()))?;
            let (spec, peak, allocations) = i.quotient.partition_storage(
                specs.map(Some),
                i.log_rows,
                i.log_rows + 1 + i.log_chunks as u32,
                schedule.state.live_bytes,
                limits,
            )?;
            schedule.peak(peak, allocations)?;
            schedule.release(extracted);
            quotient_inputs.push(schedule.hold([spec.words()])?);
            let shape =
                QuotientCommitShape::new(spec, i.chunks(), crate::config::NUM_RANDOM_CODEWORDS)?;
            let tile = TilePlan::new(
                shape.height.ilog2(),
                shape.width,
                i.log_lde(params),
                2,
                true,
            )?;
            // The parameter allocation is pending throughout both sample draws.
            quotient_inputs.push(schedule.hold([shape.chunks * 3])?);
            quotient_inputs.push(schedule.sample(shape.random_words)?);
            quotient_inputs.push(schedule.sample(shape.mask_words)?);
            schedule.scratch(tile.scratch()?)?;
            quotient_tiles.extend(std::iter::repeat_n(tile, shape.chunks));
            schedule.release(values);
        }
        schedule.release(alpha);
        for c in challenges {
            schedule.release(c);
        }
        for p in publics {
            schedule.release(p);
        }
        schedule.phase("quotient_commitment");
        let quotient = commit(&mut schedule, &quotient_tiles, params.cap_height)?;
        for input in quotient_inputs {
            schedule.release(input);
        }
        observe_cap(&mut schedule)?;

        schedule.phase("randomization_commitment");
        let mut random_inputs = vector(count)?;
        let mut random_tiles = vector(count)?;
        for i in &prepared.instances {
            let width = 3 + crate::config::NUM_RANDOM_CODEWORDS;
            let tile = TilePlan::new(i.log_rows + 1, width, i.log_lde(params), 2, false)?;
            random_inputs.push(schedule.sample((1usize << (i.log_rows + 1)) * width)?);
            schedule.scratch(tile.scratch()?)?;
            random_tiles.push(tile);
        }
        let random = commit(&mut schedule, &random_tiles, params.cap_height)?;
        for input in random_inputs {
            schedule.release(input);
        }
        observe_cap(&mut schedule)?;

        schedule.phase("opening_points");
        schedule.hold([3])?; // zeta
        schedule.scratch([count, count * 3])?;
        schedule.hold([count * 3, count * 6])?; // next and paired points
        let preprocessing = (0..count)
            .map(|index| prepared.preprocessing.opening_shape(index))
            .collect::<Result<Vec<_>>>()?;
        let rounds: Vec<RoundShape> = [random, main, quotient, preprocessing, permutation]
            .into_iter()
            .enumerate()
            .map(|(round, shapes)| {
                shapes
                    .into_iter()
                    .map(|s| (s, if round == 4 { 2 } else { 1 }))
                    .collect()
            })
            .collect();
        schedule.phase("pcs_openings");
        let pcs =
            PcsPlan::new::<Challenge>(params, &rounds, true, schedule.state, limits, pcs_host)?;
        schedule.peak(
            pcs.device_peak,
            pcs.allocation_peak - schedule.state.allocations,
        )?;
        let layers = pcs.fri.layers.len();
        fri::plan(&mut schedule, params, &rounds, &pcs)?;

        // Main, permutation, quotient and randomization recipes, plus all FRI
        // layers. Public preprocessing may use a two-slot transient consumer.
        let recipes = rounds
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 3)
            .map(|(_, r)| r.len())
            .sum::<usize>();
        let additional_random_states = imports + recipes + layers + 2;
        self.randoms.admit_states(additional_random_states)?;
        Ok(ProofPlan {
            starting_live_bytes: state.live_bytes,
            managed_peak_bytes: schedule.phases.iter().map(|p| p.peak_bytes).max().unwrap(),
            allocation_peak: schedule
                .phases
                .iter()
                .map(|p| p.peak_allocations)
                .max()
                .unwrap(),
            host_peak_bytes: pcs.host_peak.max(generation_host),
            additional_random_states,
            phases: schedule.phases,
        })
    }
}
