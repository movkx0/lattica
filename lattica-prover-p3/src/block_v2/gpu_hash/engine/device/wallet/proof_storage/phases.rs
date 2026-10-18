//! Managed-device phase feasibility for the fixed hiding wallet PCS. LDE tiles
//! remain adaptive: each commitment uses the production planner with its live
//! inputs, output prefixes and replay storage. Other phases use conservative
//! coexistence bounds. Host/driver allocations are separate contracts.
use super::super::super::{
    opening, query, salt_replay_workspace_bytes, transform, EvaluationShape, QuotientCommitShape,
    SampleLocation, TraceCommitShape,
};
use super::super::super::{quotient::PartitionStorage, storage::ProjectionShape};
use super::*;
use crate::block_v2::{
    challenger::resources as transcript,
    gpu_hash::engine::{
        self,
        lde_plan::{InputShape, LdeCommitPlan, LdeRetention},
        Engine, Limits,
    },
    gpu_quotient_prover::program,
};
mod commitments;
mod fri;
mod inputs;
mod operations;
mod randomness;

#[derive(Debug)]
struct Phase {
    name: &'static str,
    chunks: usize,
    bytes: usize,
}

#[derive(Debug)]
struct QuotientTile {
    chunks: usize,
    rows: usize,
    peak: usize,
    row_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct Plan {
    phases: Vec<Phase>,
    quotient_tiles: Vec<QuotientTile>,
    operations: Vec<operations::OperationPlan>,
    randomness: Vec<randomness::RandomnessPlan>,
    fri: Vec<fri::FriPlan>,
    commitments: Vec<commitments::CommitmentPlan>,
    inputs: Vec<inputs::InputPlan>,
    ceiling: usize,
    max_allocation: usize,
    baseline: usize,
    initial_hash: usize,
    initial_lde: usize,
    quotient_limits: Limits,
}

impl Plan {
    pub(super) fn new(g: WalletProofMinimum, engine: &Engine, live: usize) -> Result<Self, String> {
        let initial_hash = engine
            .workspace
            .as_ref()
            .map_or(0, engine::Workspace::bytes);
        let initial_lde = engine.lde_workspace.as_ref().map_or(0, |w| w.bytes());
        let baseline = live
            .checked_sub(sum(&[initial_hash, initial_lde])?)
            .ok_or("wallet cached workspace exceeds live bytes")?;
        #[cfg(feature = "gpu")]
        let baseline = if engine.tuning.tables {
            baseline
                .checked_add(engine::ntt_tables::MAX_BYTES - engine.ntt_tables.bytes())
                .ok_or("wallet public table cache reservation overflow")?
        } else {
            baseline
        };
        let mut plan = Self {
            phases: Vec::new(),
            quotient_tiles: Vec::new(),
            operations: Vec::new(),
            randomness: Vec::new(),
            fri: Vec::new(),
            commitments: Vec::new(),
            inputs: Vec::new(),
            ceiling: engine.limits.managed_bytes,
            max_allocation: engine.max_alloc,
            baseline,
            initial_hash,
            initial_lde,
            #[cfg(feature = "gpu")]
            quotient_limits: engine.quotient_limits(),
            #[cfg(not(feature = "gpu"))]
            quotient_limits: engine::quotient::phase_limits(engine.limits, false),
        };
        plan.build(
            g,
            engine.limits,
            engine.mode.slots(),
            engine.lde_workspace_limit,
            engine.query.is_none(),
        )?;
        Ok(plan)
    }

    fn phase(
        &mut self,
        name: &'static str,
        chunks: usize,
        parts: &[usize],
        allocations: &[usize],
    ) -> Result<usize, String> {
        let bytes = sum(parts)?;
        if bytes > self.ceiling || allocations.iter().any(|&n| n > self.max_allocation) {
            return Err(format!("wallet phase {name} ({chunks} quotient chunks) exceeds managed/device allocation capacity"));
        }
        self.phases.push(Phase {
            name,
            chunks,
            bytes,
        });
        Ok(bytes)
    }

    // Actual hiding commitments capture degree prefixes while hashing the LDE.
    // Salt replay materializes one matrix at a time, including random scratch.
    fn commit(
        &mut self,
        name: &'static str,
        chunks: usize,
        inputs: &[InputShape],
        live: usize,
        capture: usize,
        limits: Limits,
        slots: usize,
    ) -> Result<usize, String> {
        let rows = inputs[0]
            .height
            .checked_shl(profile::LOG_BLOWUP as u32)
            .ok_or("wallet LDE row overflow")?;
        let replay = salt_replay_workspace_bytes(rows * 4)?;
        self.admit_randomness(
            name,
            chunks,
            [rows * 4].into_iter(),
            false,
            sum(&[live, capture])?,
        )?;
        let next = LdeCommitPlan::new_with_retention(
            inputs,
            profile::CAP_HEIGHT,
            limits,
            self.max_allocation,
            slots,
            sum(&[live, capture, replay])?,
            0,
            0,
            LdeRetention::DeviceOnly,
            engine::lde_readback::ReadbackLayout::Direct,
        )?;
        self.phase(
            name,
            chunks,
            &[next.predicted_managed_peak_bytes],
            &[
                rows * 32,
                next.transform_buffer_bytes,
                next.sponge_state_bytes,
                next.retained_tree_bytes,
            ],
        )?;
        Ok(next.hash_workspace_bytes)
    }

    fn build(
        &mut self,
        g: WalletProofMinimum,
        limits: Limits,
        slots: usize,
        cache_limit: usize,
        needs_query_buffer: bool,
    ) -> Result<(), String> {
        let program = g
            .program
            .ok_or("wallet phase admission requires recorded program geometry")?;
        if g.periodic_columns != 0 && g.periodic.is_none() {
            return Err("wallet phase admission requires retained periodic source geometry".into());
        }
        let h = g.rows;
        // Check row/tile feasibility before other adaptive planners can obscure
        // this error. Each quotient partition below repeats it with phase live storage.
        engine::quotient::Plan::for_shape(
            program,
            h * 2,
            sum(&[self.baseline, program.instruction_words * 8])?,
            self.quotient_limits,
            self.max_allocation,
        )?;
        let hidden = h * 2;
        let n = hidden << profile::LOG_BLOWUP;
        let e = g.extension.degree();
        let r = profile::NUM_RANDOM_CODEWORDS;
        let main_width = g.columns + r;
        let aux_width = e + r;
        if main_width > 4096 || aux_width > 4096 {
            return Err("wallet opening width exceeds supported geometry".into());
        }
        if g.columns
            .checked_add(g.periodic_columns)
            .and_then(|n| n.checked_mul(2))
            .is_none_or(|n| n > program::MAX_ROW_WORDS)
        {
            return Err("wallet quotient input row exceeds supported geometry".into());
        }
        let trace = h * g.columns * 8;
        let periodic = h * g.periodic_columns * 8;
        let main = hidden * main_width * 8;
        let aux = hidden * aux_width * 8;
        let fri = n * e * 8;
        let tree =
            engine::retained_layout(n, profile::CAP_HEIGHT, self.max_allocation)?.elements * 8;

        // Fixed protocol limits cover both supported fields. Public compiler
        // constant folding shares the public-hash allowance. Five RNG keys
        // cover the existing PCS/hiding/MMCS streams; clones share their key.
        let controls = transcript::reservation();
        let control = sum(&[
            controls.managed_bytes as usize,
            5 * 32,
            super::super::super::public_hash::WORKSPACE_BYTES as usize,
            if needs_query_buffer {
                engine::QUERY_ELEMENTS * 8
            } else {
                0
            },
        ])?;
        let base = sum(&[self.baseline, control])?;
        let (witness_extra, witness_largest) =
            super::super::witness_storage_extra(g.host_allowance)?;
        self.phase(
            "witness_and_publics",
            0,
            &[
                base,
                self.initial_hash,
                self.initial_lde,
                trace,
                witness_extra,
            ],
            &[
                trace,
                witness_largest,
                controls.max_allocation_bytes as usize,
            ],
        )?;
        // The same retained table geometry enters runtime expansion. Use its
        // actual compact source size, then the shared transform storage planner.
        let source_live = sum(&[base, self.initial_hash, self.initial_lde, trace])?;
        let transform_live = sum(&[base, self.initial_hash, trace])?;
        if let Some(source) = g.periodic {
            let expansion = source.plan(source_live, self.ceiling, self.max_allocation)?;
            self.phase(
                "periodic_source",
                0,
                &[expansion.peak_bytes],
                &source.allocation_bytes(),
            )?;
            let transformed = transform::storage_plan(
                source.output,
                h.ilog2(),
                sum(&[transform_live, source.output.bytes()])?,
                limits,
                self.max_allocation,
            )?;
            self.phase(
                "periodic_transform",
                0,
                &[transformed.peak_bytes],
                &[periodic],
            )?;
        } else {
            self.phase("periodic_source", 0, &[source_live], &[])?;
            self.phase("periodic_transform", 0, &[transform_live], &[])?;
        }
        let initial_lde = if periodic == 0 { self.initial_lde } else { 0 };
        let raw = MatrixSpec::new(h.ilog2(), g.columns, Extension::Base, RowOrder::Natural, 1)?;
        let trace_shape = TraceCommitShape::new(raw, r)?;
        let samples = trace_shape.allocation_bytes()[0];
        let normalization = trace_shape.allocation_bytes()[1];
        self.commitments.push(commitments::CommitmentPlan {
            name: "main_samples",
            chunks: 0,
            storage: trace_shape.storage_plan(
                SampleLocation::Resident,
                sum(&[
                    base,
                    self.initial_hash,
                    initial_lde,
                    trace,
                    periodic,
                    samples,
                ])?,
                self.ceiling,
                self.max_allocation,
            )?,
        });
        let sample_peak = salt_replay_workspace_bytes(samples / 8)?;
        self.admit_randomness(
            "main_samples",
            0,
            [samples / 8].into_iter(),
            true,
            sum(&[
                base,
                self.initial_hash,
                initial_lde,
                trace,
                periodic,
                normalization,
            ])?,
        )?;
        self.phase(
            "main_samples",
            0,
            &[
                base,
                self.initial_hash,
                initial_lde,
                trace,
                periodic,
                sample_peak,
                normalization,
            ],
            &[samples, normalization],
        )?;
        self.admit_randomness(
            "main_salt_draw",
            0,
            [n * 4].into_iter(),
            false,
            sum(&[
                base,
                self.initial_hash,
                initial_lde,
                trace,
                periodic,
                samples,
                normalization,
            ])?,
        )?;
        self.phase(
            "main_salt_draw",
            0,
            &[
                base,
                self.initial_hash,
                initial_lde,
                trace,
                periodic,
                samples,
                normalization,
                salt_replay_workspace_bytes(n * 4)?,
            ],
            &[n * 32],
        )?;
        let main_hash = self.commit(
            "main_commitment",
            0,
            &[trace_shape.lde_shape()],
            sum(&[base, trace, periodic, samples, normalization])?,
            main,
            limits,
            slots,
        )?;
        let retained_main = tree + main;

        // Do not guess a normalized AIR degree or evaluate field constants on
        // CPU. Every allowed quotient partition is covered before any proving
        // arithmetic; runtime normalization retains its existing exact degree.
        for log_chunks in 1..=profile::MAX_QUOTIENT_CHUNKS.ilog2() {
            let chunks = 1usize << log_chunks;
            let quotient = h * chunks * e * 8;
            let projected = hidden * g.columns * 8;
            let projection = ProjectionShape::new(
                MatrixSpec::new(
                    hidden.ilog2(),
                    main_width,
                    Extension::Base,
                    RowOrder::BitReversed,
                    1,
                )?,
                hidden.ilog2(),
                1,
                g.columns,
                Extension::Base,
            )?;
            let projection_storage = projection.storage_plan(
                sum(&[base, retained_main, periodic, main_hash, cache_limit])?,
                cache_limit,
                limits,
                self.max_allocation,
            )?;
            self.inputs.push(inputs::InputPlan {
                name: "quotient_projection",
                chunks,
                peak: projection_storage.peak_bytes,
                largest: projection_storage.max_allocation_bytes,
                coset_rows: 0,
                cosets: 0,
            });
            self.phase(
                "quotient_projection",
                chunks,
                &[
                    base,
                    retained_main,
                    periodic,
                    main_hash,
                    cache_limit,
                    projected,
                ],
                &[projected],
            )?;
            // Projection and coset transforms replace the LDE cache. The
            // original prefixes, projected main, expanded main/periodic input,
            // transform scratch, full output and one coset output are bounded
            // together; no complete full-width quotient-domain matrix is used.
            let code = program.instruction_words * 8;
            let quotient_workspace = engine::quotient::workspace_bytes(self.quotient_limits);
            let periodic_input = if g.periodic_columns == 0 {
                None
            } else {
                Some(MatrixSpec::new(
                    h.ilog2(),
                    g.periodic_columns,
                    Extension::Base,
                    RowOrder::BitReversed,
                    1,
                )?)
            };
            let inputs = [
                projection.output,
                periodic_input.unwrap_or(projection.output),
            ];
            let partition = PartitionStorage::new(
                &inputs[..1 + usize::from(periodic_input.is_some())],
                h.ilog2(),
                (h * chunks).ilog2(),
                1,
                program,
                sum(&[
                    base,
                    retained_main,
                    main_hash,
                    projected,
                    periodic,
                    code,
                    cache_limit,
                ])?,
                cache_limit,
                self.quotient_limits,
                self.max_allocation,
            )?;
            self.inputs.push(inputs::InputPlan {
                name: "quotient_evaluation",
                chunks,
                peak: partition.peak_bytes,
                largest: partition.max_allocation_bytes,
                coset_rows: 1usize << partition.part_log,
                cosets: partition.cosets,
            });
            // Preserve the compiler-bound/maximum-workspace envelope, and also
            // include the runtime planner's result/cache overlap before any LDE.
            let evaluation_bound = sum(&[
                base,
                retained_main,
                main_hash,
                3 * projected,
                5 * periodic,
                quotient,
                hidden * e * 8,
                code,
                quotient_workspace,
            ])?
            .max(partition.peak_bytes);
            self.phase(
                "quotient_evaluation",
                chunks,
                &[evaluation_bound],
                &[
                    projected,
                    2 * periodic,
                    quotient,
                    hidden * e * 8,
                    code,
                    quotient_workspace,
                    partition.max_allocation_bytes,
                ],
            )?;

            let live = sum(&[
                base,
                retained_main,
                main_hash,
                3 * projected,
                5 * periodic,
                quotient,
                hidden * e * 8,
                code,
            ])?;
            let tile = engine::quotient::Plan::for_shape(
                program,
                h * chunks,
                live,
                self.quotient_limits,
                self.max_allocation,
            )?;
            self.quotient_tiles.push(QuotientTile {
                chunks,
                rows: tile.rows,
                peak: tile.peak,
                row_bytes: (program.row_words + program.registers * e) * 8,
            });
            let quotient_shape = QuotientCommitShape::new(
                MatrixSpec::new((h * chunks).ilog2(), 1, g.extension, RowOrder::Natural, 1)?,
                chunks,
                r,
            )?;
            let [random, masks, parameters] = quotient_shape.allocation_words().map(|n| n * 8);
            self.commitments.push(commitments::CommitmentPlan {
                name: "quotient_samples",
                chunks,
                storage: quotient_shape.storage_plan(
                    SampleLocation::Resident,
                    sum(&[base, retained_main, main_hash, quotient, random, masks])?,
                    self.ceiling,
                    self.max_allocation,
                )?,
            });
            let random_scratch = (salt_replay_workspace_bytes(random / 8)? - random)
                .max(salt_replay_workspace_bytes(masks / 8)? - masks);
            self.admit_randomness(
                "quotient_samples",
                chunks,
                [random / 8, masks / 8].into_iter(),
                true,
                sum(&[base, retained_main, main_hash, quotient, parameters])?,
            )?;
            self.phase(
                "quotient_samples",
                chunks,
                &[
                    base,
                    retained_main,
                    main_hash,
                    quotient,
                    random,
                    masks,
                    random_scratch,
                    parameters,
                ],
                &[random, masks, parameters],
            )?;
            self.admit_randomness(
                "quotient_salt_draw",
                chunks,
                (0..chunks).map(|_| n * 4),
                false,
                sum(&[
                    base,
                    retained_main,
                    main_hash,
                    quotient,
                    random,
                    masks,
                    parameters,
                ])?,
            )?;
            self.phase(
                "quotient_salt_draw",
                chunks,
                &[
                    base,
                    retained_main,
                    main_hash,
                    quotient,
                    random,
                    masks,
                    parameters,
                    salt_replay_workspace_bytes(n * 4)?,
                ],
                &[n * 32],
            )?;
            // Hiding doubles each chunk's degree. This conservative LDE shape
            // keeps that effective height while deriving width from runtime.
            let shapes = [InputShape {
                height: quotient_shape.height * 2,
                width: quotient_shape.width,
                added_bits: profile::LOG_BLOWUP,
            }; profile::MAX_QUOTIENT_CHUNKS];
            let quotient_hash = self.commit(
                "quotient_commitment",
                chunks,
                &shapes[..chunks],
                sum(&[base, retained_main, quotient, random, masks, parameters])?,
                chunks * aux,
                limits,
                slots,
            )?;
            self.phase("quotient_prefix_buffers", chunks, &[chunks * aux], &[aux])?;
            let retained_pair = sum(&[retained_main, tree, chunks * aux])?;
            let evaluation_shape = EvaluationShape::new(MatrixSpec::new(
                hidden.ilog2(),
                aux_width,
                Extension::Base,
                RowOrder::Natural,
                1,
            )?)?;
            let evaluation_storage = evaluation_shape.storage_plan(
                sum(&[base, retained_pair, quotient_hash, cache_limit, aux])?,
                self.ceiling,
                self.max_allocation,
            )?;
            let evaluation_parameters = evaluation_storage.allocation_bytes[2];
            self.commitments.push(commitments::CommitmentPlan {
                name: "randomization_samples",
                chunks,
                storage: evaluation_storage,
            });
            self.admit_randomness(
                "randomization_samples",
                chunks,
                [aux / 8].into_iter(),
                true,
                sum(&[
                    base,
                    retained_pair,
                    quotient_hash,
                    cache_limit,
                    evaluation_parameters,
                ])?,
            )?;
            self.phase(
                "randomization_samples",
                chunks,
                &[
                    base,
                    retained_pair,
                    quotient_hash,
                    cache_limit,
                    salt_replay_workspace_bytes(aux / 8)?,
                    evaluation_parameters,
                ],
                &[aux, evaluation_parameters],
            )?;
            self.admit_randomness(
                "randomization_salt_draw",
                chunks,
                [n * 4].into_iter(),
                false,
                sum(&[
                    base,
                    retained_pair,
                    quotient_hash,
                    cache_limit,
                    aux,
                    evaluation_parameters,
                ])?,
            )?;
            self.phase(
                "randomization_salt_draw",
                chunks,
                &[
                    base,
                    retained_pair,
                    quotient_hash,
                    cache_limit,
                    aux,
                    evaluation_parameters,
                    salt_replay_workspace_bytes(n * 4)?,
                ],
                &[n * 32],
            )?;
            let random_hash = self.commit(
                "randomization_commitment",
                chunks,
                &[evaluation_shape.lde_shape(profile::LOG_BLOWUP)?],
                sum(&[base, retained_pair, aux, evaluation_parameters])?,
                aux,
                limits,
                slots,
            )?;
            let retained = sum(&[retained_pair, tree, aux])?;
            let prefix = MatrixSpec::new(
                hidden.ilog2(),
                main_width.max(aux_width),
                Extension::Base,
                RowOrder::BitReversed,
                1,
            )?;
            self.phase(
                "opening_transcript",
                chunks,
                &[base, retained, random_hash, cache_limit],
                &[],
            )?;

            // At most two points per matrix; all opening objects are retained
            // while evaluation temporaries are recycled. Reduction retains one
            // accumulator and two full-size transform vectors simultaneously.
            let claims = 2 * e * (main_width + (chunks + 1) * aux_width + chunks + 2) * 8;
            self.admit_openings(
                prefix,
                n.ilog2(),
                chunks,
                g.extension,
                sum(&[base, retained, random_hash, claims])?,
                limits,
                g.host_allowance,
            )?;
            let opening_fixed = (hidden * e
                + main_width.max(aux_width) * e
                + (hidden.ilog2() + n.ilog2() + 2) as usize
                + 5 * e
                + 1)
                * 8;
            self.phase(
                "opening_evaluation",
                chunks,
                &[
                    base,
                    retained,
                    random_hash,
                    claims,
                    opening::TILE_LIMIT,
                    4 * e * 8 + 8,
                ],
                &[opening::TILE_LIMIT, claims],
            )?;
            self.phase(
                "opening_reduction",
                chunks,
                &[
                    base,
                    retained,
                    random_hash,
                    claims,
                    3 * fri,
                    opening_fixed,
                    opening::TILE_LIMIT,
                ],
                &[fri, hidden * e * 8, opening::TILE_LIMIT],
            )?;

            // One wallet FRI input height. Binary folding bounds both profiles:
            // all vectors total <2 full inputs, all FRI trees <one height-N
            // tree. Arity up to 16 only decreases those series. Salt replay and
            // sponge sizes are largest at the first binary commitment.
            let mut hash_bound = random_hash;
            for log_arity in 1..=4 {
                let arity = 1usize << log_arity;
                let fri_hash = engine::plan_slots(
                    n / arity,
                    arity * e + 4,
                    limits,
                    self.max_allocation,
                    slots,
                )?;
                hash_bound = hash_bound.max(
                    fri_hash.bytes
                        - engine::CONSTANT_BYTES
                        - limits.staging_bytes
                        - engine::transport_bytes(limits),
                );
            }
            // Binary layers bound every permitted FRI arity, including small
            // terminal layers. Salts are consumed/replayed one matrix at a time.
            self.admit_randomness(
                "fri_commit_fold_and_final",
                chunks,
                (0..n.ilog2()).map(|level| (n >> (level + 1)) * 4),
                false,
                sum(&[
                    base,
                    retained,
                    claims,
                    2 * fri,
                    tree,
                    hash_bound,
                    (n / 2) * 64,
                ])?,
            )?;
            let fri_bound = self.admit_fri_final(
                MatrixSpec::new(n.ilog2(), 1, g.extension, RowOrder::BitReversed, 1)?,
                chunks,
                sum(&[
                    base,
                    retained,
                    claims,
                    2 * fri,
                    tree,
                    hash_bound,
                    (n / 2) * 64,
                    salt_replay_workspace_bytes((n / 2) * 4)?,
                ])?,
                g.host_allowance,
            )?;
            self.phase(
                "fri_commit_fold_and_final",
                chunks,
                &[fri_bound],
                &[fri, (n / 2) * 64, (n / 2) * 32],
            )?;
            // Query transforms clear both caches. Include the previous hash
            // workspace anyway for the earlier salt materialization boundary.
            let queries = match g.extension {
                Extension::Quadratic => crate::config::NUM_QUERIES,
                Extension::Cubic => profile::NUM_QUERIES,
                Extension::Base => return Err("wallet query extension".into()),
            };
            let query_scratch = query::PREFERRED_SCRATCH.max(
                (2 * n + queries + hidden.ilog2() as usize + n.ilog2() as usize + 2 + queries) * 8,
            );
            // PCS salts have the largest replay output. Smaller FRI replays
            // are also covered while every retained vector/tree remains live.
            self.admit_randomness(
                "pcs_and_fri_queries",
                chunks,
                [n * 4].into_iter(),
                false,
                sum(&[
                    base,
                    retained,
                    claims,
                    2 * fri,
                    tree,
                    hash_bound,
                    query_scratch,
                ])?,
            )?;
            let query_bound = self.admit_fri_queries(
                MatrixSpec::new(n.ilog2(), 1, g.extension, RowOrder::BitReversed, 1)?,
                chunks,
                queries,
                sum(&[
                    base,
                    retained,
                    claims,
                    2 * fri,
                    tree,
                    hash_bound,
                    salt_replay_workspace_bytes(n * 4)?,
                    query_scratch,
                ])?,
                g.host_allowance,
            )?;
            self.phase(
                "pcs_and_fri_queries",
                chunks,
                &[query_bound],
                &[n * 32, query_scratch],
            )?;
            self.admit_queries(
                prefix,
                n.ilog2(),
                chunks,
                queries,
                sum(&[
                    base,
                    retained,
                    claims,
                    2 * fri,
                    tree,
                    hash_bound,
                    salt_replay_workspace_bytes(n * 4)?,
                ])?,
                g.host_allowance,
            )?;
        }
        Ok(())
    }

    pub(crate) fn report(&self) {
        eprintln!(
            "bounded_wallet_phase_admission {}",
            serde_json::json!({
                "schema": "lattica-wallet-device-phase-v9", "managed_ceiling_bytes": self.ceiling,
                "max_allocation_bytes": self.max_allocation, "baseline_bytes": self.baseline,
                "initial_hash_workspace_bytes": self.initial_hash, "initial_lde_workspace_bytes": self.initial_lde,
                "adaptive_lde_tiles": true, "host_lifetime_admitted": false,
                "recorded_program_tile_admission": true,
                "exact_compiled_registers": false,
                "opening_query_operation_admission": true,
                "retained_periodic_source_admission": true,
                "periodic_source_construction_admission": true,
                "randomness_storage_admission": true,
                "randomness_complete_stream_admission": false,
                "fri_operation_admission": true,
                "fri_single_input_height": true,
                "commitment_input_storage_admission": true,
                "quotient_input_operation_admission": true,
                "quotient_input_plans": self.inputs.iter().map(|p| p.report()).collect::<Vec<_>>(),
                "commitment_input_plans": self.commitments.iter().map(|p| p.report()).collect::<Vec<_>>(),
                "fri_operation_plans": self.fri.iter().map(|p| p.report()).collect::<Vec<_>>(),
                "randomness_plans": self.randomness.iter().map(|p| p.report()).collect::<Vec<_>>(),
                "operation_plans": self.operations.iter().map(|p| p.report()).collect::<Vec<_>>(),
                "quotient_tiles": self.quotient_tiles.iter().map(|p| serde_json::json!({
                    "quotient_chunks":p.chunks, "rows_at_bound":p.rows,
                    "managed_bytes_at_bound":p.peak, "row_bytes_bound":p.row_bytes
                })).collect::<Vec<_>>(),
                "phases": self.phases.iter().map(|p| serde_json::json!({
                    "name":p.name, "quotient_chunks":p.chunks, "managed_bytes":p.bytes
                })).collect::<Vec<_>>()
            })
        );
    }
}

#[cfg(test)]
mod tests;
