//! Pure phase composition for the pinned, one-shot wide registered proof.
//!
//! The caller charges the engine, transcript, scalar/RNG owners, and lookup /
//! quotient code in `common_device_bytes`. Program/instruction retirement is
//! established by the consuming backend before this phase. Any upstream matrix
//! retained beyond quotient commitment must also be included in that charge;
//! the prefixes, public salts and trees below must not be charged twice. The native host
//! partition already covers program/compiler/verifier, engine/session and the
//! separate RNG/transcript quotas. Host tree backing has its own worker charge.
use crate::block_v2::{
    gpu_hash::{
        device::{
            self, DeviceMatrix, DeviceOpening, Extension, MatrixSpec, PublicMatrix, PublicSalts,
            ReplaySalts, RowOrder,
        },
        engine::{
            retained_storage::{RetainedTreeStorageMode, Selection},
            Limits,
        },
        CandidateMmcs, FriData, ProverData,
    },
    profile::{self, Challenge, ChallengeMmcs},
};
use crate::{config::Val, gpu_fri, gpu_matrix::query::QueryPlan, gpu_random};
use core::mem::size_of;
use p3_commit::{BatchOpening, Mmcs};
use p3_field::{Field, PrimeField64};
use p3_fri::{CommitPhaseProofStep, QueryProof};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

mod native_device;

const ROUNDS: usize = 5;
const MATRICES: usize = 20;
const QUOTIENT_CHUNKS: usize = 16;
const DEGREE: usize = 3;
const ROUND_MATRICES: [usize; ROUNDS] = [1, 1, QUOTIENT_CHUNKS, 1, 1];
const ROUND_COLUMNS: [usize; ROUNDS] = [7, 98, 16 * 7, 200, 55];

// These are named runtime component contracts, not new execution allowances.
const PCS_QUERY_METADATA: usize = 1 << 20; // gpu_hash::owned_queries
const FRI_QUERY_LIMIT: usize = 1 << 30; // opening_pcs::owned_fri
const FRI_ROW_QUERY_LIMIT: usize = 1 << 20; // gpu_hash::fri_data
const MERKLE_QUERY_BYTES: usize = 32 * 4 * 8; // engine::QUERY_ELEMENTS

// The quotient compiler retains at most16MiB including its Arc/Vec metadata.
// Lookup lowering creates its code with exact schedule capacity; tuple and
// boundary push growth stays below twice their capped lengths. Keep both code
// owners charged independently of the enclosing symbolic workspace.
const RETAINED_GPU_CODE_HOST_BYTES: usize = 32 << 20;
const _: () = {
    use crate::block_v2::{
        lookup_program::{MAX_LOOKUPS, MAX_TUPLES},
        quotient_program::{MAX_NODES, MAX_ROW_WORDS, WORDS_PER_INSTRUCTION},
    };
    assert!(
        (16 << 20)
            + (MAX_NODES + MAX_ROW_WORDS) * WORDS_PER_INSTRUCTION * 8
            + 2 * (MAX_TUPLES * 3 + MAX_LOOKUPS + 1) * 8
            + (1 << 20) // Existing native lifecycle metadata ceiling.
            <= RETAINED_GPU_CODE_HOST_BYTES
    );
};

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub(super) struct OpeningBounds {
    pub opening_device_peak_bytes: usize,
    pub fri_device_peak_bytes: usize,
    pub query_device_peak_bytes: usize,
    pub largest_allocation_bytes: usize,
    /// Maximum of fixed phases and smallest legal adaptive tiles, under the
    /// conservative common-owner composition. Not an actual-runtime minimum.
    pub minimum_required_device_bytes: usize,
    pub host_workspace_peak_bytes: usize,
    /// Matrix/stream wrappers and retained caps, excluding host-tree backing.
    pub retained_host_metadata_bytes: usize,
    pub required_tree_host_bytes: usize,
    pub host_bound_complete: bool,
}

fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b)
        .ok_or_else(|| "opening phase addition overflow".into())
}
fn mul(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b)
        .ok_or_else(|| "opening phase multiplication overflow".into())
}
fn sum(parts: &[usize]) -> Result<usize, String> {
    parts.iter().try_fold(0, |total, &part| add(total, part))
}
fn bytes<T>(count: usize) -> Result<usize, String> {
    mul(count, size_of::<T>())
}
fn matrix(
    log: u32,
    columns: usize,
    extension: Extension,
    shift: u64,
) -> Result<MatrixSpec, String> {
    MatrixSpec::new(log, columns, extension, RowOrder::BitReversed, shift)
}

struct Census {
    largest: usize,
    minimum: usize,
    limit: usize,
    max_allocation: usize,
}
impl Census {
    fn allocation(&mut self, bytes: usize) -> Result<(), String> {
        if bytes == 0 || bytes > self.max_allocation {
            return Err("opening phase allocation exceeds the selected device limit".into());
        }
        self.largest = self.largest.max(bytes);
        Ok(())
    }
    fn fixed(&mut self, live: usize, allocations: &[usize]) -> Result<usize, String> {
        let mut peak = live;
        for &bytes in allocations {
            self.allocation(bytes)?;
            peak = add(peak, bytes)?;
        }
        self.minimum = self.minimum.max(peak);
        self.check_peak(peak)?;
        Ok(peak)
    }
    fn check_peak(&self, peak: usize) -> Result<(), String> {
        if peak > self.limit {
            return Err("opening phase exceeds the selected managed device allowance".into());
        }
        Ok(())
    }
    fn adaptive_peak(&self, live_upper: usize, maximum_workspace: usize) -> Result<usize, String> {
        // A larger conservative live charge can select a smaller runtime tile.
        // Bound all legal tile choices using the planner at zero live bytes;
        // runtime admission independently enforces the managed ceiling.
        Ok(add(live_upper, maximum_workspace)?.min(self.limit))
    }
    fn fri_plan(&mut self, plan: gpu_fri::StoragePlan) -> Result<usize, String> {
        if plan.max_allocation_bytes != 0 {
            self.allocation(plan.max_allocation_bytes)?;
        }
        self.minimum = self.minimum.max(plan.peak_bytes);
        self.check_peak(plan.peak_bytes)?;
        Ok(plan.peak_bytes)
    }
}

/// Refuses before session creation. All geometry comes from the fixed source
/// profile and the independently checked program height, never from a packet.
pub(super) fn plan(
    rows: usize,
    common_device_bytes: usize,
    pcs_host_budget_bytes: usize,
    limits: Limits,
    max_allocation: usize,
    trees: Selection,
) -> Result<OpeningBounds, String> {
    plan_shape(
        rows,
        common_device_bytes,
        pcs_host_budget_bytes,
        limits,
        max_allocation,
        trees,
        output_geometry(),
        ROUND_MATRICES,
        ROUND_COLUMNS,
        false,
    )
}

/// The native uni schedule uses three rounds, no preprocessing or permutation,
/// and at most32 quotient chunks under the unchanged hiding cubic profile.
/// This is one phase census; it issues no native dispatch authority.
pub(super) fn native_plan(
    rows: usize,
    main_width: usize,
    common_device_bytes: usize,
    pcs_host_budget_bytes: usize,
    limits: Limits,
    max_allocation: usize,
    trees: Selection,
) -> Result<OpeningBounds, String> {
    let main = add(main_width, profile::NUM_RANDOM_CODEWORDS)?;
    if main_width == 0 || main_width > 1 << 20 {
        return Err("native opening main-width geometry refused".into());
    }
    let mut widths = [7usize; 34];
    widths[1] = main;
    let mut points = [1usize; 34];
    points[1] = 2;
    plan_shape(
        rows,
        common_device_bytes,
        pcs_host_budget_bytes,
        limits,
        max_allocation,
        trees,
        (widths, points),
        [1, 1, 32],
        [7, main, 32 * 7],
        true,
    )
}

fn plan_shape<const MATRIX_COUNT: usize, const ROUND_COUNT: usize>(
    rows: usize,
    common_device_bytes: usize,
    pcs_host_budget_bytes: usize,
    limits: Limits,
    max_allocation: usize,
    trees: Selection,
    geometry: ([usize; MATRIX_COUNT], [usize; MATRIX_COUNT]),
    round_matrices: [usize; ROUND_COUNT],
    round_columns: [usize; ROUND_COUNT],
    native: bool,
) -> Result<OpeningBounds, String> {
    let device_trees = native && trees.mode == RetainedTreeStorageMode::Device;
    let tree_profile = if device_trees {
        trees.host_bytes == 0 && ROUND_COUNT == 3 && MATRIX_COUNT == 34
    } else {
        trees.mode == RetainedTreeStorageMode::HostBacking && trees.host_bytes != 0
    };
    if !cfg!(all(
        not(debug_assertions),
        target_arch = "x86_64",
        feature = "block-v2-wide-lanes"
    )) || !(8..=1 << 20).contains(&rows)
        || !rows.is_power_of_two()
        || profile::LOG_BLOWUP != 4
        || profile::NUM_QUERIES != 128
        || profile::CAP_HEIGHT != 6
        || profile::NUM_RANDOM_CODEWORDS != 4
        || size_of::<Challenge>() != DEGREE * 8
        || !tree_profile
        || pcs_host_budget_bytes == 0
        || limits.managed_bytes == 0
        || limits.managed_bytes > 8 << 30
        || max_allocation == 0
    {
        return Err("opening phase requires its pinned tree profile".into());
    }
    let prefix_rows = mul(rows, 2)?;
    let height = mul(prefix_rows, 1 << profile::LOG_BLOWUP)?;
    let log_prefix = prefix_rows.ilog2();
    let log_height = height.ilog2();
    let shift = Val::GENERATOR.as_canonical_u64();
    let (widths, points) = geometry;
    let prefix_columns = widths
        .iter()
        .try_fold(0, |total, &width| add(total, width))?;
    let prefix_bytes = mul(mul(prefix_rows, prefix_columns)?, 8)?;
    let public_salts = mul(height, 32)?;
    // The registered host branch adds exactly zero and retains its existing
    // phase arithmetic. Native device storage keeps the entire tree graph and
    // standard hash workspace, including future FRI trees, live throughout.
    let additional = if device_trees {
        Some(native_device::Additional::new(height, limits, max_allocation)?)
    } else {
        None
    };
    let base = sum(&[
        common_device_bytes,
        prefix_bytes,
        public_salts,
        additional.map_or(0, |extra| extra.live_bytes),
    ])?;
    let mut census = Census {
        largest: additional.map_or(0, |extra| extra.largest_allocation),
        minimum: base,
        limit: limits.managed_bytes,
        max_allocation,
    };
    census.check_peak(base)?;
    census.allocation(public_salts)?;
    for width in widths {
        census.allocation(mul(mul(prefix_rows, width)?, 8)?)?;
    }

    // All original trees remain live through all FRI construction and queries.
    let initial_tree_charge = trees.charged_tree_bytes(height, profile::CAP_HEIGHT)?;
    let mut required_tree_host_bytes = mul(ROUND_COUNT, initial_tree_charge)?;
    let mut layer_log = log_height;
    let mut layer_count = 0;
    while layer_log > profile::LOG_BLOWUP as u32 {
        layer_log -= 1;
        required_tree_host_bytes = add(
            required_tree_host_bytes,
            trees.charged_tree_bytes(1usize << layer_log, profile::CAP_HEIGHT)?,
        )?;
        layer_count += 1;
    }
    if required_tree_host_bytes > trees.host_bytes {
        return Err(
            "complete opening graph exceeds the separately reserved host-tree quota".into(),
        );
    }

    let mut opening_peak = base;
    let mut prepared_device = 0;
    for (&width, &count) in widths.iter().zip(&points) {
        let spec = matrix(log_prefix, width, Extension::Base, shift)?;
        let live = add(base, prepared_device)?;
        device::opening_evaluation_plan(spec, count, DEGREE, live, limits, max_allocation)?;
        let (tile_rows, workspace) =
            device::opening_evaluation_plan(spec, count, DEGREE, 0, limits, max_allocation)?;
        opening_peak = opening_peak.max(census.adaptive_peak(live, workspace)?);
        let fixed = [
            mul(count, 24)?,
            mul(count, 48)?,
            mul(mul(count, width)?, 24)?,
            8,
        ];
        // The one-row planner is the minimum feasible evaluation tile. Runtime
        // chooses a larger tile only inside the actual managed allowance.
        let smallest = [
            fixed[0],
            fixed[1],
            fixed[2],
            fixed[3],
            mul(count, 24)?,
            mul(mul(count, width)?, 24)?,
        ];
        census.fixed(live, &smallest)?;
        census.allocation(mul(mul(tile_rows, count)?, 24)?)?;
        census.allocation(mul(mul(tile_rows.div_ceil(128), count)?, mul(width, 24)?)?)?;
        prepared_device = add(prepared_device, add(fixed[0], fixed[2])?)?;
    }
    let fri_input = matrix(log_height, 1, Extension::Cubic, 1)?;
    let accumulator_live = sum(&[base, prepared_device, fri_input.bytes(), 24])?;
    opening_peak =
        opening_peak.max(census.fixed(add(base, prepared_device)?, &[fri_input.bytes(), 24])?);
    for (&width, &count) in widths.iter().zip(&points) {
        let spec = matrix(log_prefix, width, Extension::Base, shift)?;
        device::opening_reduction_plan(
            spec,
            log_height,
            count,
            DEGREE,
            accumulator_live,
            limits,
            max_allocation,
        )?;
        let (tile_rows, workspace) = device::opening_reduction_plan(
            spec,
            log_height,
            count,
            DEGREE,
            0,
            limits,
            max_allocation,
        )?;
        opening_peak = opening_peak.max(census.adaptive_peak(accumulator_live, workspace)?);
        let fixed = [
            mul(prefix_rows, 24)?,
            fri_input.bytes(),
            fri_input.bytes(),
            mul((log_prefix.max(1) + log_height.max(1) + 2) as usize, 8)?,
            mul(width, 24)?,
            mul(count, 48)?,
            8,
            mul(count, 24)?,
        ];
        census.fixed(accumulator_live, &fixed)?;
        census.allocation(mul(mul(tile_rows, count)?, 24)?)?;
    }

    // evaluate_and_reduce drops every DeviceOpening before FRI starts. Each
    // FRI leaf matrix aliases its input: old vectors remain live in FriData.
    // A single input height means this pinned graph performs no input mixes.
    let mut fri_live = add(base, fri_input.bytes())?;
    let mut current = fri_input;
    let mut fri_peak = fri_live;
    while current.log_rows > profile::LOG_BLOWUP as u32 {
        let leaves = gpu_fri::leaves(current, 1)?;
        let salt_words = mul(leaves.rows(), 4)?;
        let random = gpu_random::Plan::new(
            salt_words,
            0,
            fri_live,
            limits.managed_bytes,
            max_allocation,
        )?;
        fri_peak = fri_peak.max(random.peak_bytes);
        census.minimum = census.minimum.max(random.peak_bytes);
        for words in [
            random.output_words,
            random.raw_words,
            random.tiles,
            random.tiles,
            1,
        ] {
            census.allocation(mul(words, 8)?)?;
        }
        // Host-backed direct hashing clears replaceable hash/NTT workspace.
        // Native device mode already keeps its maximum standard hash workspace
        // and all future trees in base. Counting this destination again is
        // conservative; both modes still need the eight-word sponge.
        let tree_bytes = mul(
            mul(leaves.rows(), 2)?
                .checked_sub(1)
                .ok_or("FRI tree geometry")?,
            32,
        )?;
        fri_peak = fri_peak.max(census.fixed(
            fri_live,
            &[mul(salt_words, 8)?, tree_bytes, mul(leaves.rows(), 64)?],
        )?);
        let next = gpu_fri::fold_output(current, 1)?;
        fri_peak = fri_peak.max(census.fri_plan(gpu_fri::vector_output(
            next,
            fri_live,
            limits.managed_bytes,
            max_allocation,
        )?)?);
        fri_live = add(fri_live, next.bytes())?;
        current = next;
    }
    let final_shape = gpu_fri::FinalShape::new(current, profile::LOG_BLOWUP, 0, 24)?;
    fri_peak = fri_peak.max(census.fri_plan(final_shape.plan(
        fri_live,
        limits.managed_bytes,
        max_allocation,
    )?)?);
    // The final constant-domain vector drops before initial PCS queries.
    let query_live = fri_live
        .checked_sub(current.bytes())
        .ok_or("FRI lifetime underflow")?;
    let mut query_peak = query_live;
    for &width in &widths {
        let spec = matrix(log_prefix, width, Extension::Base, shift)?;
        QueryPlan::new(
            spec,
            log_height,
            profile::NUM_QUERIES,
            limits
                .managed_bytes
                .checked_sub(query_live)
                .ok_or("query baseline exceeds limit")?,
            max_allocation,
            pcs_host_budget_bytes,
        )?;
        let maximum = QueryPlan::new(
            spec,
            log_height,
            profile::NUM_QUERIES,
            limits.managed_bytes,
            max_allocation,
            pcs_host_budget_bytes,
        )?;
        query_peak = query_peak.max(census.adaptive_peak(query_live, maximum.workspace_bytes)?);
        for allocation in [
            mul(mul(height, maximum.columns)?, 8)?,
            mul(maximum.inverse_words, 8)?,
            mul(maximum.forward_words, 8)?,
            16,
            mul(profile::NUM_QUERIES, 8)?,
            mul(mul(profile::NUM_QUERIES, maximum.columns)?, 8)?,
        ] {
            census.allocation(allocation)?;
        }
        let one_column = sum(&[
            mul(height, 16)?,
            mul(profile::NUM_QUERIES, 8)?,
            mul(
                (log_prefix.max(1) + log_height.max(1) + 2) as usize + profile::NUM_QUERIES,
                8,
            )?,
        ])?;
        let minimum = QueryPlan::new(
            spec,
            log_height,
            profile::NUM_QUERIES,
            one_column,
            max_allocation,
            pcs_host_budget_bytes,
        )?;
        census.minimum = census
            .minimum
            .max(add(query_live, minimum.workspace_bytes)?);
    }
    // Each query transform returns before salt replay; a single replay matrix
    // then drops before the retained tree reload. Their peaks never coexist.
    let original_salt = matrix(log_height, 4, Extension::Base, 1)?;
    let replay = gpu_random::Plan::new(
        original_salt.words(),
        0,
        query_live,
        limits.managed_bytes,
        max_allocation,
    )?;
    query_peak = query_peak.max(replay.peak_bytes);
    census.minimum = census.minimum.max(replay.peak_bytes);
    for words in [
        replay.output_words,
        replay.raw_words,
        replay.tiles,
        replay.tiles,
        1,
    ] {
        census.allocation(mul(words, 8)?)?;
    }
    let salt_gather =
        gpu_fri::GatherShape::new(original_salt, profile::NUM_QUERIES, pcs_host_budget_bytes)?;
    query_peak = query_peak.max(census.fri_plan(salt_gather.plan(
        add(query_live, original_salt.bytes())?,
        limits.managed_bytes,
        max_allocation,
    )?)?);
    let original_tree_bytes = mul(
        mul(height, 2)?
            .checked_sub(1)
            .ok_or("query tree geometry")?,
        32,
    )?;
    query_peak =
        query_peak.max(census.fixed(query_live, &[original_tree_bytes, MERKLE_QUERY_BYTES])?);
    let mut log = log_height;
    while log > profile::LOG_BLOWUP as u32 {
        let leaves = gpu_fri::leaves(matrix(log, 1, Extension::Cubic, 1)?, 1)?;
        let gather =
            gpu_fri::GatherShape::new(leaves, profile::NUM_QUERIES, pcs_host_budget_bytes)?;
        query_peak = query_peak.max(census.fri_plan(gather.plan(
            query_live,
            limits.managed_bytes,
            max_allocation,
        )?)?);
        log -= 1;
        // Its salt replay/gather and tree upload are no larger than the initial
        // PCS round just planned, and all FRI vectors stay charged in query_live.
    }
    let (workspace, retained_host_metadata_bytes) = host_bounds(
        &widths,
        &points,
        &round_matrices,
        &round_columns,
        log_height as usize,
        layer_count,
    )?;
    // The worker has already reserved these trees and the shared runtime. The
    // existing local opening commitment/runtime partitions nevertheless
    // subtract their backing again, so preflight that stricter local allowance
    // before any dispatch. This grants no new worker capacity.
    let host_workspace_peak_bytes = sum(&[
        workspace,
        mul(ROUND_COUNT, initial_tree_charge)?,
        device::opening_runtime_host_bound()?,
    ])?;
    if add(host_workspace_peak_bytes, retained_host_metadata_bytes)? > pcs_host_budget_bytes {
        return Err("opening host owners exceed the remaining native PCS allowance".into());
    }
    Ok(OpeningBounds {
        opening_device_peak_bytes: opening_peak,
        fri_device_peak_bytes: fri_peak,
        query_device_peak_bytes: query_peak,
        largest_allocation_bytes: census.largest,
        minimum_required_device_bytes: census.minimum,
        host_workspace_peak_bytes,
        retained_host_metadata_bytes,
        required_tree_host_bytes,
        host_bound_complete: true,
    })
}

fn output_geometry() -> ([usize; MATRICES], [usize; MATRICES]) {
    let mut widths = [7usize; MATRICES];
    widths[1] = 98;
    widths[18] = 200;
    widths[19] = 55;
    let mut points = [1usize; MATRICES];
    // Main/preprocessing may omit next-row openings; charging both is safe.
    points[1] = 2;
    points[18] = 2;
    points[19] = 2;
    (widths, points)
}

/// Conservative source-derived opening output and construction ceiling. This
/// includes temporary buffers rather than taking a credit for their release.
/// Native BatchProof descriptors/commitments and caller owners are separate.
/// No GPU selection, allocation, transcript operation or token is created.
pub(super) fn proof_material_host_bound(rows: usize) -> Result<usize, String> {
    if !cfg!(all(
        not(debug_assertions),
        target_arch = "x86_64",
        feature = "block-v2-wide-lanes"
    )) || !(8..=1 << 20).contains(&rows)
        || !rows.is_power_of_two()
        || profile::LOG_BLOWUP != 4
        || profile::NUM_QUERIES != 128
        || profile::CAP_HEIGHT != 6
        || profile::NUM_RANDOM_CODEWORDS != 4
        || size_of::<Challenge>() != DEGREE * 8
    {
        return Err("registered output requires the pinned wide cubic profile".into());
    }
    let log_height = rows.ilog2() as usize + 1 + profile::LOG_BLOWUP;
    let layers = log_height - profile::LOG_BLOWUP;
    let (widths, points) = output_geometry();
    host_bounds(
        &widths,
        &points,
        &ROUND_MATRICES,
        &ROUND_COLUMNS,
        log_height,
        layers,
    )
    .map(|(workspace, _)| workspace)
}

fn host_bounds<const MATRIX_COUNT: usize, const ROUND_COUNT: usize>(
    widths: &[usize; MATRIX_COUNT],
    points: &[usize; MATRIX_COUNT],
    round_matrices: &[usize; ROUND_COUNT],
    round_columns: &[usize; ROUND_COUNT],
    log_height: usize,
    layers: usize,
) -> Result<(usize, usize), String> {
    type Input = BatchOpening<Val, CandidateMmcs>;
    type Step = CommitPhaseProofStep<Challenge, ChallengeMmcs>;
    type Query = QueryProof<Challenge, ChallengeMmcs, Vec<Input>>;
    type Cap = <CandidateMmcs as Mmcs<Val>>::Commitment;
    let queries = profile::NUM_QUERIES;
    let matrix_capacity: usize = round_matrices.iter().map(|n| (2 * n).max(4)).sum();
    let point_count = points.iter().try_fold(0, |n, &p| add(n, p))?;
    let value_count = widths
        .iter()
        .zip(points)
        .try_fold(0, |n, (&w, &p)| add(n, mul(w, p)?))?;
    // Native rounds Vec grows to eight slots. Per-round collect backings are
    // bounded by their pinned single-instance shape; allow the minimum Vec
    // growth of four even for one matrix, and twice the logical matrix count.
    let round_backing = sum(&[
        bytes::<(usize, Vec<Vec<Challenge>>)>(8)?,
        bytes::<Vec<Challenge>>(matrix_capacity)?,
        bytes::<Challenge>(point_count)?,
    ])?;
    let opened = sum(&[
        bytes::<Vec<Vec<Vec<Challenge>>>>(ROUND_COUNT)?,
        bytes::<Vec<Vec<Challenge>>>(MATRIX_COUNT)?,
        bytes::<Vec<Challenge>>(point_count)?,
        bytes::<Challenge>(value_count)?,
    ])?;
    let prepared = bytes::<(u32, DeviceOpening)>(MATRIX_COUNT)?;
    let readback = widths.iter().zip(points).try_fold(0usize, |n, (&w, &p)| {
        Ok::<_, String>(n.max(bytes::<Challenge>(mul(w, p)?)?))
    })?;
    let opening = sum(&[
        round_backing,
        opened,
        prepared,
        readback,
        size_of::<DeviceMatrix>(),
    ])?;
    // Reserve hiding tails before they split off. The source arrays preserve
    // their capacities; both owners therefore coexist with the finished proof.
    let hiding = sum(&[
        bytes::<Vec<Vec<Vec<Challenge>>>>(ROUND_COUNT)?,
        bytes::<Vec<Vec<Challenge>>>(MATRIX_COUNT)?,
        bytes::<Vec<Challenge>>(point_count)?,
        bytes::<Challenge>(mul(point_count, profile::NUM_RANDOM_CODEWORDS)?)?,
    ])?;
    let bridge = add(size_of::<DeviceMatrix>(), bytes::<usize>(ROUND_COUNT)?)?;
    let retained = sum(&[round_backing, opened, hiding, bridge])?;
    let path = mul(log_height.saturating_sub(profile::CAP_HEIGHT), 32)?;
    let mut initial_queries = 0;
    for (&columns, &matrices) in round_columns.iter().zip(round_matrices) {
        let fields = add(columns, mul(matrices, 4)?)?;
        let one = sum(&[
            mul(mul(2, queries)?, add(mul(fields, 8)?, path)?)?,
            bytes::<Vec<[Val; 4]>>(queries)?,
            PCS_QUERY_METADATA,
        ])?;
        initial_queries = add(initial_queries, one)?;
    }
    let mut fri_queries = 0;
    let mut caps = 0;
    for log in profile::LOG_BLOWUP..log_height {
        let query = FriData::query_host_bytes::<Challenge>(log, 2, queries)?;
        if query > FRI_ROW_QUERY_LIMIT {
            return Err("FRI row queries exceed their existing component allowance".into());
        }
        fri_queries = add(fri_queries, query)?;
        caps = add(
            caps,
            mul(3, bytes::<[Val; 4]>(1 << log.min(profile::CAP_HEIGHT))?)?,
        )?;
    }
    let assembly = sum(&[
        caps,
        mul(
            layers,
            sum(&[
                size_of::<Cap>(),
                size_of::<(FriData, usize)>(),
                size_of::<Val>(),
            ])?,
        )?,
        mul(bytes::<usize>(queries)?, add(add(1, ROUND_COUNT)?, layers)?)?,
        mul(
            queries,
            add(size_of::<Vec<Input>>(), bytes::<Input>(ROUND_COUNT)?)?,
        )?,
        mul(
            queries,
            add(size_of::<Vec<Step>>(), bytes::<Step>(layers)?)?,
        )?,
        bytes::<Query>(queries)?,
        bytes::<Challenge>(2)?,
    ])?;
    let fri = sum(&[initial_queries, fri_queries, assembly])?;
    if fri > FRI_QUERY_LIMIT {
        return Err("FRI proof construction exceeds the existing combined allowance".into());
    }
    // Concrete Arc backing is outside sizeof(FriData/DeviceOpening). Every
    // original/FRI salt recipe is conservatively charged its shared stream;
    // aliases may therefore overcount, but never grant unowned overlap credit.
    let metadata = sum(&[
        RETAINED_GPU_CODE_HOST_BYTES,
        // Source commitment arrays and their independently owned dimensions
        // survive through queries. Include the public variants as well, even
        // though preprocessing metadata also has its enclosing reservation.
        bytes::<ProverData<RowMajorMatrix<Val>>>(ROUND_COUNT)?,
        mul(
            matrix_capacity,
            sum(&[
                size_of::<Dimensions>(),
                size_of::<DeviceMatrix>().max(size_of::<PublicMatrix>()),
                size_of::<ReplaySalts>().max(size_of::<PublicSalts>()),
            ])?,
        )?,
        mul(
            add(add(MATRIX_COUNT, layers)?, 5)?,
            device::matrix_host_backing(false),
        )?,
        device::matrix_host_backing(true),
        mul(
            add(MATRIX_COUNT, layers)?,
            add(
                size_of::<ReplaySalts>(),
                device::retained_stream_host_backing(),
            )?,
        )?,
        mul(
            3 * ROUND_COUNT,
            bytes::<[Val; 4]>(1 << profile::CAP_HEIGHT)?,
        )?,
        // owned_fri::general::words(beta) constructs one exact cubic word Vec
        // for each sequential fold; it is gone before the next fold begins.
        bytes::<u64>(DEGREE)?,
        // Evaluation/reduction planners' bounded temporary Vec growth overlap:
        // 4->8 and 7->14 usize slots; these allocations retire during preflight.
        bytes::<usize>(4 + 8 + 7 + 14)?,
    ])?;
    Ok((opening.max(add(retained, fri)?), metadata))
}

#[cfg(all(
    test,
    not(debug_assertions),
    target_arch = "x86_64",
    feature = "block-v2-wide-lanes"
))]
mod tests {
    use super::*;

    fn limits() -> Limits {
        Limits {
            managed_bytes: 8 << 30,
            tile_bytes: 128 << 20,
            staging_bytes: 64 << 20,
        }
    }

    fn trees() -> Selection {
        Selection {
            mode: RetainedTreeStorageMode::HostBacking,
            host_bytes: 8 << 30,
        }
    }

    fn full(common: usize) -> OpeningBounds {
        plan(1 << 19, common, 24 << 30, limits(), usize::MAX, trees()).unwrap()
    }

    #[test]
    fn pinned_opening_graph_requires_complete_tree_and_host_allowances() {
        let bounds = full(128 << 20);
        assert!(bounds.host_bound_complete);
        assert!(bounds.required_tree_host_bytes > 6 << 30);
        assert!(bounds.host_workspace_peak_bytes > 5 << 30);
        let host = bounds.host_workspace_peak_bytes + bounds.retained_host_metadata_bytes;
        let exact_trees = Selection {
            host_bytes: bounds.required_tree_host_bytes,
            ..trees()
        };
        assert!(plan(1 << 19, 128 << 20, host, limits(), usize::MAX, exact_trees).is_ok());
        assert!(plan(
            1 << 19,
            128 << 20,
            host - 1,
            limits(),
            usize::MAX,
            exact_trees
        )
        .is_err());
        assert!(plan(
            1 << 19,
            128 << 20,
            host,
            limits(),
            usize::MAX,
            Selection {
                host_bytes: exact_trees.host_bytes - 1,
                ..exact_trees
            },
        )
        .is_err());
    }

    #[test]
    fn fixed_phase_minimum_is_distinct_from_adaptive_scheduling_ceiling() {
        let bounds = full(128 << 20);
        let minimum = Limits {
            managed_bytes: bounds.minimum_required_device_bytes,
            ..limits()
        };
        assert!(plan(1 << 19, 128 << 20, 24 << 30, minimum, usize::MAX, trees()).is_ok());
        assert!(plan(
            1 << 19,
            128 << 20,
            24 << 30,
            Limits {
                managed_bytes: minimum.managed_bytes - 1,
                ..minimum
            },
            usize::MAX,
            trees(),
        )
        .is_err());
        assert!(
            bounds.minimum_required_device_bytes
                <= bounds.query_device_peak_bytes.max(
                    bounds
                        .opening_device_peak_bytes
                        .max(bounds.fri_device_peak_bytes)
                )
        );
    }

    #[test]
    fn adaptive_query_bound_covers_smaller_actual_common_owner_sets() {
        let prefix = matrix(20, 200, Extension::Base, Val::GENERATOR.as_canonical_u64()).unwrap();
        let fixed = (472 * (1 << 20) * 8) + ((1 << 24) * 32) + (24 * ((1 << 25) - (1 << 5)));
        for upper in [0, 64 << 20, 512 << 20, 1 << 30, 1280 << 20] {
            let bounds = full(upper);
            for actual in [0, upper / 2, upper] {
                let live = fixed + actual;
                let runtime = QueryPlan::new(
                    prefix,
                    24,
                    profile::NUM_QUERIES,
                    limits().managed_bytes - live,
                    usize::MAX,
                    24 << 30,
                )
                .unwrap();
                assert!(live + runtime.workspace_bytes <= bounds.query_device_peak_bytes);
                assert!((1 << 24) * runtime.columns * 8 <= bounds.largest_allocation_bytes);
            }
        }
    }

    #[test]
    fn unsupported_geometry_modes_and_overflow_fail_closed() {
        for rows in [0, 7, 9, 1 << 20, usize::MAX] {
            assert!(plan(rows, 128 << 20, 24 << 30, limits(), usize::MAX, trees()).is_err());
        }
        assert!(plan(1 << 19, usize::MAX, 24 << 30, limits(), usize::MAX, trees()).is_err());
        assert!(plan(1 << 19, 128 << 20, 24 << 30, limits(), 0, trees()).is_err());
        assert!(plan(
            1 << 19,
            128 << 20,
            24 << 30,
            limits(),
            (1 << 30) - 1,
            trees()
        )
        .is_err());
        assert!(plan(
            1 << 19,
            128 << 20,
            24 << 30,
            limits(),
            usize::MAX,
            Selection {
                mode: RetainedTreeStorageMode::Device,
                host_bytes: 0
            },
        )
        .is_err());
    }
}
