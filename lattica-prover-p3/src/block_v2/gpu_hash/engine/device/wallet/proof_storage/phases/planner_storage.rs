//! Source-fixed backing for wallet phase planning, with a streaming report.
//! This owns only the planner's payload bound. The caller must reserve it on
//! its shared quota before construction and retain it while the Plan is live.
use super::*;
use core::mem::size_of;
use serde::{ser::SerializeMap, Serialize, Serializer};

// build() covers every power-of-two quotient partition from 2 through 32.
// The six leading phases and fourteen per partition include commit()'s phase.
// Randomness has three leading records and eight per partition, also counting
// commit(). Two opening operations plus one query operation occur per partition.
// FRI records all four possible arities plus one final/salt record, twice.
const PARTITIONS: usize = 5;
const PHASES: usize = 6 + 14 * PARTITIONS;
const QUOTIENT_TILES: usize = PARTITIONS;
const OPERATIONS: usize = 3 * PARTITIONS;
const RANDOMNESS: usize = 3 + 8 * PARTITIONS;
const FRI: usize = 2 * (4 + 1) * PARTITIONS;
const COMMITMENTS: usize = 1 + 2 * PARTITIONS;
const INPUTS: usize = 2 * PARTITIONS;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PlannerResources {
    retained_vector_bytes: usize,
    temporary_planner_bytes: usize,
    inline_owner_bytes: usize,
    failure_scratch_bytes: usize,
    required_host_bytes: usize,
}

impl PlannerResources {
    /// Pure and allocation-free on success. Neither a quota lease nor device
    /// admission is created by computing this source-owned payload bound.
    pub(crate) fn new() -> Result<Self, String> {
        if profile::MAX_QUOTIENT_CHUNKS != 32
            || profile::MAX_QUOTIENT_CHUNKS.ilog2() as usize != PARTITIONS
            || <crate::config::Challenge as crate::block_v2::pcs_field::PcsField>::MAX_LOG_ARITY > 4
            || <profile::Challenge as crate::block_v2::pcs_field::PcsField>::MAX_LOG_ARITY > 4
        {
            return Err("wallet planner capacity profile changed".into());
        }
        let retained_vector_bytes = sum(&[
            PHASES * size_of::<Phase>(),
            QUOTIENT_TILES * size_of::<QuotientTile>(),
            OPERATIONS * size_of::<operations::OperationPlan>(),
            RANDOMNESS * size_of::<randomness::RandomnessPlan>(),
            FRI * size_of::<fri::FriPlan>(),
            COMMITMENTS * size_of::<commitments::CommitmentPlan>(),
            INPUTS * size_of::<inputs::InputPlan>(),
        ])?;
        // LdeCommitPlan retains one exact input and prefix Vec, at most 32
        // elements each. Opening evaluation grows 4 -> 8 usize slots and
        // reduction grows 7 -> 14; include old/new backing together, and add
        // both planners although their scratch is sequential in build().
        let temporary_planner_bytes = sum(&[
            32 * (size_of::<InputShape>() + size_of::<usize>()),
            (4 + 8 + 7 + 14) * size_of::<usize>(),
            size_of::<LdeCommitPlan>(),
        ])?;
        let inline_owner_bytes = sum(&[
            size_of::<Plan>(),
            size_of::<Self>(),
            size_of::<StreamReport<'static>>(),
        ])?;
        // Failure diagnostics contain fixed labels and scalar decimal fields;
        // no caller-controlled text is formatted by these planners. This is
        // independent of the receiving writer's own storage policy.
        let failure_scratch_bytes = 4096;
        let required_host_bytes = sum(&[
            retained_vector_bytes,
            temporary_planner_bytes,
            inline_owner_bytes,
            failure_scratch_bytes,
        ])?;
        Ok(Self {
            retained_vector_bytes,
            temporary_planner_bytes,
            inline_owner_bytes,
            failure_scratch_bytes,
            required_host_bytes,
        })
    }

    pub(crate) fn required_host_bytes(self) -> usize {
        self.required_host_bytes
    }
}

fn exact<T>(count: usize) -> Result<Vec<T>, String> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| "wallet planner backing allocation failed".to_string())?;
    Ok(values)
}

impl Plan {
    /// The caller holds `preclaimed_host_bytes` on its cumulative quota before
    /// this call and through Plan destruction. All capacities are source-fixed;
    /// the allowance is checked before the first backing allocation. This path
    /// does not initialize the engine or authorize proof dispatch.
    pub(crate) fn from_geometry_bounded(
        g: WalletProofMinimum,
        runtime: RuntimeGeometry,
        preclaimed_host_bytes: usize,
    ) -> Result<Self, String> {
        let storage = PlannerResources::new()?;
        if storage.required_host_bytes > preclaimed_host_bytes {
            return Err("wallet planner host preclaim is insufficient".into());
        }
        let mut plan = Self {
            phases: exact(PHASES)?,
            quotient_tiles: exact(QUOTIENT_TILES)?,
            operations: exact(OPERATIONS)?,
            randomness: exact(RANDOMNESS)?,
            fri: exact(FRI)?,
            commitments: exact(COMMITMENTS)?,
            inputs: exact(INPUTS)?,
            ceiling: runtime.limits.managed_bytes,
            max_allocation: runtime.max_allocation,
            baseline: runtime.baseline,
            initial_hash: runtime.initial_hash,
            initial_lde: runtime.initial_lde,
        };
        plan.build(
            g,
            runtime.limits,
            runtime.transfer_slots,
            runtime.lde_cache_limit,
            runtime.needs_query_buffer,
        )?;
        Ok(plan)
    }

    /// Same metadata as report(), serialized directly from borrowed records.
    /// No Value tree, temporary Vec or JSON String is constructed. The caller
    /// is responsible for any buffering performed by its selected writer.
    pub(crate) fn write_report(&self, mut writer: impl std::io::Write) -> std::io::Result<()> {
        writer.write_all(b"bounded_wallet_phase_admission ")?;
        serde_json::to_writer(&mut writer, &StreamReport(self))?;
        writer.write_all(b"\n")
    }
}

macro_rules! fields {
    ($serializer:expr; $($key:literal => $value:expr),+ $(,)?) => {{
        let mut map = $serializer.serialize_map(Some([$($key),+].len()))?;
        $(map.serialize_entry($key, &$value)?;)+
        map.end()
    }};
}

struct StreamReport<'a>(&'a Plan);
impl Serialize for StreamReport<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let p = self.0;
        fields!(serializer;
            "schema" => "lattica-wallet-device-phase-v9",
            "managed_ceiling_bytes" => p.ceiling,
            "max_allocation_bytes" => p.max_allocation,
            "baseline_bytes" => p.baseline,
            "initial_hash_workspace_bytes" => p.initial_hash,
            "initial_lde_workspace_bytes" => p.initial_lde,
            "adaptive_lde_tiles" => true,
            "host_lifetime_admitted" => false,
            "recorded_program_tile_admission" => true,
            "exact_compiled_registers" => false,
            "opening_query_operation_admission" => true,
            "retained_periodic_source_admission" => true,
            "periodic_source_construction_admission" => true,
            "randomness_storage_admission" => true,
            "randomness_complete_stream_admission" => false,
            "fri_operation_admission" => true,
            "fri_single_input_height" => true,
            "commitment_input_storage_admission" => true,
            "quotient_input_operation_admission" => true,
            "quotient_input_plans" => p.inputs,
            "commitment_input_plans" => p.commitments,
            "fri_operation_plans" => p.fri,
            "randomness_plans" => p.randomness,
            "operation_plans" => p.operations,
            "quotient_tiles" => p.quotient_tiles,
            "phases" => p.phases,
        )
    }
}

impl Serialize for Phase {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "name" => self.name, "quotient_chunks" => self.chunks, "managed_bytes" => self.bytes)
    }
}
impl Serialize for QuotientTile {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "quotient_chunks" => self.chunks, "rows_at_bound" => self.rows,
            "managed_bytes_at_bound" => self.peak, "row_bytes_bound" => self.row_bytes)
    }
}
impl Serialize for inputs::InputPlan {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "name" => self.name, "quotient_chunks" => self.chunks,
            "managed_bytes_at_bound" => self.peak, "max_allocation_bytes" => self.largest,
            "coset_rows" => self.coset_rows, "cosets" => self.cosets)
    }
}
impl Serialize for commitments::CommitmentPlan {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "name" => self.name, "quotient_chunks" => self.chunks,
            "managed_bytes_at_bound" => self.storage.peak_bytes,
            "allocation_bytes" => self.storage.allocation_bytes,
            "sample_bytes" => self.storage.sample_bytes, "pending_bytes" => self.storage.pending_bytes,
            "samples_already_resident" => (self.storage.location == SampleLocation::Resident))
    }
}
impl Serialize for operations::OperationPlan {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "name" => self.name, "quotient_chunks" => self.chunks,
            "tile_rows_at_bound" => self.rows, "tile_columns_at_bound" => self.columns,
            "managed_bytes_at_bound" => self.peak, "host_buffer_bytes_at_bound" => self.host_buffer_bytes,
            "query_count" => self.query_count)
    }
}
impl Serialize for fri::FriPlan {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "name" => self.name, "quotient_chunks" => self.chunks,
            "log_arity" => self.log_arity, "query_count" => self.query_count,
            "managed_bytes_at_bound" => self.storage.peak_bytes,
            "max_allocation_bytes" => self.storage.max_allocation_bytes,
            "host_output_bytes_at_bound" => self.storage.host_output_bytes,
            "host_temporary_bytes_at_bound" => self.storage.host_temporary_bytes)
    }
}
impl Serialize for randomness::RandomnessPlan {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        fields!(s; "name" => self.name, "quotient_chunks" => self.chunks,
            "requests" => self.storage.requests, "retain_outputs" => self.retain_outputs,
            "largest_request_words" => self.storage.largest_request_words,
            "retained_output_bytes" => self.storage.retained_output_bytes,
            "managed_bytes_at_bound" => self.storage.peak_bytes,
            "max_allocation_bytes" => self.storage.max_allocation_bytes,
            "minimum_stream_words_from_fresh" => self.storage.minimum_end_position)
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::*;

    fn runtime() -> RuntimeGeometry {
        RuntimeGeometry::fresh(Limits::default(), 4 << 30, 1, 0).unwrap()
    }

    #[test]
    fn insufficient_preclaim_rejects_before_program_planning() {
        // Deliberately missing recorded program. The resource failure must win
        // before any vector is reserved or the program geometry is inspected.
        let g = WalletProofMinimum::new(4096, 19, 0, Extension::Quadratic).unwrap();
        let bytes = PlannerResources::new().unwrap().required_host_bytes();
        let error = Plan::from_geometry_bounded(g, runtime(), bytes - 1).unwrap_err();
        assert_eq!(error, "wallet planner host preclaim is insufficient");
    }

    #[test]
    fn fixed_capacities_cover_all_partitions_and_preserve_report_values() {
        for extension in [Extension::Quadratic, Extension::Cubic] {
            let g = crate::block_v2::gpu_quotient_prover::uni::Prepared::new(
                &crate::joinsplit_air::JoinSplitAir,
                4096,
                extension,
                1 << 30,
            )
            .unwrap()
            .minimum()
            .unwrap();
            let storage = PlannerResources::new().unwrap();
            let p =
                Plan::from_geometry_bounded(g, runtime(), storage.required_host_bytes()).unwrap();
            // Capacity equality catches hidden growth, not just retained len.
            assert_eq!((p.phases.len(), p.phases.capacity()), (PHASES, PHASES));
            assert_eq!(
                (p.quotient_tiles.len(), p.quotient_tiles.capacity()),
                (QUOTIENT_TILES, QUOTIENT_TILES)
            );
            assert_eq!(
                (p.operations.len(), p.operations.capacity()),
                (OPERATIONS, OPERATIONS)
            );
            assert_eq!(
                (p.randomness.len(), p.randomness.capacity()),
                (RANDOMNESS, RANDOMNESS)
            );
            assert_eq!(p.fri.capacity(), FRI);
            assert!(p.fri.len() <= FRI);
            assert_eq!(
                (p.commitments.len(), p.commitments.capacity()),
                (COMMITMENTS, COMMITMENTS)
            );
            assert_eq!((p.inputs.len(), p.inputs.capacity()), (INPUTS, INPUTS));

            let mut output = Vec::new();
            p.write_report(&mut output).unwrap();
            let prefix = b"bounded_wallet_phase_admission ";
            assert!(output.starts_with(prefix) && output.ends_with(b"\n"));
            let report: serde_json::Value =
                serde_json::from_slice(&output[prefix.len()..]).unwrap();
            assert_eq!(report["schema"], "lattica-wallet-device-phase-v9");
            assert_eq!(report["host_lifetime_admitted"], false);
            assert_eq!(report["managed_ceiling_bytes"], p.ceiling);
            assert_eq!(
                report["quotient_input_plans"],
                serde_json::json!(p.inputs.iter().map(|x| x.report()).collect::<Vec<_>>())
            );
            assert_eq!(
                report["commitment_input_plans"],
                serde_json::json!(p.commitments.iter().map(|x| x.report()).collect::<Vec<_>>())
            );
            assert_eq!(
                report["fri_operation_plans"],
                serde_json::json!(p.fri.iter().map(|x| x.report()).collect::<Vec<_>>())
            );
            assert_eq!(
                report["randomness_plans"],
                serde_json::json!(p.randomness.iter().map(|x| x.report()).collect::<Vec<_>>())
            );
            assert_eq!(
                report["operation_plans"],
                serde_json::json!(p.operations.iter().map(|x| x.report()).collect::<Vec<_>>())
            );
        }
    }
}
