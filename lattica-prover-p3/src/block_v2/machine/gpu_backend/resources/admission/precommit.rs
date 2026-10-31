//! Complete device ownership through the five initial commitments. Bounds are
//! for the pinned wide universal AIR and a consumed registration. Adaptive LDE
//! tiles have separate minimum feasibility and enforced scheduling ceilings.
use super::*;
use crate::block_v2::{
    gpu_hash::engine::{
        self,
        device::PartitionStorage,
        lde_plan::{device_minimum, InputShape},
        Limits,
    },
    lookup_program::{MAX_LOOKUPS, MAX_TUPLES},
    quotient_program::{
        ProgramShape, MAX_CONSTRAINTS, MAX_NODES, MAX_ROW_WORDS, WORDS_PER_INSTRUCTION,
    },
};
use crate::gpu_matrix::{Extension, MatrixSpec, RowOrder};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(super) struct PrecommitBounds {
    pub common_device_bytes: usize,
    pub compiler_device_peak_bytes: usize,
    pub preprocessing_device_peak_bytes: usize,
    pub witness_device_peak_bytes: usize,
    pub main_commit_device_peak_bytes: usize,
    pub lookup_reconstruction_device_peak_bytes: usize,
    pub lookup_device_peak_bytes: usize,
    pub permutation_commit_device_peak_bytes: usize,
    pub quotient_evaluation_device_peak_bytes: usize,
    pub quotient_commit_device_peak_bytes: usize,
    pub randomization_commit_device_peak_bytes: usize,
    pub minimum_required_device_bytes: usize,
    pub largest_allocation_bytes: usize,
    pub peak_device_bytes: usize,
}

fn sum(values: &[usize]) -> Result<usize, String> {
    values.iter().try_fold(0usize, |sum, value| {
        sum.checked_add(*value)
            .ok_or_else(|| "registered phase sum overflow".into())
    })
}
fn bytes(rows: usize, columns: usize) -> Result<usize, String> {
    rows.checked_mul(columns)
        .and_then(|n| n.checked_mul(8))
        .ok_or_else(|| "registered phase matrix overflow".into())
}

struct Census {
    limits: Limits,
    max_alloc: usize,
    slots: usize,
    transform_allowance: usize,
    trees: Selection,
    minimum: usize,
    largest: usize,
}

impl Census {
    fn fixed(&mut self, live: usize, largest: usize) -> Result<usize, String> {
        if live > self.limits.managed_bytes || largest > self.max_alloc {
            return Err("registered fixed proving phase exceeds device allowance".into());
        }
        self.minimum = self.minimum.max(live);
        self.largest = self.largest.max(largest);
        Ok(live)
    }

    fn sampled(
        &mut self,
        counts: &[usize],
        pending: &[usize],
        live: usize,
    ) -> Result<usize, String> {
        let plan = crate::gpu_random::FieldStoragePlan::new(
            counts.iter().copied(),
            pending,
            true,
            0,
            live,
            self.limits.managed_bytes,
            self.max_alloc,
        )?;
        self.fixed(plan.peak_bytes, plan.max_allocation_bytes)
    }

    fn lde(
        &mut self,
        inputs: &[InputShape],
        live: usize,
        capture_bytes: &[usize],
    ) -> Result<usize, String> {
        let minimum = device_minimum(
            inputs,
            crate::block_v2::profile::CAP_HEIGHT,
            self.limits,
            self.max_alloc,
            self.slots,
            live,
            self.transform_allowance,
            self.trees.mode,
        )?;
        self.minimum = self.minimum.max(minimum.minimum_peak_bytes);
        self.largest = self.largest.max(minimum.largest_allocation_bytes);
        for &capture in capture_bytes {
            if capture > self.max_alloc {
                return Err("registered retained prefix exceeds physical allocation cap".into());
            }
            self.largest = self.largest.max(capture);
        }
        // Actual live code can be smaller than its conservative census, which
        // permits larger runtime tiles. Bound those against the same physical,
        // scratch and aggregate limits; never label a one-column floor a peak.
        let per_column = minimum.transform_buffer_bytes;
        let max_width = inputs.iter().map(|shape| shape.width).max().unwrap();
        let possible = max_width
            .min(self.max_alloc / per_column)
            .min(self.limits.managed_bytes / 2 / per_column)
            .min(self.transform_allowance / 2 / per_column);
        if possible == 0 {
            return Err("registered LDE has no admissible complete column".into());
        }
        let tile = per_column * (1usize << possible.ilog2());
        self.largest = self.largest.max(tile);
        // Runtime's shared LDE planner and Allocation leases enforce this
        // ceiling for every selected tile. Minimum feasibility was established
        // above with every simultaneous retained owner already included.
        Ok(self.limits.managed_bytes)
    }
}

pub(super) fn plan(
    bounds: &Bounds,
    public_values: usize,
    trees: Selection,
    limits: Limits,
    max_alloc: usize,
    slots: usize,
    transform_allowance: usize,
) -> Result<PrecommitBounds, String> {
    use crate::block_v2::gpu_hash::device::{
        public_hash, PERIODIC_MAX_ALLOCATION_BYTES, PERIODIC_WORKSPACE_BYTES,
    };
    use crate::gpu_hiding::{QuotientCommitShape, TraceCommitShape};
    if crate::block_v2::machine::program::MAX_PUBLIC_VALUES != 64
        || public_values > crate::block_v2::machine::program::MAX_PUBLIC_VALUES
        || 4 * 23 + public_values > MAX_TUPLES
        || bounds.main_columns != 94
        || bounds.preprocessing_columns != 200
        || crate::block_v2::profile::LOG_BLOWUP != 4
        || crate::block_v2::profile::NUM_RANDOM_CODEWORDS != 4
        || trees.mode != RetainedTreeStorageMode::HostBacking
    {
        return Err(
            "complete registered phase plan requires the pinned wide host-tree profile".into(),
        );
    }
    let h = usize::try_from(bounds.rows).map_err(|_| "registered row count overflow")?;
    let prefix_rows = h
        .checked_mul(2)
        .ok_or("registered prefix height overflow")?;
    let lde_rows = prefix_rows
        .checked_mul(16)
        .ok_or("registered LDE height overflow")?;
    let pp_prefix = bytes(prefix_rows, 200)?;
    let main_prefix = bytes(prefix_rows, 98)?;
    let perm_prefix = bytes(prefix_rows, 55)?;
    let salts = bytes(lde_rows, 4)?;
    let replay = crate::gpu_random::salt_replay_workspace_bytes(lde_rows * 4)?;
    let witness = bounds.reservation_with_tree_storage(1, trees)?;
    let lookup_code = bytes(
        (MAX_NODES + MAX_ROW_WORDS) * WORDS_PER_INSTRUCTION + MAX_TUPLES * 3 + MAX_LOOKUPS + 1,
        1,
    )?;
    let quotient_code = bytes((MAX_NODES + MAX_CONSTRAINTS) * WORDS_PER_INSTRUCTION, 1)?;
    // Both bounded code owners are conservatively retained through every
    // phase. Five keys are the existing randomness reservation's fixed count.
    // Compiler constants/periodic scratch retire per operation, but retaining
    // their maximum throughout avoids taking any overlap credit here.
    let common = sum(&[
        engine::retained_query_base_bytes(limits)?,
        lookup_code,
        quotient_code,
        crate::block_v2::challenger::resources::reservation().managed_bytes as usize,
        5 * 32,
        public_hash::WORKSPACE_BYTES.max(PERIODIC_WORKSPACE_BYTES) as usize,
    ])?;
    let mut census = Census {
        limits,
        max_alloc,
        slots,
        transform_allowance,
        trees,
        minimum: 0,
        largest: 0,
    };
    let common_largest = [
        bytes((MAX_NODES + MAX_ROW_WORDS) * WORDS_PER_INSTRUCTION, 1)?,
        bytes(MAX_TUPLES * 3, 1)?,
        bytes(MAX_LOOKUPS + 1, 1)?,
        quotient_code,
        crate::block_v2::challenger::resources::reservation().max_allocation_bytes as usize,
        public_hash::MAX_ALLOCATION_BYTES as usize,
        PERIODIC_MAX_ALLOCATION_BYTES as usize,
        limits.staging_bytes / slots,
        32,
    ]
    .into_iter()
    .max()
    .unwrap();
    census.fixed(common, common_largest)?;
    let instructions =
        usize::try_from(bounds.metadata_bytes).map_err(|_| "witness instruction byte overflow")?;
    let compiler = census.fixed(
        sum(&[common, witness.managed_bytes as usize])?,
        witness.max_allocation_bytes as usize,
    )?;
    let pp_raw = bytes(h, 200)?;
    let pp_before_salts = sum(&[common, instructions, pp_raw, 8])?;
    let pp_sample = census.sampled(&[lde_rows * 4], &[], pp_before_salts)?;
    let pp_live = sum(&[pp_before_salts, salts, pp_prefix])?;
    let preprocessing = census
        .lde(
            &[InputShape {
                height: prefix_rows,
                width: 200,
                added_bits: 4,
            }],
            pp_live,
            &[pp_prefix],
        )?
        .max(pp_sample);
    let witness_peak = census.fixed(
        sum(&[common, witness.managed_bytes as usize, pp_prefix, salts])?,
        witness.max_allocation_bytes as usize,
    )?;

    let mut hidden = |width: usize,
                      columns: usize,
                      extension: Extension,
                      prior: usize,
                      census: &mut Census|
     -> Result<usize, String> {
        let spec = MatrixSpec::new(h.ilog2(), columns, extension, RowOrder::Natural, 1)?;
        let shape = TraceCommitShape::new(spec, 4)?;
        if shape.width != width {
            return Err("registered hidden trace geometry mismatch".into());
        }
        let before = sum(&[common, prior, salts, spec.bytes()])?;
        let sampling = census.sampled(&[shape.random_words], &[8], before)?;
        let live = sum(&[
            before,
            shape.random_words * 8,
            8,
            bytes(prefix_rows, width)?,
            replay,
        ])?;
        Ok(census
            .lde(
                &[InputShape {
                    height: shape.height,
                    width,
                    added_bits: 4,
                }],
                live,
                &[bytes(prefix_rows, width)?],
            )?
            .max(sampling))
    };
    // Consuming registration drops PreparedWitness after its completed trace
    // and before prove_batch. There are no instruction/schedule owners here.
    let main_commit = hidden(98, 94, Extension::Base, pp_prefix, &mut census)?;

    let lookup_retained = sum(&[common, pp_prefix, main_prefix, salts])?;
    let main_projected =
        MatrixSpec::new(h.ilog2() + 1, 94, Extension::Base, RowOrder::BitReversed, 7)?;
    let pp_projected = MatrixSpec::new(
        h.ilog2() + 1,
        200,
        Extension::Base,
        RowOrder::BitReversed,
        7,
    )?;
    // original_trace projects hidden columns before two-buffer interpolation.
    // Main's recovered h-row output remains live during PP interpolation; PP
    // itself aliases its original prefix because it has no random columns.
    let main_recovery = engine::device::transform_storage_plan(
        main_projected,
        h.ilog2() + 1,
        sum(&[lookup_retained, main_projected.bytes()])?,
        limits,
        max_alloc,
    )?;
    let pp_recovery = engine::device::transform_storage_plan(
        pp_projected,
        h.ilog2() + 1,
        sum(&[lookup_retained, bytes(h, 94)?])?,
        limits,
        max_alloc,
    )?;
    let lookup_reconstruction = census.fixed(
        main_recovery.peak_bytes.max(pp_recovery.peak_bytes),
        main_projected.bytes().max(pp_projected.bytes()),
    )?;
    let before_lookup = sum(&[lookup_retained, bytes(h, 94)?, pp_raw])?;
    let mut scan_rows = h;
    let mut scan_bytes = 0usize;
    loop {
        scan_bytes = sum(&[scan_bytes, bytes(scan_rows, 3)?])?;
        if scan_rows <= 128 {
            break;
        }
        scan_rows = scan_rows.div_ceil(128);
    }
    // Shared lookup Plan bounds all four expression buffers by64MiB and a
    // single row by the public compiler maxima. Four one-word empty buffers
    // are included conservatively even though this pinned AIR has tuples.
    // Source-order degree-eight packing has fifteen full groups of six private
    // degree-one tuples and one group with the final two private tuples. Public
    // tuples have degree zero, so all 0..=64 publics fit that final group. The
    // permutation/challenge geometry stays fixed; only this upload grows.
    let public_upload = bytes(public_values.max(1), 1)?;
    let challenge_upload = bytes(16 * 2 * 3, 1)?;
    let lookup_parameters = sum(&[public_upload, challenge_upload])?;
    let lookup_parameter_allocation = public_upload.max(challenge_upload);
    let lookup_fixed = sum(&[
        before_lookup,
        bytes(h, 51)?,
        scan_bytes,
        lookup_parameters,
        3 * 8,
        8,
    ])?;
    let lookup_row = bytes(
        2 * (94 + 200) + MAX_NODES + MAX_ROW_WORDS + MAX_TUPLES * 3,
        1,
    )?;
    if lookup_row > limits.tile_bytes.min(64 << 20).min(max_alloc) {
        return Err("registered lookup compiler maximum cannot fit one expression row".into());
    }
    census.fixed(
        sum(&[lookup_fixed, lookup_row])?,
        bytes(h, 51)?
            .max(lookup_row)
            .max(lookup_parameter_allocation),
    )?;
    let lookup = census.fixed(
        sum(&[lookup_fixed, limits.tile_bytes.min(64 << 20), 32])?,
        bytes(h, 51)?
            .max(limits.tile_bytes.min(64 << 20).min(max_alloc))
            .max(lookup_parameter_allocation),
    )?;
    let permutation_commit = hidden(
        55,
        17,
        Extension::Cubic,
        pp_prefix + main_prefix,
        &mut census,
    )?;

    let original = sum(&[pp_prefix, main_prefix, perm_prefix])?;
    let quotient_live = sum(&[common, original, salts, bytes(prefix_rows, 94 + 51)?])?;
    let quotient_shape = ProgramShape {
        extension: Extension::Cubic,
        instruction_words: (MAX_NODES + MAX_CONSTRAINTS) * WORDS_PER_INSTRUCTION,
        registers: MAX_NODES,
        constraints: MAX_CONSTRAINTS,
        row_words: 2 * (94 + 200 + 51),
        parameter_words: MAX_ROW_WORDS,
    };
    let inputs = [
        MatrixSpec::new(h.ilog2() + 1, 94, Extension::Base, RowOrder::BitReversed, 7)?,
        MatrixSpec::new(
            h.ilog2() + 1,
            200,
            Extension::Base,
            RowOrder::BitReversed,
            7,
        )?,
        MatrixSpec::new(
            h.ilog2() + 1,
            17,
            Extension::Cubic,
            RowOrder::BitReversed,
            7,
        )?,
    ];
    let quotient = PartitionStorage::new(
        &inputs,
        h.ilog2(),
        h.ilog2() + 4,
        7,
        quotient_shape,
        quotient_live,
        0,
        limits,
        max_alloc,
    )?;
    census.fixed(quotient.peak_bytes, quotient.max_allocation_bytes)?;
    // The evaluator's64MiB workspace includes parameters and tile buffers.
    let evaluation_upper = sum(&[
        quotient_live,
        quotient.output.bytes(),
        bytes(prefix_rows, 94 + 200 + 51)?,
        bytes(prefix_rows, 3)?,
        64 << 20,
    ])?;
    let quotient_evaluation = census.fixed(
        quotient.expansion_peak_bytes.max(evaluation_upper),
        quotient.max_allocation_bytes.max(64 << 20),
    )?;

    // Projected quotient input copies have left scope before commitment.
    let shape = QuotientCommitShape::new(quotient.output, 16, 4)?;
    if shape.height != h || shape.width != 7 {
        return Err("registered quotient commitment geometry mismatch".into());
    }
    let before = sum(&[common, original, salts, quotient.output.bytes()])?;
    let sample = census.sampled(
        &[shape.random_words, shape.mask_words],
        &[shape.allocation_words()[2] * 8],
        before,
    )?;
    let quotient_prefix = bytes(prefix_rows, 16 * 7)?;
    let live = sum(&[before, shape.bytes()?, quotient_prefix, replay])?;
    let quotient_commit = census
        .lde(
            &[InputShape {
                height: h,
                width: 7,
                added_bits: 5,
            }; 16],
            live,
            &[bytes(prefix_rows, 7)?],
        )?
        .max(sample);
    let random_before = sum(&[common, original, salts, quotient_prefix])?;
    let random_words = prefix_rows * 7;
    let random_sample = census.sampled(&[random_words], &[16], random_before)?;
    let random_live = sum(&[
        random_before,
        random_words * 8,
        16,
        random_words * 8,
        replay,
    ])?;
    let randomization_commit = census
        .lde(
            &[InputShape {
                height: prefix_rows,
                width: 7,
                added_bits: 4,
            }],
            random_live,
            &[random_words * 8],
        )?
        .max(random_sample);
    let peak = [
        compiler,
        preprocessing,
        witness_peak,
        main_commit,
        lookup_reconstruction,
        lookup,
        permutation_commit,
        quotient_evaluation,
        quotient_commit,
        randomization_commit,
    ]
    .into_iter()
    .max()
    .unwrap();
    if census.largest > max_alloc {
        return Err("registered proving allocation bound exceeds selected hardware".into());
    }
    Ok(PrecommitBounds {
        common_device_bytes: common,
        compiler_device_peak_bytes: compiler,
        preprocessing_device_peak_bytes: preprocessing,
        witness_device_peak_bytes: witness_peak,
        main_commit_device_peak_bytes: main_commit,
        lookup_reconstruction_device_peak_bytes: lookup_reconstruction,
        lookup_device_peak_bytes: lookup,
        permutation_commit_device_peak_bytes: permutation_commit,
        quotient_evaluation_device_peak_bytes: quotient_evaluation,
        quotient_commit_device_peak_bytes: quotient_commit,
        randomization_commit_device_peak_bytes: randomization_commit,
        minimum_required_device_bytes: census.minimum,
        largest_allocation_bytes: census.largest,
        peak_device_bytes: peak,
    })
}

#[cfg(all(test, feature = "stream"))]
mod tests {
    use super::*;

    fn measured_wide_source() -> Bounds {
        // Immutable source-only census from fullgpu-wide-memory-diagnostic-1.
        // This does not create a Program, admission token, or GPU context.
        Bounds {
            rows: 524288,
            main_columns: 94,
            preprocessing_columns: 200,
            metadata_bytes: 1490536800,
            compiler_host_bytes: 1776288448,
            compiler_retained_host_bytes: 118419200,
            pcs_retained_host_bytes: 0,
            program_host_bytes: 1263185448,
            program_retained_host_bytes: 656454136,
            wires: 6114044,
            input_values: 59826,
        }
    }

    fn trees() -> Selection {
        Selection {
            mode: RetainedTreeStorageMode::HostBacking,
            host_bytes: 8 << 30,
        }
    }

    #[test]
    fn full_wide_source_has_complete_precommit_feasibility_inside_original_limits() {
        let source = measured_wide_source();
        let limits = Limits::default();
        let physical = 4_175_986_688;
        let result = plan(&source, 4, trees(), limits, physical, 1, usize::MAX).unwrap();
        assert_eq!(result.peak_device_bytes, limits.managed_bytes);
        assert!(result.minimum_required_device_bytes < result.peak_device_bytes);
        assert!(result.largest_allocation_bytes <= physical);
        assert!(result.lookup_reconstruction_device_peak_bytes > result.lookup_device_peak_bytes);
        assert!(
            result.quotient_evaluation_device_peak_bytes
                > result.lookup_reconstruction_device_peak_bytes
        );
        assert!(plan(
            &source,
            4,
            trees(),
            Limits {
                managed_bytes: result.minimum_required_device_bytes - 1,
                ..limits
            },
            physical,
            1,
            usize::MAX
        )
        .is_err());
        assert!(plan(
            &source,
            4,
            trees(),
            limits,
            2 * 524288 * 200 * 8 - 1,
            1,
            usize::MAX
        )
        .is_err());
    }

    #[test]
    fn public_upload_growth_preserves_the_wide_commitment_geometry() {
        let source = measured_wide_source();
        let limits = Limits::default();
        let physical = 4_175_986_688;
        let direct = plan(&source, 4, trees(), limits, physical, 1, usize::MAX).unwrap();
        let pair = plan(&source, 46, trees(), limits, physical, 1, usize::MAX).unwrap();
        let largest_public = plan(&source, 64, trees(), limits, physical, 1, usize::MAX).unwrap();
        assert_eq!(
            pair.lookup_device_peak_bytes - direct.lookup_device_peak_bytes,
            336
        );
        assert_eq!(
            largest_public.lookup_device_peak_bytes - direct.lookup_device_peak_bytes,
            480
        );
        // The only added owner in this device census is the exact public upload.
        // Source/compiler host backing remains derived separately from Program.
        let normalized = PrecommitBounds {
            lookup_device_peak_bytes: direct.lookup_device_peak_bytes,
            ..pair
        };
        assert_eq!(normalized, direct);
        assert!(plan(&source, 65, trees(), limits, physical, 1, usize::MAX).is_err());
    }

    #[test]
    fn four_public_phases_match_the_audited_pre_refactor_diagnostic() {
        // fullgpu-complete-memory-diagnostic-1, captured by the coordinator
        // before this P-derived refactor. Full JSON SHA256:
        // c91d12b47975f367e82c2b75eac2425c17485e7deaff70beff4610ebd6510897.
        // This is a numerical regression fixture, not a new proof receipt.
        let actual = plan(
            &measured_wide_source(),
            4,
            trees(),
            Limits::default(),
            4_175_986_688,
            1,
            usize::MAX,
        )
        .unwrap();
        let expected = PrecommitBounds {
            common_device_bytes: 94_935_280,
            compiler_device_peak_bytes: 2_425_119_336,
            preprocessing_device_peak_bytes: 8_589_934_592,
            witness_device_peak_bytes: 4_639_711_848,
            main_commit_device_peak_bytes: 8_589_934_592,
            lookup_reconstruction_device_peak_bytes: 6_881_319_488,
            lookup_device_peak_bytes: 4_658_437_968,
            permutation_commit_device_peak_bytes: 8_589_934_592,
            quotient_evaluation_device_peak_bytes: 8_366_103_104,
            quotient_commit_device_peak_bytes: 8_589_934_592,
            randomization_commit_device_peak_bytes: 8_589_934_592,
            minimum_required_device_bytes: 8_403_918_872,
            largest_allocation_bytes: 2_147_483_648,
            peak_device_bytes: 8_589_934_592,
        };
        assert_eq!(actual, expected);
    }

    #[test]
    fn a_device_tree_or_changed_wide_profile_is_never_admitted_by_host_schedule() {
        let mut source = measured_wide_source();
        let device = Selection {
            mode: RetainedTreeStorageMode::Device,
            host_bytes: 0,
        };
        assert!(plan(
            &source,
            4,
            device,
            Limits::default(),
            4_175_986_688,
            1,
            usize::MAX
        )
        .is_err());
        source.main_columns -= 1;
        assert!(plan(
            &source,
            4,
            trees(),
            Limits::default(),
            4_175_986_688,
            1,
            usize::MAX
        )
        .is_err());
    }
}
