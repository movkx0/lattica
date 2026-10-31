//! Additional live owners for native device-tree opening. Keep all original
//! and future FRI trees plus the largest standard hash workspace charged for
//! the whole phase; no early-release or host-offload credit is taken.
use super::{add, mul, Limits};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Additional {
    pub live_bytes: usize,
    pub largest_allocation: usize,
    pub retained_tree_bytes: usize,
    pub hash_workspace_bytes: usize,
}

fn tree_bytes(height: usize) -> Result<usize, String> {
    mul(
        mul(height, 2)?
            .checked_sub(1)
            .ok_or("native tree geometry")?,
        32,
    )
}

impl Additional {
    pub(super) fn new(
        height: usize,
        limits: Limits,
        max_allocation: usize,
    ) -> Result<Self, String> {
        if !height.is_power_of_two()
            || !(1 << 17..=1 << 25).contains(&height)
            || max_allocation == 0
        {
            return Err("native device opening tree geometry".into());
        }
        let original_tree = tree_bytes(height)?;
        let mut retained_tree_bytes = mul(3, original_tree)?;
        let mut next = height;
        while next > 1 << super::profile::LOG_BLOWUP {
            next /= 2;
            retained_tree_bytes = add(retained_tree_bytes, tree_bytes(next)?)?;
        }
        // Default engine::plan_slots retains up to the entire input tile pool,
        // height*4 leaf words and max(height/2,1)*4 parent words. The latest
        // original commitment is no smaller than any FRI hash. Replacements
        // drop old backing first; keeping this maximum throughout also covers
        // a fitting larger old workspace retained by commit_plan.
        let leaves = mul(height, 32)?;
        let parents = mul((height / 2).max(1), 32)?;
        let hash_workspace_bytes = add(limits.tile_bytes, add(leaves, parents)?)?;
        let largest_allocation = original_tree
            .max(limits.tile_bytes)
            .max(leaves)
            .max(parents);
        let live_bytes = add(retained_tree_bytes, hash_workspace_bytes)?;
        if largest_allocation > max_allocation || live_bytes > limits.managed_bytes {
            return Err("native device opening retained trees exceed selected limits".into());
        }
        Ok(Self {
            live_bytes,
            largest_allocation,
            retained_tree_bytes,
            hash_workspace_bytes,
        })
    }
}

#[cfg(all(
    test,
    not(debug_assertions),
    feature = "block-v2-wide-lanes",
    feature = "stream"
))]
mod tests {
    use super::super::{native_plan, plan, RetainedTreeStorageMode, Selection};
    use super::*;

    fn limits() -> Limits {
        Limits {
            managed_bytes: 8 << 30,
            tile_bytes: 128 << 20,
            staging_bytes: 64 << 20,
        }
    }
    fn device() -> Selection {
        Selection {
            mode: RetainedTreeStorageMode::Device,
            host_bytes: 0,
        }
    }
    fn host() -> Selection {
        Selection {
            mode: RetainedTreeStorageMode::HostBacking,
            host_bytes: 8 << 30,
        }
    }

    // Each of 34 matrices calls evaluation and reduction twice. Their
    // halving loops use at most log2(start)+1 attempts, with two Vec requests
    // (4->8 or 7->14 usize slots) and at most one fixed diagnostic per attempt.
    // This is a cumulative request ceiling, stronger than retained scratch.
    // The ordinary maintained planner partition already covers the sequential
    // Vec scratch plus4096-byte failure storage; this full call also fits that
    // original preparation's conservative legacy-planner allocation partition.
    fn opening_planner_request_bound(rows: usize) -> (usize, usize) {
        assert!(rows.is_power_of_two() && (4096..=1 << 20).contains(&rows));
        let prefix = 2 * rows;
        let height = prefix << super::super::profile::LOG_BLOWUP;
        let evaluation_attempts = prefix.min(65536).ilog2() as usize + 1;
        let reduction_attempts = height.min(1 << 20).ilog2() as usize + 1;
        let per_kind = 2 * 34;
        let calls = per_kind * 3 * (evaluation_attempts + reduction_attempts) + 1;
        let bytes = per_kind
            * (evaluation_attempts * ((4 + 8) * core::mem::size_of::<usize>() + 64)
                + reduction_attempts * ((7 + 14) * core::mem::size_of::<usize>() + 64))
            + 4096;
        (calls, bytes)
    }

    #[test]
    fn native_device_opening_requires_full_retained_graph_and_allocation_bound() {
        let (extra, requested) = crate::spill_alloc::allocation_requests::measure(|| {
            Additional::new(1 << 17, limits(), 8 << 30).unwrap()
        });
        assert_eq!(
            (requested.calls, requested.bytes, requested.overflow),
            (0, 0, false)
        );
        assert!(extra.retained_tree_bytes > 3 * tree_bytes(1 << 17).unwrap());
        assert_eq!(
            extra.live_bytes,
            extra.retained_tree_bytes + extra.hash_workspace_bytes
        );
        assert!(Additional::new(1 << 17, limits(), extra.largest_allocation - 1).is_err());
        assert!(Additional::new(
            1 << 17,
            Limits {
                managed_bytes: extra.live_bytes - 1,
                ..limits()
            },
            8 << 30
        )
        .is_err());
        let (request_calls, request_bytes) = opening_planner_request_bound(4096);
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            feature = "gpu-bounded-info"
        ))]
        {
            use crate::block_v2::native_gpu::{
                shake_preparation::ShakePreparationPlan, ShakeTraceSpec,
            };
            let preparation = ShakePreparationPlan::singleton(ShakeTraceSpec {
                input_len: 1,
                output_len: 1,
                first_permutation: 0,
                permutations: 1,
            })
            .unwrap();
            assert!(request_bytes <= preparation.planner().required_host_bytes());
        }
        for width in [517, 518] {
            let (bounded, requested) = crate::spill_alloc::allocation_requests::measure(|| {
                native_plan(
                    4096,
                    width,
                    128 << 20,
                    24 << 30,
                    limits(),
                    8 << 30,
                    device(),
                )
                .unwrap()
            });
            assert!(!requested.overflow);
            assert!(requested.calls > 0 && requested.calls <= request_calls);
            assert!(requested.bytes <= request_bytes);
            assert!(bounded.host_bound_complete);
            assert_eq!(bounded.required_tree_host_bytes, 0);
            let host =
                native_plan(4096, width, 128 << 20, 24 << 30, limits(), 8 << 30, host()).unwrap();
            assert!(host.required_tree_host_bytes > 0);
            assert!(bounded.minimum_required_device_bytes > host.minimum_required_device_bytes);
            assert!(bounded.minimum_required_device_bytes >= (128 << 20) + extra.live_bytes);
            let exact = Limits {
                managed_bytes: bounded.minimum_required_device_bytes,
                ..limits()
            };
            assert!(
                native_plan(4096, width, 128 << 20, 24 << 30, exact, 8 << 30, device()).is_ok()
            );
            assert!(native_plan(
                4096,
                width,
                128 << 20,
                24 << 30,
                Limits {
                    managed_bytes: exact.managed_bytes - 1,
                    ..exact
                },
                8 << 30,
                device()
            )
            .is_err());
        }
    }

    #[test]
    fn registered_host_schedule_and_mode_refusals_are_preserved() {
        assert!(plan(4096, 128 << 20, 24 << 30, limits(), 8 << 30, host()).is_ok());
        assert!(plan(4096, 128 << 20, 24 << 30, limits(), 8 << 30, device()).is_err());
        for bad in [
            Selection {
                host_bytes: 1,
                ..device()
            },
            Selection {
                host_bytes: 0,
                ..host()
            },
        ] {
            assert!(native_plan(4096, 517, 128 << 20, 24 << 30, limits(), 8 << 30, bad).is_err());
        }
        assert!(native_plan(4096, 517, 128 << 20, 1, limits(), 8 << 30, device()).is_err());
        assert!(native_plan(4096, 517, 128 << 20, 24 << 30, limits(), 1, device()).is_err());
    }

    #[test]
    fn standard_hash_and_native_lde_sources_keep_the_charged_schedule() {
        let engine = include_str!("../../../../../gpu_hash/engine.rs");
        let direct = include_str!("../../../../../gpu_hash/engine/direct_tree.rs");
        let lde = include_str!("../../../../../gpu_hash/engine/lde_execute.rs");
        assert!(engine.contains("let slot_input = limits.tile_bytes / slots;"));
        assert!(engine.contains("[(input, slots), (leaves, 1), (parents, 1)]"));
        assert!(engine.contains("height.checked_mul(4)"));
        assert!(direct.contains("if mode == RetainedTreeStorageMode::Device {"));
        assert!(direct.contains("plan_slots(height, width, limits, max_alloc, slots)?"));
        let opening = include_str!("../../../../../gpu_hash/engine/device/opening.rs");
        let planner = include_str!(
            "../../../../../gpu_hash/engine/device/wallet/proof_storage/phases/planner_storage.rs"
        );
        assert!(opening.contains("let mut rows = spec.rows().min(65536);"));
        assert!(opening.contains("let mut rows = height.min(1 << 20);"));
        assert_eq!(
            opening.matches("let mut words = fixed.to_vec();").count(),
            2
        );
        assert_eq!(opening.matches("rows /= 2;").count(), 2);
        assert!(opening.contains("words.extend([inverse_words, partial_words]);"));
        assert!(opening.contains("words.push(inverse_words);"));
        assert!(planner.contains("(4 + 8 + 7 + 14) * size_of::<usize>()"));
        assert!(planner.contains("let failure_scratch_bytes = 4096;"));
        let composition = include_str!("../opening.rs");
        assert!(composition.contains("let mut widths = [7usize; 34];"));
        assert_eq!(
            composition
                .matches("device::opening_evaluation_plan(")
                .count(),
            2
        );
        assert_eq!(
            composition
                .matches("device::opening_reduction_plan(")
                .count(),
            2
        );
        let checked_peak = opening
            .split("fn checked_peak(")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for literal in checked_peak.split('"').skip(1).step_by(2) {
            assert!(literal.len() <= 64);
        }
        // checked_peak emits only these fixed diagnostics inside halving loops.
        for message in [
            "opening allocation overflow",
            "opening allocation exceeds device limit",
            "opening memory plan overflow",
            "opening exceeds aggregate GPU budget",
        ] {
            assert!(message.len() <= 64 && opening.contains(message));
        }
        // Quotient prefix height is rows, but its hiding LDE adds one extra
        // bit. Therefore trace/random and quotient commitments all have the
        // same LDE height; this native FRI path has no second input-height mix.
        assert!(lde.contains("added_bits: crate::block_v2::profile::LOG_BLOWUP + 1,"));
        assert!(lde.contains(".checked_shl((crate::block_v2::profile::LOG_BLOWUP + 1) as u32)"));
        use super::super::{
            device::{QuotientCommitShape, TraceCommitShape},
            Extension, MatrixSpec, RowOrder,
        };
        for log_rows in 12..=20 {
            let trace = TraceCommitShape::new(
                MatrixSpec::new(log_rows, 518, Extension::Base, RowOrder::Natural, 1).unwrap(),
                4,
            )
            .unwrap();
            let quotient = QuotientCommitShape::new(
                MatrixSpec::new(log_rows + 4, 1, Extension::Cubic, RowOrder::Natural, 7).unwrap(),
                16,
                4,
            )
            .unwrap();
            assert_eq!(
                trace.height << super::super::profile::LOG_BLOWUP,
                quotient.height << (super::super::profile::LOG_BLOWUP + 1)
            );
        }
    }
}
