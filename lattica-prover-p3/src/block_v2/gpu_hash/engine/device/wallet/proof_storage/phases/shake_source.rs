//! Fixed native SHAKE feasibility through the maintained wallet phase planner.
//! The original caller must fund planner backing and seal execution selection
//! before this function. It constructs no engine, proof, or dispatch capability.
use super::{runtime_geometry::RuntimeGeometry, *};
use crate::block_v2::quotient_program::{MAX_CONSTRAINTS, MAX_NODES, WORDS_PER_INSTRUCTION};
use core::mem::size_of;

mod transfer_storage;

#[cfg(feature = "ringct-research-quota")]
mod owned;
#[cfg(feature = "ringct-research-quota")]
pub(crate) use owned::ShakeDeviceLease;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct ShakeSourceDeviceCensus {
    #[serde(skip)]
    runtime: RuntimeGeometry,
    #[serde(skip)]
    trees: engine::retained_storage::Selection,
    rows: usize,
    main_width: usize,
    operation_host_bytes: usize,
    managed_ceiling_bytes: usize,
    runtime_baseline_bytes: usize,
    maximum_planned_phase_bytes: usize,
    allocation_ceiling_bytes: usize,
    quotient_partitions: usize,
    source_instruction_words: usize,
}

impl ShakeSourceDeviceCensus {
    /// Covers all five allowed quotient partitions using maximum recorded
    /// compiler geometry, without evaluating AIR constants or guessing the
    /// normalized degree. The ordinary phase planner's temporary allocations
    /// have the same original reservation as its later runtime invocation.
    /// This temporary plan is destroyed before startup, so they do not coexist.
    pub(crate) fn new(
        rows: usize,
        main_width: usize,
        operation_host_bytes: usize,
        limits: Limits,
        max_allocation: usize,
        slots: usize,
    ) -> Result<Self, String> {
        let (minimum, shape) = source_geometry(rows, main_width, operation_host_bytes)?;
        minimum.check(limits.managed_bytes, max_allocation)?;
        let trees = engine::retained_storage::Selection::from_env()?;
        match (trees.mode, trees.host_bytes) {
            (engine::RetainedTreeStorageMode::Device, 0)
            | (engine::RetainedTreeStorageMode::HostBacking, 8589934592) => {}
            _ => {
                return Err(
                    "native SHAKE requires a fixed device or outer_host_v1 tree profile".into(),
                )
            }
        }
        let runtime = RuntimeGeometry::fresh(limits, max_allocation, slots, 0)?;
        let plan = Plan::from_geometry(minimum, runtime)?;
        if plan.quotient_tiles.len() != 5
            || plan
                .quotient_tiles
                .iter()
                .zip([2, 4, 8, 16, 32])
                .any(|(tile, chunks)| tile.chunks != chunks || tile.rows == 0)
            || plan.phases.is_empty()
        {
            return Err("native SHAKE maintained phase coverage changed".into());
        }
        let maximum_planned_phase_bytes = plan.phases.iter().map(|p| p.bytes).max().unwrap();
        if maximum_planned_phase_bytes > limits.managed_bytes {
            return Err("native SHAKE maintained phase exceeds selected allowance".into());
        }
        Ok(Self {
            runtime,
            trees,
            rows,
            main_width,
            operation_host_bytes,
            // Runtime may choose larger adaptive tiles for an actual smaller
            // recording. Claim its complete existing managed capacity, not the
            // modeled minimum or this static plan's selected tiles.
            managed_ceiling_bytes: limits.managed_bytes,
            runtime_baseline_bytes: runtime.managed_baseline_bytes(),
            maximum_planned_phase_bytes,
            // This is deliberately the captured hardware/managed ceiling,
            // not a claim that an allocation of this size occurred.
            allocation_ceiling_bytes: max_allocation.min(limits.managed_bytes),
            quotient_partitions: plan.quotient_tiles.len(),
            source_instruction_words: shape.instruction_words,
        })
    }

    pub(crate) fn managed_ceiling_bytes(self) -> usize {
        self.managed_ceiling_bytes
    }

    pub(crate) fn tree_selection(self) -> engine::retained_storage::Selection {
        self.trees
    }

    pub(crate) fn maximum_planned_phase_bytes(self) -> usize {
        self.maximum_planned_phase_bytes
    }

    pub(crate) fn runtime_baseline_bytes(self) -> usize {
        self.runtime_baseline_bytes
    }

    pub(crate) fn allocation_ceiling_bytes(self) -> usize {
        self.allocation_ceiling_bytes
    }

    fn check_prepared_minimum(&self, actual: WalletProofMinimum) -> Result<(), String> {
        let (expected, maximum) =
            source_geometry(self.rows, self.main_width, self.operation_host_bytes)?;
        check_minimum(expected, maximum, actual)
    }
}

fn check_minimum(
    expected: WalletProofMinimum,
    maximum: ProgramShape,
    actual: WalletProofMinimum,
) -> Result<(), String> {
    let program = actual
        .program
        .ok_or("native SHAKE recording has no program shape")?;
    // Every non-program field must match exactly, including the private
    // constructor's simultaneous/largest minima and compact periodic shape.
    let mut shape = actual;
    shape.program = expected.program;
    if shape != expected
        || program.extension != maximum.extension
        || program.row_words != maximum.row_words
        || program.parameter_words != maximum.parameter_words
        || program.registers == 0
        || program.registers > maximum.registers
        || program.constraints == 0
        || program.constraints > maximum.constraints
        || program.instruction_words
            != (program.registers + program.constraints) * WORDS_PER_INSTRUCTION
        || program.instruction_words > maximum.instruction_words
    {
        return Err("native SHAKE actual recording differs from its source model".into());
    }
    Ok(())
}

fn source_geometry(
    rows: usize,
    main_width: usize,
    operation_host_bytes: usize,
) -> Result<(WalletProofMinimum, ProgramShape), String> {
    if !cfg!(all(
        not(debug_assertions),
        target_os = "linux",
        target_arch = "x86_64",
        feature = "gpu-bounded-info"
    )) || !(4096..=1 << 20).contains(&rows)
        || !rows.is_power_of_two()
        || !matches!(main_width, 517 | 518)
        || (main_width == 517 && rows != 4096)
        || operation_host_bytes == 0
        || operation_host_bytes > 24 << 30
        || profile::MAX_QUOTIENT_CHUNKS != 32
        || profile::LOG_BLOWUP != 4
        || profile::CAP_HEIGHT != 6
        || profile::NUM_QUERIES != 128
        || profile::NUM_RANDOM_CODEWORDS != 4
        || size_of::<profile::Challenge>() != 24
    {
        return Err("native SHAKE source device geometry refused".into());
    }
    let shape = ProgramShape {
        extension: Extension::Cubic,
        instruction_words: (MAX_NODES + MAX_CONSTRAINTS) * WORDS_PER_INSTRUCTION,
        registers: MAX_NODES,
        constraints: MAX_CONSTRAINTS,
        row_words: 2 * (main_width + 42),
        parameter_words: 216,
    };
    let periodic = PeriodicShape::new(rows.ilog2(), std::iter::repeat_n(128, 42))?;
    let minimum = WalletProofMinimum::new(rows, main_width, 42, Extension::Cubic)?
        .with_program(shape, operation_host_bytes)?
        .with_periodic(Some(periodic))?;
    Ok((minimum, shape))
}

#[cfg(all(
    test,
    not(debug_assertions),
    feature = "stream",
    feature = "gpu-bounded-info"
))]
mod tests {
    use super::*;

    #[test]
    fn actual_recording_must_match_source_geometry_and_each_program_ceiling() {
        let (expected, maximum) = source_geometry(4096, 517, 24 << 30).unwrap();
        let mut actual = expected;
        actual.program = Some(ProgramShape {
            registers: 10,
            constraints: 3,
            instruction_words: 13 * WORDS_PER_INSTRUCTION,
            ..maximum
        });
        let (result, requests) = crate::spill_alloc::allocation_requests::measure(|| {
            check_minimum(expected, maximum, actual)
        });
        assert!(result.is_ok());
        assert_eq!(
            (requests.calls, requests.bytes, requests.overflow),
            (0, 0, false)
        );
        assert!(check_minimum(expected, maximum, expected).is_ok());

        for bad in [
            WalletProofMinimum {
                program: None,
                ..actual
            },
            WalletProofMinimum {
                rows: 8192,
                ..actual
            },
            WalletProofMinimum {
                columns: 518,
                ..actual
            },
            WalletProofMinimum {
                periodic: None,
                ..actual
            },
            WalletProofMinimum {
                host_allowance: (24 << 30) - 1,
                ..actual
            },
            WalletProofMinimum {
                largest_allocation: actual.largest_allocation - 1,
                ..actual
            },
            WalletProofMinimum {
                simultaneous_bytes: actual.simultaneous_bytes - 1,
                ..actual
            },
        ] {
            assert!(check_minimum(expected, maximum, bad).is_err());
        }
        let source = actual.program.unwrap();
        for bad in [
            ProgramShape {
                extension: Extension::Quadratic,
                ..source
            },
            ProgramShape {
                registers: 0,
                ..source
            },
            ProgramShape {
                registers: MAX_NODES + 1,
                ..source
            },
            ProgramShape {
                constraints: 0,
                ..source
            },
            ProgramShape {
                constraints: MAX_CONSTRAINTS + 1,
                ..source
            },
            ProgramShape {
                instruction_words: source.instruction_words + 1,
                ..source
            },
            ProgramShape {
                row_words: source.row_words + 1,
                ..source
            },
            ProgramShape {
                parameter_words: source.parameter_words - 1,
                ..source
            },
        ] {
            actual.program = Some(bad);
            assert!(check_minimum(expected, maximum, actual).is_err());
        }
    }

    #[test]
    fn native_source_geometry_is_pure_and_keeps_all_compiler_limits() {
        for (rows, width) in [(4096, 517), (4096, 518), (1 << 20, 518)] {
            let ((minimum, shape), requests) =
                crate::spill_alloc::allocation_requests::measure(|| {
                    source_geometry(rows, width, 24 << 30).unwrap()
                });
            assert_eq!(
                (requests.calls, requests.bytes, requests.overflow),
                (0, 0, false)
            );
            assert_eq!(shape.extension, Extension::Cubic);
            assert_eq!(shape.registers, MAX_NODES);
            assert_eq!(shape.constraints, MAX_CONSTRAINTS);
            assert_eq!(shape.row_words, 2 * (width + 42));
            assert_eq!(shape.parameter_words, 216);
            assert_eq!(minimum.rows, rows);
            assert_eq!(minimum.periodic.unwrap().input_words(), 42 * 128);
        }
        for (rows, width) in [(0, 517), (8192, 517), (4096, 516), (4097, 518)] {
            assert!(source_geometry(rows, width, 24 << 30).is_err());
        }
        assert!(source_geometry(4096, 517, 0).is_err());
        assert!(source_geometry(4096, 517, (24 << 30) + 1).is_err());
    }

    #[test]
    fn impossible_source_device_shapes_refuse_before_planner_execution() {
        let limits = Limits::default();
        assert!(ShakeSourceDeviceCensus::new(4096, 517, 24 << 30, limits, 1, 1).is_err());
        assert!(ShakeSourceDeviceCensus::new(
            4096,
            517,
            24 << 30,
            Limits {
                managed_bytes: 1,
                ..limits
            },
            usize::MAX,
            1,
        )
        .is_err());
    }

    #[test]
    fn source_model_covers_every_partition_without_creating_a_runtime() {
        for width in [517, 518] {
            let census = ShakeSourceDeviceCensus::new(
                4096,
                width,
                24 << 30,
                Limits::default(),
                4_175_986_688,
                1,
            )
            .unwrap();
            assert_eq!(census.quotient_partitions, 5);
            assert_eq!(census.runtime_baseline_bytes(), (64 << 20) + 752);
            assert_eq!(census.managed_ceiling_bytes(), 8 << 30);
            assert!(census.maximum_planned_phase_bytes() <= census.managed_ceiling_bytes());
            assert!(census.maximum_planned_phase_bytes() > census.runtime_baseline_bytes());
            assert_eq!(census.allocation_ceiling_bytes(), 4_175_986_688);
        }
    }
}
