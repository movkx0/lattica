//! Whole partition operation admission before domain arithmetic or transfers.
//! Inputs and prepared code are already included in `live`. Expansion is bounded
//! for later cosets. A single coset preserves runtime's same-domain aliases.
use super::*;
use crate::block_v2::gpu_quotient_prover::program::ProgramShape;

#[derive(Debug)]
pub(crate) struct PartitionStorage {
    pub output: MatrixSpec,
    pub part_log: u32,
    pub cosets: usize,
    pub peak_bytes: usize,
    pub max_allocation_bytes: usize,
    pub expansion_peak_bytes: usize,
    pub evaluation_peak_bytes: usize,
    pub tile_rows: usize,
}

impl PartitionStorage {
    pub(crate) fn new(
        inputs: &[MatrixSpec],
        log_trace: u32,
        log_quotient: u32,
        shift: u64,
        program: ProgramShape,
        live: usize,
        cache: usize,
        limits: super::super::super::Limits,
        max_allocation: usize,
    ) -> Result<Self, String> {
        let (output, part_log, cosets) =
            partition_geometry(inputs, log_trace, log_quotient, shift, program.extension)?;
        let row_words = inputs.iter().try_fold(0usize, |n, spec| {
            spec.columns
                .checked_mul(spec.extension.degree())
                .and_then(|w| w.checked_mul(2))
                .and_then(|w| n.checked_add(w))
                .ok_or("partition input width overflow")
        })?;
        if row_words != program.row_words {
            return Err("partition inputs differ from program row width".into());
        }
        let without_cache = live
            .checked_sub(cache)
            .ok_or("partition cache exceeds live storage")?;
        // split_domains uses two scalar inputs and one output word per coset;
        // both are released before the complete quotient result is allocated.
        let (_, scalars) =
            super::super::scalars::storage_plan(2, cosets, live, limits, max_allocation)?;
        let result = MemoryPlan::new(&[output], live, limits.managed_bytes, max_allocation)?;
        let mut peak_bytes = result.peak_bytes.max(scalars.peak_bytes);
        let mut largest = output.bytes().max(cosets * 8).max(16);
        let base = without_cache
            .checked_add(output.bytes())
            .ok_or("partition output storage overflow")?;
        let mut expanded = 0usize;
        let mut expansion_peak_bytes = base;
        for &input in inputs {
            if cosets == 1 && input.log_rows == part_log {
                // The one split domain retains the original shift. Runtime
                // aliases this input, so its bytes are already in `live`.
                continue;
            }
            let retained = base
                .checked_add(expanded)
                .ok_or("partition retained storage overflow")?;
            let transform = super::super::transform::storage_plan(
                input,
                part_log,
                retained,
                limits,
                max_allocation,
            )?;
            let output = MatrixSpec::new(
                part_log,
                input.columns,
                input.extension,
                RowOrder::BitReversed,
                shift,
            )?;
            largest = largest
                .max(output.bytes())
                .max(part_log.max(2) as usize * 8);
            expansion_peak_bytes = expansion_peak_bytes.max(transform.peak_bytes);
            expanded = expanded
                .checked_add(output.bytes())
                .ok_or("partition expansion storage overflow")?;
        }
        let part_output =
            MatrixSpec::new(part_log, 1, program.extension, RowOrder::Natural, shift)?;
        let evaluation_live = base
            .checked_add(expanded)
            .and_then(|n| n.checked_add(part_output.bytes()))
            .ok_or("partition evaluation storage overflow")?;
        let evaluation = Plan::for_shape(
            program,
            1usize << part_log,
            evaluation_live,
            limits,
            max_allocation,
        )?;
        for words in evaluation
            .static_words
            .into_iter()
            .chain(evaluation.tile_words)
        {
            largest = largest.max(
                words
                    .checked_mul(8)
                    .ok_or("partition evaluator storage overflow")?,
            );
        }
        largest = largest.max(part_output.bytes());
        peak_bytes = peak_bytes.max(expansion_peak_bytes).max(evaluation.peak);
        Ok(Self {
            output,
            part_log,
            cosets,
            peak_bytes,
            max_allocation_bytes: largest,
            expansion_peak_bytes,
            evaluation_peak_bytes: evaluation.peak,
            tile_rows: evaluation.rows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_single_coset_keeps_same_domain_aliases_within_a_tight_budget() {
        let input = MatrixSpec::new(10, 200, Extension::Base, RowOrder::BitReversed, 7).unwrap();
        let program = ProgramShape {
            extension: Extension::Cubic,
            instruction_words: 10,
            registers: 1,
            constraints: 1,
            row_words: 400,
            parameter_words: 0,
        };
        let live = input.bytes() + 80;
        let output_bytes = 1024 * 3 * 8;
        let limits = super::super::super::super::Limits {
            managed_bytes: live + output_bytes + (64 << 10),
            tile_bytes: 4096,
            staging_bytes: 0,
        };
        let plan =
            PartitionStorage::new(&[input], 9, 10, 7, program, live, 0, limits, 4 << 20).unwrap();
        assert_eq!(plan.cosets, 1);
        assert_eq!(plan.expansion_peak_bytes, live + output_bytes);
        assert!(plan.peak_bytes <= limits.managed_bytes);
        assert!(plan.max_allocation_bytes < input.bytes());
    }

    #[test]
    fn partition_storage_includes_cache_until_result_and_checks_every_transform() {
        let inputs = [
            MatrixSpec::new(6, 3, Extension::Base, RowOrder::BitReversed, 7).unwrap(),
            MatrixSpec::new(4, 2, Extension::Base, RowOrder::BitReversed, 7).unwrap(),
        ];
        for extension in [Extension::Quadratic, Extension::Cubic] {
            let program = ProgramShape {
                extension,
                instruction_words: 10,
                registers: 2,
                constraints: 1,
                row_words: 10,
                parameter_words: 0,
            };
            let limits = super::super::super::super::Limits {
                managed_bytes: 1 << 20,
                tile_bytes: 1 << 20,
                staging_bytes: 0,
            };
            let live = inputs.iter().map(|s| s.bytes()).sum::<usize>() + 80;
            let cold =
                PartitionStorage::new(&inputs, 4, 8, 7, program, live, 0, limits, 1 << 20).unwrap();
            let warm = PartitionStorage::new(
                &inputs,
                4,
                8,
                7,
                program,
                live + (1 << 18),
                1 << 18,
                limits,
                1 << 20,
            )
            .unwrap();
            assert_eq!((warm.part_log, warm.cosets), (6, 4));
            assert_eq!(warm.expansion_peak_bytes, cold.expansion_peak_bytes);
            assert_eq!(warm.evaluation_peak_bytes, cold.evaluation_peak_bytes);
            assert_eq!(warm.peak_bytes, live + (1 << 18) + warm.output.bytes());
            assert!(warm.tile_rows > 0 && warm.max_allocation_bytes <= 1 << 20);
            assert!(PartitionStorage::new(
                &inputs,
                4,
                8,
                7,
                program,
                live,
                0,
                super::super::super::super::Limits {
                    managed_bytes: live + cold.output.bytes() - 1,
                    ..limits
                },
                1 << 20
            )
            .is_err());
            assert!(PartitionStorage::new(
                &inputs,
                4,
                8,
                7,
                program,
                live,
                0,
                limits,
                cold.output.bytes() - 1
            )
            .is_err());
            assert!(PartitionStorage::new(
                &inputs,
                4,
                8,
                7,
                program,
                live,
                live + 1,
                limits,
                1 << 20
            )
            .is_err());
            assert!(PartitionStorage::new(
                &inputs,
                4,
                8,
                7,
                ProgramShape {
                    row_words: 12,
                    ..program
                },
                live,
                0,
                limits,
                1 << 20
            )
            .is_err());
        }
    }

    #[cfg(feature = "gpu")]
    #[test]
    #[ignore = "requires selected OpenCL GPU and bounded zero-swap service"]
    fn gpu_partition_rejects_result_capacity_before_domain_arithmetic() {
        use crate::block_v2::gpu_hash;
        let _shutdown = gpu_hash::TestShutdownGuard;
        gpu_hash::initialize_quotient_test_engine(gpu_hash::Limits {
            managed_bytes: 12 << 20,
            tile_bytes: 4 << 20,
            staging_bytes: 64 << 10,
        })
        .unwrap();
        let session = DeviceSession::new().unwrap();
        // One constant constraint is enough to exercise admission. No quotient
        // program or domain kernel may execute for this oversized result.
        let program = Arc::new(Program {
            extension: Extension::Cubic,
            instructions: vec![0, 0, 7, 0, 0, 16, 0, 0, 0, 0],
            registers: 1,
            constraints: 1,
            layout: p3_air::symbolic::AirLayout {
                main_width: 1,
                ..Default::default()
            },
            row_words: 2,
            parameter_words: 0,
        });
        let prepared = session.prepare_quotient(program).unwrap();
        let spec = MatrixSpec::new(11, 1, Extension::Base, RowOrder::BitReversed, 7).unwrap();
        let main = session.upload(spec, &vec![0; spec.words()]).unwrap();
        let before = session.stats();
        let allocations = gpu_hash::report("partition_rejection_before")
            .unwrap()
            .allocations;
        assert!(session
            .quotient_cubic_partitioned(&prepared, 11, 19, 7, &main, None, None, [1, 0, 0], &[])
            .is_err());
        assert_eq!(session.stats(), before);
        assert_eq!(
            gpu_hash::report("partition_rejection_after")
                .unwrap()
                .allocations,
            allocations
        );
        eprintln!("gpu_partition_capacity_rejected_before_domain_arithmetic=true");
    }
}
