use super::*;

const GUARD: u64 = 0xdead_beef_9876_5432;

fn inverse<F: ExtensionField<Val>>(extension: Extension) {
    let runtime = runtime(limits());
    let engine = Lookups::new(&runtime).unwrap();
    for count in [1usize, 127, 128, 129, 257] {
        let values: Vec<F> = (0..count)
            .map(|i| F::from_basis_coefficients_fn(|j| Val::from_usize((i + 1) * (j + 1) * 17)))
            .collect();
        let expected = words(&values.iter().map(|v| v.inverse()).collect::<Vec<_>>());
        let mut initial = words(&values);
        initial.extend([GUARD; 8]);
        let data = runtime.allocate(initial.len()).unwrap();
        data.write(0, &initial).unwrap();
        let status = runtime.allocate(2).unwrap();
        status.write(1, &[GUARD]).unwrap();
        // Padded lanes own identity elements; only count*degree words may be written.
        unsafe {
            engine
                .inverse
                .launch(
                    Launch {
                        blocks: count.div_ceil(128) as u32,
                        threads: 128,
                        shared_bytes: 0,
                    },
                    &[
                        Argument::Buffer(&data),
                        Argument::U32(count as u32),
                        Argument::Buffer(&status),
                        Argument::U32(extension.degree() as u32),
                    ],
                )
                .unwrap()
        }
        .finish()
        .unwrap();
        let mut actual = vec![0; initial.len()];
        data.read(0, &mut actual).unwrap();
        assert_eq!(&actual[..expected.len()], &expected);
        assert_eq!(&actual[expected.len()..], &[GUARD; 8]);
        let mut valid = [0; 2];
        status.read(0, &mut valid).unwrap();
        assert_eq!(valid, [0, GUARD]);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_lookup_batch_inverse_preserves_partial_block_guards() {
    inverse::<crate::config::Challenge>(Extension::Quadratic);
    inverse::<crate::block_v2::profile::Challenge>(Extension::Cubic);
}

fn scan<F: ExtensionField<Val>>(extension: Extension) {
    let runtime = runtime(limits());
    let engine = Lookups::new(&runtime).unwrap();
    for count in [1usize, 127, 128, 129, 16385] {
        let values: Vec<F> = (0..count)
            .map(|i| F::from_basis_coefficients_fn(|j| Val::NEG_ONE + Val::from_usize(i * (j + 3))))
            .collect();
        let mut inclusive = Vec::new();
        let mut totals = Vec::new();
        for block in values.chunks(128) {
            let mut sum = F::ZERO;
            for &value in block {
                sum += value;
                inclusive.push(sum);
            }
            totals.push(sum);
        }
        let expected = words(&inclusive);
        let expected_totals = words(&totals);
        let mut initial = words(&values);
        initial.extend([GUARD; 8]);
        let data = runtime.allocate(initial.len()).unwrap();
        data.write(0, &initial).unwrap();
        let total = runtime.allocate(expected_totals.len() + 8).unwrap();
        total.write(expected_totals.len(), &[GUARD; 8]).unwrap();
        // Each block owns one bounded parent total; padded rows contribute zero.
        unsafe {
            engine
                .scan
                .launch(
                    Launch {
                        blocks: count.div_ceil(128) as u32,
                        threads: 128,
                        shared_bytes: 0,
                    },
                    &[
                        Argument::Buffer(&data),
                        Argument::Buffer(&total),
                        Argument::U32(count as u32),
                        Argument::U32(extension.degree() as u32),
                    ],
                )
                .unwrap()
        }
        .finish()
        .unwrap();
        let mut actual = vec![0; data.len()];
        data.read(0, &mut actual).unwrap();
        assert_eq!(&actual[..expected.len()], &expected);
        assert_eq!(&actual[expected.len()..], &[GUARD; 8]);
        let mut actual_totals = vec![0; total.len()];
        total.read(0, &mut actual_totals).unwrap();
        assert_eq!(&actual_totals[..expected_totals.len()], &expected_totals);
        assert_eq!(&actual_totals[expected_totals.len()..], &[GUARD; 8]);
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_lookup_scan_preserves_partial_block_and_parent_guards() {
    scan::<crate::config::Challenge>(Extension::Quadratic);
    scan::<crate::block_v2::profile::Challenge>(Extension::Cubic);
}

#[test]
fn lookup_plan_charges_resident_inputs_once_and_admits_scan_boundaries() {
    let (layout, lookups) = lookup_fixture();
    let program = LookupProgram::compile(layout, &lookups).unwrap();
    for extension in [Extension::Quadratic, Extension::Cubic] {
        for (log, levels) in [
            (0, vec![1]),
            (7, vec![128]),
            (8, vec![256, 2]),
            (15, vec![32768, 256, 2]),
        ] {
            let spec = MatrixSpec::new(
                log,
                program.lookup_count() + 1,
                extension,
                RowOrder::Natural,
                1,
            )
            .unwrap();
            let resident = Plan::new(
                &program,
                spec,
                4096,
                64 << 20,
                TILE_BYTES,
                InputStorage::Resident,
                32 << 20,
            )
            .unwrap();
            let uploaded = Plan::new(
                &program,
                spec,
                4096,
                64 << 20,
                TILE_BYTES,
                InputStorage::Uploaded,
                32 << 20,
            )
            .unwrap();
            assert_eq!(resident.scan_rows, levels);
            assert_eq!(resident.parameters, [0, 0, 1]);
            assert_eq!(resident.rows, uploaded.rows);
            assert_eq!(
                uploaded.peak - resident.peak,
                (program.layout.num_public_values.max(1)
                    + program.lookup_count() * 2 * extension.degree())
                    * 8
            );
            assert_eq!(
                resident.peak,
                4096 + spec.bytes()
                    + extension.degree() * 8
                    + (1 + resident.tile.iter().sum::<usize>()
                        + resident.scan_rows.iter().sum::<usize>() * extension.degree())
                        * 8
            );
            assert!(Plan::new(
                &program,
                spec,
                4096,
                64 << 20,
                0,
                InputStorage::Resident,
                32 << 20
            )
            .is_err());
            assert!(Plan::new(
                &program,
                spec,
                4096,
                64 << 20,
                TILE_BYTES,
                InputStorage::Resident,
                spec.bytes() - 1
            )
            .is_err());
        }
    }
}
