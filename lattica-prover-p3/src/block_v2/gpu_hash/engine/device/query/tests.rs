use super::*;

fn spec(log: u32, columns: usize) -> MatrixSpec {
    MatrixSpec::new(log, columns, Extension::Base, RowOrder::BitReversed, 7).unwrap()
}

#[test]
#[cfg(feature = "gpu")]
#[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
fn owned_query_tiles_match_cpu_without_prefix_transfers_and_release_scratch() {
    use super::super::super::{initialize_mode, shutdown, Limits, TestShutdownGuard, TransferMode};
    use crate::config::Dft;
    use p3_dft::TwoAdicSubgroupDft;
    use p3_field::{PrimeCharacteristicRing, PrimeField64};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    let _shutdown = TestShutdownGuard;
    initialize_mode(
        Limits {
            managed_bytes: 128 << 20,
            tile_bytes: 1 << 20,
            staging_bytes: 4096,
        },
        TransferMode::Serial,
    )
    .unwrap();
    let session = DeviceSession::new().unwrap();
    let baseline = session.plan_outputs(&[spec(0, 1)]).unwrap().live_bytes;
    let physical = |row: usize, log: u32| {
        if log == 0 {
            row
        } else {
            row.reverse_bits() >> (usize::BITS - log)
        }
    };
    for (log_input, log_output, width) in [
        (0, 0, 1),
        (0, 4, 7),
        (1, 5, 7),
        (8, 12, 31),
        (12, 16, 97),
        (13, 17, 65),
    ] {
        let values: Vec<_> = (0..(1usize << log_input) * width)
            .map(|i| {
                Val::from_u64(match i % 5 {
                    0 => 0,
                    1 => 1,
                    2 => GOLDILOCKS_MODULUS - 1,
                    3 => u64::MAX,
                    _ => (i as u64).wrapping_mul(0x9e3779b97f4a7c15),
                })
            })
            .collect();
        let expected = Dft::default()
            .lde_batch(
                RowMajorMatrix::new(values.clone(), width),
                (log_output - log_input) as usize,
            )
            .to_row_major_matrix();
        let words: Vec<_> = (0..1usize << log_input)
            .flat_map(|row| {
                let at = physical(row, log_input) * width;
                values[at..at + width].iter().map(|v| v.as_canonical_u64())
            })
            .collect();
        let height = 1usize << log_output;
        let indices: Vec<_> = [height - 1, 0, height / 2, 0]
            .into_iter()
            .chain((0..252).map(|i| (i * 31337) % height))
            .collect();
        for shift in [1, 7, 11] {
            let input_spec = MatrixSpec::new(
                log_input,
                width,
                Extension::Base,
                RowOrder::BitReversed,
                shift,
            )
            .unwrap();
            let input = session.upload(input_spec, &words).unwrap();
            let live = session.plan_outputs(&[input_spec]).unwrap().live_bytes;
            let before = session.stats();
            let rows = session
                .query_rows(&input, log_output, &indices, 32 << 20)
                .unwrap();
            let after = session.stats();
            assert_eq!(
                after.uploaded_bytes - before.uploaded_bytes,
                ((log_input.max(1) + log_output.max(1)) as usize + indices.len()) as u64 * 8
            );
            assert_eq!(
                after.downloaded_bytes - before.downloaded_bytes,
                (indices.len() * width * 8) as u64
            );
            assert_eq!(
                after.query_value_bytes - before.query_value_bytes,
                (indices.len() * width * 8) as u64
            );
            assert_eq!(
                after.query_reconstructions - before.query_reconstructions,
                1
            );
            if width == 65 {
                assert!(after.query_reconstruction_tiles - before.query_reconstruction_tiles > 1);
            }
            for (&index, row) in indices.iter().zip(rows.chunks_exact(width)) {
                let at = physical(index, log_output) * width;
                assert_eq!(row, expected.values[at..at + width].iter()
                    .map(|v| v.as_canonical_u64()).collect::<Vec<_>>(),
                    "input={log_input} output={log_output} width={width} shift={shift} index={index}");
            }
            assert_eq!(
                session.plan_outputs(&[input_spec]).unwrap().live_bytes,
                live
            );
            assert_eq!(session.read(&input, input_spec.bytes()).unwrap(), words);
            let before = session.stats();
            assert!(session.query_rows(&input, log_output, &indices, 0).is_err());
            assert!(session
                .query_rows(&input, log_output, &[], usize::MAX)
                .is_err());
            assert!(session
                .query_rows(&input, log_output, &[height], usize::MAX)
                .is_err());
            assert!(session.query_rows(&input, 26, &[0], usize::MAX).is_err());
            assert!(DeviceSession::new()
                .unwrap()
                .query_rows(&input, log_output, &[0], usize::MAX)
                .is_err());
            assert_eq!(before, session.stats());
            assert_eq!(
                session.plan_outputs(&[input_spec]).unwrap().live_bytes,
                live
            );
        }
        assert_eq!(
            session.plan_outputs(&[spec(0, 1)]).unwrap().live_bytes,
            baseline
        );
    }
    // Aggregate rejection happens before uploads/kernels and frees no input.
    let input = session.upload(spec(4, 3), &[1; 48]).unwrap();
    let live = session.plan_outputs(&[input.spec]).unwrap().live_bytes;
    let filler_words = ((128 << 20) - live - 4096) / 8;
    let filler = session
        .upload(spec(0, filler_words), &vec![0; filler_words])
        .unwrap();
    let before = session.stats();
    let filled = session.plan_outputs(&[spec(0, 1)]).unwrap().live_bytes;
    assert!(session.query_rows(&input, 12, &[0], 32 << 20).is_err());
    assert_eq!(before, session.stats());
    assert_eq!(
        session.plan_outputs(&[spec(0, 1)]).unwrap().live_bytes,
        filled
    );
    drop(filler);
    session
        .query_rows(&input, 12, &[4095, 0, 4095], 32 << 20)
        .unwrap();
    drop(input);
    assert_eq!(
        session.plan_outputs(&[spec(0, 1)]).unwrap().live_bytes,
        baseline
    );
    drop(session);
    shutdown().unwrap();
}
