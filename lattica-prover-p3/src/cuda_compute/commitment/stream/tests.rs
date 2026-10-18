use super::*;
use crate::{
    config::{MyCompress, MyHash, Val},
    gpu_matrix::RowOrder,
};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_matrix::{dense::RowMajorMatrix, Matrix as _};
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};

type Plain =
    MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 2, 4>;
fn cpu(cap: usize) -> Plain {
    let p = p3_goldilocks::default_goldilocks_poseidon2_8();
    Plain::new(MyHash::new(p.clone()), MyCompress::new(p), cap)
}
fn runtime() -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: 4 << 20,
            max_allocation_bytes: 2 << 20,
            ..Limits::default()
        },
    )
    .unwrap()
}
fn spec(log: u32, width: usize, extension: Extension) -> MatrixSpec {
    MatrixSpec::new(log, width, extension, RowOrder::BitReversed, 7).unwrap()
}
fn digests(words: &[u64]) -> Vec<[Val; 4]> {
    words
        .chunks_exact(4)
        .map(|c| std::array::from_fn(|i| Val::from_u64(c[i])))
        .collect()
}

#[test]
fn streamed_plan_preserves_height_ties_and_bounds_metadata() {
    let inputs = [
        spec(3, 1, Extension::Base),
        spec(1, 7, Extension::Base),
        spec(3, 2, Extension::Quadratic),
        spec(0, 1, Extension::Cubic),
        spec(2, 5, Extension::Base),
    ];
    let plan = StreamPlan::new(&inputs, 0).unwrap();
    assert_eq!(plan.order, [0, 2, 4, 1, 3]);
    assert_eq!(plan.words, [60, 64]);
    assert_eq!(
        StreamPlan::new(&inputs, usize::MAX)
            .unwrap()
            .layout
            .cap_words,
        32
    );
    assert!(StreamPlan::new(&[], 0).is_err());
    assert!(StreamPlan::new(&vec![inputs[0]; 257], 0).is_err());
    assert!(StreamPlan::new(&[spec(32, 1, Extension::Base)], 0).is_err());
    assert!(StreamPlan::new(
        &[MatrixSpec {
            words: 1,
            ..inputs[0]
        }],
        0
    )
    .is_err());
    assert!(StreamPlan::new(&[spec(0, u32::MAX as usize, Extension::Cubic)], 0).is_err());
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_streamed_mixed_height_caps_and_paths_match_cpu_mmcs() {
    let runtime = runtime();
    let engine = Commitments::new(&runtime).unwrap();
    for input_specs in [
        vec![spec(0, 1, Extension::Base)],
        vec![
            spec(3, 1, Extension::Base),
            spec(1, 7, Extension::Base),
            spec(3, 3, Extension::Cubic),
            spec(0, 1, Extension::Quadratic),
            spec(2, 5, Extension::Base),
        ],
        vec![
            spec(5, 7, Extension::Base),
            spec(3, 2, Extension::Quadratic),
            spec(5, 2, Extension::Cubic),
        ],
    ] {
        let raw: Vec<Vec<u64>> = input_specs
            .iter()
            .enumerate()
            .map(|(m, s)| {
                (0..s.words())
                    .map(|i| {
                        if i % 7 == 0 {
                            u64::MAX
                        } else {
                            (m * 99991 + i * 319 + 17) as u64
                        }
                    })
                    .collect()
            })
            .collect();
        let matrices: Vec<_> = input_specs
            .iter()
            .zip(&raw)
            .map(|(s, words)| {
                RowMajorMatrix::new(
                    words.iter().map(|&v| Val::from_u64(v)).collect(),
                    s.words() / s.rows(),
                )
            })
            .collect();
        let max_rows = input_specs.iter().map(|s| s.rows()).max().unwrap();
        for cap_height in [0, 1, 6] {
            let oracle = cpu(cap_height);
            let (expected, data) = oracle.commit(matrices.clone());
            let mut order = Vec::new();
            let before = runtime.snapshot();
            let tree = engine
                .commit_streamed(&input_specs, cap_height, |index, sink| {
                    order.push(index);
                    let s = input_specs[index];
                    let width = s.words() / s.rows();
                    for first in (0..width).step_by(3) {
                        let columns = 3.min(width - first);
                        let tile: Vec<_> = (0..s.rows())
                            .flat_map(|row| {
                                raw[index][row * width + first..row * width + first + columns]
                                    .iter()
                                    .copied()
                            })
                            .collect();
                        let fragment = runtime
                            .upload_matrix(spec(s.log_rows, columns, Extension::Base), &tile)?;
                        sink.append(first, &fragment)?;
                    }
                    Ok(())
                })
                .unwrap();
            assert_eq!(runtime.snapshot().downloaded_bytes, before.downloaded_bytes);
            assert_eq!(
                order,
                StreamPlan::new(&input_specs, cap_height).unwrap().order
            );
            let cap = MerkleCap::new(digests(&tree.cap(tree.cap_bytes()).unwrap()));
            assert_eq!(cap, expected);
            let indices = [max_rows - 1, 0, max_rows / 2, max_rows - 1];
            let paths = engine
                .open(&tree, &indices.map(|i| i as u64), 64 << 10)
                .unwrap();
            let dimensions: Vec<_> = matrices.iter().map(|m| m.dimensions()).collect();
            for (q, index) in indices.into_iter().enumerate() {
                let (values, expected_path) = oracle.open_batch(index, &data).unpack();
                let path = digests(&paths[q * tree.path_len() * 4..(q + 1) * tree.path_len() * 4]);
                assert_eq!(path, expected_path);
                oracle
                    .verify_batch(
                        &cap,
                        &dimensions,
                        index,
                        BatchOpeningRef::new(&values, &path),
                    )
                    .unwrap();
                if cap_height == 0 {
                    let mut altered = values.clone();
                    altered[0][0] += Val::ONE;
                    assert!(oracle
                        .verify_batch(
                            &cap,
                            &dimensions,
                            index,
                            BatchOpeningRef::new(&altered, &path)
                        )
                        .is_err());
                }
            }
        }
    }
}

#[test]
#[ignore = "requires CUDA; serial bounded service"]
fn cuda_streamed_commitments_reject_partial_producers_and_release_scratch() {
    let runtime = runtime();
    let engine = Commitments::new(&runtime).unwrap();
    let s = spec(3, 3, Extension::Base);
    let fragment = runtime
        .upload_matrix(spec(3, 1, Extension::Base), &[7; 8])
        .unwrap();
    let baseline = runtime.snapshot().live_bytes;
    assert!(engine.commit_streamed(&[s], 0, |_, _| Ok(())).is_err());
    assert_eq!(runtime.snapshot().live_bytes, baseline);
    assert!(engine
        .commit_streamed(&[s], 0, |_, sink| sink.append(1, &fragment))
        .is_err());
    assert_eq!(runtime.snapshot().live_bytes, baseline);
    assert!(engine
        .commit_streamed(&[s], 0, |_, sink| {
            sink.append(0, &fragment)?;
            Err("injected producer failure".into())
        })
        .is_err());
    assert_eq!(runtime.snapshot().live_bytes, baseline);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = engine.commit_streamed(&[s], 0, |_, sink| -> Result<()> {
            sink.append(0, &fragment)?;
            panic!("injected producer unwind");
        });
    }));
    assert!(panic.is_err());
    assert_eq!(runtime.snapshot().live_bytes, baseline);
    let before = runtime.snapshot();
    assert!(engine
        .commit_streamed(&[spec(20, 1, Extension::Base)], 0, |_, _| panic!(
            "must reject before producer"
        ))
        .is_err());
    assert_eq!(runtime.snapshot(), before);
}
