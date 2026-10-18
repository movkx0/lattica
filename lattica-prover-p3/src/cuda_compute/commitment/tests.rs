use super::*;
use crate::{
    config::{MyCompress, MyHash, Val},
    gpu_matrix::{RowOrder, GOLDILOCKS_MODULUS as P},
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::default_goldilocks_poseidon2_8;
use p3_symmetric::{CryptographicHasher, Permutation, PseudoCompressionFunction};

fn runtime(managed: usize, allocation: usize) -> Runtime {
    Runtime::new(
        &std::env::var("LATTICA_GPU_DEVICE_UUID").unwrap(),
        Limits {
            managed_bytes: managed,
            max_allocation_bytes: allocation,
            ..Limits::default()
        },
    )
    .unwrap()
}

fn raw_words(words: usize, seed: u64) -> Vec<u64> {
    (0..words)
        .map(|i| match i % 9 {
            0 => 0,
            1 => 1,
            2 => P - 1,
            3 => P,
            4 => u64::MAX,
            _ => (i as u64)
                .wrapping_mul(seed)
                .wrapping_add(0x9e37_79b9_7f4a_7c15),
        })
        .collect()
}

fn upload(
    runtime: &Runtime,
    log: u32,
    width: usize,
    extension: Extension,
    order: RowOrder,
    seed: u64,
) -> (Matrix, Vec<u64>) {
    let spec = MatrixSpec::new(log, width, extension, order, 7).unwrap();
    let raw = raw_words(spec.words(), seed);
    (runtime.upload_matrix(spec, &raw).unwrap(), raw)
}

fn reference_layers(rows: usize, fragments: &[&[u64]]) -> Vec<Vec<[Val; 4]>> {
    let perm = default_goldilocks_poseidon2_8();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm);
    let mut layers = vec![(0..rows)
        .map(|row| {
            hash.hash_iter(fragments.iter().flat_map(|fragment| {
                let width = fragment.len() / rows;
                fragment[row * width..(row + 1) * width]
                    .iter()
                    .map(|&v| Val::from_u64(v))
            }))
        })
        .collect::<Vec<_>>()];
    while layers.last().unwrap().len() > 1 {
        layers.push(
            layers
                .last()
                .unwrap()
                .chunks_exact(2)
                .map(|pair| compress.compress([pair[0], pair[1]]))
                .collect(),
        );
    }
    layers
}

fn flatten(layer: &[[Val; 4]]) -> Vec<u64> {
    layer
        .iter()
        .flatten()
        .map(|v| v.as_canonical_u64())
        .collect()
}

fn root_from_path(mut digest: [Val; 4], index: usize, path: &[u64]) -> [Val; 4] {
    let compress = MyCompress::new(default_goldilocks_poseidon2_8());
    for (level, sibling) in path.chunks_exact(4).enumerate() {
        let sibling = std::array::from_fn(|i| Val::from_u64(sibling[i]));
        digest = compress.compress(if index >> level & 1 == 0 {
            [digest, sibling]
        } else {
            [sibling, digest]
        });
    }
    digest
}

#[test]
fn commitment_layout_and_budgets_reject_before_allocation() {
    for log in 0..=31 {
        for cap in [0, 1, 6, 31, usize::MAX] {
            let layout = Layout::new(log, cap).unwrap();
            let height = 1usize << log;
            assert_eq!(layout.height, height);
            assert_eq!(layout.words, (2 * height - 1) * 4);
            assert_eq!(layout.path_len, (log as usize).saturating_sub(cap));
            assert!(layout.cap_first + layout.cap_words <= layout.words);
            assert_eq!(layout.cap_words, (height >> layout.path_len) * 4);
        }
    }
    for log in [32, 33, u32::MAX] {
        assert!(Layout::new(log, 0).is_err());
    }
    let limits = Limits {
        managed_bytes: 2048,
        max_allocation_bytes: 1024,
        ..Limits::default()
    };
    assert!(admit(&[128, 127], 8, limits).is_ok());
    assert!(admit(&[128, 128], 1, limits).is_err());
    for words in [0, 129, usize::MAX] {
        assert!(admit(&[words], 0, limits).is_err());
    }
    assert!(admit(&[1], usize::MAX, limits).is_err());
    assert!(host_words(2, 15).is_err());
    assert!(host_words(usize::MAX, usize::MAX).is_err());
    assert!(launch(0).is_err());
    assert!(launch(usize::MAX).is_err());
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_poseidon2_matches_independent_cpu_permutation() {
    let runtime = runtime(2 << 20, 1 << 20);
    let program = Commitments::new(&runtime).unwrap();
    let perm = default_goldilocks_poseidon2_8();
    for log in [0, 1, 7, 10] {
        let (input, raw) = upload(
            &runtime,
            log,
            8,
            Extension::Base,
            RowOrder::Natural,
            0xda94_2042_e4dd_58b5,
        );
        let before = runtime.snapshot();
        let output = program.permute(&input).unwrap();
        let after = runtime.snapshot();
        assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
        assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
        assert_eq!(after.completed_commands, before.completed_commands + 1);
        let expected: Vec<u64> = raw
            .chunks_exact(8)
            .flat_map(|words| {
                let mut state = std::array::from_fn(|i| Val::from_u64(words[i]));
                perm.permute_mut(&mut state);
                state.map(|v| v.as_canonical_u64())
            })
            .collect();
        assert_eq!(output.read(output.spec.bytes()).unwrap(), expected);
        assert_eq!(input.read(input.spec.bytes()).unwrap(), raw);
    }
    drop(program);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    assert_eq!(runtime.snapshot().modules, 0);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_salted_commitments_and_paths_match_cpu_in_both_row_orders() {
    let runtime = runtime(16 << 20, 8 << 20);
    let program = Commitments::new(&runtime).unwrap();
    for (log, width, extension) in [
        (0, 1, Extension::Base),
        (1, 2, Extension::Base),
        (5, 3, Extension::Base),
        (7, 4, Extension::Base),
        (8, 5, Extension::Base),
        (5, 7, Extension::Quadratic),
        (6, 9, Extension::Cubic),
        (9, 127, Extension::Base),
    ] {
        for order in [RowOrder::Natural, RowOrder::BitReversed] {
            let (input, values) = upload(
                &runtime,
                log,
                width,
                extension,
                order,
                0x1234_5678_9abc_def1,
            );
            let (salts, salt_words) = upload(
                &runtime,
                log,
                4,
                Extension::Base,
                order,
                0x3133_7bad_f00d_0001,
            );
            let height = 1usize << log;
            let layers = reference_layers(height, &[&values, &salt_words]);
            for cap_height in [0, 2, 6, log as usize + 1] {
                let before = runtime.snapshot();
                let tree = program.commit_salted(&input, &salts, cap_height).unwrap();
                let after = runtime.snapshot();
                assert_eq!(after.downloaded_bytes, before.downloaded_bytes);
                assert_eq!(after.uploaded_bytes, before.uploaded_bytes);
                assert_eq!(after.live_bytes - before.live_bytes, (2 * height - 1) * 32);
                let depth = tree.path_len();
                let cap = tree.cap(height * 32).unwrap();
                assert_eq!(cap, flatten(&layers[depth]), "log={log} width={width} extension={extension:?} order={order:?} cap={cap_height}");
                let indices = [height as u64 - 1, 0, height as u64 / 2, 0];
                let before = runtime.snapshot();
                let paths = program
                    .open(&tree, &indices, indices.len() * depth * 32)
                    .unwrap();
                let after = runtime.snapshot();
                assert_eq!(after.live_bytes, before.live_bytes);
                assert_eq!(
                    after.downloaded_bytes - before.downloaded_bytes,
                    paths.len() as u64 * 8
                );
                assert_eq!(
                    after.uploaded_bytes - before.uploaded_bytes,
                    if depth == 0 {
                        0
                    } else {
                        indices.len() as u64 * 8
                    }
                );
                for (q, &index) in indices.iter().enumerate() {
                    let path = &paths[q * depth * 4..(q + 1) * depth * 4];
                    for level in 0..depth {
                        assert_eq!(
                            &path[level * 4..(level + 1) * 4],
                            flatten(&[layers[level][(index as usize >> level) ^ 1]])
                        );
                    }
                    let expected = layers[depth][index as usize >> depth];
                    assert_eq!(
                        root_from_path(layers[0][index as usize], index as usize, path),
                        expected
                    );
                    if depth > 0 {
                        let mut altered = path.to_vec();
                        altered[0] ^= 1;
                        assert_ne!(
                            root_from_path(layers[0][index as usize], index as usize, &altered),
                            expected
                        );
                    }
                }
                let before = runtime.snapshot();
                assert!(tree.cap(cap.len() * 8 - 1).is_err());
                assert!(program.open(&tree, &[height as u64], usize::MAX).is_err());
                assert!(program
                    .open(&tree, &vec![0; MAX_QUERIES + 1], usize::MAX)
                    .is_err());
                if depth > 0 {
                    assert!(program.open(&tree, &[0], depth * 32 - 1).is_err());
                }
                assert_eq!(runtime.snapshot(), before);
            }
            assert_eq!(input.read(input.spec.bytes()).unwrap(), values);
            assert_eq!(salts.read(salts.spec.bytes()).unwrap(), salt_words);
        }
    }
    drop(program);
    assert_eq!(runtime.snapshot().live_bytes, 0);
    runtime.finish().unwrap();
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_fragment_absorption_preserves_partial_rates_and_tree_ownership() {
    let runtime = runtime(4 << 20, 2 << 20);
    let program = Commitments::new(&runtime).unwrap();
    for widths in [vec![1, 1, 1, 1], vec![3, 5, 2, 7], vec![9], vec![4, 8, 12]] {
        let inputs: Vec<_> = widths
            .iter()
            .map(|&width| {
                upload(
                    &runtime,
                    5,
                    width,
                    Extension::Base,
                    RowOrder::BitReversed,
                    width as u64 * 31337,
                )
            })
            .collect();
        let fragments: Vec<_> = inputs.iter().map(|(matrix, _)| matrix).collect();
        let raw: Vec<_> = inputs.iter().map(|(_, words)| words.as_slice()).collect();
        let expected = reference_layers(32, &raw);
        let tree = program.commit(&fragments, 0).unwrap();
        assert_eq!(tree.cap(32).unwrap(), flatten(expected.last().unwrap()));
    }
    let (input, raw) = upload(&runtime, 4, 1, Extension::Base, RowOrder::Natural, 31337);
    let expected = reference_layers(16, &[&raw]);
    let tree = program.commit(&[&input], 0).unwrap();
    let before = runtime.snapshot();
    assert!(program.commit(&[], 0).is_err());
    assert!(program.commit(&vec![&input; MAX_FRAGMENTS + 1], 0).is_err());
    assert!(program.commit_salted(&input, &input, 0).is_err());
    assert!(program.permute(&input).is_err());
    assert_eq!(runtime.snapshot(), before);
    let (different, _) = upload(&runtime, 4, 1, Extension::Base, RowOrder::BitReversed, 1);
    let before = runtime.snapshot();
    assert!(program.commit(&[&input, &different], 0).is_err());
    assert_eq!(runtime.snapshot(), before);
    drop(different);
    drop(input);
    drop(program);
    let clone = tree.clone();
    drop(tree);
    assert_eq!(runtime.snapshot().modules, 0);
    assert_eq!(runtime.snapshot().live_bytes, 31 * 32);
    assert_eq!(clone.cap(32).unwrap(), flatten(expected.last().unwrap()));
    drop(clone);
    assert_eq!(runtime.snapshot().live_bytes, 0);
}

#[test]
#[ignore = "requires CUDA and NVRTC; run serially"]
fn cuda_commitment_budget_rejection_preserves_existing_tree() {
    // The small tree fits; a new 32-row tree + sponge exceeds the allocation cap.
    let runtime = runtime(8192, 2040);
    let program = Commitments::new(&runtime).unwrap();
    let (small, _) = upload(&runtime, 1, 1, Extension::Base, RowOrder::Natural, 1);
    let tree = program.commit(&[&small], 0).unwrap();
    let cap = tree.cap(32).unwrap();
    let (large, _) = upload(&runtime, 5, 1, Extension::Base, RowOrder::Natural, 2);
    let before = runtime.snapshot();
    assert!(program.commit(&[&large], 0).is_err());
    assert_eq!(runtime.snapshot(), before);
    assert_eq!(tree.cap(32).unwrap(), cap);
    assert!(program.open(&tree, &[], 0).unwrap().is_empty());
}

#[test]
#[ignore = "requires pinned NVRTC; does not require a GPU"]
fn cuda_commitment_compiles_for_volta_and_blackwell() {
    for capability in [70, 120] {
        assert!(!super::super::compiler::compile(SOURCE, capability)
            .unwrap()
            .is_empty());
    }
}
