//! Small independent CPU oracles. These require actual NVIDIA execution and
//! must not be reported as passing merely because they compile on a CPU host.
use super::super::*;
use crate::config::Val;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_symmetric::Permutation;

fn on_gpu(body: impl FnOnce(&mut Engine)) {
    let _shutdown = TestShutdownGuard;
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let mut slot = ENGINE.get().unwrap().lock().unwrap();
    let engine = slot.as_mut().unwrap();
    assert!(
        engine.nvidia_shuffle,
        "these tests require NVIDIA SM7+ with 32-lane warps"
    );
    body(engine);
}

// Test buffers are tiny and do not escape the exclusively borrowed engine.
fn buffer(engine: &Engine, words: &[u64]) -> Buffer<u64> {
    Buffer::builder()
        .queue(engine.pq.queue().clone())
        .flags(compute::flags::MEM_READ_WRITE)
        .len(words.len())
        .copy_host_slice(words)
        .build()
        .unwrap()
}
fn read(buffer: &Buffer<u64>) -> Vec<u64> {
    let mut result = vec![0; buffer.len()];
    buffer.read(&mut result).enq().unwrap();
    result
}
fn words(count: usize) -> Vec<u64> {
    let edge = [0, 1, 0xffff_ffff_0000_0000, 0xffff_ffff_0000_0001, u64::MAX];
    (0..count)
        .map(|i| {
            if i % 11 < edge.len() {
                edge[i % 11]
            } else {
                (i as u64).wrapping_mul(0x9e3779b97f4a7c15)
            }
        })
        .collect()
}
fn cpu_leaf(input: &[u64]) -> [u64; 4] {
    let perm = p3_goldilocks::default_goldilocks_poseidon2_8();
    let mut state = [Val::ZERO; 8];
    for block in input.chunks(4) {
        for (i, word) in block.iter().enumerate() {
            state[i] = Val::from_u64(*word);
        }
        perm.permute_mut(&mut state);
    }
    std::array::from_fn(|i| state[i].as_canonical_u64())
}

#[test]
#[ignore = "requires NVIDIA GPU; run serially with gpu-tuning enabled"]
fn gpu_tuning_commitments_match_cpu_across_warps_and_stream_boundaries() {
    on_gpu(|engine| {
        engine.tuning.commitment = true;
        for rows in [1usize, 3, 4, 15, 16, 17, 31, 33] {
            for width in [1usize, 3, 4, 5, 8, 17, 98, 200] {
                let input = words(rows * width);
                let expected: Vec<u64> = input.chunks(width).flat_map(cpu_leaf).collect();
                let source = buffer(engine, &input);
                let output = buffer(engine, &vec![99; (rows + 5) * 4]);
                let mut kernel = engine.commitment_builder("leaf_hash", rows).unwrap();
                kernel
                    .arg(&source)
                    .arg(&output)
                    .arg(2u32)
                    .arg(rows as u32)
                    .arg(width as u32);
                for c in &engine.constants {
                    kernel.arg(&c.buffer);
                }
                unsafe {
                    kernel.build().unwrap().cmd().enq().unwrap();
                }
                let actual = read(&output);
                assert_eq!(&actual[..8], &[99; 8]);
                assert_eq!(
                    &actual[8..8 + rows * 4],
                    expected,
                    "rows={rows} width={width}"
                );
                assert!(actual[8 + rows * 4..].iter().all(|&x| x == 99));

                // Irregular tiles exercise every rate offset; matrix/tile edges
                // are not sponge boundaries. Row offset also covers banded input.
                let state = buffer(engine, &vec![0; (rows + 2) * 8]);
                let mut column = 0;
                let mut rate = 0;
                for tile in [1usize, 2, 5, 3, width] {
                    let count = tile.min(width - column);
                    if count == 0 {
                        break;
                    }
                    let tile_words: Vec<_> = input
                        .chunks(width)
                        .flat_map(|row| row[column..column + count].iter().copied())
                        .collect();
                    let tile_input = buffer(engine, &tile_words);
                    let mut kernel = engine.commitment_builder("lde_absorb", rows).unwrap();
                    kernel
                        .arg(&tile_input)
                        .arg(&state)
                        .arg(2u32)
                        .arg(rows as u32)
                        .arg(count as u32)
                        .arg(rate as u32);
                    for c in &engine.constants {
                        kernel.arg(&c.buffer);
                    }
                    unsafe {
                        kernel.build().unwrap().cmd().enq().unwrap();
                    }
                    engine.pq.queue().finish().unwrap();
                    column += count;
                    rate = (rate + count) % 4;
                }
                assert_eq!(column, width);
                let state_words = read(&state);
                assert_eq!(&state_words[..16], &[0; 16]);
                let compact = buffer(engine, &state_words[16..]);
                let finalized = buffer(engine, &vec![99; (rows + 3) * 4]);
                let mut kernel = engine
                    .commitment_builder("lde_leaf_finalize", rows)
                    .unwrap();
                kernel
                    .arg(&compact)
                    .arg(&finalized)
                    .arg(rows as u32)
                    .arg(rate as u32);
                for c in &engine.constants {
                    kernel.arg(&c.buffer);
                }
                unsafe {
                    kernel.build().unwrap().cmd().enq().unwrap();
                }
                let actual = read(&finalized);
                assert_eq!(&actual[..rows * 4], expected);
                assert!(actual[rows * 4..].iter().all(|&x| x == 99));
            }
            let input = words(rows * 8);
            let source = buffer(engine, &input);
            let output = buffer(engine, &vec![99; (rows + 3) * 4]);
            let mut kernel = engine.commitment_builder("compress_layer", rows).unwrap();
            kernel.arg(&source).arg(&output).arg(rows as u32);
            for c in &engine.constants {
                kernel.arg(&c.buffer);
            }
            unsafe {
                kernel.build().unwrap().cmd().enq().unwrap();
            }
            let expected: Vec<_> = input
                .chunks(8)
                .flat_map(|row| {
                    let mut state: [Val; 8] = std::array::from_fn(|i| Val::from_u64(row[i]));
                    p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut state);
                    std::array::from_fn::<_, 4, _>(|i| state[i].as_canonical_u64())
                })
                .collect();
            let actual = read(&output);
            assert_eq!(&actual[..rows * 4], expected);
            assert!(actual[rows * 4..].iter().all(|&x| x == 99));
        }
    });
}

#[test]
#[ignore = "requires NVIDIA GPU; run serially with gpu-tuning enabled"]
fn gpu_tuning_shared_scales_match_cpu_and_zero_padding() {
    on_gpu(|engine| {
        for width in [1usize, 3, 98, 200] {
            let (input_rows, output_rows) = (17usize, 33usize);
            let input = words(input_rows * width);
            let coefficients = buffer(engine, &input);
            let parameters = buffer(engine, &[Val::from_u64(17).inverse().as_canonical_u64(), 7]);
            let output = buffer(engine, &vec![99; output_rows * width + 5]);
            unsafe {
                engine
                    .pq
                    .kernel_builder("device_transform_scale_shared")
                    .arg(&coefficients)
                    .arg(&output)
                    .arg(&parameters)
                    .arg(width as u32)
                    .arg(input_rows as u32)
                    .arg(output_rows as u32)
                    .arg_local::<u64>(256)
                    .global_work_size((output_rows * width).div_ceil(256) * 256)
                    .local_work_size(256)
                    .build()
                    .unwrap()
                    .cmd()
                    .enq()
                    .unwrap();
            }
            let actual = read(&output);
            for i in 0..output_rows * width {
                let expected = if i < input.len() {
                    Val::from_u64(input[i])
                        * Val::from_u64(17).inverse()
                        * Val::from_u64(7).exp_u64((i / width) as u64)
                } else {
                    Val::ZERO
                };
                assert_eq!(
                    actual[i],
                    expected.as_canonical_u64(),
                    "width={width} i={i}"
                );
            }
            assert_eq!(&actual[output_rows * width..], &[99; 5]);
        }
    });
}

#[test]
#[ignore = "requires NVIDIA GPU; run serially with gpu-tuning enabled"]
fn gpu_tuning_ntt_powers_match_independent_cpu_dft() {
    on_gpu(|engine| {
        for log_rows in [1u32, 3, 6, 8] {
            let rows = 1usize << log_rows;
            for width in [1usize, 3, 8] {
                let input = words(rows * width);
                for inverse in [false, true] {
                    let roots: Vec<_> = (1..=log_rows)
                        .map(|log| {
                            let root = Val::two_adic_generator(log as usize);
                            if inverse {
                                root.inverse()
                            } else {
                                root
                            }
                        })
                        .collect();
                    let root = roots[roots.len() - 1];
                    let roots = buffer(
                        engine,
                        &roots
                            .iter()
                            .map(|x| x.as_canonical_u64())
                            .collect::<Vec<_>>(),
                    );
                    let scale = if inverse {
                        Val::from_usize(rows).inverse()
                    } else {
                        Val::ONE
                    };
                    let shift = if inverse { Val::from_u64(7) } else { Val::ONE };
                    let expected: Vec<_> = (0..rows * width)
                        .map(|i| {
                            let (row, col) = (i / width, i % width);
                            let mut sum = Val::ZERO;
                            for k in 0..rows {
                                sum += Val::from_u64(input[k * width + col])
                                    * root.exp_u64((k * row) as u64);
                            }
                            (sum * scale * shift.exp_u64(row as u64)).as_canonical_u64()
                        })
                        .collect();
                    // Both one-group transforms and multiple stages with
                    // nonzero row origins/outer exponents exercise tuned powers.
                    for tile_stages in [log_rows, log_rows.div_ceil(2)] {
                        for bit_reversed in [false, true] {
                            let mut initial = input.clone();
                            initial.extend_from_slice(&[99; 5]);
                            let mut source = buffer(engine, &initial);
                            let mut output = buffer(engine, &vec![99; rows * width + 5]);
                            for stage in (0..log_rows).step_by(tile_stages as usize) {
                                let count = tile_stages.min(log_rows - stage);
                                let tile_rows = 1usize << count;
                                let group = (tile_rows / 2).clamp(32, 256);
                                let last = stage + count == log_rows;
                                unsafe {
                                    engine
                                        .pq
                                        .kernel_builder("ntt_tile_cached_tuned")
                                        .arg(&source)
                                        .arg(&output)
                                        .arg(width as u32)
                                        .arg(rows as u32)
                                        .arg(stage)
                                        .arg(count)
                                        .arg(0u32)
                                        .arg(u32::from(stage == 0))
                                        .arg(log_rows)
                                        .arg(1u32)
                                        .arg(u32::from(last && bit_reversed))
                                        .arg(if last { scale.as_canonical_u64() } else { 1u64 })
                                        .arg(if last { shift.as_canonical_u64() } else { 1u64 })
                                        .arg(&roots)
                                        .arg_local::<u64>(tile_rows)
                                        .arg_local::<u64>(
                                            tile_rows / 2 + count as usize + tile_rows,
                                        )
                                        .global_work_size((rows >> count) * width * group)
                                        .local_work_size(group)
                                        .build()
                                        .unwrap()
                                        .cmd()
                                        .enq()
                                        .unwrap();
                                }
                                std::mem::swap(&mut source, &mut output);
                            }
                            let actual = read(&source);
                            for row in 0..rows {
                                let stored = if bit_reversed {
                                    row.reverse_bits() >> (usize::BITS - log_rows)
                                } else {
                                    row
                                };
                                assert_eq!(
                                    &actual[stored * width..(stored + 1) * width],
                                    &expected[row * width..(row + 1) * width]
                                );
                            }
                            assert_eq!(&actual[rows * width..], &[99; 5]);
                        }
                    }
                }
            }
        }
    });
}

#[test]
#[ignore = "requires V100 OpenCL GPU; run serially with gpu-tuning enabled"]
fn gpu_tuning_expanded_ntt_cache_matches_cpu_for_orders_scaling_and_in_place_stages() {
    use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
    use p3_matrix::{dense::RowMajorMatrix, Matrix};
    on_gpu(|engine| {
        let expanded =
            crate::gpu::ntt_cache::local_word_limit(engine.pq.device(), engine.pq.program())
                .unwrap();
        assert!(
            expanded > 4096,
            "this test must exercise the expanded V100 cache"
        );
        let saved_tuning = engine.tuning;
        engine.tuning.tables = false;
        engine.tuning.ntt = false;
        for (log_rows, width) in [
            (1u32, 1usize),
            (5, 3),
            (8, 15),
            (8, 16),
            (8, 17),
            (12, 1),
            (14, 16),
            (16, 17),
            (18, 3),
        ] {
            let rows = 1usize << log_rows;
            let input = words(rows * width);
            for inverse in [false, true] {
                let values = RowMajorMatrix::new(
                    input.iter().map(|&word| Val::from_u64(word)).collect(),
                    width,
                );
                let cpu = Radix2DitParallel::<Val>::default();
                let expected = if inverse {
                    cpu.idft_batch(values)
                } else {
                    cpu.dft_batch(values).to_row_major_matrix()
                };
                let roots = buffer(
                    engine,
                    &(1..=log_rows)
                        .map(|log| {
                            let root = Val::two_adic_generator(log as usize);
                            (if inverse { root.inverse() } else { root }).as_canonical_u64()
                        })
                        .collect::<Vec<_>>(),
                );
                let scale = if inverse {
                    Val::from_usize(rows).inverse()
                } else {
                    Val::ONE
                };
                for shift in [Val::ONE, Val::from_u64(7)] {
                    let expected: Vec<_> = expected
                        .values
                        .iter()
                        .enumerate()
                        .map(|(i, &value)| {
                            (value * shift.exp_u64((i / width) as u64)).as_canonical_u64()
                        })
                        .collect();
                    for local_words in [4096, 4232, 4360, expanded] {
                        engine.ntt_local_words = local_words;
                        for shared in [false, true] {
                            engine.tuning.ntt_shared = shared;
                            for reversed in [false, true] {
                                let mut initial = input.clone();
                                initial.extend_from_slice(&[99; 5]);
                                let source = buffer(engine, &initial);
                                let output = buffer(engine, &vec![99; rows * width + 5]);
                                let in_output = engine
                                    .lde_ntt(
                                        &source,
                                        &output,
                                        &roots,
                                        inverse,
                                        rows,
                                        width,
                                        scale.as_canonical_u64(),
                                        shift.as_canonical_u64(),
                                        true,
                                        reversed,
                                        false,
                                        None,
                                    )
                                    .unwrap();
                                let actual = read(if in_output { &output } else { &source });
                                for row in 0..rows {
                                    let stored = if reversed {
                                        row.reverse_bits() >> (usize::BITS - log_rows)
                                    } else {
                                        row
                                    };
                                    assert_eq!(&actual[stored * width..(stored + 1) * width],
                                    &expected[row * width..(row + 1) * width],
                                    "log={log_rows} width={width} inverse={inverse} reversed={reversed} local={local_words} shared={shared}");
                                }
                                assert_eq!(&actual[rows * width..], &[99; 5]);
                            }
                        }
                    }
                }
            }
        }
        engine.ntt_local_words = expanded;
        engine.tuning = saved_tuning;
    });
}
