//! Actual OpenCL parity and rejected-operation checks. These tests require the
//! coordinator's exclusive GPU slot; compilation alone is not validation.
use super::super::*;
use p3_field::PrimeField64;
use p3_symmetric::Permutation;

const CANARY: u64 = 0xa591_7a2c_641e_09b3;

fn on_gpu(body: impl FnOnce(&mut Engine)) {
    let _shutdown = TestShutdownGuard;
    crate::block_v2::gpu_hash::initialize_quotient_test_engine(Limits {
        managed_bytes: 64 << 20,
        tile_bytes: 1 << 20,
        staging_bytes: 64 << 10,
    })
    .unwrap();
    let mut slot = ENGINE.get().unwrap().lock().unwrap();
    body(slot.as_mut().unwrap());
}

fn buffer(engine: &Engine, words: &[u64]) -> Allocation {
    let before = engine.accounting.lock().unwrap().live;
    // These raw kernel buffers use the same managed Allocation/Lease path as
    // engine scratch. They are not DeviceSession matrices, whose additional
    // device_live classification is private to the session implementation.
    let storage = allocation(
        &engine.pq,
        &engine.accounting,
        engine.limits,
        engine.max_alloc,
        words.len(),
        compute::flags::MEM_READ_WRITE,
    )
    .unwrap();
    assert_eq!(
        engine.accounting.lock().unwrap().live,
        before + words.len() * core::mem::size_of::<u64>()
    );
    let fence = engine.fence();
    storage.buffer.write(words).enq().unwrap();
    fence.finish().unwrap();
    storage
}

fn read(engine: &Engine, storage: &Allocation) -> Vec<u64> {
    let mut words = vec![0; storage.buffer.len()];
    let fence = engine.fence();
    storage.buffer.read(&mut words).enq().unwrap();
    fence.finish().unwrap();
    words
}

fn input_words(count: usize) -> Vec<u64> {
    const EDGE: [u64; 5] = [0, 1, 0xffff_ffff_0000_0000, 0xffff_ffff_0000_0001, u64::MAX];
    (0..count)
        .map(|i| {
            if i % 11 < EDGE.len() {
                EDGE[i % 11]
            } else {
                (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
            }
        })
        .collect()
}

fn cpu_compress(words: &[u64]) -> [u64; 4] {
    assert_eq!(words.len(), 8);
    let mut state = std::array::from_fn(|i| Val::from_u64(words[i]));
    p3_goldilocks::default_goldilocks_poseidon2_8().permute_mut(&mut state);
    std::array::from_fn(|i| state[i].as_canonical_u64())
}

#[test]
#[ignore = "requires actual OpenCL GPU; coordinator runs serially"]
fn direct_retained_kernel_matches_cpu_and_legacy_for_odd_counts_and_both_offset_orders() {
    on_gpu(|engine| {
        for n_out in [1usize, 3, 4, 15, 16, 17, 31, 33, 65] {
            let input = input_words(n_out * 8);
            let expected: Vec<_> = input.chunks_exact(8).flat_map(cpu_compress).collect();
            let source = buffer(engine, &input);
            let legacy = buffer(engine, &vec![CANARY; n_out * 4 + 8]);
            let fence = engine.fence();
            // SAFETY: exact source/output capacities; the deliberately padded
            // grid also checks the existing kernel's output-count guard.
            unsafe {
                engine
                    .pq
                    .kernel_builder("compress_layer")
                    .arg(&source.buffer)
                    .arg(&legacy.buffer)
                    .arg(n_out as u32)
                    .arg(&engine.constants[0].buffer)
                    .arg(&engine.constants[1].buffer)
                    .arg(&engine.constants[2].buffer)
                    .arg(&engine.constants[3].buffer)
                    .global_work_size(n_out + 7)
                    .build()
                    .unwrap()
                    .enq()
                    .unwrap();
            }
            fence.finish().unwrap();
            let baseline = read(engine, &legacy);
            assert_eq!(&baseline[..n_out * 4], expected);
            assert!(baseline[n_out * 4..].iter().all(|&word| word == CANARY));

            for destination_first in [false, true] {
                let (src, dst) = if destination_first {
                    (12 + n_out * 4 + 8, 12)
                } else {
                    (12, 12 + n_out * 8 + 8)
                };
                let mut original = vec![CANARY; (src + n_out * 8).max(dst + n_out * 4) + 12];
                original[src..src + input.len()].copy_from_slice(&input);
                let storage = buffer(engine, &original);
                let fence = engine.fence();
                // SAFETY: source/destination ranges are disjoint, nonzero,
                // and contained in this tiny buffer; no work item aliases a
                // source word. All argument conversions fit in u32.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("compress_retained_layer")
                        .arg(&storage.buffer)
                        .arg(src as u32)
                        .arg(dst as u32)
                        .arg(n_out as u32)
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .global_work_size(n_out + 7)
                        .build()
                        .unwrap()
                        .enq()
                        .unwrap();
                }
                fence.finish().unwrap();
                original[dst..dst + expected.len()].copy_from_slice(&expected);
                // Compare the entire backing, including original source,
                // inter-layer gaps, leading padding, and trailing padding.
                assert_eq!(read(engine, &storage), original);
            }
        }
    });
}

fn cpu_layers(leaves: &[u64]) -> Vec<Vec<u64>> {
    assert!(leaves.len() >= 4 && (leaves.len() / 4).is_power_of_two());
    let mut layers = vec![leaves.to_vec()];
    while layers.last().unwrap().len() > 4 {
        let next = layers
            .last()
            .unwrap()
            .chunks_exact(8)
            .flat_map(cpu_compress)
            .collect();
        layers.push(next);
    }
    layers
}

#[test]
#[ignore = "requires actual OpenCL GPU; coordinator runs serially"]
fn direct_retained_tree_caps_and_gpu_paths_match_independent_cpu_reference() {
    on_gpu(|engine| {
        for height in [1usize, 2, 4, 16, 64, 256] {
            let leaves: Vec<_> = input_words(height * 4)
                .into_iter()
                .map(|word| Val::from_u64(word).as_canonical_u64())
                .collect();
            let expected = cpu_layers(&leaves);
            for cap_height in [0usize, 1, 3, 8] {
                let layout = retained_layout(height, cap_height, engine.max_alloc).unwrap();
                let mut original = vec![CANARY; layout.elements];
                original[..leaves.len()].copy_from_slice(&leaves);
                let storage = buffer(engine, &original);
                let fence = engine.fence();
                let cap = engine
                    .finish_direct_retained_layers(&storage, height, layout)
                    .unwrap();
                fence.finish().unwrap();
                let actual = read(engine, &storage);
                let flattened: Vec<_> = expected.iter().flatten().copied().collect();
                assert_eq!(actual, flattened, "height={height} cap_height={cap_height}");
                let cap_words: Vec<_> = cap
                    .iter()
                    .flatten()
                    .map(|word| word.as_canonical_u64())
                    .collect();
                assert_eq!(cap_words, expected[layout.path_len]);

                for index in [0, height / 2, height - 1] {
                    let path = if layout.path_len == 0 {
                        Vec::new()
                    } else {
                        let output = buffer(engine, &vec![CANARY; layout.path_len * 4 + 8]);
                        let fence = engine.fence();
                        // SAFETY: exact complete tree, checked index/path
                        // geometry, and output contains every sibling digest.
                        unsafe {
                            engine
                                .pq
                                .kernel_builder("retained_merkle_path")
                                .arg(&storage.buffer)
                                .arg(&output.buffer)
                                .arg(height as u32)
                                .arg(index as u32)
                                .arg(layout.path_len as u32)
                                .global_work_size(layout.path_len + 3)
                                .build()
                                .unwrap()
                                .enq()
                                .unwrap();
                        }
                        fence.finish().unwrap();
                        let words = read(engine, &output);
                        assert!(words[layout.path_len * 4..]
                            .iter()
                            .all(|&word| word == CANARY));
                        words[..layout.path_len * 4].to_vec()
                    };
                    let mut current: [u64; 4] =
                        leaves[index * 4..index * 4 + 4].try_into().unwrap();
                    for (level, sibling) in path.chunks_exact(4).enumerate() {
                        let sibling_index = (index >> level) ^ 1;
                        assert_eq!(
                            sibling,
                            &expected[level][sibling_index * 4..sibling_index * 4 + 4]
                        );
                        let mut pair = [0; 8];
                        if (index >> level) & 1 == 0 {
                            pair[..4].copy_from_slice(&current);
                            pair[4..].copy_from_slice(sibling);
                        } else {
                            pair[..4].copy_from_slice(sibling);
                            pair[4..].copy_from_slice(&current);
                        }
                        current = cpu_compress(&pair);
                    }
                    let root_index = (index >> layout.path_len) * 4;
                    assert_eq!(current, cap_words[root_index..root_index + 4]);
                }
            }
        }
    });
}

#[test]
#[ignore = "requires actual OpenCL GPU; coordinator runs serially"]
fn direct_retained_rejected_geometry_preserves_backing_and_engine_counters() {
    on_gpu(|engine| {
        let height = 8usize;
        let layout = retained_layout(height, 1, engine.max_alloc).unwrap();
        let original = vec![CANARY; layout.elements];
        let storage = buffer(engine, &original);
        let mut wrong_cap = layout;
        wrong_cap.cap_offset += 4;
        let mut zero_cap = layout;
        zero_cap.cap_rows = 0;
        let mut wrong_elements = layout;
        wrong_elements.elements -= 4;
        for (rejected_height, rejected_layout) in [
            (height, wrong_cap),
            (height, zero_cap),
            (height, wrong_elements),
            (height - 1, layout),
        ] {
            let live = engine.accounting.lock().unwrap().live;
            let events = engine.timeline.events.len();
            let downloads = engine.stats.downloaded_bytes;
            let compression = engine.stats.compress_kernel_ns;
            let fence = engine.fence();
            assert!(engine
                .finish_direct_retained_layers(&storage, rejected_height, rejected_layout)
                .is_err());
            fence.finish().unwrap();
            assert_eq!(engine.accounting.lock().unwrap().live, live);
            assert_eq!(engine.timeline.events.len(), events);
            assert_eq!(engine.stats.downloaded_bytes, downloads);
            assert_eq!(engine.stats.compress_kernel_ns, compression);
            assert_eq!(read(engine, &storage), original);
        }
    });
}
