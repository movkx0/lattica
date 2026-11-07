//! Bounded leaf buffers. Worker times overlap and are not commitment wall time.
use super::*;
use crate::block_v2::compact_salts::{ROWS, ReplayCursor};
use p3_field::PackedFieldPow2;

#[derive(Default, Clone, Copy)]
pub(super) struct Metrics {
    pub replay_worker_ns: u128,
    pub pack_worker_ns: u128,
    pub hash_worker_ns: u128,
    pub replayed_rows: usize,
    pub buffer_sets: usize,
    pub scratch_peak_bytes: usize,
}
impl Metrics {
    pub fn add(mut self, other: Self) -> Self {
        self.replay_worker_ns += other.replay_worker_ns;
        self.pack_worker_ns += other.pack_worker_ns;
        self.hash_worker_ns += other.hash_worker_ns;
        self.replayed_rows += other.replayed_rows;
        self.buffer_sets += other.buffer_sets;
        self.scratch_peak_bytes = self.scratch_peak_bytes.max(other.scratch_peak_bytes);
        self
    }
}

fn pack_matrix<M: Matrix<Val>>(
    matrix: &M,
    first: usize,
    height: usize,
    packed: &mut [Packed],
    columns: usize,
    offset: usize,
    transpose: bool,
) {
    for batch in 0..height.div_ceil(Packed::WIDTH) {
        let row = batch * Packed::WIDTH;
        let valid = (height - row).min(Packed::WIDTH);
        let base = batch * columns + offset;
        let mut col = 0;
        if transpose && Packed::WIDTH == 4 && valid == 4 {
            // Dense PCS matrices lend slices; no source-row copies or unsafe casts.
            let source: [_; 4] =
                std::array::from_fn(|lane| matrix.row_slice(first + row + lane).unwrap());
            while col + 4 <= matrix.width() {
                let r: [Packed; 4] =
                    std::array::from_fn(|lane| Packed::from_fn(|c| source[lane][col + c]));
                let (a, b) = r[0].interleave(r[1], 1);
                let (c, d) = r[2].interleave(r[3], 1);
                let (c0, c2) = a.interleave(c, 2);
                let (c1, c3) = b.interleave(d, 2);
                packed[base + col..base + col + 4].copy_from_slice(&[c0, c1, c2, c3]);
                col += 4;
            }
        }
        for lane in 0..valid {
            for (c, value) in matrix
                .row(first + row + lane)
                .unwrap()
                .into_iter()
                .enumerate()
                .skip(col)
            {
                packed[base + c].as_slice_mut()[lane] = value;
            }
        }
    }
}

fn hash_rows(mmcs: &CpuMmcs, packed: &[Packed], columns: usize, out: &mut [Digest]) {
    let states = mmcs.hash_kernel.states();
    for (group, dest) in out.chunks_mut(Packed::WIDTH * states).enumerate() {
        let first = group * states * columns;
        let count = dest.len().div_ceil(Packed::WIDTH);
        let rows = &packed[first..first + count * columns];
        let mut digests = [[Packed::default(); 4]; 4];
        match mmcs.hash_kernel {
            HashKernel::Existing => digests[0] = mmcs.hash.hash_iter(rows.iter().copied()),
            HashKernel::Interleaved2 => {
                digests[..2].copy_from_slice(&interleaved::hash::<2>(rows, columns))
            }
            HashKernel::Interleaved4 => digests = interleaved::hash::<4>(rows, columns),
        }
        for (batch, dest) in dest.chunks_mut(Packed::WIDTH).enumerate() {
            for (lane, value) in dest.iter_mut().enumerate() {
                *value = std::array::from_fn(|col| digests[batch][col].as_slice()[lane]);
            }
        }
    }
}

fn pack_salts(salts: &[Val], height: usize, packed: &mut [Packed], columns: usize, offset: usize) {
    for batch in 0..height.div_ceil(Packed::WIDTH) {
        for col in 0..SALT_WIDTH {
            packed[batch * columns + offset + col] = Packed::from_fn(|lane| {
                let row = batch * Packed::WIDTH + lane;
                if row < height {
                    salts[row * SALT_WIDTH + col]
                } else {
                    Val::default()
                }
            });
        }
    }
}

pub(super) fn build<M: Matrix<Val>>(
    mmcs: &CpuMmcs,
    matrices: &[M],
    salts: &[Salts],
    group: &[usize],
) -> (Vec<Digest>, Metrics) {
    let height = matrices[group[0]].height();
    let columns: usize = group
        .iter()
        .map(|&i| matrices[i].width() + SALT_WIDTH)
        .sum();
    let threads = rayon::current_num_threads().max(1);
    let blocked = mmcs.commitment_path != CommitmentPath::Existing;
    let cursor_bytes = if blocked {
        group.len().checked_mul(size_of::<ReplayCursor>()).unwrap()
    } else {
        0
    };
    let allowance = (HASH_SCRATCH_BYTES / threads)
        .checked_sub(cursor_bytes)
        .expect("CPU replay cursors exceed scratch");
    let row_bytes = (columns + SALT_WIDTH)
        .checked_mul(size_of::<Val>())
        .unwrap();
    let available_rows = allowance / row_bytes;
    assert!(
        available_rows >= Packed::WIDTH,
        "CPU hash tile exceeds scratch allowance"
    );
    let rows =
        mmcs.tile_rows.min(available_rows).max(Packed::WIDTH) / Packed::WIDTH * Packed::WIDTH;
    if blocked {
        assert!(
            mmcs.variant == Variant::Combined && mmcs.tile_rows == TILE_ROWS && rows == TILE_ROWS
        );
    }
    let mut output = vec![[Val::default(); 4]; height];
    // Exactly bounded shards, with no per-thread cache or nested parallel work.
    let shard_rows = if blocked {
        height.div_ceil(ROWS).div_ceil(threads).max(1) * ROWS
    } else {
        rows
    };
    let metrics = output
        .par_chunks_mut(shard_rows)
        .enumerate()
        .map(|(shard, out)| {
            let first = shard * shard_rows;
            let buffer_rows = rows.min(out.len());
            let mut packed = vec![Packed::default(); buffer_rows.div_ceil(Packed::WIDTH) * columns];
            let mut salt_rows = vec![Val::default(); buffer_rows * SALT_WIDTH];
            let mut cursors = if blocked {
                group
                    .iter()
                    .map(|&i| match &salts[i] {
                        Salts::Replay(c) => c.cursor(first),
                        _ => unreachable!("blocked replay requires replay salts"),
                    })
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            let scratch = packed.capacity() * size_of::<Packed>()
                + salt_rows.capacity() * size_of::<Val>()
                + cursors.capacity() * size_of::<ReplayCursor>();
            assert!(scratch <= HASH_SCRATCH_BYTES / threads);
            let mut metrics = Metrics {
                buffer_sets: 1,
                scratch_peak_bytes: scratch * threads,
                ..Default::default()
            };
            for (tile, dest) in out.chunks_mut(rows).enumerate() {
                let start_row = first + tile * rows;
                if blocked && tile != 0 && start_row % ROWS == 0 {
                    for (cursor, &i) in cursors.iter_mut().zip(group) {
                        let Salts::Replay(checkpoints) = &salts[i] else {
                            unreachable!()
                        };
                        *cursor = checkpoints.cursor(start_row);
                    }
                }
                let count = dest.len();
                if count % Packed::WIDTH != 0 {
                    let tail = count / Packed::WIDTH * columns;
                    packed[tail..tail + columns].fill(Packed::default());
                }
                let mut column = 0;
                for (position, &index) in group.iter().enumerate() {
                    let timer = Instant::now();
                    let salt = &mut salt_rows[..count * SALT_WIDTH];
                    if blocked {
                        cursors[position].fill(salt);
                    } else {
                        salts[index].fill(start_row, salt);
                    }
                    metrics.replay_worker_ns += timer.elapsed().as_nanos();
                    metrics.replayed_rows += count
                        + if !blocked && matches!(salts[index], Salts::Replay(_)) {
                            start_row % ROWS
                        } else {
                            0
                        };
                    let timer = Instant::now();
                    if mmcs.variant.tiled() {
                        pack_matrix(
                            &matrices[index],
                            start_row,
                            count,
                            &mut packed,
                            columns,
                            column,
                            matches!(
                                mmcs.commitment_path,
                                CommitmentPath::Packed | CommitmentPath::Chunked
                            ),
                        );
                    } else {
                        for batch in 0..count.div_ceil(Packed::WIDTH) {
                            for col in 0..matrices[index].width() {
                                packed[batch * columns + column + col] = Packed::from_fn(|lane| {
                                    let row = batch * Packed::WIDTH + lane;
                                    if row < count {
                                        matrices[index].get(start_row + row, col).unwrap()
                                    } else {
                                        Val::default()
                                    }
                                });
                            }
                        }
                    }
                    pack_salts(
                        salt,
                        count,
                        &mut packed,
                        columns,
                        column + matrices[index].width(),
                    );
                    column += matrices[index].width() + SALT_WIDTH;
                    metrics.pack_worker_ns += timer.elapsed().as_nanos();
                }
                let timer = Instant::now();
                hash_rows(mmcs, &packed, columns, dest);
                metrics.hash_worker_ns += timer.elapsed().as_nanos();
            }
            metrics
        })
        .reduce(Metrics::default, Metrics::add);
    (output, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::default_goldilocks_poseidon2_8;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::SeedableRng;

    fn config(path: CommitmentPath, cap: usize) -> CpuMmcs {
        let perm = default_goldilocks_poseidon2_8();
        CpuMmcs::new(
            MyHash::new(perm.clone()),
            MyCompress::new(perm),
            cap,
            ChaCha20Rng::from_seed([9; 32]),
        )
        .with_variant(Variant::Combined)
        .with_commitment_path(path)
    }
    #[test]
    fn replay_blocks_remove_duplicate_rows_and_bound_buffer_owners() {
        rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
            .install(|| {
                let matrices = vec![RowMajorMatrix::new(vec![Val::ONE; 4096 * 5], 5)];
                let mut rng = ChaCha20Rng::from_seed([9; 32]);
                let salts = vec![Salts::Replay(Checkpoints::capture(&mut rng, 4096).unwrap())];
                let (expected, old) = build(
                    &config(CommitmentPath::Existing, 0),
                    &matrices,
                    &salts,
                    &[0],
                );
                assert_eq!(old.replayed_rows, 4096 * 5 / 2);
                for path in [
                    CommitmentPath::Replay,
                    CommitmentPath::Packed,
                    CommitmentPath::Chunked,
                ] {
                    let (actual, metrics) = build(&config(path, 0), &matrices, &salts, &[0]);
                    assert_eq!(actual, expected);
                    assert_eq!(metrics.replayed_rows, 4096);
                    assert_eq!(metrics.buffer_sets, 4);
                    assert!(metrics.scratch_peak_bytes <= HASH_SCRATCH_BYTES);
                }
            });
    }
    #[test]
    fn all_paths_match_caps_openings_and_continuing_rng_with_mixed_heights() {
        for threads in [1, 4] {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    for cap in [0, 2] {
                        for path in [
                            CommitmentPath::Replay,
                            CommitmentPath::Packed,
                            CommitmentPath::Chunked,
                        ] {
                            let reference = config(CommitmentPath::Existing, cap)
                                .with_variant(Variant::Reference);
                            let candidate = config(path, cap);
                            for heights in [[2048, 1024, 512, 4, 2], [1, 2, 4, 1024, 2048]] {
                                let matrices: Vec<_> = heights
                                    .iter()
                                    .zip([3, 5, 51, 94, 200])
                                    .map(|(&h, w)| {
                                        RowMajorMatrix::new(
                                            (0..h * w).map(|v| Val::from_usize(v + 7)).collect(),
                                            w,
                                        )
                                    })
                                    .collect();
                                let dimensions: Vec<_> =
                                    matrices.iter().map(Matrix::dimensions).collect();
                                let (expected, ed) = reference.commit(matrices.clone());
                                let (actual, ad) = candidate.commit(matrices);
                                assert_eq!(actual, expected);
                                for index in [0, 1, 255, 256, 1023, 1024, 2047] {
                                    let a = reference.open_batch(index, &ed);
                                    let b = candidate.open_batch(index, &ad);
                                    assert_eq!(a.opened_values, b.opened_values);
                                    assert_eq!(a.opening_proof, b.opening_proof);
                                    reference
                                        .verify_batch(
                                            &actual,
                                            &dimensions,
                                            index,
                                            BatchOpeningRef::new(
                                                &b.opened_values,
                                                &b.opening_proof,
                                            ),
                                        )
                                        .unwrap();
                                }
                            }
                        }
                    }
                });
        }
    }
}
