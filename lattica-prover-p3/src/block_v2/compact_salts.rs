//! Private replay checkpoints for compact MMCS salts. Nothing here is serialized
//! or shared between workers. Checkpoints preserve rejection sampling exactly.
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use crate::block_v2::worker_memory::MEMORY_BACKEND;
#[cfg(not(any(feature = "gpu", feature = "gpu-metal")))]
const MEMORY_BACKEND: &str = "cpu";
use crate::config::Val;
use p3_matrix::dense::RowMajorMatrix;
use rand::{
    Rng,
    distr::{Distribution, StandardUniform},
};
use rand_chacha::ChaCha20Rng;
use std::collections::BTreeMap;

pub(crate) const ROWS: usize = 1024;
const WIDTH: usize = 4;

// Deliberately no Debug, serde, seed accessor, or mutable replay API.
pub(crate) struct Checkpoints<R = ChaCha20Rng> {
    height: usize,
    states: Vec<R>,
}
/// A private, single-checkpoint replay cursor. No seed/state serialization.
pub(crate) struct ReplayCursor<R = ChaCha20Rng> {
    rng: R,
    remaining: usize,
}
impl<R: Rng> ReplayCursor<R> {
    pub(crate) fn fill(&mut self, output: &mut [Val]) {
        assert!(output.len() % WIDTH == 0 && output.len() / WIDTH <= self.remaining);
        for value in output.iter_mut() {
            *value = StandardUniform.sample(&mut self.rng);
        }
        self.remaining -= output.len() / WIDTH;
    }
}
impl<R: Rng + Clone> Checkpoints<R> {
    pub(crate) fn cursor(&self, first: usize) -> ReplayCursor<R> {
        assert!(first % ROWS == 0 && first < self.height);
        ReplayCursor {
            rng: self.states[first / ROWS].clone(),
            remaining: ROWS.min(self.height - first),
        }
    }
    /// Advance the original stream exactly once without allocating dense salts.
    pub(crate) fn capture(rng: &mut R, height: usize) -> Result<Self, String> {
        height
            .checked_mul(WIDTH)
            .filter(|n| *n > 0)
            .ok_or("salt matrix dimensions")?;
        let mut states = Vec::new();
        states
            .try_reserve_exact(height.div_ceil(ROWS))
            .map_err(|e| e.to_string())?;
        for row in 0..height {
            if row % ROWS == 0 {
                states.push(rng.clone());
            }
            for _ in 0..WIDTH {
                let _: Val = StandardUniform.sample(rng);
            }
        }
        Ok(Self { height, states })
    }

    /// One bounded tile; checkpoints include rejection-sampling state.
    pub(crate) fn fill(&self, first: usize, output: &mut [Val]) {
        assert!(output.len() % WIDTH == 0);
        let end = first
            .checked_add(output.len() / WIDTH)
            .expect("salt row overflow");
        assert!(end <= self.height);
        let mut row = first;
        while row < end {
            let block = row / ROWS;
            let mut rng = self.states[block].clone();
            for _ in block * ROWS..row {
                for _ in 0..WIDTH {
                    let _: Val = StandardUniform.sample(&mut rng);
                }
            }
            let stop = end.min((block + 1) * ROWS);
            for current in row..stop {
                for col in 0..WIDTH {
                    output[(current - first) * WIDTH + col] = StandardUniform.sample(&mut rng);
                }
            }
            row = stop;
        }
    }
    fn generate(rng: &mut R, height: usize) -> Result<(RowMajorMatrix<Val>, Self), String> {
        let elements = height
            .checked_mul(WIDTH)
            .filter(|n| *n > 0)
            .ok_or("salt matrix dimensions")?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(elements)
            .map_err(|e| e.to_string())?;
        let mut states = Vec::new();
        states
            .try_reserve_exact(height.div_ceil(ROWS))
            .map_err(|e| e.to_string())?;
        for row in 0..height {
            if row % ROWS == 0 {
                states.push(rng.clone());
            }
            for _ in 0..WIDTH {
                values.push(StandardUniform.sample(rng));
            }
        }
        Ok((RowMajorMatrix::new(values, WIDTH), Self { height, states }))
    }

    pub(crate) fn rows(&self, indices: &[usize]) -> Result<(Vec<Vec<Val>>, usize), String> {
        if indices.len() > 256 || indices.iter().any(|&i| i >= self.height) {
            return Err("salt query outside commitment or query bound".into());
        }
        // Process a block once, including unsorted and duplicate requests.
        let mut blocks = BTreeMap::<usize, BTreeMap<usize, Vec<usize>>>::new();
        for (position, &index) in indices.iter().enumerate() {
            blocks
                .entry(index / ROWS)
                .or_default()
                .entry(index)
                .or_default()
                .push(position);
        }
        let mut output = vec![Vec::new(); indices.len()];
        let mut regenerated = 0;
        for (block, requests) in blocks {
            let mut rng = self.states[block].clone();
            let end = *requests.last_key_value().unwrap().0;
            for row in block * ROWS..=end {
                let values: [Val; WIDTH] =
                    std::array::from_fn(|_| StandardUniform.sample(&mut rng));
                regenerated += 1;
                if let Some(positions) = requests.get(&row) {
                    for &position in positions {
                        output[position] = values.to_vec();
                    }
                }
            }
        }
        Ok((output, regenerated))
    }

    pub(crate) fn bytes(&self) -> usize {
        self.states.capacity() * size_of::<R>()
    }
}

pub(crate) enum SaltMatrix {
    Dense(RowMajorMatrix<Val>),
    Replay(Checkpoints),
}
impl SaltMatrix {
    pub(crate) fn height(&self) -> usize {
        match self {
            Self::Dense(m) => m.values.len() / WIDTH,
            Self::Replay(c) => c.height,
        }
    }
    pub(crate) fn rows(&self, indices: &[usize]) -> Result<Vec<Vec<Val>>, String> {
        if indices.len() > 256 || indices.iter().any(|&i| i >= self.height()) {
            return Err("salt query outside commitment or query bound".into());
        }
        match self {
            Self::Dense(m) => Ok(indices
                .iter()
                .map(|&i| m.values[i * WIDTH..(i + 1) * WIDTH].to_vec())
                .collect()),
            Self::Replay(c) => {
                let (rows, regenerated) = c.rows(indices)?;
                eprintln!(
                    "{MEMORY_BACKEND}_salt_queries pid={} height={} queries={} regenerated_rows={} checkpoint_bytes={}",
                    std::process::id(),
                    c.height,
                    indices.len(),
                    regenerated,
                    c.bytes()
                );
                Ok(rows)
            }
        }
    }
}

/// Temporary dense matrices stay alive through the commit's queue fence. The
/// caller consumes them only after that fence has drained (also on unwind).
pub(crate) fn generate(
    rng: &mut ChaCha20Rng,
    height: usize,
    matrices: usize,
    compact: bool,
) -> Result<(Vec<RowMajorMatrix<Val>>, Vec<Checkpoints>), String> {
    let mut dense = Vec::with_capacity(matrices);
    let mut replay = Vec::with_capacity(if compact { matrices } else { 0 });
    for _ in 0..matrices {
        if compact {
            let (matrix, checkpoints) = Checkpoints::generate(rng, height)?;
            dense.push(matrix);
            replay.push(checkpoints);
        } else {
            dense.push(RowMajorMatrix::rand(rng, height, WIDTH));
        }
    }
    Ok((dense, replay))
}

pub(crate) fn retain(dense: Vec<RowMajorMatrix<Val>>, replay: Vec<Checkpoints>) -> Vec<SaltMatrix> {
    if replay.is_empty() {
        return dense.into_iter().map(SaltMatrix::Dense).collect();
    }
    assert_eq!(dense.len(), replay.len());
    let dense_bytes: usize = dense
        .iter()
        .map(|m| m.values.len() * size_of::<Val>())
        .sum();
    let checkpoint_bytes: usize = replay.iter().map(Checkpoints::bytes).sum();
    for (matrix, saved) in dense.iter().zip(&replay) {
        assert_eq!(matrix.width, WIDTH);
        assert_eq!(matrix.values.len() / WIDTH, saved.height);
    }
    drop(dense);
    eprintln!(
        "{MEMORY_BACKEND}_salt_storage pid={} matrices={} dense_bytes={} checkpoint_bytes={} released_bytes={}",
        std::process::id(),
        replay.len(),
        dense_bytes,
        checkpoint_bytes,
        dense_bytes.saturating_sub(checkpoint_bytes)
    );
    replay.into_iter().map(SaltMatrix::Replay).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, TryRng};
    #[test]
    fn compact_salts_replay_boundaries_duplicates_and_rng_continuation() {
        let mut actual = ChaCha20Rng::seed_from_u64(72);
        let mut expected = actual.clone();
        for height in [1, 17, 1024, 1025, 2061, 8192] {
            let reference = RowMajorMatrix::<Val>::rand(&mut expected, height, WIDTH);
            let (dense, replay) = generate(&mut actual, height, 2, true).unwrap();
            let second = RowMajorMatrix::<Val>::rand(&mut expected, height, WIDTH);
            assert_eq!(dense[0], reference);
            assert_eq!(dense[1], second);
            let stores = retain(dense, replay);
            let indices = [
                height - 1,
                0,
                (height - 1).min(1023),
                (height - 1).min(1024),
                height - 1,
            ];
            for (store, original) in stores.iter().zip([&reference, &second]) {
                let rows = store.rows(&indices).unwrap();
                for (&i, row) in indices.iter().zip(&rows) {
                    assert_eq!(row, &original.values[i * 4..(i + 1) * 4]);
                }
                assert_eq!(store.rows(&indices).unwrap(), rows);
                assert!(store.rows(&[height]).is_err());
                assert!(store.rows(&vec![0; 257]).is_err());
                assert!(store.rows(&[]).unwrap().is_empty());
            }
            assert_eq!(actual.next_u64(), expected.next_u64());
        }
    }

    #[derive(Clone)]
    struct Rejecting {
        calls: u64,
    }
    impl TryRng for Rejecting {
        type Error = std::convert::Infallible;
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.calls += 1;
            Ok(if self.calls % 7 == 0 {
                u64::MAX
            } else {
                self.calls
            })
        }
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
            for b in bytes {
                *b = self.try_next_u64()? as u8;
            }
            Ok(())
        }
    }
    #[test]
    fn compact_salts_replay_preserves_rejection_draws_and_releases_dense_storage() {
        let mut rng = Rejecting { calls: 0 };
        let mut reference = rng.clone();
        let expected = RowMajorMatrix::<Val>::rand(&mut reference, 2051, 4);
        let (matrix, checkpoints) = Checkpoints::generate(&mut rng, 2051).unwrap();
        assert_eq!(matrix, expected);
        assert_eq!(rng.calls, reference.calls);
        let mut captured_rng = Rejecting { calls: 0 };
        let captured = Checkpoints::capture(&mut captured_rng, 2051).unwrap();
        assert_eq!(captured_rng.calls, reference.calls);
        for (first, count) in [(0, 2051), (1023, 5), (1024, 1027), (2050, 1)] {
            let mut replayed = vec![Val::default(); count * WIDTH];
            captured.fill(first, &mut replayed);
            assert_eq!(
                &replayed,
                &expected.values[first * WIDTH..(first + count) * WIDTH]
            );
        }
        let indices = [2050, 1024, 1023, 1024, 0];
        let (rows, regenerated) = checkpoints.rows(&indices).unwrap();
        for (&i, row) in indices.iter().zip(&rows) {
            assert_eq!(row, &expected.values[i * 4..(i + 1) * 4]);
        }
        assert_eq!(regenerated, 1024 + 1 + 3);
        assert!(checkpoints.bytes() < matrix.values.len() * size_of::<Val>() / 100);
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (dense, replay) = generate(&mut rng, 8192, 1, true).unwrap();
        let dense_bytes = dense[0].values.len() * 8;
        let storage = retain(dense, replay);
        let SaltMatrix::Replay(saved) = &storage[0] else {
            panic!("dense salt retention");
        };
        assert!(saved.bytes() < dense_bytes / 50);
    }

    #[test]
    fn checkpoint_cursor_preserves_rejections_across_tiles_and_rejects_overrun() {
        let mut rng = Rejecting { calls: 0 };
        let mut expected = rng.clone();
        let dense = RowMajorMatrix::<Val>::rand(&mut expected, 2051, WIDTH);
        let checkpoints = Checkpoints::capture(&mut rng, 2051).unwrap();
        for first in (0..2051).step_by(ROWS) {
            let mut cursor = checkpoints.cursor(first);
            for row in (first..(first + ROWS).min(2051)).step_by(256) {
                let count = 256.min(2051 - row).min(first + ROWS - row);
                let mut values = vec![Val::default(); count * WIDTH];
                cursor.fill(&mut values);
                assert_eq!(values, dense.values[row * WIDTH..(row + count) * WIDTH]);
            }
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cursor.fill(&mut [Val::default(); WIDTH]);
                }))
                .is_err()
            );
        }
        assert_eq!(rng.next_u64(), expected.next_u64());
        assert!(std::panic::catch_unwind(|| checkpoints.cursor(256)).is_err());
    }
}
