//! Private replay recipes retain a key reference and exact stream boundaries.
//! Reproduction never advances or locks the active random cursor.
use super::*;
use crate::gpu_matrix::GOLDILOCKS_MODULUS;
use crate::gpu_random::{validate_salt_replay_spec, MAX_REPLAY_MATRICES};

const MAX_QUERIES: usize = 4096;
mod public;
pub(crate) use public::{PublicPreprocessingSalts, PublicReplaySalts};

/// Private proof material: no serialization or conversion to public salts.
/// Each recipe consumes a bounded RNG state slot until its last owner retires.
pub(crate) struct ReplaySalts {
    random: DeviceRandom,
    start: u128,
    end: u128,
    spec: MatrixSpec,
    _slot: Slot,
}
impl std::fmt::Debug for ReplaySalts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CudaReplaySalts(<redacted>)")
    }
}

impl DeviceRandom {
    pub(crate) fn preflight_salt_recipes(
        &self,
        specs: &[MatrixSpec],
        pending: &[usize],
    ) -> Result<()> {
        if specs.is_empty() || specs.len() > MAX_REPLAY_MATRICES {
            return Err("salt replay batch requires 1..256 matrices".into());
        }
        for &spec in specs {
            validate_salt_replay_spec(spec)?;
        }
        if self
            .0
            .slot
            .0
            .states
            .load(Ordering::Acquire)
            .checked_add(specs.len())
            .is_none_or(|n| n > MAX_STREAM_STATES)
        {
            return Err("CUDA salt replay exceeds the stream-state allowance".into());
        }
        self.preflight_salt_replay(
            &specs.iter().map(|s| s.words()).collect::<Vec<_>>(),
            pending,
        )
    }

    pub(crate) fn preflight_salt_replay(
        &self,
        requests: &[usize],
        pending: &[usize],
    ) -> Result<()> {
        let position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.preflight_at(*position, requests, pending, false)
    }

    /// Capture boundaries and advance the active stream under the same lock.
    pub(crate) fn sample_salt_with_replay(
        &self,
        spec: MatrixSpec,
    ) -> Result<(Matrix, ReplaySalts)> {
        validate_salt_replay_spec(spec)?;
        let mut position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.check_live()?;
        // Reserve recipe metadata before consuming randomness.
        let slot = self.0.slot.0.slot()?;
        self.draw_salt_at(&mut position, spec, slot)
    }

    fn draw_salt_at(
        &self,
        position: &mut u128,
        spec: MatrixSpec,
        slot: Slot,
    ) -> Result<(Matrix, ReplaySalts)> {
        let start = *position;
        let samples = self.sample_at(position, spec.words(), Fault::None)?;
        let recipe = ReplaySalts {
            random: self.clone(),
            start,
            end: *position,
            spec,
            _slot: slot,
        };
        Ok((
            Matrix {
                spec,
                buffer: samples.storage,
            },
            recipe,
        ))
    }

    /// Discover exact rejection boundaries while retaining no sample matrices.
    /// Same-height convenience form; draw ordering is shared with mixed batches.
    pub(crate) fn prepare_salt_replay(
        &self,
        spec: MatrixSpec,
        count: usize,
    ) -> Result<Vec<ReplaySalts>> {
        validate_salt_replay_spec(spec)?;
        if count == 0 || count > MAX_REPLAY_MATRICES {
            return Err("salt replay batch requires 1..256 matrices".into());
        }
        self.prepare_salt_replay_specs(&vec![spec; count])
    }

    /// Capture a mixed-height batch in caller order, before Merkle height
    /// sorting. The cursor lock spans every matrix, and all recipe slots are
    /// admitted before the first draw.
    pub(crate) fn prepare_salt_replay_specs(
        &self,
        specs: &[MatrixSpec],
    ) -> Result<Vec<ReplaySalts>> {
        let count = specs.len();
        if count == 0 || count > MAX_REPLAY_MATRICES {
            return Err("salt replay batch requires 1..256 matrices".into());
        }
        for &spec in specs {
            validate_salt_replay_spec(spec)?;
        }
        let mut position = self
            .0
            .position
            .lock()
            .map_err(|_| "CUDA random cursor poisoned")?;
        self.preflight_at(
            *position,
            &specs.iter().map(|s| s.words()).collect::<Vec<_>>(),
            &[],
            false,
        )?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(super::super::error)?;
        let mut recipes = Vec::new();
        recipes
            .try_reserve_exact(count)
            .map_err(super::super::error)?;
        for _ in 0..count {
            slots.push(self.0.slot.0.slot()?);
        }
        let mut attempt = Attempt {
            failed: &self.0.failed,
            started: false,
            complete: false,
        };
        for (slot, &spec) in slots.into_iter().zip(specs) {
            let (samples, recipe) = self.draw_salt_at(&mut position, spec, slot)?;
            attempt.started = true;
            drop(samples);
            recipes.push(recipe);
        }
        self.check_live()?;
        attempt.complete = true;
        Ok(recipes)
    }
}

impl ReplaySalts {
    // Only the fixed-public-seed wrapper may fork failure ownership. These are
    // deliberately private to random: ordinary private snapshots still share
    // their original proof family's failure flag.
    fn preflight_public_lease(&self) -> Result<()> {
        self.random.check_live()?;
        if self
            .random
            .0
            .slot
            .0
            .states
            .load(Ordering::Acquire)
            .checked_add(2)
            .is_none_or(|n| n > MAX_STREAM_STATES)
        {
            return Err("CUDA public salt lease exceeds stream-state allowance".into());
        }
        Ok(())
    }

    fn public_lease(&self) -> Result<Self> {
        self.preflight_public_lease()?;
        let source = &self.random.0;
        let random = DeviceRandom(Arc::new(Stream {
            key: source.key.clone(),
            stream: source.stream,
            position: Mutex::new(self.start),
            failed: Arc::new(AtomicBool::new(false)),
            slot: source.slot.0.slot()?,
        }));
        Ok(Self {
            random,
            start: self.start,
            end: self.end,
            spec: self.spec,
            _slot: source.slot.0.slot()?,
        })
    }

    pub(crate) fn spec(&self) -> MatrixSpec {
        self.spec
    }

    pub(in crate::cuda_compute) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        if !Arc::ptr_eq(&self.random.0.slot.0.runtime.state, &runtime.state) {
            return Err("CUDA salt replay belongs to another runtime".into());
        }
        self.random.check_live()
    }

    pub(in crate::cuda_compute) fn preflight(&self, pending: &[usize]) -> Result<()> {
        self.random
            .preflight_at(self.start, &[self.spec.words()], pending, false)
    }

    pub(crate) fn materialize(&self) -> Result<Matrix> {
        self.materialize_with_fault(Fault::None)
    }

    fn materialize_with_fault(&self, fault: Fault) -> Result<Matrix> {
        let mut position = self.start;
        let samples = self
            .random
            .sample_at(&mut position, self.spec.words(), fault)?;
        if position != self.end {
            self.random.retire();
            return Err("CUDA salt replay changed its original rejection boundary".into());
        }
        Ok(Matrix {
            spec: self.spec,
            buffer: samples.storage,
        })
    }

    /// Once replayed private material is consumed, downstream errors or unwinds
    /// retire the same proof family, including escaped aliases.
    pub(in crate::cuda_compute) fn with_materialized<T>(
        &self,
        f: impl FnOnce(&Matrix) -> Result<T>,
    ) -> Result<T> {
        let salts = self.materialize()?;
        let mut attempt = Attempt {
            failed: &self.random.0.failed,
            started: true,
            complete: false,
        };
        let result = f(&salts)?;
        self.random.check_live()?;
        attempt.complete = true;
        Ok(result)
    }

    /// Only requested public proof rows are downloaded; preserve order and
    /// duplicates of physical (already bit-reversed) row indices.
    pub(crate) fn query_rows(&self, indices: &[u64], host_bytes: usize) -> Result<Vec<u64>> {
        self.random.check_live()?;
        if indices.len() > MAX_QUERIES || indices.iter().any(|&row| row >= self.spec.rows() as u64)
        {
            return Err("CUDA salt query exceeds bounded physical rows".into());
        }
        let words = indices.len() * 4;
        if words * 8 > host_bytes {
            return Err("CUDA salt query exceeds host output allowance".into());
        }
        if indices.is_empty() {
            return Ok(Vec::new());
        }
        self.preflight(&[indices.len() * 8, words * 8])?;
        let mut output = Vec::new();
        output
            .try_reserve_exact(words)
            .map_err(super::super::error)?;
        output.resize(words, 0);
        let engine = &self.random.0.slot.0;
        let queries = engine.runtime.allocate(indices.len())?;
        let gathered = engine.runtime.allocate(words)?;
        queries.write(0, indices)?;
        self.with_materialized(|salts| {
            // Validated indices address four words inside each physical row;
            // both allocations are distinct and owned by the replay runtime.
            unsafe {
                engine.gather.launch(
                    Launch {
                        blocks: words.div_ceil(128) as u32,
                        threads: 128,
                        shared_bytes: 0,
                    },
                    &[
                        Argument::Buffer(&salts.buffer),
                        Argument::Buffer(&queries),
                        Argument::Buffer(&gathered),
                        Argument::U32(indices.len() as u32),
                    ],
                )?
            }
            .finish()?;
            gathered.read(0, &mut output)?;
            if output.iter().any(|&word| word >= GOLDILOCKS_MODULUS) {
                return Err("CUDA salt query returned a noncanonical field word".into());
            }
            Ok(output)
        })
    }
}

#[cfg(test)]
mod tests;
