//! Public preprocessing salts have a fixed public seed. No private stream or
//! arbitrary device matrix can be converted into this reusable storage type.
use super::*;
use rand::SeedableRng;

#[derive(Clone)]
pub struct PublicSalts {
    storage: Arc<SecretAllocation>,
    context: Arc<JobLease>,
    spec: MatrixSpec,
}

#[derive(Clone)]
pub(crate) struct PublicSaltStream {
    random: DeviceRandom,
    batch: Arc<Mutex<()>>,
}

fn spec(height: usize) -> Result<MatrixSpec, String> {
    if !height.is_power_of_two() || height > 1 << 25 {
        return Err("public salt height must be a power of two in 1..2^25".into());
    }
    MatrixSpec::new(height.ilog2(), 4, Extension::Base, RowOrder::BitReversed, 1)
}

impl DeviceSession {
    /// Only the fixed public preprocessing seed can enter this stream. Proof
    /// entropy and caller-provided seeds use the distinct private interface.
    pub(crate) fn public_preprocessing_salt_stream(&self) -> Result<PublicSaltStream, String> {
        Ok(PublicSaltStream {
            random: self.import_random_stream(ChaCha20Rng::from_seed([0; 32]))?,
            batch: Arc::new(Mutex::new(())),
        })
    }

    pub(crate) fn import_public_salts(&self, salts: &PublicSalts) -> Result<DeviceMatrix, String> {
        salts.check_context(self)?;
        Ok(DeviceMatrix {
            storage: salts.storage.allocation.clone(),
            // Retain the cleanup guard through every alias, including aliases
            // in a fresh proof session. It cannot be used to promote a trace.
            private_random: Some(salts.storage.clone()),
            session: self.session.clone(),
            spec: salts.spec,
        })
    }
}

impl PublicSalts {
    pub(crate) fn cached_host_backing(&self) -> usize {
        use crate::block_v2::gpu_hash::cache_metadata::arc_bytes;
        arc_bytes::<SecretAllocation>() + arc_bytes::<Allocation>()
    }
    pub(crate) fn spec(&self) -> MatrixSpec {
        self.spec
    }

    pub(crate) fn check_context(&self, session: &DeviceSession) -> Result<(), String> {
        if !Arc::ptr_eq(&self.context, &session.session.context) {
            return Err("public salts belong to another GPU context".into());
        }
        Ok(())
    }
}

impl PublicSaltStream {
    pub(crate) fn retire(&self) -> Result<(), String> {
        let _batch = self
            .batch
            .lock()
            .map_err(|_| "public salt batch poisoned")?;
        self.random
            .0
            .cursor
            .lock()
            .map_err(|_| "GPU random cursor poisoned")?
            .poisoned = true;
        Ok(())
    }

    /// Construction snapshots copy the cursor; Clone shares the active cursor.
    pub(crate) fn snapshot(&self) -> Result<Self, String> {
        let _batch = self
            .batch
            .lock()
            .map_err(|_| "public salt batch poisoned")?;
        Ok(Self {
            random: self.random.snapshot()?,
            batch: Arc::new(Mutex::new(())),
        })
    }

    /// Admission is a snapshot. Execution rechecks every allocation under the
    /// engine lock. No field is drawn if this complete batch cannot fit now.
    pub(crate) fn preflight(
        &self,
        height: usize,
        count: usize,
        pending: &[usize],
    ) -> Result<(), String> {
        let _batch = self
            .batch
            .lock()
            .map_err(|_| "public salt batch poisoned")?;
        self.preflight_inner(height, count, pending)
    }

    fn preflight_inner(
        &self,
        height: usize,
        count: usize,
        pending: &[usize],
    ) -> Result<(), String> {
        let shape = spec(height)?;
        if count == 0 || count > 256 {
            return Err("public salt batch requires 1..256 matrices".into());
        }
        let cursor = self
            .random
            .0
            .cursor
            .lock()
            .map_err(|_| "GPU random cursor poisoned")?;
        if cursor.poisoned {
            return Err("public salt stream has failed".into());
        }
        self.random.0.session.with_engine(|engine| {
            let mut live = engine
                .accounting
                .lock()
                .map_err(|_| "GPU accounting poisoned")?
                .live;
            for &bytes in pending {
                live = live
                    .checked_add(bytes)
                    .ok_or("public salt admission overflow")?;
                if bytes > engine.max_alloc || live > engine.limits.managed_bytes {
                    return Err("public salt pending inputs exceed admission".into());
                }
            }
            for index in 0..count {
                let position = cursor
                    .position
                    .checked_add(2 * shape.words() as u128 * index as u128)
                    .ok_or("public salt stream position overflow")?;
                Plan::new(
                    shape.words(),
                    position,
                    live,
                    engine.limits.managed_bytes,
                    engine.max_alloc,
                )?;
                live = live
                    .checked_add(shape.bytes())
                    .ok_or("public salt storage overflow")?;
            }
            Ok(())
        })
    }

    pub(crate) fn generate(&self, height: usize, count: usize) -> Result<Vec<PublicSalts>, String> {
        let _batch = self
            .batch
            .lock()
            .map_err(|_| "public salt batch poisoned")?;
        self.preflight_inner(height, count, &[])?;
        let shape = spec(height)?;
        let mut output = Vec::new();
        output.try_reserve_exact(count).map_err(|e| e.to_string())?;
        for _ in 0..count {
            let words = match self.random.sample_fields(shape.words()) {
                Ok(words) => words,
                Err(error) => {
                    // A partial batch must not be retried on an advanced cursor.
                    if !output.is_empty() {
                        self.random
                            .0
                            .cursor
                            .lock()
                            .map_err(|_| "GPU random cursor poisoned")?
                            .poisoned = true;
                    }
                    return Err(error);
                }
            };
            output.push(PublicSalts {
                storage: Arc::new(words.storage),
                context: words.session.session.context.clone(),
                spec: shape,
            });
        }
        Ok(output)
    }
}
