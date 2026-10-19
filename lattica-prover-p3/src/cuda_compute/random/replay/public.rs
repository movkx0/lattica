//! Deterministic PUBLIC preprocessing salts. No caller-supplied seed or private
//! replay recipe can be converted into this type. Each consumer gets a separate
//! failure scope; the immutable public recipe survives failed proof attempts.
use super::*;
use rand::SeedableRng;

pub(crate) struct PublicPreprocessingSalts {
    random: DeviceRandom,
}

pub(crate) struct PublicReplaySalts {
    recipe: ReplaySalts,
}

impl Randoms {
    pub(crate) fn public_preprocessing(self: &Arc<Self>) -> Result<PublicPreprocessingSalts> {
        Ok(PublicPreprocessingSalts {
            random: self.import(ChaCha20Rng::from_seed([0; 32]))?,
        })
    }
}

impl PublicPreprocessingSalts {
    pub(crate) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        self.random.check_runtime(runtime)
    }

    pub(crate) fn preflight(&self, specs: &[MatrixSpec], pending: &[usize]) -> Result<()> {
        self.random.preflight_salt_recipes(specs, pending)?;
        if self
            .random
            .0
            .slot
            .0
            .states
            .load(Ordering::Acquire)
            .checked_add(specs.len())
            .and_then(|n| n.checked_add(2))
            .is_none_or(|n| n > MAX_STREAM_STATES)
        {
            return Err("CUDA public salt recipes leave no consumer lease allowance".into());
        }
        Ok(())
    }

    pub(crate) fn prepare(&self, specs: &[MatrixSpec]) -> Result<Vec<PublicReplaySalts>> {
        // The sole conversion site starts from the fixed public seed above.
        self.preflight(specs, &[])?;
        Ok(self
            .random
            .prepare_salt_replay_specs(specs)?
            .into_iter()
            .map(|recipe| PublicReplaySalts { recipe })
            .collect())
    }
}

impl PublicReplaySalts {
    pub(crate) fn spec(&self) -> MatrixSpec {
        self.recipe.spec()
    }

    pub(crate) fn check_runtime(&self, runtime: &Runtime) -> Result<()> {
        self.recipe.check_runtime(runtime)
    }

    pub(crate) fn preflight(&self, pending: &[usize]) -> Result<()> {
        self.recipe.preflight(pending)?;
        self.recipe.preflight_public_lease()
    }

    pub(crate) fn with_materialized<T>(
        &self,
        consume: impl FnOnce(&Matrix) -> Result<T>,
    ) -> Result<T> {
        self.recipe.public_lease()?.with_materialized(consume)
    }

    pub(crate) fn query_rows(&self, indices: &[u64], host_bytes: usize) -> Result<Vec<u64>> {
        self.recipe.public_lease()?.query_rows(indices, host_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Val;
    use crate::cuda_compute::Limits;
    use crate::gpu_matrix::RowOrder;
    use p3_field::PrimeField64;
    use rand::RngExt;

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

    #[test]
    #[ignore = "requires CUDA; serial bounded service"]
    fn cuda_public_salts_match_cpu_and_survive_consumer_failure_and_unwind() {
        let runtime = runtime();
        let engine = Randoms::new(&runtime).unwrap();
        let baseline = runtime.snapshot();
        let source = engine.public_preprocessing().unwrap();
        let specs: Vec<_> = [4, 6, 3]
            .into_iter()
            .map(|log| MatrixSpec::new(log, 4, Extension::Base, RowOrder::BitReversed, 1).unwrap())
            .collect();
        let recipes = source.prepare(&specs).unwrap();
        drop(source);
        let mut cpu = ChaCha20Rng::from_seed([0; 32]);
        for (recipe, spec) in recipes.iter().zip(specs) {
            let expected: Vec<_> = (0..spec.words())
                .map(|_| cpu.random::<Val>().as_canonical_u64())
                .collect();
            assert_eq!(recipe.spec(), spec);
            let before = runtime.snapshot();
            let slots = engine.states.load(Ordering::Acquire);
            let lease = recipe.recipe.public_lease().unwrap();
            assert!(lease.materialize_with_fault(Fault::InvalidStatus).is_err());
            assert!(lease.random.check_live().is_err());
            assert!(recipe.check_runtime(&runtime).is_ok());
            drop(lease);
            assert!(recipe
                .with_materialized::<()>(|_| Err("consumer failure".into()))
                .is_err());
            assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                recipe.with_materialized::<()>(|_| panic!("consumer unwind"))
            }))
            .is_err());
            assert_eq!(engine.states.load(Ordering::Acquire), slots);
            assert_eq!(runtime.snapshot().live_bytes, before.live_bytes);
            assert_eq!(runtime.snapshot().allocations, before.allocations);
            // The public key remains resident; replay imports no new key and
            // neither consumes nor locks the original immutable stream cursor.
            let _cursor = recipe.recipe.random.0.position.lock().unwrap();
            let actual = recipe.with_materialized(|m| m.read(spec.bytes())).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(runtime.snapshot().uploaded_bytes, before.uploaded_bytes);
            let indices = [(spec.rows() - 1) as u64, 0, (spec.rows() - 1) as u64];
            let wanted: Vec<_> = indices
                .iter()
                .flat_map(|&r| expected[r as usize * 4..r as usize * 4 + 4].iter().copied())
                .collect();
            assert_eq!(recipe.query_rows(&indices, 96).unwrap(), wanted);
            assert_eq!(engine.states.load(Ordering::Acquire), slots);
        }
        drop(recipes);
        assert_eq!(engine.states.load(Ordering::Acquire), 0);
        assert_eq!(runtime.snapshot().live_bytes, baseline.live_bytes);
        assert_eq!(runtime.snapshot().allocations, baseline.allocations);
    }

    #[test]
    #[ignore = "requires CUDA; serial bounded service"]
    fn cuda_public_salt_lease_limits_and_driver_failure_remain_fail_closed() {
        let runtime = runtime();
        let engine = Randoms::new(&runtime).unwrap();
        let source = engine.public_preprocessing().unwrap();
        let spec = MatrixSpec::new(4, 4, Extension::Base, RowOrder::BitReversed, 1).unwrap();
        let recipes = source.prepare(&[spec]).unwrap();
        let recipe = &recipes[0];
        let slots: Vec<_> = (engine.states.load(Ordering::Acquire)..MAX_STREAM_STATES - 1)
            .map(|_| engine.slot().unwrap())
            .collect();
        let before = runtime.snapshot();
        assert!(recipe.preflight(&[]).is_err());
        assert!(recipe.with_materialized(|_| Ok(())).is_err());
        assert_eq!(runtime.snapshot(), before);
        drop(slots);
        recipe.with_materialized(|_| Ok(())).unwrap();
        // The immutable cache cannot bypass runtime failure even though it has
        // no private proof family to retire.
        runtime.state.fail();
        assert!(recipe.check_runtime(&runtime).is_err());
        assert!(recipe.with_materialized(|_| Ok(())).is_err());
        assert!(recipe.query_rows(&[0], 32).is_err());
    }
}
