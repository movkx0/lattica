//! One owned RNG per protocol stream. Active clones share state; explicit
//! construction snapshots copy it. A selected GPU stream has no CPU fallback.
use rand::{Rng, TryCryptoRng, TryRng};
use rand_chacha::ChaCha20Rng;
use std::convert::Infallible;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) mod resources;

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
use super::gpu_hash::device::{DeviceRandom, DeviceSession};
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "gpu-cuda")]
mod cuda;

enum State {
    Host(ChaCha20Rng),
    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    Device {
        stream: DeviceRandom,
        failure: Failure,
    },
    #[cfg(feature = "gpu-cuda")]
    Cuda {
        stream: crate::cuda_compute::DeviceRandom,
        failure: Failure,
    },
    Retired,
}

#[derive(Clone)]
pub(crate) struct ProofRng(Arc<Mutex<State>>);

impl core::fmt::Debug for ProofRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedProofRng(<redacted>)")
    }
}

pub(crate) struct HostGuard<'a>(MutexGuard<'a, State>);
impl Deref for HostGuard<'_> {
    type Target = ChaCha20Rng;
    fn deref(&self) -> &Self::Target {
        match &*self.0 {
            State::Host(rng) => rng,
            _ => unreachable!(),
        }
    }
}
impl DerefMut for HostGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut *self.0 {
            State::Host(rng) => rng,
            _ => unreachable!(),
        }
    }
}

impl ProofRng {
    /// One freshly constructed host stream, including the Arc reference counts.
    #[cfg(all(not(debug_assertions), target_arch = "x86_64"))]
    pub(crate) fn host_storage_bytes() -> usize {
        super::profile::verification::arc_bytes::<Mutex<State>>()
    }

    pub(crate) fn new(rng: ChaCha20Rng) -> Self {
        Self(Arc::new(Mutex::new(State::Host(rng))))
    }

    pub(crate) fn lock(&self) -> Result<HostGuard<'_>, String> {
        let state = self.0.lock().map_err(|_| "proof random stream poisoned")?;
        if !matches!(*state, State::Host(_)) {
            return Err("CPU expansion is unavailable for a GPU or retired proof stream".into());
        }
        Ok(HostGuard(state))
    }

    pub(crate) fn with<T>(&self, f: impl FnOnce(&mut ChaCha20Rng) -> T) -> T {
        f(&mut self
            .lock()
            .expect("CPU proof random expansion is unavailable"))
    }

    pub(crate) fn snapshot(&self) -> Result<Self, String> {
        let state = self.0.lock().map_err(|_| "proof random stream poisoned")?;
        let snapshot = match &*state {
            State::Host(rng) => State::Host(rng.clone()),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            State::Device { stream, failure } => {
                failure.check()?;
                State::Device {
                    stream: stream.snapshot()?,
                    failure: failure.clone(),
                }
            }
            State::Retired => return Err("proof random stream is retired".into()),
            #[cfg(feature = "gpu-cuda")]
            State::Cuda { stream, failure } => {
                failure.check()?;
                State::Cuda {
                    stream: stream.snapshot()?,
                    failure: failure.clone(),
                }
            }
        };
        Ok(Self(Arc::new(Mutex::new(snapshot))))
    }

    #[cfg(test)]
    pub(crate) fn shares_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn activate(
        &self,
        session: &DeviceSession,
        failure: &Failure,
    ) -> Result<(), String> {
        failure.check()?;
        let mut state = self.0.lock().map_err(|_| "proof random stream poisoned")?;
        if !matches!(*state, State::Host(_)) {
            return Err("proof randomness selection is immutable".into());
        }
        let State::Host(host) = core::mem::replace(&mut *state, State::Retired) else {
            unreachable!()
        };
        let stream = session.import_random_stream(host)?;
        *state = State::Device {
            stream,
            failure: failure.clone(),
        };
        Ok(())
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
    pub(crate) fn is_device(&self) -> Result<bool, String> {
        match &*self.0.lock().map_err(|_| "proof random stream poisoned")? {
            State::Host(_) => Ok(false),
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            State::Device { failure, .. } => {
                failure.check()?;
                Ok(true)
            }
            State::Retired => Err("proof random stream is retired".into()),
            #[cfg(feature = "gpu-cuda")]
            State::Cuda { stream, failure } => {
                failure.check()?;
                stream.check_live()?;
                Ok(true)
            }
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
    pub(crate) fn with_device<T>(
        &self,
        f: impl FnOnce(&DeviceRandom) -> Result<T, String>,
    ) -> Result<T, String> {
        let state = self.0.lock().map_err(|_| "proof random stream poisoned")?;
        match &*state {
            State::Device { stream, failure } => {
                failure.check()?;
                f(stream)
            }
            _ => Err("device random expansion is not selected".into()),
        }
    }

    #[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
    pub(crate) fn begin(&self) -> Result<FailureGuard, String> {
        match &*self.0.lock().map_err(|_| "proof random stream poisoned")? {
            #[cfg(any(feature = "gpu", feature = "gpu-metal"))]
            State::Device { failure, .. } => failure.begin(),
            #[cfg(feature = "gpu-cuda")]
            State::Cuda { stream, failure } => {
                stream.check_live()?;
                failure.begin()
            }
            _ => Err("device random expansion is not selected".into()),
        }
    }
}

impl TryRng for ProofRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.with(|rng| rng.next_u32()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.with(|rng| rng.next_u64()))
    }
    fn try_fill_bytes(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        self.with(|rng| rng.fill_bytes(output));
        Ok(())
    }
}
impl TryCryptoRng for ProofRng {}

#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
#[derive(Clone, Default)]
pub(crate) struct Failure(Arc<AtomicBool>);
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
impl Failure {
    pub(crate) fn check(&self) -> Result<(), String> {
        if self.0.load(Ordering::Acquire) {
            Err("GPU randomness attempt has failed; use a fresh proof configuration".into())
        } else {
            Ok(())
        }
    }
    pub(crate) fn begin(&self) -> Result<FailureGuard, String> {
        self.check()?;
        Ok(FailureGuard {
            failure: self.clone(),
            completed: false,
        })
    }
}
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
pub(crate) struct FailureGuard {
    failure: Failure,
    completed: bool,
}
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
impl FailureGuard {
    pub(crate) fn complete(mut self) {
        self.completed = true;
    }
}
#[cfg(any(feature = "gpu", feature = "gpu-metal", feature = "gpu-cuda"))]
impl Drop for FailureGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.failure.0.store(true, Ordering::Release);
        }
    }
}

/// Observe completed GPU sampler calls, even when a later stage unwinds.
/// The event counters contain no samples, seeds, or field values.
#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
pub(crate) struct RandomnessObservation<'a> {
    run: &'a crate::proving::Run,
    session: DeviceSession,
    before: super::gpu_hash::device::SessionStats,
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
impl<'a> RandomnessObservation<'a> {
    pub(crate) fn new(
        run: &'a crate::proving::Run,
        session: DeviceSession,
    ) -> Result<Self, String> {
        run.check_device_stage(
            crate::proving::Stage::Randomness,
            crate::proving::Backend::OpenCl,
        )
        .map_err(|e| e.to_string())?;
        let before = session
            .try_stats()
            .ok_or("GPU random statistics poisoned")?;
        Ok(Self {
            run,
            session,
            before,
        })
    }
}

#[cfg(any(feature = "gpu", feature = "gpu-metal"))]
impl Drop for RandomnessObservation<'_> {
    fn drop(&mut self) {
        if let Some(after) = self.session.try_stats() {
            let calls = after.random_calls.checked_sub(self.before.random_calls);
            let ns = after
                .random_device_ns
                .checked_sub(self.before.random_device_ns);
            if let (Some(calls), Some(ns)) = (calls, ns) {
                let _ = self.run.observe_device(
                    crate::proving::Stage::Randomness,
                    crate::proving::Backend::OpenCl,
                    calls,
                    ns,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Val;
    use rand::{RngExt, SeedableRng};

    #[test]
    fn host_construction_snapshots_are_distinct_from_active_clones() {
        let mut expected = ChaCha20Rng::from_seed([107; 32]);
        expected.set_word_pos(15);
        let rng = ProofRng::new(expected.clone());
        let shared = rng.clone();
        let snapshot = rng.snapshot().unwrap();
        let mut initial = expected.clone();
        assert!(rng.shares_with(&shared));
        assert!(!rng.shares_with(&snapshot));
        for active in [&rng, &shared, &rng] {
            for _ in 0..31 {
                assert_eq!(active.with(|r| r.random::<Val>()), expected.random::<Val>());
            }
        }
        for _ in 0..93 {
            assert_eq!(
                snapshot.with(|r| r.random::<Val>()),
                initial.random::<Val>()
            );
        }
    }

    #[test]
    #[cfg(feature = "gpu")]
    #[ignore = "requires OpenCL GPU; run serially in a <=3 GiB zero-swap service"]
    fn gpu_random_group_rejects_host_fallback_and_retires_every_stream_after_failure() {
        use crate::block_v2::gpu_hash;
        use p3_field::PrimeField64;
        let _shutdown = gpu_hash::TestShutdownGuard;
        gpu_hash::initialize_quotient_test_engine(gpu_hash::Limits {
            managed_bytes: 256 << 20,
            tile_bytes: 32 << 20,
            staging_bytes: 64 << 10,
        })
        .unwrap();
        let session = DeviceSession::new().unwrap();
        let baseline = gpu_hash::report("random group baseline").unwrap();
        let failure = Failure::default();
        let streams: Vec<_> = [41, 41, 43, 47]
            .into_iter()
            .map(|seed| {
                let rng = ProofRng::new(ChaCha20Rng::from_seed([seed; 32]));
                rng.activate(&session, &failure).unwrap();
                rng
            })
            .collect();
        assert_eq!(session.stats().random_streams, 4);
        let before = session.stats();
        for rng in &streams {
            assert!(rng.lock().is_err());
            assert!(rng.activate(&session, &failure).is_err());
            assert!(rng
                .with_device(|r| r.preflight_fields(&[usize::MAX], &[]))
                .is_err());
            assert!(rng
                .with_device(|r| r.preflight_fields(&[8], &[usize::MAX]))
                .is_err());
        }
        assert_eq!(session.stats(), before);
        let snapshot = streams[0].snapshot().unwrap();
        assert_eq!(session.stats(), before);
        let shared = streams[0].clone();
        let mut reference = ChaCha20Rng::from_seed([41; 32]);
        let mut fork_reference = reference.clone();
        for rng in [&streams[0], &shared] {
            let expected: Vec<_> = (0..37)
                .map(|_| reference.random::<Val>().as_canonical_u64())
                .collect();
            let actual = rng
                .with_device(|r| r.sample_fields(37)?.read_for_test(37 * 8))
                .unwrap();
            assert_eq!(actual, expected);
        }
        let expected: Vec<_> = (0..74)
            .map(|_| fork_reference.random::<Val>().as_canonical_u64())
            .collect();
        assert_eq!(
            snapshot
                .with_device(|r| r.sample_fields(74)?.read_for_test(74 * 8))
                .unwrap(),
            expected
        );
        failure.begin().unwrap().complete();
        assert!(streams.iter().all(|r| r.is_device().unwrap()));
        let failed: Result<(), String> = (|| {
            let _guard = failure.begin()?;
            let _samples = streams[2].with_device(|r| r.sample_fields(19))?;
            Err("injected downstream operation failure".into())
        })();
        assert!(failed.is_err());
        let before = session.stats();
        for rng in streams.iter().chain([&shared, &snapshot]) {
            assert!(rng.is_device().is_err());
            assert!(rng.snapshot().is_err());
            assert!(rng.with_device(|r| r.sample_fields(1)).is_err());
            assert!(rng.lock().is_err());
        }
        assert_eq!(session.stats(), before);
        drop((streams, snapshot, shared));
        assert_eq!(
            gpu_hash::report("random group released")
                .unwrap()
                .device_matrix_live_bytes,
            baseline.device_matrix_live_bytes
        );
    }
}
