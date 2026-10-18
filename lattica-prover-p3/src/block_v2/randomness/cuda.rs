//! Explicit native activation of the existing protocol RNG ownership model.
use super::*;
use crate::cuda_compute::{DeviceRandom, Randoms};

impl ProofRng {
    pub(crate) fn activate_cuda(
        &self,
        engine: &Arc<Randoms>,
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
        // A failed import leaves the source retired, never eligible for CPU use.
        let stream = engine.import_shared(host, failure.0.clone())?;
        *state = State::Cuda {
            stream,
            failure: failure.clone(),
        };
        Ok(())
    }
    pub(crate) fn with_cuda<T>(
        &self,
        f: impl FnOnce(&DeviceRandom) -> Result<T, String>,
    ) -> Result<T, String> {
        let state = self.0.lock().map_err(|_| "proof random stream poisoned")?;
        let State::Cuda { stream, failure } = &*state else {
            return Err("native CUDA randomness is not selected".into());
        };
        failure.check()?;
        let result = f(stream);
        // Admission failures may be replanned before consumption. Once a native
        // stream has retired, propagate failure to every RNG in the proof group.
        if result.is_err() && stream.check_live().is_err() {
            failure.0.store(true, Ordering::Release);
        }
        result
    }
}

#[cfg(test)]
mod tests;
