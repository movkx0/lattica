//! Immutable, session-owned salt replay. Original draws advance atomically;
//! only a device-key reference and checked stream positions remain retained.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// This is private proof material. It cannot be imported as public preprocessing
/// or serialized. Replays reproduce an existing commitment's salts only.
pub struct ReplaySalts {
    random: DeviceRandom,
    position: u128,
    end: u128,
    spec: MatrixSpec,
    failed: AtomicBool,
}

fn validate_spec(spec: MatrixSpec) -> Result<(), String> {
    if spec.extension() != Extension::Base
        || spec.columns() != 4
        || spec.rows() > 1 << 25
        || spec.order() != RowOrder::BitReversed
        || spec.shift() != 1
    {
        return Err("salt replay requires bounded bit-reversed four-column base geometry".into());
    }
    Ok(())
}

/// One output and its sampling scratch, regardless of retained recipe count.
pub(crate) fn salt_replay_workspace_bytes(words: usize) -> Result<usize, String> {
    Ok(Plan::new(words, 0, 0, usize::MAX, usize::MAX)?.peak_bytes)
}

impl DeviceRandom {
    pub(crate) fn preflight_salt_replay(
        &self,
        requests: &[usize],
        pending: &[usize],
    ) -> Result<(), String> {
        self.preflight_field_storage(requests, pending, false)
    }

    pub(crate) fn prepare_salt_replay(
        &self,
        spec: MatrixSpec,
        count: usize,
    ) -> Result<Vec<ReplaySalts>, String> {
        validate_spec(spec)?;
        if count == 0 || count > 256 {
            return Err("salt replay batch requires 1..256 matrices".into());
        }
        self.preflight_salt_replay(&vec![spec.words(); count], &[])?;
        #[cfg(not(feature = "gpu"))]
        return Err("salt replay is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            // Hold the active cursor across every original draw. Snapshot and
            // advancement cannot race another clone of the same random stream.
            let mut cursor = self
                .0
                .cursor
                .lock()
                .map_err(|_| "GPU random cursor poisoned")?;
            self.0.session.with_engine(|engine| {
                let mut recipes = Vec::with_capacity(count);
                for _ in 0..count {
                    let (samples, recipe) = self.draw_salt_in(&mut cursor, engine, spec)?;
                    // The first pass establishes the exact rejection-consumption
                    // boundary. Samples are wiped before drawing the next matrix.
                    drop(samples);
                    recipes.push(recipe);
                }
                eprintln!("bounded_gpu_salt_replay_prepared matrices={count} rows={} retained_sample_bytes=0 sample_upload_bytes=0 sample_readback_bytes=0", spec.rows());
                Ok(recipes)
            })
        }
    }

    /// One commitment can consume the original draw immediately and retain
    /// only its recipe for queries. Cursor capture and advancement are atomic.
    pub(crate) fn sample_salt_with_replay(
        &self,
        spec: MatrixSpec,
    ) -> Result<(DeviceMatrix, ReplaySalts), String> {
        validate_spec(spec)?;
        #[cfg(not(feature = "gpu"))]
        return Err("salt replay is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            let mut cursor = self
                .0
                .cursor
                .lock()
                .map_err(|_| "GPU random cursor poisoned")?;
            self.0
                .session
                .with_engine(|engine| self.draw_salt_in(&mut cursor, engine, spec))
        }
    }

    #[cfg(feature = "gpu")]
    fn draw_salt_in(
        &self,
        cursor: &mut Cursor,
        engine: &mut Engine,
        spec: MatrixSpec,
    ) -> Result<(DeviceMatrix, ReplaySalts), String> {
        let position = cursor.position;
        let samples = self.sample_fields_in_engine(
            cursor,
            engine,
            spec.words(),
            #[cfg(test)]
            None,
        )?;
        let recipe = ReplaySalts {
            random: self.clone(),
            position,
            end: cursor.position,
            spec,
            failed: AtomicBool::new(false),
        };
        Ok((samples.into_matrix(spec), recipe))
    }
}

impl ReplaySalts {
    /// Each recipe conservatively charges the shared stream and seed wrappers.
    /// The stream's session, engine/driver objects and device bytes stay separate.
    pub(crate) fn retained_host_backing(&self) -> usize {
        retained_stream_host_backing()
    }

    pub(crate) fn spec(&self) -> MatrixSpec {
        self.spec
    }

    pub(crate) fn check_session(&self, session: &DeviceSession) -> Result<(), String> {
        if !Arc::ptr_eq(&self.random.0.session.session, &session.session) {
            return Err("salt replay belongs to another proof session".into());
        }
        self.check_live()
    }

    fn check_live(&self) -> Result<(), String> {
        if self.failed.load(Ordering::Acquire) {
            return Err("salt replay is unusable after execution failure".into());
        }
        Ok(())
    }

    pub(crate) fn check_engine(&self, engine: &Engine) -> Result<(), String> {
        if !Arc::ptr_eq(&self.random.0.session.session.context, &engine._job_lease) {
            return Err("salt replay belongs to another GPU context".into());
        }
        self.check_live()
    }

    pub(crate) fn workspace_bytes(&self, engine: &Engine) -> Result<usize, String> {
        self.check_engine(engine)?;
        Ok(Plan::new(
            self.spec.words(),
            self.position,
            0,
            usize::MAX,
            engine.max_alloc,
        )?
        .peak_bytes)
    }

    pub(crate) fn materialize(&self, session: &DeviceSession) -> Result<DeviceMatrix, String> {
        self.check_session(session)?;
        session.with_engine(|engine| self.materialize_in(engine))
    }

    /// Called by commitment hashing with the engine already held. It never
    /// locks the active random cursor or recursively acquires the engine.
    pub(crate) fn materialize_in(&self, engine: &mut Engine) -> Result<DeviceMatrix, String> {
        self.materialize_inner(
            engine,
            #[cfg(test)]
            None,
        )
    }

    fn materialize_inner(
        &self,
        engine: &mut Engine,
        #[cfg(test)] fail_after_batch: Option<usize>,
    ) -> Result<DeviceMatrix, String> {
        self.check_engine(engine)?;
        #[cfg(not(feature = "gpu"))]
        return Err("salt replay is not implemented on Metal".into());
        #[cfg(feature = "gpu")]
        {
            let mut cursor = Cursor {
                position: self.position,
                poisoned: false,
            };
            let result = self.random.sample_fields_in_engine(
                &mut cursor,
                engine,
                self.spec.words(),
                #[cfg(test)]
                fail_after_batch,
            );
            if cursor.poisoned || (result.is_ok() && cursor.position != self.end) {
                self.failed.store(true, Ordering::Release);
            }
            self.check_live()?;
            Ok(result?.into_matrix(self.spec))
        }
    }
}

#[cfg(test)]
mod tests;
