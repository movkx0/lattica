//! Scoped event collection on the existing in-order queue. The engine's inline
//! array is included in its retained-host census; no unbounded event heap exists.
use super::*;
use crate::proving::Stage;

pub(in crate::block_v2::gpu_hash::engine) const CAPACITY: usize = 256;

pub(in crate::block_v2::gpu_hash::engine) struct PendingEvents<T> {
    entries: [Option<(&'static str, T)>; CAPACITY],
    len: usize,
}
impl<T> Default for PendingEvents<T> {
    fn default() -> Self {
        Self {
            entries: std::array::from_fn(|_| None),
            len: 0,
        }
    }
}
impl<T> PendingEvents<T> {
    fn push(&mut self, label: &'static str, event: T) -> Result<(), String> {
        if self.len == CAPACITY {
            return Err("GPU event batch capacity exceeded".into());
        }
        self.entries[self.len] = Some((label, event));
        self.len += 1;
        Ok(())
    }
}

pub(in crate::block_v2::gpu_hash::engine) type EventReceipts = PendingEvents<compute::Event>;

pub(super) struct EventBatch<'a> {
    pub(super) engine: &'a mut Engine,
    owner: &'a Session,
    stage: Stage,
    total_ns: u128,
    finished: bool,
}
impl<'a> EventBatch<'a> {
    pub(super) fn new(engine: &'a mut Engine, owner: &'a Session, stage: Stage) -> Self {
        // The exclusive engine borrow prevents another batch/session entering.
        assert_eq!(engine.event_receipts.len, 0, "undrained GPU event batch");
        Self {
            engine,
            owner,
            stage,
            total_ns: 0,
            finished: false,
        }
    }

    pub(super) fn record(
        &mut self,
        label: &'static str,
        event: compute::Event,
    ) -> Result<(), String> {
        if !self.engine.tuning.events {
            let ns = self
                .owner
                .record_event(self.engine, self.stage, label, &event)?;
            self.total_ns = self.total_ns.checked_add(ns).ok_or_else(|| {
                self.owner.observation_failed();
                "GPU event duration overflow".to_string()
            })?;
            return Ok(());
        }
        self.engine.event_receipts.push(label, event)?;
        let limit = if self.engine.tuning.events256 { CAPACITY } else { 64 };
        if self.engine.event_receipts.len == limit {
            self.drain()?;
        }
        Ok(())
    }

    fn drain(&mut self) -> Result<(), String> {
        let pending = &self.engine.event_receipts;
        if pending.len == 0 {
            return Ok(());
        }
        // One completion wait for the batch. Individual timestamps remain
        // mandatory, and only completed, successfully profiled events count.
        let mut error = pending.entries[pending.len - 1]
            .as_ref()
            .unwrap()
            .1
            .wait_for()
            .err()
            .map(|e| e.to_string());
        for index in 0..self.engine.event_receipts.len {
            let (label, event) = self.engine.event_receipts.entries[index].take().unwrap();
            match self.engine.timeline.record(label, &event) {
                Ok(ns) => {
                    self.owner.record_execution(self.stage, 1, ns);
                    match self.total_ns.checked_add(ns) {
                        Some(total) => self.total_ns = total,
                        None => {
                            error.get_or_insert_with(|| "GPU event duration overflow".into());
                        }
                    }
                }
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        self.engine.event_receipts.len = 0;
        if let Some(error) = error {
            self.owner.observation_failed();
            // Failed events must never release storage while commands still run.
            if let Err(e) = self.engine.fence().finish() {
                super::super::fatal_cleanup("event_batch_drain", e);
            }
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<u128, String> {
        let result = self.drain().map(|()| self.total_ns);
        self.finished = true;
        result
    }
}
impl Drop for EventBatch<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Preserve completed receipts on enqueue failure and unwinding.
            // Also reject successful completion if a caller forgets finish().
            self.owner.observation_failed();
            let _ = self.drain();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn event_storage_is_bounded_and_releases_every_handle() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Receipt(Arc<AtomicUsize>);
        impl Drop for Receipt {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let released = Arc::new(AtomicUsize::new(0));
        let mut batch = PendingEvents::default();
        for _ in 0..CAPACITY {
            batch.push("test", Receipt(released.clone())).unwrap();
        }
        assert!(batch.push("overflow", Receipt(released.clone())).is_err());
        assert_eq!(released.load(Ordering::SeqCst), 1);
        drop(batch);
        assert_eq!(released.load(Ordering::SeqCst), CAPACITY + 1);
    }

    #[cfg(feature = "gpu-tuning")]
    #[test]
    #[ignore = "requires OpenCL GPU; run serially with gpu-tuning enabled"]
    fn gpu_tuning_event_batches_preserve_receipts_on_completion_errors_and_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let _shutdown = super::super::super::TestShutdownGuard;
        crate::block_v2::gpu_hash::initialize_quotient_test_engine(super::super::super::Limits {
            managed_bytes: 64 << 20,
            tile_bytes: 1 << 20,
            staging_bytes: 64 << 10,
        })
        .unwrap();
        let session = DeviceSession::new().unwrap();
        let other = DeviceSession::new().unwrap();
        session
            .with_engine(|engine| {
                engine.tuning.events = true;
                let spec = MatrixSpec::new(1, 1, Extension::Base, RowOrder::Natural, 1)?;
                let output = session.allocate(engine, spec)?;
                let kernel = engine
                    .pq
                    .kernel_builder("device_transform_parameters")
                    .arg(&output.storage.buffer)
                    .arg(8u32)
                    .arg(1u64)
                    .arg(7u64)
                    .global_work_size(1)
                    .build()
                    .map_err(|e| e.to_string())?;
                let invalid_group = engine
                    .pq
                    .device()
                    .max_wg_size()
                    .map_err(|e| e.to_string())?
                    .checked_add(1)
                    .unwrap();
                let untouched = other.session.test_receipt(Stage::Transform);
                for failure in 0..3 {
                    let before = session.session.test_receipt(Stage::Transform);
                    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), String> {
                        let mut batch = EventBatch::new(engine, &session.session, Stage::Transform);
                        for i in 0..(2 * CAPACITY + 2) {
                            if i == 5 && failure == 1 {
                                // Exceed the device's advertised limit to exercise
                                // a real enqueue failure with five commands pending.
                                unsafe {
                                    kernel
                                        .cmd()
                                        .local_work_size(invalid_group)
                                        .enq()
                                        .map_err(|e| e.to_string())?;
                                }
                                panic!("invalid workgroup unexpectedly accepted");
                            }
                            if i == 5 && failure == 2 {
                                panic!("injected producer unwind");
                            }
                            let mut event = compute::Event::empty();
                            unsafe {
                                kernel
                                    .cmd()
                                    .enew(&mut event)
                                    .enq()
                                    .map_err(|e| e.to_string())?;
                            }
                            batch.record("event_batch_test", event)?;
                        }
                        batch.finish()?;
                        Ok(())
                    }));
                    match failure {
                        0 => assert!(result.unwrap().is_ok()),
                        1 => assert!(result.unwrap().is_err()),
                        _ => assert!(result.is_err()),
                    }
                    assert_eq!(engine.event_receipts.len, 0);
                    let after = session.session.test_receipt(Stage::Transform);
                    assert_eq!(after.0 - before.0,
                        if failure == 0 { (2 * CAPACITY + 2) as u64 } else { 5 });
                    assert!(after.1 >= before.1);
                    assert_eq!(after.2 - before.2, u64::from(failure != 0));
                    assert_eq!(other.session.test_receipt(Stage::Transform), untouched);
                }
                let before = session.session.test_receipt(Stage::Transform);
                // User events have no device profiling timestamps. Completion alone
                // must not create a receipt or hide a profiling failure.
                let event = compute::Event::user(engine.pq.context()).map_err(|e| e.to_string())?;
                event.set_complete().map_err(|e| e.to_string())?;
                let mut batch = EventBatch::new(engine, &session.session, Stage::Transform);
                batch.record("missing_profile", event)?;
                assert!(batch.finish().is_err());
                let after = session.session.test_receipt(Stage::Transform);
                assert_eq!(after.0, before.0);
                assert_eq!(after.2, before.2 + 1);
                assert_eq!(engine.event_receipts.len, 0);
                Ok(())
            })
            .unwrap();
    }
}
