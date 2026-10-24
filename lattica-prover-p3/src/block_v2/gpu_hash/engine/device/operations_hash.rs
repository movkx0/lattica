//! Raw hash-chain roots for graph preparation, with bounded input and egress.
use super::*;
use crate::block_v2::native_gpu::operations_hash::field_chunk_staging_bytes;
use crate::proving::{Backend, Run, Stage};

impl DeviceSession {
    pub(crate) fn pq_operation_commit_fields(
        &self,
        initial: [u64; 4],
        words: &[u64],
        host_allowance: usize,
        run: &Run,
    ) -> Result<[u64; 4], String> {
        if field_chunk_staging_bytes(words.len())? > host_allowance {
            return Err("raw field commitment exceeds host allowance".into());
        }
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        self.with_engine(|engine| {
            let spec = |n| MatrixSpec::new(0, n, Extension::Base, RowOrder::Natural, 1);
            let count = words.len().max(1);
            let _plan = Self::plan(engine, &[spec(count)?, spec(4)?, spec(5)?])?;
            let raw = random::SecretAllocation::new(engine, count)?;
            let start = random::SecretAllocation::new(engine, 4)?;
            let output = random::SecretAllocation::new(engine, 5)?;
            // Declare readback storage before its queue fence so error/unwind
            // drains all commands before any referenced host slice is released.
            let mut result = [0u64; 5];
            let fence = engine.fence();
            if !words.is_empty() {
                raw.buffer().write(words).enq().map_err(|e| e.to_string())?;
            }
            start
                .buffer()
                .write(&initial[..])
                .enq()
                .map_err(|e| e.to_string())?;
            for begin in (0..words.len().max(1)).step_by(4096) {
                let mut event = compute::Event::empty();
                // SAFETY: the aggregate plan admits all raw and result buffers.
                // Consecutive aligned tiles share only a five-word device state;
                // each validates its raw fields before hashing. The first tile
                // initializes the state, including when the stream is empty.
                unsafe {
                    engine
                        .pq
                        .kernel_builder("pq_operation_commit_fields")
                        .arg(raw.buffer())
                        .arg(words.len() as u32)
                        .arg(begin as u32)
                        .arg(start.buffer())
                        .arg(output.buffer())
                        .arg(&engine.constants[0].buffer)
                        .arg(&engine.constants[1].buffer)
                        .arg(&engine.constants[2].buffer)
                        .arg(&engine.constants[3].buffer)
                        .global_work_size(1)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let ns = self
                    .session
                    .record_event(
                        engine,
                        Stage::WitnessTrace,
                        "pq_operation_commit_fields",
                        &event,
                    )
                    .map_err(|error| {
                        run.observation_failed();
                        error
                    })?;
                run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, ns)
                    .map_err(|e| e.to_string())?;
            }
            output
                .buffer()
                .read(&mut result[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = ((words.len() + 4) * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 40;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += 40;
            }
            if result[4] != 0 || result[..4].iter().any(|&v| v >= GOLDILOCKS_MODULUS) {
                return Err("GPU field commitment rejected noncanonical input or root".into());
            }
            Ok(result[..4].try_into().expect("four root words"))
        })
    }
}
