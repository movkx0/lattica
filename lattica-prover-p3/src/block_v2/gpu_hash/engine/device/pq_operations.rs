//! Small raw witness operations; only node roots and status are read back.
use super::*;
use crate::proving::{Backend, Run, Stage};

pub(in crate::block_v2::gpu_hash::engine) const KERNEL_SRC: &str = include_str!("pq_operations.cl");

impl DeviceSession {
    pub(crate) fn pq_operation_commit_node(
        &self,
        kind: u32,
        input: &[u64],
        modulus: u64,
        host_allowance: usize,
        run: &Run,
    ) -> Result<[u64; 4], String> {
        let expected_words = match kind {
            0 if matches!(modulus, 167770241 | 3489661057) => 256,
            1 if modulus == 0 => 256,
            2 if modulus == 0 => 32,
            _ => return Err("raw node commitment kind or modulus".into()),
        };
        if input.len() != expected_words || (expected_words + 9) * 8 > host_allowance {
            return Err("raw node commitment shape or host allowance".into());
        }
        run.check_device_stage(Stage::WitnessTrace, Backend::OpenCl)
            .map_err(|e| e.to_string())?;
        #[cfg(not(feature = "gpu"))]
        {
            Err("raw node commitment requires OpenCL".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let spec = |words| MatrixSpec::new(0, words, Extension::Base, RowOrder::Natural, 1);
            let _plan = Self::plan(engine, &[spec(expected_words)?, spec(5)?])?;
            // Each allocation scrubs itself on error, including partial setup.
            let raw = random::SecretAllocation::new(engine, expected_words)?;
            let output = random::SecretAllocation::new(engine, 5)?;
            let fence = engine.fence();
            raw.buffer().write(input).enq().map_err(|e| e.to_string())?;
            let mut builder = engine.pq.kernel_builder("pq_operation_commit_node");
            builder
                .arg(raw.buffer())
                .arg(kind)
                .arg(modulus)
                .arg(output.buffer());
            for constant in &engine.constants {
                builder.arg(&constant.buffer);
            }
            let mut event = compute::Event::empty();
            // SAFETY: fixed input/output shapes were admitted together before
            // uploading any node values; the kernel has one bounded work item.
            unsafe {
                builder
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
                    "pq_operation_commit_node",
                    &event,
                )
                .map_err(|e| {
                    run.observation_failed();
                    e
                })?;
            run.observe_device(Stage::WitnessTrace, Backend::OpenCl, 1, ns)
                .map_err(|e| e.to_string())?;
            let mut words = [0u64; 5];
            output
                .buffer()
                .read(&mut words[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = (input.len() * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 40;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += 40;
            }
            if words[4] != 0 || words[..4].iter().any(|&v| v >= GOLDILOCKS_MODULUS) {
                return Err("GPU node commitment rejected input or noncanonical root".into());
            }
            Ok(words[..4].try_into().expect("four root words"))
        })
    }
}
