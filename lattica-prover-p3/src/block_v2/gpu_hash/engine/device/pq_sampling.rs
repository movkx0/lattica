//! Bounded GPU-only byte-to-polynomial sampling and public endpoint generation.
use super::*;
use crate::proving::{Backend, Run, Stage};

// The helper has an include guard and is shared with arithmetic/source kernels.
pub(in crate::block_v2::gpu_hash::engine) const KERNEL_SRC: &str = concat!(
    include_str!("pq_poseidon.cl"),
    include_str!("pq_sampling.cl")
);

struct Scratch {
    matrices: [DeviceMatrix; 4],
    queue: compute::Queue,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        for matrix in &self.matrices {
            if let Err(error) = matrix.storage.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("pq_sampler_scratch_scrub", error);
            }
        }
        if let Err(error) = self.queue.finish() {
            super::super::fatal_cleanup("pq_sampler_scrub_drain", error);
        }
    }
}

impl DeviceSession {
    pub(crate) fn pq_sampling_trace(
        &self,
        kind: u32,
        bytes: &[u8],
        host_allowance: usize,
        run: &Run,
    ) -> Result<(DeviceMatrix, DeviceMatrix), String> {
        let (rows, width, expected) = match kind {
            0 => (2048usize, 445usize, 1197usize * 4),
            1 => (1024, 445, 643 * 4),
            2 => (256, 506, 127),
            3 => (256, 506, 137),
            _ => return Err("unknown native sampler".into()),
        };
        if bytes.len() != expected
            || expected
                .checked_mul(8)
                .and_then(|n| n.checked_add(8))
                .is_none_or(|n| n > host_allowance)
        {
            return Err("native sampler input exceeds admitted geometry or host storage".into());
        }
        for stage in [Stage::WitnessTrace, Stage::PublicValues] {
            run.check_device_stage(stage, Backend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        self.with_engine(|engine| {
            let spec =
                |log, columns| MatrixSpec::new(log, columns, Extension::Base, RowOrder::Natural, 1);
            let specs = [
                spec(rows.ilog2(), width)?,
                spec(0, 8)?,
                spec(0, expected)?,
                spec(0, 8)?,
                spec(0, 1)?,
                spec(0, if kind < 2 { 1 } else { 512 })?,
            ];
            let _plan = Self::plan(engine, &specs)?;
            let trace = self.allocate(engine, specs[0])?;
            let public = self.allocate(engine, specs[1])?;
            let scratch = Scratch {
                matrices: [
                    self.allocate(engine, specs[2])?,
                    self.allocate(engine, specs[3])?,
                    self.allocate(engine, specs[4])?,
                    self.allocate(engine, specs[5])?,
                ],
                queue: engine.pq.queue().clone(),
            };
            let [raw, endpoints, status, history] = &scratch.matrices;
            let mut words =
                crate::gpu_wallet::InputWords(crate::gpu_wallet::staging_words(expected)?);
            words.0.extend(bytes.iter().map(|&byte| u64::from(byte)));
            let fence = engine.fence();
            raw.storage
                .buffer
                .write(&words.0)
                .enq()
                .map_err(|e| e.to_string())?;
            trace
                .storage
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            let kernels = [
                (
                    if kind < 2 {
                        "pq_uniform_chain"
                    } else {
                        "pq_sparse_chain"
                    },
                    1,
                    Stage::WitnessTrace,
                ),
                (
                    "pq_uniform_hints",
                    if kind < 2 { rows * 147 } else { 0 },
                    Stage::WitnessTrace,
                ),
                (
                    "pq_sparse_snapshots",
                    if kind >= 2 { rows * 320 } else { 0 },
                    Stage::WitnessTrace,
                ),
                (
                    "pq_sampling_poseidon",
                    rows * if kind < 2 { 2 } else { 1 },
                    Stage::WitnessTrace,
                ),
                (
                    "pq_uniform_bundle_columns",
                    if kind < 2 { rows } else { 0 },
                    Stage::WitnessTrace,
                ),
                ("pq_sampling_public", 8, Stage::PublicValues),
            ];
            history
                .storage
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|error| error.to_string())?;
            for (name, work, stage) in kernels {
                if work == 0 {
                    continue;
                }
                let mut builder = engine.pq.kernel_builder(name);
                match name {
                    "pq_uniform_chain" | "pq_sparse_chain" => {
                        builder
                            .arg(&raw.storage.buffer)
                            .arg(kind)
                            .arg(&trace.storage.buffer)
                            .arg(&endpoints.storage.buffer)
                            .arg(&status.storage.buffer);
                        if kind >= 2 {
                            builder.arg(&history.storage.buffer);
                        }
                    }
                    "pq_uniform_hints" => {
                        builder
                            .arg(kind)
                            .arg(rows as u32)
                            .arg(&trace.storage.buffer);
                    }
                    "pq_sparse_snapshots" => {
                        builder
                            .arg(&raw.storage.buffer)
                            .arg(kind)
                            .arg(&history.storage.buffer)
                            .arg(&trace.storage.buffer);
                    }
                    "pq_sampling_poseidon" => {
                        builder
                            .arg(kind)
                            .arg(rows as u32)
                            .arg(&trace.storage.buffer);
                    }
                    "pq_uniform_bundle_columns" => {
                        builder.arg(rows as u32).arg(&trace.storage.buffer);
                    }
                    "pq_sampling_public" => {
                        builder
                            .arg(&endpoints.storage.buffer)
                            .arg(&public.storage.buffer);
                    }
                    _ => unreachable!(),
                }
                if matches!(
                    name,
                    "pq_uniform_chain"
                        | "pq_sparse_chain"
                        | "pq_sampling_poseidon"
                        | "pq_uniform_bundle_columns"
                ) {
                    for constant in &engine.constants {
                        builder.arg(&constant.buffer);
                    }
                }
                let mut event = compute::Event::empty();
                // SAFETY: fixed family geometry and the aggregate plan above
                // bound every trace/scratch access. The fence drains before
                // borrowed host staging or scrubbed scratch can be destroyed.
                unsafe {
                    builder
                        .global_work_size(work)
                        .build()
                        .map_err(|e| e.to_string())?
                        .cmd()
                        .enew(&mut event)
                        .enq()
                        .map_err(|e| e.to_string())?;
                }
                let ns = self
                    .session
                    .record_event(engine, stage, name, &event)
                    .map_err(|error| {
                        run.observation_failed();
                        error
                    })?;
                run.observe_device(stage, Backend::OpenCl, 1, ns)
                    .map_err(|e| e.to_string())?;
            }
            let mut invalid = [0u64; 1];
            status
                .storage
                .buffer
                .read(&mut invalid[..])
                .enq()
                .map_err(|e| e.to_string())?;
            fence.finish()?;
            let uploaded = (expected * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 8;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += 8;
            }
            if invalid[0] != 0 {
                return Err("native GPU sampler exhausted its input stream".into());
            }
            Ok((trace, public))
        })
    }
}
