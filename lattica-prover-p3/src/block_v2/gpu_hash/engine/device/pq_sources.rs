//! GPU source witness generation; only raw words/static geometry cross the host boundary.
use super::*;
use crate::proving::{Backend, Run, Stage};
pub(in crate::block_v2::gpu_hash::engine) const KERNEL_SRC: &str = include_str!("pq_sources.cl");

#[cfg(feature = "gpu")]
struct Scratch {
    matrices: [DeviceMatrix; 4],
    queue: compute::Queue,
}
#[cfg(feature = "gpu")]
impl Drop for Scratch {
    fn drop(&mut self) {
        for m in &self.matrices {
            if let Err(e) = m.storage.buffer.cmd().fill(0u64, None).enq() {
                super::super::fatal_cleanup("pq_source_scratch_scrub", e);
            }
        }
        if let Err(e) = self.queue.finish() {
            super::super::fatal_cleanup("pq_source_scrub_drain", e);
        }
    }
}
impl DeviceSession {
    pub(crate) fn pq_source_trace(
        &self,
        input: &[u64],
        geometry: &[u64],
        host_allowance: usize,
        run: &Run,
    ) -> Result<(DeviceMatrix, DeviceMatrix), String> {
        if geometry.len() < 4 || input.is_empty() {
            return Err("native source input geometry".into());
        }
        let width = usize::try_from(geometry[1]).map_err(|_| "source width")?;
        let rows = usize::try_from(geometry[2]).map_err(|_| "source rows")?;
        let count = usize::try_from(geometry[3]).map_err(|_| "source public width")?;
        if !rows.is_power_of_two()
            || rows > 32768
            || width > 1024
            || width == 0
            || !matches!(count, 4 | 8)
        {
            return Err("native source matrix geometry".into());
        }
        let host_bytes = input
            .len()
            .checked_add(geometry.len())
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(8))
            .ok_or("source host size overflow")?;
        if host_bytes > host_allowance {
            return Err("source inputs exceed host allowance".into());
        }
        for stage in [Stage::WitnessTrace, Stage::PublicValues] {
            run.check_device_stage(stage, Backend::OpenCl)
                .map_err(|e| e.to_string())?;
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (width, count);
            Err("native source witness requires OpenCL".into())
        }
        #[cfg(feature = "gpu")]
        self.with_engine(|engine| {
            let spec =
                |r: u32, c: usize| MatrixSpec::new(r, c, Extension::Base, RowOrder::Natural, 1);
            let specs = [
                spec(rows.ilog2(), width)?,
                spec(0, count)?,
                spec(0, input.len())?,
                spec(0, geometry.len())?,
                spec(0, count)?,
                spec(0, 1)?,
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
            let [raw, geometry_buffer, endpoints, status] = &scratch.matrices;
            let fence = engine.fence();
            raw.storage
                .buffer
                .write(input)
                .enq()
                .map_err(|e| e.to_string())?;
            geometry_buffer
                .storage
                .buffer
                .write(geometry)
                .enq()
                .map_err(|e| e.to_string())?;
            trace
                .storage
                .buffer
                .cmd()
                .fill(0u64, None)
                .enq()
                .map_err(|e| e.to_string())?;
            for (name, work, stage) in [
                ("pq_source_chain", 1, Stage::WitnessTrace),
                ("pq_source_hints", rows, Stage::WitnessTrace),
                ("pq_source_poseidon", rows, Stage::WitnessTrace),
                ("pq_source_public", count, Stage::PublicValues),
            ] {
                let mut builder = engine.pq.kernel_builder(name);
                match name {
                    "pq_source_chain" => {
                        builder
                            .arg(&raw.storage.buffer)
                            .arg(&geometry_buffer.storage.buffer)
                            .arg(&trace.storage.buffer)
                            .arg(&endpoints.storage.buffer)
                            .arg(&status.storage.buffer);
                    }
                    "pq_source_hints" | "pq_source_poseidon" => {
                        builder
                            .arg(&geometry_buffer.storage.buffer)
                            .arg(&trace.storage.buffer);
                    }
                    _ => {
                        builder
                            .arg(&geometry_buffer.storage.buffer)
                            .arg(&endpoints.storage.buffer)
                            .arg(&public.storage.buffer);
                    }
                }
                if matches!(name, "pq_source_chain" | "pq_source_poseidon") {
                    for c in &engine.constants {
                        builder.arg(&c.buffer);
                    }
                }
                let mut event = compute::Event::empty();
                // SAFETY: typed source adapter validates exact layout, and the aggregate
                // allocation plan covers all output/scratch before any private upload.
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
                    .map_err(|e| {
                        run.observation_failed();
                        e
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
            let uploaded = ((input.len() + geometry.len()) * 8) as u64;
            engine.stats.uploaded_bytes += uploaded;
            engine.stats.downloaded_bytes += 8;
            {
                let mut stats = self.session.stats.lock().unwrap();
                stats.uploaded_bytes += uploaded;
                stats.downloaded_bytes += 8;
            }
            if invalid[0] != 0 {
                return Err("native source witness arithmetic overflow".into());
            }
            Ok((trace, public))
        })
    }
}
